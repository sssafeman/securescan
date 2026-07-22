"""Semgrep integration for static analysis detection.

Runs semgrep with our custom rules + community rulesets against the target repo.
Converts semgrep JSON output into RawFinding objects.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from pathlib import Path
from typing import Any

from securescan.detect.models import DetectionMethod, RawFinding, VulnType

logger = logging.getLogger(__name__)

# Map semgrep rule IDs / categories to our vulnerability types
_VULN_TYPE_MAP = {
    "sqli": VulnType.SQLI,
    "sql-injection": VulnType.SQLI,
    "sql_injection": VulnType.SQLI,
    "hardcoded-secret": VulnType.HARDCODED_SECRET,
    "hardcoded_secret": VulnType.HARDCODED_SECRET,
    "secrets": VulnType.HARDCODED_SECRET,
    "xss": VulnType.XSS,
    "cross-site-scripting": VulnType.XSS,
}

# Confidence mapping from semgrep severity
_CONFIDENCE_MAP = {
    "ERROR": 0.9,
    "WARNING": 0.7,
    "INFO": 0.5,
}
_BASE_COMMAND = (
    "semgrep",
    "--json",
    "--quiet",
    "--no-git-ignore",
    "--timeout",
    "30",
    "--max-target-bytes",
    "1000000",
)
_COMMUNITY_CONFIGS = (
    "p/python",
    "p/javascript",
    "p/golang",
    "p/java",
    "p/spring",
    "p/jwt",
    "p/command-injection",
    "p/secrets",
    "p/owasp-top-ten",
)
_SQLI_KEYWORDS = (
    "sql-injection",
    "sqli",
    "sql_injection",
    "parameterized",
    "cursor.execute",
    "db.query",
    "raw query",
    "string concatenation in query",
    "string formatting in query",
)
_EVAL_KEYWORDS = (
    "eval",
    "exec(",
    "code injection",
    "code-injection",
    "remote code",
)
_SECRET_KEYWORDS = (
    "secret",
    "password",
    "api.key",
    "api_key",
    "apikey",
    "token",
    "credential",
    "private.key",
    "private_key",
    "hardcoded",
    "hard-coded",
    "hard_coded",
    "bcrypt",
    "hash detected",
)
_XSS_KEYWORDS = (
    "xss",
    "cross-site",
    "cross_site",
    "innerhtml",
    "document.write",
    "dangerouslysetinnerhtml",
    "reflected",
    "stored xss",
    "dom-based",
)


def _semgrep_available() -> bool:
    """Check if semgrep is installed and accessible."""

    return shutil.which("semgrep") is not None


def _get_code_context(file_path: Path, line: int, context_lines: int = 5) -> str:
    """Extract lines around a finding for context."""

    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(0, line - context_lines - 1)
        end = min(len(lines), line + context_lines)
        numbered = [f"{index + 1:4d} | {lines[index]}" for index in range(start, end)]
        return "\n".join(numbered)
    except OSError:
        return ""


def _contains_rule_or_message_keyword(
    rule_id: str,
    message: str,
    keywords: tuple[str, ...],
) -> bool:
    """Return whether a keyword occurs in a rule ID or finding message."""

    return any(keyword in rule_id or keyword in message for keyword in keywords)


def _classify_vuln_type(rule_id: str, message: str) -> VulnType | None:
    """Determine vulnerability type from semgrep rule ID and message.

    Returns None if the finding doesn't match any of our target vulnerability
    types. This is intentional - we only want findings in our scope.
    """
    rule_lower = rule_id.lower()
    msg_lower = message.lower()

    for keyword, vuln_type in _VULN_TYPE_MAP.items():
        if keyword in rule_lower:
            return vuln_type

    if _contains_rule_or_message_keyword(rule_lower, msg_lower, _SQLI_KEYWORDS):
        return VulnType.SQLI
    if any(keyword in msg_lower for keyword in _EVAL_KEYWORDS):
        return VulnType.SQLI
    if _contains_rule_or_message_keyword(rule_lower, msg_lower, _SECRET_KEYWORDS):
        return VulnType.HARDCODED_SECRET
    if _contains_rule_or_message_keyword(rule_lower, msg_lower, _XSS_KEYWORDS):
        return VulnType.XSS
    return None


def _is_in_scope(
    vuln_type: VulnType | None,
    target_vuln_types: set[VulnType] | None,
) -> bool:
    """Return True when the finding should be included in results."""
    if vuln_type is None:
        return False
    if target_vuln_types and vuln_type not in target_vuln_types:
        return False
    return True


def _add_custom_config(
    command: list[str],
    custom_rules_dir: Path | None,
) -> int:
    """Add a custom rules directory and return its config contribution."""

    if not custom_rules_dir or not custom_rules_dir.is_dir():
        return 0

    yaml_files = list(custom_rules_dir.glob("*.yaml")) + list(
        custom_rules_dir.glob("*.yml")
    )
    if not yaml_files:
        return 0

    command.extend(["--config", str(custom_rules_dir)])
    logger.info(f"Using {len(yaml_files)} custom rule files from {custom_rules_dir}")
    return 1


def _add_community_configs(command: list[str], enabled: bool) -> int:
    """Add community configs in their established order."""

    if not enabled:
        return 0
    for config in _COMMUNITY_CONFIGS:
        command.extend(["--config", config])
    return len(_COMMUNITY_CONFIGS)


def _build_semgrep_command(
    custom_rules_dir: Path | None,
    use_community_rules: bool,
) -> tuple[list[str], int]:
    """Build the Semgrep command and return its configuration count."""

    command = list(_BASE_COMMAND)
    config_count = _add_custom_config(command, custom_rules_dir)
    config_count += _add_community_configs(command, use_community_rules)
    return command, config_count


def _append_scan_targets(
    command: list[str],
    repo_path: Path,
    target_files: list[str] | None,
    config_count: int,
) -> bool:
    """Append repository or explicit file targets to a Semgrep command."""

    if target_files is None:
        command.append(str(repo_path))
        logger.info(f"Running semgrep with {config_count} config(s)...")
        return True

    scan_targets: list[str] = []
    for relative_path in target_files:
        target_path = repo_path / relative_path
        if target_path.exists() and target_path.is_file():
            scan_targets.append(str(target_path))

    if not scan_targets:
        logger.info("Semgrep: no target files in scope, skipping semgrep analysis.")
        return False

    command.extend(scan_targets)
    logger.info(
        f"Running semgrep with {config_count} config(s) on "
        f"{len(scan_targets)} target files..."
    )
    return True


def _run_semgrep_command(
    command: list[str],
) -> subprocess.CompletedProcess[str] | None:
    """Execute Semgrep and handle process-level failures."""

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.error("semgrep timed out after 5 minutes")
        return None

    if result.returncode not in (0, 1):
        logger.error(f"semgrep failed (exit {result.returncode}): {result.stderr[:500]}")
        return None
    return result


def _normalize_finding_path(file_path: str, repo_path: Path) -> str:
    """Make a finding path relative to the repository when possible."""

    try:
        return str(Path(file_path).relative_to(repo_path))
    except ValueError:
        return file_path


def _finding_from_result(
    result_item: dict[str, Any],
    repo_path: Path,
    target_vuln_types: set[VulnType] | None,
) -> RawFinding | None:
    """Convert one Semgrep result item into an in-scope raw finding."""

    rule_id = result_item.get("check_id", "unknown")
    extra = result_item.get("extra", {})
    message = extra.get("message", "")
    severity = extra.get("severity", "WARNING")
    file_path = _normalize_finding_path(result_item.get("path", ""), repo_path)
    start_line = result_item.get("start", {}).get("line", 0)
    end_line = result_item.get("end", {}).get("line", start_line)
    vuln_type = _classify_vuln_type(rule_id, message)
    if not _is_in_scope(vuln_type, target_vuln_types):
        return None

    return RawFinding(
        vuln_type=vuln_type,
        file_path=file_path,
        line_start=start_line,
        line_end=end_line,
        code_snippet=_get_code_context(repo_path / file_path, start_line),
        detection_method=DetectionMethod.SEMGREP,
        confidence=_CONFIDENCE_MAP.get(severity, 0.5),
        message=message or f"Semgrep rule {rule_id} triggered",
        rule_id=rule_id,
        metadata={
            "semgrep_severity": severity,
            "semgrep_rule": rule_id,
            "matched_text": extra.get("lines", ""),
        },
    )


def _convert_results(
    results_data: list[dict[str, Any]],
    repo_path: Path,
    target_vuln_types: set[VulnType] | None,
) -> list[RawFinding]:
    """Convert Semgrep result items while preserving their order."""

    findings: list[RawFinding] = []
    for result_item in results_data:
        finding = _finding_from_result(result_item, repo_path, target_vuln_types)
        if finding is not None:
            findings.append(finding)
    return findings


def _log_finding_summary(
    total_matches: int,
    findings: list[RawFinding],
) -> None:
    """Log total, filtered, and vulnerability-type finding counts."""

    out_of_scope = total_matches - len(findings)
    sqli_count = sum(
        1 for finding in findings if finding.vuln_type == VulnType.SQLI
    )
    secret_count = sum(
        1
        for finding in findings
        if finding.vuln_type == VulnType.HARDCODED_SECRET
    )
    xss_count = sum(
        1 for finding in findings if finding.vuln_type == VulnType.XSS
    )
    logger.info(
        f"Semgrep: {total_matches} total matches, "
        f"{len(findings)} in scope ({out_of_scope} filtered out) -> "
        f"{sqli_count} SQLi, {secret_count} secrets, {xss_count} XSS"
    )


def run_semgrep(
    repo_path: Path,
    custom_rules_dir: Path | None = None,
    use_community_rules: bool = True,
    target_vuln_types: set[VulnType] | None = None,
    target_files: list[str] | None = None,
) -> list[RawFinding]:
    """Run semgrep against a repository and return findings.

    Args:
        repo_path: Path to the cloned repository
        custom_rules_dir: Path to directory containing custom .yaml rules
        use_community_rules: Whether to include semgrep community rulesets
        target_vuln_types: Only return findings matching these types (None = all)
        target_files: Relative file paths to scan (None = entire repo)

    Returns:
        List of RawFinding objects
    """

    if not _semgrep_available():
        logger.warning(
            "semgrep not installed. Install with: pip install semgrep\n"
            "Skipping semgrep analysis - relying on custom scanners only."
        )
        return []

    command, config_count = _build_semgrep_command(
        custom_rules_dir,
        use_community_rules,
    )
    if config_count == 0:
        logger.warning("No semgrep configs available. Skipping semgrep analysis.")
        return []
    if not _append_scan_targets(
        command,
        repo_path,
        target_files,
        config_count,
    ):
        return []

    result = _run_semgrep_command(command)
    if result is None:
        return []

    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.error("Failed to parse semgrep JSON output")
        return []

    results_data = output.get("results", [])
    findings = _convert_results(results_data, repo_path, target_vuln_types)
    _log_finding_summary(len(results_data), findings)
    return findings
