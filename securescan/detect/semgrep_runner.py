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


def _classify_vuln_type(rule_id: str, message: str) -> VulnType | None:
    """Determine vulnerability type from semgrep rule ID and message.

    Returns None if the finding doesn't match any of our target vulnerability
    types. This is intentional - we only want findings in our scope.
    """
    rule_lower = rule_id.lower()
    msg_lower = message.lower()

    # Check explicit mappings first
    for keyword, vuln_type in _VULN_TYPE_MAP.items():
        if keyword in rule_lower:
            return vuln_type

    # SQL Injection indicators
    sqli_keywords = (
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
    if any(keyword in rule_lower or keyword in msg_lower for keyword in sqli_keywords):
        return VulnType.SQLI

    # Also classify eval/exec injection as SQLI (code injection, close enough)
    eval_keywords = ("eval", "exec(", "code injection", "code-injection", "remote code")
    if any(keyword in msg_lower for keyword in eval_keywords):
        return VulnType.SQLI

    # Hardcoded secrets indicators
    secret_keywords = (
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
    if any(keyword in rule_lower or keyword in msg_lower for keyword in secret_keywords):
        return VulnType.HARDCODED_SECRET

    # XSS indicators
    xss_keywords = (
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
    if any(keyword in rule_lower or keyword in msg_lower for keyword in xss_keywords):
        return VulnType.XSS

    # If nothing matches, return None - this finding is out of scope
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

    cmd = [
        "semgrep",
        "--json",
        "--quiet",
        "--no-git-ignore",
        "--timeout",
        "30",
        "--max-target-bytes",
        "1000000",
    ]

    configs_added = 0

    if custom_rules_dir and custom_rules_dir.is_dir():
        yaml_files = list(custom_rules_dir.glob("*.yaml")) + list(custom_rules_dir.glob("*.yml"))
        if yaml_files:
            cmd.extend(["--config", str(custom_rules_dir)])
            configs_added += 1
            logger.info(f"Using {len(yaml_files)} custom rule files from {custom_rules_dir}")

    if use_community_rules:
        community_configs = [
            "p/python",
            "p/javascript",
            "p/golang",
            "p/java",
            "p/spring",
            "p/jwt",
            "p/command-injection",
            "p/secrets",
            "p/owasp-top-ten",
        ]
        for config in community_configs:
            cmd.extend(["--config", config])
            configs_added += 1

    if configs_added == 0:
        logger.warning("No semgrep configs available. Skipping semgrep analysis.")
        return []

    if target_files is None:
        cmd.append(str(repo_path))
        logger.info(f"Running semgrep with {configs_added} config(s)...")
    else:
        scan_targets: list[str] = []
        for relative in target_files:
            target_path = repo_path / relative
            if target_path.exists() and target_path.is_file():
                scan_targets.append(str(target_path))

        if not scan_targets:
            logger.info("Semgrep: no target files in scope, skipping semgrep analysis.")
            return []

        cmd.extend(scan_targets)
        logger.info(
            f"Running semgrep with {configs_added} config(s) on "
            f"{len(scan_targets)} target files..."
        )

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired:
        logger.error("semgrep timed out after 5 minutes")
        return []

    if result.returncode not in (0, 1):
        logger.error(f"semgrep failed (exit {result.returncode}): {result.stderr[:500]}")
        return []

    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.error("Failed to parse semgrep JSON output")
        return []

    results_data = output.get("results", [])
    findings: list[RawFinding] = []

    for result_item in results_data:
        rule_id = result_item.get("check_id", "unknown")
        message = result_item.get("extra", {}).get("message", "")
        severity = result_item.get("extra", {}).get("severity", "WARNING")
        file_path = result_item.get("path", "")
        # Make path relative to repo root
        try:
            file_path = str(Path(file_path).relative_to(repo_path))
        except ValueError:
            pass  # Already relative or different root
        start_line = result_item.get("start", {}).get("line", 0)
        end_line = result_item.get("end", {}).get("line", start_line)

        vuln_type = _classify_vuln_type(rule_id, message)

        # Skip findings that don't match any of our target vuln types
        if vuln_type is None:
            continue

        # Filter by specific target vuln types if specified
        if not _is_in_scope(vuln_type, target_vuln_types):
            continue

        abs_path = repo_path / file_path
        code_snippet = _get_code_context(abs_path, start_line)

        finding = RawFinding(
            vuln_type=vuln_type,
            file_path=file_path,
            line_start=start_line,
            line_end=end_line,
            code_snippet=code_snippet,
            detection_method=DetectionMethod.SEMGREP,
            confidence=_CONFIDENCE_MAP.get(severity, 0.5),
            message=message or f"Semgrep rule {rule_id} triggered",
            rule_id=rule_id,
            metadata={
                "semgrep_severity": severity,
                "semgrep_rule": rule_id,
                "matched_text": result_item.get("extra", {}).get("lines", ""),
            },
        )
        findings.append(finding)

    out_of_scope = len(results_data) - len(findings)
    logger.info(
        f"Semgrep: {len(results_data)} total matches, "
        f"{len(findings)} in scope ({out_of_scope} filtered out) -> "
        f"{sum(1 for f in findings if f.vuln_type == VulnType.SQLI)} SQLi, "
        f"{sum(1 for f in findings if f.vuln_type == VulnType.HARDCODED_SECRET)} secrets, "
        f"{sum(1 for f in findings if f.vuln_type == VulnType.XSS)} XSS"
    )

    return findings
