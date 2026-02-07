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


def _classify_vuln_type(rule_id: str, message: str) -> VulnType:
    """Determine vulnerability type from semgrep rule ID and message."""

    rule_lower = rule_id.lower()
    msg_lower = message.lower()

    for keyword, vuln_type in _VULN_TYPE_MAP.items():
        if keyword in rule_lower or keyword in msg_lower:
            return vuln_type

    if any(word in msg_lower for word in ("sql", "query", "injection", "parameterized")):
        return VulnType.SQLI
    if any(
        word in msg_lower
        for word in ("secret", "password", "api_key", "token", "credential")
    ):
        return VulnType.HARDCODED_SECRET
    if any(word in msg_lower for word in ("xss", "innerhtml", "document.write", "cross-site")):
        return VulnType.XSS

    return VulnType.SQLI


def run_semgrep(
    repo_path: Path,
    custom_rules_dir: Path | None = None,
    use_community_rules: bool = True,
    target_vuln_types: set[VulnType] | None = None,
) -> list[RawFinding]:
    """Run semgrep against a repository and return findings.

    Args:
        repo_path: Path to the cloned repository
        custom_rules_dir: Path to directory containing custom .yaml rules
        use_community_rules: Whether to include semgrep community rulesets
        target_vuln_types: Only return findings matching these types (None = all)

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
            "p/secrets",
            "p/owasp-top-ten",
        ]
        for config in community_configs:
            cmd.extend(["--config", config])
            configs_added += 1

    if configs_added == 0:
        logger.warning("No semgrep configs available. Skipping semgrep analysis.")
        return []

    cmd.append(str(repo_path))

    logger.info(f"Running semgrep with {configs_added} config(s)...")

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
        start_line = result_item.get("start", {}).get("line", 0)
        end_line = result_item.get("end", {}).get("line", start_line)

        vuln_type = _classify_vuln_type(rule_id, message)

        if target_vuln_types and vuln_type not in target_vuln_types:
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

    logger.info(
        f"Semgrep: {len(results_data)} total matches, "
        f"{len(findings)} in scope -> "
        f"{sum(1 for f in findings if f.vuln_type == VulnType.SQLI)} SQLi, "
        f"{sum(1 for f in findings if f.vuln_type == VulnType.HARDCODED_SECRET)} secrets, "
        f"{sum(1 for f in findings if f.vuln_type == VulnType.XSS)} XSS"
    )

    return findings
