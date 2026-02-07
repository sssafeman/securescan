"""Custom secrets scanner using entropy analysis and pattern matching.

Detects hardcoded API keys, tokens, passwords, and other credentials
embedded in source code. Independent from semgrep for cross-validation.
"""

from __future__ import annotations

import logging
import math
import re
from dataclasses import dataclass
from pathlib import Path

from securescan.detect.models import DetectionMethod, RawFinding, VulnType

logger = logging.getLogger(__name__)


def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string. Higher = more random = more likely a secret."""

    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


@dataclass
class SecretPattern:
    """A regex pattern for a known secret type."""

    name: str
    pattern: re.Pattern[str]
    confidence: float
    min_entropy: float = 0.0


SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern(
        name="AWS Access Key ID",
        pattern=re.compile(r"(?:AKIA|ABIA|ACCA)[0-9A-Z]{16}"),
        confidence=0.95,
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        pattern=re.compile(
            r"(?i)aws[_\-\.]?secret[_\-\.]?access[_\-\.]?key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
        ),
        confidence=0.95,
        min_entropy=3.5,
    ),
    SecretPattern(
        name="GitHub Token",
        pattern=re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"),
        confidence=0.95,
    ),
    SecretPattern(
        name="Stripe API Key",
        pattern=re.compile(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}"),
        confidence=0.95,
    ),
    SecretPattern(
        name="Slack Token",
        pattern=re.compile(r"xox[baprs]-[0-9]{10,}-[A-Za-z0-9-]+"),
        confidence=0.90,
    ),
    SecretPattern(
        name="JSON Web Token",
        pattern=re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+"),
        confidence=0.85,
    ),
    SecretPattern(
        name="Private Key",
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        confidence=0.95,
    ),
    SecretPattern(
        name="Hardcoded Password",
        pattern=re.compile(
            r"""(?i)(?:password|passwd|pwd|secret|api_?key|auth_?token|access_?token)\s*[=:]\s*['\"]([^'\"]{8,})['\"]"""
        ),
        confidence=0.70,
        min_entropy=2.5,
    ),
    SecretPattern(
        name="High-Entropy String",
        pattern=re.compile(
            r"""(?i)(?:key|token|secret|credential|auth)\s*[=:]\s*['\"]([A-Za-z0-9+/=_-]{20,})['\"]"""
        ),
        confidence=0.60,
        min_entropy=3.0,
    ),
]


_FP_INDICATORS = re.compile(
    r"(?i)("
    r"placeholder|changeme|your[_\-]?|insert[_\-]?|replace[_\-]?"
    r"|xxx+|test|dummy|fake|sample|todo|fixme"
    r"|process\.env|os\.environ|os\.getenv|ENV\[|getenv"
    r"|<[A-Z_]+>|\{\{.*\}\}|\$\{.*\}"
    r")"
)

_TEST_FILE_INDICATORS = re.compile(
    r"(?i)(test[_/]|_test\.|\.test\.|spec[_/]|_spec\.|\.spec\.|fixtures?[_/]|mock[_/]|__mocks__)"
)


def _is_likely_false_positive(value: str, file_path: str) -> bool:
    """Check if a detected secret is likely a false positive."""

    if _FP_INDICATORS.search(value):
        return True
    if _TEST_FILE_INDICATORS.search(file_path):
        return True
    if len(set(value)) <= 2:
        return True
    if len(value) < 8:
        return True
    return False


def _get_line_context(lines: list[str], line_idx: int, context: int = 5) -> str:
    """Get context lines around a finding."""

    start = max(0, line_idx - context)
    end = min(len(lines), line_idx + context + 1)
    return "\n".join(f"{index + 1:4d} | {lines[index]}" for index in range(start, end))


def scan_file_for_secrets(file_path: str, abs_path: Path) -> list[RawFinding]:
    """Scan a single file for hardcoded secrets.

    Args:
        file_path: Path relative to repo root
        abs_path: Absolute filesystem path

    Returns:
        List of RawFinding objects for detected secrets
    """

    try:
        content = abs_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    lines = content.splitlines()
    findings: list[RawFinding] = []
    seen_lines: set[int] = set()

    for pattern in SECRET_PATTERNS:
        for match in pattern.pattern.finditer(content):
            line_idx = content[: match.start()].count("\n")
            line_num = line_idx + 1

            if line_num in seen_lines:
                continue

            value = match.group(1) if match.lastindex else match.group(0)

            if pattern.min_entropy > 0:
                entropy = shannon_entropy(value)
                if entropy < pattern.min_entropy:
                    continue

            line_text = lines[line_idx] if line_idx < len(lines) else ""
            if _is_likely_false_positive(value, file_path):
                continue
            if _is_likely_false_positive(line_text, file_path):
                continue

            seen_lines.add(line_num)

            confidence = pattern.confidence
            entropy = shannon_entropy(value)
            if entropy > 4.0:
                confidence = min(confidence + 0.1, 1.0)

            findings.append(
                RawFinding(
                    vuln_type=VulnType.HARDCODED_SECRET,
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    code_snippet=_get_line_context(lines, line_idx),
                    detection_method=(
                        DetectionMethod.REGEX
                        if pattern.min_entropy == 0
                        else DetectionMethod.ENTROPY
                    ),
                    confidence=confidence,
                    message=f"Potential {pattern.name} detected",
                    rule_id=f"secrets/{pattern.name.lower().replace(' ', '_')}",
                    metadata={
                        "pattern_name": pattern.name,
                        "entropy": round(entropy, 2),
                        "matched_length": len(value),
                    },
                )
            )

    return findings


def scan_repo_for_secrets(repo_path: Path, files: list[tuple[str, Path]]) -> list[RawFinding]:
    """Scan multiple files for secrets.

    Args:
        repo_path: Repository root path
        files: List of (relative_path, absolute_path) tuples

    Returns:
        Combined list of findings
    """

    del repo_path
    all_findings: list[RawFinding] = []

    for rel_path, abs_path in files:
        findings = scan_file_for_secrets(rel_path, abs_path)
        all_findings.extend(findings)

    logger.info(
        f"Secrets scanner: {len(all_findings)} potential secrets in "
        f"{len(files)} files"
    )

    return all_findings
