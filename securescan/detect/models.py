"""Data models for the SecureScan pipeline.

All inter-stage communication uses these models. They are designed to be
serializable to JSON for caching, debugging, and report generation.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


# Enums

class VulnType(str, Enum):
    SQLI = "sqli"
    HARDCODED_SECRET = "hardcoded_secret"
    XSS = "xss"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DetectionMethod(str, Enum):
    SEMGREP = "semgrep"
    ENTROPY = "entropy"
    REGEX = "regex"
    LLM = "llm"


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"
    RUST = "rust"
    JAVA = "java"
    UNKNOWN = "unknown"


class Exploitability(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    POSSIBLE = "possible"
    UNLIKELY = "unlikely"


class ValidationStatus(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY_FP = "likely_fp"
    UNCERTAIN = "uncertain"


# Stage 3 Output: Raw Detection

@dataclass
class RawFinding:
    """Output of the Detect stage. High recall, moderate precision."""

    vuln_type: VulnType
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    detection_method: DetectionMethod
    confidence: float
    message: str
    rule_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "vuln_type": self.vuln_type.value,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "code_snippet": self.code_snippet,
            "detection_method": self.detection_method.value,
            "confidence": self.confidence,
            "message": self.message,
            "rule_id": self.rule_id,
            "metadata": self.metadata,
        }


# Stage 4 Output: LLM-Enriched Analysis

@dataclass
class EnrichedFinding:
    """Output of the Analyze stage. LLM has reasoned about the finding."""

    raw: RawFinding
    severity: Severity
    cvss_estimate: float
    reasoning: str
    taint_chain: str | None
    exploitability: Exploitability
    blast_radius: str
    is_reachable: bool | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw.to_dict(),
            "severity": self.severity.value,
            "cvss_estimate": self.cvss_estimate,
            "reasoning": self.reasoning,
            "taint_chain": self.taint_chain,
            "exploitability": self.exploitability.value,
            "blast_radius": self.blast_radius,
            "is_reachable": self.is_reachable,
        }


# Stage 5 Output: Adversarial Validation

@dataclass
class ValidatedFinding:
    """Output of the Validate stage. Adversarial review complete."""

    enriched: EnrichedFinding
    validation_status: ValidationStatus
    fp_argument: str
    fp_rebuttal: str
    final_confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "enriched": self.enriched.to_dict(),
            "validation_status": self.validation_status.value,
            "fp_argument": self.fp_argument,
            "fp_rebuttal": self.fp_rebuttal,
            "final_confidence": self.final_confidence,
        }

    @property
    def is_confirmed(self) -> bool:
        return self.validation_status == ValidationStatus.CONFIRMED


# Stage 6 Output: Remediation Patch

@dataclass
class Patch:
    """A remediation patch for a confirmed finding."""

    finding_id: str
    diff: str
    explanation: str
    syntax_valid: bool
    files_modified: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "diff": self.diff,
            "explanation": self.explanation,
            "syntax_valid": self.syntax_valid,
            "files_modified": self.files_modified,
        }


# Stage 7 Output: Complete Report

@dataclass
class ScanResult:
    """Complete scan result for a repository."""

    repo_name: str
    repo_url: str
    branch: str
    commit_hash: str
    scan_timestamp: datetime
    files_analyzed: int
    total_lines: int
    raw_findings_count: int
    confirmed_findings: list[ValidatedFinding]
    patches: list[Patch]
    executive_summary: str = ""
    scan_duration_seconds: float = 0.0

    @property
    def critical_count(self) -> int:
        return sum(
            1 for finding in self.confirmed_findings
            if finding.enriched.severity == Severity.CRITICAL
        )

    @property
    def high_count(self) -> int:
        return sum(
            1 for finding in self.confirmed_findings
            if finding.enriched.severity == Severity.HIGH
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_name": self.repo_name,
            "repo_url": self.repo_url,
            "branch": self.branch,
            "commit_hash": self.commit_hash,
            "scan_timestamp": self.scan_timestamp.isoformat(),
            "files_analyzed": self.files_analyzed,
            "total_lines": self.total_lines,
            "raw_findings_count": self.raw_findings_count,
            "confirmed_findings": [f.to_dict() for f in self.confirmed_findings],
            "patches": [p.to_dict() for p in self.patches],
            "executive_summary": self.executive_summary,
            "scan_duration_seconds": self.scan_duration_seconds,
        }
