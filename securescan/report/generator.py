"""Report generator.

Renders the scan results into a professional HTML report using Jinja2 templates.
Also generates optional JSON and SARIF outputs for programmatic consumption.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from securescan.detect.models import Patch, ScanResult

logger = logging.getLogger(__name__)

SARIF_SCHEMA_URL = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
    "sarif-2.1/schema/sarif-schema-2.1.0.json"
)
SECURESCAN_INFO_URI = "https://github.com/sssafeman/securescan"
SECURESCAN_VERSION = "0.1.0"

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape

    JINJA2_AVAILABLE = True
except ImportError:  # pragma: no cover - environment dependent
    JINJA2_AVAILABLE = False
    logger.warning("jinja2 not available. Install with: pip install jinja2")


def generate_html_report(
    result: ScanResult,
    patches: list[Patch],
    output_path: Path | None = None,
) -> str:
    """Generate an HTML security audit report."""
    if not JINJA2_AVAILABLE:
        logger.error("Cannot generate HTML report: jinja2 not installed")
        return _generate_fallback_report(result, patches)

    template_dir = Path(__file__).parent / "templates"
    if not template_dir.exists():
        logger.error(f"Template directory not found: {template_dir}")
        return _generate_fallback_report(result, patches)

    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html"]),
    )

    template = env.get_template("report.html")
    html = template.render(
        result=result,
        patches=patches,
    )

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        logger.info(f"HTML report saved to {output_path}")

    return html


def generate_json_report(
    result: ScanResult,
    patches: list[Patch],
    output_path: Path | None = None,
) -> str:
    """Generate a JSON report for programmatic consumption."""
    data = result.to_dict()
    data["patches"] = [patch.to_dict() for patch in patches]

    json_str = json.dumps(data, indent=2, default=str)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json_str, encoding="utf-8")
        logger.info(f"JSON report saved to {output_path}")

    return json_str


def _severity_to_sarif_level(severity: str) -> str:
    """Map SecureScan severities to SARIF levels."""
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"


def _sarif_level_priority(level: str) -> int:
    return {"note": 0, "warning": 1, "error": 2}.get(level, 0)


def _to_relative_uri(file_path: str) -> str:
    """Ensure SARIF artifact URIs are relative, not absolute."""
    path = Path(file_path).as_posix()
    if path.startswith("/"):
        return path.lstrip("/")
    return path


def generate_sarif_report(
    result: ScanResult,
    patches: list[Patch],
    output_path: Path | None = None,
) -> Path:
    """Generate a SARIF v2.1.0 report and return its file path."""
    if output_path is None:
        reports_dir = Path("reports")
        timestamp = result.scan_timestamp.strftime("%Y%m%d_%H%M%S")
        repo_slug = result.repo_name.replace("/", "_")
        output_path = reports_dir / f"{repo_slug}_{timestamp}.sarif.json"

    patch_map = {patch.finding_id: patch for patch in patches}

    rules_by_id: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []

    for finding in result.confirmed_findings:
        raw = finding.enriched.raw
        rule_id = raw.vuln_type.value
        level = _severity_to_sarif_level(finding.enriched.severity.value)

        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {
                    "text": raw.message or f"Potential {rule_id} vulnerability"
                },
                "fullDescription": {"text": finding.enriched.reasoning},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "tags": ["security"],
                    "security-severity": f"{finding.enriched.cvss_estimate:.1f}",
                },
            }
        else:
            existing = rules_by_id[rule_id]
            existing_level = str(
                existing.get("defaultConfiguration", {}).get("level", "note")
            )
            if _sarif_level_priority(level) > _sarif_level_priority(existing_level):
                existing["defaultConfiguration"] = {"level": level}

            existing_cvss = float(
                str(existing.get("properties", {}).get("security-severity", "0.0"))
            )
            if finding.enriched.cvss_estimate > existing_cvss:
                existing["properties"] = {
                    "tags": ["security"],
                    "security-severity": f"{finding.enriched.cvss_estimate:.1f}",
                }

        result_properties: dict[str, object] = {
            "confidence": finding.final_confidence,
            "cvss": finding.enriched.cvss_estimate,
            "taintChain": finding.enriched.taint_chain,
            "validationStatus": finding.validation_status.value,
            "fpArgument": finding.fp_argument or None,
            "fpRebuttal": finding.fp_rebuttal or None,
        }

        patch = patch_map.get(raw.id)
        if patch is not None:
            result_properties["patch"] = patch.to_dict()

        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": finding.enriched.reasoning},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": _to_relative_uri(raw.file_path)
                            },
                            "region": {
                                "startLine": raw.line_start,
                                "endLine": raw.line_end,
                            },
                        }
                    }
                ],
                "properties": result_properties,
            }
        )

    sarif_data = {
        "$schema": SARIF_SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecureScan",
                        "version": SECURESCAN_VERSION,
                        "informationUri": SECURESCAN_INFO_URI,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(sarif_data, indent=2, default=str),
        encoding="utf-8",
    )
    logger.info(f"SARIF report saved to {output_path}")
    return output_path


def _generate_fallback_report(
    result: ScanResult,
    patches: list[Patch],
) -> str:
    """Generate a simple text-based report when Jinja2 is unavailable."""
    lines = [
        "=" * 60,
        "SecureScan Security Report",
        "=" * 60,
        f"Repository: {result.repo_name}",
        f"Branch: {result.branch} ({result.commit_hash[:8]})",
        f"Scan Date: {result.scan_timestamp.isoformat()}",
        f"Files Analyzed: {result.files_analyzed}",
        f"Lines of Code: {result.total_lines:,}",
        f"Duration: {result.scan_duration_seconds:.1f}s",
        "",
        f"Raw Findings: {result.raw_findings_count}",
        f"Confirmed: {len(result.confirmed_findings)}",
        f"Patches: {len(patches)}",
        "",
    ]

    if result.executive_summary:
        lines.extend(["Executive Summary:", result.executive_summary, ""])

    for index, finding in enumerate(result.confirmed_findings, 1):
        lines.extend(
            [
                f"--- Finding {index} ---",
                f"Type: {finding.enriched.raw.vuln_type.value}",
                f"Severity: {finding.enriched.severity.value}",
                f"File: {finding.enriched.raw.file_path}:{finding.enriched.raw.line_start}",
                f"Reasoning: {finding.enriched.reasoning}",
                f"Confidence: {finding.final_confidence:.0%}",
                "",
            ]
        )

    return "\n".join(lines)
