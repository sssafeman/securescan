"""HTML report generator.

Renders the scan results into a professional HTML report using Jinja2 templates.
Also generates an optional JSON dump for programmatic consumption.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from securescan.detect.models import Patch, ScanResult

logger = logging.getLogger(__name__)

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
