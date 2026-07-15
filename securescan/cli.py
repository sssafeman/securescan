"""SecureScan CLI - entry point for the security audit pipeline."""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

import click

try:
    from rich.console import Console
    from rich.logging import RichHandler
except ModuleNotFoundError:  # pragma: no cover - fallback for minimal envs
    Console = None
    RichHandler = None

from securescan.config import config
from securescan.detect.models import ScanResult, ValidationStatus

if TYPE_CHECKING:
    from securescan.pipeline import PipelineContext

_RICH_TAG_RE = re.compile(r"\[/?[a-zA-Z0-9 _-]+\]")
logger = logging.getLogger(__name__)


class PlainConsole:
    """Fallback console when rich is unavailable."""

    def print(self, message: object = "") -> None:
        text = _RICH_TAG_RE.sub("", str(message))
        print(text)


console = Console() if Console is not None else PlainConsole()


def setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    if RichHandler is None:
        logging.basicConfig(level=level, format="%(message)s")
        return

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


def _require_scan_result(ctx: PipelineContext) -> ScanResult:
    """Return the completed scan result or terminate with a clear message."""

    if getattr(ctx, "scan_result", None) is None:
        console.print("[yellow]No scan results available.[/yellow]")
        sys.exit(1)
    return ctx.scan_result


def _print_scan_summary(result: ScanResult) -> None:
    """Print repository and scan-level result metrics."""

    console.print(f"\n{'=' * 60}")
    console.print(f"[bold]SCAN RESULTS: {result.repo_name}[/bold]")
    console.print(f"{'=' * 60}")
    console.print(f"  Branch: {result.branch} ({result.commit_hash[:8]})")
    console.print(f"  Files analyzed: {result.files_analyzed}")
    console.print(f"  Lines of code: {result.total_lines:,}")
    console.print(f"  Raw findings: {result.raw_findings_count}")
    console.print(f"  Duration: {result.scan_duration_seconds:.1f}s")


def _print_raw_findings(ctx: PipelineContext) -> None:
    """Print raw detector findings in their pipeline order."""

    if not ctx.raw_findings:
        return

    console.print("\n[bold]Raw Findings:[/bold]")
    for finding in ctx.raw_findings:
        console.print(
            f"  [{finding.detection_method.value}] {finding.vuln_type.value}: "
            f"{finding.file_path}:{finding.line_start} - {finding.message[:80]}"
        )


def _print_validated_findings(ctx: PipelineContext) -> None:
    """Print validated findings with status-specific colors."""

    if not ctx.validated_findings:
        return

    console.print("\n[bold]Validated Findings:[/bold]")
    for finding in ctx.validated_findings:
        status_color = {
            ValidationStatus.CONFIRMED: "red",
            ValidationStatus.LIKELY_FP: "green",
            ValidationStatus.UNCERTAIN: "yellow",
        }[finding.validation_status]
        console.print(
            f"  [{status_color}]{finding.validation_status.value}[/{status_color}] "
            f"{finding.enriched.severity.value.upper()} - "
            f"{finding.enriched.raw.vuln_type.value} in "
            f"{finding.enriched.raw.file_path}:{finding.enriched.raw.line_start} "
            f"(confidence: {finding.final_confidence:.2f})"
        )


def _print_scan_outcome(result: ScanResult, skip_llm: bool) -> None:
    """Print the final vulnerability outcome for a scan."""

    confirmed_count = len(result.confirmed_findings)
    if confirmed_count > 0:
        console.print(
            f"\n[bold red]{confirmed_count} confirmed vulnerabilities[/bold red]"
        )
    elif skip_llm:
        console.print(
            "\n[yellow]LLM analysis was skipped. "
            "Run without --skip-llm to validate findings.[/yellow]"
        )
    else:
        console.print("\n[bold green]No confirmed vulnerabilities.[/bold green]")


def _report_paths(result: ScanResult) -> tuple[Path, Path, Path]:
    """Build timestamped HTML, JSON, and SARIF report paths."""

    reports_dir = Path("reports")
    timestamp = result.scan_timestamp.strftime("%Y%m%d_%H%M%S")
    repo_slug = result.repo_name.replace("/", "_")
    return (
        reports_dir / f"{repo_slug}_{timestamp}.html",
        reports_dir / f"{repo_slug}_{timestamp}.json",
        reports_dir / f"{repo_slug}_{timestamp}.sarif.json",
    )


def _print_report_paths(
    html_path: Path,
    json_path: Path,
    sarif_path: Path,
) -> None:
    """Print generated report destinations."""

    console.print("\n[bold]Reports saved:[/bold]")
    console.print(f"  HTML: {html_path}")
    console.print(f"  JSON: {json_path}")
    console.print(f"  SARIF: {sarif_path}")
    console.print()


def _render_and_save_reports(ctx: PipelineContext, skip_llm: bool) -> None:
    """Print scan results and save reports for a completed pipeline context."""

    from securescan.report.generator import (
        generate_html_report,
        generate_json_report,
        generate_sarif_report,
    )

    result = _require_scan_result(ctx)
    _print_scan_summary(result)
    _print_raw_findings(ctx)
    _print_validated_findings(ctx)
    _print_scan_outcome(result, skip_llm)

    html_path, json_path, sarif_path = _report_paths(result)
    generate_html_report(result, ctx.patches or [], html_path)
    generate_json_report(result, ctx.patches or [], json_path)
    generate_sarif_report(result, ctx.patches or [], sarif_path)
    _print_report_paths(html_path, json_path, sarif_path)


def _print_banner() -> None:
    """Print the SecureScan command banner."""

    console.print("\n[bold]SecureScan[/bold] - AI-Powered Security Audit\n")


def _validate_llm_configuration(skip_llm: bool) -> None:
    """Validate LLM settings when the analysis stages are enabled."""

    if skip_llm:
        return

    errors = config.validate()
    if not errors:
        return

    for error in errors:
        console.print(f"[red]Config error:[/red] {error}")
    console.print("\nCopy .env.example to .env and fill in your API keys.")
    console.print("Or use --skip-llm to test detection only.")
    sys.exit(1)


def _invoke_pipeline(
    pipeline_runner: Callable[..., PipelineContext],
    pipeline_options: dict[str, object],
) -> PipelineContext:
    """Run a pipeline command with the CLI error boundary."""

    try:
        return pipeline_runner(**pipeline_options)
    except Exception as error:
        console.print(f"[red]Pipeline failed:[/red] {error}")
        logger.debug("Full traceback:", exc_info=True)
        sys.exit(1)


def _execute_analysis(
    pipeline_runner: Callable[..., PipelineContext],
    skip_llm: bool,
    pipeline_options: dict[str, object],
) -> None:
    """Run the shared command workflow for remote and local analysis."""

    _print_banner()
    _validate_llm_configuration(skip_llm)
    ctx = _invoke_pipeline(pipeline_runner, pipeline_options)
    _render_and_save_reports(ctx, skip_llm=skip_llm)


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
def main(verbose: bool) -> None:
    """SecureScan - AI-powered security audit pipeline."""
    setup_logging(verbose)


@main.command()
@click.argument("repo_url")
@click.option("--branch", "-b", default=None, help="Branch to analyze")
@click.option(
    "--config",
    type=click.Path(exists=True),
    default=None,
    help="Path to .securescan.yml config file",
)
@click.option(
    "--skip-llm",
    is_flag=True,
    help="Skip LLM analysis stages (useful for testing detection only)",
)
@click.option(
    "--diff",
    "diff_base",
    default=None,
    help="Only scan files changed vs this git ref (e.g., main, origin/main, HEAD~3)",
)
def analyze(
    repo_url: str,
    branch: str | None,
    config_path: str | None,
    skip_llm: bool,
    diff_base: str | None,
) -> None:
    """Analyze a GitHub repository for security vulnerabilities."""
    from securescan.pipeline import run_pipeline

    _execute_analysis(
        run_pipeline,
        skip_llm,
        {
            "repo_url": repo_url,
            "branch": branch,
            "skip_llm": skip_llm,
            "config_path": config_path,
            "diff_base": diff_base,
        },
    )


@main.command("analyze-local")
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True),
    default=None,
    help="Path to .securescan.yml",
)
@click.option(
    "--skip-llm",
    is_flag=True,
    help="Skip LLM analysis stages (useful for testing detection only)",
)
@click.option(
    "--diff",
    "diff_base",
    default=None,
    help="Only scan files changed vs this git ref (e.g., main, origin/main, HEAD~3)",
)
def analyze_local(
    path: str,
    config_path: str | None,
    skip_llm: bool,
    diff_base: str | None,
) -> None:
    """Analyze a local repository directory for security vulnerabilities."""
    from securescan.pipeline import run_pipeline

    _execute_analysis(
        run_pipeline,
        skip_llm,
        {
            "local_path": path,
            "skip_llm": skip_llm,
            "config_path": config_path,
            "diff_base": diff_base,
        },
    )


@main.command()
def version() -> None:
    """Show version information."""
    console.print("SecureScan v0.1.0")


if __name__ == "__main__":
    main()
