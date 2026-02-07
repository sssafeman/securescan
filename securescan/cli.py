"""SecureScan CLI - entry point for the security audit pipeline."""

import logging
import re
import sys

import click

try:
    from rich.console import Console
    from rich.logging import RichHandler
except ModuleNotFoundError:  # pragma: no cover - fallback for minimal envs
    Console = None
    RichHandler = None

from securescan.config import config
from securescan.ingest.manifest import build_manifest
from securescan.ingest.repo import IngestError, clone_repo

_RICH_TAG_RE = re.compile(r"\[/?[a-zA-Z0-9 _-]+\]")


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


@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
def main(verbose: bool) -> None:
    """SecureScan - AI-powered security audit pipeline."""
    setup_logging(verbose)


@main.command()
@click.argument("repo_url")
@click.option("--branch", "-b", default=None, help="Branch to analyze")
@click.option(
    "--skip-llm",
    is_flag=True,
    help="Skip LLM analysis stages (useful for testing detection only)",
)
def analyze(repo_url: str, branch: str | None, skip_llm: bool) -> None:
    """Analyze a GitHub repository for security vulnerabilities."""
    from securescan.detect.models import Severity, ValidationStatus
    from securescan.pipeline import PipelineContext, run_pipeline

    console.print("\n[bold]SecureScan[/bold] - AI-Powered Security Audit\n")

    # Validate config (skip API key check if --skip-llm)
    if not skip_llm:
        errors = config.validate()
        if errors:
            for err in errors:
                console.print(f"[red]Config error:[/red] {err}")
            console.print("\nCopy .env.example to .env and fill in your API keys.")
            console.print("Or use --skip-llm to test detection only.")
            sys.exit(1)

    try:
        ctx = run_pipeline(repo_url, branch=branch, skip_llm=skip_llm)
    except Exception as e:
        console.print(f"[red]Pipeline failed:[/red] {e}")
        logger = logging.getLogger(__name__)
        logger.debug("Full traceback:", exc_info=True)
        sys.exit(1)

    # Keep imported names intentionally for parity with requested interface.
    del PipelineContext, Severity

    # Display results
    if ctx.scan_result is None:
        console.print("[yellow]No scan results available.[/yellow]")
        sys.exit(1)

    result = ctx.scan_result
    console.print(f"\n{'=' * 60}")
    console.print(f"[bold]SCAN RESULTS: {result.repo_name}[/bold]")
    console.print(f"{'=' * 60}")
    console.print(f"  Branch: {result.branch} ({result.commit_hash[:8]})")
    console.print(f"  Files analyzed: {result.files_analyzed}")
    console.print(f"  Lines of code: {result.total_lines:,}")
    console.print(f"  Raw findings: {result.raw_findings_count}")
    console.print(f"  Duration: {result.scan_duration_seconds:.1f}s")

    if ctx.raw_findings:
        console.print("\n[bold]Raw Findings:[/bold]")
        for finding in ctx.raw_findings:
            console.print(
                f"  [{finding.detection_method.value}] {finding.vuln_type.value}: "
                f"{finding.file_path}:{finding.line_start} - {finding.message[:80]}"
            )

    if ctx.validated_findings:
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

    console.print()


@main.command()
def version() -> None:
    """Show version information."""
    console.print("SecureScan v0.1.0")


if __name__ == "__main__":
    main()
