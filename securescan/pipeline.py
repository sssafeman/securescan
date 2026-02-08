"""Main pipeline orchestrator.

Wires together all stages of the SecureScan pipeline:
1. Ingest (clone + manifest)
2. Parse (AST extraction)
3. Detect (semgrep + secrets scanner)
4. Analyze (LLM semantic analysis)
5. Validate (adversarial false-positive review)
6. Remediate (patch generation)
7. Report (summary generation)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from securescan.analyze.adversarial_reviewer import review_findings
from securescan.analyze.codebase_digest import build_digest
from securescan.analyze.opus_client import OpusClient
from securescan.analyze.vulnerability_analyzer import analyze_findings
from securescan.config import config
from securescan.detect.models import (
    EnrichedFinding,
    Patch,
    RawFinding,
    ScanResult,
    ValidatedFinding,
)
from securescan.detect.secrets_scanner import scan_repo_for_secrets
from securescan.detect.semgrep_runner import run_semgrep
from securescan.ingest.manifest import RepoManifest, build_manifest
from securescan.ingest.repo import RepoInfo, clone_repo
from securescan.parse.dependencies import DependencyManifest, extract_dependencies
from securescan.parse.treesitter import ParsedFile, parse_file

logger = logging.getLogger(__name__)


@dataclass
class PipelineContext:
    """Accumulated state as the pipeline progresses."""

    repo_info: RepoInfo | None = None
    manifest: RepoManifest | None = None
    parsed_files: dict[str, ParsedFile] | None = None
    dependencies: DependencyManifest | None = None
    raw_findings: list[RawFinding] | None = None
    enriched_findings: list[EnrichedFinding] | None = None
    validated_findings: list[ValidatedFinding] | None = None
    patches: list[Patch] | None = None
    scan_result: ScanResult | None = None


def run_pipeline(
    repo_url: str,
    branch: str | None = None,
    skip_llm: bool = False,
) -> PipelineContext:
    """Run the full SecureScan pipeline."""

    ctx = PipelineContext()
    start_time = time.time()

    logger.info("=" * 60)
    logger.info("STAGE 1: INGEST")
    logger.info("=" * 60)
    ctx.repo_info = clone_repo(repo_url, branch=branch)

    logger.info("=" * 60)
    logger.info("STAGE 2: PARSE")
    logger.info("=" * 60)
    ctx.manifest = build_manifest(ctx.repo_info.local_path)
    ctx.dependencies = extract_dependencies(ctx.repo_info.local_path)

    ctx.parsed_files = {}
    for file_entry in ctx.manifest.files:
        parsed = parse_file(
            file_entry.relative_path,
            file_entry.absolute_path,
            file_entry.language.value,
        )
        ctx.parsed_files[file_entry.relative_path] = parsed

    total_funcs = sum(len(parsed.functions) for parsed in ctx.parsed_files.values())
    total_dangerous = sum(len(parsed.dangerous_calls) for parsed in ctx.parsed_files.values())
    logger.info(
        f"Parsed {len(ctx.parsed_files)} files: "
        f"{total_funcs} functions, {total_dangerous} dangerous calls"
    )

    logger.info("=" * 60)
    logger.info("STAGE 3: DETECT")
    logger.info("=" * 60)
    ctx.raw_findings = []

    semgrep_rules_dir = Path(__file__).parent.parent / "semgrep_rules"
    if not semgrep_rules_dir.exists():
        semgrep_rules_dir = Path("semgrep_rules")

    semgrep_findings = run_semgrep(
        repo_path=ctx.repo_info.local_path,
        custom_rules_dir=semgrep_rules_dir if semgrep_rules_dir.exists() else None,
    )
    ctx.raw_findings.extend(semgrep_findings)

    # 3b: Secrets scanner - scan ALL text files, not just source code
    # Secrets can be in config files, .env files, .key files, etc.
    secrets_file_list: list[tuple[str, Path]] = []
    secrets_extensions = {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".mjs",
        ".cjs",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".cfg",
        ".ini",
        ".conf",
        ".env",
        ".properties",
        ".xml",
        ".key",
        ".pem",
        ".cert",
        ".sh",
        ".bash",
        ".zsh",
        ".bat",
        ".ps1",
        ".rb",
        ".go",
        ".rs",
        ".java",
        ".cs",
        ".php",
        ".tf",
        ".hcl",
        ".dockerfile",
        "",
    }
    secrets_skip_dirs = set(config.skip_dirs)

    for path in sorted(ctx.repo_info.local_path.rglob("*")):
        if not path.is_file():
            continue

        rel = path.relative_to(ctx.repo_info.local_path)
        if any(part in secrets_skip_dirs or part.startswith(".") for part in rel.parts[:-1]):
            continue

        if path.suffix.lower() in secrets_extensions or path.name.lower() in (
            "dockerfile",
            ".env",
            ".env.example",
            ".env.local",
            ".env.production",
            ".env.development",
        ):
            secrets_file_list.append((str(rel), path))

    # Also include the manifest files to ensure we don't miss source code
    included_paths = {rel_path for rel_path, _ in secrets_file_list}
    for file_entry in ctx.manifest.files:
        if file_entry.relative_path not in included_paths:
            secrets_file_list.append((file_entry.relative_path, file_entry.absolute_path))

    file_list = secrets_file_list
    secrets_findings = scan_repo_for_secrets(
        repo_path=ctx.repo_info.local_path,
        files=file_list,
    )
    ctx.raw_findings.extend(secrets_findings)

    # Deduplicate findings on same file+line (keep highest confidence)
    seen: dict[tuple[str, int], RawFinding] = {}
    for f in ctx.raw_findings:
        key = (f.file_path, f.line_start)
        if key not in seen or f.confidence > seen[key].confidence:
            seen[key] = f
    ctx.raw_findings = list(seen.values())

    logger.info(
        f"Detection complete: {len(ctx.raw_findings)} raw findings "
        f"({len(semgrep_findings)} semgrep + {len(secrets_findings)} secrets)"
    )

    if not ctx.raw_findings:
        logger.info("No findings detected. Pipeline complete.")
        ctx.scan_result = ScanResult(
            repo_name=ctx.repo_info.name,
            repo_url=ctx.repo_info.url,
            branch=ctx.repo_info.branch,
            commit_hash=ctx.repo_info.commit_hash,
            scan_timestamp=datetime.now(),
            files_analyzed=ctx.manifest.total_files_included,
            total_lines=ctx.manifest.total_lines,
            raw_findings_count=0,
            confirmed_findings=[],
            patches=[],
            scan_duration_seconds=time.time() - start_time,
        )
        return ctx

    if skip_llm:
        logger.info("LLM analysis skipped (--skip-llm flag)")
        ctx.scan_result = ScanResult(
            repo_name=ctx.repo_info.name,
            repo_url=ctx.repo_info.url,
            branch=ctx.repo_info.branch,
            commit_hash=ctx.repo_info.commit_hash,
            scan_timestamp=datetime.now(),
            files_analyzed=ctx.manifest.total_files_included,
            total_lines=ctx.manifest.total_lines,
            raw_findings_count=len(ctx.raw_findings),
            confirmed_findings=[],
            patches=[],
            scan_duration_seconds=time.time() - start_time,
        )
        return ctx

    logger.info("=" * 60)
    logger.info("STAGE 4: ANALYZE (Opus 4.6)")
    logger.info("=" * 60)

    digest = build_digest(
        manifest=ctx.manifest,
        repo_root=ctx.repo_info.local_path,
        parsed_files=ctx.parsed_files,
        raw_findings=ctx.raw_findings,
    )

    ctx.patches = []
    executive_summary = ""

    with OpusClient() as client:
        ctx.enriched_findings = analyze_findings(
            client=client,
            findings=ctx.raw_findings,
            digest=digest,
            repo_name=ctx.repo_info.name,
            max_workers=config.max_concurrent_llm_calls,
        )

        if not ctx.enriched_findings:
            logger.info("All findings rejected by analysis. Pipeline complete.")
            ctx.validated_findings = []
        else:
            logger.info("=" * 60)
            logger.info("STAGE 5: VALIDATE (Adversarial Review)")
            logger.info("=" * 60)

            ctx.validated_findings = review_findings(
                client=client,
                findings=ctx.enriched_findings,
                digest=digest,
                confidence_threshold=config.confidence_threshold,
                max_workers=config.max_concurrent_llm_calls,
            )

        confirmed = [finding for finding in (ctx.validated_findings or []) if finding.is_confirmed]

        # Stage 6: Remediate
        if confirmed:
            logger.info("=" * 60)
            logger.info("STAGE 6: REMEDIATE (Anthropic Patch Generation)")
            logger.info("=" * 60)

            try:
                from securescan.remediate.patch_generator import generate_patches

                ctx.patches = generate_patches(
                    client=client,
                    findings=ctx.validated_findings or [],
                    repo_root=ctx.repo_info.local_path,
                    max_workers=config.max_concurrent_llm_calls,
                )
            except Exception as e:
                logger.warning(f"Patch generation failed: {e}")
                ctx.patches = []

        # Stage 7: Report
        logger.info("=" * 60)
        logger.info("STAGE 7: REPORT")
        logger.info("=" * 60)

        if confirmed:
            try:
                summary_response = client.analyze(
                    system_prompt=(
                        "You are a security report writer. Write a concise 2-3 sentence "
                        "executive summary in plain text. Do NOT use markdown formatting - "
                        "no headers, no bold, no bullet points."
                    ),
                    user_prompt=(
                        f"Repository: {ctx.repo_info.name}\n"
                        f"Confirmed vulnerabilities: {len(confirmed)}\n"
                        f"Types: {', '.join(set(f.enriched.raw.vuln_type.value for f in confirmed))}\n"
                        f"Severities: {', '.join(set(f.enriched.severity.value for f in confirmed))}\n"
                        "Write a 2-3 sentence executive summary for a security audit report.\n"
                        "Respond in plain text only, no markdown."
                    ),
                    max_tokens=300,
                    temperature=0.3,
                )
                if summary_response.success:
                    executive_summary = summary_response.content
            except Exception:
                executive_summary = (
                    f"SecureScan identified {len(confirmed)} confirmed vulnerabilities in "
                    f"{ctx.repo_info.name}. Manual review and remediation is recommended."
                )

        logger.info(client.usage.summary())

    confirmed = [finding for finding in (ctx.validated_findings or []) if finding.is_confirmed]

    ctx.scan_result = ScanResult(
        repo_name=ctx.repo_info.name,
        repo_url=ctx.repo_info.url,
        branch=ctx.repo_info.branch,
        commit_hash=ctx.repo_info.commit_hash,
        scan_timestamp=datetime.now(),
        files_analyzed=ctx.manifest.total_files_included,
        total_lines=ctx.manifest.total_lines,
        raw_findings_count=len(ctx.raw_findings),
        confirmed_findings=confirmed,
        patches=ctx.patches or [],
        executive_summary=executive_summary,
        scan_duration_seconds=time.time() - start_time,
    )

    logger.info("=" * 60)
    logger.info(
        f"PIPELINE COMPLETE: {len(confirmed)} confirmed findings "
        f"from {len(ctx.raw_findings)} raw detections "
        f"({ctx.scan_result.scan_duration_seconds:.1f}s)"
    )
    logger.info("=" * 60)

    return ctx
