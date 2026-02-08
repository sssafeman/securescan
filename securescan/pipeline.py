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
import re
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from securescan.analyze.adversarial_reviewer import review_findings
from securescan.analyze.codebase_digest import build_digest
from securescan.analyze.opus_client import OpusClient
from securescan.analyze.vulnerability_analyzer import analyze_findings
from securescan.config import config
from securescan.diff import get_changed_files
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
from securescan.rule_config import RuleConfig

logger = logging.getLogger(__name__)

_GITHUB_REMOTE_RE = re.compile(
    r"github\.com[:/](?P<owner>[A-Za-z0-9._-]+)/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?$"
)


def _normalize_path(path: str) -> str:
    normalized = Path(path).as_posix()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized.startswith("/"):
        normalized = normalized[1:]
    return normalized


def _scoped_manifest(manifest: RepoManifest, scoped_files: list) -> RepoManifest:
    """Return a new manifest with file list restricted to scoped_files."""
    language_breakdown: dict[str, int] = {}
    risk_breakdown: dict[str, int] = {}
    for file_entry in scoped_files:
        language_breakdown[file_entry.language.value] = (
            language_breakdown.get(file_entry.language.value, 0) + 1
        )
        risk_breakdown[file_entry.risk_level.value] = (
            risk_breakdown.get(file_entry.risk_level.value, 0) + 1
        )

    filtered_out = max(0, manifest.total_files_included - len(scoped_files))
    return RepoManifest(
        files=scoped_files,
        total_files_discovered=manifest.total_files_discovered,
        total_files_included=len(scoped_files),
        total_files_excluded=manifest.total_files_excluded + filtered_out,
        total_lines=sum(file_entry.line_count for file_entry in scoped_files),
        total_estimated_tokens=sum(file_entry.estimated_tokens for file_entry in scoped_files),
        language_breakdown=language_breakdown,
        risk_breakdown=risk_breakdown,
    )


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
    repo_url: str | None = None,
    local_path: str | Path | None = None,
    branch: str | None = None,
    skip_llm: bool = False,
    config_path: str | Path | None = None,
    diff_base: str | None = None,
) -> PipelineContext:
    """Run the full SecureScan pipeline."""

    ctx = PipelineContext()
    start_time = time.time()

    if (repo_url is None) == (local_path is None):
        raise ValueError("Provide exactly one of repo_url or local_path")

    logger.info("=" * 60)
    logger.info("STAGE 1: INGEST")
    logger.info("=" * 60)
    if local_path is not None:
        ctx.repo_info = _build_local_repo_info(local_path, branch=branch)
    else:
        assert repo_url is not None
        ctx.repo_info = clone_repo(repo_url, branch=branch)

    rule_config_path: Path | None = None
    if config_path is not None:
        rule_config_path = Path(config_path)
    else:
        repo_rule_config = ctx.repo_info.local_path / ".securescan.yml"
        if repo_rule_config.exists():
            rule_config_path = repo_rule_config

    rule_config = RuleConfig.load(rule_config_path)
    logger.info(
        "Rule config: min_severity=%s, confidence_threshold=%.2f, "
        "max_concurrent=%d, max_retries=%d",
        rule_config.min_severity,
        rule_config.confidence_threshold,
        rule_config.max_concurrent,
        rule_config.max_retries,
    )

    logger.info("=" * 60)
    logger.info("STAGE 2: PARSE")
    logger.info("=" * 60)
    ctx.manifest = build_manifest(ctx.repo_info.local_path)
    ctx.dependencies = extract_dependencies(ctx.repo_info.local_path)

    changed_files: set[str] | None = None
    if diff_base:
        changed_list = get_changed_files(ctx.repo_info.local_path, diff_base)
        changed_files = {_normalize_path(path) for path in changed_list}
        before_count = len(ctx.manifest.files)
        scoped_files = [
            file_entry
            for file_entry in ctx.manifest.files
            if _normalize_path(file_entry.relative_path) in changed_files
        ]
        ctx.manifest = _scoped_manifest(ctx.manifest, scoped_files)
        logger.info(
            f"Diff filter: {len(ctx.manifest.files)}/{before_count} files in scope "
            f"(changed vs {diff_base})"
        )

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

    semgrep_targets: list[str] | None = None
    if changed_files is not None:
        semgrep_targets = sorted(
            path for path in changed_files if not rule_config.is_path_excluded(path)
        )

    semgrep_findings = run_semgrep(
        repo_path=ctx.repo_info.local_path,
        custom_rules_dir=semgrep_rules_dir if semgrep_rules_dir.exists() else None,
        target_files=semgrep_targets,
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
        rel_str = str(rel)
        rel_norm = _normalize_path(rel_str)
        if changed_files is not None and rel_norm not in changed_files:
            continue
        if rule_config.is_path_excluded(rel_str):
            continue
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
            secrets_file_list.append((rel_str, path))

    # Also include the manifest files to ensure we don't miss source code
    included_paths = {rel_path for rel_path, _ in secrets_file_list}
    for file_entry in ctx.manifest.files:
        if changed_files is not None and _normalize_path(file_entry.relative_path) not in changed_files:
            continue
        if rule_config.is_path_excluded(file_entry.relative_path):
            continue
        if file_entry.relative_path not in included_paths:
            secrets_file_list.append((file_entry.relative_path, file_entry.absolute_path))

    file_list = secrets_file_list
    secrets_findings = scan_repo_for_secrets(
        repo_path=ctx.repo_info.local_path,
        files=file_list,
    )
    ctx.raw_findings.extend(secrets_findings)

    filtered_disabled_checks = 0
    filtered_excluded_paths = 0
    filtered_findings: list[RawFinding] = []
    for finding in ctx.raw_findings:
        vuln_type = finding.vuln_type.value
        if not rule_config.is_check_enabled(vuln_type):
            filtered_disabled_checks += 1
            continue
        if rule_config.is_path_excluded(finding.file_path):
            filtered_excluded_paths += 1
            continue
        filtered_findings.append(finding)
    ctx.raw_findings = filtered_findings

    filtered_total = filtered_disabled_checks + filtered_excluded_paths
    if filtered_total > 0:
        logger.info(
            f"Filtered {filtered_total} raw findings by config "
            f"({filtered_disabled_checks} disabled checks, "
            f"{filtered_excluded_paths} excluded paths)"
        )

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
            max_workers=rule_config.max_concurrent,
        )

        if not ctx.enriched_findings:
            logger.info("All findings rejected by analysis. Pipeline complete.")
            ctx.validated_findings = []
        else:
            before_severity_filter = len(ctx.enriched_findings)
            ctx.enriched_findings = [
                finding
                for finding in ctx.enriched_findings
                if rule_config.meets_severity_threshold(finding.severity.value)
            ]
            severity_filtered = before_severity_filter - len(ctx.enriched_findings)
            if severity_filtered > 0:
                logger.info(
                    f"Filtered {severity_filtered} analyzed findings below "
                    f"min_severity={rule_config.min_severity}"
                )

            if not ctx.enriched_findings:
                logger.info(
                    "All findings filtered out by severity threshold. "
                    "Pipeline complete."
                )
                ctx.validated_findings = []
            else:
                logger.info("=" * 60)
                logger.info("STAGE 5: VALIDATE (Adversarial Review)")
                logger.info("=" * 60)

                ctx.validated_findings = review_findings(
                    client=client,
                    findings=ctx.enriched_findings,
                    digest=digest,
                    confidence_threshold=rule_config.confidence_threshold,
                    max_workers=rule_config.max_concurrent,
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
                    max_workers=rule_config.max_concurrent,
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

    try:
        from securescan.report.generator import generate_sarif_report

        sarif_path = generate_sarif_report(
            result=ctx.scan_result,
            patches=ctx.patches or [],
        )
        logger.info(f"SARIF report saved to {sarif_path}")
    except Exception as e:
        logger.warning(f"SARIF report generation failed: {e}")

    logger.info("=" * 60)
    logger.info(
        f"PIPELINE COMPLETE: {len(confirmed)} confirmed findings "
        f"from {len(ctx.raw_findings)} raw detections "
        f"({ctx.scan_result.scan_duration_seconds:.1f}s)"
    )
    logger.info("=" * 60)

    return ctx


def _run_git_command(repo_path: Path, *args: str) -> str | None:
    """Run a git command and return stripped stdout when successful."""
    result = subprocess.run(
        ["git", *args],
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def _infer_repo_name_from_remote(remote_url: str | None, local_path: Path) -> str:
    """Infer repo name from remote URL, fallback to local directory name."""
    if remote_url:
        match = _GITHUB_REMOTE_RE.search(remote_url.strip())
        if match:
            return f"{match.group('owner')}/{match.group('repo')}"
    return local_path.name


def _build_local_repo_info(
    local_path: str | Path,
    branch: str | None = None,
) -> RepoInfo:
    """Build RepoInfo from an existing local directory (no clone)."""
    resolved_path = Path(local_path).expanduser().resolve()
    if not resolved_path.exists() or not resolved_path.is_dir():
        raise ValueError(f"Local path does not exist or is not a directory: {local_path}")

    remote_url = _run_git_command(resolved_path, "remote", "get-url", "origin")
    repo_name = _infer_repo_name_from_remote(remote_url, resolved_path)
    detected_branch = _run_git_command(resolved_path, "rev-parse", "--abbrev-ref", "HEAD")
    commit_hash = _run_git_command(resolved_path, "rev-parse", "HEAD")
    commit_date_raw = _run_git_command(resolved_path, "show", "-s", "--format=%cI", "HEAD")

    commit_date = datetime.now()
    if commit_date_raw:
        try:
            commit_date = datetime.fromisoformat(commit_date_raw.replace("Z", "+00:00"))
        except ValueError:
            pass

    info = RepoInfo(
        name=repo_name,
        local_path=resolved_path,
        url=remote_url or resolved_path.as_uri(),
        branch=branch or detected_branch or "local",
        commit_hash=commit_hash or "local",
        commit_date=commit_date,
        clone_depth=0,
    )
    logger.info(
        f"Using local repository {info.name} @ {info.commit_hash[:8]} "
        f"({info.branch}, {info.commit_date.isoformat()})"
    )
    return info
