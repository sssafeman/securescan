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
from securescan.analyze.codebase_digest import CodebaseDigest, build_digest
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
_STAGE_SEPARATOR = "=" * 60
_SECRETS_EXTENSIONS = frozenset(
    {
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
)
_SECRETS_FILENAMES = frozenset(
    {
        "dockerfile",
        ".env",
        ".env.example",
        ".env.local",
        ".env.production",
        ".env.development",
    }
)
_SUMMARY_SYSTEM_PROMPT = (
    "You are a security report writer. Write a concise 2-3 sentence "
    "executive summary in plain text. Do NOT use markdown formatting - "
    "no headers, no bold, no bullet points."
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


def _log_stage(label: str) -> None:
    """Log a consistently formatted pipeline stage heading."""

    logger.info(_STAGE_SEPARATOR)
    logger.info(label)
    logger.info(_STAGE_SEPARATOR)


def _ingest_repository(
    repo_url: str | None,
    local_path: str | Path | None,
    branch: str | None,
) -> RepoInfo:
    """Load repository metadata from a local path or remote URL."""

    if local_path is not None:
        return _build_local_repo_info(local_path, branch=branch)
    assert repo_url is not None
    return clone_repo(repo_url, branch=branch)


def _load_rule_config(
    repo_path: Path,
    config_path: str | Path | None,
) -> RuleConfig:
    """Load the applicable rule configuration and log its runtime settings."""

    rule_config_path: Path | None = None
    if config_path is not None:
        rule_config_path = Path(config_path)
    else:
        repo_rule_config = repo_path / ".securescan.yml"
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
    return rule_config


def _apply_diff_scope(
    manifest: RepoManifest,
    repo_path: Path,
    diff_base: str | None,
) -> tuple[RepoManifest, set[str] | None]:
    """Restrict a manifest to files changed from the requested base ref."""

    if not diff_base:
        return manifest, None

    changed_list = get_changed_files(repo_path, diff_base)
    changed_files = {_normalize_path(path) for path in changed_list}
    before_count = len(manifest.files)
    scoped_files = [
        file_entry
        for file_entry in manifest.files
        if _normalize_path(file_entry.relative_path) in changed_files
    ]
    scoped_manifest = _scoped_manifest(manifest, scoped_files)
    logger.info(
        f"Diff filter: {len(scoped_manifest.files)}/{before_count} files in scope "
        f"(changed vs {diff_base})"
    )
    return scoped_manifest, changed_files


def _parse_manifest_files(manifest: RepoManifest) -> dict[str, ParsedFile]:
    """Parse every file included in a repository manifest."""

    parsed_files: dict[str, ParsedFile] = {}
    for file_entry in manifest.files:
        parsed_files[file_entry.relative_path] = parse_file(
            file_entry.relative_path,
            file_entry.absolute_path,
            file_entry.language.value,
        )

    total_functions = sum(len(parsed.functions) for parsed in parsed_files.values())
    total_dangerous = sum(len(parsed.dangerous_calls) for parsed in parsed_files.values())
    logger.info(
        f"Parsed {len(parsed_files)} files: "
        f"{total_functions} functions, {total_dangerous} dangerous calls"
    )
    return parsed_files


def _resolve_semgrep_rules_dir() -> Path:
    """Locate bundled Semgrep rules with a working-directory fallback."""

    rules_dir = Path(__file__).parent.parent / "semgrep_rules"
    return rules_dir if rules_dir.exists() else Path("semgrep_rules")


def _semgrep_target_files(
    changed_files: set[str] | None,
    rule_config: RuleConfig,
) -> list[str] | None:
    """Build the explicit Semgrep target list for a diff scan."""

    if changed_files is None:
        return None
    return sorted(
        path for path in changed_files if not rule_config.is_path_excluded(path)
    )


def _is_secret_scan_candidate(path: Path) -> bool:
    """Return whether a file is eligible for the custom secrets scanner."""

    return (
        path.suffix.lower() in _SECRETS_EXTENSIONS
        or path.name.lower() in _SECRETS_FILENAMES
    )


def _collect_secret_files(
    repo_path: Path,
    manifest: RepoManifest,
    changed_files: set[str] | None,
    rule_config: RuleConfig,
) -> list[tuple[str, Path]]:
    """Collect text and manifest files eligible for secrets scanning."""

    secret_files: list[tuple[str, Path]] = []
    skipped_directories = set(config.skip_dirs)

    for path in sorted(repo_path.rglob("*")):
        if not path.is_file():
            continue

        relative_path = path.relative_to(repo_path)
        relative_string = str(relative_path)
        normalized_path = _normalize_path(relative_string)
        if changed_files is not None and normalized_path not in changed_files:
            continue
        if rule_config.is_path_excluded(relative_string):
            continue
        if any(
            part in skipped_directories or part.startswith(".")
            for part in relative_path.parts[:-1]
        ):
            continue
        if _is_secret_scan_candidate(path):
            secret_files.append((relative_string, path))

    included_paths = {relative_path for relative_path, _ in secret_files}
    for file_entry in manifest.files:
        normalized_path = _normalize_path(file_entry.relative_path)
        if changed_files is not None and normalized_path not in changed_files:
            continue
        if rule_config.is_path_excluded(file_entry.relative_path):
            continue
        if file_entry.relative_path not in included_paths:
            secret_files.append((file_entry.relative_path, file_entry.absolute_path))

    return secret_files


def _filter_raw_findings(
    findings: list[RawFinding],
    rule_config: RuleConfig,
) -> list[RawFinding]:
    """Apply enabled-check and excluded-path policy to raw findings."""

    disabled_checks = 0
    excluded_paths = 0
    filtered_findings: list[RawFinding] = []
    for finding in findings:
        if not rule_config.is_check_enabled(finding.vuln_type.value):
            disabled_checks += 1
            continue
        if rule_config.is_path_excluded(finding.file_path):
            excluded_paths += 1
            continue
        filtered_findings.append(finding)

    filtered_total = disabled_checks + excluded_paths
    if filtered_total > 0:
        logger.info(
            f"Filtered {filtered_total} raw findings by config "
            f"({disabled_checks} disabled checks, "
            f"{excluded_paths} excluded paths)"
        )
    return filtered_findings


def _deduplicate_findings(findings: list[RawFinding]) -> list[RawFinding]:
    """Keep the highest-confidence finding at each file and line location."""

    findings_by_location: dict[tuple[str, int], RawFinding] = {}
    for finding in findings:
        key = (finding.file_path, finding.line_start)
        current = findings_by_location.get(key)
        if current is None or finding.confidence > current.confidence:
            findings_by_location[key] = finding
    return list(findings_by_location.values())


def _run_detection(
    repo_info: RepoInfo,
    manifest: RepoManifest,
    changed_files: set[str] | None,
    rule_config: RuleConfig,
) -> list[RawFinding]:
    """Run configured detectors and apply raw finding policy."""

    semgrep_rules_dir = _resolve_semgrep_rules_dir()
    semgrep_findings = run_semgrep(
        repo_path=repo_info.local_path,
        custom_rules_dir=semgrep_rules_dir if semgrep_rules_dir.exists() else None,
        target_files=_semgrep_target_files(changed_files, rule_config),
    )
    secret_files = _collect_secret_files(
        repo_info.local_path,
        manifest,
        changed_files,
        rule_config,
    )
    secrets_findings = scan_repo_for_secrets(
        repo_path=repo_info.local_path,
        files=secret_files,
    )

    findings: list[RawFinding] = []
    findings.extend(semgrep_findings)
    findings.extend(secrets_findings)
    findings = _filter_raw_findings(findings, rule_config)
    findings = _deduplicate_findings(findings)
    logger.info(
        f"Detection complete: {len(findings)} raw findings "
        f"({len(semgrep_findings)} semgrep + {len(secrets_findings)} secrets)"
    )
    return findings


def _build_scan_result(
    ctx: PipelineContext,
    start_time: float,
    confirmed_findings: list[ValidatedFinding],
    executive_summary: str = "",
) -> ScanResult:
    """Build a scan result from the current pipeline context."""

    assert ctx.repo_info is not None
    assert ctx.manifest is not None
    return ScanResult(
        repo_name=ctx.repo_info.name,
        repo_url=ctx.repo_info.url,
        branch=ctx.repo_info.branch,
        commit_hash=ctx.repo_info.commit_hash,
        scan_timestamp=datetime.now(),
        files_analyzed=ctx.manifest.total_files_included,
        total_lines=ctx.manifest.total_lines,
        raw_findings_count=len(ctx.raw_findings or []),
        confirmed_findings=confirmed_findings,
        patches=ctx.patches or [],
        executive_summary=executive_summary,
        scan_duration_seconds=time.time() - start_time,
    )


def _filter_enriched_findings(
    findings: list[EnrichedFinding],
    rule_config: RuleConfig,
) -> list[EnrichedFinding]:
    """Apply the configured minimum severity to analyzed findings."""

    filtered_findings = [
        finding
        for finding in findings
        if rule_config.meets_severity_threshold(finding.severity.value)
    ]
    filtered_count = len(findings) - len(filtered_findings)
    if filtered_count > 0:
        logger.info(
            f"Filtered {filtered_count} analyzed findings below "
            f"min_severity={rule_config.min_severity}"
        )
    return filtered_findings


def _analyze_and_validate(
    client: OpusClient,
    ctx: PipelineContext,
    digest: CodebaseDigest,
    rule_config: RuleConfig,
) -> None:
    """Analyze raw findings and validate those meeting severity policy."""

    assert ctx.raw_findings is not None
    assert ctx.repo_info is not None
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
        return

    ctx.enriched_findings = _filter_enriched_findings(
        ctx.enriched_findings,
        rule_config,
    )
    if not ctx.enriched_findings:
        logger.info(
            "All findings filtered out by severity threshold. "
            "Pipeline complete."
        )
        ctx.validated_findings = []
        return

    _log_stage("STAGE 5: VALIDATE (Adversarial Review)")
    ctx.validated_findings = review_findings(
        client=client,
        findings=ctx.enriched_findings,
        digest=digest,
        confidence_threshold=rule_config.confidence_threshold,
        max_workers=rule_config.max_concurrent,
    )


def _confirmed_findings(ctx: PipelineContext) -> list[ValidatedFinding]:
    """Return confirmed findings currently held by a pipeline context."""

    return [
        finding
        for finding in (ctx.validated_findings or [])
        if finding.is_confirmed
    ]


def _generate_patches(
    client: OpusClient,
    ctx: PipelineContext,
    confirmed_findings: list[ValidatedFinding],
    max_workers: int,
) -> None:
    """Generate remediation patches for confirmed findings when possible."""

    if not confirmed_findings:
        return

    assert ctx.repo_info is not None
    _log_stage("STAGE 6: REMEDIATE (Anthropic Patch Generation)")
    try:
        from securescan.remediate.patch_generator import generate_patches

        ctx.patches = generate_patches(
            client=client,
            findings=ctx.validated_findings or [],
            repo_root=ctx.repo_info.local_path,
            max_workers=max_workers,
        )
    except Exception as error:
        logger.warning(f"Patch generation failed: {error}")
        ctx.patches = []


def _generate_executive_summary(
    client: OpusClient,
    ctx: PipelineContext,
    confirmed_findings: list[ValidatedFinding],
) -> str:
    """Generate a concise executive summary for confirmed findings."""

    if not confirmed_findings:
        return ""

    assert ctx.repo_info is not None
    try:
        vulnerability_types = ", ".join(
            set(finding.enriched.raw.vuln_type.value for finding in confirmed_findings)
        )
        severities = ", ".join(
            set(finding.enriched.severity.value for finding in confirmed_findings)
        )
        summary_response = client.analyze(
            system_prompt=_SUMMARY_SYSTEM_PROMPT,
            user_prompt=(
                f"Repository: {ctx.repo_info.name}\n"
                f"Confirmed vulnerabilities: {len(confirmed_findings)}\n"
                f"Types: {vulnerability_types}\n"
                f"Severities: {severities}\n"
                "Write a 2-3 sentence executive summary for a security audit report.\n"
                "Respond in plain text only, no markdown."
            ),
            max_tokens=300,
            temperature=0.3,
        )
        return summary_response.content if summary_response.success else ""
    except Exception:
        return (
            f"SecureScan identified {len(confirmed_findings)} confirmed vulnerabilities in "
            f"{ctx.repo_info.name}. Manual review and remediation is recommended."
        )


def _run_llm_stages(
    ctx: PipelineContext,
    rule_config: RuleConfig,
) -> str:
    """Run analysis, validation, remediation, and summary stages."""

    assert ctx.manifest is not None
    assert ctx.repo_info is not None
    assert ctx.parsed_files is not None
    assert ctx.raw_findings is not None
    _log_stage("STAGE 4: ANALYZE (Opus 4.6)")
    digest = build_digest(
        manifest=ctx.manifest,
        repo_root=ctx.repo_info.local_path,
        parsed_files=ctx.parsed_files,
        raw_findings=ctx.raw_findings,
    )
    ctx.patches = []

    with OpusClient() as client:
        _analyze_and_validate(client, ctx, digest, rule_config)
        confirmed_findings = _confirmed_findings(ctx)
        _generate_patches(
            client,
            ctx,
            confirmed_findings,
            rule_config.max_concurrent,
        )
        _log_stage("STAGE 7: REPORT")
        executive_summary = _generate_executive_summary(
            client,
            ctx,
            confirmed_findings,
        )
        logger.info(client.usage.summary())

    return executive_summary


def _generate_sarif(ctx: PipelineContext) -> None:
    """Generate the pipeline SARIF report without failing the scan."""

    assert ctx.scan_result is not None
    try:
        from securescan.report.generator import generate_sarif_report

        sarif_path = generate_sarif_report(
            result=ctx.scan_result,
            patches=ctx.patches or [],
        )
        logger.info(f"SARIF report saved to {sarif_path}")
    except Exception as error:
        logger.warning(f"SARIF report generation failed: {error}")


def _log_pipeline_complete(
    ctx: PipelineContext,
    confirmed_findings: list[ValidatedFinding],
) -> None:
    """Log final pipeline counts and duration."""

    assert ctx.raw_findings is not None
    assert ctx.scan_result is not None
    logger.info(_STAGE_SEPARATOR)
    logger.info(
        f"PIPELINE COMPLETE: {len(confirmed_findings)} confirmed findings "
        f"from {len(ctx.raw_findings)} raw detections "
        f"({ctx.scan_result.scan_duration_seconds:.1f}s)"
    )
    logger.info(_STAGE_SEPARATOR)


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

    _log_stage("STAGE 1: INGEST")
    ctx.repo_info = _ingest_repository(repo_url, local_path, branch)
    rule_config = _load_rule_config(ctx.repo_info.local_path, config_path)

    _log_stage("STAGE 2: PARSE")
    ctx.manifest = build_manifest(ctx.repo_info.local_path)
    ctx.dependencies = extract_dependencies(ctx.repo_info.local_path)
    ctx.manifest, changed_files = _apply_diff_scope(
        ctx.manifest,
        ctx.repo_info.local_path,
        diff_base,
    )
    ctx.parsed_files = _parse_manifest_files(ctx.manifest)

    _log_stage("STAGE 3: DETECT")
    ctx.raw_findings = _run_detection(
        ctx.repo_info,
        ctx.manifest,
        changed_files,
        rule_config,
    )
    if not ctx.raw_findings:
        logger.info("No findings detected. Pipeline complete.")
        ctx.scan_result = _build_scan_result(ctx, start_time, [])
        return ctx

    if skip_llm:
        logger.info("LLM analysis skipped (--skip-llm flag)")
        ctx.scan_result = _build_scan_result(ctx, start_time, [])
        return ctx

    executive_summary = _run_llm_stages(ctx, rule_config)
    confirmed_findings = _confirmed_findings(ctx)
    ctx.scan_result = _build_scan_result(
        ctx,
        start_time,
        confirmed_findings,
        executive_summary,
    )
    _generate_sarif(ctx)
    _log_pipeline_complete(ctx, confirmed_findings)
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
