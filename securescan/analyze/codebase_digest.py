"""Codebase digest builder for LLM context optimization.

Constructs a structured document containing the most security-relevant
parts of a codebase, optimized to fit within the LLM's context window.
Prioritizes high-risk files and code surrounding detected findings.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from securescan.detect.models import RawFinding
from securescan.ingest.manifest import FileEntry, RepoManifest, RiskLevel
from securescan.parse.treesitter import ParsedFile

logger = logging.getLogger(__name__)

# Conservative token budget - leave room for system prompt + response
MAX_CONTEXT_TOKENS = 600_000
TOKENS_PER_CHAR = 0.25  # Rough estimate: 1 token ~= 4 chars

# How many context lines to include around each finding
FINDING_CONTEXT_LINES = 20


@dataclass
class DigestSection:
    """A section of the codebase digest."""

    heading: str
    content: str
    estimated_tokens: int
    priority: int = 0


@dataclass
class CodebaseDigest:
    """Complete digest ready for LLM consumption."""

    sections: list[DigestSection]
    total_estimated_tokens: int
    files_included: int
    files_excluded: int
    truncated: bool

    def render(self) -> str:
        """Render the digest as a single string for the LLM."""

        parts: list[str] = []
        for section in self.sections:
            parts.append(f"## {section.heading}\n")
            parts.append(section.content)
            parts.append("")
        return "\n".join(parts)


def _estimate_tokens(text: str) -> int:
    """Estimate token count from text length."""

    return int(len(text) * TOKENS_PER_CHAR)


def _read_file_safe(path: Path) -> str:
    """Read a file with graceful error handling."""

    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _build_project_structure(manifest: RepoManifest) -> DigestSection:
    """Build a project structure overview section."""

    lines = ["```"]
    for file_entry in manifest.files:
        risk_marker = {
            RiskLevel.HIGH: " [HIGH RISK]",
            RiskLevel.MEDIUM: " [MED]",
            RiskLevel.LOW: "",
        }[file_entry.risk_level]
        lines.append(
            f"{file_entry.relative_path} ({file_entry.line_count} lines){risk_marker}"
        )
    lines.append("```")
    content = "\n".join(lines)
    return DigestSection(
        heading="Project Structure",
        content=content,
        estimated_tokens=_estimate_tokens(content),
        priority=0,
    )


def _build_dependency_section(repo_root: Path) -> DigestSection:
    """Build a dependency manifest section."""

    parts: list[str] = []

    for name in ("requirements.txt", "Pipfile", "pyproject.toml"):
        dep_file = repo_root / name
        if dep_file.exists():
            content = _read_file_safe(dep_file)
            if content:
                parts.append(f"### {name}\n```\n{content}\n```")

    pkg_json = repo_root / "package.json"
    if pkg_json.exists():
        content = _read_file_safe(pkg_json)
        if content:
            parts.append(f"### package.json\n```json\n{content}\n```")

    content = "\n\n".join(parts) if parts else "No dependency manifests found."
    return DigestSection(
        heading="Dependencies",
        content=content,
        estimated_tokens=_estimate_tokens(content),
        priority=1,
    )


def _build_finding_context_section(
    finding: RawFinding,
    repo_root: Path,
    parsed_files: dict[str, ParsedFile],
) -> DigestSection:
    """Build a context section focused on a specific finding."""

    parts: list[str] = []

    file_path = repo_root / finding.file_path
    if file_path.exists():
        lines = _read_file_safe(file_path).splitlines()
        total_lines = len(lines)

        ctx_start = max(0, finding.line_start - FINDING_CONTEXT_LINES - 1)
        ctx_end = min(total_lines, finding.line_end + FINDING_CONTEXT_LINES)

        if total_lines <= 200:
            ctx_start = 0
            ctx_end = total_lines

        numbered_lines = [
            f"{index + 1:4d} | {lines[index]}" for index in range(ctx_start, ctx_end)
        ]

        marked_lines: list[str] = []
        for line_number, line in enumerate(numbered_lines, ctx_start + 1):
            if finding.line_start <= line_number <= finding.line_end:
                marked_lines.append(f">>> {line}")
            else:
                marked_lines.append(f"    {line}")

        lang = "python" if finding.file_path.endswith(".py") else "javascript"
        parts.append(
            f"### {finding.file_path} "
            f"(lines {ctx_start + 1}-{ctx_end}, finding at L{finding.line_start})\n"
            f"```{lang}\n" + "\n".join(marked_lines) + "\n```"
        )

    parsed = parsed_files.get(finding.file_path)
    if parsed:
        for func in parsed.functions:
            if func.line_start <= finding.line_start <= func.line_end:
                parts.append(
                    f"\n### Containing function: `{func.name}` "
                    f"(L{func.line_start}-{func.line_end})\n"
                    f"Parameters: {', '.join(func.parameters)}"
                )
                break

    content = "\n".join(parts)
    return DigestSection(
        heading=(
            f"Finding Context: {finding.vuln_type.value} "
            f"in {finding.file_path}:{finding.line_start}"
        ),
        content=content,
        estimated_tokens=_estimate_tokens(content),
        priority=2,
    )


def _build_file_section(file_entry: FileEntry) -> DigestSection:
    """Build a full-file section for high-risk files."""

    content = _read_file_safe(file_entry.absolute_path)
    if not content:
        return DigestSection(
            heading=f"File: {file_entry.relative_path}",
            content="(empty or unreadable)",
            estimated_tokens=10,
            priority=5,
        )

    lang = "python" if file_entry.language.value == "python" else "javascript"
    lines = content.splitlines()
    numbered = "\n".join(f"{i + 1:4d} | {line}" for i, line in enumerate(lines))

    formatted = f"```{lang}\n{numbered}\n```"
    return DigestSection(
        heading=(
            f"File: {file_entry.relative_path} "
            f"({len(lines)} lines, {file_entry.risk_level.value} risk)"
        ),
        content=formatted,
        estimated_tokens=_estimate_tokens(formatted),
        priority=3 if file_entry.risk_level == RiskLevel.HIGH else 4,
    )


def build_digest(
    manifest: RepoManifest,
    repo_root: Path,
    parsed_files: dict[str, ParsedFile],
    raw_findings: list[RawFinding],
    max_tokens: int = MAX_CONTEXT_TOKENS,
) -> CodebaseDigest:
    """Build an optimized codebase digest for LLM analysis."""

    sections: list[DigestSection] = []

    sections.append(_build_project_structure(manifest))
    sections.append(_build_dependency_section(repo_root))

    for finding in raw_findings:
        sections.append(_build_finding_context_section(finding, repo_root, parsed_files))

    finding_files = {finding.file_path for finding in raw_findings}
    for file_entry in manifest.files_by_risk(RiskLevel.HIGH):
        if file_entry.relative_path not in finding_files:
            sections.append(_build_file_section(file_entry))

    for file_entry in manifest.files_by_risk(RiskLevel.MEDIUM):
        if file_entry.relative_path not in finding_files:
            sections.append(_build_file_section(file_entry))

    sections.sort(key=lambda section: section.priority)

    included_sections: list[DigestSection] = []
    running_tokens = 0
    truncated = False
    files_excluded = 0

    for section in sections:
        if running_tokens + section.estimated_tokens <= max_tokens:
            included_sections.append(section)
            running_tokens += section.estimated_tokens
        else:
            truncated = True
            files_excluded += 1

    files_included = sum(
        1 for section in included_sections if section.heading.startswith("File:")
    )

    digest = CodebaseDigest(
        sections=included_sections,
        total_estimated_tokens=running_tokens,
        files_included=files_included,
        files_excluded=files_excluded,
        truncated=truncated,
    )

    logger.info(
        f"Digest: {len(included_sections)} sections, "
        f"~{running_tokens:,} tokens, "
        f"{files_included} full files included"
        + (f", {files_excluded} excluded (truncated)" if truncated else "")
    )

    return digest
