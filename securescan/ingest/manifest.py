"""File discovery and classification for vulnerability analysis."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from securescan.config import config

logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Language(str, Enum):
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"


@dataclass
class FileEntry:
    """A single file in the repository manifest."""

    relative_path: str
    absolute_path: Path
    language: Language
    risk_level: RiskLevel
    line_count: int
    estimated_tokens: int
    size_bytes: int


@dataclass
class RepoManifest:
    """Complete file manifest for a repository."""

    files: list[FileEntry]
    total_files_discovered: int
    total_files_included: int
    total_files_excluded: int
    total_lines: int
    total_estimated_tokens: int
    language_breakdown: dict[str, int]
    risk_breakdown: dict[str, int]

    @property
    def fits_single_context(self) -> bool:
        """Whether the entire codebase fits in a single LLM context window (~800K tokens)."""
        return self.total_estimated_tokens < 800_000

    def files_by_risk(self, level: RiskLevel) -> list[FileEntry]:
        return [f for f in self.files if f.risk_level == level]


def _classify_language(path: Path) -> Language | None:
    """Determine the language of a file by extension."""
    ext = path.suffix.lower()
    if ext in config.python_extensions:
        return Language.PYTHON
    if ext in config.javascript_extensions:
        if ext in (".ts", ".tsx"):
            return Language.TYPESCRIPT
        return Language.JAVASCRIPT
    return None


def _classify_risk(relative_path: str) -> RiskLevel:
    """Classify a file's risk level based on its path and name."""
    path_lower = relative_path.lower()
    # Check if any high-risk pattern appears in the path
    for pattern in config.high_risk_patterns:
        if pattern in path_lower:
            return RiskLevel.HIGH
    # Medium risk: main source directories
    medium_dirs = ("src/", "lib/", "app/", "server/", "api/", "routes/", "controllers/")
    if any(path_lower.startswith(d) or f"/{d}" in path_lower for d in medium_dirs):
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _should_skip_dir(dir_name: str) -> bool:
    """Check if a directory should be skipped."""
    return dir_name in config.skip_dirs or dir_name.startswith(".")


def _count_lines(path: Path) -> int:
    """Count lines in a file, handling encoding errors gracefully."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as file_handle:
            return sum(1 for _ in file_handle)
    except (OSError, ValueError):
        return 0


def build_manifest(repo_root: Path) -> RepoManifest:
    """Walk a repository and build a classified file manifest.

    Args:
        repo_root: Path to the cloned repository root

    Returns:
        RepoManifest with all discovered and classified files
    """
    all_files: list[FileEntry] = []
    total_discovered = 0
    total_excluded = 0

    for path in sorted(repo_root.rglob("*")):
        # Skip directories in skip list
        if any(_should_skip_dir(part) for part in path.relative_to(repo_root).parts):
            continue

        if not path.is_file():
            continue

        total_discovered += 1

        language = _classify_language(path)
        if language is None:
            total_excluded += 1
            continue

        relative = str(path.relative_to(repo_root))
        line_count = _count_lines(path)
        size_bytes = path.stat().st_size

        entry = FileEntry(
            relative_path=relative,
            absolute_path=path,
            language=language,
            risk_level=_classify_risk(relative),
            line_count=line_count,
            estimated_tokens=line_count * 10,
            size_bytes=size_bytes,
        )
        all_files.append(entry)

    # Sort: high risk first, then medium, then low. Within each level, sort by line count desc.
    risk_order = {RiskLevel.HIGH: 0, RiskLevel.MEDIUM: 1, RiskLevel.LOW: 2}
    all_files.sort(key=lambda f: (risk_order[f.risk_level], -f.line_count))

    # Apply max files limit
    included = all_files[: config.max_files]
    excluded_by_limit = len(all_files) - len(included)
    total_excluded += excluded_by_limit

    if excluded_by_limit > 0:
        logger.warning(
            f"Truncated manifest to {config.max_files} files "
            f"({excluded_by_limit} lower-risk files excluded)"
        )

    # Build summary statistics
    language_breakdown: dict[str, int] = {}
    risk_breakdown: dict[str, int] = {}
    for file_entry in included:
        language_breakdown[file_entry.language.value] = (
            language_breakdown.get(file_entry.language.value, 0) + 1
        )
        risk_breakdown[file_entry.risk_level.value] = (
            risk_breakdown.get(file_entry.risk_level.value, 0) + 1
        )

    manifest = RepoManifest(
        files=included,
        total_files_discovered=total_discovered,
        total_files_included=len(included),
        total_files_excluded=total_excluded,
        total_lines=sum(file_entry.line_count for file_entry in included),
        total_estimated_tokens=sum(file_entry.estimated_tokens for file_entry in included),
        language_breakdown=language_breakdown,
        risk_breakdown=risk_breakdown,
    )

    logger.info(
        f"Manifest: {manifest.total_files_included} files, "
        f"{manifest.total_lines:,} lines, "
        f"~{manifest.total_estimated_tokens:,} tokens | "
        f"Risk: {risk_breakdown} | "
        f"Fits single context: {manifest.fits_single_context}"
    )

    return manifest
