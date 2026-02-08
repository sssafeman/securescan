"""Git diff utilities for PR-level scanning."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def _normalize_path(path: str) -> str:
    normalized = Path(path).as_posix()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized.startswith("/"):
        normalized = normalized[1:]
    return normalized


def get_changed_files(
    repo_path: Path,
    base_ref: str,
) -> list[str]:
    """Get list of files changed between base_ref and HEAD.

    Uses git diff --name-only --diff-filter=ACMR to get added, copied,
    modified, and renamed files. Deleted files are excluded since there's
    nothing to scan.

    Args:
        repo_path: Path to the git repository
        base_ref: Base git ref to diff against (e.g., 'main', 'origin/main', 'HEAD~3')

    Returns:
        List of relative file paths that changed

    Raises:
        ValueError: If git diff fails (e.g., invalid ref)
    """
    result = subprocess.run(
        ["git", "diff", "--name-only", "--diff-filter=ACMR", base_ref, "HEAD"],
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise ValueError(
            f"git diff failed (base_ref={base_ref!r}): {result.stderr.strip()}"
        )

    files = [_normalize_path(f.strip()) for f in result.stdout.splitlines() if f.strip()]
    logger.info(f"Diff scan: {len(files)} files changed vs {base_ref}")
    return files
