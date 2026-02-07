"""Repository ingestion - clone and extract metadata."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

try:
    from git import Repo
    from git.exc import GitCommandError
except ModuleNotFoundError:  # pragma: no cover - fallback for minimal envs
    Repo = None
    GitCommandError = Exception  # type: ignore[assignment]

from securescan.config import config

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RepoInfo:
    """Metadata about an ingested repository."""

    name: str
    local_path: Path
    url: str
    branch: str
    commit_hash: str
    commit_date: datetime
    clone_depth: int


class IngestError(Exception):
    """Raised when repo ingestion fails."""


# URL pattern: https://github.com/owner/repo[.git][/tree/branch]
_GITHUB_URL_RE = re.compile(
    r"^https://github\.com/"
    r"(?P<owner>[A-Za-z0-9._-]+)/"
    r"(?P<repo>[A-Za-z0-9._-]+?)"
    r"(?:\.git)?"
    r"(?:/tree/(?P<branch>.+))?"
    r"/?$"
)


def _match_github_url(url: str) -> re.Match[str]:
    match = _GITHUB_URL_RE.match(url.strip())
    if not match:
        raise IngestError(
            f"Invalid GitHub URL: {url}\n"
            "Expected format: https://github.com/owner/repo"
        )
    return match


def parse_github_url(url: str) -> tuple[str, str]:
    """Extract owner and repo name from GitHub URL.

    Returns:
        Tuple of (owner, repo_name)

    Raises:
        IngestError: If URL doesn't match expected pattern.
    """
    match = _match_github_url(url)
    return match.group("owner"), match.group("repo")


def _parse_url_branch(url: str) -> str | None:
    branch = _match_github_url(url).group("branch")
    if not branch:
        return None
    return branch.rstrip("/")


def _clone_with_system_git(
    clone_url: str,
    clone_path: Path,
    depth: int,
    selected_branch: str | None,
    full_name: str,
    original_url: str,
) -> RepoInfo:
    clone_cmd = ["git", "clone", "--depth", str(depth), "--single-branch"]
    if selected_branch:
        clone_cmd.extend(["--branch", selected_branch])
    clone_cmd.extend([clone_url, str(clone_path)])

    clone_proc = subprocess.run(clone_cmd, capture_output=True, text=True, check=False)
    if clone_proc.returncode != 0:
        raise IngestError(
            f"Failed to clone {full_name}: {(clone_proc.stderr or clone_proc.stdout).strip()}"
        )

    def _git(*args: str) -> str:
        proc = subprocess.run(
            ["git", "-C", str(clone_path), *args],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise IngestError(
                f"Failed to read metadata for {full_name}: {(proc.stderr or proc.stdout).strip()}"
            )
        return proc.stdout.strip()

    commit_hash = _git("rev-parse", "HEAD")
    commit_date_raw = _git("show", "-s", "--format=%cI", "HEAD")
    commit_date = datetime.fromisoformat(commit_date_raw.replace("Z", "+00:00"))
    branch_name = selected_branch or _git("rev-parse", "--abbrev-ref", "HEAD")

    return RepoInfo(
        name=full_name,
        local_path=clone_path,
        url=original_url,
        branch=branch_name,
        commit_hash=commit_hash,
        commit_date=commit_date,
        clone_depth=depth,
    )


def clone_repo(
    url: str,
    branch: str | None = None,
    depth: int = 1,
    work_dir: Path | None = None,
) -> RepoInfo:
    """Clone a GitHub repository and return metadata.

    Args:
        url: GitHub repository URL
        branch: Specific branch to clone (None = default branch)
        depth: Git clone depth (1 = shallow)
        work_dir: Override working directory

    Returns:
        RepoInfo with clone metadata

    Raises:
        IngestError: If cloning fails
    """
    owner, repo_name = parse_github_url(url)
    branch_from_url = _parse_url_branch(url)
    selected_branch = branch or branch_from_url
    full_name = f"{owner}/{repo_name}"
    base_dir = work_dir or config.work_dir
    clone_path = base_dir / repo_name

    # Clean up existing clone if present
    if clone_path.exists():
        logger.info(f"Removing existing clone at {clone_path}")
        shutil.rmtree(clone_path)

    # Ensure parent directory exists
    base_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Cloning {full_name} (depth={depth})...")

    clone_kwargs: dict[str, str | int | bool] = {"depth": depth, "single_branch": True}
    if selected_branch:
        clone_kwargs["branch"] = selected_branch

    # If we have a GitHub token, use it for auth (helps with rate limits)
    canonical_url = f"https://github.com/{owner}/{repo_name}"
    clone_url = canonical_url
    if config.github_token:
        clone_url = canonical_url.replace(
            "https://github.com",
            f"https://{config.github_token}@github.com",
        )

    if Repo is not None:
        try:
            repo = Repo.clone_from(clone_url, clone_path, **clone_kwargs)
        except GitCommandError as e:
            raise IngestError(f"Failed to clone {full_name}: {e}") from e

        head = repo.head.commit
        branch_name = selected_branch or repo.git.rev_parse("--abbrev-ref", "HEAD")

        info = RepoInfo(
            name=full_name,
            local_path=clone_path,
            url=url,
            branch=branch_name,
            commit_hash=head.hexsha,
            commit_date=datetime.fromtimestamp(head.committed_date),
            clone_depth=depth,
        )
    else:
        info = _clone_with_system_git(
            clone_url=clone_url,
            clone_path=clone_path,
            depth=depth,
            selected_branch=selected_branch,
            full_name=full_name,
            original_url=url,
        )

    logger.info(
        f"Cloned {full_name} @ {info.commit_hash[:8]} "
        f"({info.branch}, {info.commit_date.isoformat()})"
    )

    return info
