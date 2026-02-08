"""Tests for git diff-based scan scoping."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from securescan.diff import get_changed_files


def _run_git(repo_path: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed: {(result.stderr or result.stdout).strip()}"
        )
    return result.stdout.strip()


def _init_repo(repo_path: Path) -> None:
    repo_path.mkdir(parents=True, exist_ok=True)
    _run_git(repo_path, "init")
    _run_git(repo_path, "config", "user.email", "tester@example.com")
    _run_git(repo_path, "config", "user.name", "SecureScan Tester")


def _commit_all(repo_path: Path, message: str) -> str:
    _run_git(repo_path, "add", ".")
    _run_git(repo_path, "commit", "-m", message)
    return _run_git(repo_path, "rev-parse", "HEAD")


class TestDiffScanning:
    def test_get_changed_files(self, tmp_path):
        """Returns list of changed files between refs."""
        repo = tmp_path / "repo"
        _init_repo(repo)

        (repo / "file_a.py").write_text("print('a')\n", encoding="utf-8")
        base_commit = _commit_all(repo, "add file_a")

        (repo / "file_a.py").write_text("print('a changed')\n", encoding="utf-8")
        (repo / "file_b.py").write_text("print('b')\n", encoding="utf-8")
        _commit_all(repo, "modify a and add b")

        changed = get_changed_files(repo, base_commit)
        assert set(changed) == {"file_a.py", "file_b.py"}

    def test_get_changed_files_excludes_deleted(self, tmp_path):
        """Deleted files are not included in diff."""
        repo = tmp_path / "repo"
        _init_repo(repo)

        (repo / "obsolete.py").write_text("print('obsolete')\n", encoding="utf-8")
        base_commit = _commit_all(repo, "add obsolete")

        _run_git(repo, "rm", "obsolete.py")
        _commit_all(repo, "delete obsolete")

        changed = get_changed_files(repo, base_commit)
        assert "obsolete.py" not in changed
        assert changed == []

    def test_get_changed_files_invalid_ref(self, tmp_path):
        """Invalid base ref raises ValueError."""
        repo = tmp_path / "repo"
        _init_repo(repo)

        (repo / "file.py").write_text("print('x')\n", encoding="utf-8")
        _commit_all(repo, "initial")

        with pytest.raises(ValueError, match="git diff failed"):
            get_changed_files(repo, "not-a-real-ref")

    def test_empty_diff(self, tmp_path):
        """No changes returns empty list."""
        repo = tmp_path / "repo"
        _init_repo(repo)

        (repo / "file.py").write_text("print('x')\n", encoding="utf-8")
        _commit_all(repo, "initial")

        changed = get_changed_files(repo, "HEAD")
        assert changed == []
