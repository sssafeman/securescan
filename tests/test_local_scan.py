"""Tests for local repository scan support."""

from __future__ import annotations

import subprocess

import pytest

from securescan.pipeline import _build_local_repo_info, run_pipeline


def _run_git(cwd: str, *args: str) -> None:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")


class TestLocalScan:
    def test_local_path_creates_repo_info(self, tmp_path):
        """Local path creates valid RepoInfo without cloning."""
        repo_dir = tmp_path / "sample-repo"
        repo_dir.mkdir()

        _run_git(str(repo_dir), "init")
        _run_git(str(repo_dir), "config", "user.email", "tester@example.com")
        _run_git(str(repo_dir), "config", "user.name", "SecureScan Tester")
        (repo_dir / "app.py").write_text("print('hello')\n", encoding="utf-8")
        _run_git(str(repo_dir), "add", ".")
        _run_git(str(repo_dir), "commit", "-m", "Initial commit")
        _run_git(
            str(repo_dir),
            "remote",
            "add",
            "origin",
            "https://github.com/example/sample-repo.git",
        )

        info = _build_local_repo_info(repo_dir)
        assert info.local_path == repo_dir.resolve()
        assert info.name == "example/sample-repo"
        assert info.clone_depth == 0
        assert info.commit_hash != "local"
        assert len(info.commit_hash) >= 8

    def test_local_path_rejects_nonexistent(self, tmp_path):
        """Nonexistent local path raises error."""
        missing = tmp_path / "does-not-exist"
        with pytest.raises(ValueError, match="Local path does not exist"):
            _build_local_repo_info(missing)

    def test_either_url_or_local_required(self, tmp_path):
        """Must provide either repo_url or local_path."""
        with pytest.raises(ValueError, match="exactly one of repo_url or local_path"):
            run_pipeline()

        with pytest.raises(ValueError, match="exactly one of repo_url or local_path"):
            run_pipeline(
                repo_url="https://github.com/example/repo",
                local_path=tmp_path,
            )
