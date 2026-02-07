"""Tests for the ingest module."""

import pytest
from securescan.ingest.repo import IngestError, parse_github_url


class TestParseGitHubUrl:
    def test_valid_url(self):
        owner, repo = parse_github_url("https://github.com/pallets/flask")
        assert owner == "pallets"
        assert repo == "flask"

    def test_valid_url_with_git_suffix(self):
        owner, repo = parse_github_url("https://github.com/pallets/flask.git")
        assert owner == "pallets"
        assert repo == "flask"

    def test_valid_url_with_trailing_slash(self):
        owner, repo = parse_github_url("https://github.com/pallets/flask/")
        assert owner == "pallets"
        assert repo == "flask"

    def test_invalid_url(self):
        with pytest.raises(IngestError):
            parse_github_url("https://gitlab.com/owner/repo")

    def test_invalid_format(self):
        with pytest.raises(IngestError):
            parse_github_url("not a url at all")

    def test_whitespace_stripped(self):
        owner, repo = parse_github_url("  https://github.com/owner/repo  ")
        assert owner == "owner"
        assert repo == "repo"
