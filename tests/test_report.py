"""Tests for report generation."""

import json
from datetime import datetime

from securescan.detect.models import ScanResult


class TestJsonReport:
    def test_generates_valid_json(self, tmp_path):
        from securescan.report.generator import generate_json_report

        result = ScanResult(
            repo_name="test/repo",
            repo_url="https://github.com/test/repo",
            branch="main",
            commit_hash="abc123def456",
            scan_timestamp=datetime.now(),
            files_analyzed=10,
            total_lines=1000,
            raw_findings_count=5,
            confirmed_findings=[],
            patches=[],
            executive_summary="No issues found.",
            scan_duration_seconds=5.0,
        )

        output = tmp_path / "report.json"
        json_str = generate_json_report(result, [], output)

        data = json.loads(json_str)
        assert data["repo_name"] == "test/repo"
        assert data["files_analyzed"] == 10
        assert data["executive_summary"] == "No issues found."

        assert output.exists()


class TestFallbackReport:
    def test_generates_text_report(self):
        from securescan.report.generator import _generate_fallback_report

        result = ScanResult(
            repo_name="test/repo",
            repo_url="https://github.com/test/repo",
            branch="main",
            commit_hash="abc123def456",
            scan_timestamp=datetime.now(),
            files_analyzed=10,
            total_lines=1000,
            raw_findings_count=3,
            confirmed_findings=[],
            patches=[],
        )

        text = _generate_fallback_report(result, [])
        assert "test/repo" in text
        assert "10" in text
        assert "1,000" in text


class TestPatchGenerator:
    def test_generate_diff(self):
        from securescan.remediate.patch_generator import _generate_diff

        original = "x = eval(input())\nprint(x)\n"
        fixed = "import ast\nx = ast.literal_eval(input())\nprint(x)\n"

        diff = _generate_diff(original, fixed, "app.py")
        assert "--- a/app.py" in diff
        assert "+++ b/app.py" in diff
        assert "-x = eval(input())" in diff
        assert "+x = ast.literal_eval(input())" in diff

    def test_validate_python_syntax_valid(self):
        from securescan.remediate.patch_generator import _validate_python_syntax

        assert _validate_python_syntax("x = 1\nprint(x)\n") is True

    def test_validate_python_syntax_invalid(self):
        from securescan.remediate.patch_generator import _validate_python_syntax

        assert _validate_python_syntax("def foo(:\n  pass") is False


class TestCodexClient:
    def test_extract_json_direct(self):
        from securescan.remediate.codex_client import CodexClient

        result = CodexClient._extract_json('{"fixed_code": "x = 1"}')
        assert result is not None
        assert result["fixed_code"] == "x = 1"

    def test_extract_json_with_markdown(self):
        from securescan.remediate.codex_client import CodexClient

        text = '```json\n{"fixed_code": "x = 1"}\n```'
        result = CodexClient._extract_json(text)
        assert result is not None
