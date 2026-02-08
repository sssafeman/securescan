"""Tests for report generation."""

import json
from datetime import datetime

from securescan.detect.models import (
    DetectionMethod,
    EnrichedFinding,
    Exploitability,
    Patch,
    RawFinding,
    ScanResult,
    Severity,
    ValidatedFinding,
    ValidationStatus,
    VulnType,
)


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


class TestSarifReport:
    def test_generates_valid_sarif(self, tmp_path):
        from securescan.report.generator import generate_sarif_report

        raw_critical = RawFinding(
            id="finding-critical",
            vuln_type=VulnType.SQLI,
            file_path="app/db.py",
            line_start=42,
            line_end=42,
            code_snippet="cursor.execute(f\"SELECT * FROM users WHERE id={uid}\")",
            detection_method=DetectionMethod.SEMGREP,
            confidence=0.95,
            message="SQL injection via string interpolation",
        )
        raw_medium = RawFinding(
            id="finding-medium",
            vuln_type=VulnType.XSS,
            file_path="web/view.js",
            line_start=10,
            line_end=10,
            code_snippet="element.innerHTML = input",
            detection_method=DetectionMethod.SEMGREP,
            confidence=0.8,
            message="Possible XSS sink",
        )

        finding_critical = ValidatedFinding(
            enriched=EnrichedFinding(
                raw=raw_critical,
                severity=Severity.CRITICAL,
                cvss_estimate=9.8,
                reasoning="Untrusted input flows directly to SQL sink.",
                taint_chain="request.id -> uid -> cursor.execute",
                exploitability=Exploitability.CONFIRMED,
                blast_radius="Database compromise",
                is_reachable=True,
            ),
            validation_status=ValidationStatus.CONFIRMED,
            fp_argument="Driver may escape values.",
            fp_rebuttal="Interpolation occurs before query execution.",
            final_confidence=0.99,
        )
        finding_medium = ValidatedFinding(
            enriched=EnrichedFinding(
                raw=raw_medium,
                severity=Severity.MEDIUM,
                cvss_estimate=6.4,
                reasoning="Input reaches HTML sink without encoding.",
                taint_chain="query.param -> render -> innerHTML",
                exploitability=Exploitability.LIKELY,
                blast_radius="Session hijacking",
                is_reachable=True,
            ),
            validation_status=ValidationStatus.CONFIRMED,
            fp_argument="Framework template might sanitize.",
            fp_rebuttal="Direct DOM sink bypasses templating protections.",
            final_confidence=0.86,
        )

        patch = Patch(
            finding_id="finding-critical",
            diff="--- a/app/db.py\n+++ b/app/db.py\n@@\n-f\n+parameterized\n",
            explanation="Replaced string interpolation with parameterized query.",
            syntax_valid=True,
            files_modified=["app/db.py"],
        )

        result = ScanResult(
            repo_name="test/repo",
            repo_url="https://github.com/test/repo",
            branch="main",
            commit_hash="abc123def456",
            scan_timestamp=datetime.now(),
            files_analyzed=12,
            total_lines=1500,
            raw_findings_count=4,
            confirmed_findings=[finding_critical, finding_medium],
            patches=[patch],
            executive_summary="Security issues found.",
            scan_duration_seconds=6.0,
        )

        output = tmp_path / "report.sarif.json"
        report_path = generate_sarif_report(result, [patch], output)

        assert report_path == output
        assert output.exists()

        data = json.loads(output.read_text(encoding="utf-8"))
        assert data["$schema"] == (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/"
            "sarif-2.1/schema/sarif-schema-2.1.0.json"
        )
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) == 1

        run = data["runs"][0]
        assert "tool" in run
        assert "driver" in run["tool"]
        assert "results" in run
        assert len(run["results"]) == 2

        rules = run["tool"]["driver"]["rules"]
        rule_ids = {rule["id"] for rule in rules}
        assert "sqli" in rule_ids
        assert "xss" in rule_ids

        result_by_uri = {
            item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: item
            for item in run["results"]
        }
        assert result_by_uri["app/db.py"]["level"] == "error"
        assert result_by_uri["web/view.js"]["level"] == "warning"

        critical_props = result_by_uri["app/db.py"]["properties"]
        assert critical_props["validationStatus"] == "confirmed"
        assert critical_props["confidence"] == 0.99
        assert critical_props["cvss"] == 9.8
        assert critical_props["patch"]["finding_id"] == "finding-critical"
