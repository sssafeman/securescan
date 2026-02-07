"""Tests for the pipeline orchestrator and LLM modules."""

from securescan.analyze.opus_client import LLMResponse, OpusClient


class TestOpusClient:
    """Test the Opus API client (mocked - no real API calls)."""

    def test_extract_json_direct(self):
        result = OpusClient._extract_json('{"is_vulnerable": true, "confidence": 0.9}')
        assert result is not None
        assert result["is_vulnerable"] is True
        assert result["confidence"] == 0.9

    def test_extract_json_with_markdown(self):
        text = '''Here's my analysis:
```json
{"is_vulnerable": false, "confidence": 0.8}
```
That's my finding.'''
        result = OpusClient._extract_json(text)
        assert result is not None
        assert result["is_vulnerable"] is False

    def test_extract_json_with_preamble(self):
        text = 'Based on my analysis: {"severity": "high", "cvss_estimate": 8.5}'
        result = OpusClient._extract_json(text)
        assert result is not None
        assert result["severity"] == "high"

    def test_extract_json_invalid(self):
        result = OpusClient._extract_json("This is not JSON at all")
        assert result is None


class TestLLMResponse:
    def test_success_response(self):
        response = LLMResponse(
            content='{"test": true}',
            json_data={"test": True},
            input_tokens=100,
            output_tokens=50,
            model="claude-opus-4-6",
            latency_ms=500.0,
            success=True,
        )
        assert response.success
        assert response.json_data["test"] is True

    def test_error_response(self):
        response = LLMResponse(
            content="",
            success=False,
            error="Rate limited",
        )
        assert not response.success
        assert response.error == "Rate limited"


class TestVulnerabilityAnalyzer:
    """Test vulnerability analysis parsing (mocked LLM)."""

    def test_parse_positive_finding(self):
        from securescan.analyze.vulnerability_analyzer import _parse_analysis_response
        from securescan.detect.models import (
            DetectionMethod,
            Exploitability,
            RawFinding,
            Severity,
            VulnType,
        )

        finding = RawFinding(
            vuln_type=VulnType.SQLI,
            file_path="app/db.py",
            line_start=42,
            line_end=42,
            code_snippet="cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
            detection_method=DetectionMethod.SEMGREP,
            confidence=0.9,
            message="SQL injection",
        )

        response = LLMResponse(
            content="",
            json_data={
                "is_vulnerable": True,
                "confidence": 0.95,
                "severity": "critical",
                "cvss_estimate": 9.8,
                "reasoning": "User input flows directly into SQL query",
                "taint_chain": "req.params.id -> uid -> cursor.execute()",
                "exploitability": "confirmed",
                "blast_radius": "Full database access",
                "is_reachable": True,
            },
            success=True,
        )

        result = _parse_analysis_response(finding, response)
        assert result is not None
        assert result.severity == Severity.CRITICAL
        assert result.cvss_estimate == 9.8
        assert result.exploitability == Exploitability.CONFIRMED

    def test_parse_rejected_finding(self):
        from securescan.analyze.vulnerability_analyzer import _parse_analysis_response
        from securescan.detect.models import DetectionMethod, RawFinding, VulnType

        finding = RawFinding(
            vuln_type=VulnType.SQLI,
            file_path="tests/test_db.py",
            line_start=10,
            line_end=10,
            code_snippet="cursor.execute(f'SELECT 1')",
            detection_method=DetectionMethod.SEMGREP,
            confidence=0.5,
            message="Possible SQL injection",
        )

        response = LLMResponse(
            content="",
            json_data={
                "is_vulnerable": False,
                "confidence": 0.1,
                "severity": "low",
                "cvss_estimate": 0.0,
                "reasoning": "This is a test file with no user input",
                "taint_chain": None,
                "exploitability": "unlikely",
                "blast_radius": "None",
                "is_reachable": False,
            },
            success=True,
        )

        result = _parse_analysis_response(finding, response)
        assert result is None


class TestAdversarialReviewer:
    """Test adversarial review parsing (mocked LLM)."""

    def test_parse_confirmed_finding(self):
        from securescan.analyze.adversarial_reviewer import _parse_adversarial_response
        from securescan.detect.models import (
            DetectionMethod,
            EnrichedFinding,
            Exploitability,
            RawFinding,
            Severity,
            ValidationStatus,
            VulnType,
        )

        raw = RawFinding(
            vuln_type=VulnType.SQLI,
            file_path="app/db.py",
            line_start=42,
            line_end=42,
            code_snippet="cursor.execute(f'...')",
            detection_method=DetectionMethod.SEMGREP,
            confidence=0.9,
            message="SQL injection",
        )

        enriched = EnrichedFinding(
            raw=raw,
            severity=Severity.CRITICAL,
            cvss_estimate=9.8,
            reasoning="Direct SQL injection",
            taint_chain="req -> query",
            exploitability=Exploitability.CONFIRMED,
            blast_radius="Full DB",
            is_reachable=True,
        )

        response = LLMResponse(
            content="",
            json_data={
                "fp_argument": "The cursor might use parameterized queries internally",
                "fp_argument_strength": "weak",
                "rebuttal": (
                    "The f-string is evaluated before cursor.execute, "
                    "so parameterization cannot help"
                ),
                "final_verdict": "confirmed_vulnerable",
                "adjusted_confidence": 0.95,
            },
            success=True,
        )

        result = _parse_adversarial_response(enriched, response)
        assert result.validation_status == ValidationStatus.CONFIRMED
        assert result.final_confidence == 0.95
        assert result.is_confirmed
