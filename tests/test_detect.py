"""Tests for the detection modules."""

from pathlib import Path
from textwrap import dedent

from securescan.detect.models import DetectionMethod, Language, RawFinding, VulnType
from securescan.detect.secrets_scanner import scan_file_for_secrets, shannon_entropy
from securescan.ingest.manifest import _classify_language


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_two_chars(self):
        assert abs(shannon_entropy("abab") - 1.0) < 0.01

    def test_high_entropy(self):
        high_ent = shannon_entropy("aB3$kL9mNp2qRs5tUv8wXy")
        assert high_ent > 3.5

    def test_low_entropy(self):
        low_ent = shannon_entropy("aaabbb")
        assert low_ent < 1.5


class TestSecretsScanner:
    def test_detects_aws_key(self, tmp_path):
        code = dedent(
            """\
            import boto3
            AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
            client = boto3.client('s3', aws_access_key_id=AWS_ACCESS_KEY)
        """
        )
        test_file = tmp_path / "config.py"
        test_file.write_text(code)

        findings = scan_file_for_secrets("config.py", test_file)
        assert len(findings) >= 1
        assert findings[0].vuln_type == VulnType.HARDCODED_SECRET
        assert "AWS" in findings[0].message

    def test_detects_github_token(self, tmp_path):
        code = dedent(
            """\
            GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        """
        )
        test_file = tmp_path / "settings.py"
        test_file.write_text(code)

        findings = scan_file_for_secrets("settings.py", test_file)
        assert len(findings) >= 1
        assert any("GitHub" in finding.message for finding in findings)

    def test_ignores_placeholder(self, tmp_path):
        code = dedent(
            """\
            API_KEY = "your_api_key_here"
            TOKEN = "changeme"
            SECRET = "<INSERT_SECRET>"
        """
        )
        test_file = tmp_path / "config.py"
        test_file.write_text(code)

        findings = scan_file_for_secrets("config.py", test_file)
        assert len(findings) == 0, f"Expected no findings but got: {findings}"

    def test_ignores_env_variable_reference(self, tmp_path):
        code = dedent(
            """\
            password = os.environ.get("DB_PASSWORD")
            secret = os.getenv("SECRET_KEY")
        """
        )
        test_file = tmp_path / "config.py"
        test_file.write_text(code)

        findings = scan_file_for_secrets("config.py", test_file)
        assert len(findings) == 0

    def test_ignores_test_files(self, tmp_path):
        code = dedent(
            """\
            API_KEY = "sk_test_ABCDEFGHIJKLMNOPQRSTuvwxyz1234567890"
        """
        )
        test_file = tmp_path / "test_config.py"
        test_file.write_text(code)

        findings = scan_file_for_secrets("test_config.py", test_file)
        assert len(findings) == 0


class TestRawFinding:
    def test_to_dict(self):
        finding = RawFinding(
            vuln_type=VulnType.SQLI,
            file_path="app/db.py",
            line_start=42,
            line_end=42,
            code_snippet="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
            detection_method=DetectionMethod.SEMGREP,
            confidence=0.9,
            message="SQL injection via f-string",
            rule_id="securescan-sqli-python-fstring",
        )
        finding_dict = finding.to_dict()
        assert finding_dict["vuln_type"] == "sqli"
        assert finding_dict["file_path"] == "app/db.py"
        assert finding_dict["confidence"] == 0.9
        assert "id" in finding_dict


class TestLanguageDetection:
    def test_go_file_detected(self):
        assert _classify_language(Path("main.go")) == Language.GO

    def test_rust_file_detected(self):
        assert _classify_language(Path("main.rs")) == Language.RUST

    def test_java_file_detected(self):
        assert _classify_language(Path("Main.java")) == Language.JAVA
