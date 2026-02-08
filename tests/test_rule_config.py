"""Tests for YAML rule configuration."""

import logging

from securescan.rule_config import RuleConfig


class TestRuleConfig:
    def test_default_config(self):
        """Default config enables all checks."""
        cfg = RuleConfig.default()
        assert cfg.is_check_enabled("sqli") is True
        assert cfg.is_check_enabled("xss") is True
        assert cfg.is_check_enabled("hardcoded_secret") is True
        assert cfg.min_severity == "low"
        assert cfg.confidence_threshold == 0.7

    def test_load_from_yaml(self, tmp_path):
        """Loads config from YAML file."""
        cfg_path = tmp_path / ".securescan.yml"
        cfg_path.write_text(
            """
checks:
  sqli: false
  xss: true
  hardcoded_secret: true
exclude:
  paths:
    - "generated/"
  patterns:
    - "*.gen.js"
min_severity: medium
confidence_threshold: 0.8
llm:
  max_concurrent: 7
  max_retries: 4
""".strip(),
            encoding="utf-8",
        )

        cfg = RuleConfig.load(cfg_path)
        assert cfg.is_check_enabled("sqli") is False
        assert cfg.is_check_enabled("xss") is True
        assert cfg.exclude_paths == ["generated/"]
        assert cfg.exclude_patterns == ["*.gen.js"]
        assert cfg.min_severity == "medium"
        assert cfg.confidence_threshold == 0.8
        assert cfg.max_concurrent == 7
        assert cfg.max_retries == 4

    def test_disabled_check(self, tmp_path):
        """Disabled check type is correctly reported."""
        cfg_path = tmp_path / ".securescan.yml"
        cfg_path.write_text(
            """
checks:
  sqli: false
""".strip(),
            encoding="utf-8",
        )

        cfg = RuleConfig.load(cfg_path)
        assert cfg.is_check_enabled("sqli") is False
        assert cfg.is_check_enabled("xss") is True
        assert cfg.is_check_enabled("unknown_future_check") is True

    def test_path_exclusion(self):
        """Excluded paths are correctly identified."""
        cfg = RuleConfig.default()
        cfg.exclude_paths = ["vendor/", "dist/"]
        cfg.exclude_patterns = []
        assert cfg.is_path_excluded("vendor/lib/index.js") is True
        assert cfg.is_path_excluded("dist/bundle.js") is True
        assert cfg.is_path_excluded("src/app.js") is False

    def test_pattern_exclusion(self):
        """Glob patterns correctly match files."""
        cfg = RuleConfig.default()
        cfg.exclude_paths = []
        cfg.exclude_patterns = ["*.min.js", "*.spec.js"]
        assert cfg.is_path_excluded("static/jquery.min.js") is True
        assert cfg.is_path_excluded("src/widget.spec.js") is True
        assert cfg.is_path_excluded("src/widget.js") is False

    def test_severity_threshold(self):
        """Severity threshold filtering works correctly."""
        cfg = RuleConfig.default()
        cfg.min_severity = "medium"
        assert cfg.meets_severity_threshold("low") is False
        assert cfg.meets_severity_threshold("medium") is True
        assert cfg.meets_severity_threshold("high") is True
        assert cfg.meets_severity_threshold("critical") is True

    def test_malformed_yaml_falls_back(self, tmp_path, caplog):
        """Malformed YAML falls back to defaults with warning."""
        cfg_path = tmp_path / ".securescan.yml"
        cfg_path.write_text("checks: [", encoding="utf-8")

        caplog.set_level(logging.WARNING)
        cfg = RuleConfig.load(cfg_path)

        assert cfg.is_check_enabled("sqli") is True
        assert any("Malformed YAML config" in record.message for record in caplog.records)

    def test_missing_file_uses_defaults(self, tmp_path):
        """Missing config file returns defaults."""
        missing = tmp_path / "missing.yml"
        cfg = RuleConfig.load(missing)
        assert cfg.is_check_enabled("sqli") is True
        assert cfg.min_severity == "low"
        assert cfg.max_concurrent == 5
