"""YAML-based scan rule configuration."""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover - dependency optional in minimal envs
    yaml = None

logger = logging.getLogger(__name__)

_DEFAULT_USER_CONFIG = ".securescan.yml"
_DEFAULT_CONFIG_FILE = Path(__file__).with_name("default_config.yml")
_SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _to_bool(value: object, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return default


def _to_float(
    value: object,
    *,
    default: float,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default

    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def _to_int(
    value: object,
    *,
    default: int,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default

    if minimum is not None:
        parsed = max(minimum, parsed)
    if maximum is not None:
        parsed = min(maximum, parsed)
    return parsed


def _normalize_path(path: str) -> str:
    normalized = Path(path).as_posix()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized.startswith("/"):
        normalized = normalized[1:]
    return normalized


@dataclass
class RuleConfig:
    checks: dict[str, bool] = field(
        default_factory=lambda: {
            "sqli": True,
            "xss": True,
            "hardcoded_secret": True,
            "command_injection": True,
            "deserialization": True,
            "path_traversal": True,
        }
    )
    exclude_paths: list[str] = field(default_factory=list)
    exclude_patterns: list[str] = field(default_factory=list)
    min_severity: str = "low"
    confidence_threshold: float = 0.7
    max_concurrent: int = 5
    max_retries: int = 3

    @classmethod
    def _load_yaml_file(cls, path: Path) -> dict[str, Any] | None:
        if yaml is None:
            logger.warning("pyyaml not installed; using default SecureScan rule config")
            return None

        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except OSError as exc:
            logger.warning(f"Could not read config file {path}: {exc}")
            return None
        except yaml.YAMLError as exc:  # type: ignore[union-attr]
            logger.warning(f"Malformed YAML config in {path}: {exc}")
            return None

        if raw is None:
            return {}

        if not isinstance(raw, dict):
            logger.warning(f"Config file {path} must contain a YAML mapping; using defaults")
            return None

        return raw

    @classmethod
    def _from_data(cls, data: dict[str, Any], base: RuleConfig) -> RuleConfig:
        checks = dict(base.checks)
        raw_checks = data.get("checks")
        if isinstance(raw_checks, dict):
            for key, value in raw_checks.items():
                checks[str(key)] = _to_bool(value, default=True)

        exclude_paths = list(base.exclude_paths)
        exclude_patterns = list(base.exclude_patterns)
        raw_exclude = data.get("exclude")
        if isinstance(raw_exclude, dict):
            raw_paths = raw_exclude.get("paths")
            if isinstance(raw_paths, list):
                exclude_paths = [str(item) for item in raw_paths if str(item).strip()]

            raw_patterns = raw_exclude.get("patterns")
            if isinstance(raw_patterns, list):
                exclude_patterns = [
                    str(item) for item in raw_patterns if str(item).strip()
                ]

        min_severity = str(data.get("min_severity", base.min_severity)).lower()
        if min_severity not in {"low", "medium", "high", "critical"}:
            logger.warning(
                f"Invalid min_severity={min_severity!r}; using {base.min_severity!r}"
            )
            min_severity = base.min_severity

        confidence_threshold = _to_float(
            data.get("confidence_threshold", base.confidence_threshold),
            default=base.confidence_threshold,
            minimum=0.0,
            maximum=1.0,
        )

        llm = data.get("llm")
        max_concurrent = base.max_concurrent
        max_retries = base.max_retries
        if isinstance(llm, dict):
            max_concurrent = _to_int(
                llm.get("max_concurrent", base.max_concurrent),
                default=base.max_concurrent,
                minimum=1,
                maximum=10,
            )
            max_retries = _to_int(
                llm.get("max_retries", base.max_retries),
                default=base.max_retries,
                minimum=1,
            )

        return cls(
            checks=checks,
            exclude_paths=exclude_paths,
            exclude_patterns=exclude_patterns,
            min_severity=min_severity,
            confidence_threshold=confidence_threshold,
            max_concurrent=max_concurrent,
            max_retries=max_retries,
        )

    @classmethod
    def default(cls) -> RuleConfig:
        """Return default configuration."""
        defaults = cls(
            exclude_paths=[
                "node_modules/",
                ".git/",
                "vendor/",
                "dist/",
                "build/",
            ],
            exclude_patterns=[
                "*.min.js",
                "*.bundle.js",
                "*.test.js",
                "*.spec.js",
            ],
        )

        if not _DEFAULT_CONFIG_FILE.exists():
            return defaults

        data = cls._load_yaml_file(_DEFAULT_CONFIG_FILE)
        if data is None:
            return defaults

        return cls._from_data(data, defaults)

    @classmethod
    def load(cls, config_path: Path | None = None) -> RuleConfig:
        """Load config from file, falling back to defaults."""
        defaults = cls.default()

        search_paths: list[Path] = []
        if config_path is not None:
            search_paths.append(Path(config_path))
        else:
            search_paths.append(Path.cwd() / _DEFAULT_USER_CONFIG)

        cwd_config = Path.cwd() / _DEFAULT_USER_CONFIG
        if config_path is not None:
            candidate = Path(config_path)
            try:
                same_path = candidate.resolve() == cwd_config.resolve()
            except OSError:
                same_path = candidate == cwd_config
            if not same_path:
                search_paths.append(cwd_config)

        for path in search_paths:
            if not path.exists():
                continue

            data = cls._load_yaml_file(path)
            if data is None:
                logger.warning(
                    f"Failed to load rule config from {path}; trying next fallback"
                )
                continue

            logger.info(f"Loaded rule config from {path}")
            return cls._from_data(data, defaults)

        if config_path is not None:
            logger.warning(f"Rule config not found at {config_path}; using defaults")
        else:
            logger.info("No .securescan.yml found; using built-in defaults")
        return defaults

    def is_check_enabled(self, vuln_type: str) -> bool:
        """Check if a vulnerability type is enabled."""
        return self.checks.get(vuln_type, True)

    def is_path_excluded(self, file_path: str) -> bool:
        """Check if a file path should be excluded."""
        normalized_path = _normalize_path(file_path)
        file_name = Path(normalized_path).name

        for excluded in self.exclude_paths:
            normalized_excluded = _normalize_path(excluded)
            if not normalized_excluded:
                continue

            if normalized_excluded.endswith("/"):
                normalized_excluded = normalized_excluded.rstrip("/")

            if (
                normalized_path == normalized_excluded
                or normalized_path.startswith(f"{normalized_excluded}/")
            ):
                return True

        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(normalized_path, pattern):
                return True
            if fnmatch.fnmatch(file_name, pattern):
                return True

        return False

    def meets_severity_threshold(self, severity: str) -> bool:
        """Check if severity meets the minimum threshold."""
        current_rank = _SEVERITY_RANK.get(str(severity).lower(), 0)
        threshold_rank = _SEVERITY_RANK.get(self.min_severity, 1)
        return current_rank >= threshold_rank
