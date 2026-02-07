"""Central configuration for SecureScan pipeline."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

try:
    from dotenv import load_dotenv
except ModuleNotFoundError:  # pragma: no cover - fallback for minimal envs
    def load_dotenv(*_args: object, **_kwargs: object) -> bool:
        return False

load_dotenv()

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Config:
    """Immutable pipeline configuration."""

    # API Keys
    anthropic_api_key: str = field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", "")
    )
    openai_api_key: str = field(
        default_factory=lambda: os.getenv("OPENAI_API_KEY", "")
    )
    github_token: str = field(
        default_factory=lambda: os.getenv("GITHUB_TOKEN", "")
    )

    # Pipeline settings
    max_files: int = int(os.getenv("SECURESCAN_MAX_FILES", "1000"))
    confidence_threshold: float = float(
        os.getenv("SECURESCAN_CONFIDENCE_THRESHOLD", "0.7")
    )
    output_dir: Path = Path(os.getenv("SECURESCAN_OUTPUT_DIR", "./reports"))

    # Working directory for cloned repos
    work_dir: Path = Path(os.getenv("SECURESCAN_WORK_DIR", "/tmp/securescan"))

    # LLM settings
    opus_model: str = field(
        default_factory=lambda: os.getenv(
            "OPUS_MODEL", "claude-sonnet-4-5-20250514"
        )
    )
    opus_max_tokens: int = 8192
    codex_model: str = "gpt-5.3-codex"  # Verify exact model string

    # File classification
    high_risk_patterns: tuple[str, ...] = (
        "auth", "login", "password", "token", "session",
        "admin", "api", "route", "view", "controller",
        "handler", "middleware", "database", "db", "query",
        "sql", "model", "schema", "migration", "config",
        "settings", "secret", "key", "credential", "payment",
        "checkout", "user", "account", "permission", "role",
    )

    # Directories to always skip
    skip_dirs: tuple[str, ...] = (
        "node_modules", ".git", "__pycache__", "venv", ".venv",
        "env", ".env", "dist", "build", ".next", ".nuxt",
        "coverage", ".nyc_output", ".pytest_cache", ".mypy_cache",
        "vendor", "third_party", "external", ".tox", "eggs",
        ".eggs", "bower_components",
    )

    # File extensions to analyze
    python_extensions: tuple[str, ...] = (".py",)
    javascript_extensions: tuple[str, ...] = (
        ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    )

    @property
    def all_extensions(self) -> tuple[str, ...]:
        return self.python_extensions + self.javascript_extensions

    def validate(self) -> list[str]:
        """Return list of configuration errors (empty = valid)."""
        errors = []
        if not self.anthropic_api_key:
            errors.append("ANTHROPIC_API_KEY not set")
        if not self.openai_api_key:
            logger.warning(
                "OPENAI_API_KEY not set - patch generation will use Anthropic"
            )
        return errors


# Singleton
config = Config()
