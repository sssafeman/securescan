"""Regex fallback parser helpers.

This module provides content-based regex parsing helpers for tests and
non-tree-sitter use cases. It delegates to the fallback parser logic in
`securescan.parse.treesitter`.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from securescan.parse.treesitter import ParsedFile, _parse_regex_fallback


def _language_from_path(file_path: str) -> str:
    suffix = Path(file_path).suffix.lower()
    if suffix == ".py":
        return "python"
    if suffix in {".js", ".jsx", ".mjs", ".cjs"}:
        return "javascript"
    if suffix in {".ts", ".tsx"}:
        return "typescript"
    if suffix == ".go":
        return "go"
    if suffix == ".rs":
        return "rust"
    if suffix == ".java":
        return "java"
    return "unknown"


def parse_with_regex(content: str, file_path: str) -> ParsedFile:
    """Parse source content using regex fallback based on file extension."""
    language = _language_from_path(file_path)
    with tempfile.NamedTemporaryFile(mode="w", suffix=Path(file_path).suffix, delete=True) as handle:
        handle.write(content)
        handle.flush()
        return _parse_regex_fallback(file_path, Path(handle.name), language)


def _parse_go(content: str, file_path: str) -> ParsedFile:
    return parse_with_regex(content, file_path)


def _parse_rust(content: str, file_path: str) -> ParsedFile:
    return parse_with_regex(content, file_path)


def _parse_java(content: str, file_path: str) -> ParsedFile:
    return parse_with_regex(content, file_path)
