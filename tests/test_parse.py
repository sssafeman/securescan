"""Tests for the parse module."""

from textwrap import dedent

from securescan.parse.treesitter import TREE_SITTER_AVAILABLE, parse_file


class TestPythonParsing:
    def test_extracts_function_defs(self, tmp_path):
        code = dedent(
            """\
            def login(username, password):
                pass

            def get_user(user_id: int) -> dict:
                pass
        """
        )
        test_file = tmp_path / "auth.py"
        test_file.write_text(code)

        result = parse_file("auth.py", test_file, "python")
        assert len(result.functions) >= 2
        names = {func.name for func in result.functions}
        assert "login" in names
        assert "get_user" in names

    def test_extracts_imports(self, tmp_path):
        code = dedent(
            """\
            import os
            from flask import Flask, request
            from sqlalchemy import text
        """
        )
        test_file = tmp_path / "app.py"
        test_file.write_text(code)

        result = parse_file("app.py", test_file, "python")
        assert len(result.imports) >= 2
        modules = {imp.module for imp in result.imports}
        assert "os" in modules

    def test_flags_dangerous_calls(self, tmp_path):
        code = dedent(
            """\
            import sqlite3
            conn = sqlite3.connect("db.sqlite")
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
            eval(user_input)
        """
        )
        test_file = tmp_path / "db.py"
        test_file.write_text(code)

        result = parse_file("db.py", test_file, "python")
        dangerous = result.dangerous_calls
        assert len(dangerous) >= 1
        dangerous_names = {call.name for call in dangerous}
        assert "eval" in dangerous_names

    def test_handles_empty_file(self, tmp_path):
        test_file = tmp_path / "empty.py"
        test_file.write_text("")

        result = parse_file("empty.py", test_file, "python")
        assert result.functions == []
        assert result.calls == []


class TestJavaScriptParsing:
    def test_extracts_function_defs(self, tmp_path):
        code = dedent(
            """\
            function handleLogin(req, res) {
                return res.send("ok");
            }

            const getUser = async (userId) => {
                return db.query("SELECT * FROM users");
            };
        """
        )
        test_file = tmp_path / "routes.js"
        test_file.write_text(code)

        result = parse_file("routes.js", test_file, "javascript")
        assert len(result.functions) >= 1
        names = {func.name for func in result.functions}
        assert "handleLogin" in names

    def test_extracts_require_imports(self, tmp_path):
        code = dedent(
            """\
            const express = require('express');
            const { Pool } = require('pg');
        """
        )
        test_file = tmp_path / "server.js"
        test_file.write_text(code)

        result = parse_file("server.js", test_file, "javascript")
        assert len(result.imports) >= 1 or len(result.calls) >= 1


class TestParserFallback:
    """Test regex fallback behavior."""

    def test_regex_parses_python(self, tmp_path):
        code = dedent(
            """\
            def foo(x, y):
                return x + y

            async def bar(z):
                pass
        """
        )
        test_file = tmp_path / "test.py"
        test_file.write_text(code)

        from securescan.parse.treesitter import _parse_regex_fallback

        result = _parse_regex_fallback("test.py", test_file, "python")

        names = {func.name for func in result.functions}
        assert "foo" in names


def test_parser_availability_flag():
    assert isinstance(TREE_SITTER_AVAILABLE, bool)
