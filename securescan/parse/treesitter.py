"""AST parsing using tree-sitter for Python and JavaScript.

Extracts security-relevant structural information:
- Function/method definitions with their parameters
- Function calls (especially to known dangerous functions)
- String literals and template literals
- Import statements
- Variable assignments involving sensitive names
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Try to import tree-sitter; fall back to regex parsing if unavailable
try:
    import tree_sitter_javascript as tsjavascript
    import tree_sitter_python as tspython
    from tree_sitter import Language, Parser

    PY_LANGUAGE = Language(tspython.language())
    JS_LANGUAGE = Language(tsjavascript.language())
    TREE_SITTER_AVAILABLE = True
except (ImportError, Exception) as e:  # pragma: no cover - env dependent
    logger.warning(f"tree-sitter not available, using regex fallback: {e}")
    TREE_SITTER_AVAILABLE = False


# Known dangerous function calls to flag
DANGEROUS_CALLS_PYTHON = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "execfile",
        "__import__",
        "os.system",
        "os.popen",
        "subprocess.call",
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.check_output",
        "cursor.execute",
        "connection.execute",
        "engine.execute",
        "session.execute",
        "db.execute",
        "raw",
        "pickle.loads",
        "yaml.load",
        "marshal.loads",
    }
)

DANGEROUS_CALLS_JS = frozenset(
    {
        "eval",
        "Function",
        "setTimeout",
        "setInterval",
        "document.write",
        "document.writeln",
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "dangerouslySetInnerHTML",
        "exec",
        "execSync",
        "spawn",
        "execFile",
        "query",
        "raw",
        "deserialize",
        "unserialize",
    }
)

DANGEROUS_CALLS_GO = frozenset(
    {
        "exec.Command",
        "sql.Query",
        "template.HTML",
        "os.Exec",
        "unsafe.Pointer",
        "database/sql",
    }
)

DANGEROUS_CALLS_RUST = frozenset(
    {
        "unsafe {",
        "Command::new",
        "std::process::Command",
        "*const",
        "*mut",
    }
)

DANGEROUS_CALLS_JAVA = frozenset(
    {
        "Runtime.getRuntime().exec",
        "ProcessBuilder",
        "Statement.execute",
        "ObjectInputStream",
        "eval(",
        "ScriptEngine",
    }
)


@dataclass
class FunctionDef:
    """A function or method definition."""

    name: str
    file_path: str
    line_start: int
    line_end: int
    parameters: list[str]
    body_text: str
    is_method: bool = False
    class_name: str | None = None


@dataclass
class FunctionCall:
    """A function call site."""

    name: str
    file_path: str
    line: int
    arguments_text: str
    is_dangerous: bool = False


@dataclass
class ImportStatement:
    """An import statement."""

    module: str
    alias: str | None
    file_path: str
    line: int


@dataclass
class StringLiteral:
    """A string literal that might contain secrets or SQL."""

    value: str
    file_path: str
    line: int
    is_fstring: bool = False
    is_template_literal: bool = False


@dataclass
class ParsedFile:
    """Complete parse result for a single file."""

    file_path: str
    language: str
    functions: list[FunctionDef] = field(default_factory=list)
    calls: list[FunctionCall] = field(default_factory=list)
    imports: list[ImportStatement] = field(default_factory=list)
    strings: list[StringLiteral] = field(default_factory=list)
    line_count: int = 0
    parse_errors: list[str] = field(default_factory=list)

    @property
    def dangerous_calls(self) -> list[FunctionCall]:
        return [call for call in self.calls if call.is_dangerous]

    @property
    def function_defs(self) -> list[FunctionDef]:
        """Compatibility alias for tests that expect `function_defs`."""
        return self.functions


def _read_file(path: Path) -> bytes:
    """Read file as bytes for tree-sitter."""

    return path.read_bytes()


def _get_text(node: Any, source: bytes) -> str:
    """Extract text from a tree-sitter node."""

    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _parse_python_ts(file_path: str, abs_path: Path) -> ParsedFile:
    """Parse a Python file using tree-sitter."""

    source = _read_file(abs_path)
    parser = Parser(PY_LANGUAGE)
    tree = parser.parse(source)

    result = ParsedFile(
        file_path=file_path,
        language="python",
        line_count=source.count(b"\n") + 1,
    )

    def walk(node: Any) -> None:
        if node.type in ("function_definition", "decorated_definition"):
            func_node = node
            if node.type == "decorated_definition":
                for child in node.children:
                    if child.type == "function_definition":
                        func_node = child
                        break

            name_node = func_node.child_by_field_name("name")
            params_node = func_node.child_by_field_name("parameters")

            if name_node:
                params = []
                if params_node:
                    for param in params_node.children:
                        if param.type in (
                            "identifier",
                            "typed_parameter",
                            "default_parameter",
                            "typed_default_parameter",
                        ):
                            params.append(
                                _get_text(param, source)
                                .split(":")[0]
                                .split("=")[0]
                                .strip()
                            )

                parent = node.parent
                is_method = (
                    parent is not None
                    and parent.type == "block"
                    and parent.parent is not None
                    and parent.parent.type == "class_definition"
                )
                class_name = None
                if is_method and parent.parent:
                    class_name_node = parent.parent.child_by_field_name("name")
                    if class_name_node:
                        class_name = _get_text(class_name_node, source)

                result.functions.append(
                    FunctionDef(
                        name=_get_text(name_node, source),
                        file_path=file_path,
                        line_start=node.start_point[0] + 1,
                        line_end=node.end_point[0] + 1,
                        parameters=params,
                        body_text=_get_text(node, source),
                        is_method=is_method,
                        class_name=class_name,
                    )
                )

        elif node.type == "call":
            func = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if func:
                call_name = _get_text(func, source)
                is_dangerous = any(
                    call_name == danger or call_name.endswith(f".{danger}")
                    for danger in DANGEROUS_CALLS_PYTHON
                )
                result.calls.append(
                    FunctionCall(
                        name=call_name,
                        file_path=file_path,
                        line=node.start_point[0] + 1,
                        arguments_text=_get_text(args, source) if args else "",
                        is_dangerous=is_dangerous,
                    )
                )

        elif node.type == "import_statement":
            for child in node.children:
                if child.type == "dotted_name":
                    result.imports.append(
                        ImportStatement(
                            module=_get_text(child, source),
                            alias=None,
                            file_path=file_path,
                            line=node.start_point[0] + 1,
                        )
                    )

        elif node.type == "import_from_statement":
            module_node = node.child_by_field_name("module_name")
            if module_node:
                result.imports.append(
                    ImportStatement(
                        module=_get_text(module_node, source),
                        alias=None,
                        file_path=file_path,
                        line=node.start_point[0] + 1,
                    )
                )

        elif node.type in ("string", "concatenated_string"):
            text = _get_text(node, source)
            is_fstring = text.startswith(("f'", 'f"', "f'''", 'f"""'))
            result.strings.append(
                StringLiteral(
                    value=text,
                    file_path=file_path,
                    line=node.start_point[0] + 1,
                    is_fstring=is_fstring,
                )
            )

        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return result


def _parse_javascript_ts(file_path: str, abs_path: Path) -> ParsedFile:
    """Parse a JavaScript/TypeScript file using tree-sitter."""

    source = _read_file(abs_path)
    parser = Parser(JS_LANGUAGE)
    tree = parser.parse(source)

    result = ParsedFile(
        file_path=file_path,
        language="javascript",
        line_count=source.count(b"\n") + 1,
    )

    def walk(node: Any) -> None:
        if node.type in (
            "function_declaration",
            "method_definition",
            "arrow_function",
            "function",
        ):
            name_node = node.child_by_field_name("name")
            params_node = node.child_by_field_name("parameters")
            name = _get_text(name_node, source) if name_node else "<anonymous>"

            if node.type == "arrow_function" and name == "<anonymous>":
                parent = node.parent
                if parent and parent.type == "variable_declarator":
                    parent_name = parent.child_by_field_name("name")
                    if parent_name:
                        name = _get_text(parent_name, source)

            params = []
            if params_node:
                for param in params_node.children:
                    if param.type in (
                        "identifier",
                        "shorthand_property_identifier_pattern",
                        "assignment_pattern",
                    ):
                        params.append(_get_text(param, source).split("=")[0].strip())

            result.functions.append(
                FunctionDef(
                    name=name,
                    file_path=file_path,
                    line_start=node.start_point[0] + 1,
                    line_end=node.end_point[0] + 1,
                    parameters=params,
                    body_text=_get_text(node, source),
                )
            )

        if node.type == "call_expression":
            func = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if func:
                call_name = _get_text(func, source)
                is_dangerous = any(
                    call_name == danger or call_name.endswith(f".{danger}")
                    for danger in DANGEROUS_CALLS_JS
                )
                result.calls.append(
                    FunctionCall(
                        name=call_name,
                        file_path=file_path,
                        line=node.start_point[0] + 1,
                        arguments_text=_get_text(args, source) if args else "",
                        is_dangerous=is_dangerous,
                    )
                )

                if call_name == "require" and args and args.child_count > 1:
                    module_node = args.children[1]
                    module_name = _get_text(module_node, source).strip("'\"")
                    result.imports.append(
                        ImportStatement(
                            module=module_name,
                            alias=None,
                            file_path=file_path,
                            line=node.start_point[0] + 1,
                        )
                    )

        elif node.type == "import_statement":
            source_node = node.child_by_field_name("source")
            if source_node:
                module_name = _get_text(source_node, source).strip("'\"")
                result.imports.append(
                    ImportStatement(
                        module=module_name,
                        alias=None,
                        file_path=file_path,
                        line=node.start_point[0] + 1,
                    )
                )

        elif node.type in ("string", "template_string"):
            text = _get_text(node, source)
            result.strings.append(
                StringLiteral(
                    value=text,
                    file_path=file_path,
                    line=node.start_point[0] + 1,
                    is_template_literal=(node.type == "template_string"),
                )
            )

        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return result


# Regex fallback (when tree-sitter unavailable)

_PY_FUNC_RE = re.compile(
    r"^(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)\s*(?:->.*)?:",
    re.MULTILINE,
)
_JS_FUNC_RE = re.compile(
    r"(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>)",
    re.MULTILINE,
)
_IMPORT_PY_RE = re.compile(
    r"^(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))",
    re.MULTILINE,
)
_IMPORT_JS_RE = re.compile(
    r"""(?:import\s+.*?from\s+['\"]([^'\"]+)['\"]|require\s*\(\s*['\"]([^'\"]+)['\"]\s*\))""",
    re.MULTILINE,
)
_GO_FUNC_RE = re.compile(
    r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(",
    re.MULTILINE,
)
_IMPORT_GO_SINGLE_RE = re.compile(
    r'^\s*import\s+"([^"]+)"',
    re.MULTILINE,
)
_IMPORT_GO_BLOCK_RE = re.compile(
    r"^\s*import\s*\((.*?)\)",
    re.MULTILINE | re.DOTALL,
)
_RUST_FUNC_RE = re.compile(
    r"^\s*(?:pub\s+)?fn\s+([A-Za-z_]\w*)\s*[<(]",
    re.MULTILINE,
)
_IMPORT_RUST_USE_RE = re.compile(
    r"^\s*use\s+([^;]+);",
    re.MULTILINE,
)
_IMPORT_RUST_EXTERN_RE = re.compile(
    r"^\s*extern\s+crate\s+([A-Za-z_]\w*)\s*;",
    re.MULTILINE,
)
_JAVA_CLASS_RE = re.compile(
    r"^\s*(?:public|private|protected)?\s*class\s+([A-Za-z_]\w*)",
    re.MULTILINE,
)
_JAVA_METHOD_RE = re.compile(
    r"^\s*(?:public|private|protected)\s+(?:static\s+)?[\w<>\[\], ?]+\s+([A-Za-z_]\w*)\s*\(",
    re.MULTILINE,
)
_IMPORT_JAVA_RE = re.compile(
    r"^\s*import\s+([\w.]+\*?)\s*;",
    re.MULTILINE,
)

_DANGEROUS_PATTERN_GO = (
    re.compile(r"\bexec\.Command\s*\("),
    re.compile(r"\bsql\.Query\s*\("),
    re.compile(r"\btemplate\.HTML\s*\("),
    re.compile(r"\bos\.Exec\s*\("),
    re.compile(r"\bunsafe\.Pointer\b"),
)

_DANGEROUS_PATTERN_RUST = (
    re.compile(r"\bunsafe\s*\{"),
    re.compile(r"\b(?:std::process::)?Command::new\s*\("),
    re.compile(r"\*(?:const|mut)\s+"),
)

_DANGEROUS_PATTERN_JAVA = (
    re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\("),
    re.compile(r"\bProcessBuilder\s*\("),
    re.compile(r"\bStatement\.execute(?:Query|Update)?\s*\("),
    re.compile(r"\bObjectInputStream\b"),
    re.compile(r"\beval\s*\("),
    re.compile(r"\bScriptEngine\b"),
)


def _parse_regex_fallback(file_path: str, abs_path: Path, language: str) -> ParsedFile:
    """Regex-based fallback parser when tree-sitter is not available."""

    try:
        source_text = abs_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ParsedFile(
            file_path=file_path,
            language=language,
            parse_errors=["Could not read file"],
        )

    result = ParsedFile(
        file_path=file_path,
        language=language,
        line_count=source_text.count("\n") + 1,
    )

    lines = source_text.split("\n")

    if language == "python":
        for match in _PY_FUNC_RE.finditer(source_text):
            line_num = source_text[: match.start()].count("\n") + 1
            result.functions.append(
                FunctionDef(
                    name=match.group(1),
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    parameters=[
                        part.strip().split(":")[0].split("=")[0]
                        for part in match.group(2).split(",")
                        if part.strip()
                    ],
                    body_text=match.group(0),
                )
            )

        for match in _IMPORT_PY_RE.finditer(source_text):
            module_name = match.group(1) or match.group(2)
            line_num = source_text[: match.start()].count("\n") + 1
            result.imports.append(
                ImportStatement(
                    module=module_name,
                    alias=None,
                    file_path=file_path,
                    line=line_num,
                )
            )

    elif language in ("javascript", "typescript"):
        for match in _JS_FUNC_RE.finditer(source_text):
            name = match.group(1) or match.group(2)
            line_num = source_text[: match.start()].count("\n") + 1
            result.functions.append(
                FunctionDef(
                    name=name,
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    parameters=[],
                    body_text=match.group(0),
                )
            )

        for match in _IMPORT_JS_RE.finditer(source_text):
            module_name = match.group(1) or match.group(2)
            line_num = source_text[: match.start()].count("\n") + 1
            result.imports.append(
                ImportStatement(
                    module=module_name,
                    alias=None,
                    file_path=file_path,
                    line=line_num,
                )
            )

    elif language == "go":
        for match in _GO_FUNC_RE.finditer(source_text):
            line_num = source_text[: match.start()].count("\n") + 1
            result.functions.append(
                FunctionDef(
                    name=match.group(1),
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    parameters=[],
                    body_text=match.group(0),
                )
            )

        for match in _IMPORT_GO_SINGLE_RE.finditer(source_text):
            module_name = match.group(1)
            line_num = source_text[: match.start()].count("\n") + 1
            result.imports.append(
                ImportStatement(
                    module=module_name,
                    alias=None,
                    file_path=file_path,
                    line=line_num,
                )
            )

        for match in _IMPORT_GO_BLOCK_RE.finditer(source_text):
            line_num = source_text[: match.start()].count("\n") + 1
            for module_name in re.findall(r'"([^"]+)"', match.group(1)):
                result.imports.append(
                    ImportStatement(
                        module=module_name,
                        alias=None,
                        file_path=file_path,
                        line=line_num,
                    )
                )

    elif language == "rust":
        for match in _RUST_FUNC_RE.finditer(source_text):
            line_num = source_text[: match.start()].count("\n") + 1
            result.functions.append(
                FunctionDef(
                    name=match.group(1),
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    parameters=[],
                    body_text=match.group(0),
                )
            )

        for match in _IMPORT_RUST_USE_RE.finditer(source_text):
            line_num = source_text[: match.start()].count("\n") + 1
            result.imports.append(
                ImportStatement(
                    module=match.group(1).strip(),
                    alias=None,
                    file_path=file_path,
                    line=line_num,
                )
            )

        for match in _IMPORT_RUST_EXTERN_RE.finditer(source_text):
            line_num = source_text[: match.start()].count("\n") + 1
            result.imports.append(
                ImportStatement(
                    module=match.group(1),
                    alias=None,
                    file_path=file_path,
                    line=line_num,
                )
            )

    elif language == "java":
        for match in _JAVA_CLASS_RE.finditer(source_text):
            line_num = source_text[: match.start()].count("\n") + 1
            result.functions.append(
                FunctionDef(
                    name=match.group(1),
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    parameters=[],
                    body_text=match.group(0),
                )
            )

        for match in _JAVA_METHOD_RE.finditer(source_text):
            line_num = source_text[: match.start()].count("\n") + 1
            result.functions.append(
                FunctionDef(
                    name=match.group(1),
                    file_path=file_path,
                    line_start=line_num,
                    line_end=line_num,
                    parameters=[],
                    body_text=match.group(0),
                )
            )

        for match in _IMPORT_JAVA_RE.finditer(source_text):
            line_num = source_text[: match.start()].count("\n") + 1
            result.imports.append(
                ImportStatement(
                    module=match.group(1),
                    alias=None,
                    file_path=file_path,
                    line=line_num,
                )
            )

    if language == "python":
        dangerous_calls = DANGEROUS_CALLS_PYTHON
        for index, line in enumerate(lines, 1):
            for danger in dangerous_calls:
                if danger in line and "(" in line:
                    result.calls.append(
                        FunctionCall(
                            name=danger,
                            file_path=file_path,
                            line=index,
                            arguments_text=line.strip(),
                            is_dangerous=True,
                        )
                    )
    elif language in ("javascript", "typescript"):
        dangerous_calls = DANGEROUS_CALLS_JS
        for index, line in enumerate(lines, 1):
            for danger in dangerous_calls:
                if danger in line and "(" in line:
                    result.calls.append(
                        FunctionCall(
                            name=danger,
                            file_path=file_path,
                            line=index,
                            arguments_text=line.strip(),
                            is_dangerous=True,
                        )
                    )
    elif language == "go":
        for index, line in enumerate(lines, 1):
            for pattern in _DANGEROUS_PATTERN_GO:
                if pattern.search(line):
                    match_text = pattern.pattern
                    result.calls.append(
                        FunctionCall(
                            name=match_text,
                            file_path=file_path,
                            line=index,
                            arguments_text=line.strip(),
                            is_dangerous=True,
                        )
                    )
    elif language == "rust":
        for index, line in enumerate(lines, 1):
            for pattern in _DANGEROUS_PATTERN_RUST:
                if pattern.search(line):
                    match_text = pattern.pattern
                    result.calls.append(
                        FunctionCall(
                            name=match_text,
                            file_path=file_path,
                            line=index,
                            arguments_text=line.strip(),
                            is_dangerous=True,
                        )
                    )
    elif language == "java":
        for index, line in enumerate(lines, 1):
            for pattern in _DANGEROUS_PATTERN_JAVA:
                if pattern.search(line):
                    match_text = pattern.pattern
                    result.calls.append(
                        FunctionCall(
                            name=match_text,
                            file_path=file_path,
                            line=index,
                            arguments_text=line.strip(),
                            is_dangerous=True,
                        )
                    )

    return result


# Public API

def parse_file(file_path: str, abs_path: Path, language: str) -> ParsedFile:
    """Parse a single file and extract security-relevant structures.

    Args:
        file_path: Path relative to repo root
        abs_path: Absolute filesystem path
        language: "python", "javascript", "typescript", "go", "rust", or "java"

    Returns:
        ParsedFile with extracted structures
    """

    if not TREE_SITTER_AVAILABLE:
        return _parse_regex_fallback(file_path, abs_path, language)

    try:
        if language == "python":
            return _parse_python_ts(file_path, abs_path)
        if language in ("javascript", "typescript"):
            return _parse_javascript_ts(file_path, abs_path)
        if language in ("go", "rust", "java"):
            return _parse_regex_fallback(file_path, abs_path, language)
        return _parse_regex_fallback(file_path, abs_path, language)
    except Exception as e:  # pragma: no cover - parser fallback path
        logger.warning(f"tree-sitter parse failed for {file_path}, using regex fallback: {e}")
        return _parse_regex_fallback(file_path, abs_path, language)


def parse_files(files: list[tuple[str, Path, str]]) -> list[ParsedFile]:
    """Parse multiple files.

    Args:
        files: List of (relative_path, absolute_path, language) tuples

    Returns:
        List of ParsedFile results
    """

    results: list[ParsedFile] = []
    for rel_path, abs_path, language in files:
        parsed = parse_file(rel_path, abs_path, language)
        results.append(parsed)
        if parsed.dangerous_calls:
            logger.debug(f"  {rel_path}: {len(parsed.dangerous_calls)} dangerous call(s)")

    logger.info(
        f"Parsed {len(results)} files | "
        f"{sum(len(parsed.functions) for parsed in results)} functions | "
        f"{sum(len(parsed.dangerous_calls) for parsed in results)} dangerous calls"
    )
    return results
