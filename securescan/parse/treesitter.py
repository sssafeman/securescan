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
from collections.abc import Callable
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
except Exception as e:  # pragma: no cover - env dependent
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


def _walk_tree(node: Any, visit: Callable[[Any], None]) -> None:
    """Visit a tree-sitter node and its descendants in source order."""

    visit(node)
    for child in node.children:
        _walk_tree(child, visit)


def _is_dangerous_call(call_name: str, dangerous_calls: frozenset[str]) -> bool:
    """Return whether a call name matches a configured dangerous call."""

    return any(
        call_name == dangerous or call_name.endswith(f".{dangerous}")
        for dangerous in dangerous_calls
    )


_PYTHON_PARAMETER_NODE_TYPES = frozenset(
    {
        "identifier",
        "typed_parameter",
        "default_parameter",
        "typed_default_parameter",
    }
)


def _python_parameters(params_node: Any, source: bytes) -> list[str]:
    """Extract normalized Python parameter names from a parameter node."""

    if params_node is None:
        return []
    return [
        _get_text(param, source).split(":")[0].split("=")[0].strip()
        for param in params_node.children
        if param.type in _PYTHON_PARAMETER_NODE_TYPES
    ]


def _python_method_context(node: Any, source: bytes) -> tuple[bool, str | None]:
    """Return method status and class name for a Python definition node."""

    parent = node.parent
    is_method = (
        parent is not None
        and parent.type == "block"
        and parent.parent is not None
        and parent.parent.type == "class_definition"
    )
    if not is_method or parent.parent is None:
        return False, None

    class_name_node = parent.parent.child_by_field_name("name")
    class_name = _get_text(class_name_node, source) if class_name_node else None
    return True, class_name


def _python_function_node(node: Any) -> Any:
    """Return the function node represented by a Python definition node."""

    if node.type != "decorated_definition":
        return node
    return next(
        (child for child in node.children if child.type == "function_definition"),
        node,
    )


def _extract_python_function(
    node: Any,
    source: bytes,
    file_path: str,
    result: ParsedFile,
) -> None:
    """Add a Python function definition to a parse result."""

    function_node = _python_function_node(node)
    name_node = function_node.child_by_field_name("name")
    if name_node is None:
        return

    params_node = function_node.child_by_field_name("parameters")
    is_method, class_name = _python_method_context(node, source)
    result.functions.append(
        FunctionDef(
            name=_get_text(name_node, source),
            file_path=file_path,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            parameters=_python_parameters(params_node, source),
            body_text=_get_text(node, source),
            is_method=is_method,
            class_name=class_name,
        )
    )


def _extract_python_call(
    node: Any,
    source: bytes,
    file_path: str,
    result: ParsedFile,
) -> None:
    """Add a Python call expression to a parse result."""

    function_node = node.child_by_field_name("function")
    if function_node is None:
        return

    arguments_node = node.child_by_field_name("arguments")
    call_name = _get_text(function_node, source)
    result.calls.append(
        FunctionCall(
            name=call_name,
            file_path=file_path,
            line=node.start_point[0] + 1,
            arguments_text=_get_text(arguments_node, source) if arguments_node else "",
            is_dangerous=_is_dangerous_call(call_name, DANGEROUS_CALLS_PYTHON),
        )
    )


def _extract_python_import(
    node: Any,
    source: bytes,
    file_path: str,
    result: ParsedFile,
) -> None:
    """Add imports represented by a Python import node to a parse result."""

    if node.type == "import_statement":
        module_nodes = (child for child in node.children if child.type == "dotted_name")
    else:
        module_node = node.child_by_field_name("module_name")
        module_nodes = (module_node,) if module_node else ()

    for module_node in module_nodes:
        result.imports.append(
            ImportStatement(
                module=_get_text(module_node, source),
                alias=None,
                file_path=file_path,
                line=node.start_point[0] + 1,
            )
        )


def _extract_python_string(
    node: Any,
    source: bytes,
    file_path: str,
    result: ParsedFile,
) -> None:
    """Add a Python string node to a parse result."""

    value = _get_text(node, source)
    result.strings.append(
        StringLiteral(
            value=value,
            file_path=file_path,
            line=node.start_point[0] + 1,
            is_fstring=value.startswith(("f'", 'f"', "f'''", 'f"""')),
        )
    )


def _visit_python_node(
    node: Any,
    source: bytes,
    file_path: str,
    result: ParsedFile,
) -> None:
    """Extract supported structures from one Python syntax node."""

    if node.type in ("function_definition", "decorated_definition"):
        _extract_python_function(node, source, file_path, result)
    elif node.type == "call":
        _extract_python_call(node, source, file_path, result)
    elif node.type in ("import_statement", "import_from_statement"):
        _extract_python_import(node, source, file_path, result)
    elif node.type in ("string", "concatenated_string"):
        _extract_python_string(node, source, file_path, result)


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

    _walk_tree(
        tree.root_node,
        lambda node: _visit_python_node(node, source, file_path, result),
    )
    return result


_JAVASCRIPT_FUNCTION_NODE_TYPES = frozenset(
    {
        "function_declaration",
        "method_definition",
        "arrow_function",
        "function",
    }
)
_JAVASCRIPT_PARAMETER_NODE_TYPES = frozenset(
    {
        "identifier",
        "shorthand_property_identifier_pattern",
        "assignment_pattern",
    }
)


def _javascript_function_name(node: Any, source: bytes) -> str:
    """Extract a declared or inferred JavaScript function name."""

    name_node = node.child_by_field_name("name")
    if name_node is not None:
        return _get_text(name_node, source)
    if node.type != "arrow_function":
        return "<anonymous>"

    parent = node.parent
    if parent is None or parent.type != "variable_declarator":
        return "<anonymous>"
    parent_name = parent.child_by_field_name("name")
    return _get_text(parent_name, source) if parent_name else "<anonymous>"


def _javascript_parameters(node: Any, source: bytes) -> list[str]:
    """Extract normalized JavaScript parameters from a function node."""

    params_node = node.child_by_field_name("parameters")
    if params_node is None:
        return []
    return [
        _get_text(param, source).split("=")[0].strip()
        for param in params_node.children
        if param.type in _JAVASCRIPT_PARAMETER_NODE_TYPES
    ]


def _extract_javascript_function(
    node: Any,
    source: bytes,
    file_path: str,
    result: ParsedFile,
) -> None:
    """Add a JavaScript function definition to a parse result."""

    result.functions.append(
        FunctionDef(
            name=_javascript_function_name(node, source),
            file_path=file_path,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            parameters=_javascript_parameters(node, source),
            body_text=_get_text(node, source),
        )
    )


def _append_javascript_import(
    module_node: Any,
    node: Any,
    source: bytes,
    file_path: str,
    result: ParsedFile,
) -> None:
    """Add a JavaScript module node to a parse result."""

    result.imports.append(
        ImportStatement(
            module=_get_text(module_node, source).strip("'\""),
            alias=None,
            file_path=file_path,
            line=node.start_point[0] + 1,
        )
    )


def _extract_javascript_call(
    node: Any,
    source: bytes,
    file_path: str,
    result: ParsedFile,
) -> None:
    """Add a JavaScript call expression and any require import."""

    function_node = node.child_by_field_name("function")
    if function_node is None:
        return

    arguments_node = node.child_by_field_name("arguments")
    call_name = _get_text(function_node, source)
    result.calls.append(
        FunctionCall(
            name=call_name,
            file_path=file_path,
            line=node.start_point[0] + 1,
            arguments_text=_get_text(arguments_node, source) if arguments_node else "",
            is_dangerous=_is_dangerous_call(call_name, DANGEROUS_CALLS_JS),
        )
    )

    if call_name == "require" and arguments_node and arguments_node.child_count > 1:
        _append_javascript_import(
            arguments_node.children[1],
            node,
            source,
            file_path,
            result,
        )


def _extract_javascript_import(
    node: Any,
    source: bytes,
    file_path: str,
    result: ParsedFile,
) -> None:
    """Add an ES module import to a parse result."""

    module_node = node.child_by_field_name("source")
    if module_node is not None:
        _append_javascript_import(module_node, node, source, file_path, result)


def _extract_javascript_string(
    node: Any,
    source: bytes,
    file_path: str,
    result: ParsedFile,
) -> None:
    """Add a JavaScript string node to a parse result."""

    result.strings.append(
        StringLiteral(
            value=_get_text(node, source),
            file_path=file_path,
            line=node.start_point[0] + 1,
            is_template_literal=(node.type == "template_string"),
        )
    )


def _visit_javascript_node(
    node: Any,
    source: bytes,
    file_path: str,
    result: ParsedFile,
) -> None:
    """Extract supported structures from one JavaScript syntax node."""

    if node.type in _JAVASCRIPT_FUNCTION_NODE_TYPES:
        _extract_javascript_function(node, source, file_path, result)

    if node.type == "call_expression":
        _extract_javascript_call(node, source, file_path, result)
    elif node.type == "import_statement":
        _extract_javascript_import(node, source, file_path, result)
    elif node.type in ("string", "template_string"):
        _extract_javascript_string(node, source, file_path, result)


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

    _walk_tree(
        tree.root_node,
        lambda node: _visit_javascript_node(node, source, file_path, result),
    )
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


def _match_line_number(source_text: str, match: re.Match[str]) -> int:
    """Return the one-based line number where a regex match begins."""

    return source_text[: match.start()].count("\n") + 1


def _append_regex_function(
    result: ParsedFile,
    source_text: str,
    match: re.Match[str],
    name: str,
    parameters: list[str] | None = None,
) -> None:
    """Append a function captured by a fallback regex."""

    line_number = _match_line_number(source_text, match)
    result.functions.append(
        FunctionDef(
            name=name,
            file_path=result.file_path,
            line_start=line_number,
            line_end=line_number,
            parameters=parameters or [],
            body_text=match.group(0),
        )
    )


def _append_regex_import(
    result: ParsedFile,
    source_text: str,
    match: re.Match[str],
    module_name: str,
    line_number: int | None = None,
) -> None:
    """Append an import captured by a fallback regex."""

    result.imports.append(
        ImportStatement(
            module=module_name,
            alias=None,
            file_path=result.file_path,
            line=line_number or _match_line_number(source_text, match),
        )
    )


def _extract_python_regex(result: ParsedFile, source_text: str) -> None:
    """Extract Python definitions and imports with fallback regexes."""

    for match in _PY_FUNC_RE.finditer(source_text):
        parameters = [
            part.strip().split(":")[0].split("=")[0]
            for part in match.group(2).split(",")
            if part.strip()
        ]
        _append_regex_function(result, source_text, match, match.group(1), parameters)

    for match in _IMPORT_PY_RE.finditer(source_text):
        _append_regex_import(
            result,
            source_text,
            match,
            match.group(1) or match.group(2),
        )


def _extract_javascript_regex(result: ParsedFile, source_text: str) -> None:
    """Extract JavaScript definitions and imports with fallback regexes."""

    for match in _JS_FUNC_RE.finditer(source_text):
        _append_regex_function(
            result,
            source_text,
            match,
            match.group(1) or match.group(2),
        )

    for match in _IMPORT_JS_RE.finditer(source_text):
        _append_regex_import(
            result,
            source_text,
            match,
            match.group(1) or match.group(2),
        )


def _extract_go_regex(result: ParsedFile, source_text: str) -> None:
    """Extract Go definitions and imports with fallback regexes."""

    for match in _GO_FUNC_RE.finditer(source_text):
        _append_regex_function(result, source_text, match, match.group(1))

    for match in _IMPORT_GO_SINGLE_RE.finditer(source_text):
        _append_regex_import(result, source_text, match, match.group(1))

    for match in _IMPORT_GO_BLOCK_RE.finditer(source_text):
        line_number = _match_line_number(source_text, match)
        for module_name in re.findall(r'"([^"]+)"', match.group(1)):
            _append_regex_import(
                result,
                source_text,
                match,
                module_name,
                line_number,
            )


def _extract_rust_regex(result: ParsedFile, source_text: str) -> None:
    """Extract Rust definitions and imports with fallback regexes."""

    for match in _RUST_FUNC_RE.finditer(source_text):
        _append_regex_function(result, source_text, match, match.group(1))

    for match in _IMPORT_RUST_USE_RE.finditer(source_text):
        _append_regex_import(result, source_text, match, match.group(1).strip())

    for match in _IMPORT_RUST_EXTERN_RE.finditer(source_text):
        _append_regex_import(result, source_text, match, match.group(1))


def _extract_java_regex(result: ParsedFile, source_text: str) -> None:
    """Extract Java definitions and imports with fallback regexes."""

    for match in _JAVA_CLASS_RE.finditer(source_text):
        _append_regex_function(result, source_text, match, match.group(1))

    for match in _JAVA_METHOD_RE.finditer(source_text):
        _append_regex_function(result, source_text, match, match.group(1))

    for match in _IMPORT_JAVA_RE.finditer(source_text):
        _append_regex_import(result, source_text, match, match.group(1))


_REGEX_EXTRACTORS: dict[str, Callable[[ParsedFile, str], None]] = {
    "python": _extract_python_regex,
    "javascript": _extract_javascript_regex,
    "typescript": _extract_javascript_regex,
    "go": _extract_go_regex,
    "rust": _extract_rust_regex,
    "java": _extract_java_regex,
}

_NAMED_DANGEROUS_CALLS = {
    "python": DANGEROUS_CALLS_PYTHON,
    "javascript": DANGEROUS_CALLS_JS,
    "typescript": DANGEROUS_CALLS_JS,
}

_PATTERN_DANGEROUS_CALLS = {
    "go": _DANGEROUS_PATTERN_GO,
    "rust": _DANGEROUS_PATTERN_RUST,
    "java": _DANGEROUS_PATTERN_JAVA,
}


def _append_fallback_dangerous_call(
    result: ParsedFile,
    name: str,
    line_number: int,
    source_line: str,
) -> None:
    """Append a dangerous call found by fallback scanning."""

    result.calls.append(
        FunctionCall(
            name=name,
            file_path=result.file_path,
            line=line_number,
            arguments_text=source_line.strip(),
            is_dangerous=True,
        )
    )


def _scan_named_dangerous_calls(
    result: ParsedFile,
    lines: list[str],
    dangerous_calls: frozenset[str],
) -> None:
    """Find dangerous calls using the legacy substring matching rules."""

    for line_number, line in enumerate(lines, 1):
        for dangerous_call in dangerous_calls:
            if dangerous_call in line and "(" in line:
                _append_fallback_dangerous_call(
                    result,
                    dangerous_call,
                    line_number,
                    line,
                )


def _scan_pattern_dangerous_calls(
    result: ParsedFile,
    lines: list[str],
    patterns: tuple[re.Pattern[str], ...],
) -> None:
    """Find dangerous calls using compiled fallback patterns."""

    for line_number, line in enumerate(lines, 1):
        for pattern in patterns:
            if pattern.search(line):
                _append_fallback_dangerous_call(
                    result,
                    pattern.pattern,
                    line_number,
                    line,
                )


def _scan_fallback_dangerous_calls(
    result: ParsedFile,
    lines: list[str],
    language: str,
) -> None:
    """Dispatch dangerous call scanning for a fallback language."""

    named_calls = _NAMED_DANGEROUS_CALLS.get(language)
    if named_calls is not None:
        _scan_named_dangerous_calls(result, lines, named_calls)
        return

    patterns = _PATTERN_DANGEROUS_CALLS.get(language)
    if patterns is not None:
        _scan_pattern_dangerous_calls(result, lines, patterns)


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
    extractor = _REGEX_EXTRACTORS.get(language)
    if extractor is not None:
        extractor(result, source_text)
    _scan_fallback_dangerous_calls(result, source_text.split("\n"), language)
    return result


# Public API

_TREE_SITTER_PARSERS: dict[str, Callable[[str, Path], ParsedFile]] = {
    "python": _parse_python_ts,
    "javascript": _parse_javascript_ts,
    "typescript": _parse_javascript_ts,
}


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
        parser = _TREE_SITTER_PARSERS.get(language)
        if parser is None:
            return _parse_regex_fallback(file_path, abs_path, language)
        return parser(file_path, abs_path)
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
