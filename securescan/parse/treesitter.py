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
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Try to import tree-sitter; fall back to regex parsing if unavailable
PY_LANGUAGE: Any | None = None
JS_LANGUAGE: Any | None = None
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


@dataclass(frozen=True)
class _TreeSitterContext:
    """Shared state for extracting nodes from one syntax tree."""

    source: bytes
    result: ParsedFile


@dataclass(frozen=True)
class _TreeSitterConfig:
    """Language-specific configuration for the tree-sitter driver."""

    language: str
    grammar: Callable[[], Any]
    handlers: dict[str, Callable[[Any, _TreeSitterContext], None]]


@dataclass(frozen=True)
class _FunctionMetadata:
    """Language-specific fields for a parsed function definition."""

    name: str
    parameters: list[str]
    is_method: bool = False
    class_name: str | None = None


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


def _append_tree_sitter_function(
    node: Any,
    context: _TreeSitterContext,
    metadata: _FunctionMetadata,
) -> None:
    """Append a function definition using shared node metadata."""

    context.result.functions.append(
        FunctionDef(
            name=metadata.name,
            file_path=context.result.file_path,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            parameters=metadata.parameters,
            body_text=_get_text(node, context.source),
            is_method=metadata.is_method,
            class_name=metadata.class_name,
        )
    )


def _append_tree_sitter_call(
    node: Any,
    context: _TreeSitterContext,
    dangerous_calls: frozenset[str],
) -> tuple[str, Any] | None:
    """Append a call expression and return its name and arguments node."""

    function_node = node.child_by_field_name("function")
    if function_node is None:
        return None

    arguments_node = node.child_by_field_name("arguments")
    call_name = _get_text(function_node, context.source)
    context.result.calls.append(
        FunctionCall(
            name=call_name,
            file_path=context.result.file_path,
            line=node.start_point[0] + 1,
            arguments_text=(
                _get_text(arguments_node, context.source) if arguments_node else ""
            ),
            is_dangerous=_is_dangerous_call(call_name, dangerous_calls),
        )
    )
    return call_name, arguments_node


def _append_tree_sitter_import(
    node: Any,
    module_node: Any,
    context: _TreeSitterContext,
    strip_quotes: bool = False,
) -> None:
    """Append an import represented by a module syntax node."""

    module_name = _get_text(module_node, context.source)
    if strip_quotes:
        module_name = module_name.strip("'\"")
    context.result.imports.append(
        ImportStatement(
            module=module_name,
            alias=None,
            file_path=context.result.file_path,
            line=node.start_point[0] + 1,
        )
    )


def _append_tree_sitter_string(node: Any, context: _TreeSitterContext) -> None:
    """Append a string literal with language-specific flags."""

    value = _get_text(node, context.source)
    context.result.strings.append(
        StringLiteral(
            value=value,
            file_path=context.result.file_path,
            line=node.start_point[0] + 1,
            is_fstring=(
                context.result.language == "python"
                and value.startswith(("f'", 'f"', "f'''", 'f"""'))
            ),
            is_template_literal=(node.type == "template_string"),
        )
    )


def _visit_tree_sitter_node(
    node: Any,
    context: _TreeSitterContext,
    config: _TreeSitterConfig,
) -> None:
    """Dispatch one syntax node to its configured extraction handler."""

    handler = config.handlers.get(node.type)
    if handler is not None:
        handler(node, context)


def _parse_tree_sitter(
    file_path: str,
    abs_path: Path,
    config: _TreeSitterConfig,
) -> ParsedFile:
    """Parse one file with a configured tree-sitter language."""

    source = _read_file(abs_path)
    parser = Parser(config.grammar())
    tree = parser.parse(source)
    result = ParsedFile(
        file_path=file_path,
        language=config.language,
        line_count=source.count(b"\n") + 1,
    )
    context = _TreeSitterContext(source=source, result=result)
    _walk_tree(
        tree.root_node,
        lambda node: _visit_tree_sitter_node(node, context, config),
    )
    return result


_PYTHON_PARAMETER_NODE_TYPES = frozenset(
    {
        "identifier",
        "typed_parameter",
        "default_parameter",
        "typed_default_parameter",
    }
)


def _python_parameters(
    params_node: Any,
    context: _TreeSitterContext,
) -> list[str]:
    """Extract normalized Python parameter names from a parameter node."""

    if params_node is None:
        return []
    return [
        _get_text(param, context.source).split(":")[0].split("=")[0].strip()
        for param in params_node.children
        if param.type in _PYTHON_PARAMETER_NODE_TYPES
    ]


def _python_method_context(
    node: Any,
    context: _TreeSitterContext,
) -> tuple[bool, str | None]:
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
    class_name = (
        _get_text(class_name_node, context.source) if class_name_node else None
    )
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
    context: _TreeSitterContext,
) -> None:
    """Add a Python function definition to a parse result."""

    function_node = _python_function_node(node)
    name_node = function_node.child_by_field_name("name")
    if name_node is None:
        return

    params_node = function_node.child_by_field_name("parameters")
    is_method, class_name = _python_method_context(node, context)
    _append_tree_sitter_function(
        node,
        context,
        _FunctionMetadata(
            name=_get_text(name_node, context.source),
            parameters=_python_parameters(params_node, context),
            is_method=is_method,
            class_name=class_name,
        ),
    )


def _extract_python_import(
    node: Any,
    context: _TreeSitterContext,
) -> None:
    """Add imports represented by a Python import node to a parse result."""

    if node.type == "import_statement":
        module_nodes = (child for child in node.children if child.type == "dotted_name")
    else:
        module_node = node.child_by_field_name("module_name")
        module_nodes = (module_node,) if module_node else ()

    for module_node in module_nodes:
        _append_tree_sitter_import(node, module_node, context)


def _extract_python_call(
    node: Any,
    context: _TreeSitterContext,
) -> None:
    """Add a Python call expression to a parse result."""

    _append_tree_sitter_call(node, context, DANGEROUS_CALLS_PYTHON)


_PYTHON_TREE_SITTER_CONFIG = _TreeSitterConfig(
    language="python",
    grammar=lambda: PY_LANGUAGE,
    handlers={
        "function_definition": _extract_python_function,
        "decorated_definition": _extract_python_function,
        "call": _extract_python_call,
        "import_statement": _extract_python_import,
        "import_from_statement": _extract_python_import,
        "string": _append_tree_sitter_string,
        "concatenated_string": _append_tree_sitter_string,
    },
)


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


def _javascript_function_name(
    node: Any,
    context: _TreeSitterContext,
) -> str:
    """Extract a declared or inferred JavaScript function name."""

    name_node = node.child_by_field_name("name")
    if name_node is not None:
        return _get_text(name_node, context.source)
    if node.type != "arrow_function":
        return "<anonymous>"

    parent = node.parent
    if parent is None or parent.type != "variable_declarator":
        return "<anonymous>"
    parent_name = parent.child_by_field_name("name")
    return (
        _get_text(parent_name, context.source) if parent_name else "<anonymous>"
    )


def _javascript_parameters(
    node: Any,
    context: _TreeSitterContext,
) -> list[str]:
    """Extract normalized JavaScript parameters from a function node."""

    params_node = node.child_by_field_name("parameters")
    if params_node is None:
        return []
    return [
        _get_text(param, context.source).split("=")[0].strip()
        for param in params_node.children
        if param.type in _JAVASCRIPT_PARAMETER_NODE_TYPES
    ]


def _extract_javascript_function(
    node: Any,
    context: _TreeSitterContext,
) -> None:
    """Add a JavaScript function definition to a parse result."""

    _append_tree_sitter_function(
        node,
        context,
        _FunctionMetadata(
            name=_javascript_function_name(node, context),
            parameters=_javascript_parameters(node, context),
        ),
    )


def _extract_javascript_call(
    node: Any,
    context: _TreeSitterContext,
) -> None:
    """Add a JavaScript call expression and any require import."""

    call_details = _append_tree_sitter_call(node, context, DANGEROUS_CALLS_JS)
    if call_details is None:
        return

    call_name, arguments_node = call_details
    if call_name == "require" and arguments_node and arguments_node.child_count > 1:
        _append_tree_sitter_import(
            node,
            arguments_node.children[1],
            context,
            strip_quotes=True,
        )


def _extract_javascript_import(
    node: Any,
    context: _TreeSitterContext,
) -> None:
    """Add an ES module import to a parse result."""

    module_node = node.child_by_field_name("source")
    if module_node is not None:
        _append_tree_sitter_import(
            node,
            module_node,
            context,
            strip_quotes=True,
        )


_JAVASCRIPT_TREE_SITTER_CONFIG = _TreeSitterConfig(
    language="javascript",
    grammar=lambda: JS_LANGUAGE,
    handlers={
        **{
            node_type: _extract_javascript_function
            for node_type in _JAVASCRIPT_FUNCTION_NODE_TYPES
        },
        "call_expression": _extract_javascript_call,
        "import_statement": _extract_javascript_import,
        "string": _append_tree_sitter_string,
        "template_string": _append_tree_sitter_string,
    },
)


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
_GO_BLOCK_MODULE_RE = re.compile(r'"([^"]+)"')
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


@dataclass(frozen=True)
class _RegexRule:
    """One named capture rule for fallback extraction."""

    pattern: re.Pattern[str]
    value_groups: tuple[int, ...] = (1,)
    strip_value: bool = False
    parameters_group: int | None = None


@dataclass(frozen=True)
class _RegexBlockImportRule:
    """One rule for imports nested inside a matched block."""

    pattern: re.Pattern[str]
    module_pattern: re.Pattern[str]
    content_group: int = 1


@dataclass(frozen=True)
class _RegexExtractionSpec:
    """Fallback extraction rules for one language."""

    functions: tuple[_RegexRule, ...] = ()
    imports: tuple[_RegexRule, ...] = ()
    block_imports: tuple[_RegexBlockImportRule, ...] = ()


_PYTHON_REGEX_SPEC = _RegexExtractionSpec(
    functions=(
        _RegexRule(
            pattern=_PY_FUNC_RE,
            parameters_group=2,
        ),
    ),
    imports=(
        _RegexRule(
            pattern=_IMPORT_PY_RE,
            value_groups=(1, 2),
        ),
    ),
)
_JAVASCRIPT_REGEX_SPEC = _RegexExtractionSpec(
    functions=(
        _RegexRule(
            pattern=_JS_FUNC_RE,
            value_groups=(1, 2),
        ),
    ),
    imports=(
        _RegexRule(
            pattern=_IMPORT_JS_RE,
            value_groups=(1, 2),
        ),
    ),
)
_GO_REGEX_SPEC = _RegexExtractionSpec(
    functions=(_RegexRule(pattern=_GO_FUNC_RE),),
    imports=(_RegexRule(pattern=_IMPORT_GO_SINGLE_RE),),
    block_imports=(
        _RegexBlockImportRule(
            pattern=_IMPORT_GO_BLOCK_RE,
            module_pattern=_GO_BLOCK_MODULE_RE,
        ),
    ),
)
_RUST_REGEX_SPEC = _RegexExtractionSpec(
    functions=(_RegexRule(pattern=_RUST_FUNC_RE),),
    imports=(
        _RegexRule(
            pattern=_IMPORT_RUST_USE_RE,
            strip_value=True,
        ),
        _RegexRule(pattern=_IMPORT_RUST_EXTERN_RE),
    ),
)
_JAVA_REGEX_SPEC = _RegexExtractionSpec(
    functions=(
        _RegexRule(pattern=_JAVA_CLASS_RE),
        _RegexRule(pattern=_JAVA_METHOD_RE),
    ),
    imports=(_RegexRule(pattern=_IMPORT_JAVA_RE),),
)


def _match_line_number(match: re.Match[str]) -> int:
    """Return the one-based line number where a regex match begins."""

    return match.string[: match.start()].count("\n") + 1


def _append_regex_function(
    result: ParsedFile,
    match: re.Match[str],
    name: str,
    parameters: list[str] | None = None,
) -> None:
    """Append a function captured by a fallback regex."""

    line_number = _match_line_number(match)
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
            line=line_number or _match_line_number(match),
        )
    )


def _regex_rule_value(match: re.Match[str], rule: _RegexRule) -> str:
    """Return the first populated value capture for a regex rule."""

    value = next(
        match.group(group)
        for group in rule.value_groups
        if match.group(group) is not None
    )
    return value.strip() if rule.strip_value else value


def _regex_rule_parameters(
    match: re.Match[str],
    rule: _RegexRule,
) -> list[str] | None:
    """Return normalized parameters when a regex rule captures them."""

    if rule.parameters_group is None:
        return None
    return [
        part.strip().split(":")[0].split("=")[0]
        for part in match.group(rule.parameters_group).split(",")
        if part.strip()
    ]


def _extract_regex_spec(
    result: ParsedFile,
    source_text: str,
    spec: _RegexExtractionSpec,
) -> None:
    """Apply configured function and import rules to fallback source."""

    for rule in spec.functions:
        for match in rule.pattern.finditer(source_text):
            _append_regex_function(
                result,
                match,
                _regex_rule_value(match, rule),
                _regex_rule_parameters(match, rule),
            )

    for rule in spec.imports:
        for match in rule.pattern.finditer(source_text):
            _append_regex_import(
                result,
                match,
                _regex_rule_value(match, rule),
            )

    for rule in spec.block_imports:
        for match in rule.pattern.finditer(source_text):
            line_number = _match_line_number(match)
            content = match.group(rule.content_group)
            for module_name in rule.module_pattern.findall(content):
                _append_regex_import(result, match, module_name, line_number)


_REGEX_SPECS: dict[str, _RegexExtractionSpec] = {
    "python": _PYTHON_REGEX_SPEC,
    "javascript": _JAVASCRIPT_REGEX_SPEC,
    "typescript": _JAVASCRIPT_REGEX_SPEC,
    "go": _GO_REGEX_SPEC,
    "rust": _RUST_REGEX_SPEC,
    "java": _JAVA_REGEX_SPEC,
}

_FALLBACK_DANGEROUS_CALLS: dict[
    str,
    frozenset[str] | tuple[re.Pattern[str], ...],
] = {
    "python": DANGEROUS_CALLS_PYTHON,
    "javascript": DANGEROUS_CALLS_JS,
    "typescript": DANGEROUS_CALLS_JS,
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


def _dangerous_detector_matches(
    detector: str | re.Pattern[str],
    line: str,
) -> bool:
    """Return whether one fallback detector matches a source line."""

    if isinstance(detector, str):
        return detector in line and "(" in line
    return detector.search(line) is not None


def _dangerous_detector_name(detector: str | re.Pattern[str]) -> str:
    """Return the call name emitted for a fallback detector."""

    return detector if isinstance(detector, str) else detector.pattern


def _scan_dangerous_calls(
    result: ParsedFile,
    lines: list[str],
    detectors: frozenset[str] | tuple[re.Pattern[str], ...],
) -> None:
    """Find dangerous calls with configured string or regex detectors."""

    for line_number, line in enumerate(lines, 1):
        for detector in detectors:
            if _dangerous_detector_matches(detector, line):
                _append_fallback_dangerous_call(
                    result,
                    _dangerous_detector_name(detector),
                    line_number,
                    line,
                )


def _scan_fallback_dangerous_calls(
    result: ParsedFile,
    lines: list[str],
    language: str,
) -> None:
    """Dispatch dangerous call scanning for a fallback language."""

    detectors = _FALLBACK_DANGEROUS_CALLS.get(language)
    if detectors is not None:
        _scan_dangerous_calls(result, lines, detectors)


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
    spec = _REGEX_SPECS.get(language)
    if spec is not None:
        _extract_regex_spec(result, source_text, spec)
    _scan_fallback_dangerous_calls(result, source_text.split("\n"), language)
    return result


# Public API

_TREE_SITTER_CONFIGS: dict[str, _TreeSitterConfig] = {
    "python": _PYTHON_TREE_SITTER_CONFIG,
    "javascript": _JAVASCRIPT_TREE_SITTER_CONFIG,
    "typescript": _JAVASCRIPT_TREE_SITTER_CONFIG,
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
        config = _TREE_SITTER_CONFIGS.get(language)
        if config is None:
            return _parse_regex_fallback(file_path, abs_path, language)
        return _parse_tree_sitter(file_path, abs_path, config)
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
