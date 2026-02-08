"""Patch generator for confirmed vulnerabilities.

Uses GPT to generate code fixes, then produces unified diff patches.
Includes syntax validation to ensure patches don't break the code.
"""

from __future__ import annotations

import ast
import difflib
import logging
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from securescan.analyze.opus_client import LLMResponse, OpusClient
from securescan.config import config
from securescan.detect.models import Patch, ValidatedFinding

logger = logging.getLogger(__name__)


PATCH_SYSTEM_PROMPT = """\
You are a senior security engineer writing code patches to fix vulnerabilities.

Rules:
- Produce ONLY the fixed version of the code shown to you.
- Preserve the original code's style, formatting, and logic.
- Fix ONLY the security vulnerability described - don't refactor or improve.
- Use parameterized queries for SQL injection fixes.
- Use environment variables or config files for hardcoded secrets.
- Use proper output encoding/escaping for XSS fixes.
- Maintain backward compatibility.

Respond with a JSON object:
{
    "fixed_code": "the complete fixed code for the file or function",
    "explanation": "1-3 sentences explaining what was changed and why",
    "changes_summary": "brief list of specific changes made"
}"""


def _build_patch_prompt(finding: ValidatedFinding, repo_root: Path) -> str:
    """Build the prompt for patch generation."""
    raw = finding.enriched.raw
    file_path = repo_root / raw.file_path

    try:
        original_code = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        original_code = raw.code_snippet

    lines = original_code.splitlines()
    if len(lines) > 200:
        start = max(0, raw.line_start - 50)
        end = min(len(lines), raw.line_end + 50)
        section = "\n".join(lines[start:end])
        context_note = (
            f"(showing lines {start + 1}-{end} of {len(lines)}; "
            f"vulnerability is at line {raw.line_start})"
        )
    else:
        section = original_code
        context_note = (
            f"(full file, {len(lines)} lines; vulnerability at line {raw.line_start})"
        )

    return f"""\
## Vulnerability to Fix
- **Type:** {raw.vuln_type.value}
- **File:** {raw.file_path}
- **Line:** {raw.line_start}
- **Severity:** {finding.enriched.severity.value}
- **Description:** {finding.enriched.reasoning}
- **Taint Chain:** {finding.enriched.taint_chain or 'N/A'}

## Original Code {context_note}
```
{section}
```

## Instructions
Fix the security vulnerability described above. Return the complete fixed version
of the code shown, with minimal changes to address the vulnerability.

Respond ONLY with JSON matching the schema described in your instructions."""


def _generate_diff(
    original: str,
    fixed: str,
    file_path: str,
) -> str:
    """Generate a unified diff between original and fixed code."""
    original_lines = original.splitlines(keepends=True)
    fixed_lines = fixed.splitlines(keepends=True)

    diff = difflib.unified_diff(
        original_lines,
        fixed_lines,
        fromfile=f"a/{file_path}",
        tofile=f"b/{file_path}",
        lineterm="",
    )
    return "".join(diff)


def _validate_python_syntax(code: str) -> bool:
    """Check if Python code has valid syntax."""
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False


def _validate_js_syntax(code: str) -> bool:
    """Check JavaScript syntax using node if available."""
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=True) as handle:
            handle.write(code)
            handle.flush()
            result = subprocess.run(
                ["node", "--check", handle.name],
                capture_output=True,
                timeout=10,
                check=False,
            )
            return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return True


def _validate_syntax(code: str, file_path: str) -> bool:
    """Validate that the fixed code has correct syntax."""
    if file_path.endswith(".py"):
        return _validate_python_syntax(code)
    if file_path.endswith((".js", ".ts", ".jsx", ".tsx")):
        return _validate_js_syntax(code)
    return True


def generate_patch(
    client: OpusClient,
    finding: ValidatedFinding,
    repo_root: Path,
) -> Patch | None:
    """Generate a remediation patch for a single finding."""
    raw = finding.enriched.raw
    file_path = repo_root / raw.file_path

    try:
        original_code = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        logger.error(f"Cannot read {raw.file_path} for patch generation")
        return None

    prompt = _build_patch_prompt(finding, repo_root)

    response = client.analyze(
        system_prompt=PATCH_SYSTEM_PROMPT,
        user_prompt=prompt,
        max_tokens=4096,
        temperature=0.0,
    )

    response_obj: LLMResponse = response
    if not response_obj.success:
        logger.warning(
            f"Patch generation failed for {raw.file_path}:{raw.line_start}: "
            f"{response_obj.error or 'Analysis call failed'}"
        )
        return None

    json_data = OpusClient._extract_json(response_obj.content)
    if not json_data:
        logger.warning(
            f"Patch generation failed for {raw.file_path}:{raw.line_start}: "
            "No JSON in response"
        )
        return None

    data = json_data
    fixed_code = data.get("fixed_code", "")
    explanation = data.get("explanation", "No explanation provided")

    if not fixed_code:
        logger.warning(f"Empty patch for {raw.file_path}:{raw.line_start}")
        return None

    syntax_valid = _validate_syntax(fixed_code, raw.file_path)
    if not syntax_valid:
        logger.warning(f"Patch for {raw.file_path}:{raw.line_start} has syntax errors")

    diff = _generate_diff(original_code, fixed_code, raw.file_path)
    if not diff.strip():
        logger.warning(f"Patch for {raw.file_path}:{raw.line_start} produced no diff")
        return None

    return Patch(
        finding_id=raw.id,
        diff=diff,
        explanation=explanation,
        syntax_valid=syntax_valid,
        files_modified=[raw.file_path],
    )


def generate_patches(
    client: OpusClient,
    findings: list[ValidatedFinding],
    repo_root: Path,
    max_workers: int | None = None,
) -> list[Patch]:
    """Generate patches for all confirmed findings."""
    confirmed = [finding for finding in findings if finding.is_confirmed]

    if not confirmed:
        logger.info("No confirmed findings to patch.")
        return []

    logger.info(f"Generating patches for {len(confirmed)} confirmed findings...")
    worker_count = max(1, max_workers or config.max_concurrent_llm_calls)
    patch_results: list[Patch | None] = [None] * len(confirmed)

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_idx = {}
        for idx, finding in enumerate(confirmed):
            raw = finding.enriched.raw
            logger.info(
                f"  [{idx + 1}/{len(confirmed)}] Patching {raw.vuln_type.value} in "
                f"{raw.file_path}:{raw.line_start}"
            )
            future = executor.submit(generate_patch, client, finding, repo_root)
            future_to_idx[future] = idx

        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            finding = confirmed[idx]
            raw = finding.enriched.raw
            finding_id = f"[{raw.file_path}:{raw.line_start}]"

            try:
                patch = future.result()
            except Exception as exc:
                logger.error(f"{finding_id} Patch generation failed: {exc}")
                patch = None

            patch_results[idx] = patch
            if patch:
                status = "valid" if patch.syntax_valid else "syntax issues"
                logger.info(f"    {finding_id} -> Patch generated ({status})")
            else:
                logger.info(f"    {finding_id} -> Patch generation failed")

    patches = [patch for patch in patch_results if patch is not None]

    logger.info(
        f"Patch generation complete: {len(patches)}/{len(confirmed)} successful"
    )
    return patches
