"""Adversarial false-positive reviewer using Claude Opus 4.6.

For each finding, generates the strongest possible argument that it's
a false positive, then evaluates that argument's strength.
"""

from __future__ import annotations

import logging

from securescan.analyze.codebase_digest import CodebaseDigest
from securescan.analyze.opus_client import LLMResponse, OpusClient
from securescan.detect.models import EnrichedFinding, ValidatedFinding, ValidationStatus

logger = logging.getLogger(__name__)

ADVERSARIAL_SYSTEM_PROMPT = """\
You are a defense attorney for code. Your job is to argue that reported
security vulnerabilities are actually FALSE POSITIVES.

You must make the STRONGEST possible case that each finding is not a real
vulnerability. Look for:
- Sanitization or validation the original analyst may have missed
- Framework-level protections that apply automatically
- Code paths that are unreachable from external input
- Test code, example code, or dead code
- Compensating controls elsewhere in the codebase
- Incorrect assumptions about data flow

After making your argument, honestly evaluate how strong it is.
A strong argument means the finding should be reconsidered.
A weak argument means the finding is likely genuine.

Always respond with valid JSON matching the requested schema."""


def _build_adversarial_prompt(
    finding: EnrichedFinding,
    digest: CodebaseDigest,
) -> str:
    """Build the adversarial review prompt."""

    extended_context = ""
    for section in digest.sections:
        if finding.raw.file_path in section.heading:
            extended_context = section.content
            break

    if not extended_context:
        extended_context = finding.raw.code_snippet

    return f"""\
A security analyst has flagged the following as a vulnerability.
Your job is to argue it is a FALSE POSITIVE.

## Reported Finding
- **Type:** {finding.raw.vuln_type.value}
- **File:** {finding.raw.file_path}:{finding.raw.line_start}
- **Severity:** {finding.severity.value}
- **CVSS Estimate:** {finding.cvss_estimate}
- **Analyst's Reasoning:** {finding.reasoning}
- **Taint Chain:** {finding.taint_chain or 'Not specified'}
- **Exploitability:** {finding.exploitability.value}

## Code Context
{extended_context}

## Your Task
1. Make the STRONGEST possible argument that this is NOT a real vulnerability.
2. Then evaluate your own argument honestly.

Respond ONLY with a JSON object:
{{
    "fp_argument": "Your strongest case for false positive...",
    "fp_argument_strength": "strong" or "moderate" or "weak",
    "rebuttal": "Why the finding might still be valid despite your argument...",
    "final_verdict": "confirmed_vulnerable" or "likely_fp" or "uncertain",
    "adjusted_confidence": 0.0 to 1.0
}}"""


_VALIDATION_MAP = {
    "confirmed_vulnerable": ValidationStatus.CONFIRMED,
    "likely_fp": ValidationStatus.LIKELY_FP,
    "uncertain": ValidationStatus.UNCERTAIN,
}


def _parse_adversarial_response(
    finding: EnrichedFinding,
    response: LLMResponse,
) -> ValidatedFinding:
    """Parse the adversarial review response."""

    if not response.success or not response.json_data:
        logger.warning(
            f"Adversarial review failed for "
            f"{finding.raw.file_path}:{finding.raw.line_start}. "
            f"Defaulting to confirmed."
        )
        return ValidatedFinding(
            enriched=finding,
            validation_status=ValidationStatus.CONFIRMED,
            fp_argument="Adversarial review unavailable",
            fp_rebuttal="Original analysis stands by default",
            final_confidence=finding.raw.confidence,
        )

    data = response.json_data

    return ValidatedFinding(
        enriched=finding,
        validation_status=_VALIDATION_MAP.get(
            data.get("final_verdict", "confirmed_vulnerable"),
            ValidationStatus.CONFIRMED,
        ),
        fp_argument=data.get("fp_argument", "No argument provided"),
        fp_rebuttal=data.get("rebuttal", "No rebuttal provided"),
        final_confidence=float(data.get("adjusted_confidence", finding.raw.confidence)),
    )


def review_findings(
    client: OpusClient,
    findings: list[EnrichedFinding],
    digest: CodebaseDigest,
    confidence_threshold: float = 0.7,
) -> list[ValidatedFinding]:
    """Run adversarial review on enriched findings."""

    validated: list[ValidatedFinding] = []

    logger.info(f"Running adversarial review on {len(findings)} findings...")

    for index, finding in enumerate(findings, 1):
        logger.info(
            f"  [{index}/{len(findings)}] Reviewing {finding.raw.vuln_type.value} in "
            f"{finding.raw.file_path}:{finding.raw.line_start}"
        )

        prompt = _build_adversarial_prompt(finding, digest)

        response = client.analyze(
            system_prompt=ADVERSARIAL_SYSTEM_PROMPT,
            user_prompt=prompt,
            max_tokens=2048,
            temperature=0.0,
            expect_json=True,
        )

        result = _parse_adversarial_response(finding, response)
        validated.append(result)

        status_text = {
            ValidationStatus.CONFIRMED: "CONFIRMED",
            ValidationStatus.LIKELY_FP: "LIKELY FP",
            ValidationStatus.UNCERTAIN: "UNCERTAIN",
        }[result.validation_status]

        fp_strength = response.json_data.get("fp_argument_strength", "?") if response.json_data else "N/A"
        logger.info(
            f"    -> {status_text} "
            f"(confidence: {result.final_confidence:.2f}, FP argument: {fp_strength})"
        )

    confirmed = sum(
        1 for finding in validated if finding.validation_status == ValidationStatus.CONFIRMED
    )
    likely_fp = sum(
        1 for finding in validated if finding.validation_status == ValidationStatus.LIKELY_FP
    )
    uncertain = sum(
        1 for finding in validated if finding.validation_status == ValidationStatus.UNCERTAIN
    )

    logger.info(
        f"Adversarial review complete: "
        f"{confirmed} confirmed, {likely_fp} likely FP, {uncertain} uncertain "
        f"(threshold: {confidence_threshold})"
    )

    return validated
