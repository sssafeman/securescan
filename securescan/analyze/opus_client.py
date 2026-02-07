"""Anthropic Claude Opus 4.6 API client.

Provides a robust interface for making LLM calls with:
- Automatic retry with exponential backoff
- Structured JSON response parsing
- Token usage tracking
- Timeout handling
- Rate limit awareness
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any

try:
    import httpx
except ModuleNotFoundError:  # pragma: no cover - environment dependent
    httpx = None

from securescan.config import config

logger = logging.getLogger(__name__)

# API constants
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_API_VERSION = "2023-06-01"


@dataclass
class LLMResponse:
    """Parsed response from the LLM."""

    content: str
    json_data: dict[str, Any] | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""
    latency_ms: float = 0.0
    success: bool = True
    error: str | None = None


@dataclass
class TokenUsageTracker:
    """Tracks cumulative token usage across calls."""

    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_calls: int = 0
    failed_calls: int = 0

    def record(self, response: LLMResponse) -> None:
        self.total_calls += 1
        if response.success:
            self.total_input_tokens += response.input_tokens
            self.total_output_tokens += response.output_tokens
        else:
            self.failed_calls += 1

    @property
    def total_tokens(self) -> int:
        return self.total_input_tokens + self.total_output_tokens

    def summary(self) -> str:
        return (
            f"LLM Usage: {self.total_calls} calls "
            f"({self.failed_calls} failed) | "
            f"{self.total_input_tokens:,} input + "
            f"{self.total_output_tokens:,} output = "
            f"{self.total_tokens:,} total tokens"
        )


if httpx is not None:
    HTTPStatusError = httpx.HTTPStatusError
    TimeoutException = httpx.TimeoutException
else:
    class HTTPStatusError(Exception):
        """Fallback for environments without httpx."""

    class TimeoutException(Exception):
        """Fallback for environments without httpx."""


class OpusClient:
    """Client for Claude Opus 4.6 API calls."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        max_retries: int = 3,
        base_timeout: float = 120.0,
    ):
        self.api_key = api_key or config.anthropic_api_key
        self.model = model or config.opus_model
        self.max_retries = max_retries
        self.base_timeout = base_timeout
        self.usage = TokenUsageTracker()

        if httpx is None:
            raise ValueError(
                "httpx is not installed. Install with: pip install httpx"
            )

        if not self.api_key:
            raise ValueError(
                "Anthropic API key not set. "
                "Set ANTHROPIC_API_KEY in .env or pass api_key parameter."
            )

        self._client = httpx.Client(
            timeout=httpx.Timeout(base_timeout, connect=10.0),
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": ANTHROPIC_API_VERSION,
                "content-type": "application/json",
            },
        )

    def _make_request(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> dict[str, Any]:
        """Make a raw API request to the Anthropic Messages API."""

        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }

        response = self._client.post(ANTHROPIC_API_URL, json=payload)
        response.raise_for_status()
        return response.json()

    def _parse_response(
        self,
        raw: dict[str, Any],
        expect_json: bool,
        start_time: float,
    ) -> LLMResponse:
        """Parse a raw API response into an LLMResponse."""

        content_blocks = raw.get("content", [])
        text_parts = [
            block["text"]
            for block in content_blocks
            if block.get("type") == "text"
        ]
        content = "\n".join(text_parts)

        usage = raw.get("usage", {})
        input_tokens = usage.get("input_tokens", 0)
        output_tokens = usage.get("output_tokens", 0)

        json_data = None
        if expect_json and content:
            json_data = self._extract_json(content)

        latency = (time.time() - start_time) * 1000

        return LLMResponse(
            content=content,
            json_data=json_data,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model=raw.get("model", self.model),
            latency_ms=latency,
            success=True,
        )

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any] | None:
        """Extract JSON from LLM response text."""

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        json_block = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
        if json_block:
            try:
                return json.loads(json_block.group(1))
            except json.JSONDecodeError:
                pass

        first_brace = text.find("{")
        last_brace = text.rfind("}")
        if first_brace != -1 and last_brace > first_brace:
            try:
                return json.loads(text[first_brace : last_brace + 1])
            except json.JSONDecodeError:
                pass

        logger.warning("Failed to extract JSON from LLM response")
        return None

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        expect_json: bool = False,
    ) -> LLMResponse:
        """Make an analysis call to Opus 4.6 with retry logic."""

        last_error = None

        for attempt in range(self.max_retries):
            try:
                start_time = time.time()
                raw = self._make_request(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                response = self._parse_response(raw, expect_json, start_time)
                self.usage.record(response)

                logger.debug(
                    f"Opus call: {response.input_tokens}in + "
                    f"{response.output_tokens}out tokens, "
                    f"{response.latency_ms:.0f}ms"
                )
                return response

            except HTTPStatusError as e:
                status = e.response.status_code if hasattr(e, "response") else None
                last_error = str(e)

                if status == 429:
                    wait = min(2**attempt * 5, 60)
                    logger.warning(
                        f"Rate limited (429). Waiting {wait}s "
                        f"(attempt {attempt + 1}/{self.max_retries})"
                    )
                    time.sleep(wait)
                    continue
                if status == 529:
                    wait = min(2**attempt * 10, 120)
                    logger.warning(
                        f"API overloaded (529). Waiting {wait}s "
                        f"(attempt {attempt + 1}/{self.max_retries})"
                    )
                    time.sleep(wait)
                    continue
                if status in (500, 502, 503):
                    wait = 2**attempt * 2
                    logger.warning(
                        f"Server error ({status}). Retrying in {wait}s "
                        f"(attempt {attempt + 1}/{self.max_retries})"
                    )
                    time.sleep(wait)
                    continue

                logger.error(f"API error ({status}): {e}")
                break

            except TimeoutException:
                last_error = "Request timed out"
                wait = 2**attempt * 3
                logger.warning(
                    f"Timeout. Retrying in {wait}s "
                    f"(attempt {attempt + 1}/{self.max_retries})"
                )
                time.sleep(wait)
                continue

            except Exception as e:
                last_error = str(e)
                logger.error(f"Unexpected error: {e}")
                break

        error_response = LLMResponse(
            content="",
            success=False,
            error=f"Failed after {self.max_retries} attempts: {last_error}",
        )
        self.usage.record(error_response)
        return error_response

    def close(self) -> None:
        """Close the HTTP client."""

        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
