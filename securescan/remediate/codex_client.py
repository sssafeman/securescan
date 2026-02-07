"""OpenAI GPT API client for code generation tasks.

Used for generating remediation patches for confirmed vulnerabilities.
Separate from the Opus client since code generation is GPT's strength.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Any

from securescan.config import config

logger = logging.getLogger(__name__)

OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"

try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:  # pragma: no cover - environment dependent
    HTTPX_AVAILABLE = False


@dataclass
class CodexResponse:
    """Response from the Codex/GPT API."""

    content: str
    json_data: dict[str, Any] | None = None
    model: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0
    success: bool = True
    error: str | None = None


class CodexClient:
    """Client for OpenAI GPT API calls for code generation."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        max_retries: int = 3,
        timeout: float = 90.0,
    ):
        self.api_key = api_key or config.openai_api_key
        self.model = model or config.codex_model
        self.max_retries = max_retries
        self.timeout = timeout

        if not self.api_key:
            raise ValueError(
                "OpenAI API key not set. "
                "Set OPENAI_API_KEY in .env or pass api_key parameter."
            )

        if not HTTPX_AVAILABLE:
            raise ImportError("httpx is required for API calls: pip install httpx")

        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout, connect=10.0),
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
        )

    @staticmethod
    def _extract_json(text: str) -> dict[str, Any] | None:
        """Extract JSON from response text."""
        import re

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

        return None

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = 4096,
        temperature: float = 0.0,
        expect_json: bool = False,
    ) -> CodexResponse:
        """Make a code generation call to GPT."""
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

        last_error = None

        for attempt in range(self.max_retries):
            try:
                start_time = time.time()
                response = self._client.post(OPENAI_API_URL, json=payload)
                response.raise_for_status()
                data = response.json()

                content = data["choices"][0]["message"]["content"]
                usage = data.get("usage", {})

                json_data = None
                if expect_json:
                    json_data = self._extract_json(content)

                latency = (time.time() - start_time) * 1000

                result = CodexResponse(
                    content=content,
                    json_data=json_data,
                    model=data.get("model", self.model),
                    input_tokens=usage.get("prompt_tokens", 0),
                    output_tokens=usage.get("completion_tokens", 0),
                    latency_ms=latency,
                    success=True,
                )

                logger.debug(
                    f"Codex call: {result.input_tokens}in + "
                    f"{result.output_tokens}out tokens, "
                    f"{result.latency_ms:.0f}ms"
                )
                return result

            except httpx.HTTPStatusError as e:
                status = e.response.status_code
                last_error = str(e)

                if status in (429, 500, 502, 503, 529):
                    wait = min(2**attempt * 5, 60)
                    logger.warning(
                        f"Codex API error ({status}). Retrying in {wait}s "
                        f"(attempt {attempt + 1}/{self.max_retries})"
                    )
                    time.sleep(wait)
                    continue

                logger.error(f"Codex API error ({status}): {e}")
                break

            except httpx.TimeoutException:
                last_error = "Request timed out"
                wait = 2**attempt * 3
                logger.warning(
                    f"Codex timeout. Retrying in {wait}s "
                    f"(attempt {attempt + 1}/{self.max_retries})"
                )
                time.sleep(wait)
                continue

            except Exception as e:
                last_error = str(e)
                logger.error(f"Unexpected Codex error: {e}")
                break

        return CodexResponse(
            content="",
            success=False,
            error=f"Failed after {self.max_retries} attempts: {last_error}",
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
