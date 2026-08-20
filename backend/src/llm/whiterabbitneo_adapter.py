"""WhiteRabbitNeo adapter — primary pentest AI, OpenAI-compatible via vLLM.
WhiteRabbitNeo V3 7B is the single source of truth for all pentest analysis.
Cloud providers (DeepSeek, OpenAI, Perplexity) serve only as report supplements.
"""

import json
import logging
from typing import Any

import httpx

from src.llm.base import LLMAdapter

logger = logging.getLogger(__name__)

WRB_DEFAULT_MODEL = "taico-ai/WhiteRabbitNeo-v3-7B"
WRB_DEFAULT_MAX_TOKENS = 4096
WRB_DEFAULT_TEMPERATURE = 0.3
WRB_DEFAULT_TIMEOUT = 3600.0
# WhiteRabbitNeo v3 7B context window (tokens). Source of truth: the unified
# model registry (src/llm/registry.py → provider_id "local_wrb"). The adapter
# factory reads the live registry value; this default mirrors it.
WRB_DEFAULT_MAX_CONTEXT_TOKENS = 32768
# Conservative chars-per-token estimate for prompt-budget math — undershoots so
# the rendered prompt never overflows the model context window.
_CHARS_PER_TOKEN = 3
# Prompt token floor so a large ``max_tokens`` can never starve the prompt.
_MIN_PROMPT_TOKENS = 1024
# Character budget for the combined prompt at the DEFAULT context window.
# Replaces the previous blunt 8 KiB byte cut that silently dropped ~75% of the
# available WRB context on every ``call_with_usage``. Still exported for the
# admin diagnostic dashboard (``WrbDashboardOut.max_prompt_bytes``).
WRB_MAX_PROMPT_BYTES = (WRB_DEFAULT_MAX_CONTEXT_TOKENS - WRB_DEFAULT_MAX_TOKENS) * _CHARS_PER_TOKEN


class WhiteRabbitNeoAdapter(LLMAdapter):
    """Primary pentest AI — all scan phases run through this adapter first.
    Falls back to cloud providers only when explicitly configured for
    report-supplement tasks (REPORT_SECTION, EXECUTIVE_SUMMARY).
    """

    def __init__(
        self,
        base_url: str = "",
        api_key: str = "",
        *,
        timeout_sec: float = WRB_DEFAULT_TIMEOUT,
        max_context_tokens: int = WRB_DEFAULT_MAX_CONTEXT_TOKENS,
    ) -> None:
        self._base_url: str = base_url.rstrip("/") if base_url else ""
        self._api_key: str = api_key
        self._timeout_sec: float = max(10.0, float(timeout_sec))
        self._max_context_tokens: int = max(2048, int(max_context_tokens))

    def _httpx_timeout(self) -> httpx.Timeout:
        return httpx.Timeout(
            connect=30.0,
            read=self._timeout_sec,
            write=self._timeout_sec,
            pool=30.0,
        )

    @property
    def base_url(self) -> str:
        return self._base_url

    @property
    def is_configured(self) -> bool:
        return bool(self._base_url)

    def is_available(self) -> bool:
        return bool(self._base_url)

    def _prompt_char_budget(self, max_tokens: int) -> int:
        """Character budget for the combined prompt, derived from the context window.

        Reserves ``max_tokens`` for the completion and converts the remaining
        context tokens to characters with a conservative ratio, so prompts are
        trimmed to the REAL WRB window (registry-driven) instead of a blunt fixed
        byte cut that discarded most of the available context.
        """
        usable_tokens = max(_MIN_PROMPT_TOKENS, self._max_context_tokens - max(0, max_tokens))
        return usable_tokens * _CHARS_PER_TOKEN

    async def call(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        model: str | None = None,
        max_tokens: int = WRB_DEFAULT_MAX_TOKENS,
        temperature: float = WRB_DEFAULT_TEMPERATURE,
    ) -> str:
        if not self._base_url:
            raise RuntimeError("WhiteRabbitNeo not configured: WHITERABBITNEO_URL is empty")

        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": model or WRB_DEFAULT_MODEL,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        url = f"{self._base_url}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        async with httpx.AsyncClient(timeout=self._httpx_timeout()) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                body = (resp.text or "")[:2000]
                prompt_bytes = len(payload.get("messages", [{}])[-1].get("content", ""))
                logger.error(
                    "whiterabbitneo_http_error",
                    extra={
                        "event": "whiterabbitneo_http_error",
                        "status": resp.status_code,
                        "body": body,
                        "prompt_bytes": prompt_bytes,
                        "prompt_bytes_total": len(json.dumps(payload)),
                    },
                )
            resp.raise_for_status()
            data = resp.json()

        choices = data.get("choices", [])
        if not choices:
            raise ValueError("Empty response from WhiteRabbitNeo")

        content: str = choices[0].get("message", {}).get("content", "")
        return content.strip()

    async def call_with_usage(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        model: str | None = None,
        max_tokens: int = WRB_DEFAULT_MAX_TOKENS,
        temperature: float = WRB_DEFAULT_TEMPERATURE,
    ) -> tuple[str, dict[str, int]]:
        """Call and return (text, usage_dict) with token counts."""
        if not self._base_url:
            raise RuntimeError("WhiteRabbitNeo not configured: WHITERABBITNEO_URL is empty")

        # Trim to the REAL WRB context window (registry-driven) instead of a blunt
        # fixed byte cut. The system prompt may take up to half the budget; the
        # user prompt takes the remainder.
        budget = self._prompt_char_budget(max_tokens)
        system_prompt = system_prompt or ""
        if len(system_prompt) > budget // 2:
            system_prompt = system_prompt[: budget // 2]
        remaining = max(0, budget - len(system_prompt))
        if len(prompt) > remaining:
            prompt = prompt[:remaining]

        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": model or WRB_DEFAULT_MODEL,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        url = f"{self._base_url}/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        async with httpx.AsyncClient(timeout=self._httpx_timeout()) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code != 200:
                body = (resp.text or "")[:2000]
                prompt_bytes = len(payload.get("messages", [{}])[-1].get("content", ""))
                logger.error(
                    "whiterabbitneo_http_error",
                    extra={
                        "event": "whiterabbitneo_http_error",
                        "status": resp.status_code,
                        "body": body,
                        "prompt_bytes": prompt_bytes,
                        "prompt_bytes_total": len(json.dumps(payload)),
                    },
                )
            resp.raise_for_status()
            data = resp.json()

        choices = data.get("choices", [])
        if not choices:
            raise ValueError("Empty response from WhiteRabbitNeo")

        content: str = choices[0].get("message", {}).get("content", "")
        usage_raw: dict[str, Any] = data.get("usage", {})
        usage = {
            "prompt_tokens": int(usage_raw.get("prompt_tokens", 0)),
            "completion_tokens": int(usage_raw.get("completion_tokens", 0)),
            "total_tokens": int(usage_raw.get("total_tokens", 0)),
        }
        return content.strip(), usage

    async def health_check(self) -> dict[str, Any]:
        """Check WhiteRabbitNeo availability."""
        if not self._base_url:
            return {"status": "unconfigured"}
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"{self._base_url}/models")
                resp.raise_for_status()
                return {"status": "available", "models": len(resp.json().get("data", []))}
        except Exception as exc:
            return {"status": "unavailable", "error": str(exc)}


_wrb_adapter: WhiteRabbitNeoAdapter | None = None


def _resolve_wrb_max_context() -> int:
    """Read WRB's context window from the unified model registry (fail-safe).

    Lazily imported to keep this low-level adapter module decoupled from the
    registry at import time (mirrors the lazy ``settings`` import below and
    avoids an import cycle). Falls back to
    :data:`WRB_DEFAULT_MAX_CONTEXT_TOKENS` if the registry is unavailable.
    """
    try:
        from src.llm.registry import ProviderRegistry

        record = ProviderRegistry().get("local_wrb")
    except (ImportError, AttributeError, TypeError, ValueError):
        return WRB_DEFAULT_MAX_CONTEXT_TOKENS
    if record is not None and record.capabilities.max_context > 0:
        return int(record.capabilities.max_context)
    return WRB_DEFAULT_MAX_CONTEXT_TOKENS


def get_whiterabbitneo_adapter() -> WhiteRabbitNeoAdapter:
    global _wrb_adapter
    if _wrb_adapter is None:
        from src.core.config import settings

        _wrb_adapter = WhiteRabbitNeoAdapter(
            base_url=settings.whiterabbitneo_url,
            api_key=settings.whiterabbitneo_api_key,
            timeout_sec=float(settings.whiterabbitneo_timeout_seconds),
            max_context_tokens=_resolve_wrb_max_context(),
        )
    return _wrb_adapter


def reset_whiterabbitneo_adapter() -> None:
    global _wrb_adapter
    _wrb_adapter = None
