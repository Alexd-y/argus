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
WRB_DEFAULT_TIMEOUT = 1800.0
WRB_MAX_PROMPT_BYTES = 8192


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
    ) -> None:
        self._base_url: str = base_url.rstrip("/") if base_url else ""
        self._api_key: str = api_key
        self._timeout_sec: float = max(10.0, float(timeout_sec))

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

        # Truncate prompts to fit WRB context window (7B model ~8k tokens)
        system_prompt = (system_prompt or "")[:WRB_MAX_PROMPT_BYTES]
        prompt = prompt[:WRB_MAX_PROMPT_BYTES]

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


def get_whiterabbitneo_adapter() -> WhiteRabbitNeoAdapter:
    global _wrb_adapter
    if _wrb_adapter is None:
        from src.core.config import settings

        _wrb_adapter = WhiteRabbitNeoAdapter(
            base_url=settings.whiterabbitneo_url,
            api_key=settings.whiterabbitneo_api_key,
            timeout_sec=float(settings.whiterabbitneo_timeout_seconds),
        )
    return _wrb_adapter


def reset_whiterabbitneo_adapter() -> None:
    global _wrb_adapter
    _wrb_adapter = None
