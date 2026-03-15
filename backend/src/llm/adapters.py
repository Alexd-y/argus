"""LLM provider adapters — OpenAI, DeepSeek, OpenRouter, Gemini, Kimi, Perplexity."""

import os
from typing import Any

import httpx

# OpenAI-compatible request format
_OPENAI_CHAT_URL = "/v1/chat/completions"

# Provider configs: (env_key, base_url, default_model)
_PROVIDERS: list[tuple[str, str, str]] = [
    ("OPENAI_API_KEY", "https://api.openai.com", "gpt-4o-mini"),
    ("DEEPSEEK_API_KEY", "https://api.deepseek.com", "deepseek-chat"),
    ("OPENROUTER_API_KEY", "https://openrouter.ai/api", "openai/gpt-4o-mini"),
    ("KIMI_API_KEY", "https://api.moonshot.cn", "moonshot-v1-8k"),
    ("PERPLEXITY_API_KEY", "https://api.perplexity.ai", "sonar"),
]


def _get_key(env_key: str) -> str | None:
    """Get env value, return None if empty or missing."""
    v = os.environ.get(env_key)
    return (v or "").strip() or None


class OpenAICompatibleAdapter:
    """Adapter for OpenAI-compatible APIs (OpenAI, DeepSeek, OpenRouter, Kimi, Perplexity)."""

    def __init__(self, env_key: str, base_url: str, default_model: str) -> None:
        self._env_key = env_key
        self._base_url = base_url.rstrip("/")
        self._default_model = default_model

    def is_available(self) -> bool:
        return _get_key(self._env_key) is not None

    async def call(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        model: str | None = None,
    ) -> str:
        key = _get_key(self._env_key)
        if not key:
            raise RuntimeError(f"Provider not configured: {self._env_key}")

        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": model or self._default_model,
            "messages": messages,
            "temperature": 0.3,
        }

        url = f"{self._base_url}{_OPENAI_CHAT_URL}"
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()

        choices = data.get("choices", [])
        if not choices:
            raise ValueError("Empty response from LLM")
        content = choices[0].get("message", {}).get("content", "")
        return (content or "").strip()


class GeminiAdapter:
    """Adapter for Google Gemini API (GOOGLE_API_KEY)."""

    def __init__(self) -> None:
        self._env_key = "GOOGLE_API_KEY"
        self._default_model = "gemini-1.5-flash"

    def is_available(self) -> bool:
        return _get_key(self._env_key) is not None

    async def call(
        self,
        prompt: str,
        *,
        system_prompt: str | None = None,
        model: str | None = None,
    ) -> str:
        key = _get_key(self._env_key)
        if not key:
            raise RuntimeError(f"Provider not configured: {self._env_key}")

        full_prompt = prompt
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"

        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model or self._default_model}:generateContent?key={key}"
        )
        payload = {
            "contents": [{"parts": [{"text": full_prompt}]}],
            "generationConfig": {"temperature": 0.3},
        }

        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()

        candidates = data.get("candidates", [])
        if not candidates:
            raise ValueError("Empty response from Gemini")
        parts = candidates[0].get("content", {}).get("parts", [])
        if not parts:
            return ""
        return (parts[0].get("text", "") or "").strip()


def _build_adapters() -> list[OpenAICompatibleAdapter | GeminiAdapter]:
    """Build list of adapters in priority order."""
    adapters: list[OpenAICompatibleAdapter | GeminiAdapter] = []
    for env_key, base_url, default_model in _PROVIDERS:
        adapters.append(OpenAICompatibleAdapter(env_key, base_url, default_model))
    adapters.append(GeminiAdapter())
    return adapters


_ADAPTERS = _build_adapters()


def get_available_adapters() -> list[OpenAICompatibleAdapter | GeminiAdapter]:
    """Return adapters that are configured (env key present)."""
    return [a for a in _ADAPTERS if a.is_available()]
