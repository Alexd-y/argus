"""LLM config helpers — check API keys and provide sync callable for recon reporting.

Used by anomaly_builder and stage2_builder when LLM interpretation is available.
Uses OpenAI-compatible API (OpenAI package with base_url for OpenRouter, etc.).
"""

import logging
import os
from collections.abc import Callable

logger = logging.getLogger(__name__)

LLM_KEYS = [
    "OPENAI_API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENROUTER_API_KEY",
    "GOOGLE_API_KEY",
    "KIMI_API_KEY",
    "PERPLEXITY_API_KEY",
]

# Provider configs: (env_key, base_url, default_model)
_PROVIDER_CONFIG: list[tuple[str, str, str]] = [
    ("OPENROUTER_API_KEY", "https://openrouter.ai/api/v1", "openai/gpt-4o-mini"),
    ("OPENAI_API_KEY", "https://api.openai.com/v1", "gpt-4o-mini"),
    ("DEEPSEEK_API_KEY", "https://api.deepseek.com/v1", "deepseek-chat"),
    ("KIMI_API_KEY", "https://api.moonshot.cn/v1", "moonshot-v1-8k"),
    ("PERPLEXITY_API_KEY", "https://api.perplexity.ai", "sonar"),
]


def has_any_llm_key() -> bool:
    """Check os.environ for any non-empty key from LLM_KEYS."""
    for key in LLM_KEYS:
        val = os.environ.get(key, "").strip()
        if val:
            return True
    return False


def _get_first_available_provider() -> tuple[str, str, str] | None:
    """Return (env_key, base_url, default_model) for first configured provider."""
    for env_key, base_url, default_model in _PROVIDER_CONFIG:
        val = os.environ.get(env_key, "").strip()
        if val:
            return (env_key, base_url, default_model)
    return None


def get_llm_provider_info() -> tuple[str, str] | None:
    """Return (provider_name, model) for first configured provider, or None."""
    p = _get_first_available_provider()
    if not p:
        return None
    env_key, _, default_model = p
    name = env_key.replace("_API_KEY", "").replace("_", " ").title()
    return (name, default_model)


def get_llm_client() -> Callable[[str, dict], str]:
    """Return sync callable that calls first available LLM with given prompt.

    Returns:
        call_llm(prompt: str, context: dict) -> str
    """
    provider = _get_first_available_provider()
    if not provider:
        raise RuntimeError(
            "No LLM provider configured. Set one of: "
            + ", ".join(LLM_KEYS)
        )

    env_key, base_url, default_model = provider
    api_key = os.environ.get(env_key, "").strip()

    try:
        from openai import OpenAI
    except ImportError:
        raise RuntimeError(
            "openai package required for LLM. Install with: pip install openai"
        ) from None

    client = OpenAI(api_key=api_key, base_url=base_url.rstrip("/"))

    def call_llm(prompt: str, context: dict) -> str:
        """Sync LLM call. context is passed for future use (e.g. model override)."""
        try:
            messages: list[dict[str, str]] = [{"role": "user", "content": prompt}]
            resp = client.chat.completions.create(
                model=default_model,
                messages=messages,
                temperature=0.3,
            )
            choices = resp.choices or []
            if not choices:
                return ""
            msg = choices[0].message
            text = getattr(msg, "content", None) or ""
            return (text or "").strip()
        except Exception as e:
            logger.debug("LLM call failed", extra={"error_type": type(e).__name__})
            return ""

    return call_llm
