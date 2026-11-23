"""Provider Clients — selects and calls LLM providers through alias resolution.

Algorithm:
  1. Resolve alias → provider list
  2. Filter by policy (airgapped, local_only, cloud_allowed)
  3. Try providers in order: WRB first, then cloud fallbacks
  4. Return first successful response
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from src.llm_gateway.router import AllProvidersFailedError

logger = logging.getLogger(__name__)

_PROVIDER_TIMEOUT = 300.0
_WRB_TIMEOUT = 120.0
_CLOUD_TIMEOUT = 120.0


def _nvidia_nim_base_url() -> str:
    """Self-hosted NIM base URL from the environment (empty → provider disabled)."""
    return (os.environ.get("NVIDIA_NIM_BASE_URL") or "").strip()


ALIAS_REGISTRY: dict[str, dict[str, Any]] = {
    "argus-pentest-primary": {
        "role": "pentest",
        "providers": [
            {
                "key": "whiterabbitneo-7b",
                "base_url": "http://whiterabbitneo:8000/v1",
                "model": "taico-ai/WhiteRabbitNeo-v3-7B",
                "cloud_allowed": False,
                "price": {"input_per_million_usd": 0.0, "output_per_million_usd": 0.0},
            },
        ],
    },
    "argus-planner-fast": {
        "role": "planner",
        "providers": [
            {
                "key": "deepseek-v4-flash",
                "base_url": "https://api.deepseek.com/v1",
                "model": "deepseek-chat",
                "cloud_allowed": True,
                "price": {
                    "input_per_million_usd": 0.14,
                    "output_per_million_usd": 0.28,
                },
            },
        ],
    },
    "argus-planner-deep": {
        "role": "reasoning",
        "providers": [
            {
                "key": "deepseek-v4-pro",
                "base_url": "https://api.deepseek.com/v1",
                "model": "deepseek-v4-pro",
                "cloud_allowed": True,
                "price": {
                    "input_per_million_usd": 0.28,
                    "output_per_million_usd": 0.56,
                },
            },
        ],
    },
    "argus-code-cloud": {
        "role": "code",
        "providers": [
            {
                "key": "qwen3-coder-480b",
                "base_url": "https://openrouter.ai/api/v1",
                "model": "qwen/qwen3-coder:free",
                "cloud_allowed": True,
                "price": {
                    "input_per_million_usd": 0.15,
                    "output_per_million_usd": 0.15,
                },
            },
        ],
    },
    "argus-code-local": {
        "role": "code",
        "providers": [
            {
                "key": "qwen3-32b-local",
                "base_url": "http://qwen3-32b-coder.llm-serving.svc:8000/v1",
                "model": "qwen3-32b",
                "cloud_allowed": False,
                "price": {"input_per_million_usd": 0.0, "output_per_million_usd": 0.0},
            },
        ],
    },
    "argus-devsecops-local": {
        "role": "devsecops",
        "providers": [
            {
                "key": "whiterabbitneo-7b",
                "base_url": "http://whiterabbitneo:8000/v1",
                "model": "taico-ai/WhiteRabbitNeo-v3-7B",
                "cloud_allowed": False,
                "price": {"input_per_million_usd": 0.0, "output_per_million_usd": 0.0},
            },
        ],
    },
    "argus-report": {
        "role": "report",
        "providers": [
            {
                "key": "deepseek-v4-pro",
                "base_url": "https://api.deepseek.com/v1",
                "model": "deepseek-v4-pro",
                "cloud_allowed": True,
                "price": {
                    "input_per_million_usd": 0.28,
                    "output_per_million_usd": 0.56,
                },
            },
        ],
    },
    "argus-osint": {
        "role": "osint",
        "providers": [
            {
                "key": "perplexity",
                "base_url": "https://api.perplexity.ai",
                "model": "sonar",
                "cloud_allowed": True,
                "price": {
                    "input_per_million_usd": 1.00,
                    "output_per_million_usd": 1.00,
                },
            },
        ],
    },
    # WP C — hosted NVIDIA NIM (build.nvidia.com). Cloud-fallback / rotation member
    # for NON-sensitive tasks only (reports, OSINT triage). ``sensitive_allowed`` is
    # False so it is never selected for pentest analysis (WRB-001). Egress passes the
    # redaction gate (src.llm_gateway.redaction.redact_for_cloud_egress).
    "argus-nvidia-hosted": {
        "role": "report",
        "providers": [
            {
                "key": "nvidia-hosted",
                "base_url": "https://integrate.api.nvidia.com/v1",
                "model": "meta/llama-3.3-70b-instruct",
                "cloud_allowed": True,
                "sensitive_allowed": False,
                "price": {
                    "input_per_million_usd": 0.0,
                    "output_per_million_usd": 0.0,
                },
            },
        ],
    },
    # Self-hosted NIM container: provider is LOCAL (``cloud_allowed=False``), so it
    # may sit beside WRB in analysis rotations without breaking WRB-001. Disabled
    # until ``NVIDIA_NIM_BASE_URL`` is set (empty base_url → skipped by select).
    "argus-nvidia-nim-local": {
        "role": "pentest",
        "providers": [
            {
                "key": "nvidia-nim-local",
                "base_url": _nvidia_nim_base_url(),
                "model": "meta/llama-3.1-8b-instruct",
                "cloud_allowed": False,
                "price": {"input_per_million_usd": 0.0, "output_per_million_usd": 0.0},
            },
        ],
    },
}


class ProviderRouter:
    def __init__(self) -> None:
        self._calls: dict[str, int] = {}
        self._spent: dict[str, float] = {}

    async def select_provider(
        self,
        alias: str,
        policy: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        alias_cfg = ALIAS_REGISTRY.get(alias)
        if not alias_cfg:
            raise AllProvidersFailedError(f"Unknown alias: {alias}")

        compliance = (policy or {}).get("compliance", {})
        airgapped = compliance.get("airgapped_only", False)
        # WP C — a sensitive task (pentest analysis) must never select a provider that
        # declares ``sensitive_allowed=False`` (hosted NVIDIA). Defence in depth over
        # the facade's WRB-001 routing; ``sensitive_allowed`` defaults True so existing
        # providers are unaffected.
        sensitive = bool((policy or {}).get("sensitive", False))

        for provider in alias_cfg["providers"]:
            if airgapped and provider.get("cloud_allowed", True):
                continue
            if sensitive and not provider.get("sensitive_allowed", True):
                continue
            if not provider.get("cloud_allowed", True) and not provider.get("base_url"):
                continue
            self._calls[provider["key"]] = self._calls.get(provider["key"], 0) + 1
            return provider

        raise AllProvidersFailedError(f"No available providers for alias {alias}")

    async def call_provider(
        self,
        provider: dict[str, Any],
        messages: list[dict[str, str]],
        *,
        temperature: float = 0.2,
        max_tokens: int = 2000,
    ) -> dict[str, Any]:
        key = provider["key"]
        base_url = provider["base_url"]
        model = provider["model"]
        is_local = not provider.get("cloud_allowed", True)
        timeout = _WRB_TIMEOUT if is_local else _CLOUD_TIMEOUT

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        api_key = self._get_api_key(key)
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(
                    f"{base_url}/chat/completions",
                    json=payload,
                    headers=headers,
                )
                resp.raise_for_status()
                data = resp.json()

            choices = data.get("choices", [])
            if not choices:
                raise AllProvidersFailedError(f"Empty response from {key}")

            content = choices[0].get("message", {}).get("content", "")
            usage = data.get("usage", {})

            return {
                "content": content.strip(),
                "usage": {
                    "prompt_tokens": usage.get("prompt_tokens", 0),
                    "completion_tokens": usage.get("completion_tokens", 0),
                    "total_tokens": usage.get("total_tokens", 0),
                },
                "model": model,
                "provider": key,
            }
        except httpx.TimeoutException:
            raise AllProvidersFailedError(f"Provider {key} timed out") from None
        except Exception as exc:
            raise AllProvidersFailedError(f"Provider {key} failed: {exc}") from exc

    def _get_api_key(self, provider_key: str) -> str:
        import os

        key_map = {
            "whiterabbitneo-7b": "WHITERABBITNEO_API_KEY",
            "deepseek-v4-flash": "DEEPSEEK_API_KEY",
            "deepseek-v4-pro": "DEEPSEEK_API_KEY",
            "qwen3-coder-480b": "OPENROUTER_API_KEY",
            "qwen3-32b-local": "",
            "perplexity": "PERPLEXITY_API_KEY",
            # WP C — hosted NVIDIA uses NVIDIA_API_KEY; self-hosted NIM is keyless.
            "nvidia-hosted": "NVIDIA_API_KEY",
            "nvidia-nim-local": "",
        }
        env_key = key_map.get(provider_key, "")
        return (os.environ.get(env_key) or "").strip() if env_key else ""
