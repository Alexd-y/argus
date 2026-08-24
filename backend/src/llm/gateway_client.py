"""Gateway Client — typed async HTTP client to internal llm-gateway.

OpenAI-compatible request/response. Typed errors: budget exceeded,
policy denied, provider unavailable, schema error.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_GATEWAY_TIMEOUT = 300.0


class GatewayClientError(Exception):
    code: str
    message: str
    details: dict[str, Any]

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


class GatewayResponse:
    def __init__(self, data: dict[str, Any]) -> None:
        self.id: str = data.get("id", "")
        self.model: str = data.get("model", "")
        self.resolved_provider: str = data.get("resolved_provider", "")
        self.resolved_model: str = data.get("resolved_model", "")
        choices = data.get("choices", [])
        self.content: str = ""
        if choices:
            self.content = choices[0].get("message", {}).get("content", "")
        usage = data.get("usage", {})
        self.prompt_tokens: int = usage.get("prompt_tokens", 0)
        self.completion_tokens: int = usage.get("completion_tokens", 0)
        self.total_tokens: int = usage.get("total_tokens", 0)
        self.estimated_cost_usd: float = usage.get("estimated_cost_usd", 0.0)

        pd = data.get("policy_decision", {})
        self.policy_allowed: bool = pd.get("allowed", True)
        self.policy_reason: str | None = pd.get("reason")


class GatewayClient:
    def __init__(self, base_url: str) -> None:
        self._base_url = base_url.rstrip("/")

    async def chat_completion(
        self,
        model: str,
        messages: list[dict[str, str]],
        *,
        policy: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        temperature: float = 0.2,
        max_tokens: int = 2000,
    ) -> GatewayResponse:
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "metadata": metadata or {},
            "policy": policy or {},
        }

        headers = {"Content-Type": "application/json"}

        try:
            async with httpx.AsyncClient(timeout=_GATEWAY_TIMEOUT) as client:
                resp = await client.post(
                    f"{self._base_url}/v1/chat/completions",
                    json=payload, headers=headers,
                )
        except httpx.TimeoutException:
            raise GatewayClientError(
                "llm_gateway_timeout",
                "LLM Gateway request timed out",
            )
        except httpx.ConnectError:
            raise GatewayClientError(
                "llm_gateway_unavailable",
                "LLM Gateway is unreachable",
            )

        if resp.status_code == 403:
            detail = {}
            try:
                detail = resp.json()
                detail = detail.get("detail", detail)
            except Exception:
                pass
            raise GatewayClientError(
                detail.get("code") if isinstance(detail, dict) else "llm_policy_denied",
                detail.get("message") if isinstance(detail, dict) else "LLM request denied by policy",
                detail.get("details") if isinstance(detail, dict) else {},
            )

        if resp.status_code == 502:
            raise GatewayClientError(
                "llm_all_providers_failed",
                "All LLM providers failed",
            )

        resp.raise_for_status()

        try:
            data = resp.json()
        except Exception:
            raise GatewayClientError(
                "llm_gateway_parse_error",
                "Failed to parse gateway response",
            )

        return GatewayResponse(data)


_gateway_client: GatewayClient | None = None


def get_gateway_client() -> GatewayClient | None:
    global _gateway_client
    from src.core.config import settings

    url = settings.llm_gateway_url
    if not url:
        return None
    if _gateway_client is None:
        _gateway_client = GatewayClient(url)
    return _gateway_client
