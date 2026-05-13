"""Cloud Supplement Client — report-only cloud LLM fallback.

Used ONLY when WhiteRabbitNeo is unavailable AND the task permits cloud fallback
(REPORT_SECTION, EXECUTIVE_SUMMARY, COST_SUMMARY).
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

CLOUD_SUPPLEMENT_TASKS = {"REPORT_SECTION", "EXECUTIVE_SUMMARY", "COST_SUMMARY"}


async def call_cloud_supplement(
    messages: list[dict[str, str]],
    *,
    model: str = "deepseek-chat",
    temperature: float = 0.2,
    max_tokens: int = 2000,
) -> dict[str, Any]:
    import os
    key = (os.environ.get("DEEPSEEK_API_KEY") or "").strip()
    if not key:
        return {"content": "", "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}

    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                "https://api.deepseek.com/v1/chat/completions",
                json=payload, headers=headers,
            )
            resp.raise_for_status()
            data = resp.json()
        choices = data.get("choices", [])
        usage = data.get("usage", {})
        return {
            "content": choices[0].get("message", {}).get("content", "") if choices else "",
            "usage": {
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            },
            "model": model,
            "provider": "deepseek",
        }
    except Exception as exc:
        logger.warning("cloud_supplement_failed", extra={"error": str(exc)})
        return {"content": "", "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}
