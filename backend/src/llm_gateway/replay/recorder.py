"""Replay — deterministic recording and replay of LLM calls for audit/debug."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ReplayRecord:
    id: str = ""
    timestamp: str = ""
    model: str = ""
    provider: str = ""
    messages: list[dict[str, str]] = field(default_factory=list)
    response: str = ""
    usage: dict[str, int] = field(default_factory=dict)
    duration_ms: int = 0
    policy_decision: dict[str, Any] = field(default_factory=dict)


_recorder_store: list[ReplayRecord] = []


def record_call(record: ReplayRecord) -> None:
    _recorder_store.append(record)


def get_records(
    model: str = "", provider: str = "", limit: int = 100,
) -> list[ReplayRecord]:
    filtered = _recorder_store
    if model:
        filtered = [r for r in filtered if r.model == model]
    if provider:
        filtered = [r for r in filtered if r.provider == provider]
    return filtered[-limit:]


async def replay_call(
    record: ReplayRecord, target_url: str,
) -> dict[str, Any]:
    import httpx

    payload = {
        "model": record.model,
        "messages": record.messages,
        "temperature": 0.0,  # deterministic
        "max_tokens": 2000,
    }

    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=300.0) as client:
            resp = await client.post(
                f"{target_url}/v1/chat/completions",
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
        elapsed = int((time.monotonic() - start) * 1000)
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        return {
            "replayed": True,
            "original": record.response[:200],
            "replay": content[:200],
            "match": content.strip() == record.response.strip(),
            "duration_ms": elapsed,
            "original_duration_ms": record.duration_ms,
        }
    except Exception as exc:
        return {"replayed": False, "error": str(exc)}
