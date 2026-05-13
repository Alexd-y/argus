"""Usage Ledger — DB-persistent + Prometheus metrics + in-memory cache per tenant/scan/provider."""

import logging
import uuid
from datetime import datetime, timezone
from typing import Any
import asyncio

logger = logging.getLogger(__name__)

_ledger: list[dict[str, Any]] = []


def record_usage(
    tenant_id: str = "",
    scan_id: str = "",
    phase: str = "",
    task: str = "",
    alias: str = "",
    provider: str = "",
    model: str = "",
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    estimated_cost: float = 0.0,
    *,
    status: str = "completed",
    error_code: str = "",
    latency_ms: int = 0,
    prompt_hash: str = "",
    response_hash: str = "",
) -> None:
    entry = {
        "tenant_id": tenant_id,
        "scan_id": scan_id,
        "phase": phase,
        "task": task,
        "alias": alias,
        "provider": provider,
        "model": model,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
        "estimated_cost_usd": round(estimated_cost, 6),
        "recorded_at": datetime.now(timezone.utc).isoformat(),
    }
    _ledger.append(entry)

    _record_prometheus(provider, model, prompt_tokens, completion_tokens)

    # Fire-and-forget DB persistence (non-blocking)
    asyncio.ensure_future(_persist_to_db(
        tenant_id=tenant_id, scan_id=scan_id, phase=phase, task=task,
        alias=alias, provider=provider, model=model,
        prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
        estimated_cost_usd=entry["estimated_cost_usd"],
        status=status, error_code=error_code, latency_ms=latency_ms,
        prompt_hash=prompt_hash, response_hash=response_hash,
    ))


def _record_prometheus(provider: str, model: str, prompt_tokens: int, completion_tokens: int) -> None:
    try:
        from src.core.observability import record_llm_tokens
        record_llm_tokens(provider, model, prompt_tokens, completion_tokens)
    except Exception:
        pass


async def _persist_to_db(
    tenant_id: str, scan_id: str, phase: str, task: str,
    alias: str, provider: str, model: str,
    prompt_tokens: int, completion_tokens: int,
    estimated_cost_usd: float, status: str, error_code: str,
    latency_ms: int, prompt_hash: str, response_hash: str,
) -> None:
    """Persist invocation record to gateway_invocations table (fire-and-forget)."""
    try:
        from src.db.session import async_session_factory
        from src.db.models import GatewayInvocation

        async with async_session_factory() as session:
            invocation = GatewayInvocation(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                scan_id=scan_id,
                phase=phase,
                task=task,
                alias=alias,
                provider=provider,
                model=model,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                estimated_cost_usd=estimated_cost_usd,
                latency_ms=latency_ms,
                status=status,
                error_code=error_code,
                prompt_hash=prompt_hash,
                response_hash=response_hash,
            )
            session.add(invocation)
            await session.commit()
    except Exception as exc:
        logger.debug("usage_ledger_db_persist_failed", extra={"error": str(exc)})


def get_usage_summary(
    tenant_id: str = "", scan_id: str = "",
) -> dict[str, Any]:
    filtered = [
        e for e in _ledger
        if (not tenant_id or e["tenant_id"] == tenant_id) and (not scan_id or e["scan_id"] == scan_id)
    ]
    total_tokens = sum(e["total_tokens"] for e in filtered)
    total_cost = sum(e["estimated_cost_usd"] for e in filtered)
    by_provider: dict[str, int] = {}
    by_model: dict[str, int] = {}
    for e in filtered:
        by_provider[e["provider"]] = by_provider.get(e["provider"], 0) + e["total_tokens"]
        by_model[e["model"]] = by_model.get(e["model"], 0) + e["total_tokens"]

    return {
        "total_calls": len(filtered),
        "total_tokens": total_tokens,
        "total_cost_usd": round(total_cost, 4),
        "by_provider": by_provider,
        "by_model": by_model,
    }
