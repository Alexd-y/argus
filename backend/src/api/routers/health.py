"""ARG-041 — Liveness + readiness endpoints.

* ``GET /health`` — liveness. Idempotent, no DB / Redis / network calls.
* ``GET /ready``  — readiness. DB ping + Redis ping + storage probe + LLM
  provider reachability summary. Returns HTTP 200 when ALL probes pass,
  503 otherwise. Each probe is wrapped in a 500 ms timeout — readiness
  must fit inside the orchestrator's 1 s probe budget.

The implementation deliberately keeps the probes *fast* and *additive*:
each one is independent and runs sequentially (a thread pool would
add overhead the probes don't need at this latency budget).
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Final

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from src.api.schemas import CheckDetail, HealthResponse, ReadinessResponse
from src.core.config import settings
from src.core.provider_health_registry import (
    KNOWN_PROVIDERS,
    get_provider_health_registry,
)
from src.core.redis_client import redis_ping
from src.db.session import engine
from src.storage.s3 import ensure_bucket

router = APIRouter(tags=["health"])

_logger = logging.getLogger(__name__)

#: Per-probe timeout. The /ready endpoint must fit inside the orchestrator's
#: probe budget (~1 s); 500 ms gives us enough room for ~3 sequential probes
#: and still respond inside the deadline.
_PROBE_TIMEOUT_SECONDS: Final[float] = 0.5


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Liveness — answers the question "is the process alive?".

    No DB / Redis / network. The contract is intentionally minimal so a
    container orchestrator can poll it dozens of times per second without
    putting load on shared infra.
    """
    return HealthResponse(status="ok", version=settings.version)


async def _timed_db_ping() -> CheckDetail:
    """``SELECT 1`` against the configured Postgres engine, 500 ms cap."""
    start = time.perf_counter()
    try:
        async with engine.connect() as conn:
            await asyncio.wait_for(
                conn.execute(text("SELECT 1")),
                timeout=_PROBE_TIMEOUT_SECONDS,
            )
        return CheckDetail(
            ok=True,
            latency_ms=round((time.perf_counter() - start) * 1000, 2),
        )
    except TimeoutError:
        return CheckDetail(ok=False, error="timeout")
    except Exception as exc:  # noqa: BLE001 — health probes catch broad exceptions
        return CheckDetail(ok=False, error=type(exc).__name__)


async def _timed_redis_ping() -> CheckDetail:
    """Synchronous Redis ping wrapped in :func:`asyncio.to_thread` (500 ms cap)."""
    start = time.perf_counter()
    try:
        ok = await asyncio.wait_for(
            asyncio.to_thread(redis_ping),
            timeout=_PROBE_TIMEOUT_SECONDS,
        )
        if not ok:
            return CheckDetail(ok=False, error="ping_failed")
        return CheckDetail(
            ok=True,
            latency_ms=round((time.perf_counter() - start) * 1000, 2),
        )
    except TimeoutError:
        return CheckDetail(ok=False, error="timeout")
    except Exception as exc:  # noqa: BLE001
        return CheckDetail(ok=False, error=type(exc).__name__)


async def _timed_storage_check() -> CheckDetail:
    """MinIO bucket existence check (already short-circuits via boto3 retries)."""
    start = time.perf_counter()
    try:
        ok = await asyncio.wait_for(
            asyncio.to_thread(
                lambda: bool(ensure_bucket() and ensure_bucket(settings.minio_reports_bucket)),
            ),
            timeout=_PROBE_TIMEOUT_SECONDS,
        )
        if not ok:
            return CheckDetail(ok=False, error="ensure_bucket_failed")
        return CheckDetail(
            ok=True,
            latency_ms=round((time.perf_counter() - start) * 1000, 2),
        )
    except TimeoutError:
        return CheckDetail(ok=False, error="timeout")
    except Exception as exc:  # noqa: BLE001
        return CheckDetail(ok=False, error=type(exc).__name__)


def _llm_providers_summary() -> CheckDetail:
    """Aggregate the in-process provider registry into a single CheckDetail.

    A provider is considered DOWN when its 60s 5xx error rate exceeds 50 %
    *and* it has handled at least one request in the window. Providers with
    zero traffic are not penalised — they may simply not have been used yet.
    """
    registry = get_provider_health_registry()
    snapshots = registry.snapshot()
    degraded: list[str] = []
    for snap in snapshots:
        if snap.provider not in KNOWN_PROVIDERS:
            continue
        if snap.request_count_60s > 0 and snap.error_rate_5xx > 0.5:
            degraded.append(snap.provider)
        if snap.state == "open":
            degraded.append(snap.provider)
    if degraded:
        return CheckDetail(ok=False, error=f"degraded:{','.join(sorted(set(degraded)))}")
    return CheckDetail(ok=True)


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    responses={503: {"model": ReadinessResponse}},
)
async def ready(response: Response) -> ReadinessResponse:
    """Readiness — DB, Redis, storage, LLM providers.

    Returns HTTP 503 when any probe fails (the response body still carries
    the structured per-probe detail so the orchestrator can surface a
    helpful banner without a second roundtrip).
    """
    db = await _timed_db_ping()
    redis = await _timed_redis_ping()
    storage = await _timed_storage_check()
    llm = _llm_providers_summary()

    all_ok = db.ok and redis.ok and storage.ok and llm.ok
    payload = ReadinessResponse(
        status="ok" if all_ok else "degraded",
        database=db.ok,
        redis=redis.ok,
        storage=storage.ok,
        llm_providers=llm.ok,
        checks={
            "database": db,
            "redis": redis,
            "storage": storage,
            "llm_providers": llm,
        },
    )
    if not all_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return payload
