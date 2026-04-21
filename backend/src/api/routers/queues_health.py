"""ARG-041 — GET /queues/health (Celery queue depths + worker count).

Reports per-queue length (via ``redis.llen``) and active worker count
(via ``celery_app.control.inspect().active()``). The endpoint is
unauthenticated by design — same reasoning as ``/providers/health``.

Failure semantics:

* Redis unreachable → HTTP 503 + ``redis_reachable=false``. We cannot
  serve queue depths without Redis, so degraded health is the only honest
  answer.
* Redis reachable, worker introspection failed → HTTP 200 + ``worker_count=0``.
  The worker introspection RPC has its own timeout and may fail in
  partially-degraded clusters; we return what we know rather than 503.

Performance: ``redis.llen`` is O(1); inspecting active workers is a
broadcast RPC and can take up to ~1 s. We bound it via a 1 s deadline.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Final, Literal

from fastapi import APIRouter, Response, status

from src.api.schemas import QueueDepth, QueuesHealthResponse
from src.core.redis_client import get_redis

router = APIRouter(tags=["health"])
_logger = logging.getLogger(__name__)

#: Queues we report. Mirrors the ``task_routes`` declaration in
#: ``src.celery_app`` plus the implicit default broker queue (``celery``).
WATCHED_QUEUES: Final[tuple[str, ...]] = (
    "celery",
    "argus.default",
    "argus.scans",
    "argus.tools",
    "argus.recon",
    "argus.reports",
    "argus.exploitation",
)

_WORKER_INSPECT_TIMEOUT_SECONDS: Final[float] = 1.0


def _safe_llen(client: object, queue: str) -> int:
    """Return ``redis.llen(queue)`` or 0 on failure (errors are logged)."""
    try:
        result = client.llen(queue)  # type: ignore[attr-defined]
    except Exception as exc:  # noqa: BLE001
        _logger.debug(
            "queues_health.llen_failed",
            extra={"queue": queue, "error_class": type(exc).__name__},
        )
        return 0
    try:
        return max(0, int(result))
    except (TypeError, ValueError):
        return 0


def _inspect_worker_count() -> int:
    """Return the active worker count, 0 if introspection fails / no workers.

    Uses the lazy-import pattern to keep the module loadable when Celery is
    intentionally absent in some deploy targets (sandbox-only builds).
    """
    try:
        from src.celery_app import app as celery_app

        inspector = celery_app.control.inspect(timeout=_WORKER_INSPECT_TIMEOUT_SECONDS)
        active = inspector.active() or {}
        return len(active)
    except Exception as exc:  # noqa: BLE001
        _logger.debug(
            "queues_health.worker_inspect_failed",
            extra={"error_class": type(exc).__name__},
        )
        return 0


@router.get(
    "/queues/health",
    response_model=QueuesHealthResponse,
    responses={503: {"model": QueuesHealthResponse}},
)
async def queues_health(response: Response) -> QueuesHealthResponse:
    """Return queue depths and active-worker counts.

    Returns HTTP 503 with ``redis_reachable=false`` when Redis is down.
    Otherwise always 200, even when worker inspection fails.
    """
    client = get_redis()
    if client is None:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return QueuesHealthResponse(
            status="degraded",
            queues=[QueueDepth(queue=q, depth=0) for q in WATCHED_QUEUES],
            worker_count=0,
            redis_reachable=False,
        )
    try:
        # ``ping`` here is a 50 µs sanity check; without it a half-broken
        # Redis client (auth failure mid-session) would still return 200.
        await asyncio.wait_for(asyncio.to_thread(client.ping), timeout=1.0)
        redis_reachable = True
    except Exception as exc:  # noqa: BLE001
        _logger.warning(
            "queues_health.redis_ping_failed",
            extra={"error_class": type(exc).__name__},
        )
        redis_reachable = False

    if not redis_reachable:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return QueuesHealthResponse(
            status="degraded",
            queues=[QueueDepth(queue=q, depth=0) for q in WATCHED_QUEUES],
            worker_count=0,
            redis_reachable=False,
        )

    queues = [QueueDepth(queue=q, depth=_safe_llen(client, q)) for q in WATCHED_QUEUES]
    worker_count = await asyncio.to_thread(_inspect_worker_count)

    overall: Literal["ok", "degraded"] = "ok" if worker_count > 0 else "degraded"
    return QueuesHealthResponse(
        status=overall,
        queues=queues,
        worker_count=worker_count,
        redis_reachable=True,
    )
