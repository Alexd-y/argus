"""ARG-044 — daily refresh of EPSS scores + KEV catalog.

Two Celery beat tasks live in this module:

* :func:`epss_batch_refresh_task` (``argus.intel.epss_refresh``) — runs
  daily at 04:00 UTC. Fetches the set of CVE IDs referenced by *open*
  findings (``status NOT IN (resolved, false_positive)``), batches them
  through :meth:`EpssClient.fetch_epss_batch` (60 rpm honoured by the
  client's internal semaphore), and upserts the result into the
  ``epss_scores`` Postgres table via :class:`EpssScoreRepository`.
* :func:`kev_catalog_refresh_task` (``argus.intel.kev_refresh``) — runs
  daily at 05:00 UTC. Pulls the full CISA KEV catalog (with ETag /
  ``If-None-Match`` so steady-state polls cost a 304), upserts into
  ``kev_catalog`` via :class:`KevCatalogRepository`, and refreshes the
  Redis-cached lookup set used by the inline enrichment path.

Both tasks are guarded by Redis distributed locks (``argus:lock:intel:*``)
so simultaneous beats from competing pods cannot duplicate work; the
loser of the lock acquisition exits cleanly with status
``{"status": "skipped", "reason": "lock_held"}``.

Air-gap mode: the tasks honour ``settings.intel_airgap_mode`` (boolean).
When True they exit with ``{"status": "airgap"}`` immediately — operators
are expected to seed the ``epss_scores`` / ``kev_catalog`` tables out of
band (e.g. via a periodic mirror import).
"""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import date, timedelta
from typing import Any, Final
from uuid import uuid4

from sqlalchemy import select

from src.celery_app import app
from src.core.config import settings
from src.core.redis_client import get_redis
from src.db.session import create_task_engine_and_session

_logger = logging.getLogger(__name__)


_EPSS_LOCK_KEY: Final[str] = "argus:lock:intel:epss_refresh"
_KEV_LOCK_KEY: Final[str] = "argus:lock:intel:kev_refresh"
_LOCK_TTL_SECONDS: Final[int] = 30 * 60  # 30 min — generous for ~10k CVEs.
_DEFAULT_EPSS_CHUNK: Final[int] = 100
_DEFAULT_KEV_CHUNK: Final[int] = 500


# ---------------------------------------------------------------------------
# Public Celery tasks
# ---------------------------------------------------------------------------


@app.task(bind=True, name="argus.intel.epss_refresh", max_retries=0)
def epss_batch_refresh_task(self) -> dict[str, Any]:  # noqa: ARG001
    """Refresh EPSS scores for CVEs referenced by open findings.

    Returns a structured dict suitable for downstream observability /
    Celery result inspection. Never raises — failures are returned as
    ``status="error"`` with a stable ``reason`` code.
    """
    return _run_with_lock(
        lock_key=_EPSS_LOCK_KEY,
        runner=_run_epss_refresh,
        task_name="epss_refresh",
    )


@app.task(bind=True, name="argus.intel.kev_refresh", max_retries=0)
def kev_catalog_refresh_task(self) -> dict[str, Any]:  # noqa: ARG001
    """Refresh the full CISA KEV catalog (Postgres + Redis cache)."""
    return _run_with_lock(
        lock_key=_KEV_LOCK_KEY,
        runner=_run_kev_refresh,
        task_name="kev_refresh",
    )


# ---------------------------------------------------------------------------
# Lock + airgap helpers
# ---------------------------------------------------------------------------


def _run_with_lock(
    *,
    lock_key: str,
    runner: Any,
    task_name: str,
) -> dict[str, Any]:
    """Acquire ``lock_key`` (best-effort), run ``runner``, release on exit.

    Lock semantics:
    * ``SET ... NX EX <ttl>`` provides single-writer guarantee across pods.
    * If Redis is unreachable, we proceed *without* the lock (logged as a
      warning) — degraded but not blocked. The duplicate-write window is
      bounded by the daily cadence and the upsert idempotency.
    """
    if getattr(settings, "intel_airgap_mode", False):
        _logger.info(
            "intel_refresh.airgap_skip",
            extra={"event": "intel_refresh_airgap_skip", "task": task_name},
        )
        return {"status": "airgap", "task": task_name}

    redis = _safe_get_redis()
    lock_token = f"{int(time.time() * 1000)}:{uuid4().hex}"
    acquired = _try_acquire_lock(redis, lock_key, lock_token)
    if redis is not None and not acquired:
        _logger.info(
            "intel_refresh.lock_held",
            extra={"event": "intel_refresh_lock_held", "task": task_name},
        )
        return {"status": "skipped", "reason": "lock_held", "task": task_name}

    started = time.perf_counter()
    try:
        result = asyncio.run(runner())
    except Exception:  # pragma: no cover — defensive blanket
        _logger.exception(
            "intel_refresh.failed",
            extra={"event": "intel_refresh_failed", "task": task_name},
        )
        result = {"status": "error", "reason": "task_error", "task": task_name}
    finally:
        if acquired and redis is not None:
            _safe_release_lock(redis, lock_key, lock_token)

    duration_ms = int((time.perf_counter() - started) * 1000)
    result.setdefault("duration_ms", duration_ms)
    result.setdefault("task", task_name)
    _logger.info(
        "intel_refresh.completed",
        extra={
            "event": "intel_refresh_completed",
            "task": task_name,
            "status": result.get("status"),
            "rows_written": result.get("rows_written"),
            "duration_ms": duration_ms,
        },
    )
    return result


def _safe_get_redis() -> Any | None:
    try:
        return get_redis()
    except Exception:
        _logger.warning(
            "intel_refresh.redis_unavailable",
            extra={"event": "intel_refresh_redis_unavailable"},
        )
        return None


def _try_acquire_lock(redis: Any | None, key: str, token: str) -> bool:
    if redis is None:
        return False
    try:
        # SET NX EX is the standard distributed-lock idiom in Redis.
        # ``set(..., nx=True, ex=...)`` returns True on acquire, None / False
        # otherwise depending on the client version.
        result = redis.set(key, token, nx=True, ex=_LOCK_TTL_SECONDS)
        return bool(result)
    except Exception:
        _logger.warning(
            "intel_refresh.lock_acquire_failed",
            extra={"event": "intel_refresh_lock_acquire_failed"},
        )
        return False


def _safe_release_lock(redis: Any, key: str, token: str) -> None:
    """Release lock only if we still own it (token comparison)."""
    try:
        # Lua script for safe release (CAS-style): only DEL if the stored
        # value matches our token. This avoids the classic "lock expired
        # mid-task and we delete the next holder's lock" race.
        script = (
            "if redis.call('get', KEYS[1]) == ARGV[1] then "
            "return redis.call('del', KEYS[1]) else return 0 end"
        )
        redis.eval(script, 1, key, token)
    except Exception:
        _logger.warning(
            "intel_refresh.lock_release_failed",
            extra={"event": "intel_refresh_lock_release_failed"},
        )


# ---------------------------------------------------------------------------
# EPSS refresh
# ---------------------------------------------------------------------------


async def _run_epss_refresh() -> dict[str, Any]:
    """Async core of :func:`epss_batch_refresh_task`."""
    from src.findings.epss_persistence import EpssScoreRecord, EpssScoreRepository

    cve_ids = await _collect_open_finding_cves()
    if not cve_ids:
        return {"status": "ok", "cves_requested": 0, "rows_written": 0}

    epss_client = _build_epss_client()
    if epss_client is None:
        return {"status": "error", "reason": "client_unavailable"}

    rows = await epss_client.fetch_epss_batch(
        cve_ids, chunk_size=_DEFAULT_EPSS_CHUNK
    )
    if not rows:
        return {
            "status": "ok",
            "cves_requested": len(cve_ids),
            "rows_written": 0,
        }

    records = [
        EpssScoreRecord(
            cve_id=entry.cve_id,
            epss_score=entry.epss_score,
            epss_percentile=entry.epss_percentile,
            model_date=entry.model_date,
            updated_at=_utcnow(),
        )
        for entry in rows.values()
    ]

    written = 0
    engine, session_factory = create_task_engine_and_session()
    try:
        async with session_factory() as session:
            repo = EpssScoreRepository(session)
            written = await repo.upsert_batch(records, chunk_size=_DEFAULT_EPSS_CHUNK)
            await session.commit()
    finally:
        await engine.dispose()

    return {
        "status": "ok",
        "cves_requested": len(cve_ids),
        "cves_returned": len(rows),
        "rows_written": written,
    }


async def _collect_open_finding_cves() -> list[str]:
    """Distinct CVE IDs referenced by findings still under triage.

    Uses a raw column projection (``cve_id``) rather than loading full
    ``Finding`` rows — the table can run into the high tens of thousands
    and we only need the strings here.
    """
    try:
        from src.db.models import Finding
    except ImportError:
        _logger.warning(
            "intel_refresh.finding_model_missing",
            extra={"event": "intel_refresh_finding_model_missing"},
        )
        return []

    cve_column = getattr(Finding, "cve_id", None)
    if cve_column is None:
        return []

    status_column = getattr(Finding, "status", None)
    excluded_statuses = {"resolved", "false_positive", "fixed"}

    engine, session_factory = create_task_engine_and_session()
    try:
        async with session_factory() as session:
            stmt = select(cve_column).distinct().where(cve_column.is_not(None))
            if status_column is not None:
                stmt = stmt.where(status_column.notin_(excluded_statuses))
            result = await session.execute(stmt)
            raw = [row for (row,) in result.all() if row]
    finally:
        await engine.dispose()

    out: list[str] = []
    seen: set[str] = set()
    for value in raw:
        if isinstance(value, str):
            up = value.strip().upper()
            if up and up not in seen:
                out.append(up)
                seen.add(up)
    return out


def _build_epss_client() -> Any | None:
    try:
        import httpx

        from src.findings.epss_client import EpssClient
    except ImportError:
        return None
    redis = _safe_get_redis()
    airgap = bool(getattr(settings, "intel_airgap_mode", False))
    http = httpx.AsyncClient()
    return EpssClient(http_client=http, redis_client=redis, airgap=airgap)


# ---------------------------------------------------------------------------
# KEV refresh
# ---------------------------------------------------------------------------


async def _run_kev_refresh() -> dict[str, Any]:
    """Async core of :func:`kev_catalog_refresh_task`."""
    from src.findings.kev_persistence import KevCatalogRepository

    kev_client = _build_kev_client()
    if kev_client is None:
        return {"status": "error", "reason": "client_unavailable"}

    records = await kev_client.fetch_kev_catalog()
    if records is None:
        return {"status": "ok", "rows_written": 0, "reason": "not_modified_or_failed"}
    if not records:
        return {"status": "ok", "rows_written": 0}

    written = 0
    engine, session_factory = create_task_engine_and_session()
    try:
        async with session_factory() as session:
            repo = KevCatalogRepository(session)
            written = await repo.upsert_batch(records, chunk_size=_DEFAULT_KEV_CHUNK)
            await session.commit()
    finally:
        await engine.dispose()

    # Update the Redis lookup set so the inline ``KevClient.is_listed``
    # path sees the freshest catalogue without waiting for its own TTL.
    try:
        await kev_client.refresh()
    except Exception:
        _logger.warning(
            "intel_refresh.kev_redis_warmup_failed",
            extra={"event": "intel_refresh_kev_redis_warmup_failed"},
        )

    return {
        "status": "ok",
        "rows_written": written,
        "catalog_size": len(records),
    }


def _build_kev_client() -> Any | None:
    try:
        import httpx

        from src.findings.kev_client import KevClient
    except ImportError:
        return None
    redis = _safe_get_redis()
    airgap = bool(getattr(settings, "intel_airgap_mode", False))
    http = httpx.AsyncClient()
    return KevClient(http_client=http, redis_client=redis, airgap=airgap)


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------


def _utcnow() -> "datetime":  # noqa: F821 — forward reference for runtime
    from datetime import datetime, timezone

    return datetime.now(tz=timezone.utc)


def _today_minus(days: int) -> date:
    return date.today() - timedelta(days=days)


__all__ = [
    "epss_batch_refresh_task",
    "kev_catalog_refresh_task",
]
