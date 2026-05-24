"""Scan queue processor — pick queued scans when slots are available.

When a scan is created it lands in the DB with ``status="queued"``. This
module provides :func:`try_pick_queued_scan` which checks whether the
tenant has a free slot (fewer than ``SCAN_MAX_CONCURRENT`` scans in
``running`` or ``awaiting_approval``) and, if so, transitions the oldest
queued scan to ``running`` and dispatches the Celery ``argus.scan_phase``
task.

Call sites:

* Scan creation endpoints (REST / MCP) — try an immediate start after
  persisting the row.
* Scan state machine — on terminal transition (completed / failed /
  cancelled) call :func:`notify_scan_finished` so the next queued scan
  can be picked up.
* A periodic Celery beat task (:func:`poll_queued_scans`) runs as a
  safety-net to recover from lost notifications.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from sqlalchemy import String, cast, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.db.models import Scan
from src.db.session import (
    create_task_engine_and_session,
    set_session_tenant,
)

logger = logging.getLogger(__name__)

_RUNNING_STATUSES: frozenset[str] = frozenset({"running", "awaiting_approval"})
_QUEUED_STATUS: str = "queued"
_TERMINAL_STATUSES: frozenset[str] = frozenset({"completed", "failed", "cancelled"})
_DEFAULT_MAX_CONCURRENT: int = 3


def _max_concurrent() -> int:
    return settings.scan_max_concurrent or _DEFAULT_MAX_CONCURRENT


async def try_pick_queued_scan(
    tenant_id: str,
    *,
    max_concurrent: int | None = None,
) -> str | None:
    """Pick the oldest queued scan for *tenant_id* if a slot is free.

    Returns the ``scan_id`` of the scan that was dispatched, or ``None``
    if no queued scan was eligible or no slot was available.

    The function is idempotent: concurrent calls are safe because the
    ``UPDATE … SET status='running'`` uses a WHERE clause on
    ``status='queued'`` — only one caller wins the race.
    """
    limit = max_concurrent or _max_concurrent()

    engine, session_factory = create_task_engine_and_session()
    try:
        async with session_factory() as session:
            await set_session_tenant(session, tenant_id)

            running_count = await _count_running(session, tenant_id)
            if running_count >= limit:
                logger.debug(
                    "scan_queue.slot_full",
                    extra={
                        "event": "argus.scan_queue.slot_full",
                        "tenant_id_hash": _safe_hash(tenant_id),
                        "running_count": running_count,
                        "max_concurrent": limit,
                    },
                )
                return None

            candidate = await _oldest_queued(session, tenant_id)
            if candidate is None:
                return None

            scan_id: str = str(candidate[0])
            target_url: str = str(candidate[1])
            options: Any = candidate[2]

            won = await _claim_queued(session, scan_id, tenant_id)
            if not won:
                logger.debug(
                    "scan_queue.claim_lost",
                    extra={
                        "event": "argus.scan_queue.claim_lost",
                        "scan_id": scan_id,
                        "tenant_id_hash": _safe_hash(tenant_id),
                    },
                )
                return None

            logger.info(
                "scan_queue.picked",
                extra={
                    "event": "argus.scan_queue.picked",
                    "scan_id": scan_id,
                    "tenant_id_hash": _safe_hash(tenant_id),
                    "running_count": running_count,
                    "max_concurrent": limit,
                },
            )

            _dispatch_scan_phase(
                scan_id=scan_id,
                tenant_id=tenant_id,
                target_url=target_url,
                options=options or {},
            )
            return scan_id
    finally:
        await engine.dispose()


async def notify_scan_finished(tenant_id: str) -> str | None:
    """Call after a scan reaches a terminal status.

    Delegates to :func:`try_pick_queued_scan` so the next queued scan
    for the same tenant can be started immediately.
    """
    return await try_pick_queued_scan(tenant_id)


async def poll_queued_scans() -> list[str]:
    """Beat task: scan every tenant with queued scans and pick where possible.

    This is a safety-net for lost notifications. Returns the list of
    scan IDs that were dispatched.
    """
    dispatched: list[str] = []

    engine, session_factory = create_task_engine_and_session()
    try:
        async with session_factory() as session:
            stmt = (
                select(Scan.tenant_id)
                .where(Scan.status == _QUEUED_STATUS)
                .distinct()
            )
            result = await session.execute(stmt)
            tenant_ids = [str(row[0]) for row in result.all()]
    finally:
        await engine.dispose()

    for tid in tenant_ids:
        try:
            picked = await try_pick_queued_scan(tid)
            if picked:
                dispatched.append(picked)
        except Exception:
            logger.warning(
                "scan_queue.poll_tenant_failed",
                extra={
                    "event": "argus.scan_queue.poll_tenant_failed",
                    "tenant_id_hash": _safe_hash(tid),
                },
                exc_info=True,
            )

    return dispatched


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _count_running(session: AsyncSession, tenant_id: str) -> int:
    stmt = (
        select(func.count())
        .select_from(Scan)
        .where(
            cast(Scan.tenant_id, String) == tenant_id,
            Scan.status.in_(_RUNNING_STATUSES),
        )
    )
    result = await session.execute(stmt)
    return result.scalar_one()


async def _oldest_queued(
    session: AsyncSession, tenant_id: str
) -> tuple[Any, ...] | None:
    stmt = (
        select(Scan.id, Scan.target_url, Scan.options)
        .where(
            cast(Scan.tenant_id, String) == tenant_id,
            Scan.status == _QUEUED_STATUS,
        )
        .order_by(Scan.created_at.asc())
        .limit(1)
    )
    result = await session.execute(stmt)
    return result.one_or_none()


async def _claim_queued(
    session: AsyncSession, scan_id: str, tenant_id: str
) -> bool:
    """Atomically claim a queued scan by setting status to ``running``.

    Returns ``True`` iff the row was actually updated (i.e. we won the
    race against a concurrent picker).
    """
    stmt = (
        update(Scan)
        .where(
            cast(Scan.id, String) == scan_id,
            cast(Scan.tenant_id, String) == tenant_id,
            Scan.status == _QUEUED_STATUS,
        )
        .values(status="running")
    )
    result = await session.execute(stmt)
    await session.commit()
    return result.rowcount > 0


def _dispatch_scan_phase(
    *,
    scan_id: str,
    tenant_id: str,
    target_url: str,
    options: dict[str, Any],
) -> None:
    from src.tasks import scan_phase_task

    scan_phase_task.delay(scan_id, tenant_id, target_url, options)


def _safe_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]