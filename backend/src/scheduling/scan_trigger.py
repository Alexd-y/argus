"""T33 / ARG-056 — Celery task fired by RedBeat for each ``scan_schedules`` row.

The task name is ``argus.scheduling.run_scheduled_scan``. RedBeat invokes
it with ``schedule_id`` + ``tenant_id`` keyword arguments (set by
:mod:`src.scheduling.redbeat_loader`). The body performs three pre-flight
checks before delegating to the existing scan-launch pipeline:

1. **Schedule still exists and is enabled.** A row may have been deleted
   or disabled between the beat tick and task pickup; we treat both as
   silent skips with a structured log so operators can audit drops.
2. **Kill switch.** :class:`src.policy.kill_switch.KillSwitchService.is_blocked`
   is consulted against the schedule's tenant. A blocked tenant gets a
   ``skipped_kill_switch`` log entry and the trigger returns without
   enqueueing anything.
3. **Maintenance window.** When the schedule has a non-empty
   ``maintenance_window_cron`` and the current time falls inside it
   (per :func:`src.scheduling.cron_parser.is_in_maintenance_window`), the
   trigger logs ``skipped_maintenance_window`` and returns. The "run
   now" admin override bypasses this check separately (it does not call
   this task — it dispatches ``argus.scan_phase`` directly).

After the gates pass, the task:

* Inserts a ``Target`` and ``Scan`` row using the same shape as
  :func:`src.api.routers.scans._persist_scan_start` (we duplicate the
  small helper here to avoid pulling the FastAPI router module into
  the Celery worker import graph).
* Dispatches ``argus.scan_phase`` (the existing scan executor).
* Updates ``last_run_at`` (always) and ``next_run_at`` (best-effort,
  via :func:`next_fire_time`). Failures to recompute ``next_run_at`` log
  a warning and leave the field unchanged so RedBeat's own bookkeeping
  remains the source of truth for the next fire instant.

The task is intentionally idempotent at the *schedule level* but not at
the *fire level*: if RedBeat double-fires (network blip during ack), two
``Scan`` rows will be created. RedBeat's lock_timeout makes this rare,
and downstream dedup is out of scope for T33.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import String, cast, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.celery_app import app
from src.core.observability import tenant_hash
from src.db.models import ScanSchedule, Target, Tenant
from src.db.session import create_task_engine_and_session, set_session_tenant
from src.policy.kill_switch import KillSwitchService, KillSwitchUnavailableError
from src.scheduling.cron_parser import (
    CronValidationError,
    is_in_maintenance_window,
    next_fire_time,
)

logger = logging.getLogger(__name__)

#: Default duration assumed for a maintenance window when the schedule
#: stores only the *opening* cron. Matches the
#: :func:`is_in_maintenance_window` default. Operators can later make
#: this configurable per schedule (T35 / future), but YAGNI for now.
DEFAULT_MAINTENANCE_WINDOW_DURATION_MINUTES: int = 60


# ---------------------------------------------------------------------------
# Pure decision helpers (kept module-level for unit-testability)
# ---------------------------------------------------------------------------


def _should_skip_for_maintenance_window(
    *,
    window_cron: str | None,
    at: datetime,
) -> bool:
    """True when ``window_cron`` is set and ``at`` falls inside the window.

    A ``None`` / empty ``window_cron`` always returns False (no window).
    Cron parsing errors are treated as "not in window" — failing closed
    here would suppress every fire forever, which is the wrong default
    for a defensive guard. The error is logged so an operator can fix
    the bad cron via the CRUD endpoint.
    """
    if not window_cron:
        return False
    try:
        return is_in_maintenance_window(
            window_cron,
            at=at,
            window_duration_minutes=DEFAULT_MAINTENANCE_WINDOW_DURATION_MINUTES,
        )
    except CronValidationError:
        logger.warning(
            "scan_trigger.maintenance_window_invalid",
            extra={"event": "scan_trigger.maintenance_window_invalid"},
        )
        return False


def _compute_next_run_at(cron_expression: str, *, after: datetime) -> datetime | None:
    """Compute next fire time; return ``None`` if the cron is malformed.

    Defensive logging only — the API layer already validates ``cron_expression``
    before persisting, so reaching the ``except`` branch here means a
    schema migration or direct DB write bypassed validation.
    """
    try:
        return next_fire_time(cron_expression, after=after)
    except CronValidationError:
        logger.warning(
            "scan_trigger.next_run_compute_failed",
            extra={"event": "scan_trigger.next_run_compute_failed"},
        )
        return None


# ---------------------------------------------------------------------------
# DB helpers (async — callable from the asyncio.run() body inside the task)
# ---------------------------------------------------------------------------


async def _load_schedule(
    session: AsyncSession, schedule_id: str
) -> ScanSchedule | None:
    """Fetch the schedule row by id; ``None`` when missing."""
    result = await session.execute(
        select(ScanSchedule).where(cast(ScanSchedule.id, String) == schedule_id)
    )
    return result.scalar_one_or_none()


async def _ensure_tenant(session: AsyncSession, tenant_id: str) -> None:
    """Idempotently materialise a default tenant row if missing.

    Mirrors the same fallback used in
    :func:`src.api.routers.scans._persist_scan_start` so scheduled scans
    behave identically to ad-hoc scans on a fresh tenant.
    """
    result = await session.execute(
        select(Tenant).where(cast(Tenant.id, String) == tenant_id)
    )
    if result.scalar_one_or_none() is None:
        session.add(Tenant(id=tenant_id, name="default"))
        await session.flush()


async def _persist_scheduled_scan(
    session: AsyncSession,
    *,
    tenant_id: str,
    target_url: str,
    scan_mode: str,
    schedule_id: str,
) -> str:
    """Insert ``Target`` + ``Scan`` rows; return new scan_id.

    The ``options`` payload tags the scan with ``triggered_by="schedule"``
    and the originating ``schedule_id`` so downstream observability can
    distinguish operator-triggered runs from scheduled ones without
    joining ``scan_schedules`` on every dashboard query.
    """
    from src.db.models import Scan

    scan_id = str(uuid.uuid4())
    target_row = Target(id=str(uuid.uuid4()), tenant_id=tenant_id, url=target_url)
    session.add(target_row)
    await session.flush()

    scan = Scan(
        id=scan_id,
        tenant_id=tenant_id,
        target_id=target_row.id,
        target_url=target_url,
        status="queued",
        progress=0,
        phase="init",
        options={"triggered_by": "schedule", "schedule_id": schedule_id},
        scan_mode=scan_mode,
    )
    session.add(scan)
    await session.flush()
    return scan_id


async def _update_run_timestamps(
    session: AsyncSession,
    *,
    schedule_id: str,
    fired_at: datetime,
    next_run_at: datetime | None,
) -> None:
    """Bump ``last_run_at`` (and ``next_run_at`` when computable)."""
    values: dict[str, Any] = {"last_run_at": fired_at}
    if next_run_at is not None:
        values["next_run_at"] = next_run_at
    await session.execute(
        update(ScanSchedule)
        .where(cast(ScanSchedule.id, String) == schedule_id)
        .values(**values)
    )


# ---------------------------------------------------------------------------
# KillSwitch dependency (lazy redis client)
# ---------------------------------------------------------------------------


def _build_kill_switch() -> KillSwitchService:
    """Build a :class:`KillSwitchService` against the configured Redis.

    On import / connection error we return a service with ``redis_client=None``;
    the service then raises :class:`KillSwitchUnavailableError` from
    :meth:`is_blocked`, which we catch and treat as fail-closed (skip the
    fire). Failing closed when the kill switch backend is down is the
    safer choice — better to drop a scan than to fire one we cannot
    emergency-stop.
    """
    try:
        from src.core.redis_client import get_redis

        return KillSwitchService(get_redis())
    except Exception:
        logger.warning(
            "scan_trigger.kill_switch_redis_unavailable",
            extra={"event": "scan_trigger.kill_switch_redis_unavailable"},
            exc_info=True,
        )
        return KillSwitchService(redis_client=None)


# ---------------------------------------------------------------------------
# Async task body
# ---------------------------------------------------------------------------


async def _run_scheduled_scan_async(
    *,
    schedule_id: str,
    tenant_id: str,
    fired_at: datetime,
) -> dict[str, Any]:
    """Async core for the Celery task — separated for testability.

    Returns a small status dict that the Celery wrapper re-raises as the
    task result; serialisable as JSON for the task backend.
    """
    kill_switch = _build_kill_switch()
    try:
        verdict = kill_switch.is_blocked(tenant_id)
        if verdict.blocked:
            logger.info(
                "scan_trigger.skipped_kill_switch",
                extra={
                    "event": "scan_trigger.skipped_kill_switch",
                    "schedule_id": schedule_id,
                    "tenant_hash": tenant_hash(tenant_id),
                    "scope": verdict.scope.value if verdict.scope else None,
                },
            )
            return {"status": "skipped_kill_switch", "schedule_id": schedule_id}
    except KillSwitchUnavailableError:
        logger.warning(
            "scan_trigger.kill_switch_unavailable_fail_closed",
            extra={
                "event": "scan_trigger.kill_switch_unavailable_fail_closed",
                "schedule_id": schedule_id,
                "tenant_hash": tenant_hash(tenant_id),
            },
        )
        return {"status": "skipped_kill_switch_unavailable", "schedule_id": schedule_id}

    engine, session_factory = create_task_engine_and_session()
    try:
        async with session_factory() as session:
            await set_session_tenant(session, tenant_id)
            schedule = await _load_schedule(session, schedule_id)
            if schedule is None:
                logger.info(
                    "scan_trigger.skipped_missing",
                    extra={
                        "event": "scan_trigger.skipped_missing",
                        "schedule_id": schedule_id,
                    },
                )
                return {"status": "skipped_missing", "schedule_id": schedule_id}

            if not schedule.enabled:
                logger.info(
                    "scan_trigger.skipped_disabled",
                    extra={
                        "event": "scan_trigger.skipped_disabled",
                        "schedule_id": schedule_id,
                    },
                )
                return {"status": "skipped_disabled", "schedule_id": schedule_id}

            if _should_skip_for_maintenance_window(
                window_cron=schedule.maintenance_window_cron,
                at=fired_at,
            ):
                logger.info(
                    "scan_trigger.skipped_maintenance_window",
                    extra={
                        "event": "scan_trigger.skipped_maintenance_window",
                        "schedule_id": schedule_id,
                    },
                )
                return {
                    "status": "skipped_maintenance_window",
                    "schedule_id": schedule_id,
                }

            await _ensure_tenant(session, schedule.tenant_id)
            scan_id = await _persist_scheduled_scan(
                session,
                tenant_id=schedule.tenant_id,
                target_url=schedule.target_url,
                scan_mode=schedule.scan_mode,
                schedule_id=schedule.id,
            )

            next_run = _compute_next_run_at(schedule.cron_expression, after=fired_at)
            await _update_run_timestamps(
                session,
                schedule_id=schedule.id,
                fired_at=fired_at,
                next_run_at=next_run,
            )
            await session.commit()

            target_url = schedule.target_url
            captured_tenant_id = schedule.tenant_id
    finally:
        await engine.dispose()

    _dispatch_scan_phase(
        scan_id=scan_id,
        tenant_id=captured_tenant_id,
        target_url=target_url,
    )
    logger.info(
        "scan_trigger.dispatched",
        extra={
            "event": "scan_trigger.dispatched",
            "schedule_id": schedule_id,
            "scan_id": scan_id,
            "tenant_hash": tenant_hash(captured_tenant_id),
        },
    )
    return {
        "status": "dispatched",
        "schedule_id": schedule_id,
        "scan_id": scan_id,
    }


def _dispatch_scan_phase(
    *,
    scan_id: str,
    tenant_id: str,
    target_url: str,
) -> None:
    """Enqueue the existing ``argus.scan_phase`` Celery task.

    Imported lazily to avoid a circular import at module load — the
    ``src.tasks`` package itself imports ``src.celery_app`` which is the
    parent of this module.
    """
    from src.tasks import scan_phase_task

    scan_phase_task.delay(scan_id, tenant_id, target_url, {})


# ---------------------------------------------------------------------------
# Celery task wrapper
# ---------------------------------------------------------------------------


@app.task(bind=True, name="argus.scheduling.run_scheduled_scan")
def run_scheduled_scan(
    _self: Any,
    schedule_id: str,
    tenant_id: str,
) -> dict[str, Any]:
    """Celery task body: dispatches a scan if all gates pass.

    See module docstring for the gate semantics. The task always returns
    a JSON-serialisable dict; failures inside the body bubble up to
    Celery (the worker logs + retries per task config) but the explicit
    "skipped" returns are normal flow control, not errors.
    """
    fired_at = datetime.now(UTC)
    return asyncio.run(
        _run_scheduled_scan_async(
            schedule_id=schedule_id,
            tenant_id=tenant_id,
            fired_at=fired_at,
        )
    )


__all__ = [
    "DEFAULT_MAINTENANCE_WINDOW_DURATION_MINUTES",
    "run_scheduled_scan",
]
