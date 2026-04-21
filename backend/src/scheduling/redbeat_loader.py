"""T33 / ARG-056 — RedBeat dynamic loader.

Bridges the ``scan_schedules`` table to Celery's :class:`redbeat.RedBeatScheduler`.
The CRUD layer in :mod:`src.api.routers.admin_schedules` calls into this
module after every persisted change so the running beat process picks up
schedule mutations without a restart.

Public surface (kept minimal — YAGNI):

* :func:`sync_one`           — upsert a single :class:`ScanSchedule` row
* :func:`remove_one`         — drop a schedule entry by id
* :func:`sync_all_from_db`   — bootstrap reconciliation on beat startup

All operations are best-effort with structured logging:

* When ``celery-redbeat`` is not installed (slim test images, local
  dev without Redis), the loader logs ``redbeat.unavailable`` and
  returns False / 0. The CRUD layer keeps working — only the dynamic
  beat sync is downgraded.
* When Redis itself is unreachable, the loader catches the connection
  error, emits ``redbeat.redis_unavailable``, and likewise returns
  False / 0. The next successful API call (or the periodic sync from
  ``sync_all_from_db`` on beat startup) reconciles the missed update.

The loader does NOT raise to its callers. CRUD endpoints already
returned 2xx by the time they invoke the loader; surfacing a 503 here
would create a confusing partial-success contract for operators.

Cron mapping
------------
* 5-field cron expressions are passed to :class:`celery.schedules.crontab`
  in ``minute hour day_of_month month_of_year day_of_week`` order, mirroring
  the standard Vixie cron interpretation that :func:`validate_cron` enforces.
* Disabled rows still register a RedBeat entry with ``enabled=False`` so
  the scheduler keeps the metadata available for inspection but does not
  fire. This keeps re-enable cheap (single ``HSET``) and avoids
  losing ``last_run_at`` history during temporary disables.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import ScanSchedule

logger = logging.getLogger(__name__)

#: Name of the Celery task that the dynamic schedule fires. Kept as a
#: module-level constant so the CRUD tests can assert wiring without
#: importing the Celery app (avoids loading the broker on import).
SCAN_TRIGGER_TASK_NAME = "argus.scheduling.run_scheduled_scan"


# ---------------------------------------------------------------------------
# Lazy redbeat / celery imports
# ---------------------------------------------------------------------------
#
# Celery + redbeat are imported lazily so that:
#   1. The CRUD endpoints can ``from src.scheduling import sync_one`` without
#      forcing the broker connection to be established at import time.
#   2. Test environments that do not install celery-redbeat still get a
#      clean ``False`` return rather than an ImportError at module load.
#   3. We can swap the underlying entry class in tests via
#      ``patch("src.scheduling.redbeat_loader._get_redbeat_entry_cls", ...)``.


def _get_redbeat_entry_cls() -> type[Any] | None:
    """Return the ``RedBeatSchedulerEntry`` class or ``None`` if unavailable."""
    try:
        from redbeat import RedBeatSchedulerEntry  # type: ignore[import-untyped]
    except ImportError:
        return None
    return RedBeatSchedulerEntry


def _get_celery_crontab() -> type[Any] | None:
    """Return :class:`celery.schedules.crontab` or ``None``."""
    try:
        from celery.schedules import crontab
    except ImportError:  # pragma: no cover — celery is a hard runtime dep
        return None
    return crontab


def _get_celery_app() -> Any | None:
    """Return the configured Celery app instance or ``None``.

    Imported lazily so ``redbeat_loader`` can be loaded in process trees
    that have not finished broker setup (e.g. alembic migrations).
    """
    try:
        from src.celery_app import app
    except Exception:  # pragma: no cover — defensive
        logger.debug("redbeat.celery_app_import_failed", exc_info=True)
        return None
    return app


# ---------------------------------------------------------------------------
# Cron → Celery crontab translation
# ---------------------------------------------------------------------------


def _build_celery_schedule(cron_expression: str) -> Any | None:
    """Translate a 5-field cron string into a :class:`celery.schedules.crontab`.

    Returns ``None`` when Celery is not importable (test environment) or
    when the expression cannot be parsed. We don't re-validate the
    expression here — :func:`validate_cron` already gated it at the API
    boundary, so any failure at this layer is a bug we want surfaced as
    a structured warning, not an HTTP 500.
    """
    crontab_cls = _get_celery_crontab()
    if crontab_cls is None:
        return None

    parts = cron_expression.strip().split()
    if len(parts) != 5:
        logger.warning(
            "redbeat.cron_field_count_mismatch",
            extra={
                "event": "redbeat.cron_field_count_mismatch",
                "field_count": len(parts),
            },
        )
        return None

    minute, hour, day_of_month, month_of_year, day_of_week = parts
    try:
        return crontab_cls(
            minute=minute,
            hour=hour,
            day_of_month=day_of_month,
            month_of_year=month_of_year,
            day_of_week=day_of_week,
        )
    except Exception:  # pragma: no cover — defensive: validator already ran
        logger.warning(
            "redbeat.crontab_construction_failed",
            extra={"event": "redbeat.crontab_construction_failed"},
            exc_info=True,
        )
        return None


def _entry_name(schedule_id: str) -> str:
    """Stable RedBeat entry name for a schedule row.

    The ``argus.schedule.<uuid>`` prefix gives operators searching the
    Redis namespace ("``KEYS argus:redbeat:argus.schedule.*``") an easy
    handle for ad-hoc inspection without colliding with the static
    intel-refresh entries (``argus.intel.*``).
    """
    return f"argus.schedule.{schedule_id}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def sync_one(schedule_row: ScanSchedule) -> bool:
    """Upsert the RedBeat entry for ``schedule_row``.

    Returns:
        True when the entry was successfully persisted to Redis;
        False when redbeat / celery / Redis is unavailable, the cron
        could not be translated, or any other defensive guard tripped.

    The function is a no-op for ``schedule_row.enabled is False`` in the
    sense that it still writes the entry (so the CRUD endpoint can flip
    ``enabled`` back without a re-create round-trip), but RedBeat will
    not fire it.
    """
    entry_cls = _get_redbeat_entry_cls()
    if entry_cls is None:
        logger.warning(
            "redbeat.unavailable",
            extra={
                "event": "redbeat.unavailable",
                "schedule_id": schedule_row.id,
                "tenant_id": schedule_row.tenant_id,
            },
        )
        return False

    app = _get_celery_app()
    if app is None:
        return False

    schedule_obj = _build_celery_schedule(schedule_row.cron_expression)
    if schedule_obj is None:
        return False

    try:
        entry = entry_cls(
            name=_entry_name(schedule_row.id),
            task=SCAN_TRIGGER_TASK_NAME,
            schedule=schedule_obj,
            kwargs={
                "schedule_id": schedule_row.id,
                "tenant_id": schedule_row.tenant_id,
            },
            options={"queue": "argus.scans"},
            enabled=bool(schedule_row.enabled),
            app=app,
        )
        entry.save()
    except Exception:
        # Catch broad: Redis connection, serialisation, schema mismatch
        # — all of these collapse to a structured log here. The next
        # successful sync (CRUD call or beat startup) will reconcile.
        logger.warning(
            "redbeat.sync_one_failed",
            extra={
                "event": "redbeat.sync_one_failed",
                "schedule_id": schedule_row.id,
                "tenant_id": schedule_row.tenant_id,
            },
            exc_info=True,
        )
        return False

    logger.info(
        "redbeat.sync_one_ok",
        extra={
            "event": "redbeat.sync_one_ok",
            "schedule_id": schedule_row.id,
            "tenant_id": schedule_row.tenant_id,
            "enabled": bool(schedule_row.enabled),
        },
    )
    return True


def remove_one(schedule_id: str) -> bool:
    """Delete the RedBeat entry for ``schedule_id``.

    Returns ``True`` when the delete succeeded OR the entry was already
    absent (idempotent semantics). Returns ``False`` only when redbeat /
    celery / Redis itself is unavailable.
    """
    entry_cls = _get_redbeat_entry_cls()
    if entry_cls is None:
        logger.warning(
            "redbeat.unavailable",
            extra={"event": "redbeat.unavailable", "schedule_id": schedule_id},
        )
        return False

    app = _get_celery_app()
    if app is None:
        return False

    key = entry_cls.generate_key(app, _entry_name(schedule_id))

    try:
        entry = entry_cls.from_key(key, app=app)
    except KeyError:
        logger.info(
            "redbeat.remove_one_already_absent",
            extra={
                "event": "redbeat.remove_one_already_absent",
                "schedule_id": schedule_id,
            },
        )
        return True
    except Exception:
        logger.warning(
            "redbeat.remove_one_lookup_failed",
            extra={
                "event": "redbeat.remove_one_lookup_failed",
                "schedule_id": schedule_id,
            },
            exc_info=True,
        )
        return False

    try:
        entry.delete()
    except Exception:
        logger.warning(
            "redbeat.remove_one_failed",
            extra={"event": "redbeat.remove_one_failed", "schedule_id": schedule_id},
            exc_info=True,
        )
        return False

    logger.info(
        "redbeat.remove_one_ok",
        extra={"event": "redbeat.remove_one_ok", "schedule_id": schedule_id},
    )
    return True


async def sync_all_from_db(session: AsyncSession) -> int:
    """Reconcile every ``ScanSchedule`` row into RedBeat.

    Intended for Celery beat startup so a fresh process re-builds the
    Redis-side schedule from the authoritative table. Returns the
    number of successfully synced rows; failures are logged and counted
    against the total but do not raise.
    """
    if _get_redbeat_entry_cls() is None or _get_celery_app() is None:
        logger.warning(
            "redbeat.unavailable",
            extra={"event": "redbeat.unavailable"},
        )
        return 0

    result = await session.execute(select(ScanSchedule))
    rows = list(result.scalars().all())

    succeeded = 0
    for row in rows:
        if sync_one(row):
            succeeded += 1

    logger.info(
        "redbeat.sync_all_from_db",
        extra={
            "event": "redbeat.sync_all_from_db",
            "total": len(rows),
            "succeeded": succeeded,
        },
    )
    return succeeded


__all__ = [
    "SCAN_TRIGGER_TASK_NAME",
    "remove_one",
    "sync_all_from_db",
    "sync_one",
]
