"""Celery app — Redis broker, tasks for scan phases and tool runs (Phase 5).

ARG-041 — Observability: ``setup_celery_observability`` is invoked at module
import so worker processes share the OTel pipeline with the API. Per-task
duration / failure metrics are emitted via the canonical Celery signals
(``task_prerun`` / ``task_postrun`` / ``task_failure``).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from celery import Celery
from celery.signals import beat_init, task_failure, task_postrun, task_prerun

from src.core.config import settings
from src.core.observability import record_celery_task

_logger = logging.getLogger(__name__)

app = Celery(
    "argus",
    broker=settings.celery_broker,
    backend=settings.redis_url,
    include=[
        "src.tasks",
        "src.recon.jobs.runner",
        # ARG-044 — daily EPSS / KEV intelligence refresh.
        "src.celery.tasks.intel_refresh",
        # T40 (Cycle 6 Batch 5, ARG-053) — daily webhook DLQ replay + auto-abandon.
        "src.celery.tasks.webhook_dlq_replay",
        # T33 — operator-managed scan_schedules; the trigger task is
        # scheduled dynamically via celery-redbeat (see redbeat block below).
        "src.scheduling.scan_trigger",
    ],
)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,
    worker_prefetch_multiplier=1,
    task_routes={
        "argus.scan_phase": {"queue": "argus.scans"},
        "argus.generate_report": {"queue": "argus.reports"},
        "argus.generate_all_reports": {"queue": "argus.reports"},
        "argus.report_generation": {"queue": "argus.reports"},
        "argus.ai_text_generation": {"queue": "argus.reports"},
        "argus.tool_run": {"queue": "argus.tools"},
        "argus.va_active_scan_tool": {"queue": "argus.tools"},
        "argus.va.run_dalfox": {"queue": "argus.tools"},
        "argus.va.run_xsstrike": {"queue": "argus.tools"},
        "argus.va.run_ffuf": {"queue": "argus.tools"},
        "argus.va.run_sqlmap": {"queue": "argus.tools"},
        "argus.va.run_nuclei": {"queue": "argus.tools"},
        "argus.va.run_whatweb": {"queue": "argus.tools"},
        "argus.va.run_nikto": {"queue": "argus.tools"},
        "argus.va.run_testssl": {"queue": "argus.tools"},
        "argus.recon_job": {"queue": "argus.recon"},
        "argus.exploitation": {"queue": "argus.exploitation"},
        # ARG-044 — intel refresh tasks (EPSS / KEV) on a dedicated queue
        # so they cannot starve scan / report queues during a scheduled run.
        "argus.intel.epss_refresh": {"queue": "argus.intel"},
        "argus.intel.kev_refresh": {"queue": "argus.intel"},
        # T40 (Cycle 6 Batch 5, ARG-053) — webhook DLQ housekeeping (and any
        # future notification beat / on-demand replay tasks) lands on its own
        # dedicated queue so a slow upstream cannot starve the scan / report
        # queues during the daily 06:00 UTC sweep.
        "argus.notifications.*": {"queue": "argus.notifications"},
        # T33 — scheduled scans fire onto the same queue as ad-hoc scans
        # so the existing worker pool drains them with no extra config.
        "argus.scheduling.run_scheduled_scan": {"queue": "argus.scans"},
    },
    task_default_queue="argus.default",
)


# T33 — celery-redbeat dynamic scheduler.
#
# RedBeat persists schedule entries in Redis under ``redbeat:<key>``, which
# lets the API layer add/remove ``scan_schedules`` at runtime without
# restarting Celery beat. We point it at the same Redis instance used as
# broker / backend so a single Redis is sufficient for dev + small prod
# deployments. Operators who want to isolate beat state from broker state
# can override ``REDBEAT_REDIS_URL`` in the environment (Celery picks it
# up from ``app.conf`` directly).
#
# The import is wrapped in a try/except: if celery-redbeat is not
# installed (for example in a slim test image) Celery falls back to its
# default in-memory ``PersistentScheduler`` and the API endpoints will
# log a warning when ``redbeat_loader.sync_one`` is called. The CRUD
# layer still functions; only the dynamic beat sync is downgraded.
try:
    import redbeat  # type: ignore[import-untyped]  # noqa: F401

    _REDBEAT_AVAILABLE = True
except ImportError:  # pragma: no cover — redbeat is a runtime dependency in prod
    _REDBEAT_AVAILABLE = False
    _logger.warning(
        "celery.redbeat.unavailable",
        extra={"event": "celery.redbeat.unavailable"},
    )

if _REDBEAT_AVAILABLE:
    app.conf.update(
        beat_scheduler="redbeat.RedBeatScheduler",
        redbeat_redis_url=settings.redis_url,
        # Lock timeout (seconds) protects against split-brain when two
        # beat processes race for the lock. 60s is the upstream default;
        # we keep it explicit so ops can tune it without code changes.
        redbeat_lock_timeout=60,
        # Key prefix isolates ARGUS schedules from any other Celery app
        # that might share this Redis instance.
        redbeat_key_prefix="argus:redbeat:",
    )


# ARG-044 — beat schedule (daily EPSS / KEV refresh). The merge helper is
# idempotent and respects operator overrides loaded from settings.
try:
    from src.celery.beat_schedule import apply_beat_schedule

    apply_beat_schedule(app)
except Exception:  # pragma: no cover — defensive
    _logger.debug("celery.beat_schedule.setup_failed", exc_info=True)


# ---------------------------------------------------------------------------
# T33 / ARG-056 — RedBeat hydration on beat startup.
#
# The CRUD layer (``admin_schedules``) writes scan_schedule rows AND syncs
# them to RedBeat. If the beat process restarts, RedBeat's Redis keyspace
# is rebuilt only as the next CRUD mutation lands on each row — meaning
# a fresh beat process can sit idle for hours after a restart. The
# ``beat_init`` signal fires once per beat-process startup; we use it to
# reconcile the entire ``scan_schedules`` table into RedBeat from the
# authoritative DB.
#
# The handler is intentionally fault-tolerant:
#
# * ``sync_all_from_db`` already swallows per-row failures and logs a
#   structured warning; only an unrecoverable session-factory error
#   would surface here, which we catch + log so beat still starts.
# * ``asyncio.run`` is safe at this point — beat_init fires synchronously
#   before any worker loop is running.
# ---------------------------------------------------------------------------


@beat_init.connect
def _hydrate_redbeat_on_beat_startup(sender: Any = None, **_kwargs: Any) -> None:  # noqa: ARG001
    """Rehydrate RedBeat from the DB on beat startup.

    Idempotent — :func:`src.scheduling.redbeat_loader.sync_all_from_db`
    upserts each row and tolerates Redis being unavailable. ARG-056 / T33.
    """
    import asyncio

    from src.db.session import async_session_factory
    from src.scheduling.redbeat_loader import sync_all_from_db

    async def _run() -> None:
        async with async_session_factory() as session:
            await sync_all_from_db(session)

    try:
        asyncio.run(_run())
    except Exception:
        _logger.exception("celery.beat_init.redbeat_hydrate_failed")


# ---------------------------------------------------------------------------
# ARG-041 — task duration + failure observability
#
# We attach the start timestamp to the task instance via ``__argus_start_ts``
# (intentional non-public attribute name to avoid colliding with Celery's
# own bookkeeping) and read it back on postrun. Postrun also fires on
# failure, so we always emit *both* a duration histogram sample and (on
# failure) a counter increment with the exception class.
# ---------------------------------------------------------------------------


@task_prerun.connect
def _argus_task_prerun(sender: Any = None, task: Any = None, **_kwargs: Any) -> None:  # noqa: ARG001
    target = task or sender
    if target is None:
        return
    try:
        target.__argus_start_ts = time.perf_counter()
    except Exception:  # pragma: no cover — defensive
        _logger.debug("celery.observability.prerun_set_failed", exc_info=True)


@task_postrun.connect
def _argus_task_postrun(
    sender: Any = None,
    task: Any = None,
    state: str | None = None,
    **_kwargs: Any,
) -> None:  # noqa: ARG001
    target = task or sender
    if target is None:
        return
    start_ts = getattr(target, "__argus_start_ts", None)
    duration = max(0.0, time.perf_counter() - start_ts) if start_ts else 0.0
    task_name = getattr(target, "name", None) or "unknown"
    status = (state or "success").lower()
    if status not in {"success", "failure", "retry", "revoked", "rejected"}:
        status = "success"
    try:
        record_celery_task(
            task_name=task_name,
            status=status,
            duration_seconds=duration,
        )
    except Exception:  # pragma: no cover — defensive
        _logger.debug("celery.observability.postrun_record_failed", exc_info=True)


@task_failure.connect
def _argus_task_failure(
    sender: Any = None,
    exception: BaseException | None = None,
    **_kwargs: Any,
) -> None:
    if sender is None:
        return
    task_name = getattr(sender, "name", None) or "unknown"
    error_class = type(exception).__name__ if exception else "UnknownError"
    try:
        record_celery_task(
            task_name=task_name,
            status="failure",
            duration_seconds=0.0,
            error_class=error_class,
        )
    except Exception:  # pragma: no cover — defensive
        _logger.debug("celery.observability.failure_record_failed", exc_info=True)


# OTel instrumentation — defer import + best-effort.
try:
    from src.core.otel_init import setup_celery_observability

    setup_celery_observability(app)
except Exception:  # pragma: no cover — defensive
    _logger.debug("celery.observability.otel_setup_failed", exc_info=True)
