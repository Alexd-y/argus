"""ARG-044 / T40 — Celery beat schedule registry.

Centralises beat schedules so the wiring is in one place rather than
scattered across task modules. Imported once at module-load time by
:mod:`src.celery_app`; the :func:`apply_beat_schedule` helper merges
the entries into ``app.conf.beat_schedule`` without clobbering existing
operator overrides.

Current schedule:

* ``argus.intel.epss_refresh`` — daily at 04:00 UTC.
* ``argus.intel.kev_refresh`` — daily at 05:00 UTC (one hour after EPSS
  so a single Celery beat container can sequence them on a single core
  without contention).
* ``argus.notifications.webhook_dlq_replay`` — daily at 06:00 UTC (T40,
  Cycle 6 Batch 5, ARG-053). Replays every DLQ row whose
  ``next_retry_at`` has elapsed and auto-abandons rows older than
  ``DLQ_MAX_AGE_DAYS`` (14d). Routed to the dedicated
  ``argus.notifications`` queue so it cannot starve scan / report queues
  during a sweep.

Adding a new schedule: define a constant below and append it to
``BEAT_SCHEDULE``. Keep names dotted (``argus.<area>.<task>``) so the
queue routing in :mod:`src.celery_app` can target them by prefix.
"""

from __future__ import annotations

from typing import Any

try:
    from celery.schedules import crontab
except ImportError:  # pragma: no cover — celery is a runtime dependency
    crontab = None  # type: ignore[assignment]


def _schedule(hour: int, minute: int) -> Any:
    """Return a daily-at-HH:MM crontab schedule (``None`` if Celery missing)."""
    if crontab is None:
        return None
    return crontab(hour=hour, minute=minute)


BEAT_SCHEDULE: dict[str, dict[str, Any]] = {
    "argus.intel.epss_refresh": {
        "task": "argus.intel.epss_refresh",
        "schedule": _schedule(hour=4, minute=0),
        "options": {"queue": "argus.intel"},
    },
    "argus.intel.kev_refresh": {
        "task": "argus.intel.kev_refresh",
        "schedule": _schedule(hour=5, minute=0),
        "options": {"queue": "argus.intel"},
    },
    # T40 (Cycle 6 Batch 5, ARG-053) — daily DLQ replay + auto-abandon @ 14d.
    # Scheduled one hour after KEV refresh so the three intel + notification
    # housekeeping tasks can share a single beat container without contention.
    "argus.notifications.webhook_dlq_replay": {
        "task": "argus.notifications.webhook_dlq_replay",
        "schedule": _schedule(hour=6, minute=0),
        "options": {"queue": "argus.notifications"},
    },
}


def apply_beat_schedule(app: Any) -> None:
    """Merge :data:`BEAT_SCHEDULE` into ``app.conf.beat_schedule``.

    Operator overrides loaded from settings (e.g. environment-driven
    schedule changes) take precedence — we only add entries that are
    not already declared, never overwrite.
    """
    existing = dict(getattr(app.conf, "beat_schedule", {}) or {})
    for name, spec in BEAT_SCHEDULE.items():
        if name in existing:
            continue
        if spec.get("schedule") is None:
            # Celery isn't importable — nothing to schedule.
            continue
        existing[name] = spec
    app.conf.beat_schedule = existing


__all__ = [
    "BEAT_SCHEDULE",
    "apply_beat_schedule",
]
