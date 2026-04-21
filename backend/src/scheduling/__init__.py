"""ARGUS scheduling plane (ARG-056, Cycle 6 Batch 4).

Pure logic for cron-driven scan schedules. The package owns:

* :mod:`src.scheduling.cron_parser` — closed-taxonomy cron expression
  validation, next-fire-time calculation, and maintenance-window
  membership checks. Pure functions only — no DB, no Redis, no I/O.

Downstream consumers (added in later T33 / T35 commits):

* ``src.api.routers.admin_schedules`` — CRUD endpoints validate
  operator-supplied cron expressions through this module.
* ``src.scheduling.redbeat_loader`` — atomically syncs DB rows into
  ``RedBeatScheduler``.
* ``src.scheduling.scan_trigger`` — Celery task that consults
  :func:`is_in_maintenance_window` before launching a scan.
* Frontend ``/admin/schedules`` page renders cron previews via a server
  action that proxies to this module.

The public surface is intentionally minimal (YAGNI). New helpers
(``previous_fire_time``, ``human_readable``, etc.) MUST be justified by
a concrete caller in T33 / T35 / future tasks.
"""

from src.scheduling.cron_parser import (
    MAX_CRON_FIELDS,
    MIN_INTERVAL_SECONDS,
    CronParserError,
    CronValidationError,
    ParsedCron,
    is_in_maintenance_window,
    next_fire_time,
    normalize_to_utc,
    validate_cron,
)
from src.scheduling.redbeat_loader import (
    SCAN_TRIGGER_TASK_NAME,
    remove_one,
    sync_all_from_db,
    sync_one,
)

__all__ = [
    "MAX_CRON_FIELDS",
    "MIN_INTERVAL_SECONDS",
    "SCAN_TRIGGER_TASK_NAME",
    "CronParserError",
    "CronValidationError",
    "ParsedCron",
    "is_in_maintenance_window",
    "next_fire_time",
    "normalize_to_utc",
    "remove_one",
    "sync_all_from_db",
    "sync_one",
    "validate_cron",
]
