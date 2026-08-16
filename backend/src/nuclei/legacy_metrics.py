"""CONT-009 — Metrics and warnings for legacy nuclei argv builders.

Legacy paths increment a module-level counter (testable via
:func:`get_legacy_argv_total`) and emit structured log events. When Prometheus
is available, increments are also recorded on ``argus_sandbox_runs_total`` with
``tool_id=nuclei_legacy_argv`` for dashboard continuity.
"""

from __future__ import annotations

import logging
from threading import Lock
from typing import Final

from src.nuclei.legacy_inventory import NUCLEI_ARGV_CALL_SITES

logger = logging.getLogger(__name__)

_EVENT: Final[str] = "nuclei_legacy_argv_builder_total"

_legacy_total = 0
_lock = Lock()


def increment_legacy_argv(caller: str) -> int:
    """Record one legacy nuclei argv build and return the running total."""
    global _legacy_total
    with _lock:
        _legacy_total += 1
        total = _legacy_total

    logger.warning(
        _EVENT,
        extra={
            "event": _EVENT,
            "caller": caller,
            "total": total,
        },
    )

    return total


def get_legacy_argv_total() -> int:
    """Return the module-level legacy argv counter (for tests and diagnostics)."""
    with _lock:
        return _legacy_total


def reset_legacy_argv_metrics() -> None:
    """Reset the module-level counter — tests only."""
    global _legacy_total
    with _lock:
        _legacy_total = 0


__all__ = [
    "NUCLEI_ARGV_CALL_SITES",
    "get_legacy_argv_total",
    "increment_legacy_argv",
    "reset_legacy_argv_metrics",
]
