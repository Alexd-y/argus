"""Structured observability for agent execution (platform-hardening A, §13).

Prometheus counters/histograms for the new execution events plus a helper to
emit structured log events with correlation fields.

Cardinality discipline (§13): high-cardinality identifiers (tenant_id, scan_id,
task_id, attempt_id) go into LOGS/traces, never into Prometheus labels. Metric
labels are restricted to low-cardinality dimensions (phase, agent_role, outcome,
pool, reason). ``metric_labels`` enforces this by dropping unknown/forbidden
keys rather than silently exploding series count.

Degrades gracefully: if ``prometheus_client`` is unavailable the counters become
no-ops so importing this module never breaks a worker.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("argus.agent.events")

# Allowed low-cardinality label keys for Prometheus series.
_ALLOWED_LABELS = frozenset({"phase", "agent_role", "outcome", "pool", "reason", "provider"})
# Never allowed as Prometheus labels (unbounded cardinality).
_FORBIDDEN_LABELS = frozenset({"tenant_id", "scan_id", "task_id", "attempt_id"})


def metric_labels(**kwargs: Any) -> dict[str, str]:
    """Keep only low-cardinality labels; drop unbounded identifiers."""
    out: dict[str, str] = {}
    for key, value in kwargs.items():
        if key in _FORBIDDEN_LABELS:
            continue
        if key in _ALLOWED_LABELS and value is not None:
            out[key] = str(value)
    return out


class _NoopMetric:
    def labels(self, *_a: Any, **_k: Any) -> _NoopMetric:
        return self

    def inc(self, *_a: Any, **_k: Any) -> None:
        pass

    def observe(self, *_a: Any, **_k: Any) -> None:
        pass


def _counter(name: str, doc: str, labels: tuple[str, ...]):
    try:
        from prometheus_client import Counter

        return Counter(name, doc, labels)
    except Exception:  # noqa: BLE001 — optional dep / duplicate registration
        return _NoopMetric()


def _histogram(name: str, doc: str, labels: tuple[str, ...]):
    try:
        from prometheus_client import Histogram

        return Histogram(name, doc, labels)
    except Exception:  # noqa: BLE001
        return _NoopMetric()


_LABELS = ("phase", "agent_role", "outcome")

AGENT_TASK_EVENTS = _counter(
    "argus_agent_task_events_total", "Agent task lifecycle events", ("phase", "outcome")
)
AGENT_TASK_RETRIES = _counter(
    "argus_agent_task_retries_total", "Agent task retries scheduled", ("phase",)
)
BUDGET_EVENTS = _counter(
    "argus_budget_events_total", "Budget reserve/settle/release/deny events", ("outcome",)
)
LEASE_EVENTS = _counter(
    "argus_lease_events_total", "Distributed lease acquire/contended/release", ("pool", "outcome")
)
SANDBOX_FAILURES = _counter(
    "argus_sandbox_failures_total", "Sandbox lifecycle failures", ("reason",)
)
EVIDENCE_EVENTS = _counter(
    "argus_evidence_events_total", "Evidence accepted/rejected", ("outcome",)
)
OUTBOX_EVENTS = _counter(
    "argus_outbox_events_total", "Transactional outbox dispatch results", ("outcome",)
)
QUEUE_WAIT = _histogram(
    "argus_agent_queue_wait_seconds", "Time a task waited before being claimed", ("phase",)
)
TASK_DURATION = _histogram(
    "argus_agent_task_duration_seconds", "Task attempt duration", ("phase", "outcome")
)


def log_event(event: str, level: int = logging.INFO, **fields: Any) -> None:
    """Emit a structured log event with correlation fields (safe to include IDs).

    Never logs secrets/credentials — callers must not pass them. Correlation
    fields (tenant_id/scan_id/task_id/attempt_id/phase/agent_role) belong here,
    NOT in Prometheus labels.
    """
    logger.log(level, event, extra={"event": event, **fields})


__all__ = [
    "AGENT_TASK_EVENTS",
    "AGENT_TASK_RETRIES",
    "BUDGET_EVENTS",
    "EVIDENCE_EVENTS",
    "LEASE_EVENTS",
    "OUTBOX_EVENTS",
    "QUEUE_WAIT",
    "SANDBOX_FAILURES",
    "TASK_DURATION",
    "log_event",
    "metric_labels",
]
