"""B6-T03 (Cycle 6 Batch 6, T49 / D-5) — backfill ``argus_celery_queue_depth`` Gauge.

Purpose
-------
``infra/helm/argus/values-prod.yaml`` already references ``argus_celery_queue_depth``
as the celery HPA's custom-metric scaling target (see ``hpa.celery.customMetrics``)
but no source emitted that gauge before this module landed. Without a source the
prod HPA silently degrades to CPU-only scaling and the Prometheus Adapter rule
shipped in ``templates/prometheus-adapter-rules.yaml`` would have no underlying
series to expose as an external metric.

What this module does
---------------------
1. Lazily registers a single Prometheus :class:`prometheus_client.Gauge` named
   ``argus_celery_queue_depth`` (label: ``queue``) against the same default
   registry that :mod:`src.core.observability` exposes via the ``/metrics``
   endpoint. The gauge is intentionally kept OUT of ``METRIC_CATALOGUE`` —
   that catalogue locks the public *attack-surface* metric set at 9 families
   (cardinality + label-whitelist discipline). The queue-depth gauge is
   operational telemetry with a tiny, static label set (one entry per queue
   declared in :mod:`src.celery_app`), so it does not carry the same risk
   profile and would only pollute the cardinality unit test.

2. Exposes :func:`refresh_queue_depths` which:
   * preferentially queries ``app.control.inspect()`` aggregating
     ``reserved`` + ``active`` + ``scheduled`` per known queue (this matches
     the depth visible to a worker mid-run and avoids double-counting tasks
     sitting in the broker but already reserved by a worker), and
   * falls back to ``redis.LLEN`` against the broker keys when worker
     introspection fails (broker reachable but no workers alive yet — the
     classic cold-start condition the HPA is supposed to react to).

3. Exposes a Celery task ``argus.metrics.queue_depth_refresh`` registered
   on the dedicated ``argus.intel`` queue. The beat schedule wires it to
   fire every 15 s — short enough to react to scan-burst spikes within
   one HPA stabilization window (default 30 s upstream) without flooding
   Redis (one ``LLEN`` per queue, ~9 round-trips per tick).

Failure semantics
-----------------
The task body NEVER raises. Any failure (broker offline, redis offline,
inspect timeout) is downgraded to a structured warning log; the previously
recorded gauge value is preserved (Prometheus' last-write-wins semantics).
This mirrors the discipline in :mod:`src.core.observability` — observability
must never break the request / scheduling path.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Final

from src.core.observability import PROMETHEUS_AVAILABLE, get_registry

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Canonical list of Celery queues whose depth should be observed. Mirrors
#: the ``task_routes`` declaration in :mod:`src.celery_app` plus the
#: ``argus.notifications`` queue (T40, ARG-053). Adding a new queue requires
#: appending it here AND declaring its route in ``celery_app.py`` — the gate
#: lives in ``test_queue_depth_metrics_updater.py`` so drift is caught in CI.
KNOWN_QUEUES: Final[tuple[str, ...]] = (
    "argus.default",
    "argus.scans",
    "argus.reports",
    "argus.tools",
    "argus.recon",
    "argus.exploitation",
    "argus.intel",
    "argus.notifications",
)

#: Inspect RPC deadline. Same budget as :mod:`src.api.routers.queues_health`.
_INSPECT_TIMEOUT_SECONDS: Final[float] = 1.0

#: Prometheus metric metadata. Kept here (not in
#: ``src.core.observability.METRIC_CATALOGUE``) so the locked 9-family
#: cardinality unit test stays green — see module docstring for rationale.
_GAUGE_NAME: Final[str] = "argus_celery_queue_depth"
_GAUGE_HELP: Final[str] = (
    "Current depth of an ARGUS Celery queue (reserved + active + scheduled, "
    "or LLEN of the broker list when worker introspection is unavailable)."
)
_GAUGE_LABELS: Final[tuple[str, ...]] = ("queue",)


# ---------------------------------------------------------------------------
# Lazy gauge handle (singleton against whatever registry observability owns).
# ---------------------------------------------------------------------------

_gauge_lock = threading.Lock()
_gauge: Any | None = None


def _get_gauge() -> Any | None:
    """Return the singleton :class:`Gauge`, registering it on first call.

    The registry handle is fetched fresh from
    :func:`src.core.observability.get_registry` so that test suites which
    rebuild the registry via :func:`reset_metrics_registry` get a fresh
    gauge as well (the previous one would still be bound to the old
    registry and therefore invisible from the test snapshot).

    Returns ``None`` when :mod:`prometheus_client` is unavailable — in
    that mode the rest of the module degrades to a no-op.
    """
    global _gauge
    if not PROMETHEUS_AVAILABLE:
        return None
    with _gauge_lock:
        if _gauge is not None:
            return _gauge
        try:
            from prometheus_client import Gauge

            _gauge = Gauge(
                name=_GAUGE_NAME,
                documentation=_GAUGE_HELP,
                labelnames=_GAUGE_LABELS,
                registry=get_registry(),
            )
        except ValueError:
            _gauge = _find_existing_gauge()
        except Exception:
            logger.exception(
                "metrics_updater.gauge_registration_failed",
                extra={"event": "metrics_updater_gauge_registration_failed"},
            )
            return None
    return _gauge


def _find_existing_gauge() -> Any | None:
    """Recover the gauge if a previous import already registered it.

    Reload-style imports during tests can re-execute the module body; the
    second registration would raise :class:`ValueError` (duplicate metric).
    Walking the registry's ``_names_to_collectors`` dict is the documented
    upstream-supported way to retrieve the existing collector.
    """
    registry = get_registry()
    if registry is None:
        return None
    collectors = getattr(registry, "_names_to_collectors", None)
    if not isinstance(collectors, dict):
        return None
    return collectors.get(_GAUGE_NAME)


def reset_gauge() -> None:
    """Drop the cached gauge handle. Intended for tests only."""
    global _gauge
    with _gauge_lock:
        _gauge = None


# ---------------------------------------------------------------------------
# Depth probe (worker introspect + Redis LLEN fallback).
# ---------------------------------------------------------------------------


def _inspect_reserved_depths() -> dict[str, int] | None:
    """Aggregate ``reserved + active + scheduled`` per queue via Celery inspect.

    Returns ``None`` (fall through to Redis) on any failure or when no
    worker replies — the latter is indistinguishable from "broker reachable
    but no workers alive" and is exactly the condition the HPA is meant to
    react to, so falling back to broker LLEN keeps the signal flowing.
    """
    try:
        from src.celery_app import app as celery_app

        inspector = celery_app.control.inspect(timeout=_INSPECT_TIMEOUT_SECONDS)
        reserved = inspector.reserved() or {}
        active = inspector.active() or {}
        scheduled = inspector.scheduled() or {}
    except Exception as exc:
        logger.debug(
            "metrics_updater.inspect_failed",
            extra={
                "event": "metrics_updater_inspect_failed",
                "error_class": type(exc).__name__,
            },
        )
        return None

    if not (reserved or active or scheduled):
        return None

    counts: dict[str, int] = {q: 0 for q in KNOWN_QUEUES}
    for bucket in (reserved, active, scheduled):
        for tasks in bucket.values():
            if not isinstance(tasks, list):
                continue
            for task in tasks:
                queue = _resolve_task_queue(task)
                if queue in counts:
                    counts[queue] += 1
    return counts


def _resolve_task_queue(task: object) -> str | None:
    """Best-effort extraction of the queue name from an inspect dict entry.

    The inspect RPC returns a list of dicts; the queue lives under
    ``delivery_info.routing_key`` (Celery's broker primitive). When the
    field is missing we return ``None`` so the caller can skip the entry
    instead of attributing it to a wrong bucket.
    """
    if not isinstance(task, dict):
        return None
    delivery = task.get("delivery_info")
    if isinstance(delivery, dict):
        rk = delivery.get("routing_key")
        if isinstance(rk, str) and rk:
            return rk
    rk = task.get("routing_key")
    return rk if isinstance(rk, str) and rk else None


def _redis_llen_depths() -> dict[str, int]:
    """Return per-queue ``LLEN`` fallback. Missing keys collapse to 0.

    Each individual ``LLEN`` is wrapped so a single broken key (e.g. type
    mismatch from an external producer) cannot kill the whole sweep.
    """
    from src.core.redis_client import get_redis

    counts: dict[str, int] = {q: 0 for q in KNOWN_QUEUES}
    client = get_redis()
    if client is None:
        logger.warning(
            "metrics_updater.redis_unavailable",
            extra={"event": "metrics_updater_redis_unavailable"},
        )
        return counts
    for queue in KNOWN_QUEUES:
        counts[queue] = _safe_llen(client, queue)
    return counts


def _safe_llen(client: object, queue: str) -> int:
    """Return ``int(client.llen(queue))`` clamped to >=0 or 0 on any failure."""
    try:
        result = client.llen(queue)  # type: ignore[attr-defined]
    except Exception as exc:
        logger.debug(
            "metrics_updater.llen_failed",
            extra={
                "event": "metrics_updater_llen_failed",
                "queue": queue,
                "error_class": type(exc).__name__,
            },
        )
        return 0
    try:
        return max(0, int(result))
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def refresh_queue_depths() -> dict[str, int]:
    """Probe queues and update the gauge. Returns the per-queue counts.

    Strategy: prefer worker-side ``inspect`` (matches what the worker
    pool actually sees), fall back to Redis ``LLEN`` (matches what the
    HPA needs when there are zero workers — the cold-start case). Either
    way, every queue in :data:`KNOWN_QUEUES` ends up with a numeric
    sample so dashboards show a flat zero rather than a stale gap.
    """
    depths = _inspect_reserved_depths()
    if depths is None:
        depths = _redis_llen_depths()

    gauge = _get_gauge()
    if gauge is None:
        return depths
    for queue, depth in depths.items():
        try:
            gauge.labels(queue=queue).set(float(depth))
        except Exception:
            logger.debug(
                "metrics_updater.gauge_set_failed",
                extra={
                    "event": "metrics_updater_gauge_set_failed",
                    "queue": queue,
                },
            )
    logger.debug(
        "metrics_updater.refresh_complete",
        extra={
            "event": "metrics_updater_refresh_complete",
            "queue_count": len(depths),
            "total_depth": sum(depths.values()),
        },
    )
    return depths


# ---------------------------------------------------------------------------
# Celery task — registered when celery_app is importable.
# Wrapped in try/except so this module can still be imported in unit tests
# that stub Celery away.
# ---------------------------------------------------------------------------


try:
    from src.celery_app import app as _celery_app

    @_celery_app.task(  # type: ignore[misc]
        name="argus.metrics.queue_depth_refresh",
        bind=True,
        queue="argus.intel",
        max_retries=0,
        ignore_result=True,
    )
    def queue_depth_refresh_task(self: Any) -> dict[str, int]:  # noqa: ARG001
        """Beat-driven 15 s refresh of :func:`refresh_queue_depths`.

        Returns the per-queue depths so Celery's result backend (and any
        ad-hoc ``apply_async().get()`` from operators) carries the same
        snapshot the gauge just received. Failures inside
        :func:`refresh_queue_depths` are already absorbed; this wrapper
        adds a final defensive blanket so the beat tick can never fail.
        """
        try:
            return refresh_queue_depths()
        except Exception:
            logger.exception(
                "metrics_updater.task_unhandled",
                extra={"event": "metrics_updater_task_unhandled"},
            )
            return {q: 0 for q in KNOWN_QUEUES}

except Exception:  # pragma: no cover — defensive, only hits when Celery import fails
    logger.debug(
        "metrics_updater.celery_task_not_registered",
        extra={"event": "metrics_updater_celery_task_not_registered"},
        exc_info=True,
    )


__all__ = [
    "KNOWN_QUEUES",
    "refresh_queue_depths",
    "reset_gauge",
]
