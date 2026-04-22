"""B6-T03 (Cycle 6 Batch 6, T49 / D-5) — tests for ``queue_depth_refresh``.

Acceptance criteria mirrored from
``ai_docs/develop/plans/2026-04-22-argus-cycle6-b6.md`` §B6-T03:

Unit cases (8):
  1. ``BEAT_SCHEDULE`` registers ``argus.metrics.queue_depth_refresh`` at a
     15s interval on the ``argus.intel`` queue.
  2. ``KNOWN_QUEUES`` mirrors the ``task_routes`` declaration in
     ``src.celery_app`` — every queue we report must be a queue Celery
     actually routes onto (drift gate).
  3. ``refresh_queue_depths`` returns one entry per known queue (flat zeros
     when both inspect and Redis are unavailable).
  4. ``refresh_queue_depths`` aggregates ``reserved + active + scheduled``
     when the Celery inspect RPC succeeds.
  5. ``refresh_queue_depths`` falls back to ``redis.LLEN`` when
     ``app.control.inspect()`` returns empty maps (cold-start case).
  6. ``refresh_queue_depths`` swallows broker-offline failures (no raise),
     gauge retains its last-set value via the registry.
  7. ``refresh_queue_depths`` writes the gauge against the same registry
     that ``observability.get_registry()`` exposes (so ``/metrics`` will
     surface the series).
  8. ``_safe_llen`` clamps negative / non-numeric Redis returns to 0.

Determinism: no network, no real Celery, no Redis — everything is
monkeypatched at the module boundary.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Layer 1 — env defaults BEFORE any ``src.*`` import. Mirrors the patterns in
# tests/celery/test_webhook_dlq_replay_task.py and tests/unit/conftest.py.
# ---------------------------------------------------------------------------

import os

os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault(
    "JWT_SECRET",
    "test-secret-not-for-prod-but-required-by-settings",
)
os.environ.setdefault("ARGUS_TEST_MODE", "1")


# ---------------------------------------------------------------------------
# Layer 2 — module-under-test imports.
# ---------------------------------------------------------------------------

from datetime import timedelta  # noqa: E402
from typing import Any  # noqa: E402

import pytest  # noqa: E402
from prometheus_client import CollectorRegistry  # noqa: E402

from src.celery import beat_schedule  # noqa: E402
from src.celery import metrics_updater  # noqa: E402
from src.celery_app import app as celery_app  # noqa: E402
from src.core import observability as obs  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers + fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_registry() -> CollectorRegistry:
    """Each test runs against a private CollectorRegistry.

    The metrics_updater registers its gauge lazily against
    ``observability.get_registry()`` — by rebuilding observability's
    registry first AND clearing the gauge cache, every test gets a fresh
    series namespace and previous test gauges cannot leak in.
    """
    reg = CollectorRegistry()
    obs.reset_metrics_registry(registry=reg)
    metrics_updater.reset_gauge()
    return reg


def _gauge_samples(reg: CollectorRegistry) -> dict[str, float]:
    """Return ``{queue_label: value}`` for the queue-depth gauge."""
    out: dict[str, float] = {}
    for family in reg.collect():
        if family.name != "argus_celery_queue_depth":
            continue
        for sample in family.samples:
            if sample.name != "argus_celery_queue_depth":
                continue
            queue = sample.labels.get("queue", "")
            out[queue] = float(sample.value)
    return out


class _FakeRedis:
    """Synchronous in-memory Redis double — only the methods we call."""

    def __init__(self, depths: dict[str, int] | None = None) -> None:
        self._depths = dict(depths or {})

    def llen(self, queue: str) -> int:
        return self._depths.get(queue, 0)


class _ExplodingRedis:
    """Redis stub whose ``llen`` always raises (broker-offline simulation)."""

    def llen(self, queue: str) -> int:  # noqa: ARG002
        raise ConnectionError("redis://broker is gone")


class _ExplodingInspector:
    """Celery inspect double whose every probe raises."""

    def reserved(self) -> Any:
        raise ConnectionError("broker offline")

    def active(self) -> Any:  # pragma: no cover — exhaustive parity
        raise ConnectionError("broker offline")

    def scheduled(self) -> Any:  # pragma: no cover — exhaustive parity
        raise ConnectionError("broker offline")


class _StubInspector:
    """Inspect double that returns canned reserved/active/scheduled maps."""

    def __init__(
        self,
        *,
        reserved: dict[str, list[dict[str, Any]]] | None = None,
        active: dict[str, list[dict[str, Any]]] | None = None,
        scheduled: dict[str, list[dict[str, Any]]] | None = None,
    ) -> None:
        self._reserved = reserved or {}
        self._active = active or {}
        self._scheduled = scheduled or {}

    def reserved(self) -> dict[str, list[dict[str, Any]]]:
        return self._reserved

    def active(self) -> dict[str, list[dict[str, Any]]]:
        return self._active

    def scheduled(self) -> dict[str, list[dict[str, Any]]]:
        return self._scheduled


def _patch_inspect(
    monkeypatch: pytest.MonkeyPatch, inspector: object
) -> None:
    """Force ``celery_app.control.inspect(...)`` to return ``inspector``."""

    class _Control:
        def inspect(self, timeout: float = 1.0) -> object:  # noqa: ARG002
            return inspector

    monkeypatch.setattr(celery_app, "control", _Control(), raising=False)


def _patch_redis(
    monkeypatch: pytest.MonkeyPatch, fake: object | None
) -> None:
    """Stub ``src.core.redis_client.get_redis`` to return ``fake``."""
    import src.core.redis_client as redis_module

    monkeypatch.setattr(redis_module, "get_redis", lambda: fake)


# ---------------------------------------------------------------------------
# Unit case 1 — beat-schedule registration
# ---------------------------------------------------------------------------


class TestBeatScheduleRegistration:
    """``argus.metrics.queue_depth_refresh`` is wired at 15s on argus.intel."""

    _ENTRY: str = "argus.metrics.queue_depth_refresh"
    _QUEUE: str = "argus.intel"

    def test_beat_schedule_registers_queue_depth_refresh_every_15s(self) -> None:
        entry = beat_schedule.BEAT_SCHEDULE.get(self._ENTRY)
        assert entry is not None, (
            f"{self._ENTRY!r} missing from BEAT_SCHEDULE"
        )
        assert entry["task"] == self._ENTRY
        assert entry["options"] == {"queue": self._QUEUE}

        sched = entry["schedule"]
        assert isinstance(sched, timedelta), (
            f"schedule must be a timedelta; got {type(sched).__name__}"
        )
        assert sched == timedelta(
            seconds=beat_schedule.QUEUE_DEPTH_REFRESH_INTERVAL_SECONDS
        )
        assert beat_schedule.QUEUE_DEPTH_REFRESH_INTERVAL_SECONDS == 15

    def test_celery_app_routes_queue_depth_refresh_onto_argus_intel(self) -> None:
        routes = celery_app.conf.task_routes
        assert routes.get(self._ENTRY) == {"queue": self._QUEUE}, (
            "argus.metrics.queue_depth_refresh must be routed onto argus.intel"
        )


# ---------------------------------------------------------------------------
# Unit case 2 — KNOWN_QUEUES vs celery_app.task_routes drift gate
# ---------------------------------------------------------------------------


class TestKnownQueuesDriftGate:
    """Every queue in ``KNOWN_QUEUES`` must be a queue Celery actually uses."""

    def test_every_known_queue_is_a_celery_route_target_or_default(self) -> None:
        routes = celery_app.conf.task_routes or {}
        declared_queues = {
            spec.get("queue")
            for spec in routes.values()
            if isinstance(spec, dict) and spec.get("queue")
        }
        declared_queues.add(celery_app.conf.task_default_queue)
        missing = set(metrics_updater.KNOWN_QUEUES) - declared_queues
        assert not missing, (
            f"KNOWN_QUEUES references queues not declared on celery_app: {sorted(missing)}"
        )


# ---------------------------------------------------------------------------
# Unit case 3 — refresh returns a flat-zero dict when nothing is reachable
# ---------------------------------------------------------------------------


def test_refresh_returns_flat_zeros_when_inspect_and_redis_both_silent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No workers, no Redis → every queue lands at 0 (no gaps)."""
    _patch_inspect(monkeypatch, _StubInspector())
    _patch_redis(monkeypatch, None)

    depths = metrics_updater.refresh_queue_depths()
    assert set(depths.keys()) == set(metrics_updater.KNOWN_QUEUES)
    assert all(v == 0 for v in depths.values())


# ---------------------------------------------------------------------------
# Unit case 4 — inspect RPC aggregates reserved + active + scheduled
# ---------------------------------------------------------------------------


def test_refresh_aggregates_reserved_active_scheduled_when_inspect_succeeds(
    monkeypatch: pytest.MonkeyPatch,
    _isolated_registry: CollectorRegistry,
) -> None:
    inspector = _StubInspector(
        reserved={
            "worker-1@host": [
                {"delivery_info": {"routing_key": "argus.scans"}},
                {"delivery_info": {"routing_key": "argus.scans"}},
                {"delivery_info": {"routing_key": "argus.tools"}},
            ],
            "worker-2@host": [
                {"delivery_info": {"routing_key": "argus.intel"}},
            ],
        },
        active={
            "worker-1@host": [
                {"delivery_info": {"routing_key": "argus.scans"}},
            ],
        },
        scheduled={
            "worker-1@host": [
                {"delivery_info": {"routing_key": "argus.reports"}},
                {"delivery_info": {"routing_key": "argus.reports"}},
            ],
        },
    )
    _patch_inspect(monkeypatch, inspector)
    _patch_redis(monkeypatch, None)

    depths = metrics_updater.refresh_queue_depths()
    assert depths["argus.scans"] == 3
    assert depths["argus.tools"] == 1
    assert depths["argus.intel"] == 1
    assert depths["argus.reports"] == 2

    snapshot = _gauge_samples(_isolated_registry)
    assert snapshot["argus.scans"] == 3.0
    assert snapshot["argus.reports"] == 2.0


# ---------------------------------------------------------------------------
# Unit case 5 — Redis LLEN fallback when inspect returns empty maps
# ---------------------------------------------------------------------------


def test_refresh_falls_back_to_redis_llen_when_no_workers_replied(
    monkeypatch: pytest.MonkeyPatch,
    _isolated_registry: CollectorRegistry,
) -> None:
    """Cold-start case: broker reachable, no workers alive → Redis LLEN."""
    _patch_inspect(monkeypatch, _StubInspector())  # All three probes return {}
    fake = _FakeRedis({"argus.scans": 17, "argus.reports": 4})
    _patch_redis(monkeypatch, fake)

    depths = metrics_updater.refresh_queue_depths()
    assert depths["argus.scans"] == 17
    assert depths["argus.reports"] == 4
    # Queues with no broker-side rows still surface as 0, never gaps.
    assert depths["argus.tools"] == 0

    snapshot = _gauge_samples(_isolated_registry)
    assert snapshot["argus.scans"] == 17.0
    assert snapshot["argus.reports"] == 4.0
    assert snapshot["argus.tools"] == 0.0


# ---------------------------------------------------------------------------
# Unit case 6 — broker offline never raises out of refresh_queue_depths
# ---------------------------------------------------------------------------


def test_refresh_swallows_broker_offline_failures(
    monkeypatch: pytest.MonkeyPatch,
    _isolated_registry: CollectorRegistry,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Inspect raises + Redis missing → flat zeros, structured log, no raise."""
    _patch_inspect(monkeypatch, _ExplodingInspector())
    _patch_redis(monkeypatch, None)

    depths = metrics_updater.refresh_queue_depths()
    assert all(v == 0 for v in depths.values())
    assert any(
        "metrics_updater.redis_unavailable" in r.message for r in caplog.records
    ) or any(
        "metrics_updater.inspect_failed" in r.message for r in caplog.records
    )


def test_refresh_swallows_redis_llen_per_key_failures(
    monkeypatch: pytest.MonkeyPatch,
    _isolated_registry: CollectorRegistry,
) -> None:
    """One broken key cannot kill the whole sweep — exploding LLEN → 0."""
    _patch_inspect(monkeypatch, _StubInspector())
    _patch_redis(monkeypatch, _ExplodingRedis())

    depths = metrics_updater.refresh_queue_depths()
    assert all(v == 0 for v in depths.values())


# ---------------------------------------------------------------------------
# Unit case 7 — gauge ends up on observability.get_registry()
# ---------------------------------------------------------------------------


def test_gauge_registered_against_observability_default_registry(
    monkeypatch: pytest.MonkeyPatch,
    _isolated_registry: CollectorRegistry,
) -> None:
    """The `/metrics` endpoint scrapes ``observability.get_registry()``;
    the gauge MUST land there for HPAs to ever see a value."""
    _patch_inspect(monkeypatch, _StubInspector())
    fake = _FakeRedis({"argus.scans": 9})
    _patch_redis(monkeypatch, fake)

    metrics_updater.refresh_queue_depths()
    assert obs.get_registry() is _isolated_registry, (
        "gauge must register against the observability registry, "
        "not the global default"
    )
    snapshot = _gauge_samples(_isolated_registry)
    assert snapshot.get("argus.scans") == 9.0


# ---------------------------------------------------------------------------
# Unit case 8 — _safe_llen sanitisation
# ---------------------------------------------------------------------------


class TestSafeLlen:
    """Defensive parsing — Redis returning garbage cannot crash the sweep."""

    def test_safe_llen_clamps_negative_to_zero(self) -> None:
        class _Negative:
            def llen(self, _q: str) -> int:
                return -3

        assert metrics_updater._safe_llen(_Negative(), "argus.scans") == 0

    def test_safe_llen_returns_zero_on_garbage(self) -> None:
        class _Garbage:
            def llen(self, _q: str) -> str:
                return "not-a-number"

        assert metrics_updater._safe_llen(_Garbage(), "argus.scans") == 0

    def test_safe_llen_returns_zero_when_llen_raises(self) -> None:
        class _Raises:
            def llen(self, _q: str) -> int:
                raise RuntimeError("kaboom")

        assert metrics_updater._safe_llen(_Raises(), "argus.scans") == 0
