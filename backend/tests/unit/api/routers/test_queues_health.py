"""Unit tests for the ``GET /queues/health`` router — ARG-041.

Strategy: stub :func:`src.core.redis_client.get_redis` with a lightweight
``FakeRedis`` and patch the worker-inspect helper so we never touch a real
Redis or Celery cluster. Each test asserts a single behaviour:

* Redis up + workers active → HTTP 200, ``status="ok"``.
* Redis up + no workers       → HTTP 200, ``status="degraded"``.
* Redis up + ``llen`` raises  → depth coerced to 0, no exception bubbles.
* Redis missing               → HTTP 503, ``redis_reachable=false``.
* Redis ping fails            → HTTP 503, ``redis_reachable=false``.
* All ``WATCHED_QUEUES`` are present in the response.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.routers import queues_health as queues_module


class FakeRedis:
    """Synchronous in-memory Redis double — only the methods we call."""

    def __init__(
        self,
        *,
        depths: Mapping[str, int] | None = None,
        ping_ok: bool = True,
        llen_should_raise: bool = False,
    ) -> None:
        self._depths: dict[str, int] = dict(depths or {})
        self._ping_ok = ping_ok
        self._llen_should_raise = llen_should_raise

    def llen(self, queue: str) -> int:
        if self._llen_should_raise:
            raise ConnectionError("redis://localhost is gone")
        return self._depths.get(queue, 0)

    def ping(self) -> bool:
        if not self._ping_ok:
            raise ConnectionError("redis ping rejected")
        return True


@pytest.fixture
def app() -> FastAPI:
    a = FastAPI()
    a.include_router(queues_module.router)
    return a


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def _patch_get_redis(monkeypatch: pytest.MonkeyPatch, fake: Any | None) -> None:
    monkeypatch.setattr(queues_module, "get_redis", lambda: fake)


def _patch_workers(monkeypatch: pytest.MonkeyPatch, count: int) -> None:
    monkeypatch.setattr(
        queues_module, "_inspect_worker_count", lambda: count
    )


def test_returns_503_when_redis_missing(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_get_redis(monkeypatch, None)
    resp = client.get("/queues/health")
    assert resp.status_code == 503
    assert resp.json()["redis_reachable"] is False
    assert resp.json()["status"] == "degraded"


def test_returns_503_when_redis_ping_fails(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_get_redis(monkeypatch, FakeRedis(ping_ok=False))
    _patch_workers(monkeypatch, 1)
    resp = client.get("/queues/health")
    assert resp.status_code == 503
    assert resp.json()["redis_reachable"] is False


def test_returns_200_with_queue_depths_when_redis_and_workers_up(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_get_redis(
        monkeypatch,
        FakeRedis(depths={"celery": 5, "argus.scans": 12}),
    )
    _patch_workers(monkeypatch, 3)
    resp = client.get("/queues/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["redis_reachable"] is True
    assert body["worker_count"] == 3
    depths = {q["queue"]: q["depth"] for q in body["queues"]}
    assert depths["celery"] == 5
    assert depths["argus.scans"] == 12


def test_status_is_degraded_when_no_workers_active(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_get_redis(monkeypatch, FakeRedis())
    _patch_workers(monkeypatch, 0)
    resp = client.get("/queues/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["worker_count"] == 0


def test_llen_failure_returns_zero_depth_without_raising(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_get_redis(
        monkeypatch, FakeRedis(llen_should_raise=True)
    )
    _patch_workers(monkeypatch, 1)
    resp = client.get("/queues/health")
    assert resp.status_code == 200
    assert all(q["depth"] == 0 for q in resp.json()["queues"])


def test_response_contains_all_watched_queues(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_get_redis(monkeypatch, FakeRedis())
    _patch_workers(monkeypatch, 1)
    body = client.get("/queues/health").json()
    queues = [q["queue"] for q in body["queues"]]
    for required in queues_module.WATCHED_QUEUES:
        assert required in queues


def test_safe_llen_helper_returns_zero_on_garbage_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Wonky:
        def llen(self, _q: str) -> str:  # pragma: no cover — exercised via call
            return "not-a-number"

    val = queues_module._safe_llen(Wonky(), "celery")
    assert val == 0


def test_safe_llen_helper_clamps_negative_values() -> None:
    class Negative:
        def llen(self, _q: str) -> int:
            return -3

    val = queues_module._safe_llen(Negative(), "celery")
    assert val == 0
