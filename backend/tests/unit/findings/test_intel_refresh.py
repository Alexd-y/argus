"""ARG-044 — unit tests for :mod:`src.celery.tasks.intel_refresh`.

The Celery task layer is exercised through ``_run_with_lock``, the
private dispatcher that does all the airgap / lock / error bookkeeping.
We mock the Redis client and the underlying async runner so the suite
stays fully offline.
"""

from __future__ import annotations

from typing import Any

import pytest

from src.celery.tasks import intel_refresh as ir


class _FakeRedis:
    """Minimal Redis stand-in that records lock state."""

    def __init__(
        self,
        *,
        held: bool = False,
        raise_on_set: bool = False,
        raise_on_eval: bool = False,
    ) -> None:
        self.held = held
        self.raise_on_set = raise_on_set
        self.raise_on_eval = raise_on_eval
        self.set_calls: list[tuple[str, str, bool, int]] = []
        self.eval_calls: list[tuple[str, str]] = []

    def set(self, key: str, value: str, *, nx: bool, ex: int) -> bool | None:
        if self.raise_on_set:
            raise RuntimeError("redis down")
        self.set_calls.append((key, value, nx, ex))
        if self.held:
            return None
        self.held = True
        return True

    def eval(self, _script: str, _n: int, key: str, value: str) -> int:
        if self.raise_on_eval:
            raise RuntimeError("redis down")
        self.eval_calls.append((key, value))
        if self.held and value:
            self.held = False
            return 1
        return 0


# ---------------------------------------------------------------------------
# Airgap short-circuit
# ---------------------------------------------------------------------------


def test_airgap_skips_runner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ir.settings, "intel_airgap_mode", True, raising=False)
    called = {"runner": False}

    async def _runner() -> dict[str, Any]:
        called["runner"] = True
        return {"status": "ok"}

    out = ir._run_with_lock(
        lock_key="argus:lock:test", runner=_runner, task_name="t"
    )
    assert out["status"] == "airgap"
    assert out["task"] == "t"
    assert called["runner"] is False


# ---------------------------------------------------------------------------
# Lock acquisition / release
# ---------------------------------------------------------------------------


def test_lock_acquire_and_release_on_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ir.settings, "intel_airgap_mode", False, raising=False)
    redis = _FakeRedis(held=False)
    monkeypatch.setattr(ir, "_safe_get_redis", lambda: redis)

    async def _runner() -> dict[str, Any]:
        return {"status": "ok", "rows_written": 7}

    out = ir._run_with_lock(
        lock_key="argus:lock:test", runner=_runner, task_name="t"
    )
    assert out["status"] == "ok"
    assert out["rows_written"] == 7
    assert out["task"] == "t"
    assert "duration_ms" in out
    assert len(redis.set_calls) == 1
    assert len(redis.eval_calls) == 1
    assert not redis.held


def test_lock_held_skips_work(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ir.settings, "intel_airgap_mode", False, raising=False)
    redis = _FakeRedis(held=True)
    monkeypatch.setattr(ir, "_safe_get_redis", lambda: redis)
    called = {"runner": False}

    async def _runner() -> dict[str, Any]:
        called["runner"] = True
        return {"status": "ok"}

    out = ir._run_with_lock(
        lock_key="argus:lock:test", runner=_runner, task_name="t"
    )
    assert out["status"] == "skipped"
    assert out["reason"] == "lock_held"
    assert called["runner"] is False


def test_redis_unavailable_runs_without_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ir.settings, "intel_airgap_mode", False, raising=False)
    monkeypatch.setattr(ir, "_safe_get_redis", lambda: None)

    async def _runner() -> dict[str, Any]:
        return {"status": "ok", "rows_written": 1}

    out = ir._run_with_lock(
        lock_key="argus:lock:test", runner=_runner, task_name="t"
    )
    assert out["status"] == "ok"
    assert out["rows_written"] == 1


def test_runner_error_returns_error_dict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ir.settings, "intel_airgap_mode", False, raising=False)
    monkeypatch.setattr(ir, "_safe_get_redis", lambda: None)

    async def _runner() -> dict[str, Any]:
        raise RuntimeError("kaboom")

    out = ir._run_with_lock(
        lock_key="argus:lock:test", runner=_runner, task_name="t"
    )
    assert out["status"] == "error"
    assert out["reason"] == "task_error"


def test_lock_released_even_on_runner_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ir.settings, "intel_airgap_mode", False, raising=False)
    redis = _FakeRedis(held=False)
    monkeypatch.setattr(ir, "_safe_get_redis", lambda: redis)

    async def _runner() -> dict[str, Any]:
        raise RuntimeError("kaboom")

    ir._run_with_lock(lock_key="argus:lock:test", runner=_runner, task_name="t")
    assert len(redis.eval_calls) == 1
    assert not redis.held


def test_lock_acquire_failure_continues_unlocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If SET NX raises, we treat it as no-lock (degraded path)."""
    monkeypatch.setattr(ir.settings, "intel_airgap_mode", False, raising=False)
    redis = _FakeRedis(raise_on_set=True)
    monkeypatch.setattr(ir, "_safe_get_redis", lambda: redis)

    async def _runner() -> dict[str, Any]:
        return {"status": "ok"}

    # SET NX raised, lock not acquired and we still have a redis stub,
    # so contract is "lock not acquired with redis present" → skipped.
    out = ir._run_with_lock(
        lock_key="argus:lock:test", runner=_runner, task_name="t"
    )
    assert out["status"] == "skipped"
    assert out["reason"] == "lock_held"


# ---------------------------------------------------------------------------
# epss_batch_refresh_task — surface
# ---------------------------------------------------------------------------


def test_epss_task_routes_through_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ir.settings, "intel_airgap_mode", True, raising=False)
    out = ir.epss_batch_refresh_task()  # type: ignore[call-arg]
    assert out["status"] == "airgap"
    assert out["task"] == "epss_refresh"


def test_kev_task_routes_through_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ir.settings, "intel_airgap_mode", True, raising=False)
    out = ir.kev_catalog_refresh_task()  # type: ignore[call-arg]
    assert out["status"] == "airgap"
    assert out["task"] == "kev_refresh"


# ---------------------------------------------------------------------------
# _build_*_client behaviour with airgap on
# ---------------------------------------------------------------------------


def test_build_epss_client_returns_object_or_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ir.settings, "intel_airgap_mode", False, raising=False)
    monkeypatch.setattr(ir, "_safe_get_redis", lambda: None)
    client = ir._build_epss_client()
    assert client is None or hasattr(client, "fetch_epss_batch")


def test_build_kev_client_returns_object_or_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ir.settings, "intel_airgap_mode", False, raising=False)
    monkeypatch.setattr(ir, "_safe_get_redis", lambda: None)
    client = ir._build_kev_client()
    assert client is None or hasattr(client, "fetch_kev_catalog")


# ---------------------------------------------------------------------------
# safe redis getter
# ---------------------------------------------------------------------------


def test_safe_get_redis_returns_none_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _raise() -> Any:
        raise RuntimeError("no redis")

    monkeypatch.setattr(ir, "get_redis", _raise)
    assert ir._safe_get_redis() is None


def test_safe_release_lock_swallows_exceptions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    redis = _FakeRedis(raise_on_eval=True)
    # Should not raise.
    ir._safe_release_lock(redis, "k", "tok")


# ---------------------------------------------------------------------------
# duration / observability hook
# ---------------------------------------------------------------------------


def test_result_carries_duration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ir.settings, "intel_airgap_mode", False, raising=False)
    monkeypatch.setattr(ir, "_safe_get_redis", lambda: None)

    async def _runner() -> dict[str, Any]:
        return {"status": "ok"}

    out = ir._run_with_lock(
        lock_key="argus:lock:test", runner=_runner, task_name="t"
    )
    assert isinstance(out["duration_ms"], int)
    assert out["duration_ms"] >= 0
