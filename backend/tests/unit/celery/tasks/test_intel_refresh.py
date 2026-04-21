"""ARG-044 — unit tests for :mod:`src.celery.tasks.intel_refresh`.

Behaviours covered:

* Air-gap mode short-circuits without touching Redis / network.
* Distributed lock is acquired before the runner runs and released after.
* Lock loser exits with ``status="skipped"`` and does NOT execute the runner.
* If Redis is unreachable, the task proceeds without the lock (degraded
  but not blocked) and logs a warning.
* Successful EPSS / KEV refresh return the documented status payload.
* The runner exception path is converted to ``status="error"`` (never raises
  out of the task).

The test suite **monkey-patches** the async runners (``_run_epss_refresh`` /
``_run_kev_refresh``) so we can exercise the lock + airgap orchestration
without spinning up a real Postgres or HTTP client.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from src.celery.tasks import intel_refresh as intel


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeRedisLock:
    """Minimal Redis stand-in that supports ``set(nx=...)`` + ``eval``.

    Honours the ``nx`` semantics so the loser of a contended acquire gets
    ``None`` back, exactly matching the production redis-py contract.
    """

    def __init__(self) -> None:
        self.store: dict[str, str] = {}
        self.acquire_calls = 0
        self.release_calls = 0
        self.raise_on_set = False
        self.raise_on_eval = False

    def set(
        self,
        key: str,
        value: str,
        *,
        nx: bool = False,
        ex: int | None = None,
    ) -> bool | None:
        self.acquire_calls += 1
        if self.raise_on_set:
            raise RuntimeError("redis down")
        if nx and key in self.store:
            return None
        self.store[key] = value
        return True

    def eval(
        self,
        script: str,
        numkeys: int,
        key: str,
        token: str,
    ) -> int:
        self.release_calls += 1
        if self.raise_on_eval:
            raise RuntimeError("redis down")
        if self.store.get(key) == token:
            del self.store[key]
            return 1
        return 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@contextmanager
def _patch_settings_airgap(
    monkeypatch: pytest.MonkeyPatch,
    *,
    enabled: bool,
) -> Iterator[None]:
    """Force ``settings.intel_airgap_mode`` to a known value."""
    monkeypatch.setattr(intel.settings, "intel_airgap_mode", enabled, raising=False)
    yield


def _stub_runner(result: dict[str, Any]) -> Any:
    """Build an async function returning the supplied result dict."""

    async def _run() -> dict[str, Any]:
        return result

    return _run


def _failing_runner() -> Any:
    async def _run() -> dict[str, Any]:
        raise RuntimeError("kaboom")

    return _run


# ---------------------------------------------------------------------------
# Air-gap mode
# ---------------------------------------------------------------------------


def test_epss_task_airgap_returns_airgap_status(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRedisLock()
    monkeypatch.setattr(intel, "_safe_get_redis", lambda: fake)
    monkeypatch.setattr(intel, "_run_epss_refresh", _stub_runner({"status": "ok"}))
    with _patch_settings_airgap(monkeypatch, enabled=True):
        result = intel.epss_batch_refresh_task()
    assert result["status"] == "airgap"
    assert result["task"] == "epss_refresh"
    assert fake.acquire_calls == 0


def test_kev_task_airgap_returns_airgap_status(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRedisLock()
    monkeypatch.setattr(intel, "_safe_get_redis", lambda: fake)
    monkeypatch.setattr(intel, "_run_kev_refresh", _stub_runner({"status": "ok"}))
    with _patch_settings_airgap(monkeypatch, enabled=True):
        result = intel.kev_catalog_refresh_task()
    assert result["status"] == "airgap"
    assert result["task"] == "kev_refresh"
    assert fake.acquire_calls == 0


# ---------------------------------------------------------------------------
# Distributed lock
# ---------------------------------------------------------------------------


def test_epss_task_acquires_and_releases_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRedisLock()
    monkeypatch.setattr(intel, "_safe_get_redis", lambda: fake)
    monkeypatch.setattr(
        intel,
        "_run_epss_refresh",
        _stub_runner(
            {"status": "ok", "cves_requested": 1, "cves_returned": 1, "rows_written": 1}
        ),
    )
    with _patch_settings_airgap(monkeypatch, enabled=False):
        result = intel.epss_batch_refresh_task()
    assert result["status"] == "ok"
    assert result["rows_written"] == 1
    assert fake.acquire_calls == 1
    assert fake.release_calls == 1
    # Lock store should be empty after a successful release.
    assert intel._EPSS_LOCK_KEY not in fake.store


def test_kev_task_acquires_and_releases_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRedisLock()
    monkeypatch.setattr(intel, "_safe_get_redis", lambda: fake)
    monkeypatch.setattr(
        intel,
        "_run_kev_refresh",
        _stub_runner({"status": "ok", "rows_written": 5, "catalog_size": 5}),
    )
    with _patch_settings_airgap(monkeypatch, enabled=False):
        result = intel.kev_catalog_refresh_task()
    assert result["status"] == "ok"
    assert result["rows_written"] == 5
    assert fake.acquire_calls == 1
    assert fake.release_calls == 1
    assert intel._KEV_LOCK_KEY not in fake.store


def test_epss_task_skips_when_lock_already_held(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeRedisLock()
    fake.store[intel._EPSS_LOCK_KEY] = "another-pod"
    monkeypatch.setattr(intel, "_safe_get_redis", lambda: fake)
    runner_called = False

    async def _runner() -> dict[str, Any]:
        nonlocal runner_called
        runner_called = True
        return {"status": "ok"}

    monkeypatch.setattr(intel, "_run_epss_refresh", _runner)
    with _patch_settings_airgap(monkeypatch, enabled=False):
        result = intel.epss_batch_refresh_task()
    assert result["status"] == "skipped"
    assert result["reason"] == "lock_held"
    assert runner_called is False
    # The held lock must not be released by the loser.
    assert fake.store[intel._EPSS_LOCK_KEY] == "another-pod"


def test_kev_task_skips_when_lock_already_held(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeRedisLock()
    fake.store[intel._KEV_LOCK_KEY] = "another-pod"
    monkeypatch.setattr(intel, "_safe_get_redis", lambda: fake)
    runner_called = False

    async def _runner() -> dict[str, Any]:
        nonlocal runner_called
        runner_called = True
        return {"status": "ok"}

    monkeypatch.setattr(intel, "_run_kev_refresh", _runner)
    with _patch_settings_airgap(monkeypatch, enabled=False):
        result = intel.kev_catalog_refresh_task()
    assert result["status"] == "skipped"
    assert result["reason"] == "lock_held"
    assert runner_called is False


def test_redis_unavailable_proceeds_without_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If we cannot reach Redis we still run — degraded mode."""
    monkeypatch.setattr(intel, "_safe_get_redis", lambda: None)
    monkeypatch.setattr(intel, "_run_epss_refresh", _stub_runner({"status": "ok"}))
    with _patch_settings_airgap(monkeypatch, enabled=False):
        result = intel.epss_batch_refresh_task()
    assert result["status"] == "ok"


def test_runner_exception_is_converted_to_error_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeRedisLock()
    monkeypatch.setattr(intel, "_safe_get_redis", lambda: fake)
    monkeypatch.setattr(intel, "_run_epss_refresh", _failing_runner())
    with _patch_settings_airgap(monkeypatch, enabled=False):
        result = intel.epss_batch_refresh_task()
    assert result["status"] == "error"
    assert result["reason"] == "task_error"
    # Even on failure we must release the lock we acquired.
    assert fake.release_calls == 1
    assert intel._EPSS_LOCK_KEY not in fake.store


def test_release_does_not_delete_other_pod_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lock release must be a CAS — only the owner deletes."""
    fake = FakeRedisLock()
    fake.store[intel._EPSS_LOCK_KEY] = "other-token"
    monkeypatch.setattr(intel, "_safe_get_redis", lambda: fake)
    monkeypatch.setattr(intel, "_run_epss_refresh", _stub_runner({"status": "ok"}))
    with _patch_settings_airgap(monkeypatch, enabled=False):
        result = intel.epss_batch_refresh_task()
    # We never acquired (lock was already held), so we must not release.
    assert result["status"] == "skipped"
    assert fake.store[intel._EPSS_LOCK_KEY] == "other-token"


def test_idempotent_back_to_back_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeRedisLock()
    monkeypatch.setattr(intel, "_safe_get_redis", lambda: fake)
    monkeypatch.setattr(
        intel,
        "_run_epss_refresh",
        _stub_runner({"status": "ok", "rows_written": 7}),
    )
    with _patch_settings_airgap(monkeypatch, enabled=False):
        a = intel.epss_batch_refresh_task()
        b = intel.epss_batch_refresh_task()
    # Both calls succeed because each released its lock.
    assert a["status"] == b["status"] == "ok"
    assert a["rows_written"] == b["rows_written"]
    assert fake.acquire_calls == 2
    assert fake.release_calls == 2


# ---------------------------------------------------------------------------
# Result shape
# ---------------------------------------------------------------------------


def test_result_includes_duration_and_task(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeRedisLock()
    monkeypatch.setattr(intel, "_safe_get_redis", lambda: fake)

    async def slow_runner() -> dict[str, Any]:
        await asyncio.sleep(0.001)
        return {"status": "ok"}

    monkeypatch.setattr(intel, "_run_epss_refresh", slow_runner)
    with _patch_settings_airgap(monkeypatch, enabled=False):
        result = intel.epss_batch_refresh_task()
    assert result["status"] == "ok"
    assert result["task"] == "epss_refresh"
    assert "duration_ms" in result
    assert isinstance(result["duration_ms"], int)
    assert result["duration_ms"] >= 0


def test_redis_set_failure_does_not_propagate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeRedisLock()
    fake.raise_on_set = True
    monkeypatch.setattr(intel, "_safe_get_redis", lambda: fake)
    monkeypatch.setattr(intel, "_run_epss_refresh", _stub_runner({"status": "ok"}))
    with _patch_settings_airgap(monkeypatch, enabled=False):
        # set() raises → _try_acquire_lock returns False → since redis is not
        # None we treat as "lock held" and skip.
        result = intel.epss_batch_refresh_task()
    assert result["status"] == "skipped"
    assert result["reason"] == "lock_held"


def test_lock_release_failure_is_swallowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeRedisLock()
    fake.raise_on_eval = True
    monkeypatch.setattr(intel, "_safe_get_redis", lambda: fake)
    monkeypatch.setattr(intel, "_run_epss_refresh", _stub_runner({"status": "ok"}))
    with _patch_settings_airgap(monkeypatch, enabled=False):
        result = intel.epss_batch_refresh_task()
    # The task must still report success — lock release errors are best-effort.
    assert result["status"] == "ok"


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_safe_get_redis_returns_none_on_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _explode() -> Any:
        raise RuntimeError("no redis")

    monkeypatch.setattr(intel, "get_redis", _explode)
    assert intel._safe_get_redis() is None


def test_try_acquire_lock_returns_false_when_redis_none() -> None:
    assert intel._try_acquire_lock(None, "k", "tok") is False


def test_try_acquire_lock_returns_true_when_set_succeeds() -> None:
    fake = FakeRedisLock()
    assert intel._try_acquire_lock(fake, "k", "tok") is True
    assert fake.store["k"] == "tok"


def test_safe_release_lock_does_not_raise_on_redis_error() -> None:
    fake = FakeRedisLock()
    fake.raise_on_eval = True
    intel._safe_release_lock(fake, "k", "tok")  # must not raise
