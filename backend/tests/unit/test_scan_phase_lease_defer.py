"""Offline tests for §8.1 — pool contention defers the scan, never fails it.

``scan_phase_task`` must treat a :class:`LeaseContendedError` (distributed-pool
backpressure surfaced from a provider slot) as a bounded Celery retry, and — on
retry-budget exhaustion — return a ``deferred`` status without marking the scan
row failed. All infrastructure (engine/session/state-machine/notify) is mocked;
no Redis/Celery broker or Postgres is required.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from celery.exceptions import MaxRetriesExceededError, Retry
from src.orchestration.distributed_lease import LeaseContendedError
from src.tasks import scan_phase_task

_TENANT = "00000000-0000-0000-0000-000000000001"
_URL = "https://example.com"


def _session_mocks():
    """Build (engine, session_factory) mocks for a ``scan_phase_task`` run."""
    engine = MagicMock()
    engine.dispose = AsyncMock()
    session = MagicMock()
    session.execute = AsyncMock(return_value=MagicMock())
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=session)
    cm.__aexit__ = AsyncMock(return_value=None)
    factory = MagicMock(return_value=cm)
    return engine, factory


def test_lease_contended_reschedules_via_retry() -> None:
    engine, factory = _session_mocks()
    with (
        patch("src.tasks.create_task_engine_and_session", return_value=(engine, factory)),
        patch("src.tasks.run_scan_state_machine", new_callable=AsyncMock) as mock_sm,
        patch.object(scan_phase_task, "retry", side_effect=Retry()) as mock_retry,
    ):
        mock_sm.side_effect = LeaseContendedError("pool exhausted: provider:cloud")

        # A raised Retry means Celery reschedules the task — not a scan failure.
        with pytest.raises(Retry):
            scan_phase_task("scan-lease-1", _TENANT, _URL, {})
        mock_retry.assert_called_once()
        # Bounded backoff + deadline are passed to the retry.
        assert mock_retry.call_args.kwargs["countdown"] == 15
        assert mock_retry.call_args.kwargs["max_retries"] == 6


def test_lease_contended_exhaustion_returns_deferred_not_failed() -> None:
    engine, factory = _session_mocks()
    with (
        patch("src.tasks.create_task_engine_and_session", return_value=(engine, factory)),
        patch("src.tasks.run_scan_state_machine", new_callable=AsyncMock) as mock_sm,
        patch("src.tasks.notify_scan_finished", new_callable=AsyncMock) as mock_notify,
        patch.object(scan_phase_task, "retry", side_effect=MaxRetriesExceededError()),
    ):
        mock_sm.side_effect = LeaseContendedError("pool exhausted")

        result = scan_phase_task("scan-lease-2", _TENANT, _URL, {})

        # On retry-budget exhaustion the scan is deferred — never marked failed.
        assert result["status"] == "deferred"
        assert result["error"] == "pool_contended"
        mock_notify.assert_awaited_once()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
