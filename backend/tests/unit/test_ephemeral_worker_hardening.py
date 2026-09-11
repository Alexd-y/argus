"""Regression tests for EphemeralWorkerPool isolation honesty (3.5).

Offline: the dev host has no Docker daemon, so the real path must fail loudly
instead of returning a pseudo container-ID that looks like success.
"""

from __future__ import annotations

import pytest
from src.orchestration.ephemeral_worker import (
    EphemeralWorkerError,
    EphemeralWorkerPool,
)


async def test_real_mode_raises_when_docker_unavailable():
    pool = EphemeralWorkerPool(max_containers=2)  # real mode (default)
    with pytest.raises(EphemeralWorkerError):
        await pool.acquire("task-abc")
    # No pseudo container registered — nothing looks isolated.
    assert pool.active_count == 0


async def test_mock_mode_returns_pseudo_id_explicitly():
    pool = EphemeralWorkerPool(max_containers=2, mock_mode=True)
    cid = await pool.acquire("task-xyz")
    assert cid.startswith("argus-task-")
    assert pool.active_count == 1
    await pool.release(cid)
    assert pool.active_count == 0


def test_single_active_assignment_invariant():
    """Guards against the double-registration bug reappearing in acquire."""
    import inspect

    src = inspect.getsource(EphemeralWorkerPool.acquire)
    assert src.count("self._active[container_id] = time.monotonic()") == 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
