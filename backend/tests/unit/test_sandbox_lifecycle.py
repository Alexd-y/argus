"""Offline lifecycle tests for the sandbox wrapper (§10).

Uses a mock adapter to verify cleanup on every path and owner-scoped orphan
cleanup. Real Docker behaviour is covered separately under requires_docker.
"""

from __future__ import annotations

import asyncio

import pytest
from src.orchestration.sandbox_lifecycle import (
    ExecResult,
    SandboxStatus,
    cleanup_orphans,
    run_in_sandbox,
)


class MockSandboxAdapter:
    def __init__(self, *, create_error=False, exec_behavior="ok", owned=None):
        self.create_error = create_error
        self.exec_behavior = exec_behavior
        self.created: list[str] = []
        self.destroyed: list[str] = []
        self.artifacts_collected: list[str] = []
        self._owned = owned or []

    async def create(self, task_id, _owner_labels):
        if self.create_error:
            raise RuntimeError("docker unavailable")
        cid = f"c-{task_id}"
        self.created.append(cid)
        return cid

    async def exec(self, _container_id, _argv):
        if self.exec_behavior == "raise":
            raise RuntimeError("exec boom")
        if self.exec_behavior == "hang":
            await asyncio.sleep(10)
        if self.exec_behavior == "nonzero":
            return ExecResult(exit_code=2, stderr="fail")
        return ExecResult(exit_code=0, stdout="done")

    async def collect_artifacts(self, container_id, prefix):
        self.artifacts_collected.append(container_id)
        return [f"{prefix}/out.json"]

    async def destroy(self, container_id):
        self.destroyed.append(container_id)

    async def list_owned(self, _owner_labels):
        return list(self._owned)


_LABELS = {"owner": "argus", "task": "t1"}


async def test_success_path_collects_artifacts_and_cleans_up():
    a = MockSandboxAdapter()
    res = await run_in_sandbox(a, "t1", ["nmap"], owner_labels=_LABELS)
    assert res.status == SandboxStatus.SUCCEEDED
    assert res.exit_code == 0
    assert res.artifacts == ["t1/out.json"]
    assert a.destroyed == ["c-t1"]  # cleaned up


async def test_nonzero_exit_is_failed_not_success():
    a = MockSandboxAdapter(exec_behavior="nonzero")
    res = await run_in_sandbox(a, "t1", ["x"], owner_labels=_LABELS)
    assert res.status == SandboxStatus.FAILED
    assert res.is_success is False
    assert a.destroyed == ["c-t1"]


async def test_exec_exception_still_cleans_up():
    a = MockSandboxAdapter(exec_behavior="raise")
    res = await run_in_sandbox(a, "t1", ["x"], owner_labels=_LABELS)
    assert res.status == SandboxStatus.FAILED
    assert "boom" in res.error
    assert a.destroyed == ["c-t1"]


async def test_timeout_cleans_up():
    a = MockSandboxAdapter(exec_behavior="hang")
    res = await run_in_sandbox(a, "t1", ["x"], owner_labels=_LABELS, timeout_seconds=0.05)
    assert res.status == SandboxStatus.TIMEOUT
    assert a.destroyed == ["c-t1"]


async def test_create_failure_no_pseudo_success_no_destroy():
    a = MockSandboxAdapter(create_error=True)
    res = await run_in_sandbox(a, "t1", ["x"], owner_labels=_LABELS)
    assert res.status == SandboxStatus.CREATE_FAILED
    assert res.is_success is False
    assert res.container_id == ""
    # Nothing was created, so nothing to destroy (no pseudo container).
    assert a.destroyed == []


async def test_cancellation_cleans_up_and_propagates():
    a = MockSandboxAdapter(exec_behavior="hang")

    async def _run():
        return await run_in_sandbox(a, "t1", ["x"], owner_labels=_LABELS, timeout_seconds=10)

    task = asyncio.create_task(_run())
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert a.destroyed == ["c-t1"]  # cleaned up on cancellation


async def test_orphan_cleanup_only_touches_owned_and_old():
    # (container_id, age_seconds) — list_owned already filters to OUR labels.
    a = MockSandboxAdapter(owned=[("old-1", 700.0), ("young-1", 30.0)])
    removed = await cleanup_orphans(a, _LABELS, max_age_seconds=600.0)
    assert removed == 1
    assert a.destroyed == ["old-1"]  # young one left alone


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
