"""Offline logic tests for the durable agent-task store (§6)."""

from __future__ import annotations

import pytest
from src.orchestration.agent_contracts import AgentTaskSpec, AgentTaskState
from src.orchestration.agent_task_store import InMemoryAgentTaskStore


def _spec(role="injection", key="k1"):
    return AgentTaskSpec(
        tenant_id="t1", scan_id="s1", phase="vuln", agent_role=role, idempotency_key=key
    )


async def test_enqueue_is_idempotent():
    store = InMemoryAgentTaskStore()
    id1 = await store.enqueue(_spec(key="dup"))
    id2 = await store.enqueue(_spec(key="dup"))
    assert id1 == id2


async def test_claim_transitions_and_bumps_fencing():
    store = InMemoryAgentTaskStore()
    await store.enqueue(_spec())
    claimed = await store.claim("worker-A")
    assert claimed is not None
    assert claimed.fencing_token == 1
    assert claimed.attempts == 1
    row = await store.get(claimed.task_id)
    assert row["state"] == AgentTaskState.RUNNING.value
    # Nothing else claimable now.
    assert await store.claim("worker-B") is None


async def test_heartbeat_requires_owner_and_token():
    store = InMemoryAgentTaskStore()
    await store.enqueue(_spec())
    c = await store.claim("worker-A")
    assert await store.heartbeat(c.task_id, "worker-A", c.fencing_token) is True
    assert await store.heartbeat(c.task_id, "worker-B", c.fencing_token) is False
    assert await store.heartbeat(c.task_id, "worker-A", c.fencing_token + 5) is False


async def test_stale_worker_cannot_complete_over_newer_attempt():
    store = InMemoryAgentTaskStore()
    await store.enqueue(_spec())
    stale = await store.claim("worker-A", lease_seconds=0)  # token 1, lease already expired
    assert stale is not None
    reclaimed = await store.reclaim_expired()
    assert reclaimed == 1
    fresh = await store.claim("worker-B")  # token 2
    assert fresh.fencing_token == 2
    # The stale worker (token 1) must NOT be able to complete.
    assert await store.complete(stale.task_id, stale.fencing_token, AgentTaskState.SUCCEEDED) is False
    # The current owner can.
    assert await store.complete(fresh.task_id, fresh.fencing_token, AgentTaskState.SUCCEEDED) is True


async def test_retry_is_bounded_and_uses_outbox():
    store = InMemoryAgentTaskStore()
    await store.enqueue(_spec())
    # attempts=1..3 retryable, 4th -> failed (max_attempts=3).
    states = []
    for _ in range(4):
        c = await store.claim("w")
        if c is None:
            break
        states.append(await store.retry_or_fail(c.task_id, c.fencing_token, retryable=True, error="x"))
    assert states[-1] == AgentTaskState.FAILED.value
    assert states.count(AgentTaskState.RETRY_WAIT.value) == 2  # attempts 1,2 -> retry; 3 -> fail


async def test_outbox_reconciliation():
    store = InMemoryAgentTaskStore()
    tid = await store.enqueue(_spec())
    pending = await store.fetch_outbox()
    assert any(t == tid for _oid, t in pending)
    oid = pending[0][0]
    await store.mark_dispatched(oid)
    remaining = await store.fetch_outbox()
    assert all(o != oid for o, _t in remaining)


async def test_non_retryable_fails_immediately():
    store = InMemoryAgentTaskStore()
    await store.enqueue(_spec())
    c = await store.claim("w")
    assert await store.retry_or_fail(c.task_id, c.fencing_token, retryable=False, error="fatal") == (
        AgentTaskState.FAILED.value
    )


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
