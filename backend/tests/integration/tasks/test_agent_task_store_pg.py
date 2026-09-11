"""Real-Postgres tests for the durable agent-task store (§6).

Marked ``requires_postgres``. Two independent engines model two workers; atomic
claim uses ``FOR UPDATE SKIP LOCKED``.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from src.orchestration.agent_contracts import AgentTaskSpec, AgentTaskState
from src.orchestration.agent_task_store import (
    PostgresAgentTaskStore,
    create_task_tables,
)

pytestmark = pytest.mark.requires_postgres

_DSN = os.environ.get("ARGUS_TEST_PG_DSN")


def _engine():
    return create_async_engine(_DSN, pool_pre_ping=True)


@pytest.fixture(scope="module", autouse=True)
def _require_dsn():
    if not _DSN:
        pytest.skip("ARGUS_TEST_PG_DSN not set")


def _spec(scan, role="injection", phase="vuln"):
    return AgentTaskSpec(
        tenant_id="t1", scan_id=scan, phase=phase, agent_role=role,
        idempotency_key=uuid.uuid4().hex,
    )


async def test_two_workers_claim_distinct_tasks():
    scan = f"scan-{uuid.uuid4().hex[:8]}"
    phase = f"ph-{uuid.uuid4().hex[:8]}"
    e1, e2 = _engine(), _engine()
    try:
        await create_task_tables(e1)
        s1 = PostgresAgentTaskStore(async_sessionmaker(e1, expire_on_commit=False))
        s2 = PostgresAgentTaskStore(async_sessionmaker(e2, expire_on_commit=False))
        await s1.enqueue(_spec(scan, "injection", phase))
        await s1.enqueue(_spec(scan, "xss", phase))
        # Two workers claim concurrently — must get two DIFFERENT tasks.
        c1, c2 = await asyncio.gather(s1.claim("w1", [phase]), s2.claim("w2", [phase]))
        assert c1 is not None and c2 is not None
        assert c1.task_id != c2.task_id
    finally:
        await e1.dispose()
        await e2.dispose()


async def test_stale_worker_complete_rejected_by_fencing():
    scan = f"scan-{uuid.uuid4().hex[:8]}"
    phase = f"ph-{uuid.uuid4().hex[:8]}"
    e1 = _engine()
    try:
        await create_task_tables(e1)
        store = PostgresAgentTaskStore(async_sessionmaker(e1, expire_on_commit=False))
        tid = await store.enqueue(_spec(scan, phase=phase))
        stale = await store.claim("w-stale", [phase])
        # Simulate lost worker: mark retryable so the task becomes claimable again.
        await store.retry_or_fail(stale.task_id, stale.fencing_token, retryable=True, error="lost")
        fresh = await store.claim("w-fresh", [phase])
        assert fresh.task_id == tid
        assert fresh.fencing_token > stale.fencing_token
        # Stale token cannot complete.
        assert await store.complete(tid, stale.fencing_token, AgentTaskState.SUCCEEDED) is False
        assert await store.complete(tid, fresh.fencing_token, AgentTaskState.SUCCEEDED) is True
    finally:
        await e1.dispose()


async def test_reclaim_expired_lease():
    scan = f"scan-{uuid.uuid4().hex[:8]}"
    phase = f"ph-{uuid.uuid4().hex[:8]}"
    e1 = _engine()
    try:
        await create_task_tables(e1)
        store = PostgresAgentTaskStore(async_sessionmaker(e1, expire_on_commit=False))
        await store.enqueue(_spec(scan, phase=phase))
        c = await store.claim("w1", [phase], lease_seconds=0)  # already-expired lease
        assert c is not None
        reclaimed = await store.reclaim_expired()
        assert reclaimed >= 1
        row = await store.get(c.task_id)
        assert row["state"] == AgentTaskState.RETRY_WAIT.value
    finally:
        await e1.dispose()


async def test_outbox_written_with_task():
    scan = f"scan-{uuid.uuid4().hex[:8]}"
    e1 = _engine()
    try:
        await create_task_tables(e1)
        store = PostgresAgentTaskStore(async_sessionmaker(e1, expire_on_commit=False))
        tid = await store.enqueue(_spec(scan))
        pending = await store.fetch_outbox()
        assert any(t == tid for _oid, t in pending)
        oid = next(o for o, t in pending if t == tid)
        await store.mark_dispatched(oid)
        assert all(o != oid for o, _t in await store.fetch_outbox())
    finally:
        await e1.dispose()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v", "-m", "requires_postgres"]))
