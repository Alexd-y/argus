"""Reproducible dispatcher harness (§15).

Drives the durable task store + budget ledger + lease with fake LLM/tool adapters
at increasing concurrency (1/5/10/20) and a worker-crash scenario. Asserts
dispatch CORRECTNESS — not real LLM/GPU throughput or readiness for 10k agents.

Checks: no lost tasks, no double-accepted results (fencing), shared budget
respected, queue drains, and errors never become empty successes.
"""

from __future__ import annotations

import asyncio

import pytest
from src.orchestration.agent_contracts import (
    AgentTaskSpec,
    AgentTaskState,
    AgentUsage,
)
from src.orchestration.agent_task_store import InMemoryAgentTaskStore
from src.orchestration.budget_ledger import (
    BudgetDeniedError,
    BudgetLedger,
    BudgetScope,
    InMemoryBudgetStore,
)


async def _run_dispatch(n_tasks: int, n_workers: int):
    store = InMemoryAgentTaskStore()
    ledger = BudgetLedger(InMemoryBudgetStore())
    # Generous scan budget so all succeed; per-task reserve is 100 tokens.
    await ledger._store.set_limits("scan:s1", max_tokens=n_tasks * 1000)

    for i in range(n_tasks):
        spec = AgentTaskSpec(
            tenant_id="t1", scan_id="s1", phase="vuln",
            agent_role="injection", idempotency_key=f"task-{i}",
        )
        await store.enqueue(spec)

    completed: list[str] = []
    completed_lock = asyncio.Lock()

    async def _worker(wid: str):
        while True:
            claimed = await store.claim(wid, ["vuln"], lease_seconds=60)
            if claimed is None:
                return
            scope = BudgetScope(scan_id=claimed.scan_id)
            async with ledger.budgeted(scope, tokens=100) as run:
                run.mark_started()
                # Fake LLM/tool work — deterministic, no network.
                await asyncio.sleep(0)
                run.record_usage(AgentUsage(input_tokens=40, output_tokens=40))
            ok = await store.complete(
                claimed.task_id, claimed.fencing_token, AgentTaskState.SUCCEEDED, "result-ref"
            )
            if ok:
                async with completed_lock:
                    completed.append(claimed.task_id)

    await asyncio.gather(*[_worker(f"w{i}") for i in range(n_workers)])

    # No lost tasks: every task reached SUCCEEDED.
    for i in range(n_tasks):
        row = await store.get(await _find_task(store, f"task-{i}"))
        assert row["state"] == AgentTaskState.SUCCEEDED.value
    # No double-accept: exactly n_tasks successful completions, all unique.
    assert len(completed) == n_tasks
    assert len(set(completed)) == n_tasks
    # Queue drained.
    assert await store.claim("drain", ["vuln"]) is None
    # Budget consistent: used == n_tasks * 80, nothing left reserved.
    snap = await ledger.snapshot("scan:s1")
    assert snap.used_tokens == n_tasks * 80
    assert snap.reserved_tokens == 0


async def _find_task(store: InMemoryAgentTaskStore, idem: str) -> str:
    for tid, row in store._rows.items():  # test-only introspection
        if row["idempotency_key"] == idem:
            return tid
    raise AssertionError(f"task {idem} not found")


@pytest.mark.parametrize("n_workers", [1, 5, 10, 20])
async def test_dispatch_scales_without_loss_or_double_accept(n_workers):
    await _run_dispatch(n_tasks=n_workers * 2, n_workers=n_workers)


async def test_worker_crash_mid_task_is_recovered():
    store = InMemoryAgentTaskStore()
    spec = AgentTaskSpec(
        tenant_id="t1", scan_id="s1", phase="vuln", agent_role="injection",
        idempotency_key="crashy",
    )
    tid = await store.enqueue(spec)

    # Worker A claims with an already-expired lease and then "crashes" (never
    # completes).
    crashed = await store.claim("A", ["vuln"], lease_seconds=0)
    assert crashed is not None
    # Reconciler reclaims the expired lease.
    assert await store.reclaim_expired() == 1
    # Worker B picks it up with a fresh fencing token and finishes.
    fresh = await store.claim("B", ["vuln"], lease_seconds=60)
    assert fresh.fencing_token > crashed.fencing_token
    assert await store.complete(tid, fresh.fencing_token, AgentTaskState.SUCCEEDED) is True
    # The crashed worker's late completion is rejected (no double-accept).
    assert await store.complete(tid, crashed.fencing_token, AgentTaskState.SUCCEEDED) is False


async def test_budget_denial_does_not_become_empty_success():
    store = InMemoryAgentTaskStore()
    ledger = BudgetLedger(InMemoryBudgetStore())
    await ledger._store.set_limits("scan:s1", max_tokens=50)  # too small for a 100-token reserve
    spec = AgentTaskSpec(
        tenant_id="t1", scan_id="s1", phase="vuln", agent_role="injection",
        idempotency_key="poor",
    )
    await store.enqueue(spec)
    c = await store.claim("w", ["vuln"])
    with pytest.raises(BudgetDeniedError):
        async with ledger.budgeted(BudgetScope(scan_id="s1"), tokens=100):
            pass
    # Budget denial -> task is failed, NOT silently completed as empty success.
    state = await store.retry_or_fail(c.task_id, c.fencing_token, retryable=False, error="budget")
    assert state == AgentTaskState.FAILED.value
    snap = await ledger.snapshot("scan:s1")
    assert snap.used_tokens == 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
