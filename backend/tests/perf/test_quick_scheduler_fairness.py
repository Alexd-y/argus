"""QUICK-009 — in-memory QuickScheduler fairness for 1/10/100 targets.

1000-target case is opt-in: ``ARGUS_PERF_SCALE=1 pytest -m perf_scale``.
No Docker, no live Redis/Postgres.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime

import pytest
from src.quick.budget import QuickBudgetManager
from src.quick.circuit_breaker import QuickCircuitBreaker
from src.quick.clock import FrozenClock
from src.quick.idempotency import QuickIdempotencyStore
from src.quick.profiles import DeploymentQuickClamps, load_quick_profiles
from src.quick.resolver import QuickProfileResolver
from src.quick.scheduler import QuickScheduler
from src.quick.schemas import QuickProfileName, QuickTask, QuickTaskStage
from src.quick.workflow import QuickWorkflow

pytestmark = [pytest.mark.perf, pytest.mark.no_auth_override]

_TENANT = "tenant-quick-009-perf-01"
_STARTED = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
_CATALOG = load_quick_profiles()


def _task(index: int, host: int) -> QuickTask:
    task_id = f"{index:08x}-0000-4000-8000-000000000000"
    return QuickTask(
        task_id=task_id,
        stage=QuickTaskStage.TEST,
        target_ref=f"https://h{host}.example/",
        tool_id="nuclei",
        capability_id="web.application.cve.known_product",
        estimated_seconds=5,
        estimated_requests=2,
        priority_score=0.5,
        idempotency_key=f"scan:nuclei:h{host}:{index}:none:1",
    )


def _scheduler(n_targets: int, *, per_host: int = 1) -> tuple[QuickScheduler, str]:
    clock = FrozenClock(_STARTED)
    manager = QuickBudgetManager(clock=clock, catalog=_CATALOG, clamps=DeploymentQuickClamps())
    config = QuickProfileResolver(catalog=_CATALOG, clamps=DeploymentQuickClamps()).resolve(
        _TENANT, QuickProfileName.BALANCED
    )
    scan_id = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
    manager.open_scan(
        tenant_id=_TENANT,
        scan_id=scan_id,
        config=config,
        started_at=_STARTED,
    )
    tasks = tuple(_task(idx, idx % n_targets) for idx in range(n_targets))
    scheduler = QuickScheduler(
        QuickWorkflow(tasks),
        budget_manager=manager,
        circuit_breaker=QuickCircuitBreaker(),
        idempotency=QuickIdempotencyStore(),
        clock=clock,
        per_host_running_limit=per_host,
    )
    return scheduler, scan_id


def _simulate(n_targets: int) -> dict[str, int]:
    scheduler, scan_id = _scheduler(n_targets)
    completed: set[str] = set()
    started_per_host: dict[str, int] = {}
    running_hosts: dict[str, int] = {}
    running_ids: set[str] = set()
    # Drain the queue: pick, immediately complete (fairness of start order).
    for _ in range(n_targets * 2):
        pick = scheduler.pick_next(
            scan_id=scan_id,
            completed_ids=completed,
            running_ids=running_ids,
            running_hosts=running_hosts,
        )
        if pick.task is None:
            break
        host = pick.task.target_ref
        started_per_host[host] = started_per_host.get(host, 0) + 1
        completed.add(pick.task.task_id)
    return started_per_host


@pytest.mark.parametrize("n_targets", [1, 10, 100])
def test_scheduler_fairness_no_starvation(n_targets: int) -> None:
    started = _simulate(n_targets)
    assert len(started) == n_targets
    counts = list(started.values())
    assert min(counts) >= 1
    assert max(counts) - min(counts) <= 1


@pytest.mark.perf_scale
@pytest.mark.skipif(
    os.environ.get("ARGUS_PERF_SCALE") != "1",
    reason="opt-in 1000-target fairness; set ARGUS_PERF_SCALE=1",
)
def test_scheduler_fairness_1000_targets() -> None:
    started = _simulate(1000)
    assert len(started) == 1000
    counts = list(started.values())
    assert min(counts) >= 1
    assert max(counts) - min(counts) <= 1
