"""QUICK-004 — idempotency keys: duplicate delivery must not start another run."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from src.quick.budget import QuickBudgetManager
from src.quick.circuit_breaker import QuickCircuitBreaker
from src.quick.clock import FrozenClock
from src.quick.idempotency import (
    IdempotencyClaim,
    QuickIdempotencyStore,
    build_idempotency_key,
)
from src.quick.profiles import DeploymentQuickClamps, load_quick_profiles
from src.quick.resolver import QuickProfileResolver
from src.quick.scheduler import QuickScheduler
from src.quick.schemas import QuickProfileName, QuickTask, QuickTaskStage
from src.quick.workflow import QuickWorkflow

_SCAN_ID = "cccccccc-dddd-eeee-ffff-000000000001"
_TENANT_ID = "tenant-quick-004-idem-01"
_STARTED = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
_CATALOG = load_quick_profiles()
_TARGET = "https://app.example/"
_TASK_A = "10000000-0000-4000-8000-00000000000a"
_TASK_B = "10000000-0000-4000-8000-00000000000b"


def test_build_idempotency_key_stable_and_hashes_when_over_256() -> None:
    key = build_idempotency_key(
        scan_id=_SCAN_ID,
        tool_id="nuclei",
        target_ref=_TARGET,
        template_digest=None,
        plan_version=1,
    )
    assert key == f"{_SCAN_ID}:nuclei:{_TARGET}:none:1"
    again = build_idempotency_key(
        scan_id=_SCAN_ID,
        tool_id="nuclei",
        target_ref=_TARGET,
        template_digest="  ",
        plan_version=1,
    )
    assert again == key

    digest = "b" * 64
    with_digest = build_idempotency_key(
        scan_id=_SCAN_ID,
        tool_id="nuclei",
        target_ref=_TARGET,
        template_digest=digest,
        plan_version=2,
    )
    assert with_digest == f"{_SCAN_ID}:nuclei:{_TARGET}:{digest}:2"

    long_target = "https://app.example/" + ("x" * 300)
    hashed = build_idempotency_key(
        scan_id=_SCAN_ID,
        tool_id="nuclei",
        target_ref=long_target,
        template_digest=digest,
        plan_version=1,
    )
    raw = f"{_SCAN_ID}:nuclei:{long_target}:{digest}:1"
    assert len(raw) > 256
    assert hashed == hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert len(hashed) == 64


def test_claim_acquired_then_duplicate_succeeded() -> None:
    store = QuickIdempotencyStore()
    key = build_idempotency_key(
        scan_id=_SCAN_ID,
        tool_id="nuclei",
        target_ref=_TARGET,
        template_digest=None,
        plan_version=1,
    )
    first = store.claim(
        key,
        scan_id=_SCAN_ID,
        tool_id="nuclei",
        plan_version=1,
        lease_remaining=True,
    )
    assert first is IdempotencyClaim.ACQUIRED
    assert store.get(key) is not None
    assert store.get(key).status == "running"

    in_flight = store.claim(
        key,
        scan_id=_SCAN_ID,
        tool_id="nuclei",
        plan_version=1,
        lease_remaining=True,
    )
    assert in_flight is IdempotencyClaim.IN_FLIGHT

    store.complete(key, succeeded=True)
    duplicate = store.claim(
        key,
        scan_id=_SCAN_ID,
        tool_id="nuclei",
        plan_version=1,
        lease_remaining=True,
    )
    assert duplicate is IdempotencyClaim.DUPLICATE_SUCCEEDED
    assert store.get(key).status == "succeeded"


def test_in_flight_without_lease_is_blocked() -> None:
    store = QuickIdempotencyStore()
    key = "scan:nuclei:blocked"
    store.claim(key, scan_id=_SCAN_ID, tool_id="nuclei", plan_version=1, lease_remaining=True)
    blocked = store.claim(
        key,
        scan_id=_SCAN_ID,
        tool_id="nuclei",
        plan_version=1,
        lease_remaining=False,
    )
    assert blocked is IdempotencyClaim.BLOCKED


def test_failed_and_lost_retry_only_while_lease_remains() -> None:
    store = QuickIdempotencyStore()
    failed_key = "scan:nuclei:failed"
    store.claim(failed_key, scan_id=_SCAN_ID, tool_id="nuclei", plan_version=1, lease_remaining=True)
    store.complete(failed_key, succeeded=False)
    retry = store.claim(
        failed_key,
        scan_id=_SCAN_ID,
        tool_id="nuclei",
        plan_version=1,
        lease_remaining=True,
    )
    assert retry is IdempotencyClaim.RETRY_ALLOWED
    assert store.get(failed_key).status == "running"

    store.complete(failed_key, succeeded=False)
    no_lease = store.claim(
        failed_key,
        scan_id=_SCAN_ID,
        tool_id="nuclei",
        plan_version=1,
        lease_remaining=False,
    )
    assert no_lease is IdempotencyClaim.BLOCKED

    lost_key = "scan:nuclei:lost"
    store.claim(lost_key, scan_id=_SCAN_ID, tool_id="nuclei", plan_version=1, lease_remaining=True)
    store.mark_lost(lost_key)
    assert store.get(lost_key).status == "lost"
    lost_retry = store.claim(
        lost_key,
        scan_id=_SCAN_ID,
        tool_id="nuclei",
        plan_version=1,
        lease_remaining=True,
    )
    assert lost_retry is IdempotencyClaim.RETRY_ALLOWED


def test_mark_lost_does_not_overwrite_succeeded() -> None:
    store = QuickIdempotencyStore()
    key = "scan:nuclei:done"
    store.claim(key, scan_id=_SCAN_ID, tool_id="nuclei", plan_version=1, lease_remaining=True)
    store.complete(key, succeeded=True)
    store.mark_lost(key)
    assert store.get(key).status == "succeeded"
    store.complete("missing-key", succeeded=True)
    assert store.get("missing-key") is None


def test_scheduler_skips_duplicate_idempotency_key() -> None:
    clock = FrozenClock(_STARTED)
    manager = QuickBudgetManager(
        clock=clock,
        catalog=_CATALOG,
        clamps=DeploymentQuickClamps(),
    )
    config = QuickProfileResolver(catalog=_CATALOG, clamps=DeploymentQuickClamps()).resolve(
        _TENANT_ID, QuickProfileName.COMPACT
    )
    manager.open_scan(
        tenant_id=_TENANT_ID,
        scan_id=_SCAN_ID,
        config=config,
        started_at=_STARTED,
    )
    shared_key = build_idempotency_key(
        scan_id=_SCAN_ID,
        tool_id="nuclei",
        target_ref=_TARGET,
        template_digest=None,
        plan_version=1,
    )
    store = QuickIdempotencyStore()
    task_a = QuickTask(
        task_id=_TASK_A,
        stage=QuickTaskStage.TEST,
        target_ref=_TARGET,
        tool_id="nuclei",
        capability_id="http.test",
        estimated_seconds=10,
        estimated_requests=5,
        priority_score=0.9,
        idempotency_key=shared_key,
    )
    task_b = QuickTask(
        task_id=_TASK_B,
        stage=QuickTaskStage.TEST,
        target_ref=_TARGET,
        tool_id="nuclei",
        capability_id="http.test.alt",
        estimated_seconds=10,
        estimated_requests=5,
        priority_score=0.1,
        idempotency_key=shared_key,
    )
    scheduler = QuickScheduler(
        QuickWorkflow((task_a, task_b)),
        budget_manager=manager,
        circuit_breaker=QuickCircuitBreaker(),
        idempotency=store,
        clock=clock,
    )
    first = scheduler.pick_next(
        scan_id=_SCAN_ID,
        completed_ids=set(),
        running_ids=set(),
    )
    assert first.task is not None
    assert first.task.task_id == _TASK_A
    store.complete(shared_key, succeeded=True)

    second = scheduler.pick_next(
        scan_id=_SCAN_ID,
        completed_ids=set(),
        running_ids={_TASK_A},
    )
    assert second.task is None
    assert _TASK_B in second.skipped_task_ids
    assert store.get(shared_key).status == "succeeded"


def test_eligible_tasks_does_not_claim_key() -> None:
    store = QuickIdempotencyStore()
    clock = FrozenClock(_STARTED)
    manager = QuickBudgetManager(
        clock=clock,
        catalog=_CATALOG,
        clamps=DeploymentQuickClamps(),
    )
    config = QuickProfileResolver(catalog=_CATALOG, clamps=DeploymentQuickClamps()).resolve(
        _TENANT_ID, QuickProfileName.COMPACT
    )
    manager.open_scan(
        tenant_id=_TENANT_ID,
        scan_id=_SCAN_ID,
        config=config,
        started_at=_STARTED,
    )
    key = "eligible-does-not-claim"
    task = QuickTask(
        task_id=_TASK_A,
        stage=QuickTaskStage.TEST,
        target_ref=_TARGET,
        tool_id="nuclei",
        capability_id="http.test",
        estimated_seconds=10,
        estimated_requests=5,
        priority_score=0.5,
        idempotency_key=key,
    )
    scheduler = QuickScheduler(
        QuickWorkflow((task,)),
        budget_manager=manager,
        circuit_breaker=QuickCircuitBreaker(),
        idempotency=store,
        clock=clock,
    )
    eligible = scheduler.eligible_tasks(scan_id=_SCAN_ID, completed_ids=set())
    assert [item.task_id for item in eligible] == [_TASK_A]
    assert store.get(key) is None
