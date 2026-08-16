"""QUICK-004 — per-(tool, host) circuit breaker; open does not kill the scan."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from src.quick.budget import QuickBudgetManager, normalize_host_key
from src.quick.circuit_breaker import (
    CIRCUIT_OPEN_REASON,
    DEFAULT_FAILURE_THRESHOLD,
    QuickCircuitBreaker,
)
from src.quick.clock import FrozenClock
from src.quick.idempotency import QuickIdempotencyStore
from src.quick.profiles import DeploymentQuickClamps, load_quick_profiles
from src.quick.resolver import QuickProfileResolver
from src.quick.scheduler import QuickScheduler, ScheduleSkipReason
from src.quick.schemas import QuickProfileName, QuickTask, QuickTaskStage
from src.quick.workflow import QuickWorkflow

_SCAN_ID = "dddddddd-eeee-ffff-0000-111111111111"
_TENANT_ID = "tenant-quick-004-cb-01"
_STARTED = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
_CATALOG = load_quick_profiles()
_HOST_A = "https://app.example/login"
_HOST_B = "https://api.other.example/v1"
_TASK_NUCLEI = "10000000-0000-4000-8000-0000000000aa"
_TASK_HTTPX = "10000000-0000-4000-8000-0000000000bb"


def _task(task_id: str, tool_id: str, target_ref: str) -> QuickTask:
    return QuickTask(
        task_id=task_id,
        stage=QuickTaskStage.TEST,
        target_ref=target_ref,
        tool_id=tool_id,
        capability_id=f"cap.{tool_id}",
        estimated_seconds=10,
        estimated_requests=5,
        priority_score=0.5 if tool_id == "nuclei" else 0.1,
        idempotency_key=f"{_SCAN_ID}:{tool_id}:{task_id}:none:1",
    )


def test_failure_threshold_must_be_at_least_one() -> None:
    with pytest.raises(ValueError, match="failure_threshold"):
        QuickCircuitBreaker(failure_threshold=0)


def test_opens_after_consecutive_failures_and_resets_on_success() -> None:
    clock = FrozenClock(_STARTED)
    breaker = QuickCircuitBreaker(failure_threshold=3, clock=clock)
    host = normalize_host_key(_HOST_A)
    assert breaker.is_open("nuclei", _HOST_A) is False
    assert breaker.record_failure("nuclei", _HOST_A) is False
    assert breaker.record_failure("NUCLEI", "https://app.example/other") is False
    assert breaker.is_open("nuclei", host) is False
    tripped = breaker.record_failure("nuclei", _HOST_A)
    assert tripped is True
    assert breaker.is_open("nuclei", _HOST_A) is True
    snapshot = breaker.snapshot("nuclei", _HOST_A)
    assert snapshot is not None
    assert snapshot.opened is True
    assert snapshot.failure_count == 3
    assert snapshot.opened_at == _STARTED
    assert breaker.coverage_reason() == CIRCUIT_OPEN_REASON
    assert CIRCUIT_OPEN_REASON == "circuit_open"

    already = breaker.record_failure("nuclei", _HOST_A)
    assert already is False
    assert breaker.snapshot("nuclei", _HOST_A).failure_count == 4

    breaker.record_success("nuclei", _HOST_A)
    assert breaker.is_open("nuclei", _HOST_A) is False
    assert breaker.snapshot("nuclei", _HOST_A) is None


def test_open_is_scoped_to_tool_and_host() -> None:
    breaker = QuickCircuitBreaker(failure_threshold=1)
    breaker.record_failure("nuclei", _HOST_A)
    assert breaker.is_open("nuclei", _HOST_A) is True
    assert breaker.is_open("nuclei", _HOST_B) is False
    assert breaker.is_open("httpx", _HOST_A) is False


def test_default_threshold_is_three() -> None:
    assert DEFAULT_FAILURE_THRESHOLD == 3
    breaker = QuickCircuitBreaker()
    assert breaker.record_failure("nuclei", _HOST_A) is False
    assert breaker.record_failure("nuclei", _HOST_A) is False
    assert breaker.record_failure("nuclei", _HOST_A) is True


def test_open_circuit_skips_tool_but_does_not_kill_scan() -> None:
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
    breaker = QuickCircuitBreaker(failure_threshold=1)
    breaker.record_failure("nuclei", _HOST_A)
    scheduler = QuickScheduler(
        QuickWorkflow(
            (
                _task(_TASK_NUCLEI, "nuclei", _HOST_A),
                _task(_TASK_HTTPX, "httpx", _HOST_B),
            )
        ),
        budget_manager=manager,
        circuit_breaker=breaker,
        idempotency=QuickIdempotencyStore(),
        clock=clock,
    )
    pick = scheduler.pick_next(
        scan_id=_SCAN_ID,
        completed_ids=set(),
        running_ids=set(),
    )
    assert pick.task is not None
    assert pick.task.task_id == _TASK_HTTPX
    assert pick.task.tool_id == "httpx"
    assert _TASK_NUCLEI in pick.skipped_task_ids

    only_open = QuickScheduler(
        QuickWorkflow((_task(_TASK_NUCLEI, "nuclei", _HOST_A),)),
        budget_manager=manager,
        circuit_breaker=breaker,
        idempotency=QuickIdempotencyStore(),
        clock=clock,
    )
    skipped = only_open.pick_next(
        scan_id=_SCAN_ID,
        completed_ids=set(),
        running_ids=set(),
    )
    assert skipped.task is None
    assert skipped.skip_reason is ScheduleSkipReason.CIRCUIT_OPEN
    assert skipped.skip_reason.value == CIRCUIT_OPEN_REASON


def test_open_circuit_filters_va_plan_steps_without_raising() -> None:
    """Mirrors va_active_scan_phase: drop open-circuit tools, keep the scan."""
    breaker = QuickCircuitBreaker(failure_threshold=1)
    breaker.record_failure("nuclei", _HOST_A)
    plan = (
        ("nuclei", _HOST_A),
        ("httpx", _HOST_A),
        ("nuclei", _HOST_B),
    )
    remaining = tuple(
        step for step in plan if not breaker.is_open(step[0], step[1])
    )
    assert remaining == (("httpx", _HOST_A), ("nuclei", _HOST_B))
