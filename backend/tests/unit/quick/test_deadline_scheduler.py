"""QUICK-004 — deadline-aware QuickScheduler: stop discovery, keep report."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from src.quick.budget import QuickBudgetManager
from src.quick.circuit_breaker import QuickCircuitBreaker
from src.quick.clock import FrozenClock
from src.quick.idempotency import QuickIdempotencyStore
from src.quick.profiles import DeploymentQuickClamps, load_quick_profiles
from src.quick.resolver import QuickProfileResolver
from src.quick.scheduler import (
    QuickScheduler,
    ScheduleSkipReason,
    deadline_from_options,
    quick_deadline_reached,
    quick_should_stop_discovery,
    seconds_until_deadline,
)
from src.quick.schemas import QuickProfileName, QuickTask, QuickTaskStage
from src.quick.workflow import PROTECTED_STAGES, QuickWorkflow

_TENANT_ID = "tenant-quick-004-sched-01"
_SCAN_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
_STARTED = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
_CATALOG = load_quick_profiles()
_TARGET = "https://app.example/"


def _task(
    task_id: str,
    stage: QuickTaskStage,
    *,
    depends_on: tuple[str, ...] = (),
    tool_id: str = "nuclei",
    target_ref: str = _TARGET,
    priority_score: float = 0.5,
) -> QuickTask:
    return QuickTask(
        task_id=task_id,
        stage=stage,
        target_ref=target_ref,
        tool_id=tool_id,
        capability_id=f"cap.{stage.value}",
        estimated_seconds=10,
        estimated_requests=5,
        priority_score=priority_score,
        depends_on=depends_on,
        idempotency_key=f"{_SCAN_ID}:{tool_id}:{task_id}:none:1",
    )


_DISC = "10000000-0000-4000-8000-000000000001"
_FP = "10000000-0000-4000-8000-000000000002"
_VERIFY = "10000000-0000-4000-8000-000000000003"
_REPORT = "10000000-0000-4000-8000-000000000004"


def _workflow() -> QuickWorkflow:
    return QuickWorkflow(
        (
            _task(_DISC, QuickTaskStage.DISCOVERY),
            _task(_FP, QuickTaskStage.FINGERPRINT, depends_on=(_DISC,)),
            _task(_VERIFY, QuickTaskStage.VERIFY),
            _task(_REPORT, QuickTaskStage.REPORT, depends_on=(_VERIFY,)),
        )
    )


def _manager(clock: FrozenClock) -> QuickBudgetManager:
    return QuickBudgetManager(
        clock=clock,
        catalog=_CATALOG,
        clamps=DeploymentQuickClamps(),
    )


def _open(manager: QuickBudgetManager, scan_id: str = _SCAN_ID):
    config = QuickProfileResolver(catalog=_CATALOG, clamps=DeploymentQuickClamps()).resolve(
        _TENANT_ID, QuickProfileName.BALANCED
    )
    return manager.open_scan(
        tenant_id=_TENANT_ID,
        scan_id=scan_id,
        config=config,
        started_at=_STARTED,
    )


def _scheduler(
    clock: FrozenClock,
    manager: QuickBudgetManager,
    *,
    workflow: QuickWorkflow | None = None,
    breaker: QuickCircuitBreaker | None = None,
    idempotency: QuickIdempotencyStore | None = None,
    per_host_running_limit: int = 1,
) -> QuickScheduler:
    return QuickScheduler(
        workflow if workflow is not None else _workflow(),
        budget_manager=manager,
        circuit_breaker=breaker if breaker is not None else QuickCircuitBreaker(),
        idempotency=idempotency if idempotency is not None else QuickIdempotencyStore(),
        clock=clock,
        per_host_running_limit=per_host_running_limit,
    )


def test_seconds_until_deadline_uses_injected_clock_not_sleep() -> None:
    clock = FrozenClock(_STARTED)
    deadline = _STARTED + timedelta(seconds=90)
    assert seconds_until_deadline(deadline, clock) == 90.0
    clock.advance(90)
    assert seconds_until_deadline(deadline, clock) == 0.0
    clock.advance(10)
    assert seconds_until_deadline(deadline, clock) == 0.0
    assert seconds_until_deadline(None, clock) == float("inf")


def test_deadline_from_options_parses_datetime_and_isoformat() -> None:
    aware = _STARTED + timedelta(minutes=15)
    assert deadline_from_options({"deadline_at": aware}) == aware
    parsed = deadline_from_options({"deadline_at": aware.isoformat()})
    assert parsed == aware
    assert deadline_from_options({"deadline_at": "not-a-date"}) is None
    assert deadline_from_options(None) is None
    naive = datetime(2026, 8, 16, 12, 0)
    assert deadline_from_options({"deadline_at": naive}).tzinfo is not None


def test_quick_deadline_reached_via_options_when_budget_not_open() -> None:
    past = {"deadline_at": datetime(2020, 1, 1, tzinfo=UTC)}
    future = {"deadline_at": datetime(2099, 1, 1, tzinfo=UTC)}
    unknown = "00000000-0000-4000-8000-000000000099"
    assert quick_deadline_reached(unknown, past) is True
    assert quick_deadline_reached(unknown, future) is False
    assert quick_deadline_reached(unknown, {}) is False
    assert quick_should_stop_discovery(unknown, past) is True
    assert quick_should_stop_discovery(unknown, future) is False


def test_pick_next_starts_discovery_before_deadline() -> None:
    clock = FrozenClock(_STARTED)
    manager = _manager(clock)
    _open(manager)
    scheduler = _scheduler(clock, manager)
    pick = scheduler.pick_next(
        scan_id=_SCAN_ID,
        completed_ids=set(),
        running_ids=set(),
    )
    assert pick.task is not None
    assert pick.task.task_id == _DISC
    assert pick.skip_reason is None


def test_stop_discovery_skips_discovery_keeps_verify() -> None:
    clock = FrozenClock(_STARTED)
    manager = _manager(clock)
    snapshot = _open(manager)
    reserved = snapshot.budget.reserve_for_validation_percent
    wall = snapshot.budget.wall_clock_budget_seconds
    # Leave only the verification/report reserve on the wall clock.
    clock.advance(int(wall * (100 - reserved) / 100))
    assert manager.deadline_reached(_SCAN_ID) is False
    assert manager.should_stop_discovery(_SCAN_ID) is True

    scheduler = _scheduler(clock, manager)
    eligible = scheduler.eligible_tasks(
        scan_id=_SCAN_ID,
        completed_ids=set(),
    )
    assert [task.task_id for task in eligible] == [_VERIFY]

    pick = scheduler.pick_next(
        scan_id=_SCAN_ID,
        completed_ids=set(),
        running_ids=set(),
    )
    assert pick.task is not None
    assert pick.task.task_id == _VERIFY
    assert pick.task.stage.value in PROTECTED_STAGES
    assert _DISC in pick.skipped_task_ids
    assert pick.skip_reason is None


def test_hard_deadline_stops_discovery_keeps_report() -> None:
    clock = FrozenClock(_STARTED)
    manager = _manager(clock)
    snapshot = _open(manager)
    clock.advance(snapshot.budget.wall_clock_budget_seconds)
    assert manager.deadline_reached(_SCAN_ID) is True
    assert manager.should_stop_discovery(_SCAN_ID) is True

    scheduler = _scheduler(clock, manager)
    blocked_discovery = scheduler.pick_next(
        scan_id=_SCAN_ID,
        completed_ids=set(),
        running_ids=set(),
    )
    assert blocked_discovery.task is not None
    assert blocked_discovery.task.stage.value in PROTECTED_STAGES
    assert blocked_discovery.task.task_id == _VERIFY
    assert blocked_discovery.skip_reason is ScheduleSkipReason.DEADLINE_REACHED

    report_pick = scheduler.pick_next(
        scan_id=_SCAN_ID,
        completed_ids={_VERIFY},
        running_ids=set(),
    )
    assert report_pick.task is not None
    assert report_pick.task.task_id == _REPORT
    assert report_pick.task.stage is QuickTaskStage.REPORT
    assert report_pick.skip_reason is ScheduleSkipReason.DEADLINE_REACHED

    idle = scheduler.pick_next(
        scan_id=_SCAN_ID,
        completed_ids={_VERIFY, _REPORT},
        running_ids=set(),
    )
    assert idle.task is None
    assert idle.skip_reason is ScheduleSkipReason.DEADLINE_REACHED


def test_cancelled_pick_returns_no_task() -> None:
    clock = FrozenClock(_STARTED)
    manager = _manager(clock)
    _open(manager)
    scheduler = _scheduler(clock, manager)
    pick = scheduler.pick_next(
        scan_id=_SCAN_ID,
        completed_ids=set(),
        running_ids=set(),
        cancelled=True,
    )
    assert pick.task is None
    assert pick.skip_reason is ScheduleSkipReason.CANCELLED
    assert scheduler.eligible_tasks(
        scan_id=_SCAN_ID,
        completed_ids=set(),
        cancelled=True,
    ) == ()


def test_per_host_concurrency_skips_same_host_picks_other() -> None:
    clock = FrozenClock(_STARTED)
    manager = _manager(clock)
    _open(manager)
    other = "https://api.other.example/"
    extra = "10000000-0000-4000-8000-000000000005"
    workflow = QuickWorkflow(
        (
            _task(_DISC, QuickTaskStage.DISCOVERY, tool_id="httpx"),
            _task(extra, QuickTaskStage.DISCOVERY, tool_id="naabu", target_ref=other),
        )
    )
    scheduler = _scheduler(clock, manager, workflow=workflow, per_host_running_limit=1)
    pick = scheduler.pick_next(
        scan_id=_SCAN_ID,
        completed_ids=set(),
        running_ids=set(),
        running_hosts={"app.example": 1},
    )
    assert pick.task is not None
    assert pick.task.task_id == extra
    assert pick.task.target_ref == other


def test_no_ready_when_dependencies_unfinished() -> None:
    clock = FrozenClock(_STARTED)
    manager = _manager(clock)
    _open(manager)
    workflow = QuickWorkflow(
        (
            _task(_DISC, QuickTaskStage.DISCOVERY),
            _task(_FP, QuickTaskStage.FINGERPRINT, depends_on=(_DISC,)),
        )
    )
    scheduler = _scheduler(clock, manager, workflow=workflow)
    pick = scheduler.pick_next(
        scan_id=_SCAN_ID,
        completed_ids=set(),
        running_ids={_DISC},
    )
    assert pick.task is None
    assert pick.skip_reason is ScheduleSkipReason.NO_READY
