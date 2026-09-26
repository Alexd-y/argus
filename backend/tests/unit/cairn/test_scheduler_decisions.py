"""Phase 8 — task-selection decisions (D-03/D-05/D-06) + conclude fallback (D-13)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from src.cairn.scheduler.decisions import (
    IntentSnapshot,
    ProjectDispatchState,
    ReasonCheckpoint,
    is_initial_project,
    reason_trigger,
    select_task_for_project,
)
from src.cairn.tasks import should_conclude_fallback

_NOW = datetime.now(UTC)


def _state(**over) -> ProjectDispatchState:
    base = {
        "status": "active",
        "fact_refs": ["origin", "goal"],
        "open_intents": [],
        "bootstrap_enabled": True,
        "reason_worker": None,
        "hint_count": 0,
        "running_task_count": 0,
        "max_project_workers": 4,
        "checkpoint": None,
        "fact_count": 2,
    }
    base.update(over)
    return ProjectDispatchState(**base)


def test_initial_project_detection() -> None:
    assert is_initial_project(_state()) is True
    assert is_initial_project(_state(fact_refs=["origin", "goal", "f001"])) is False


def test_initial_dispatches_bootstrap_when_supported() -> None:
    d = select_task_for_project(_state(), worker_supports_bootstrap=True)
    assert d.kind == "bootstrap"
    assert d.trigger == "initial"


def test_initial_dispatches_reason_without_bootstrap() -> None:
    d = select_task_for_project(_state(bootstrap_enabled=False), worker_supports_bootstrap=False)
    assert d.kind == "reason"
    assert d.trigger == "initial"


def test_max_project_workers_blocks() -> None:
    d = select_task_for_project(
        _state(running_task_count=4, max_project_workers=4), worker_supports_bootstrap=True
    )
    assert d.kind == "noop"


def test_non_active_blocks() -> None:
    d = select_task_for_project(_state(status="stopped"), worker_supports_bootstrap=True)
    assert d.kind == "noop"


def test_reason_trigger_on_facts_grew() -> None:
    state = _state(
        fact_refs=["origin", "goal", "f001"],
        fact_count=3,
        checkpoint=ReasonCheckpoint(fact_count=2, hint_count=0, open_intent_count=1),
        open_intents=[IntentSnapshot("i001", None, False, _NOW)],
    )
    assert reason_trigger(state) == "facts_grew"


def test_explore_picks_newest_unclaimed_intent() -> None:
    older = IntentSnapshot("i001", None, False, _NOW - timedelta(minutes=5))
    newer = IntentSnapshot("i002", None, False, _NOW)
    state = _state(
        fact_refs=["origin", "goal", "f001"],
        fact_count=3,
        open_intents=[older, newer],
        checkpoint=ReasonCheckpoint(fact_count=3, hint_count=0, open_intent_count=2),
    )
    d = select_task_for_project(state, worker_supports_bootstrap=True)
    assert d.kind == "explore"
    assert d.intent_ref == "i002"


def test_conclude_fallback_matrix() -> None:
    ok = {
        "driver_supports_conclude": True,
        "has_session": True,
        "heartbeat_lost": False,
        "cancelled": False,
        "project_active": True,
    }
    assert should_conclude_fallback(**ok) is True
    assert should_conclude_fallback(**{**ok, "driver_supports_conclude": False}) is False
    assert should_conclude_fallback(**{**ok, "has_session": False}) is False
    assert should_conclude_fallback(**{**ok, "heartbeat_lost": True}) is False
    assert should_conclude_fallback(**{**ok, "cancelled": True}) is False
    assert should_conclude_fallback(**{**ok, "project_active": False}) is False
