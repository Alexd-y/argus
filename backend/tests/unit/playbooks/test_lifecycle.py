"""Tests for the scenario lifecycle state machine."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.playbooks.lifecycle import (
    InvalidTransitionError,
    ScenarioState,
    ScenarioStatus,
    can_transition,
    validate_transition,
)


def test_valid_transition_chain() -> None:
    state = ScenarioState.initial()
    state = state.transition(ScenarioStatus.PLANNED)
    state = state.transition(ScenarioStatus.RUNNING)
    state = state.transition(ScenarioStatus.CONFIRMED)
    state = state.transition(ScenarioStatus.CLEANUP_COMPLETE)
    assert state.status is ScenarioStatus.CLEANUP_COMPLETE


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (ScenarioStatus.DISCOVERED, ScenarioStatus.CONFIRMED),
        (ScenarioStatus.PLANNED, ScenarioStatus.CONFIRMED),
        (ScenarioStatus.CONFIRMED, ScenarioStatus.RUNNING),
        (ScenarioStatus.SKIPPED_NOT_APPLICABLE, ScenarioStatus.PLANNED),
        (ScenarioStatus.CLEANUP_COMPLETE, ScenarioStatus.RUNNING),
    ],
)
def test_invalid_transitions(current: ScenarioStatus, target: ScenarioStatus) -> None:
    assert can_transition(current, target) is False
    with pytest.raises(InvalidTransitionError):
        validate_transition(current, target)


@pytest.mark.parametrize(
    "status",
    [
        ScenarioStatus.SKIPPED_NOT_APPLICABLE,
        ScenarioStatus.REJECTED,
        ScenarioStatus.CLEANUP_FAILED,
    ],
)
def test_reason_required_statuses(status: ScenarioStatus) -> None:
    with pytest.raises(ValidationError):
        ScenarioState(status=status)  # no reason
    with pytest.raises(ValidationError):
        ScenarioState(status=status, reason="   ")  # blank reason
    ok = ScenarioState(status=status, reason="documented cause")
    assert ok.reason == "documented cause"


def test_transition_carries_reason() -> None:
    state = ScenarioState.initial().transition(
        ScenarioStatus.SKIPPED_NOT_APPLICABLE, reason="method not allowed"
    )
    assert state.status is ScenarioStatus.SKIPPED_NOT_APPLICABLE
    assert state.reason == "method not allowed"


def test_transition_to_skip_without_reason_fails() -> None:
    state = ScenarioState.initial()
    with pytest.raises(ValidationError):
        state.transition(ScenarioStatus.SKIPPED_NOT_APPLICABLE)


def test_non_reason_status_allows_missing_reason() -> None:
    state = ScenarioState.initial().transition(ScenarioStatus.PLANNED)
    assert state.reason is None
