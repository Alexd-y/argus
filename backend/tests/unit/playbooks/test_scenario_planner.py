"""Tests for the P4 :class:`ScenarioPlanner` (applicability + approval routing)."""

from __future__ import annotations

from collections.abc import Callable

from src.playbooks.planner import (
    EndpointContext,
    ScenarioPlanner,
    ScenarioPlanningContext,
)
from src.playbooks.lifecycle import ScenarioStatus
from src.playbooks.schema import ActionType, HttpMethod, InputKind, Playbook


def _planner(
    playbook_dict: Callable[..., dict[str, object]], **over: object
) -> ScenarioPlanner:
    return ScenarioPlanner([Playbook(**playbook_dict(**over))])


_ENDPOINT = EndpointContext(
    method=HttpMethod.GET,
    path="/api/v1/users/42",
    input_kinds=frozenset({InputKind.PATH_PARAM}),
)


def test_applicable_playbook_is_planned(
    playbook_dict: Callable[..., dict[str, object]],
) -> None:
    planner = _planner(playbook_dict)
    ctx = ScenarioPlanningContext(
        endpoints=[_ENDPOINT],
        available_principals=frozenset({"owner", "attacker"}),
        available_capabilities=frozenset({"http_client"}),
    )
    scenarios = planner.plan(ctx)
    assert len(scenarios) == 1
    assert scenarios[0].status is ScenarioStatus.PLANNED


def test_missing_principal_is_skipped_with_reason(
    playbook_dict: Callable[..., dict[str, object]],
) -> None:
    planner = _planner(playbook_dict)
    ctx = ScenarioPlanningContext(
        endpoints=[_ENDPOINT],
        available_principals=frozenset({"owner"}),  # missing attacker
        available_capabilities=frozenset({"http_client"}),
    )
    scenario = planner.plan(ctx)[0]
    assert scenario.status is ScenarioStatus.SKIPPED_NOT_APPLICABLE
    assert "principal" in (scenario.state.reason or "")


def test_missing_executor_is_skipped_with_reason(
    playbook_dict: Callable[..., dict[str, object]],
) -> None:
    planner = _planner(playbook_dict)
    ctx = ScenarioPlanningContext(
        endpoints=[_ENDPOINT],
        available_principals=frozenset({"owner", "attacker"}),
        available_capabilities=frozenset({"http_client"}),
        # No http_request executor available → the playbook cannot run.
        available_action_types=frozenset({ActionType.WAIT}),
    )
    scenario = planner.plan(ctx)[0]
    assert scenario.status is ScenarioStatus.SKIPPED_NOT_APPLICABLE
    assert "executor" in (scenario.state.reason or "")


def test_approval_gated_without_eap_is_waiting_approval(
    playbook_dict: Callable[..., dict[str, object]],
) -> None:
    planner = _planner(playbook_dict, risk_level="high", requires_approval=True)
    ctx = ScenarioPlanningContext(
        endpoints=[_ENDPOINT],
        available_principals=frozenset({"owner", "attacker"}),
        available_capabilities=frozenset({"http_client"}),
    )
    scenario = planner.plan(ctx)[0]
    assert scenario.status is ScenarioStatus.WAITING_APPROVAL
    assert scenario.state.reason is not None


def test_approval_gated_with_preauthorization_is_planned(
    playbook_dict: Callable[..., dict[str, object]],
) -> None:
    planner = _planner(playbook_dict, risk_level="high", requires_approval=True)
    ctx = ScenarioPlanningContext(
        endpoints=[_ENDPOINT],
        available_principals=frozenset({"owner", "attacker"}),
        available_capabilities=frozenset({"http_client"}),
        is_preauthorized=lambda _pb: True,
    )
    scenario = planner.plan(ctx)[0]
    assert scenario.status is ScenarioStatus.PLANNED


def test_manual_approval_on_file_is_planned(
    playbook_dict: Callable[..., dict[str, object]],
) -> None:
    planner = _planner(playbook_dict, risk_level="high", requires_approval=True)
    ctx = ScenarioPlanningContext(
        endpoints=[_ENDPOINT],
        available_principals=frozenset({"owner", "attacker"}),
        available_capabilities=frozenset({"http_client"}),
        has_manual_approval=lambda _pb: True,
    )
    scenario = planner.plan(ctx)[0]
    assert scenario.status is ScenarioStatus.PLANNED
