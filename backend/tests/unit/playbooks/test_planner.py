"""Tests for the applicability planner (P2 skeleton)."""

from __future__ import annotations

from collections.abc import Callable

from src.playbooks.planner import ApplicabilityContext, PlaybookPlanner
from src.playbooks.schema import HttpMethod, InputKind, Playbook


def _planner(playbook_dict: Callable[..., dict[str, object]]) -> PlaybookPlanner:
    return PlaybookPlanner([Playbook(**playbook_dict())])


def test_applicable_context_is_planned(
    playbook_dict: Callable[..., dict[str, object]],
) -> None:
    planner = _planner(playbook_dict)
    ctx = ApplicabilityContext(
        method=HttpMethod.GET,
        path="/api/v1/users/42",
        input_kinds=frozenset({InputKind.PATH_PARAM}),
        available_principals=frozenset({"owner", "attacker"}),
        available_capabilities=frozenset({"http_client"}),
    )
    scenarios = planner.select(ctx)
    assert len(scenarios) == 1
    assert scenarios[0].is_planned
    assert scenarios[0].state.reason is None


def test_method_mismatch_is_skipped_with_reason(
    playbook_dict: Callable[..., dict[str, object]],
) -> None:
    planner = _planner(playbook_dict)
    ctx = ApplicabilityContext(
        method=HttpMethod.POST,
        path="/api/v1/users/42",
        input_kinds=frozenset({InputKind.PATH_PARAM}),
        available_principals=frozenset({"owner", "attacker"}),
        available_capabilities=frozenset({"http_client"}),
    )
    scenario = planner.select(ctx)[0]
    assert not scenario.is_planned
    assert scenario.state.reason is not None
    assert "method" in scenario.state.reason


def test_path_mismatch_is_skipped(
    playbook_dict: Callable[..., dict[str, object]],
) -> None:
    planner = _planner(playbook_dict)
    ctx = ApplicabilityContext(
        method=HttpMethod.GET,
        path="/public/health",
        input_kinds=frozenset({InputKind.PATH_PARAM}),
        available_principals=frozenset({"owner", "attacker"}),
        available_capabilities=frozenset({"http_client"}),
    )
    scenario = planner.select(ctx)[0]
    assert not scenario.is_planned
    assert "path" in (scenario.state.reason or "")


def test_missing_principal_is_skipped(
    playbook_dict: Callable[..., dict[str, object]],
) -> None:
    planner = _planner(playbook_dict)
    ctx = ApplicabilityContext(
        method=HttpMethod.GET,
        path="/api/v1/users/42",
        input_kinds=frozenset({InputKind.PATH_PARAM}),
        available_principals=frozenset({"owner"}),  # missing attacker
        available_capabilities=frozenset({"http_client"}),
    )
    scenario = planner.select(ctx)[0]
    assert not scenario.is_planned
    assert "principal" in (scenario.state.reason or "")


def test_planned_only_filters(
    playbook_dict: Callable[..., dict[str, object]],
) -> None:
    planner = _planner(playbook_dict)
    ctx = ApplicabilityContext(
        method=HttpMethod.DELETE,
        path="/api/v1/users/42",
        available_principals=frozenset({"owner", "attacker"}),
        available_capabilities=frozenset({"http_client"}),
    )
    assert planner.planned_only(ctx) == []
