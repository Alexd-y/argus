"""Coverage status honesty tests."""

from __future__ import annotations

import pytest

from src.capabilities.coverage import (
    CoverageAccountingError,
    absence_of_finding_is_not_coverage,
    build_coverage_result,
    can_transition_coverage,
    infer_status_from_execution,
    resolve_coverage_status,
)
from src.capabilities.graph import default_capability_graph
from src.capabilities.schemas import CoverageRequirement, CoverageStatus


def test_seed_graph_has_minimum_nodes_and_families():
    graph = default_capability_graph()
    assert len(graph.nodes) >= 15
    families = {str(node.family) for node in graph.nodes}
    assert "web.application" in families
    assert "windows.server" in families
    assert "linux.system" in families
    assert "network.attack_paths" in families
    assert "reverse_engineering" in families
    assert "privilege_escalation.linux" in families
    assert "privilege_escalation.windows" in families
    assert any(node.training_only for node in graph.training_nodes())


def test_not_tested_never_becomes_covered_without_evidence():
    assert (
        can_transition_coverage(
            CoverageStatus.NOT_TESTED,
            CoverageStatus.COVERED_NO_FINDING,
            has_execution_evidence=False,
            has_finding=False,
        )
        is False
    )
    with pytest.raises(CoverageAccountingError):
        resolve_coverage_status(
            current=CoverageStatus.NOT_TESTED,
            proposed=CoverageStatus.COVERED_NO_FINDING,
            execution_evidence_id=None,
            tool_executed=False,
        )


def test_covered_no_finding_requires_execution_evidence():
    status = resolve_coverage_status(
        current=CoverageStatus.RUNNING,
        proposed=CoverageStatus.COVERED_NO_FINDING,
        execution_evidence_id="ev-1",
        tool_executed=True,
    )
    assert status is CoverageStatus.COVERED_NO_FINDING


def test_absence_of_finding_is_not_automatic_coverage():
    assert (
        absence_of_finding_is_not_coverage(
            prior_status=CoverageStatus.PLANNED,
            finding_present=False,
            execution_evidence_id=None,
        )
        is CoverageStatus.PLANNED
    )
    req = CoverageRequirement(
        id="r1",
        tenant_id="t1",
        scan_id="s1",
        asset_id="a1",
        capability_id="web.application.xss",
    )
    with pytest.raises(CoverageAccountingError):
        build_coverage_result(
            req,
            status=CoverageStatus.COVERED_NO_FINDING,
            execution_evidence_id=None,
            tool_executed=False,
        )


def test_infer_status_from_execution_honest_blocked_states():
    assert (
        infer_status_from_execution(
            tool_executed=False, tool_error=False, target_unreachable=False
        )
        is CoverageStatus.NOT_TESTED
    )
    assert (
        infer_status_from_execution(
            tool_executed=True,
            tool_error=False,
            target_unreachable=False,
            execution_evidence_id="ev-1",
        )
        is CoverageStatus.COVERED_NO_FINDING
    )
