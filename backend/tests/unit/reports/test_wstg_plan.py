"""ARGUS-WSTG-COV-1 — engagement plan + fact→state bridge tests.

These replace the removed tool-name → pass synthesis: coverage now derives only
from evidence-validated executions (spec §3.4/§3.5, §14 scenarios 8, 13, 26).
"""

from __future__ import annotations

from src.reports.wstg_applicability import decide_applicability
from src.reports.wstg_coverage import _WSTG_TESTS, wstg_ids_for_finding
from src.reports.wstg_execution import aggregate_executions
from src.reports.wstg_model import Applicability, ExecutionStatus, Outcome
from src.reports.wstg_plan import (
    build_engagement_test_plan,
    build_wstg_states,
    catalog_checksum,
    catalog_ids,
)
from src.reports.wstg_producers import findings_to_executions


def test_plan_snapshots_full_catalog_all_not_started():
    plan = build_engagement_test_plan()
    assert len(plan.states) == len(_WSTG_TESTS)
    assert all(s.execution_status == ExecutionStatus.NOT_STARTED for s in plan.states)
    rep = plan.coverage()
    assert rep.counted == 0
    assert rep.coverage_gate_passed is False


def test_catalog_checksum_is_stable_and_nonempty():
    assert catalog_checksum() == catalog_checksum()
    assert len(catalog_checksum()) == 64


def test_catalog_ids_matches_registry():
    assert catalog_ids() == frozenset(t.id for t in _WSTG_TESTS)


def _states_from_findings(findings, *, scan_id="scan-1", target="https://t.example"):
    """End-to-end helper mirroring the shared assembler (producer → states)."""
    execs = findings_to_executions(
        findings, scan_id=scan_id, target=target, wstg_ids_for_finding=wstg_ids_for_finding
    )
    aggregated = aggregate_executions(execs)
    finding_test_ids = frozenset(
        wid for f in findings if f.get("_has_evidence") for wid in wstg_ids_for_finding(f)
    )
    decisions = decide_applicability(finding_test_ids=finding_test_ids)
    # In this pure-unit helper the finding IS the evidence (validated upstream).
    ev = {tid: True for tid in aggregated}
    return build_wstg_states(
        decisions=decisions, aggregated=aggregated, evidence_validated_by_test=ev
    )


def test_scenario13_finding_with_evidence_marks_completed_fail_and_counts():
    first = _WSTG_TESTS[0].id
    states = _states_from_findings([{"id": "f1", "wstg": first, "_has_evidence": True}])
    s = next(s for s in states if s.test_id == first)
    assert s.execution_status == ExecutionStatus.COMPLETED
    assert s.outcome == Outcome.FAIL
    assert s.counts_toward_coverage() is True


def test_scenario8_finding_without_evidence_does_not_count():
    first = _WSTG_TESTS[0].id
    # No _has_evidence → producer emits a partial diagnostic execution.
    states = _states_from_findings([{"id": "f1", "wstg": first, "_has_evidence": False}])
    s = next(s for s in states if s.test_id == first)
    assert s.execution_status != ExecutionStatus.COMPLETED
    assert s.counts_toward_coverage() is False


def test_tool_name_alone_produces_no_coverage():
    # No findings at all → nothing counts, everything not_started/unknown.
    states = _states_from_findings([])
    assert all(not s.counts_toward_coverage() for s in states)


def test_finding_forces_applicability_over_unknown_surface():
    # An auth test (unknown surface by default) becomes applicable when a finding
    # maps to it — the vulnerability proves the surface exists.
    athn = "WSTG-ATHN-07"
    states = _states_from_findings([{"id": "f1", "wstg": athn, "_has_evidence": True}])
    s = next(s for s in states if s.test_id == athn)
    assert s.applicability == Applicability.APPLICABLE
    assert s.counts_toward_coverage() is True


def test_unobserved_auth_test_is_unknown_not_excluded():
    # With no findings and no surface, an auth test stays UNKNOWN (in denominator),
    # never silently excluded (spec §3.1).
    decisions = decide_applicability()
    d = decisions["WSTG-ATHN-07"]
    assert d.state == Applicability.UNKNOWN
    assert d.is_valid_not_applicable() is False
