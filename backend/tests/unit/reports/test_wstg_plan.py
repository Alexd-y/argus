"""Track B — engagement test plan (B-plan) + run→state bridge (B-populate)."""

from __future__ import annotations

from src.reports.wstg_coverage import _WSTG_TESTS
from src.reports.wstg_gate import ExecutionStatus
from src.reports.wstg_gate import TestResult as Res
from src.reports.wstg_plan import (
    build_engagement_test_plan,
    catalog_checksum,
    derive_wstg_states,
)

# --- B-plan -------------------------------------------------------------------


def test_plan_snapshots_full_catalog_all_not_started():
    plan = build_engagement_test_plan()
    assert len(plan.states) == len(_WSTG_TESTS)
    assert all(s.execution_status == ExecutionStatus.NOT_STARTED for s in plan.states)
    # Fresh plan has zero coverage and does not pass the gate.
    rep = plan.coverage()
    assert rep.counted == 0
    assert rep.gate_passed is False


def test_catalog_checksum_is_stable_and_nonempty():
    assert catalog_checksum() == catalog_checksum()
    assert len(catalog_checksum()) == 64


def test_plan_exclusion_requires_rationale():
    ids = [t.id for t in _WSTG_TESTS]
    a, b = ids[0], ids[1]
    plan = build_engagement_test_plan(
        applicability={a: False, b: False},
        exclusion_rationale={a: "no SOAP/RIA surface"},  # only a is justified
    )
    by_id = {s.test_id: s for s in plan.states}
    # a: justified → not applicable; b: no rationale → stays applicable (fail-closed).
    assert by_id[a].is_applicable() is False
    assert by_id[b].is_applicable() is True


# --- B-populate ---------------------------------------------------------------


def test_finding_reference_marks_completed_fail_with_evidence():
    first = _WSTG_TESTS[0].id
    states = derive_wstg_states(
        tools_executed=[],
        findings=[{"wstg": first, "title": "x"}],
        evidence_by_test={first: ["argus/evidence/x.json"]},
    )
    s = next(s for s in states if s.test_id == first)
    assert s.execution_status == ExecutionStatus.COMPLETED
    assert s.result == Res.FAIL
    assert s.counts_toward_coverage() is True


def test_finding_reference_without_evidence_does_not_count():
    first = _WSTG_TESTS[0].id
    states = derive_wstg_states(tools_executed=[], findings=[{"wstg": first}])
    s = next(s for s in states if s.test_id == first)
    assert s.execution_status == ExecutionStatus.COMPLETED
    assert s.counts_toward_coverage() is False  # missing evidence blocks the count


def test_single_covering_tool_without_evidence_is_partial_not_counted():
    # A tool with no evidence id (wpscan) covers tests but proves nothing on its
    # own → partial, contributes zero (spec §4: evidence is the gate).
    states = derive_wstg_states(tools_executed=["wpscan"], findings=[])
    partials = [s for s in states if s.execution_status == ExecutionStatus.PARTIAL]
    assert partials, "expected at least one partial from an evidence-less covering tool"
    assert all(not s.counts_toward_coverage() for s in partials)


def test_single_covering_tool_with_evidence_is_completed_pass():
    # A single covering tool that produces a captured evidence artifact (whatweb →
    # EV-TECH-001) completes the control with pass and counts toward coverage.
    states = derive_wstg_states(tools_executed=["whatweb"], findings=[])
    counted = [s for s in states if s.counts_toward_coverage()]
    assert counted, "expected an evidenced single-tool coverage to count"
    assert all(s.execution_status == ExecutionStatus.COMPLETED for s in counted)


def test_uncovered_tests_stay_not_started():
    states = derive_wstg_states(tools_executed=[], findings=[])
    assert all(s.execution_status == ExecutionStatus.NOT_STARTED for s in states)


def test_derive_preserves_justified_exclusion_from_base_plan():
    ids = [t.id for t in _WSTG_TESTS]
    excluded = ids[0]
    plan = build_engagement_test_plan(
        applicability={excluded: False},
        exclusion_rationale={excluded: "not applicable to this target"},
    )
    states = derive_wstg_states(tools_executed=["whatweb"], findings=[], base_plan=plan)
    s = next(s for s in states if s.test_id == excluded)
    assert s.execution_status == ExecutionStatus.NOT_APPLICABLE
    assert s.is_applicable() is False
