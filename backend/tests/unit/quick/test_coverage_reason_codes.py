"""QUICK-005 — Quick coverage reason codes and honest accounting."""

from __future__ import annotations

from src.capabilities.coverage import COVERAGE_REASON_CODES, is_allowed_coverage_reason
from src.capabilities.schemas import COVERED_STATUSES, CoverageStatus
from src.orchestration.coverage_phase_sink import CoveragePhaseSink, InMemoryCoverageStore
from src.quick.circuit_breaker import CIRCUIT_OPEN_REASON
from src.quick.coverage import (
    REASON_BUDGET_PARTIAL,
    REASON_DEADLINE_REACHED,
    REASON_EXECUTED,
    REASON_FINGERPRINT_MISMATCH,
    REASON_TOOL_ERROR,
    allowed_quick_reason_codes,
    coverage_accounting_rate,
    ensure_planned_coverage,
    is_honest_coverage,
    map_quick_state_to_status,
    reason_for_state,
    signal_from_quick_record,
    write_quick_coverage,
)
from src.quick.disallowed import NOT_SCHEDULED_BY_QUICK_PROFILE
from src.quick.schemas import QuickCoverageRecord, QuickCoverageState

_TENANT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_SCAN_ID = "11111111-2222-3333-4444-555555555555"
_ASSET_A = "abcdef01-2345-6789-abcd-ef0123456789"
_ASSET_B = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
_CAP_A = "web.application.cve.known_product"
_CAP_B = "web.application.api.rest"
_EVIDENCE_ID = "0123456789abcdef0123456789abcdef0123"


def _record(
    *,
    asset_id: str = _ASSET_A,
    capability_id: str = _CAP_A,
    state: QuickCoverageState = QuickCoverageState.TESTED,
    reason_code: str = REASON_EXECUTED,
    evidence_ids: tuple[str, ...] = (),
    template_ids: tuple[str, ...] = ("http-cve-nginx",),
    tools: tuple[str, ...] = ("nuclei",),
) -> QuickCoverageRecord:
    return QuickCoverageRecord(
        asset_id=asset_id,
        capability_id=capability_id,
        state=state,
        reason_code=reason_code,
        tools=tools,
        template_ids=template_ids,
        evidence_ids=evidence_ids,
    )


def _sink() -> CoveragePhaseSink:
    return CoveragePhaseSink(store=InMemoryCoverageStore())


def test_quick_reason_codes_are_whitelisted() -> None:
    expected = {
        REASON_EXECUTED,
        REASON_BUDGET_PARTIAL,
        REASON_FINGERPRINT_MISMATCH,
        NOT_SCHEDULED_BY_QUICK_PROFILE,
        REASON_DEADLINE_REACHED,
        REASON_TOOL_ERROR,
        CIRCUIT_OPEN_REASON,
    }
    whitelist = allowed_quick_reason_codes()
    assert whitelist == COVERAGE_REASON_CODES
    for code in expected:
        assert code in COVERAGE_REASON_CODES
        assert is_allowed_coverage_reason(code) is True
    assert is_allowed_coverage_reason("not_a_real_reason") is False
    assert is_allowed_coverage_reason("") is False
    assert is_allowed_coverage_reason(None) is False


def test_map_quick_state_tested_partial_not_scheduled_timed_out_failed() -> None:
    assert (
        map_quick_state_to_status(
            QuickCoverageState.TESTED,
            finding_id=None,
            has_execution_evidence=True,
        )
        is CoverageStatus.COVERED_NO_FINDING
    )
    assert (
        map_quick_state_to_status(
            QuickCoverageState.TESTED,
            finding_id="fid-1",
            has_execution_evidence=True,
        )
        is CoverageStatus.COVERED_WITH_FINDING
    )
    assert (
        map_quick_state_to_status(
            QuickCoverageState.PARTIALLY_TESTED,
            has_execution_evidence=True,
        )
        is CoverageStatus.PARTIAL
    )
    assert map_quick_state_to_status(QuickCoverageState.NOT_SCHEDULED) is CoverageStatus.NOT_TESTED
    assert map_quick_state_to_status(QuickCoverageState.TIMED_OUT) is CoverageStatus.BLOCKED
    assert map_quick_state_to_status(QuickCoverageState.FAILED) is CoverageStatus.BLOCKED
    assert map_quick_state_to_status(QuickCoverageState.NOT_APPLICABLE) is CoverageStatus.NOT_APPLICABLE


def test_absence_of_finding_is_not_covered() -> None:
    status = map_quick_state_to_status(
        QuickCoverageState.TESTED,
        finding_id=None,
        has_execution_evidence=False,
    )
    assert status is CoverageStatus.NOT_TESTED
    assert status not in COVERED_STATUSES

    signal = signal_from_quick_record(_record(state=QuickCoverageState.TESTED, evidence_ids=()))
    assert signal.tool_executed is False
    assert signal.execution_evidence_id is None
    assert signal.finding_id is None


def test_coverage_accounting_rate_is_one_for_all_planned_pairs() -> None:
    planned = (
        _record(asset_id=_ASSET_A, capability_id=_CAP_A),
        _record(asset_id=_ASSET_A, capability_id=_CAP_B),
        _record(asset_id=_ASSET_B, capability_id=_CAP_A),
    )
    assert coverage_accounting_rate(planned, planned) == 1.00
    assert coverage_accounting_rate((), ()) == 1.0
    assert (
        coverage_accounting_rate(
            ((_CAP_A, _ASSET_A), (_CAP_B, _ASSET_A)),
            ((_CAP_A, _ASSET_A), (_CAP_B, _ASSET_A)),
        )
        == 1.00
    )
    assert (
        coverage_accounting_rate(
            ((_CAP_A, _ASSET_A), (_CAP_B, _ASSET_A)),
            ((_CAP_A, _ASSET_A),),
        )
        == 0.5
    )
    assert coverage_accounting_rate(planned, ()) == 0.0


def test_ensure_planned_coverage_writes_every_pair() -> None:
    sink = _sink()
    planned = (
        _record(
            asset_id=_ASSET_A,
            capability_id=_CAP_A,
            state=QuickCoverageState.TESTED,
            reason_code=REASON_EXECUTED,
            evidence_ids=(_EVIDENCE_ID,),
        ),
        _record(
            asset_id=_ASSET_A,
            capability_id=_CAP_B,
            state=QuickCoverageState.NOT_SCHEDULED,
            reason_code=NOT_SCHEDULED_BY_QUICK_PROFILE,
        ),
        _record(
            asset_id=_ASSET_B,
            capability_id=_CAP_A,
            state=QuickCoverageState.TIMED_OUT,
            reason_code=REASON_DEADLINE_REACHED,
        ),
    )
    emitted = ensure_planned_coverage(
        tenant_id=_TENANT_ID,
        scan_id=_SCAN_ID,
        planned=planned,
        sink=sink,
    )
    assert len(emitted) == 3
    pairs = {(row.capability_id, row.asset_id) for row in emitted}
    assert pairs == {(_CAP_A, _ASSET_A), (_CAP_B, _ASSET_A), (_CAP_A, _ASSET_B)}
    assert coverage_accounting_rate(planned, emitted) == 1.00
    assert coverage_accounting_rate(planned, sink.results_for_scan(_SCAN_ID)) == 1.00

    again = ensure_planned_coverage(
        tenant_id=_TENANT_ID,
        scan_id=_SCAN_ID,
        planned=planned,
        sink=sink,
    )
    assert again == []


def test_write_quick_coverage_maps_reason_codes_onto_status() -> None:
    sink = _sink()
    records = (
        _record(
            capability_id=_CAP_A,
            state=QuickCoverageState.TESTED,
            reason_code=REASON_EXECUTED,
            evidence_ids=(_EVIDENCE_ID,),
        ),
        _record(
            capability_id=_CAP_B,
            state=QuickCoverageState.PARTIALLY_TESTED,
            reason_code=REASON_BUDGET_PARTIAL,
            evidence_ids=(_EVIDENCE_ID,),
        ),
        _record(
            asset_id=_ASSET_B,
            capability_id=_CAP_A,
            state=QuickCoverageState.NOT_SCHEDULED,
            reason_code=NOT_SCHEDULED_BY_QUICK_PROFILE,
        ),
        _record(
            asset_id=_ASSET_B,
            capability_id=_CAP_B,
            state=QuickCoverageState.TIMED_OUT,
            reason_code=REASON_DEADLINE_REACHED,
        ),
        _record(
            asset_id=_ASSET_B,
            capability_id="web.application.auth.session",
            state=QuickCoverageState.FAILED,
            reason_code=REASON_TOOL_ERROR,
        ),
    )
    emitted = write_quick_coverage(
        tenant_id=_TENANT_ID,
        scan_id=_SCAN_ID,
        records=records,
        finding_ids={_CAP_A: "fid-nuclei-1"},
        sink=sink,
    )
    by_cap = {(row.asset_id, row.capability_id): row for row in emitted}

    tested = by_cap[(_ASSET_A, _CAP_A)]
    assert tested.status is CoverageStatus.COVERED_WITH_FINDING
    assert tested.reason_code == REASON_EXECUTED
    assert tested.execution_evidence_id == _EVIDENCE_ID
    assert is_honest_coverage(tested) is True

    partial = by_cap[(_ASSET_A, _CAP_B)]
    assert partial.status is CoverageStatus.PARTIAL
    assert partial.reason_code == REASON_BUDGET_PARTIAL
    assert partial.execution_evidence_id == _EVIDENCE_ID

    skipped = by_cap[(_ASSET_B, _CAP_A)]
    assert skipped.status is CoverageStatus.NOT_TESTED
    assert skipped.reason_code == NOT_SCHEDULED_BY_QUICK_PROFILE
    assert skipped.execution_evidence_id is None
    assert skipped.status not in COVERED_STATUSES

    timed_out = by_cap[(_ASSET_B, _CAP_B)]
    assert timed_out.status is CoverageStatus.BLOCKED
    assert timed_out.reason_code == REASON_DEADLINE_REACHED
    assert timed_out.blocked_reason == REASON_DEADLINE_REACHED

    failed = by_cap[(_ASSET_B, "web.application.auth.session")]
    assert failed.status is CoverageStatus.BLOCKED
    assert failed.reason_code == REASON_TOOL_ERROR
    assert failed.blocked_reason == REASON_TOOL_ERROR


def test_reason_for_state_round_trip_unambiguous_states() -> None:
    assert reason_for_state(QuickCoverageState.TESTED) == REASON_EXECUTED
    assert reason_for_state(QuickCoverageState.PARTIALLY_TESTED) == REASON_BUDGET_PARTIAL
    assert reason_for_state(QuickCoverageState.NOT_APPLICABLE) == REASON_FINGERPRINT_MISMATCH
    assert reason_for_state(QuickCoverageState.NOT_SCHEDULED) == NOT_SCHEDULED_BY_QUICK_PROFILE
    assert reason_for_state(QuickCoverageState.TIMED_OUT) == REASON_DEADLINE_REACHED


def test_unknown_reason_falls_back_to_not_scheduled() -> None:
    signal = signal_from_quick_record(
        _record(state=QuickCoverageState.NOT_SCHEDULED, reason_code="made_up_reason")
    )
    assert signal.quick_reason == NOT_SCHEDULED_BY_QUICK_PROFILE
    assert signal.skipped is True
