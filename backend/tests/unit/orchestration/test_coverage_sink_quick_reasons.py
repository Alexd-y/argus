"""QUICK-005 — coverage sink accepts Quick profile / deadline reason codes."""

from __future__ import annotations

from src.capabilities.coverage import COVERAGE_REASON_CODES
from src.capabilities.schemas import CoverageStatus
from src.orchestration.coverage_phase_sink import (
    CoveragePhaseSink,
    InMemoryCoverageStore,
    ToolRunSignal,
    signals_for_quick_reason,
)

_CAP = "web.application.cve.known_product"
_TENANT = "t1"
_SCAN = "s-quick-005"
_ASSET = "a1"


def _sink() -> CoveragePhaseSink:
    return CoveragePhaseSink(store=InMemoryCoverageStore())


def _emit(sink: CoveragePhaseSink, signal: ToolRunSignal, *, scan_id: str = _SCAN) -> list:
    return sink.emit_phase(
        phase="vuln_analysis",
        tenant_id=_TENANT,
        scan_id=scan_id,
        asset_id=_ASSET,
        signals=[signal],
        execution_mode="quick",
    )


def test_not_scheduled_by_quick_profile_is_not_tested() -> None:
    assert "not_scheduled_by_quick_profile" in COVERAGE_REASON_CODES
    helper = signals_for_quick_reason(
        tool_id="nuclei",
        quick_reason="not_scheduled_by_quick_profile",
        capability_id=_CAP,
        template_ids=("http-cve-nginx",),
    )
    assert len(helper) == 1
    assert helper[0].quick_reason == "not_scheduled_by_quick_profile"
    assert helper[0].skipped is True
    assert helper[0].tool_executed is False

    results = _emit(_sink(), helper[0])
    assert len(results) == 1
    row = results[0]
    assert row.status is CoverageStatus.NOT_TESTED
    assert row.reason_code == "not_scheduled_by_quick_profile"
    assert row.execution_evidence_id is None
    assert row.finding_id is None
    assert row.blocked_reason is None
    assert row.status is not CoverageStatus.COVERED_NO_FINDING


def test_deadline_reached_is_blocked() -> None:
    assert "deadline_reached" in COVERAGE_REASON_CODES
    helper = signals_for_quick_reason(
        tool_id="nuclei",
        quick_reason="deadline_reached",
        capability_id=_CAP,
        template_ids=("http-cve-nginx",),
    )
    assert helper[0].quick_reason == "deadline_reached"
    assert helper[0].blocked_reason == "deadline_reached"
    assert helper[0].tool_executed is False

    results = _emit(_sink(), helper[0], scan_id="s-deadline")
    assert len(results) == 1
    row = results[0]
    assert row.status is CoverageStatus.BLOCKED
    assert row.reason_code == "deadline_reached"
    assert row.blocked_reason == "deadline_reached"
    assert row.execution_evidence_id is None
    assert row.status is not CoverageStatus.COVERED_NO_FINDING


def test_sink_accepts_quick_reason_on_tool_run_signal_directly() -> None:
    sink = _sink()
    skipped = _emit(
        sink,
        ToolRunSignal(
            tool_id="nuclei",
            capability_id=_CAP,
            skipped=True,
            quick_reason="not_scheduled_by_quick_profile",
            template_ids=("tpl-a",),
        ),
        scan_id="direct-skip",
    )
    assert skipped[0].status is CoverageStatus.NOT_TESTED
    assert skipped[0].reason_code == "not_scheduled_by_quick_profile"
    assert skipped[0].template_ids == ("tpl-a",)

    timed_out = _emit(
        sink,
        ToolRunSignal(
            tool_id="nuclei",
            capability_id=_CAP,
            quick_reason="deadline_reached",
            blocked_reason="deadline_reached",
        ),
        scan_id="direct-deadline",
    )
    assert timed_out[0].status is CoverageStatus.BLOCKED
    assert timed_out[0].reason_code == "deadline_reached"
    assert timed_out[0].blocked_reason == "deadline_reached"


def test_fingerprint_mismatch_and_budget_partial_quick_reasons() -> None:
    sink = _sink()
    mismatch = _emit(
        sink,
        signals_for_quick_reason(
            tool_id="nuclei",
            quick_reason="fingerprint_mismatch",
            capability_id=_CAP,
        )[0],
        scan_id="fp-mismatch",
    )
    assert mismatch[0].status is CoverageStatus.NOT_APPLICABLE
    assert mismatch[0].reason_code == "fingerprint_mismatch"

    partial = _emit(
        sink,
        signals_for_quick_reason(
            tool_id="nuclei",
            quick_reason="budget_partial",
            capability_id=_CAP,
            evidence_ids=("ev-partial-1",),
        )[0],
        scan_id="budget-partial",
    )
    assert partial[0].status is CoverageStatus.PARTIAL
    assert partial[0].reason_code == "budget_partial"
    assert partial[0].execution_evidence_id == "ev-partial-1"
