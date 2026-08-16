"""WIRE-005 — coverage phase sink: honest not_tested vs covered_no_finding."""

from __future__ import annotations

from src.capabilities.schemas import CoverageStatus
from src.orchestration.coverage_phase_sink import (
    CoveragePhaseSink,
    InMemoryCoverageStore,
    ToolRunSignal,
    get_coverage_store,
    signals_for_vuln_analysis,
)

_CAP = "web.application.api.rest"


def _sink() -> CoveragePhaseSink:
    return CoveragePhaseSink(store=InMemoryCoverageStore())


def _emit(
    sink: CoveragePhaseSink,
    signal: ToolRunSignal,
    *,
    scan_id: str = "s1",
    execution_mode: str = "production",
    lab_lease_active: bool = False,
) -> list:
    return sink.emit_phase(
        phase="vuln_analysis",
        tenant_id="t1",
        scan_id=scan_id,
        asset_id="a1",
        signals=[signal],
        execution_mode=execution_mode,
        lab_lease_active=lab_lease_active,
    )


def test_skip_is_not_tested():
    results = _emit(
        _sink(),
        ToolRunSignal(tool_id="nuclei", capability_id=_CAP, skipped=True),
    )
    assert len(results) == 1
    assert results[0].status is CoverageStatus.NOT_TESTED
    assert results[0].execution_evidence_id is None
    assert results[0].finding_id is None
    assert results[0].blocked_reason is None


def test_successful_empty_nuclei_is_covered_no_finding():
    results = _emit(
        _sink(),
        ToolRunSignal(tool_id="nuclei", capability_id=_CAP, tool_executed=True),
    )
    assert len(results) == 1
    assert results[0].status is CoverageStatus.COVERED_NO_FINDING
    assert results[0].execution_evidence_id
    assert results[0].finding_id is None
    assert results[0].status is not CoverageStatus.NOT_TESTED


def test_finding_present_is_covered_with_finding():
    results = _emit(
        _sink(),
        ToolRunSignal(
            tool_id="nuclei",
            capability_id=_CAP,
            tool_executed=True,
            finding_id="fid-nuclei-1",
        ),
    )
    assert len(results) == 1
    assert results[0].status is CoverageStatus.COVERED_WITH_FINDING
    assert results[0].finding_id == "fid-nuclei-1"
    assert results[0].execution_evidence_id


def test_lab_policy_blocked_reason_cleared_but_tool_error_stays_blocked():
    sink = _sink()
    cleared = _emit(
        sink,
        ToolRunSignal(
            tool_id="nuclei",
            capability_id=_CAP,
            skipped=True,
            policy_blocked=True,
            blocked_reason="policy_blocked",
        ),
        scan_id="lab-policy",
        execution_mode="lab_unrestricted",
        lab_lease_active=True,
    )
    assert len(cleared) == 1
    assert cleared[0].status is CoverageStatus.NOT_TESTED
    assert cleared[0].blocked_reason is None
    assert cleared[0].status is not CoverageStatus.BLOCKED

    errored = _emit(
        sink,
        ToolRunSignal(
            tool_id="nuclei",
            capability_id=_CAP,
            tool_executed=True,
            tool_error=True,
            blocked_reason="tool_error",
        ),
        scan_id="lab-error",
        execution_mode="lab_unrestricted",
        lab_lease_active=True,
    )
    assert len(errored) == 1
    assert errored[0].status is CoverageStatus.BLOCKED
    assert errored[0].blocked_reason == "tool_error"


def test_skip_never_becomes_covered_no_finding_without_execution():
    helper = signals_for_vuln_analysis(
        skipped=True,
        skip_reason="sandbox_disabled",
        tool_executed=False,
        scan_id="s-skip",
    )
    results = _emit(_sink(), helper[0])
    assert results
    assert all(row.status is CoverageStatus.NOT_TESTED for row in results)
    assert all(row.status is not CoverageStatus.COVERED_NO_FINDING for row in results)
    assert all(row.execution_evidence_id is None for row in results)


def test_default_store_is_readable_for_scan_coverage_api():
    store = get_coverage_store()
    store.clear("api-scan")
    sink = CoveragePhaseSink(store=store)
    emitted = _emit(
        sink,
        ToolRunSignal(tool_id="nuclei", capability_id=_CAP, skipped=True),
        scan_id="api-scan",
    )
    stored = store.get("api-scan")
    assert len(stored) == 1
    assert stored[0].requirement_id == emitted[0].requirement_id
    assert stored[0].status is CoverageStatus.NOT_TESTED
    store.clear("api-scan")
