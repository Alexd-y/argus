"""Quick coverage records — CoverageResult + reason_code + templates + evidence.

Absence of a finding is never coverage. Every planned capability×asset pair
gets a record so ``coverage_accounting_rate`` is 1.00.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

from src.capabilities.coverage import (
    COVERAGE_REASON_CODES,
    is_allowed_coverage_reason,
)
from src.capabilities.schemas import COVERED_STATUSES, CoverageResult, CoverageStatus
from src.orchestration.coverage_phase_sink import (
    CoveragePhaseSink,
    ToolRunSignal,
    get_coverage_phase_sink,
    serialize_coverage_results,
)
from src.quick.circuit_breaker import CIRCUIT_OPEN_REASON
from src.quick.disallowed import NOT_SCHEDULED_BY_QUICK_PROFILE
from src.quick.metrics import record_coverage_ratio
from src.quick.schemas import QuickCoverageRecord, QuickCoverageState

REASON_EXECUTED: Final[str] = "executed"
REASON_BUDGET_PARTIAL: Final[str] = "budget_partial"
REASON_FINGERPRINT_MISMATCH: Final[str] = "fingerprint_mismatch"
REASON_DEADLINE_REACHED: Final[str] = "deadline_reached"
REASON_TOOL_ERROR: Final[str] = "tool_error"

_QUICK_STATE_TO_STATUS: Final[dict[QuickCoverageState, CoverageStatus]] = {
    QuickCoverageState.TESTED: CoverageStatus.COVERED_NO_FINDING,
    QuickCoverageState.PARTIALLY_TESTED: CoverageStatus.PARTIAL,
    QuickCoverageState.NOT_APPLICABLE: CoverageStatus.NOT_APPLICABLE,
    QuickCoverageState.NOT_SCHEDULED: CoverageStatus.NOT_TESTED,
    QuickCoverageState.TIMED_OUT: CoverageStatus.BLOCKED,
    QuickCoverageState.FAILED: CoverageStatus.BLOCKED,
}

_REASON_TO_STATE: Final[dict[str, QuickCoverageState]] = {
    REASON_EXECUTED: QuickCoverageState.TESTED,
    REASON_BUDGET_PARTIAL: QuickCoverageState.PARTIALLY_TESTED,
    REASON_FINGERPRINT_MISMATCH: QuickCoverageState.NOT_APPLICABLE,
    NOT_SCHEDULED_BY_QUICK_PROFILE: QuickCoverageState.NOT_SCHEDULED,
    REASON_DEADLINE_REACHED: QuickCoverageState.TIMED_OUT,
    REASON_TOOL_ERROR: QuickCoverageState.FAILED,
    CIRCUIT_OPEN_REASON: QuickCoverageState.FAILED,
}


def map_quick_state_to_status(
    state: QuickCoverageState,
    *,
    finding_id: str | None = None,
    has_execution_evidence: bool = False,
) -> CoverageStatus:
    """Map a Quick coverage state onto the existing CoverageStatus enum."""
    if state is QuickCoverageState.TESTED:
        if finding_id and has_execution_evidence:
            return CoverageStatus.COVERED_WITH_FINDING
        if has_execution_evidence:
            return CoverageStatus.COVERED_NO_FINDING
        return CoverageStatus.NOT_TESTED
    return _QUICK_STATE_TO_STATUS[state]


def reason_for_state(state: QuickCoverageState) -> str:
    inverse = {value: key for key, value in _REASON_TO_STATE.items()}
    return inverse.get(state, NOT_SCHEDULED_BY_QUICK_PROFILE)


def signal_from_quick_record(
    record: QuickCoverageRecord,
    *,
    finding_id: str | None = None,
    tool_id: str | None = None,
) -> ToolRunSignal:
    """Build a sink signal from a Quick coverage DTO."""
    reason = record.reason_code.strip() or reason_for_state(record.state)
    if not is_allowed_coverage_reason(reason):
        reason = NOT_SCHEDULED_BY_QUICK_PROFILE
    tools = record.tools or ("unknown",)
    primary_tool = (tool_id or tools[0]).strip() or "unknown"
    evidence_id = record.evidence_ids[0] if record.evidence_ids else None
    executed = record.state is QuickCoverageState.TESTED
    partial = record.state is QuickCoverageState.PARTIALLY_TESTED
    failed = record.state is QuickCoverageState.FAILED
    timed_out = record.state is QuickCoverageState.TIMED_OUT
    not_applicable = record.state is QuickCoverageState.NOT_APPLICABLE
    not_scheduled = record.state is QuickCoverageState.NOT_SCHEDULED
    tool_executed = (executed or partial) and bool(evidence_id)
    return ToolRunSignal(
        tool_id=primary_tool,
        capability_id=record.capability_id,
        skipped=not_scheduled or not_applicable,
        tool_executed=tool_executed,
        tool_error=failed,
        not_applicable=not_applicable,
        blocked_reason=reason if (failed or timed_out) else None,
        execution_evidence_id=evidence_id if tool_executed else None,
        finding_id=finding_id if tool_executed else None,
        quick_reason=reason,
        template_ids=record.template_ids,
        evidence_ids=record.evidence_ids,
    )


def write_quick_coverage(
    *,
    tenant_id: str,
    scan_id: str,
    records: Sequence[QuickCoverageRecord],
    finding_ids: Mapping[str, str] | None = None,
    execution_mode: str = "quick",
    phase: str = "vuln_analysis",
    sink: CoveragePhaseSink | None = None,
) -> list[CoverageResult]:
    """Emit CoverageResult rows for Quick records via the shared phase sink."""
    active = sink if sink is not None else get_coverage_phase_sink()
    ids = dict(finding_ids or {})
    emitted: list[CoverageResult] = []
    grouped: dict[str, list[ToolRunSignal]] = {}
    for record in records:
        asset_id = record.asset_id
        finding_id = ids.get(record.capability_id) or ids.get(f"{asset_id}:{record.capability_id}")
        grouped.setdefault(asset_id, []).append(
            signal_from_quick_record(record, finding_id=finding_id)
        )
    for asset_id, signals in grouped.items():
        emitted.extend(
            active.emit_phase(
                phase=phase,
                tenant_id=tenant_id,
                scan_id=scan_id,
                asset_id=asset_id,
                signals=signals,
                execution_mode=execution_mode,
                lab_lease_active=False,
            )
        )
    if records:
        record_coverage_ratio(coverage_accounting_rate(records, emitted))
    return emitted


def ensure_planned_coverage(
    *,
    tenant_id: str,
    scan_id: str,
    planned: Sequence[QuickCoverageRecord],
    finding_ids: Mapping[str, str] | None = None,
    execution_mode: str = "quick",
    phase: str = "vuln_analysis",
    sink: CoveragePhaseSink | None = None,
) -> list[CoverageResult]:
    """Write a coverage row for every planned capability×asset (rate = 1.00)."""
    active = sink if sink is not None else get_coverage_phase_sink()
    existing = {
        (row.capability_id, row.asset_id) for row in active.results_for_scan(scan_id)
    }
    missing = [
        record
        for record in planned
        if (record.capability_id, record.asset_id) not in existing
    ]
    if not missing:
        return []
    return write_quick_coverage(
        tenant_id=tenant_id,
        scan_id=scan_id,
        records=missing,
        finding_ids=finding_ids,
        execution_mode=execution_mode,
        phase=phase,
        sink=active,
    )


def coverage_accounting_rate(
    planned: Sequence[QuickCoverageRecord] | Sequence[tuple[str, str]],
    recorded: Sequence[CoverageResult] | Sequence[QuickCoverageRecord] | Sequence[tuple[str, str]],
) -> float:
    """Fraction of planned capability×asset pairs that have a coverage record."""
    planned_keys = _pair_keys(planned)
    if not planned_keys:
        return 1.0
    recorded_keys = _pair_keys(recorded)
    covered = planned_keys & recorded_keys
    return round(len(covered) / len(planned_keys), 2)


def _pair_keys(
    items: Sequence[QuickCoverageRecord]
    | Sequence[CoverageResult]
    | Sequence[tuple[str, str]],
) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    for item in items:
        if isinstance(item, tuple) and len(item) == 2:
            keys.add((str(item[0]), str(item[1])))
            continue
        cap = getattr(item, "capability_id", "")
        asset = getattr(item, "asset_id", "")
        if cap and asset:
            keys.add((str(cap), str(asset)))
    return keys


def serialize_quick_coverage(results: Sequence[CoverageResult]) -> list[dict[str, Any]]:
    """JSON rows including reason_code / template_ids / evidence_ids."""
    return serialize_coverage_results(results)


def is_honest_coverage(result: CoverageResult) -> bool:
    """Covered statuses require execution evidence; absence of finding is not coverage."""
    if result.status in COVERED_STATUSES:
        return bool(result.execution_evidence_id)
    return True


def allowed_quick_reason_codes() -> frozenset[str]:
    return COVERAGE_REASON_CODES
