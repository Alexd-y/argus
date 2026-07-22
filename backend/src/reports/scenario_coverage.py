"""Executed-scenario coverage for WSTG reporting (P7-WSTG-007).

Tool coverage (``wstg_coverage.build_wstg_coverage``) answers *"which WSTG tests
could a tool touch?"*. This module answers the stronger, honest question:
*"which WSTG tests did we actually execute, and with what outcome?"*.

The core invariant is that **running a tool/scenario is not coverage**. A
scenario that executed but produced no confirmed finding is
:attr:`CoverageStatus.EXECUTED_NO_FINDING` — never ``CONFIRMED_FINDING`` and
never silently "covered". The seven honest states are:

* ``NOT_APPLICABLE`` — the scenario did not apply to the target.
* ``NOT_RUN`` — planned/discovered but never executed.
* ``BLOCKED`` — could not run (e.g. waiting for approval).
* ``PARTIAL`` — ran but the outcome was inconclusive / incomplete.
* ``EXECUTED_NO_FINDING`` — ran to completion, no vulnerability confirmed.
* ``CONFIRMED_FINDING`` — ran and a finding was confirmed by an oracle.
* ``ERROR`` — execution or cleanup failed.

Coverage records are derived from :class:`~src.playbooks.executor.ScenarioResult`
(the executor drives the lifecycle) and are attached additively to the existing
WSTG coverage output via ``WstgCoverageResult.scenario_coverage``.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from src.playbooks.executor import ScenarioResult
from src.playbooks.lifecycle import ScenarioStatus
from src.playbooks.oracles import OracleVerdict
from src.reports.wstg_coverage import WSTG_VERSION


class CoverageStatus(StrEnum):
    """Honest execution-coverage state for a single scenario/test case."""

    NOT_APPLICABLE = "not_applicable"
    NOT_RUN = "not_run"
    BLOCKED = "blocked"
    PARTIAL = "partial"
    EXECUTED_NO_FINDING = "executed_no_finding"
    CONFIRMED_FINDING = "confirmed_finding"
    ERROR = "error"


# Direct lifecycle → coverage mapping for a *single* status, used when only a
# bare :class:`ScenarioStatus` is available (no execution history). The richer
# :func:`build_scenario_coverage_record` refines this using the full result.
_STATUS_TO_COVERAGE: dict[ScenarioStatus, CoverageStatus] = {
    ScenarioStatus.DISCOVERED: CoverageStatus.NOT_RUN,
    ScenarioStatus.PLANNED: CoverageStatus.NOT_RUN,
    ScenarioStatus.SKIPPED_NOT_APPLICABLE: CoverageStatus.NOT_APPLICABLE,
    ScenarioStatus.WAITING_APPROVAL: CoverageStatus.BLOCKED,
    ScenarioStatus.RUNNING: CoverageStatus.PARTIAL,
    ScenarioStatus.PARTIAL: CoverageStatus.PARTIAL,
    ScenarioStatus.CONFIRMED: CoverageStatus.CONFIRMED_FINDING,
    ScenarioStatus.REJECTED: CoverageStatus.EXECUTED_NO_FINDING,
    ScenarioStatus.CLEANUP_COMPLETE: CoverageStatus.EXECUTED_NO_FINDING,
    ScenarioStatus.CLEANUP_FAILED: CoverageStatus.ERROR,
}


def map_scenario_status(status: ScenarioStatus) -> CoverageStatus:
    """Map a single :class:`ScenarioStatus` to a :class:`CoverageStatus`.

    This is the context-free mapping (no execution history). For terminal
    cleanup states it reflects the cleanup outcome only; use
    :func:`build_scenario_coverage_record` for the finding-aware result.
    """
    return _STATUS_TO_COVERAGE[status]


@dataclass(frozen=True)
class ScenarioCoverageRecord:
    """One executed-scenario coverage entry for the report."""

    scenario_id: str
    coverage_status: CoverageStatus
    applicable: bool
    executed: bool
    wstg: list[str] = field(default_factory=list)
    cwe: list[int] = field(default_factory=list)
    owasp_api: list[str] = field(default_factory=list)
    evidence_sufficient: bool = False
    finding_ids: list[str] = field(default_factory=list)
    skip_or_error_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise the record for the (JSON) coverage output."""
        return {
            "scenario_id": self.scenario_id,
            "coverage_status": self.coverage_status.value,
            "applicable": self.applicable,
            "executed": self.executed,
            "wstg": list(self.wstg),
            "cwe": list(self.cwe),
            "owasp_api": list(self.owasp_api),
            "evidence_sufficient": self.evidence_sufficient,
            "finding_ids": list(self.finding_ids),
            "skip_or_error_reason": self.skip_or_error_reason,
        }


def _statuses_in(result: ScenarioResult) -> set[ScenarioStatus]:
    """All lifecycle statuses the scenario passed through (history + final)."""
    statuses = {state.status for state in result.history}
    statuses.add(result.state.status)
    return statuses


def _is_execution_error(result: ScenarioResult) -> bool:
    """A REJECTED-with-execution-error terminal indicates an ERROR, not a clean run."""
    for state in (*result.history, result.state):
        reason = (state.reason or "").lower()
        if state.status is ScenarioStatus.REJECTED and reason.startswith("execution error"):
            return True
    return False


def _derive_coverage_status(
    result: ScenarioResult,
    *,
    applicable: bool,
) -> CoverageStatus:
    """Derive the honest coverage status from the full scenario result.

    Precedence is outcome-first: a confirmed finding wins even if cleanup later
    failed (the finding is still real); an execution error that prevented a
    verdict is ERROR; otherwise a completed run with no finding is
    EXECUTED_NO_FINDING. Running a scenario is never treated as CONFIRMED.
    """
    if not applicable:
        return CoverageStatus.NOT_APPLICABLE

    statuses = _statuses_in(result)

    if result.is_confirmed:
        return CoverageStatus.CONFIRMED_FINDING
    if _is_execution_error(result):
        return CoverageStatus.ERROR
    if ScenarioStatus.SKIPPED_NOT_APPLICABLE in statuses:
        return CoverageStatus.NOT_APPLICABLE
    if ScenarioStatus.WAITING_APPROVAL in statuses:
        return CoverageStatus.BLOCKED
    if ScenarioStatus.REJECTED in statuses:
        # Ran an oracle, no finding confirmed — executed but nothing found.
        return CoverageStatus.EXECUTED_NO_FINDING
    if ScenarioStatus.PARTIAL in statuses:
        return CoverageStatus.PARTIAL
    if result.state.status is ScenarioStatus.CLEANUP_FAILED:
        return CoverageStatus.ERROR
    if not result.executed:
        return CoverageStatus.NOT_RUN
    # Executed (e.g. RUNNING/CLEANUP_COMPLETE without a verdict) but no oracle
    # verdict reached — treat as inconclusive rather than covered.
    return CoverageStatus.PARTIAL


def _oracle_reached_finding(result: ScenarioResult) -> bool:
    return any(o.verdict is OracleVerdict.FINDING for o in result.oracle_results)


def build_scenario_coverage_record(
    result: ScenarioResult,
    *,
    applicable: bool = True,
    wstg: Sequence[str] | None = None,
    cwe: Sequence[int] | None = None,
    owasp_api: Sequence[str] | None = None,
    finding_ids: Sequence[str] | None = None,
) -> ScenarioCoverageRecord:
    """Build a coverage record for one executed scenario.

    ``wstg`` / ``cwe`` / ``owasp_api`` come from the playbook definition (see
    ``backend/config/playbooks/*``). ``finding_ids`` link confirmed findings.
    """
    coverage_status = _derive_coverage_status(result, applicable=applicable)

    reason: str | None = None
    if coverage_status in (
        CoverageStatus.NOT_APPLICABLE,
        CoverageStatus.BLOCKED,
        CoverageStatus.ERROR,
    ):
        reason = result.state.reason or _first_reason(result)

    evidence_sufficient = (
        coverage_status is CoverageStatus.CONFIRMED_FINDING
        and result.evidence is not None
        and _oracle_reached_finding(result)
    )

    return ScenarioCoverageRecord(
        scenario_id=result.playbook_id,
        coverage_status=coverage_status,
        applicable=applicable,
        executed=result.executed,
        wstg=list(wstg or []),
        cwe=list(cwe or []),
        owasp_api=list(owasp_api or []),
        evidence_sufficient=evidence_sufficient,
        finding_ids=list(finding_ids or []),
        skip_or_error_reason=reason,
    )


def _first_reason(result: ScenarioResult) -> str | None:
    for state in (result.state, *reversed(result.history)):
        if state.reason:
            return state.reason
    return None


def build_scenario_coverage(
    records: Iterable[ScenarioCoverageRecord],
    *,
    wstg_version: str = WSTG_VERSION,
) -> dict[str, Any]:
    """Aggregate coverage records into an additive report block.

    The returned dict is stored on ``WstgCoverageResult.scenario_coverage`` and
    rendered alongside (not instead of) tool-based WSTG coverage.
    """
    record_list = list(records)
    by_status: dict[str, int] = {status.value: 0 for status in CoverageStatus}
    for record in record_list:
        by_status[record.coverage_status.value] += 1

    executed = sum(1 for r in record_list if r.executed)
    confirmed = by_status[CoverageStatus.CONFIRMED_FINDING.value]

    return {
        "wstg_version": wstg_version,
        "total_scenarios": len(record_list),
        "executed": executed,
        "confirmed_findings": confirmed,
        "by_status": by_status,
        "records": [record.to_dict() for record in record_list],
    }


__all__ = [
    "CoverageStatus",
    "ScenarioCoverageRecord",
    "build_scenario_coverage",
    "build_scenario_coverage_record",
    "map_scenario_status",
]
