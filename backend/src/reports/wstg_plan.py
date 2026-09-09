"""Engagement test plan + fact→state bridge for the WSTG gate (ARGUS-WSTG-COV-1).

Two pure/deterministic pieces:

* :func:`build_engagement_test_plan` snapshots the single versioned WSTG v4.2
  catalog into an initial (all ``not_started``) plan, versioned with a
  deterministic :func:`catalog_checksum`.

* :func:`build_wstg_states` translates the *verified facts* of a run — structured
  applicability decisions, aggregated executions, and already-resolved evidence
  validation verdicts — into :class:`WstgTestState` rows for
  :func:`compute_wstg_coverage`.

Crucially, this module no longer synthesises ``pass`` from the mere presence of a
covering tool or a static evidence id. A test only reaches ``completed`` with a
determined outcome when a real execution says so *and* its evidence validated.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from src.reports.wstg_coverage import _WSTG_TESTS, WSTG_VERSION
from src.reports.wstg_execution import AggregatedTest
from src.reports.wstg_gate import WstgCoverageReport, compute_wstg_coverage
from src.reports.wstg_model import (
    Applicability,
    ApplicabilityDecision,
    ExecutionStatus,
    Outcome,
    ReasonCode,
    Scope,
    WstgTestState,
)


def catalog_ids() -> frozenset[str]:
    """Authoritative full set of catalog test ids (never ``len(states)``)."""
    return frozenset(t.id for t in _WSTG_TESTS)


def catalog_checksum() -> str:
    """Deterministic SHA-256 over the catalog (version + id/name/category)."""
    basis = "|".join(f"{t.id}:{t.name}:{t.category}" for t in _WSTG_TESTS)
    return hashlib.sha256(f"wstg{WSTG_VERSION}|{basis}".encode()).hexdigest()


@dataclass
class EngagementTestPlan:
    """A versioned, per-engagement WSTG test plan."""

    wstg_version: str
    catalog_checksum: str
    states: list[WstgTestState] = field(default_factory=list)

    def test_ids(self) -> list[str]:
        return [s.test_id for s in self.states]

    def coverage(self) -> WstgCoverageReport:
        return compute_wstg_coverage(
            self.states,
            catalog_ids=catalog_ids(),
            catalog_checksum=self.catalog_checksum,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "wstg_version": self.wstg_version,
            "catalog_checksum": self.catalog_checksum,
            "catalog_size": len(_WSTG_TESTS),
            "tests": [
                {
                    "test_id": s.test_id,
                    "category": s.category,
                    "scope": s.scope.value,
                    "applicability": s.applicability.value,
                    "applicability_valid": s.applicability_valid,
                    "reason_code": s.reason_code.value if s.reason_code else None,
                    "rationale": s.rationale,
                    "execution_status": s.execution_status.value,
                    "outcome": s.outcome.value,
                    "evidence_refs": list(s.evidence_refs),
                    "evidence_validated": s.evidence_validated,
                    "required_scenarios_completed": s.required_scenarios_completed,
                    "completion_criteria_met": s.completion_criteria_met,
                    "conflict": s.conflict,
                    "scenario_ids": list(s.scenario_ids),
                }
                for s in self.states
            ],
        }


def build_engagement_test_plan() -> EngagementTestPlan:
    """Snapshot the WSTG catalog into an initial (all not_started) plan."""
    states = [WstgTestState(test_id=tc.id, category=tc.category) for tc in _WSTG_TESTS]
    return EngagementTestPlan(
        wstg_version=WSTG_VERSION,
        catalog_checksum=catalog_checksum(),
        states=states,
    )


def build_wstg_states(
    *,
    decisions: dict[str, ApplicabilityDecision],
    aggregated: dict[str, AggregatedTest] | None = None,
    evidence_validated_by_test: dict[str, bool] | None = None,
    out_of_scope_ids: frozenset[str] = frozenset(),
) -> list[WstgTestState]:
    """Build spec-compliant per-test states from verified facts.

    * ``decisions`` — structured applicability decisions (default applicable).
    * ``aggregated`` — deterministic per-test execution aggregate.
    * ``evidence_validated_by_test`` — the IO layer's verdict on whether the
      test's evidence resolved & validated. Absent/``False`` → the test cannot
      count, even if an execution claims ``completed``.
    """
    agg_map = aggregated or {}
    ev_map = evidence_validated_by_test or {}
    states: list[WstgTestState] = []

    for tc in _WSTG_TESTS:
        decision = decisions.get(tc.id)
        applicability = decision.state if decision else Applicability.APPLICABLE
        applicability_valid = (
            decision.is_valid_not_applicable()
            if (decision and applicability == Applicability.NOT_APPLICABLE)
            else True
        )
        reason_code: ReasonCode | None = decision.reason_code if decision else None
        rationale = decision.rationale if decision else ""

        agg = agg_map.get(tc.id)
        if agg is not None:
            execution_status = agg.execution_status
            outcome = agg.outcome
            evidence_refs = list(agg.evidence_refs)
            required_completed = agg.required_scenarios_completed
            conflict = agg.conflict
            scenario_ids = list(agg.scenario_ids)
        else:
            execution_status = ExecutionStatus.NOT_STARTED
            outcome = Outcome.NOT_EVALUATED
            evidence_refs = []
            required_completed = True
            conflict = False
            scenario_ids = []

        evidence_validated = bool(ev_map.get(tc.id, False))
        completion_criteria_met = (
            execution_status == ExecutionStatus.COMPLETED and required_completed
        )
        scope = Scope.OUT_OF_SCOPE if tc.id in out_of_scope_ids else Scope.IN_SCOPE

        states.append(
            WstgTestState(
                test_id=tc.id,
                category=tc.category,
                scope=scope,
                applicability=applicability,
                applicability_valid=applicability_valid,
                reason_code=reason_code,
                rationale=rationale,
                execution_status=execution_status,
                outcome=outcome,
                evidence_refs=evidence_refs,
                evidence_validated=evidence_validated,
                required_scenarios_completed=required_completed,
                completion_criteria_met=completion_criteria_met,
                conflict=conflict,
                scenario_ids=scenario_ids,
            )
        )
    return states


__all__ = [
    "EngagementTestPlan",
    "build_engagement_test_plan",
    "build_wstg_states",
    "catalog_checksum",
    "catalog_ids",
]
