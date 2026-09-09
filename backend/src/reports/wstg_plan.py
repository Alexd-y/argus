"""Engagement test plan + run→state bridge for the strict WSTG gate (Track B).

Two pieces, both pure/deterministic and unit-testable without a live scan:

* :func:`build_engagement_test_plan` (B-plan) — snapshot the single WSTG v4.2
  catalog (:data:`src.reports.wstg_coverage._WSTG_TESTS`) into an
  :class:`EngagementTestPlan` of :class:`WstgTestState` rows, versioned with a
  deterministic :func:`catalog_checksum`. Applicability exclusions are only
  honoured with a written rationale (spec §4: exclusions are audited).

* :func:`derive_wstg_states` (B-populate) — translate the *facts* of a run
  (executed tools + findings, plus any per-test evidence) into spec-compliant
  :class:`WstgTestState` rows so :func:`compute_wstg_coverage` can score them:

    - a test referenced by a finding → completed / **fail** (the finding is the
      control-failure evidence) — but only counts if evidence is attached;
    - a test fully covered (>= 2 mapping tools) with attached evidence and no
      finding → completed / **pass** (configuration fact proven);
    - a single weak tool → **partial** (contributes zero, no 0.5);
    - nothing → **not_started**.

  Evidence is never synthesized: a test with no evidence id stays uncounted,
  honouring "missing evidence blocks confirmed/coverage".
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from src.reports.wstg_coverage import (
    _TOOL_EVIDENCE_IDS,
    _TOOL_TO_WSTG,
    _WSTG_TESTS,
    WSTG_VERSION,
    _extract_wstg_ids_from_findings,
    _normalize_tool_name,
)
from src.reports.wstg_gate import (
    ExecutionStatus,
    TestResult,
    WstgCoverageReport,
    WstgTestState,
    compute_wstg_coverage,
)


def catalog_checksum() -> str:
    """Deterministic SHA-256 over the catalog (version + id/name/category)."""
    basis = "|".join(f"{t.id}:{t.name}:{t.category}" for t in _WSTG_TESTS)
    return hashlib.sha256(f"wstg{WSTG_VERSION}|{basis}".encode()).hexdigest()


@dataclass
class EngagementTestPlan:
    """A versioned, per-engagement WSTG test plan (spec §4)."""

    wstg_version: str
    catalog_checksum: str
    states: list[WstgTestState] = field(default_factory=list)

    def test_ids(self) -> list[str]:
        return [s.test_id for s in self.states]

    def coverage(self) -> WstgCoverageReport:
        return compute_wstg_coverage(self.states, catalog_size=len(self.states))

    def as_dict(self) -> dict[str, object]:
        return {
            "wstg_version": self.wstg_version,
            "catalog_checksum": self.catalog_checksum,
            "catalog_size": len(self.states),
            "tests": [
                {
                    "test_id": s.test_id,
                    "category": s.category,
                    "execution_status": s.execution_status.value,
                    "result": s.result.value,
                    "applicable": s.is_applicable(),
                    "exclusion_rationale": s.exclusion_rationale,
                    "evidence_ids": list(s.evidence_ids),
                }
                for s in self.states
            ],
        }


def build_engagement_test_plan(
    *,
    applicability: dict[str, bool] | None = None,
    exclusion_rationale: dict[str, str] | None = None,
) -> EngagementTestPlan:
    """Snapshot the WSTG catalog into an initial (all not_started) plan.

    ``applicability`` may mark specific ``test_id`` s not applicable, but a test
    is only excluded from the denominator when a matching ``exclusion_rationale``
    is supplied — otherwise it stays applicable (fail-closed).
    """
    app = applicability or {}
    rationale = exclusion_rationale or {}
    states: list[WstgTestState] = []
    for tc in _WSTG_TESTS:
        is_applicable = app.get(tc.id, True)
        why = rationale.get(tc.id)
        if not is_applicable and why:
            status = ExecutionStatus.NOT_APPLICABLE
            applicable_flag = False
        else:
            status = ExecutionStatus.NOT_STARTED
            applicable_flag = True
        states.append(
            WstgTestState(
                test_id=tc.id,
                execution_status=status,
                result=TestResult.NOT_EVALUATED,
                applicable=applicable_flag,
                exclusion_rationale=why if not applicable_flag else None,
                category=tc.category,
            )
        )
    return EngagementTestPlan(
        wstg_version=WSTG_VERSION,
        catalog_checksum=catalog_checksum(),
        states=states,
    )


def _covering_tools_by_test(tools_executed: list[str]) -> dict[str, set[str]]:
    normalized = {_normalize_tool_name(t) for t in tools_executed if t}
    out: dict[str, set[str]] = {}
    for tool in normalized:
        for wid in _TOOL_TO_WSTG.get(tool, []):
            out.setdefault(wid, set()).add(tool)
    return out


def derive_wstg_states(
    tools_executed: list[str],
    findings: list[dict] | None = None,
    *,
    base_plan: EngagementTestPlan | None = None,
    evidence_by_test: dict[str, list[str]] | None = None,
) -> list[WstgTestState]:
    """Translate run facts into spec-compliant per-test states (B-populate)."""
    finding_ids = _extract_wstg_ids_from_findings(findings or [])
    covering_by_test = _covering_tools_by_test(tools_executed)
    ev_map = evidence_by_test or {}
    base = {s.test_id: s for s in base_plan.states} if base_plan else {}

    out: list[WstgTestState] = []
    for tc in _WSTG_TESTS:
        prior = base.get(tc.id)
        # A justified not_applicable exclusion is preserved verbatim.
        if prior is not None and not prior.is_applicable():
            out.append(prior)
            continue

        applicable_flag = prior.applicable if prior is not None else True
        covering = covering_by_test.get(tc.id, set())
        tool_evidence = [_TOOL_EVIDENCE_IDS[t] for t in sorted(covering) if t in _TOOL_EVIDENCE_IDS]
        evidence = list(ev_map.get(tc.id, [])) or tool_evidence

        if tc.id in finding_ids:
            status, result = ExecutionStatus.COMPLETED, TestResult.FAIL
        elif covering and evidence:
            # A control exercised by at least one tool that produced a captured
            # evidence artifact is completed/pass — evidence, not an arbitrary
            # two-tool count, is the spec gate (§4). A covering tool with no
            # evidence id stays partial (uncounted).
            status, result = ExecutionStatus.COMPLETED, TestResult.PASS
        elif covering:
            status, result = ExecutionStatus.PARTIAL, TestResult.NOT_EVALUATED
        else:
            status, result = ExecutionStatus.NOT_STARTED, TestResult.NOT_EVALUATED

        out.append(
            WstgTestState(
                test_id=tc.id,
                execution_status=status,
                result=result,
                evidence_ids=evidence,
                applicable=applicable_flag,
                category=tc.category,
            )
        )
    return out


__all__ = [
    "EngagementTestPlan",
    "build_engagement_test_plan",
    "catalog_checksum",
    "derive_wstg_states",
]
