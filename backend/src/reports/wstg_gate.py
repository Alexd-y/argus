"""Deterministic OWASP WSTG v4.2 coverage gate (ARGUS-WSTG-COV-1).

This is the **pure** scoring + integrity core. It performs no IO: evidence has
already been resolved/validated (``WstgTestState.evidence_validated``) and
applicability has already been decided before a state reaches this module. That
keeps ``compute_wstg_coverage`` unit-testable and free of network access
(``docs/wstg-coverage.md`` §"Math & integrity").

Coverage math (ARGUS-WSTG-COV-1 §Math):

    catalog_total          = size of the versioned catalog
    in_scope_total         = in-scope tests
    validated_not_applicable = tests with a *valid* N/A decision
    denominator            = in_scope_total - validated_not_applicable
    counted                = fully-completed, evidence-validated, determined tests
    coverage_pct           = counted / denominator * 100      (None if denominator == 0)
    completed_of_catalog_pct = counted / catalog_total * 100

``unknown`` / ``blocked`` / ``unsupported`` / ``manual_required`` remain in the
denominator. Repeats and empty scenario plans never inflate the numerator (that
is handled upstream in ``wstg_execution``). On any integrity violation, or a
zero denominator, ``coverage_pct`` is ``None`` and the gate does not pass — the
subsystem never returns a plausible-but-unverified percentage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from src.reports.wstg_model import (
    Applicability,
    AssessmentStatus,
    ExecutionStatus,
    Outcome,
    Scope,
    WstgTestState,
)

WSTG_VERSION = "4.2"
COVERAGE_GATE_THRESHOLD = 80.0
POLICY_VERSION = "argus-wstg-cov-1"

# Legacy alias: external callers historically imported ``TestResult``. It is the
# security ``Outcome`` dimension under the new model.
TestResult = Outcome


class IntegrityCode(StrEnum):
    """Structured data-integrity error codes surfaced by the gate."""

    DUPLICATE_TEST_ID = "duplicate_test_id"
    UNKNOWN_TEST_ID = "unknown_test_id"
    MISSING_CATALOG_TEST = "missing_catalog_test"
    UNJUSTIFIED_EXCLUSION = "unjustified_exclusion"
    BLANK_RATIONALE = "blank_rationale"
    NA_CONTRADICTED_BY_FINDING = "na_contradicted_by_finding"
    STATE_CONFLICT = "state_conflict"
    COMPLETED_WITHOUT_EVIDENCE = "completed_without_evidence"
    CATALOG_CHECKSUM_MISMATCH = "catalog_checksum_mismatch"


@dataclass(frozen=True)
class IntegrityError:
    code: IntegrityCode
    test_id: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code.value, "test_id": self.test_id, "detail": self.detail}


@dataclass
class WstgCoverageReport:
    """Immutable coverage result. ``coverage_pct`` is ``None`` when undefined."""

    catalog_total: int
    in_scope_total: int
    validated_not_applicable: int
    denominator: int
    counted: int
    coverage_pct: float | None
    completed_of_catalog_pct: float | None
    # execution/outcome breakdown (diagnostic)
    completed_pass: int
    completed_fail: int
    partial: int
    blocked: int
    failed: int
    running: int
    not_started: int
    inconclusive: int
    unknown_applicability: int
    out_of_scope: int
    # gate + verdict
    threshold: float
    coverage_gate_passed: bool
    evidence_integrity_passed: bool
    required_scenarios_completed: bool
    assessment_status: AssessmentStatus
    integrity_errors: list[IntegrityError] = field(default_factory=list)
    # provenance
    wstg_version: str = WSTG_VERSION
    policy_version: str = POLICY_VERSION
    catalog_checksum: str | None = None
    scope_version: str | None = None

    # -- back-compat helpers -------------------------------------------------
    @property
    def applicable(self) -> int:
        """Legacy alias: the denominator (in-scope, non-validly-excluded)."""
        return self.denominator

    @property
    def not_applicable(self) -> int:
        return self.validated_not_applicable

    @property
    def gate_passed(self) -> bool:
        """Legacy alias retained for existing callers/UI (deprecated).

        Semantics: coverage gate passed AND evidence integrity intact. This is a
        *coverage* signal, never a security assurance.
        """
        return self.coverage_gate_passed and self.evidence_integrity_passed

    @property
    def exclusion_errors(self) -> list[str]:
        """Legacy alias: human-readable strings for unjustified exclusions."""
        return [
            e.detail
            for e in self.integrity_errors
            if e.code in (IntegrityCode.UNJUSTIFIED_EXCLUSION, IntegrityCode.BLANK_RATIONALE)
        ]

    def as_dict(self) -> dict[str, object]:
        cov = None if self.coverage_pct is None else round(self.coverage_pct, 4)
        cat = (
            None
            if self.completed_of_catalog_pct is None
            else round(self.completed_of_catalog_pct, 4)
        )
        return {
            # provenance / versions
            "schema_version": 2,
            "wstg_version": self.wstg_version,
            "policy_version": self.policy_version,
            "catalog_checksum": self.catalog_checksum,
            "scope_version": self.scope_version,
            # math
            "catalog_total": self.catalog_total,
            "catalog_size": self.catalog_total,  # back-compat
            "in_scope_total": self.in_scope_total,
            "validated_not_applicable": self.validated_not_applicable,
            "denominator": self.denominator,
            "applicable": self.denominator,  # back-compat
            "not_applicable": self.validated_not_applicable,  # back-compat
            "counted": self.counted,
            "coverage_pct": cov,
            "completed_of_catalog_pct": cat,
            # breakdown
            "completed_pass": self.completed_pass,
            "completed_fail": self.completed_fail,
            "partial": self.partial,
            "blocked": self.blocked,
            "failed": self.failed,
            "running": self.running,
            "not_started": self.not_started,
            "inconclusive": self.inconclusive,
            "unknown_applicability": self.unknown_applicability,
            "out_of_scope": self.out_of_scope,
            # gate + verdict
            "threshold": self.threshold,
            "coverage_gate_passed": self.coverage_gate_passed,
            "evidence_integrity_passed": self.evidence_integrity_passed,
            "required_scenarios_completed": self.required_scenarios_completed,
            "assessment_status": self.assessment_status.value,
            "gate_passed": self.gate_passed,  # back-compat (deprecated)
            "integrity_errors": [e.as_dict() for e in self.integrity_errors],
            "exclusion_errors": list(self.exclusion_errors),  # back-compat
        }


def _detect_integrity_errors(
    states: list[WstgTestState],
    catalog_ids: frozenset[str] | None,
    *,
    catalog_checksum: str | None = None,
    expected_catalog_checksum: str | None = None,
) -> list[IntegrityError]:
    errors: list[IntegrityError] = []

    # Catalog version/checksum drift: the plan was computed against a catalog
    # that no longer matches the expected one (spec §11).
    if (
        expected_catalog_checksum is not None
        and catalog_checksum is not None
        and catalog_checksum != expected_catalog_checksum
    ):
        errors.append(
            IntegrityError(
                IntegrityCode.CATALOG_CHECKSUM_MISMATCH,
                "<catalog>",
                f"catalog checksum {catalog_checksum} != expected {expected_catalog_checksum}",
            )
        )

    # Duplicate test ids.
    seen: dict[str, int] = {}
    for s in states:
        seen[s.test_id] = seen.get(s.test_id, 0) + 1
    for tid, n in seen.items():
        if n > 1:
            errors.append(
                IntegrityError(IntegrityCode.DUPLICATE_TEST_ID, tid, f"appears {n} times")
            )

    if catalog_ids is not None:
        state_ids = set(seen)
        for tid in sorted(state_ids - catalog_ids):
            errors.append(
                IntegrityError(IntegrityCode.UNKNOWN_TEST_ID, tid, "not in versioned catalog")
            )
        # Missing catalog rows shrink coverage completeness — the full set is the
        # catalog, never len(states) supplied by the caller.
        for tid in sorted(catalog_ids - state_ids):
            errors.append(
                IntegrityError(
                    IntegrityCode.MISSING_CATALOG_TEST, tid, "catalog test absent from plan"
                )
            )

    for s in states:
        if s.has_unjustified_exclusion():
            if s.rationale and not s.rationale.strip():
                errors.append(
                    IntegrityError(IntegrityCode.BLANK_RATIONALE, s.test_id, "blank rationale")
                )
            errors.append(
                IntegrityError(
                    IntegrityCode.UNJUSTIFIED_EXCLUSION,
                    s.test_id,
                    "applicable=False without a valid applicability decision",
                )
            )
        elif (
            s.applicability == Applicability.NOT_APPLICABLE
            and s.applicability_valid
            and s.rationale
            and not s.rationale.strip()
        ):
            errors.append(
                IntegrityError(IntegrityCode.BLANK_RATIONALE, s.test_id, "blank rationale")
            )
        if s.na_contradicted_by_finding():
            errors.append(
                IntegrityError(
                    IntegrityCode.NA_CONTRADICTED_BY_FINDING,
                    s.test_id,
                    "excluded as N/A but a confirmed fail exists",
                )
            )
        if s.conflict:
            errors.append(
                IntegrityError(IntegrityCode.STATE_CONFLICT, s.test_id, "unresolved state conflict")
            )
        if (
            s.execution_status == ExecutionStatus.COMPLETED
            and s.outcome in (Outcome.PASS, Outcome.FAIL)
            and not s.evidence_validated
        ):
            errors.append(
                IntegrityError(
                    IntegrityCode.COMPLETED_WITHOUT_EVIDENCE,
                    s.test_id,
                    "completed with a determined outcome but no validated evidence",
                )
            )
    return errors


def _assessment_status(
    *,
    integrity_ok: bool,
    coverage_gate_passed: bool,
    required_scenarios_completed: bool,
    counted: int,
    denominator: int,
) -> AssessmentStatus:
    """Deterministic verdict priority (ARGUS-WSTG-COV-1 §Verdict).

    Priority: invalid > incomplete > limited > complete. ``limited`` vs
    ``incomplete`` is disambiguated purely by whether the coverage gate passed.
    """
    if not integrity_ok:
        return AssessmentStatus.INVALID
    if not required_scenarios_completed or not coverage_gate_passed:
        return AssessmentStatus.INCOMPLETE
    if denominator > 0 and counted == denominator:
        return AssessmentStatus.COMPLETE
    return AssessmentStatus.LIMITED


def compute_wstg_coverage(
    states: list[WstgTestState],
    *,
    catalog_ids: frozenset[str] | None = None,
    catalog_size: int | None = None,
    threshold: float = COVERAGE_GATE_THRESHOLD,
    policy_version: str = POLICY_VERSION,
    wstg_version: str = WSTG_VERSION,
    catalog_checksum: str | None = None,
    expected_catalog_checksum: str | None = None,
    scope_version: str | None = None,
) -> WstgCoverageReport:
    """Compute deterministic, evidence-based WSTG coverage + gate + verdict.

    ``catalog_ids`` is the authoritative full set of catalog test ids; when
    supplied, unknown/missing tests are flagged as integrity errors. ``states``
    must already carry resolved evidence-validation verdicts.

    ``expected_catalog_checksum`` (when supplied) is compared against
    ``catalog_checksum`` — a mismatch is an integrity error that invalidates the
    gate (the plan was built against a drifted catalog).
    """
    catalog_total = (
        len(catalog_ids)
        if catalog_ids is not None
        else (catalog_size if catalog_size is not None else len(states))
    )

    integrity_errors = _detect_integrity_errors(
        states,
        catalog_ids,
        catalog_checksum=catalog_checksum,
        expected_catalog_checksum=expected_catalog_checksum,
    )
    integrity_ok = not integrity_errors

    in_scope = [s for s in states if s.in_scope()]
    in_scope_total = len(in_scope)
    out_of_scope = len(states) - in_scope_total
    validated_na = sum(1 for s in in_scope if s.is_validly_not_applicable())
    denominator = in_scope_total - validated_na
    counted = sum(1 for s in in_scope if s.counts_toward_coverage())

    # diagnostic breakdown (over all states)
    completed_pass = sum(
        1
        for s in states
        if s.execution_status == ExecutionStatus.COMPLETED and s.outcome == Outcome.PASS
    )
    completed_fail = sum(
        1
        for s in states
        if s.execution_status == ExecutionStatus.COMPLETED and s.outcome == Outcome.FAIL
    )
    partial = sum(1 for s in states if s.execution_status == ExecutionStatus.PARTIAL)
    blocked = sum(1 for s in states if s.execution_status == ExecutionStatus.BLOCKED)
    failed = sum(1 for s in states if s.execution_status == ExecutionStatus.FAILED)
    running = sum(1 for s in states if s.execution_status == ExecutionStatus.RUNNING)
    not_started = sum(1 for s in states if s.execution_status == ExecutionStatus.NOT_STARTED)
    inconclusive = sum(1 for s in states if s.outcome == Outcome.INCONCLUSIVE)
    unknown_applicability = sum(1 for s in states if s.applicability == Applicability.UNKNOWN)

    # Math with explicit "undefined" semantics.
    if not integrity_ok or denominator == 0:
        coverage_pct: float | None = None
    else:
        coverage_pct = counted / denominator * 100.0
    completed_of_catalog_pct = (counted / catalog_total * 100.0) if catalog_total else None

    required_scenarios_completed = all(
        s.required_scenarios_completed for s in in_scope if s.counts_toward_coverage()
    )

    # Strictly-greater gate on the unrounded value; integrity must be intact.
    coverage_gate_passed = integrity_ok and coverage_pct is not None and coverage_pct > threshold

    assessment = _assessment_status(
        integrity_ok=integrity_ok,
        coverage_gate_passed=coverage_gate_passed,
        required_scenarios_completed=required_scenarios_completed,
        counted=counted,
        denominator=denominator,
    )

    return WstgCoverageReport(
        catalog_total=catalog_total,
        in_scope_total=in_scope_total,
        validated_not_applicable=validated_na,
        denominator=denominator,
        counted=counted,
        coverage_pct=coverage_pct,
        completed_of_catalog_pct=completed_of_catalog_pct,
        completed_pass=completed_pass,
        completed_fail=completed_fail,
        partial=partial,
        blocked=blocked,
        failed=failed,
        running=running,
        not_started=not_started,
        inconclusive=inconclusive,
        unknown_applicability=unknown_applicability,
        out_of_scope=out_of_scope,
        threshold=threshold,
        coverage_gate_passed=coverage_gate_passed,
        evidence_integrity_passed=integrity_ok,
        required_scenarios_completed=required_scenarios_completed,
        assessment_status=assessment,
        integrity_errors=integrity_errors,
        wstg_version=wstg_version,
        policy_version=policy_version,
        catalog_checksum=catalog_checksum,
        scope_version=scope_version,
    )


__all__ = [
    "COVERAGE_GATE_THRESHOLD",
    "POLICY_VERSION",
    "WSTG_VERSION",
    "Applicability",
    "AssessmentStatus",
    "ExecutionStatus",
    "IntegrityCode",
    "IntegrityError",
    "Outcome",
    "Scope",
    "TestResult",
    "WstgCoverageReport",
    "WstgTestState",
    "compute_wstg_coverage",
]
