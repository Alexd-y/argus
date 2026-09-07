"""Spec-compliant OWASP WSTG v4.2 coverage gate (Track B, §4).

The legacy :func:`src.reports.wstg_coverage.build_wstg_coverage` computes a
*tool-execution heuristic* and counts ``partial * 0.5`` in the headline metric.
The engagement spec forbids that and defines coverage strictly:

    coverage = completed_evidenced_applicable_tests / applicable_tests * 100

Rules enforced here:

* Numerator counts a test ONLY when it is applicable, ``execution_status ==
  completed``, ``result in {pass, fail}`` AND it carries evidence.
* ``partial`` / ``blocked`` / ``failed`` / ``running`` / ``not_started`` and
  ``inconclusive`` / ``not_evaluated`` results contribute **zero** — no 0.5.
* ``not_applicable`` removes a test from the denominator ONLY with a written
  ``exclusion_rationale``; otherwise the test is kept applicable (fail-closed)
  and an audit error is recorded, so exclusions cannot silently inflate the
  score ("Каждое исключение требует обоснования и аудита изменения знаменателя").
* The gate passes only when coverage is **strictly greater** than the threshold
  (default 80.0) — exactly 80% does NOT pass.

This module is pure/deterministic and does not depend on live scan data, so the
formula and gate can be unit-tested independently of an actual WSTG run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

WSTG_VERSION = "4.2"
COVERAGE_GATE_THRESHOLD = 80.0


class ExecutionStatus(StrEnum):
    NOT_STARTED = "not_started"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


class TestResult(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"
    NOT_EVALUATED = "not_evaluated"


@dataclass
class WstgTestState:
    """Per-test execution state used to compute spec-compliant coverage."""

    test_id: str
    execution_status: ExecutionStatus
    result: TestResult = TestResult.NOT_EVALUATED
    evidence_ids: list[str] = field(default_factory=list)
    applicable: bool = True
    exclusion_rationale: str | None = None
    category: str | None = None

    def counts_toward_coverage(self) -> bool:
        """True only for a completed, evidenced, pass/fail applicable test."""
        return (
            self.is_applicable()
            and self.execution_status == ExecutionStatus.COMPLETED
            and self.result in (TestResult.PASS, TestResult.FAIL)
            and bool(self.evidence_ids)
        )

    def is_applicable(self) -> bool:
        """A test is excluded from the denominator only with a rationale.

        ``not_applicable`` without a written ``exclusion_rationale`` is treated
        as applicable (fail-closed) so missing credentials/tools/time cannot be
        laundered into a smaller denominator.
        """
        if self.execution_status == ExecutionStatus.NOT_APPLICABLE and self.exclusion_rationale:
            return False
        return self.applicable if self.applicable is not None else True

    def exclusion_is_unjustified(self) -> bool:
        return (
            self.execution_status == ExecutionStatus.NOT_APPLICABLE
            and not self.exclusion_rationale
        )


@dataclass
class WstgCoverageReport:
    catalog_size: int
    applicable: int
    not_applicable: int
    completed_pass: int
    completed_fail: int
    partial: int
    blocked: int
    failed: int
    running: int
    not_started: int
    inconclusive: int
    counted: int
    coverage_pct: float
    completed_of_catalog_pct: float
    threshold: float
    gate_passed: bool
    exclusion_errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "wstg_version": WSTG_VERSION,
            "catalog_size": self.catalog_size,
            "applicable": self.applicable,
            "not_applicable": self.not_applicable,
            "completed_pass": self.completed_pass,
            "completed_fail": self.completed_fail,
            "partial": self.partial,
            "blocked": self.blocked,
            "failed": self.failed,
            "running": self.running,
            "not_started": self.not_started,
            "inconclusive": self.inconclusive,
            "counted": self.counted,
            "coverage_pct": round(self.coverage_pct, 4),
            "completed_of_catalog_pct": round(self.completed_of_catalog_pct, 4),
            "threshold": self.threshold,
            "gate_passed": self.gate_passed,
            "exclusion_errors": list(self.exclusion_errors),
        }


def compute_wstg_coverage(
    states: list[WstgTestState],
    *,
    catalog_size: int | None = None,
    threshold: float = COVERAGE_GATE_THRESHOLD,
) -> WstgCoverageReport:
    """Compute strict, evidence-based WSTG coverage + gate decision."""
    size = catalog_size if catalog_size is not None else len(states)

    applicable = sum(1 for s in states if s.is_applicable())
    not_applicable = sum(1 for s in states if not s.is_applicable())
    counted = sum(1 for s in states if s.counts_toward_coverage())

    completed_pass = sum(
        1
        for s in states
        if s.execution_status == ExecutionStatus.COMPLETED and s.result == TestResult.PASS
    )
    completed_fail = sum(
        1
        for s in states
        if s.execution_status == ExecutionStatus.COMPLETED and s.result == TestResult.FAIL
    )
    partial = sum(1 for s in states if s.execution_status == ExecutionStatus.PARTIAL)
    blocked = sum(1 for s in states if s.execution_status == ExecutionStatus.BLOCKED)
    failed = sum(1 for s in states if s.execution_status == ExecutionStatus.FAILED)
    running = sum(1 for s in states if s.execution_status == ExecutionStatus.RUNNING)
    not_started = sum(1 for s in states if s.execution_status == ExecutionStatus.NOT_STARTED)
    inconclusive = sum(1 for s in states if s.result == TestResult.INCONCLUSIVE)

    exclusion_errors = [
        f"WSTG test {s.test_id!r} marked not_applicable without exclusion_rationale"
        for s in states
        if s.exclusion_is_unjustified()
    ]

    coverage_pct = (counted / applicable * 100.0) if applicable else 0.0
    completed_of_catalog_pct = (counted / size * 100.0) if size else 0.0
    gate_passed = coverage_pct > threshold and not exclusion_errors

    return WstgCoverageReport(
        catalog_size=size,
        applicable=applicable,
        not_applicable=not_applicable,
        completed_pass=completed_pass,
        completed_fail=completed_fail,
        partial=partial,
        blocked=blocked,
        failed=failed,
        running=running,
        not_started=not_started,
        inconclusive=inconclusive,
        counted=counted,
        coverage_pct=coverage_pct,
        completed_of_catalog_pct=completed_of_catalog_pct,
        threshold=threshold,
        gate_passed=gate_passed,
        exclusion_errors=exclusion_errors,
    )


__all__ = [
    "COVERAGE_GATE_THRESHOLD",
    "WSTG_VERSION",
    "ExecutionStatus",
    "TestResult",
    "WstgCoverageReport",
    "WstgTestState",
    "compute_wstg_coverage",
]
