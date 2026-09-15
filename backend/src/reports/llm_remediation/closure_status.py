"""Deterministic, application-owned computation of a finding's closure status.

The prompt is explicit (§1, §7, L02–L06, L24): *whether* a vulnerability is
closed is decided by verifiable retest results and rules — never by LLM text.
This module computes the ``permitted_closure_status`` that the LLM conclusion
is then clamped to (it may report a weaker claim but never a stronger one).

The computation is intentionally conservative: absence of proof is never
treated as proof of a fix.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from src.reports.llm_remediation.schemas import PermittedClosureStatus


class RetestOutcome(StrEnum):
    """Outcome of a single retest execution against the fixed target."""

    PASS_SECURE = "pass_secure"  # secure behaviour confirmed (fix works)
    FAIL_VULNERABLE = "fail_vulnerable"  # still exploitable
    INCONCLUSIVE = "inconclusive"  # ambiguous result
    UNREACHABLE = "unreachable"  # target down / session expired (L24)
    ERROR = "error"  # tooling error


@dataclass(frozen=True)
class RetestExecution:
    """A single executed retest and which acceptance criteria it exercises."""

    test_id: str
    outcome: RetestOutcome
    criteria_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ClosureComputationInput:
    """Everything the deterministic status rule needs for one finding."""

    finding_id: str
    acceptance_criteria_ids: tuple[str, ...]
    retests: tuple[RetestExecution, ...] = ()
    is_false_positive: bool = False
    risk_accepted: bool = False


@dataclass(frozen=True)
class ClosureComputationResult:
    """Deterministic verdict + the evidence sets that justify it."""

    finding_id: str
    permitted_status: PermittedClosureStatus
    satisfied_criteria_ids: list[str] = field(default_factory=list)
    unsatisfied_criteria_ids: list[str] = field(default_factory=list)
    untested_criteria_ids: list[str] = field(default_factory=list)
    supporting_retest_ids: list[str] = field(default_factory=list)
    supporting_evidence_ids: list[str] = field(default_factory=list)


def _dedupe(values: list[str]) -> list[str]:
    """Order-preserving de-duplication."""

    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def compute_permitted_closure_status(
    data: ClosureComputationInput,
) -> ClosureComputationResult:
    """Compute the strongest closure status the evidence actually supports.

    Precedence (strongest gating conditions first):

    1. ``is_false_positive`` → ``false_positive``.
    2. ``risk_accepted`` → ``risk_accepted`` (never ``fixed_verified``, L06).
    3. No retests executed → ``not_retested`` (L02: describing a fix is not a
       fix; every criterion is untested).
    4. Retests executed but every one was ``unreachable``/``error`` →
       ``inconclusive`` (L24: an unreachable target is not a successful retest).
    5. Every acceptance criterion satisfied by a ``pass_secure`` retest with
       evidence → ``fixed_verified`` (L05).
    6. Some (but not all) criteria satisfied, or any criterion still failing →
       ``partially_fixed`` (L04: one closed asset does not close the rest).
    7. Otherwise (retests ran, nothing satisfied) → ``open``.
    """

    all_criteria = list(data.acceptance_criteria_ids)

    if data.is_false_positive:
        return ClosureComputationResult(
            finding_id=data.finding_id,
            permitted_status=PermittedClosureStatus.FALSE_POSITIVE,
            untested_criteria_ids=list(all_criteria),
        )

    if data.risk_accepted:
        return ClosureComputationResult(
            finding_id=data.finding_id,
            permitted_status=PermittedClosureStatus.RISK_ACCEPTED,
            untested_criteria_ids=list(all_criteria),
        )

    if not data.retests:
        return ClosureComputationResult(
            finding_id=data.finding_id,
            permitted_status=PermittedClosureStatus.NOT_RETESTED,
            untested_criteria_ids=list(all_criteria),
        )

    # Classify criteria against retest outcomes.
    satisfied: list[str] = []
    failed: list[str] = []
    supporting_retests: list[str] = []
    supporting_evidence: list[str] = []
    conclusive_seen = False

    for retest in data.retests:
        if retest.outcome == RetestOutcome.PASS_SECURE:
            conclusive_seen = True
            supporting_retests.append(retest.test_id)
            supporting_evidence.extend(retest.evidence_ids)
            satisfied.extend(retest.criteria_ids)
        elif retest.outcome == RetestOutcome.FAIL_VULNERABLE:
            conclusive_seen = True
            failed.extend(retest.criteria_ids)
        # INCONCLUSIVE / UNREACHABLE / ERROR contribute no criteria evidence.

    satisfied_set = set(satisfied)
    failed_set = set(failed)
    # A criterion proven failing cannot also count as satisfied.
    satisfied_set -= failed_set

    satisfied_ids = _dedupe([c for c in all_criteria if c in satisfied_set])
    unsatisfied_ids = _dedupe([c for c in all_criteria if c in failed_set])
    untested_ids = _dedupe(
        [c for c in all_criteria if c not in satisfied_set and c not in failed_set]
    )

    if not conclusive_seen:
        # Every retest was unreachable/error/inconclusive.
        return ClosureComputationResult(
            finding_id=data.finding_id,
            permitted_status=PermittedClosureStatus.INCONCLUSIVE,
            untested_criteria_ids=list(all_criteria),
        )

    result = ClosureComputationResult(
        finding_id=data.finding_id,
        permitted_status=PermittedClosureStatus.OPEN,
        satisfied_criteria_ids=satisfied_ids,
        unsatisfied_criteria_ids=unsatisfied_ids,
        untested_criteria_ids=untested_ids,
        supporting_retest_ids=_dedupe(supporting_retests),
        supporting_evidence_ids=_dedupe(supporting_evidence),
    )

    if all_criteria and not unsatisfied_ids and not untested_ids and result.supporting_retest_ids:
        # All criteria satisfied by conclusive, evidence-backed retests.
        object.__setattr__(result, "permitted_status", PermittedClosureStatus.FIXED_VERIFIED)
    elif satisfied_ids:
        object.__setattr__(result, "permitted_status", PermittedClosureStatus.PARTIALLY_FIXED)
    else:
        object.__setattr__(result, "permitted_status", PermittedClosureStatus.OPEN)

    return result


__all__ = [
    "ClosureComputationInput",
    "ClosureComputationResult",
    "RetestExecution",
    "RetestOutcome",
    "compute_permitted_closure_status",
]
