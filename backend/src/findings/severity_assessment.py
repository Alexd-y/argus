"""Deterministic selection of the *effective* severity assessment.

A finding may carry several severity opinions (tool-native rating, CVSS-vector
computation, EPSS/KEV-adjusted view, analyst manual overrides). Persisting each
opinion (``src.db.models.SeverityAssessment``) instead of overwriting a single
field keeps the audit trail and — crucially — makes the effective severity a
**pure function** of the stored rows, so identical data always yields the same
band regardless of write order or read path.

This module owns that pure function plus conflict detection and the manual
override constructor. No I/O — the persistence adapter lives in
``src.db.severity_assessment_store``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final

from src.findings.severity import SeverityBand, normalize_severity


class AssessmentMethod(StrEnum):
    """How a severity opinion was formed, ordered by base trust below."""

    MANUAL_OVERRIDE = "manual_override"
    CONFIRMED_EXPLOIT = "confirmed_exploit"
    CVSS_V3 = "cvss_v3"
    TOOL_NATIVE = "tool_native"
    EPSS_ADJUSTED = "epss_adjusted"
    HEURISTIC = "heuristic"
    PROVISIONAL = "provisional"


#: Base trust rank (higher wins). Manual override is handled separately (it
#: always beats non-overrides) but still appears here for completeness.
_METHOD_TRUST: Final[dict[str, int]] = {
    AssessmentMethod.MANUAL_OVERRIDE: 100,
    AssessmentMethod.CONFIRMED_EXPLOIT: 80,
    AssessmentMethod.CVSS_V3: 60,
    AssessmentMethod.TOOL_NATIVE: 50,
    AssessmentMethod.EPSS_ADJUSTED: 40,
    AssessmentMethod.HEURISTIC: 20,
    AssessmentMethod.PROVISIONAL: 10,
}

#: Trust for an unrecognised method — below every known non-provisional method
#: but above nothing, so unknown opinions never silently win.
_UNKNOWN_METHOD_TRUST: Final[int] = 5

_EPOCH: Final[datetime] = datetime(1970, 1, 1, tzinfo=UTC)


@dataclass(frozen=True)
class AssessmentRecord:
    """Lightweight, storage-agnostic view of a ``SeverityAssessment`` row."""

    assessment_id: str
    method: str
    severity: str
    is_manual_override: bool = False
    created_at: datetime | None = None
    policy_version: str | None = None
    source_ref: str | None = None
    supersedes: str | None = None
    rationale: str | None = None
    override_author: str | None = None
    override_reason: str | None = None
    evidence_ref: tuple[str, ...] = field(default_factory=tuple)

    @property
    def band(self) -> SeverityBand:
        """Canonical band for this opinion (unrecognised → ``unknown``)."""
        return normalize_severity(self.severity)


def _trust(record: AssessmentRecord) -> int:
    return _METHOD_TRUST.get(record.method, _UNKNOWN_METHOD_TRUST)


def _created_ts(record: AssessmentRecord) -> datetime:
    # Missing timestamps sort oldest so a dated opinion always beats an
    # undated one at equal trust; keeps the order total and reproducible.
    return record.created_at or _EPOCH


def _selection_key(record: AssessmentRecord) -> tuple[int, int, float, str]:
    """Total order for effective-assessment selection (higher tuple wins).

    Precedence: manual override → method trust → recency → assessment id
    (lexicographic, as the final deterministic tie-break).
    """
    return (
        1 if record.is_manual_override else 0,
        _trust(record),
        _created_ts(record).timestamp(),
        record.assessment_id,
    )


def _superseded_ids(records: Iterable[AssessmentRecord]) -> set[str]:
    return {r.supersedes for r in records if r.supersedes}


def select_effective_assessment(
    records: Iterable[AssessmentRecord],
) -> AssessmentRecord | None:
    """Return the single effective opinion, or ``None`` when there are none.

    Superseded assessments are excluded (a revision replaces its predecessor).
    Among the rest the winner is fully determined by :func:`_selection_key`, so
    the same set of rows always yields the same result irrespective of input
    order.
    """
    live = list(records)
    if not live:
        return None
    superseded = _superseded_ids(live)
    candidates = [r for r in live if r.assessment_id not in superseded] or live
    return max(candidates, key=_selection_key)


def effective_band(records: Iterable[AssessmentRecord]) -> SeverityBand:
    """Effective severity band; ``unknown`` when there is no assessment."""
    winner = select_effective_assessment(records)
    return winner.band if winner is not None else SeverityBand.UNKNOWN


def conflicting_assessments(
    records: Iterable[AssessmentRecord],
    effective: AssessmentRecord | None = None,
) -> list[AssessmentRecord]:
    """Assessments whose band differs from the effective one.

    Used to surface disagreement (e.g. tool says High, CVSS says Medium) for
    analyst review and to populate ``SeverityAssessment.conflicts_with``.
    """
    live = list(records)
    winner = effective if effective is not None else select_effective_assessment(live)
    if winner is None:
        return []
    return [
        r
        for r in live
        if r.assessment_id != winner.assessment_id and r.band != winner.band
    ]


def build_manual_override(
    *,
    assessment_id: str,
    severity: str,
    author: str,
    reason: str,
    supersedes: str | None = None,
    policy_version: str | None = None,
    created_at: datetime | None = None,
) -> AssessmentRecord:
    """Construct a manual-override :class:`AssessmentRecord` (audit-logged).

    ``author`` and ``reason`` are mandatory — a manual override without an
    accountable author/reason is rejected, so the override log is never empty.
    """
    if not author.strip():
        raise ValueError("manual override requires a non-empty author")
    if not reason.strip():
        raise ValueError("manual override requires a non-empty reason")
    return AssessmentRecord(
        assessment_id=assessment_id,
        method=AssessmentMethod.MANUAL_OVERRIDE.value,
        severity=severity,
        is_manual_override=True,
        created_at=created_at or datetime.now(tz=UTC),
        policy_version=policy_version,
        supersedes=supersedes,
        override_author=author,
        override_reason=reason,
    )


__all__ = [
    "AssessmentMethod",
    "AssessmentRecord",
    "build_manual_override",
    "conflicting_assessments",
    "effective_band",
    "select_effective_assessment",
]
