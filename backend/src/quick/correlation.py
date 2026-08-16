"""Quick finding correlation — wrap fingerprint keys, never drop evidence.

Multi-tool matches collapse to one logical finding with multiple
occurrences. Duplicates are marked. Contradicting evidence is retained.
Late OAST is append-only and never reopens a cancelled scan.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from src.findings.fingerprint import compute_occurrence_key
from src.findings.lifecycle import FindingOccurrence, FindingState, LogicalFinding
from src.quick.normalize import (
    QuickEvidenceDTO,
    QuickFindingDTO,
    QuickNormalizationResult,
    QuickOccurrenceDTO,
)
from src.quick.provenance import compute_evidence_hash, mint_evidence_id
from src.quick.schemas import FindingTriage, FindingTriageVerdict

_TERMINAL_SCAN_STATUSES: Final[frozenset[str]] = frozenset(
    {
        "cancelled",
        "canceled",
        "completed",
        "failed",
        "timed_out",
        "timeout",
    }
)
_INFORMATIONAL: Final[frozenset[str]] = frozenset({"info", "informational"})
_HIGH_IMPACT: Final[frozenset[str]] = frozenset({"critical", "high"})
_MEDIUM_CONFIDENCE_LOW: Final[float] = 0.35
_MEDIUM_CONFIDENCE_HIGH: Final[float] = 0.75


class CorrelatedFinding(BaseModel):
    """One logical finding after multi-tool merge."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding: QuickFindingDTO
    occurrences: tuple[QuickOccurrenceDTO, ...]
    evidence: tuple[QuickEvidenceDTO, ...]
    contradictions: tuple[StrictStr, ...] = Field(default_factory=tuple)


class LateOastResult(BaseModel):
    """Append-only late OAST occurrence. Scan status is never moved to running."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding: QuickFindingDTO
    occurrence: QuickOccurrenceDTO
    evidence: QuickEvidenceDTO
    scan_reopened: bool = False
    scan_was_terminal: bool = False
    accepted: bool = True


def _unique(items: Sequence[str]) -> tuple[str, ...]:
    seen: list[str] = []
    present: set[str] = set()
    for item in items:
        if item and item not in present:
            seen.append(item)
            present.add(item)
    return tuple(seen)


def _merge_hypothesis(
    current: dict[str, Any] | None,
    incoming: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if not current and not incoming:
        return None
    merged: dict[str, Any] = dict(current or {})
    for key, value in (incoming or {}).items():
        if key not in merged:
            merged[key] = value
    return merged or None


def _verdict_rank(verdict: FindingTriageVerdict) -> int:
    order = {
        FindingTriageVerdict.HYPOTHESIS: 0,
        FindingTriageVerdict.FALSE_POSITIVE_CANDIDATE: 1,
        FindingTriageVerdict.NEEDS_VERIFICATION: 2,
        FindingTriageVerdict.LIKELY: 3,
        FindingTriageVerdict.CONFIRMED: 4,
    }
    return order.get(verdict, 0)


def _severity_rank(severity: str) -> int:
    order = {"info": 0, "informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(severity.lower(), 2)


def _contradictions_for(left: QuickFindingDTO, right: QuickFindingDTO) -> tuple[str, ...]:
    notes: list[str] = []
    if left.severity != right.severity:
        notes.append(f"severity:{left.severity}!={right.severity}")
    if abs(left.confidence - right.confidence) >= 0.35:
        notes.append("confidence_gap")
    if left.verdict != right.verdict:
        notes.append(f"verdict:{left.verdict.value}!={right.verdict.value}")
    if left.template_id and right.template_id and left.template_id != right.template_id:
        notes.append("multi_template")
    if left.tool_id != right.tool_id:
        notes.append(f"multi_tool:{left.tool_id}+{right.tool_id}")
    return tuple(notes)


def _merged_verdict(
    left: QuickFindingDTO,
    right: QuickFindingDTO,
    contradictions: Sequence[str],
) -> FindingTriageVerdict:
    joined = " ".join(contradictions)
    if "severity:" in joined or "confidence_gap" in contradictions:
        return FindingTriageVerdict.NEEDS_VERIFICATION
    if _verdict_rank(right.verdict) > _verdict_rank(left.verdict):
        return right.verdict
    return left.verdict


def _merge_pair(left: CorrelatedFinding, incoming: QuickNormalizationResult) -> CorrelatedFinding:
    finding = left.finding
    other = incoming.finding
    contradictions = _unique((*left.contradictions, *_contradictions_for(finding, other)))
    occ_map = {item.occurrence_key: item for item in left.occurrences}
    occ_map[incoming.occurrence.occurrence_key] = incoming.occurrence
    ev_map = {item.evidence_id: item for item in left.evidence}
    ev_map[incoming.evidence.evidence_id] = incoming.evidence
    evidence_ids = _unique((*finding.evidence_ids, incoming.evidence.evidence_id))
    occurrence_keys = _unique((*finding.occurrence_keys, incoming.occurrence.occurrence_key))
    contradicting_ids = evidence_ids if contradictions else finding.contradicting_evidence_ids
    higher = other if _severity_rank(other.severity) > _severity_rank(finding.severity) else finding
    merged = finding.model_copy(
        update={
            "severity": higher.severity,
            "title": finding.title or other.title,
            "confidence": max(finding.confidence, other.confidence),
            "verdict": _merged_verdict(finding, other, contradictions),
            "hypothesis": _merge_hypothesis(finding.hypothesis, other.hypothesis),
            "evidence_ids": evidence_ids,
            "occurrence_keys": occurrence_keys,
            "contradicting_evidence_ids": contradicting_ids,
            "dedup_status": "unique",
            "task_id": finding.task_id or other.task_id,
            "policy_decision_id": finding.policy_decision_id or other.policy_decision_id,
            "lease_id": finding.lease_id or other.lease_id,
        }
    )
    return CorrelatedFinding(
        finding=merged,
        occurrences=tuple(sorted(occ_map.values(), key=lambda item: item.occurrence_key)),
        evidence=tuple(sorted(ev_map.values(), key=lambda item: item.evidence_id)),
        contradictions=contradictions,
    )


def correlate_results(
    results: Sequence[QuickNormalizationResult],
) -> tuple[CorrelatedFinding, ...]:
    """Merge same-fingerprint matches. Evidence is never dropped."""
    buckets: dict[str, CorrelatedFinding] = {}
    for item in results:
        key = item.finding.finding_key
        existing = buckets.get(key)
        if existing is None:
            buckets[key] = CorrelatedFinding(
                finding=item.finding.model_copy(update={"dedup_status": "unique"}),
                occurrences=(item.occurrence,),
                evidence=(item.evidence,),
            )
            continue
        buckets[key] = _merge_pair(existing, item)
    return tuple(buckets[key] for key in sorted(buckets))


def mark_duplicate_occurrences(correlated: CorrelatedFinding) -> CorrelatedFinding:
    """Keep every occurrence; the logical finding stays unique."""
    return correlated.model_copy(
        update={
            "finding": correlated.finding.model_copy(update={"dedup_status": "unique"}),
        }
    )


def overlay_ai_triage(
    correlated: CorrelatedFinding,
    triage: FindingTriage,
) -> CorrelatedFinding:
    """AI may annotate; it cannot delete evidence or be the sole writer."""
    finding = correlated.finding
    hypothesis = finding.hypothesis
    if triage.hypothesis_summary:
        hypothesis = _merge_hypothesis(
            hypothesis,
            {"summary": triage.hypothesis_summary, "source": "ai_overlay"},
        )
    verdict = finding.verdict
    if (
        _verdict_rank(triage.verdict) < _verdict_rank(verdict)
        and verdict is FindingTriageVerdict.CONFIRMED
    ):
        verdict = FindingTriageVerdict.NEEDS_VERIFICATION
    elif verdict is FindingTriageVerdict.HYPOTHESIS:
        verdict = triage.verdict
    elif triage.verdict is FindingTriageVerdict.FALSE_POSITIVE_CANDIDATE:
        verdict = FindingTriageVerdict.FALSE_POSITIVE_CANDIDATE
    updated = finding.model_copy(
        update={
            "verdict": verdict,
            "confidence": max(finding.confidence, triage.confidence),
            "hypothesis": hypothesis,
            "evidence_ids": finding.evidence_ids,
            "occurrence_keys": finding.occurrence_keys,
            "contradicting_evidence_ids": finding.contradicting_evidence_ids,
        }
    )
    return correlated.model_copy(update={"finding": updated})


def needs_selective_verification(
    finding: QuickFindingDTO,
    *,
    has_contradiction: bool = False,
) -> bool:
    """Critical/high, medium-confidence, or contradictions — never informational."""
    severity = finding.severity.lower()
    if severity in _INFORMATIONAL:
        return False
    if severity in _HIGH_IMPACT:
        return True
    if has_contradiction:
        return True
    return _MEDIUM_CONFIDENCE_LOW <= finding.confidence <= _MEDIUM_CONFIDENCE_HIGH


def select_verification_candidates(
    correlated: Sequence[CorrelatedFinding],
) -> tuple[CorrelatedFinding, ...]:
    """Findings that may spend verification reserve. Informational is excluded."""
    selected: list[CorrelatedFinding] = []
    for item in correlated:
        if needs_selective_verification(
            item.finding,
            has_contradiction=bool(item.contradictions),
        ):
            selected.append(item)
    return tuple(selected)


def append_late_oast(
    correlated: CorrelatedFinding,
    *,
    payload: Mapping[str, Any],
    scan_status: str,
    tool_id: str = "oast",
    tool_version: str = "unknown",
) -> LateOastResult:
    """Append an OAST occurrence after deadline. Never reopen a cancelled scan."""
    finding = correlated.finding
    reopen_forbidden = scan_must_not_reopen(scan_status)
    llm_payload = {
        "tool_id": tool_id,
        "kind": "late_oast",
        "matched_at": str(payload.get("matched_at") or finding.endpoint),
        "interaction_id": str(payload.get("interaction_id") or payload.get("id") or ""),
    }
    evidence_hash = compute_evidence_hash(llm_payload)
    evidence_id = mint_evidence_id(
        scan_id=finding.scan_id,
        task_id=finding.task_id,
        evidence_hash=evidence_hash,
    )
    detector_id = str(payload.get("template_id") or finding.template_id or tool_id)
    occurrence_key = compute_occurrence_key(
        finding_key=finding.finding_key,
        scanner=tool_id,
        detector_id=detector_id,
        detector_version=tool_version,
        request_signature=str(payload.get("callback") or finding.endpoint or finding.finding_key),
        evidence_signal_hash=evidence_hash,
    )
    occurrence = QuickOccurrenceDTO(
        occurrence_key=occurrence_key,
        finding_key=finding.finding_key,
        scanner=tool_id,
        detector_id=detector_id,
        detector_version=tool_version,
        evidence_ids=(evidence_id,),
        protocol=finding.protocol,
        parameter=finding.parameter,
        endpoint=finding.endpoint,
        late_oast=True,
        request_signature=str(payload.get("callback") or finding.endpoint),
    )
    evidence = QuickEvidenceDTO(
        evidence_id=evidence_id,
        evidence_hash=evidence_hash,
        tool_id=tool_id,
        tool_version=tool_version,
        template_id=finding.template_id,
        payload=llm_payload,
    )
    updated = finding.model_copy(
        update={
            "evidence_ids": _unique((*finding.evidence_ids, evidence_id)),
            "occurrence_keys": _unique((*finding.occurrence_keys, occurrence_key)),
            "verdict": (
                FindingTriageVerdict.LIKELY
                if finding.verdict is FindingTriageVerdict.HYPOTHESIS
                else finding.verdict
            ),
        }
    )
    return LateOastResult(
        finding=updated,
        occurrence=occurrence,
        evidence=evidence,
        scan_reopened=False,
        scan_was_terminal=reopen_forbidden,
        accepted=True,
    )


def scan_must_not_reopen(scan_status: str) -> bool:
    """True when late OAST must not move the scan back to running."""
    return (scan_status or "").strip().lower() in _TERMINAL_SCAN_STATUSES


def to_logical_finding(correlated: CorrelatedFinding) -> LogicalFinding:
    """Project a correlated Quick finding onto the existing lifecycle model."""
    finding = correlated.finding
    return LogicalFinding(
        finding_key=finding.finding_key,
        tenant_id=finding.tenant_id,
        engagement_id=finding.engagement_id,
        state=FindingState.CANDIDATE,
        title=finding.title,
        category=finding.category,
        evidence_refs=list(finding.evidence_ids),
        occurrence_keys=list(finding.occurrence_keys),
    )


def to_lifecycle_occurrences(correlated: CorrelatedFinding) -> tuple[FindingOccurrence, ...]:
    """Lifecycle occurrences — all evidence refs retained."""
    now = datetime.now(tz=UTC)
    finding = correlated.finding
    rows: list[FindingOccurrence] = []
    for occ in correlated.occurrences:
        rows.append(
            FindingOccurrence(
                occurrence_key=occ.occurrence_key,
                finding_key=occ.finding_key,
                tenant_id=finding.tenant_id,
                scan_id=finding.scan_id,
                scanner=occ.scanner,
                detector_id=occ.detector_id,
                detector_version=occ.detector_version,
                evidence_refs=occ.evidence_ids,
                first_seen_at=now,
                last_seen_at=now,
            )
        )
    return tuple(rows)
