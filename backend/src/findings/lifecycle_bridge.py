"""FindingDTO → logical finding + occurrence (WIRE-006).

AI assessments are append-only. They must never delete findings, shrink
occurrence lists, or drop evidence refs. ``classification=contradicted``
is a triage label, not a suppress/delete signal.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Final

from src.core.unified_ai_metrics import record_finding, record_retest
from src.findings.diff import occurrence_from_scan
from src.findings.fingerprint import compute_finding_key
from src.findings.lifecycle import (
    FindingAssessment,
    FindingLifecycleService,
    FindingOccurrence,
    FindingState,
    LogicalFinding,
)
from src.findings.retest import RetestJob, RetestService
from src.pipeline.contracts.finding_dto import FindingDTO

logger = logging.getLogger(__name__)

_DELETE_INTENT_LABELS: Final[frozenset[str]] = frozenset(
    {
        "delete",
        "deleted",
        "suppress",
        "suppressed",
        "drop",
        "remove",
        "purge",
        "erase",
    }
)

_AI_TRIAGE_LABELS: Final[frozenset[str]] = frozenset(
    {
        "supported",
        "contradicted",
        "insufficient",
    }
)


@dataclass(frozen=True)
class FindingIngestContext:
    """Scanner-side identity needed to fingerprint a FindingDTO."""

    engagement_id: str
    asset: str
    location: str
    parameter_or_component: str = ""
    root_cause_family: str = ""
    scanner: str = "unknown"
    detector_id: str = "unknown"
    detector_version: str = "1.0.0"
    request_signature: str = ""
    evidence: dict[str, Any] | str = ""
    title: str = ""
    evidence_refs: tuple[str, ...] = ()

    @classmethod
    def from_dto(cls, dto: FindingDTO, *, engagement_id: str | None = None) -> FindingIngestContext:
        evidence_ids = tuple(str(eid) for eid in dto.evidence_ids)
        return cls(
            engagement_id=(engagement_id or str(dto.scan_id)),
            asset=str(dto.asset_id),
            location=str(dto.asset_id),
            parameter_or_component="",
            root_cause_family=dto.category.value,
            scanner=str(dto.tool_run_id),
            detector_id=dto.category.value,
            detector_version="1.0.0",
            request_signature=str(dto.id),
            evidence={"finding_id": str(dto.id), "evidence_ids": list(evidence_ids)},
            title="",
            evidence_refs=evidence_ids,
        )


@dataclass
class BridgedFinding:
    finding: LogicalFinding
    occurrence: FindingOccurrence


def _merge_unique(existing: Sequence[str], incoming: Sequence[str]) -> list[str]:
    merged = list(existing)
    seen = set(existing)
    for item in incoming:
        if item and item not in seen:
            merged.append(item)
            seen.add(item)
    return merged


def _is_delete_intent(assessment: FindingAssessment) -> bool:
    classification = (assessment.classification or "").strip().lower()
    return classification in _DELETE_INTENT_LABELS


def _extract_ai_classification(finding: Any) -> str:
    if isinstance(finding, dict):
        raw = finding.get("ai_classification") or finding.get("classification")
    else:
        raw = getattr(finding, "ai_classification", None)
        if raw is None:
            raw = getattr(finding, "classification", None)
    if raw is None and not isinstance(finding, dict):
        assessments = getattr(finding, "assessments", None) or ()
        if assessments:
            raw = getattr(assessments[-1], "classification", None)
    return str(raw or "").strip().lower()


def retain_findings_despite_ai_classification[T](findings: Sequence[T]) -> list[T]:
    """Keep every finding, including AI ``contradicted`` / ``insufficient``.

    Triage labels are append-only assessments. They must not remove a finding
    from the report set.
    """
    retained: list[T] = []
    for finding in findings:
        classification = _extract_ai_classification(finding)
        if classification in _AI_TRIAGE_LABELS:
            logger.info(
                "ai_triage_finding_retained",
                extra={
                    "event": "ai_triage_finding_retained",
                    "classification": classification,
                },
            )
        retained.append(finding)
    return retained


def _safe_record_finding(state: str) -> None:
    try:
        record_finding(state=state)
    except Exception:
        logger.debug("lifecycle_bridge.metrics_finding_failed", exc_info=True)


def _safe_record_retest(result: str) -> None:
    try:
        record_retest(result=result)
    except Exception:
        logger.debug("lifecycle_bridge.metrics_retest_failed", exc_info=True)


def _restore_if_shrunk(current: list[str], snapshot: list[str]) -> list[str]:
    if len(current) < len(snapshot):
        return list(snapshot)
    return _merge_unique(snapshot, current)


class FindingLifecycleBridge:
    """Create logical findings/occurrences from DTOs; AI may only append."""

    def __init__(
        self,
        *,
        lifecycle: FindingLifecycleService | None = None,
        retest: RetestService | None = None,
    ) -> None:
        self._lifecycle = lifecycle or FindingLifecycleService()
        self._retest = retest or RetestService(self._lifecycle)
        self._findings: dict[str, LogicalFinding] = {}
        self._occurrences: dict[str, list[FindingOccurrence]] = {}

    @property
    def findings(self) -> dict[str, LogicalFinding]:
        return self._findings

    @property
    def occurrences(self) -> dict[str, list[FindingOccurrence]]:
        return self._occurrences

    def ingest_dto(
        self,
        dto: FindingDTO,
        *,
        context: FindingIngestContext | None = None,
    ) -> BridgedFinding:
        ctx = context or FindingIngestContext.from_dto(dto)
        finding_key = compute_finding_key(
            tenant_id=str(dto.tenant_id),
            engagement_id=ctx.engagement_id,
            asset=ctx.asset,
            category=dto.category.value,
            normalized_location=ctx.location,
            parameter_or_component=ctx.parameter_or_component,
            root_cause_family=ctx.root_cause_family or dto.category.value,
        )
        occurrence = occurrence_from_scan(
            finding_key=finding_key,
            tenant_id=str(dto.tenant_id),
            scan_id=str(dto.scan_id),
            scanner=ctx.scanner,
            detector_id=ctx.detector_id,
            detector_version=ctx.detector_version,
            request_signature=ctx.request_signature or str(dto.id),
            evidence=ctx.evidence or str(dto.id),
            seen_at=dto.last_seen,
        )
        extra_refs = _merge_unique(occurrence.evidence_refs, ctx.evidence_refs)
        extra_refs = _merge_unique(extra_refs, [str(eid) for eid in dto.evidence_ids])
        occurrence = occurrence.model_copy(update={"evidence_refs": tuple(extra_refs)})

        finding = self._findings.get(finding_key)
        if finding is None:
            finding = LogicalFinding(
                finding_key=finding_key,
                tenant_id=str(dto.tenant_id),
                engagement_id=ctx.engagement_id,
                state=FindingState.CANDIDATE,
                title=ctx.title,
                category=dto.category.value,
                evidence_refs=list(occurrence.evidence_refs),
                occurrence_keys=[occurrence.occurrence_key],
            )
            self._findings[finding_key] = finding
            _safe_record_finding(finding.state.value)
        else:
            finding.occurrence_keys = _merge_unique(
                finding.occurrence_keys, [occurrence.occurrence_key]
            )
            finding.evidence_refs = _merge_unique(
                finding.evidence_refs, occurrence.evidence_refs
            )
            if ctx.title and not finding.title:
                finding.title = ctx.title

        occ_list = self._occurrences.setdefault(finding_key, [])
        if all(item.occurrence_key != occurrence.occurrence_key for item in occ_list):
            occ_list.append(occurrence)
        return BridgedFinding(finding=finding, occurrence=occurrence)

    def attach_assessment(
        self,
        finding: LogicalFinding,
        assessment: FindingAssessment,
    ) -> LogicalFinding:
        """Append an AI/analyst assessment. Delete/suppress intent is ignored."""
        occ_snapshot = list(finding.occurrence_keys)
        evidence_snapshot = list(finding.evidence_refs)

        if _is_delete_intent(assessment):
            logger.warning(
                "finding_delete_via_assessment_ignored",
                extra={
                    "event": "finding_delete_via_assessment_ignored",
                    "finding_key": finding.finding_key,
                    "classification": (assessment.classification or ""),
                },
            )

        self._lifecycle.attach_assessment(finding, assessment)

        finding.occurrence_keys = _restore_if_shrunk(finding.occurrence_keys, occ_snapshot)
        finding.evidence_refs = _restore_if_shrunk(finding.evidence_refs, evidence_snapshot)

        _safe_record_finding(finding.state.value)
        return finding

    def mark_resolved_candidate(
        self,
        finding: LogicalFinding,
        *,
        coverage_equivalent: bool,
    ) -> LogicalFinding:
        return self._lifecycle.propose_resolved_candidate(
            finding, coverage_equivalent=coverage_equivalent
        )

    def apply_retest(
        self,
        finding: LogicalFinding,
        job: RetestJob,
    ) -> tuple[LogicalFinding, RetestJob]:
        finding, job = self._retest.apply_result(finding, job)
        _safe_record_retest(job.result.value)
        return finding, job


__all__ = [
    "BridgedFinding",
    "FindingIngestContext",
    "FindingLifecycleBridge",
    "retain_findings_despite_ai_classification",
]
