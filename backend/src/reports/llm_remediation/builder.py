"""Assemble the Valhalla LLM document and assess completeness (VH-LLM-07/10).

The builder turns a :class:`RemediationRunResult` (from the runner) plus minimal
finding metadata into the immutable :class:`ValhallaLlmDocument`. Completeness
is computed from the per-finding analysis statuses and gates the atomic release
(prompt §9, §12): a report may only be published as a completed LLM assessment
when every finding has a validated analysis. Otherwise it is an honest draft
(``incomplete``/``failed``), never a false final.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.reports.llm_remediation.document import (
    AssessmentCompleteness,
    ValhallaFindingNode,
    ValhallaLlmDocument,
)
from src.reports.llm_remediation.runner import RemediationRunResult
from src.reports.llm_remediation.schemas import AnalysisStatus


@dataclass(frozen=True)
class CompletenessAssessment:
    """Result of the LLM-completeness gate."""

    status: AssessmentCompleteness
    reasons: list[str]
    total: int
    validated: int
    needs_review: int
    insufficient_context: int
    failed: int

    @property
    def is_releasable_as_complete(self) -> bool:
        return self.status is AssessmentCompleteness.COMPLETE


def assess_llm_completeness(run_result: RemediationRunResult) -> CompletenessAssessment:
    """Compute the report-level completeness from per-finding statuses."""

    total = len(run_result.results)
    validated = needs_review = insufficient = failed = 0
    reasons: list[str] = []

    for res in run_result.results:
        status = res.llm_analysis_status
        if status == AnalysisStatus.GENERATED_VALIDATED.value:
            validated += 1
        elif status == AnalysisStatus.NEEDS_REVIEW.value:
            needs_review += 1
            reasons.append(f"{res.finding_id}: needs_review")
        elif status == AnalysisStatus.INSUFFICIENT_CONTEXT.value:
            insufficient += 1
            reasons.append(f"{res.finding_id}: insufficient_context")
        else:  # failed / incomplete
            failed += 1
            reasons.append(f"{res.finding_id}: {status}")

    if total == 0:
        status = AssessmentCompleteness.INCOMPLETE
        reasons.append("no findings analysed")
    elif failed > 0:
        status = AssessmentCompleteness.FAILED
    elif needs_review > 0 or insufficient > 0:
        status = AssessmentCompleteness.INCOMPLETE
    else:
        status = AssessmentCompleteness.COMPLETE

    return CompletenessAssessment(
        status=status,
        reasons=reasons,
        total=total,
        validated=validated,
        needs_review=needs_review,
        insufficient_context=insufficient,
        failed=failed,
    )


def build_valhalla_llm_document(
    run_result: RemediationRunResult,
    *,
    report_meta: dict[str, Any],
    finding_meta: dict[str, dict[str, Any]] | None = None,
    canonical_snapshot_hash: str = "",
    locale: str = "ru",
    generated_at: str = "",
) -> ValhallaLlmDocument:
    """Freeze accepted per-finding analyses into the versioned document tree."""

    finding_meta = finding_meta or {}
    nodes: list[ValhallaFindingNode] = []
    for res in run_result.results:
        meta = finding_meta.get(res.finding_id, {})
        nodes.append(
            ValhallaFindingNode(
                finding_id=res.finding_id,
                title=str(meta.get("title", "")),
                severity=str(meta.get("severity", "unknown")),
                verification_status=str(meta.get("verification_status", "not_assessed")),
                llm_analysis_status=res.llm_analysis_status,
                remediation=res.remediation,
                closure=res.closure,
            )
        )

    completeness = assess_llm_completeness(run_result)
    doc = ValhallaLlmDocument(
        report_id=str(report_meta.get("report_id", "")),
        report_version=str(report_meta.get("report_version", "unknown")),
        tenant_id=str(report_meta.get("tenant_id", "")),
        scan_id=str(report_meta.get("scan_id", "")),
        target=str(report_meta.get("target", "")),
        locale=locale,
        canonical_snapshot_hash=canonical_snapshot_hash,
        findings=nodes,
        summary=run_result.summary,
        assessment_completeness=completeness.status,
    )
    return doc.finalized(generated_at=generated_at)


__all__ = [
    "CompletenessAssessment",
    "assess_llm_completeness",
    "build_valhalla_llm_document",
]
