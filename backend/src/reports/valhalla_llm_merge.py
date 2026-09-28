"""Merge the Valhalla LLM analysis tree into the canonical v2 snapshot (Phase E.4).

The mandatory per-finding remediation plan and closure conclusion (produced by
``llm_remediation`` on the cloud report LLM) must live **inside** the finding card of
the main document so they print in PDF / MD / JSON / XML — not only in a side artifact
(prompt E.4). This module is a pure projection: it maps the accepted LLM document onto
:class:`ReportDocumentV1`'s ``ReportRemediation`` / ``ReportClosure`` sub-models, sets
the report-level conclusions, and derives the independent release-status fields
(``llm_analysis_status`` / ``assessment_completeness`` / ``generation_status``) from the
LLM assessment completeness. No LLM calls, no DB, no network.
"""

from __future__ import annotations

from src.reports.llm_remediation.document import AssessmentCompleteness, ValhallaLlmDocument
from src.reports.llm_remediation.schemas import (
    FindingClosureConclusion,
    FindingRemediationAnalysis,
    ReportClosureSummary,
)
from src.reports.report_document import (
    ReportClosure,
    ReportConclusions,
    ReportDocumentV1,
    ReportFinding,
    ReportRemediation,
)

#: LLM assessment completeness → snapshot (llm_analysis_status, assessment_completeness).
_COMPLETENESS_MAP: dict[AssessmentCompleteness, tuple[str, str]] = {
    AssessmentCompleteness.COMPLETE: ("completed", "complete"),
    AssessmentCompleteness.INCOMPLETE: ("partial", "partial"),
    AssessmentCompleteness.FAILED: ("failed", "incomplete"),
}


def _join(values: list[str]) -> str | None:
    parts = [str(v).strip() for v in values if str(v).strip()]
    return "; ".join(parts) if parts else None


def _map_remediation(rem: FindingRemediationAnalysis) -> ReportRemediation:
    first_step = rem.permanent_fix_steps[0] if rem.permanent_fix_steps else None
    return ReportRemediation(
        status=rem.analysis_status.value,
        established_or_hypothesis=rem.root_cause.established_or_hypothesis.value,
        temporary_containment=_join(rem.immediate_containment),
        permanent_fix=_join([s.action for s in rem.permanent_fix_steps]),
        preventive_measures=_join(rem.preventive_measures),
        component=first_step.component if first_step else None,
        rollout_order=_join([s.step_id for s in rem.permanent_fix_steps]),
        rollback_risk=(first_step.rollback_considerations if first_step else None),
        acceptance_criteria=[c.measurable_property for c in rem.acceptance_criteria],
        retest_plan=_join([r.procedure for r in rem.retest_plan]),
    )


def _map_closure(clo: FindingClosureConclusion) -> ReportClosure:
    return ReportClosure(
        permitted_status=clo.permitted_closure_status.value,
        what_verified=clo.conclusion_text,
        what_not_verified=_join(clo.unsatisfied_criteria_ids + clo.untested_criteria_ids),
        residual_risk=clo.residual_risk,
        next_step=_join(clo.next_actions),
    )


def _map_conclusions(
    summary: ReportClosureSummary | None,
    existing: ReportConclusions | None,
) -> ReportConclusions:
    base = existing or ReportConclusions()
    if summary is None:
        return base
    priority_plan = [
        {"finding_ids": list(pa.finding_ids), "rationale": pa.rationale}
        for pa in summary.priority_actions
    ]
    return ReportConclusions(
        executive_summary=base.executive_summary,
        business_risk=base.business_risk,
        closure_summary=summary.overall_conclusion,
        priority_plan=priority_plan or base.priority_plan,
    )


def merge_llm_into_document(
    doc: ReportDocumentV1,
    llm_doc: ValhallaLlmDocument,
) -> ReportDocumentV1:
    """Return a finalized copy of ``doc`` with LLM remediation/closure merged in.

    Per-finding remediation and closure are attached to the matching finding card;
    the report-level closure summary and priority plan populate ``conclusions``; and
    the release-status fields are derived from ``llm_doc.assessment_completeness``.
    """
    nodes_by_id = {n.finding_id: n for n in llm_doc.findings}

    def _enrich(f: ReportFinding) -> ReportFinding:
        node = nodes_by_id.get(f.finding_id)
        if node is None:
            return f
        updates: dict = {}
        if node.remediation is not None:
            updates["remediation"] = _map_remediation(node.remediation)
            if node.remediation.root_cause.established_or_hypothesis:
                updates["established_or_hypothesis"] = (
                    node.remediation.root_cause.established_or_hypothesis.value
                )
        if node.closure is not None:
            updates["closure"] = _map_closure(node.closure)
        return f.model_copy(update=updates) if updates else f

    enriched = [_enrich(f) for f in doc.findings]
    llm_status, completeness = _COMPLETENESS_MAP.get(
        llm_doc.assessment_completeness, ("failed", "incomplete")
    )
    conclusions = _map_conclusions(llm_doc.summary, doc.conclusions)

    return doc.model_copy(
        update={
            "findings": enriched,
            "conclusions": conclusions,
            "llm_analysis_status": llm_status,
            "assessment_completeness": completeness,
        }
    ).finalized()


__all__ = ["merge_llm_into_document"]
