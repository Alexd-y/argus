"""VH-LLM-07: document tree persistence + completeness (VH-LLM-10 gate)."""

from src.reports.llm_remediation.builder import assess_llm_completeness, build_valhalla_llm_document
from src.reports.llm_remediation.document import AssessmentCompleteness
from src.reports.llm_remediation.runner import FindingAnalysisResult, RemediationRunResult


def test_document_captures_all_findings_and_completeness(complete_document):
    doc = complete_document
    assert [n.finding_id for n in doc.findings] == ["F-1", "F-2"]
    assert doc.assessment_completeness is AssessmentCompleteness.COMPLETE
    assert doc.canonical_snapshot_hash == "snap-hash-1234"
    # F-1 fixed_verified, F-2 not_retested.
    by_id = {n.finding_id: n for n in doc.findings}
    assert by_id["F-1"].closure.permitted_closure_status.value == "fixed_verified"
    assert by_id["F-2"].closure.permitted_closure_status.value == "not_retested"
    assert by_id["F-1"].verification_status == "confirmed"


def test_content_hash_is_deterministic_across_rebuilds(document_factory):
    a = document_factory()
    b = document_factory()
    # Provenance ids/timestamps differ, but content hash excludes them.
    assert a.content_hash == b.content_hash
    assert len(a.content_hash) == 64


def test_completeness_failed_when_any_finding_failed():
    results = [
        FindingAnalysisResult(finding_id="F-1", llm_analysis_status="generated_validated"),
        FindingAnalysisResult(finding_id="F-2", llm_analysis_status="failed"),
    ]
    assessment = assess_llm_completeness(RemediationRunResult(results=results))
    assert assessment.status is AssessmentCompleteness.FAILED
    assert assessment.failed == 1


def test_completeness_incomplete_on_needs_review():
    results = [
        FindingAnalysisResult(finding_id="F-1", llm_analysis_status="generated_validated"),
        FindingAnalysisResult(finding_id="F-2", llm_analysis_status="needs_review"),
    ]
    assessment = assess_llm_completeness(RemediationRunResult(results=results))
    assert assessment.status is AssessmentCompleteness.INCOMPLETE
    assert assessment.needs_review == 1


def test_incomplete_document_marks_status(report_meta):
    results = [FindingAnalysisResult(finding_id="F-1", llm_analysis_status="needs_review")]
    doc = build_valhalla_llm_document(
        RemediationRunResult(results=results), report_meta=report_meta
    )
    assert doc.assessment_completeness is AssessmentCompleteness.INCOMPLETE
