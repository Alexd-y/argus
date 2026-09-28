"""Phase E.4 — merge the Valhalla LLM tree into the v2 snapshot finding cards."""

from __future__ import annotations

from src.reports.renderers import render_html, render_json, render_markdown, render_xml
from src.reports.report_document import ReportFinding, build_report_document
from src.reports.valhalla_llm_merge import merge_llm_into_document


def _base_doc():
    return build_report_document(
        scan_id="S1",
        tenant_id="T1",
        target="https://example.test",
        findings=[
            ReportFinding(
                finding_id="F-1",
                title="Exposed .env",
                severity="high",
                verification_status="confirmed",
                evidence_ids=["E1"],
                validator_id="nuclei",
            ),
            ReportFinding(
                finding_id="F-2",
                title="Missing CSP",
                severity="low",
                verification_status="suspected",
            ),
        ],
    )


def test_merge_attaches_remediation_and_closure(complete_document):
    doc = merge_llm_into_document(_base_doc(), complete_document)
    by_id = {f.finding_id: f for f in doc.findings}
    assert by_id["F-1"].remediation is not None
    assert by_id["F-1"].remediation.status == "generated_validated"
    assert by_id["F-1"].remediation.permanent_fix
    assert by_id["F-1"].remediation.acceptance_criteria  # measurable
    assert by_id["F-1"].closure is not None
    assert by_id["F-1"].closure.permitted_status  # app-computed status carried through


def test_merge_sets_llm_status_and_completeness(complete_document):
    doc = merge_llm_into_document(_base_doc(), complete_document)
    # All findings validated → complete → completed.
    assert doc.llm_analysis_status == "completed"
    assert doc.assessment_completeness == "complete"


def test_merged_remediation_renders_in_all_formats(complete_document):
    doc = merge_llm_into_document(_base_doc(), complete_document)
    for blob in (render_markdown(doc), render_html(doc), render_xml(doc), render_json(doc)):
        assert "generated_validated" in blob  # remediation status
        assert "file not served" in blob  # acceptance criterion text


def test_merge_recomputes_snapshot_hash(complete_document):
    base = _base_doc()
    merged = merge_llm_into_document(base, complete_document)
    # Content changed (remediation/closure added) → hash must differ.
    assert merged.snapshot_hash != base.snapshot_hash


def test_merge_is_noop_for_unmatched_findings(complete_document):
    doc = build_report_document(
        scan_id="S1",
        tenant_id="T1",
        target="https://example.test",
        findings=[ReportFinding(finding_id="OTHER", title="x", severity="info")],
    )
    merged = merge_llm_into_document(doc, complete_document)
    assert merged.findings[0].remediation is None
    assert merged.findings[0].closure is None
