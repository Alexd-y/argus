"""Phase 1 — the Valhalla release gate must fail *closed* (spec RC-01…RC-04).

An exception inside any sub-check must *add* a ``GATE-ERROR`` blocker, never silently
drop the five checks it guards. A failed report-text render is itself a blocker. The
VP-04 source/section bridge must not false-positive on a normal findings report. An
LLM-merge failure must be reflected in the document (partial / failed + a failure row).
"""

from __future__ import annotations

import types

from src.reports import report_pipeline as rp
from src.reports.report_document import (
    ReportFinding,
    ReportToolRun,
    build_report_document,
)
from src.reports.valhalla_completeness import validate_valhalla_completeness


def _report_data(findings=()):
    return types.SimpleNamespace(findings=list(findings), target="https://t", created_at=None)


def test_gate_fail_closed_on_snapshot_error(monkeypatch):
    """build_snapshot raising must yield a GATE-ERROR blocker, not an empty list (RC-01)."""
    monkeypatch.setattr(rp, "generate_markdown", lambda *a, **k: b"# r\n")

    def boom(*a, **k):
        raise RuntimeError("snap boom")

    monkeypatch.setattr(rp, "build_snapshot_from_report_data", boom)
    blockers = rp._compute_valhalla_release_blockers(
        report_data=_report_data(),
        template_context={},
        requested_tier="valhalla",
        actual_tier="valhalla",
        valhalla_llm_status="ready",
    )
    assert any(b.startswith("GATE-ERROR") for b in blockers), blockers


def test_gate_fail_closed_on_markdown_error(monkeypatch):
    """A failed report-text render is a GATE-ERROR blocker, not a silent text-check pass (RC-02)."""

    def boom(*a, **k):
        raise RuntimeError("md boom")

    monkeypatch.setattr(rp, "generate_markdown", boom)
    doc = build_report_document(scan_id="s", tenant_id="t", target="https://t")
    monkeypatch.setattr(rp, "build_snapshot_from_report_data", lambda *a, **k: doc)
    blockers = rp._compute_valhalla_release_blockers(
        report_data=_report_data(),
        template_context={},
        requested_tier="valhalla",
        actual_tier="valhalla",
        valhalla_llm_status="ready",
    )
    assert any(b.startswith("GATE-ERROR") and "report_text" in b for b in blockers), blockers


def test_vp04_inputs_bridge_no_false_positive():
    """VP-04 bridge: a report WITH findings/tool_runs must not raise a VP-04 violation (RC-03)."""
    doc = build_report_document(
        scan_id="s",
        tenant_id="t",
        target="https://t",
        findings=[ReportFinding(finding_id="F-1", title="x", severity="high")],
        tool_runs=[ReportToolRun(tool_run_id="tr-1", tool_name="nmap")],
    )
    snap, sections = rp._vp04_inputs(doc)
    report = validate_valhalla_completeness(snap, sections)
    assert not any(
        v.source_key in ("findings", "tool_runs") for v in report.violations
    ), report.violations


def test_degrade_document_for_llm_merge_failure():
    """Merge failure marks the doc partial/failed and records a ReportFailure (RC-04)."""
    doc = build_report_document(
        scan_id="s",
        tenant_id="t",
        target="https://t",
        generation_status="ready",
        llm_analysis_status="completed",
    )
    degraded = rp._degrade_doc_for_llm_merge_failure(doc, "merge exploded")
    assert degraded.generation_status == "partial"
    assert degraded.llm_analysis_status == "failed"
    assert any(f.where == "llm_merge" for f in degraded.failures)
