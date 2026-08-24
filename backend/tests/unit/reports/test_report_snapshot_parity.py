"""Report snapshot: evidence gate + 4-format parity (Requirements R6, R7, P4/P5/P7)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from xml.etree.ElementTree import fromstring

import pytest

from src.reports.renderers import render_html, render_json, render_markdown, render_xml
from src.reports.report_document import (
    ReportCoverageItem,
    ReportEvidenceRef,
    ReportFinding,
    ReportToolRun,
    build_report_document,
)

_FIXED_TS = datetime(2026, 1, 1, tzinfo=UTC)


def _sample_doc():
    findings = [
        ReportFinding(
            finding_id="F-1",
            title="SQL Injection in /login",
            severity="critical",
            cwe="CWE-89",
            verification_status="confirmed",
            confidence=0.95,
            evidence_ids=["E-1", "E-2"],
            tool_run_id="TR-1",
        ),
        # provable but no evidence → must be downgraded, must not appear confirmed
        ReportFinding(
            finding_id="F-2",
            title="Alleged RCE (unproven)",
            severity="high",
            verification_status="exploitable",
            confidence=0.4,
            evidence_ids=[],
        ),
        ReportFinding(
            finding_id="F-3",
            title="Missing security header",
            severity="low",
            verification_status="not_tested",
            confidence=0.0,
        ),
    ]
    coverage = [
        ReportCoverageItem(capability_id="cap.sqli", status="tested", evidence_ids=["E-1"]),
        ReportCoverageItem(capability_id="cap.xss", status="not_assessed", reason_code="budget_exhausted"),
        ReportCoverageItem(capability_id="cap.ssrf", status="not_assessed", reason_code="parser_unavailable"),
    ]
    return build_report_document(
        scan_id="scan-123",
        tenant_id="tenant-1",
        target="https://example.com",
        scan_profile="light",
        resolved_scan_mode="standard",
        execution_mode="production",
        nuclei_profile="vuln_default",
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-01T00:10:00Z",
        tool_runs=[ReportToolRun(tool_run_id="TR-1", tool_name="sqlmap", status="ok")],
        coverage=coverage,
        findings=findings,
        evidence_references=[
            ReportEvidenceRef(evidence_id="E-1", kind="http", object_key="k1"),
            ReportEvidenceRef(evidence_id="E-2", kind="artifact", object_key="k2"),
        ],
        limitations=["Budget exhausted before XSS active checks completed."],
        registry_versions={"tools": "t-v1", "payloads": "p-v1", "profile": "v1"},
        generated_at=_FIXED_TS,
    )


def test_evidence_gate_downgrades_unproven_finding():
    doc = _sample_doc()
    f2 = next(f for f in doc.findings if f.finding_id == "F-2")
    assert f2.verification_status == "insufficient_evidence"
    assert any(ve.finding_id == "F-2" and ve.code == "insufficient_evidence" for ve in doc.validation_errors)


def test_no_confirmed_finding_without_evidence_in_any_format():
    """P5 — a provable status may never be presented without evidence refs."""
    doc = _sample_doc()

    # JSON (authoritative structural check).
    data = json.loads(render_json(doc))
    for f in data["findings"]:
        if f["verification_status"] in ("confirmed", "exploitable"):
            assert f["evidence_ids"], f"{f['finding_id']} confirmed without evidence"

    # XML (structural): every finding presented confirmed/exploitable has evidence.
    root = fromstring(render_xml(doc))
    for fe in root.iter("finding"):
        if fe.get("verification_status") in ("confirmed", "exploitable"):
            eids = [e.text for e in fe.find("evidence_ids").iter("evidence_id")]
            assert eids, f"{fe.get('finding_id')} confirmed without evidence in XML"


def _json_sets(doc):
    data = json.loads(render_json(doc))
    finding_ids = {f["finding_id"] for f in data["findings"]}
    severities = sorted(f["severity"] for f in data["findings"])
    evidence_ids = set()
    for f in data["findings"]:
        evidence_ids.update(f["evidence_ids"])
    coverage = {(c["capability_id"], c["status"]) for c in data["coverage"]}
    return finding_ids, severities, evidence_ids, coverage, data["snapshot_hash"]


def test_json_xml_structural_parity():
    doc = _sample_doc()
    j_ids, j_sev, j_ev, j_cov, j_hash = _json_sets(doc)

    root = fromstring(render_xml(doc))
    x_ids = {fe.get("finding_id") for fe in root.iter("finding")}
    x_sev = sorted(fe.get("severity") for fe in root.iter("finding"))
    x_ev = {e.text for fe in root.iter("finding") for e in fe.find("evidence_ids").iter("evidence_id")}
    x_cov = {(c.get("capability_id"), c.get("status")) for c in root.iter("capability")}
    x_hash = root.get("snapshot_hash")

    assert x_ids == j_ids
    assert x_sev == j_sev
    assert x_ev == j_ev
    assert x_cov == j_cov
    assert x_hash == j_hash


def test_markdown_html_contain_all_semantic_tokens():
    doc = _sample_doc()
    j_ids, _j_sev, j_ev, j_cov, j_hash = _json_sets(doc)
    md = render_markdown(doc)
    html = render_html(doc)
    for text in (md, html):
        assert j_hash in text
        for fid in j_ids:
            assert fid in text
        for eid in j_ev:
            assert eid in text
        for cap, status in j_cov:
            assert cap in text
        for lim in doc.limitations:
            assert lim in text


def test_findings_count_parity_across_formats():
    doc = _sample_doc()
    data = json.loads(render_json(doc))
    n = len(data["findings"])
    root = fromstring(render_xml(doc))
    assert int(root.find("findings").get("count")) == n
    md = render_markdown(doc)
    assert f"## Findings ({n})" in md
    html = render_html(doc)
    assert f"<h2>Findings ({n})</h2>" in html


def test_snapshot_hash_idempotent():
    """P7 — identical input → identical hash (excluding generated_at)."""
    a = _sample_doc()
    b = _sample_doc()
    assert a.snapshot_hash == b.snapshot_hash


def test_snapshot_hash_changes_with_content():
    a = _sample_doc()
    b = build_report_document(
        scan_id="scan-123",
        tenant_id="tenant-1",
        target="https://example.com",
        findings=[ReportFinding(finding_id="F-9", title="new", severity="info")],
        generated_at=_FIXED_TS,
    )
    assert a.snapshot_hash != b.snapshot_hash


def test_generated_at_does_not_affect_hash():
    base = _sample_doc()
    later = base.model_copy(update={"generated_at": "2099-01-01T00:00:00Z"})
    assert later.compute_hash() == base.compute_hash()


def test_no_findings_reports_not_assessed():
    doc = build_report_document(
        scan_id="s",
        tenant_id="t",
        target="https://x.test",
        findings=[],
        generated_at=_FIXED_TS,
    )
    md = render_markdown(doc)
    html = render_html(doc)
    assert "not_assessed" in md
    assert "not_assessed" in html


@pytest.mark.parametrize("renderer", [render_json, render_markdown, render_xml, render_html])
def test_all_renderers_emit_snapshot_hash(renderer):
    doc = _sample_doc()
    assert doc.snapshot_hash in renderer(doc)
