"""Canonical snapshot builder + 4-format bundle pipeline glue (R7)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

from src.reports.canonical_bundle import bundle_formats, render_canonical_bundle
from src.reports.snapshot_builder import build_snapshot_from_report_data

_FIXED_TS = datetime(2026, 1, 1, tzinfo=UTC)


@dataclass
class FakeFinding:
    finding_id: str | None
    severity: str
    title: str = "t"
    description: str = ""
    cwe: str | None = None
    confidence: str = "possible"
    validation_status: str = "unverified"
    evidence_refs: list[str] = field(default_factory=list)
    tool_run_id: str | None = None


@dataclass
class FakeReportData:
    target: str = "https://example.com"
    scan_id: str = "scan-1"
    tenant_id: str = "tenant-1"
    created_at: str = "2026-01-01T00:10:00Z"
    findings: list[FakeFinding] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)


@dataclass
class FakeScanRow:
    scan_profile: str = "light"
    resolved_scan_mode: str = "standard"
    execution_mode: str = "production"
    quick_profile: str | None = None
    nuclei_profile: str = "vuln_default"
    scan_mode: str = "standard"


@dataclass
class FakeScanReportData:
    scan: FakeScanRow = field(default_factory=FakeScanRow)
    tool_runs: list[dict] = field(default_factory=list)
    coverage_occurrence: list[dict] = field(default_factory=list)


def _report_data():
    return FakeReportData(
        findings=[
            FakeFinding("F-1", "critical", cwe="CWE-89", confidence="confirmed",
                        validation_status="validated", evidence_refs=["E-1"], tool_run_id="TR-1"),
            # validated but no evidence → evidence gate must downgrade
            FakeFinding("F-2", "high", confidence="confirmed", validation_status="validated"),
            FakeFinding("F-3", "low", confidence="possible", validation_status="unverified"),
        ],
        evidence=[{"object_key": "E-1", "kind": "http", "finding_id": "F-1"}],
    )


def _snapshot():
    return build_snapshot_from_report_data(
        _report_data(),
        scan_report_data=FakeScanReportData(
            tool_runs=[{"id": "TR-1", "tool_name": "sqlmap", "status": "ok"}],
            coverage_occurrence=[
                {"capability_id": "cap.sqli", "status": "tested", "evidence_ids": ["E-1"]},
                {"capability_id": "cap.xss", "status": "not_assessed", "reason_code": "budget_exhausted"},
            ],
        ),
        generated_at=_FIXED_TS,
    )


def test_snapshot_maps_metadata_and_findings():
    doc = _snapshot()
    assert doc.scan_profile == "light"
    assert doc.execution_mode == "production"
    assert doc.nuclei_profile == "vuln_default"
    assert len(doc.findings) == 3
    f1 = next(f for f in doc.findings if f.finding_id == "F-1")
    assert f1.verification_status == "confirmed"
    assert f1.evidence_ids == ["E-1"]
    assert f1.confidence == 0.95


def test_evidence_gate_downgrades_validated_without_evidence():
    doc = _snapshot()
    f2 = next(f for f in doc.findings if f.finding_id == "F-2")
    assert f2.verification_status == "insufficient_evidence"
    assert any(ve.finding_id == "F-2" for ve in doc.validation_errors)


def test_coverage_split_tested_vs_not_assessed():
    doc = _snapshot()
    assert "cap.sqli" in doc.tested_capabilities
    assert "cap.xss" in doc.not_assessed_capabilities


def test_bundle_emits_json_md_xml():
    doc = _snapshot()
    artifacts = render_canonical_bundle(doc)
    assert bundle_formats(artifacts) == {"json", "md", "xml"}
    for a in artifacts:
        assert a.size == len(a.content)
        assert len(a.checksum) == 64
        assert a.snapshot_hash == doc.snapshot_hash
        assert a.status == "ready"


def test_bundle_json_is_parseable_and_consistent():
    doc = _snapshot()
    artifacts = render_canonical_bundle(doc)
    js = next(a for a in artifacts if a.format == "json")
    data = json.loads(js.content.decode("utf-8"))
    assert data["snapshot_hash"] == doc.snapshot_hash
    assert len(data["findings"]) == 3


def test_bundle_is_idempotent_for_text_formats():
    doc = _snapshot()
    a = {art.format: art.checksum for art in render_canonical_bundle(doc)}
    b = {art.format: art.checksum for art in render_canonical_bundle(doc)}
    assert a == b  # deterministic json/md/xml


def test_bundle_pdf_via_injected_renderer():
    doc = _snapshot()
    artifacts = render_canonical_bundle(
        doc, include_pdf=True, html_to_pdf=lambda html: b"%PDF-1.4 fake"
    )
    assert "pdf" in bundle_formats(artifacts)
    pdf = next(a for a in artifacts if a.format == "pdf")
    assert pdf.content.startswith(b"%PDF")


def test_bundle_pdf_absent_when_backend_unavailable():
    doc = _snapshot()
    artifacts = render_canonical_bundle(doc, include_pdf=True, html_to_pdf=lambda html: None)
    assert "pdf" not in bundle_formats(artifacts)  # skipped gracefully
    assert {"json", "md", "xml"} <= bundle_formats(artifacts)
