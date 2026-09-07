"""A2 — snapshot findings carry evidence provenance (validator_id + raw_artifact_ref)."""

from __future__ import annotations

from typing import ClassVar

from src.reports.snapshot_builder import build_snapshot_from_report_data


class _Finding:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _ReportData:
    scan_id = "s1"
    tenant_id = "t1"
    target = "alleksy.com"
    evidence: ClassVar[list] = []

    def __init__(self, findings):
        self.findings = findings


def _build(findings):
    return build_snapshot_from_report_data(_ReportData(findings), scan_meta={"scan_id": "s1"})


def test_validator_id_from_source_tool():
    doc = _build([
        _Finding(finding_id="f1", title="TLS weakness", severity="medium", cwe="CWE-326",
                 description="weak tls", validation_status="unverified", confidence="likely",
                 evidence_refs=["tool:testssl"], source_tool="testssl"),
    ])
    assert doc.findings[0].validator_id == "testssl"


def test_raw_artifact_ref_from_poc_key():
    doc = _build([
        _Finding(finding_id="f2", title="Reflected XSS", severity="high", cwe="CWE-79",
                 description="xss", validation_status="validated", confidence="confirmed",
                 evidence_refs=["tool:dalfox"], source_tool="dalfox",
                 proof_of_concept={"screenshot_key": "argus/poc/f2.png"}),
    ])
    assert doc.findings[0].raw_artifact_ref == "argus/poc/f2.png"


def test_missing_provenance_stays_none():
    doc = _build([
        _Finding(finding_id="f3", title="Info", severity="info", cwe=None,
                 description="d", validation_status="missing", confidence="advisory",
                 evidence_refs=[]),
    ])
    f = doc.findings[0]
    assert f.validator_id is None
    assert f.raw_artifact_ref is None
