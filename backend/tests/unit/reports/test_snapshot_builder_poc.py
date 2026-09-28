"""Phase D — snapshot_builder maps PoC / CVSS / surface + senior-gate downgrade."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from src.core.config import settings
from src.reports.snapshot_builder import build_snapshot_from_report_data


def _rd(findings, technologies=None, evidence=None):
    return SimpleNamespace(
        findings=findings,
        evidence=evidence if evidence is not None else [],
        technologies=technologies or [],
        target="https://target.example",
        scan_id="s1",
        tenant_id="t1",
    )


def _evidence_for(finding_id="F-1", object_key="k1"):
    return [{"finding_id": finding_id, "object_key": object_key, "kind": "artifact"}]


def _finding(**kw):
    base = {
        "finding_id": "F-1",
        "title": "SQL Injection in /search",
        "severity": "high",
        "cwe": "CWE-89",
        "description": "sqli",
        "validation_status": "validated",
        "confidence": "confirmed",
        "evidence_refs": ["k1"],
        "source_tool": "sqlmap",
        "proof_of_concept": {
            "tool": "sqlmap",
            "payload": "' OR 1=1 --",
            "curl_command": "curl -sS 'https://t/search?q=x'",
            "request": "GET /search?q=... HTTP/1.1",
            "response": "HTTP/1.1 500 ...",
            "db_error_signature": "SQL syntax",
        },
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.8,
        "owasp_category": "A03:2021",
    }
    base.update(kw)
    return SimpleNamespace(**base)


def test_poc_mapped_into_snapshot_finding():
    doc = build_snapshot_from_report_data(
        _rd([_finding()], evidence=_evidence_for()), scan_meta={"scan_id": "s1"}
    )
    f = doc.findings[0]
    assert f.poc is not None
    assert f.poc.payload == "' OR 1=1 --"
    assert f.poc.command == "curl -sS 'https://t/search?q=x'"
    assert f.poc.http_request.startswith("GET /search")
    assert f.cvss_vector.startswith("AV:N")
    assert f.cvss_score == 9.8
    assert f.owasp_category == "A03:2021"
    assert f.confirmation_class == "sqli"


def test_surface_inventory_from_technologies():
    doc = build_snapshot_from_report_data(
        _rd([_finding()], technologies=["nginx", "PHP"]), scan_meta={"scan_id": "s1"}
    )
    hosts = {s.host for s in doc.surface_inventory}
    techs = {s.technology for s in doc.surface_inventory}
    assert hosts == {"target.example"}
    assert {"nginx", "PHP"} <= techs


def test_senior_gate_off_keeps_confirmed(monkeypatch):
    monkeypatch.setattr(settings, "valhalla_senior_poc_gate_enabled", False)
    doc = build_snapshot_from_report_data(
        _rd([_finding()], evidence=_evidence_for()), scan_meta={"scan_id": "s1"}
    )
    # sqlmap-validated with resolvable evidence → stays confirmed; class recorded.
    assert doc.findings[0].verification_status == "confirmed"
    assert doc.findings[0].downgrade_reason is None


def test_senior_gate_on_downgrades_unproven_class(monkeypatch):
    monkeypatch.setattr(settings, "valhalla_senior_poc_gate_enabled", True)
    # XSS "confirmed" but PoC only reflects a string → not browser execution → downgrade.
    xss = _finding(
        finding_id="F-2",
        title="Reflected XSS in q",
        cwe="CWE-79",
        proof_of_concept={"reflection_context": "html", "payload_reflected": "<x>"},
    )
    doc = build_snapshot_from_report_data(
        _rd([xss], evidence=_evidence_for("F-2", "k1")), scan_meta={"scan_id": "s1"}
    )
    f = doc.findings[0]
    assert f.confirmation_class == "xss"
    assert f.verification_status == "suspected"
    assert f.downgrade_reason and "reflection" in f.downgrade_reason


@pytest.mark.parametrize("gate", [True, False])
def test_confirmation_class_always_recorded(monkeypatch, gate):
    monkeypatch.setattr(settings, "valhalla_senior_poc_gate_enabled", gate)
    doc = build_snapshot_from_report_data(_rd([_finding()]), scan_meta={"scan_id": "s1"})
    assert doc.findings[0].confirmation_class == "sqli"
