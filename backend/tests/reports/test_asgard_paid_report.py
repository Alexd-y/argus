"""Paid-tier (Asgard) report contract tests.

Covers the product contract from ``docs/develop/PROMPT-asgard-paid-report.md``:
full findings with evidence + remediation, TLS & header analysis, leaked-
credential (dark-web) monitoring, rescan cadence — wider than Midgard, narrower
than Valhalla (no raw/PoC/object-key/phase-artifact leakage), one payload → five
formats with parity, and the fail-closed release gates A-G1..A-G5.

Pure/offline — lives under ``tests/reports/`` (an offline path prefix).
"""

from __future__ import annotations

import csv as _csv
import json

import defusedxml.ElementTree as ET
import pytest
from src.api.schemas import Finding
from src.reports import asgard_completeness as gates
from src.reports import asgard_paid as ap
from src.reports.generators import (
    ReportData,
    ReportSummary,
    generate_csv,
    generate_html,
    generate_json,
    generate_xml,
)
from src.reports.report_bundle import ReportTier
from src.reports.tier_classifier import classify_for_tier

FORBIDDEN_HTML = (
    "Phase Artifacts",
    "Raw Tool Output",
    "Reconnaissance summary",
    "object_key",
    "raw=true",
    "AI generation skipped",
    "could not generate",
)
FORBIDDEN_MACHINE = (
    "raw_request",
    "raw_response",
    "output_raw",
    "object_key",
    "proof_of_concept",
    "phase_outputs",
    "timeline",
    "tool_command",
)


def _finding(**kw) -> Finding:
    base = {"severity": "info", "title": "t", "description": "d", "cwe": "", "cvss": None}
    base.update(kw)
    return Finding(**base)


def _report_data() -> ReportData:
    findings = [
        _finding(
            severity="high",
            title="SQL injection in the login endpoint",
            description="The JSON email field reaches a SQL statement without parameterization.",
            cwe="CWE-89",
            cvss=8.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            owasp_category="A05",
            affected_endpoint="http://t:3000/rest/user/login",
            observed_impact="Authentication bypass and user-table disclosure.",
            evidence_classification="candidate",
            confidence="likely",
            proof_of_concept={"replay_command": ["curl", "-s", "http://t:3000/login"]},
            raw_request="POST /rest/user/login",
        ),
        _finding(
            severity="medium",
            title="Missing HTTP security response headers",
            description="CSP/HSTS/Referrer-Policy/Permissions-Policy absent.",
            cwe="CWE-693",
            cvss=5.3,
            owasp_category="A02",
            affected_asset="http://t:3000/",
            observed_impact="No second line of defense against XSS.",
            evidence_classification="observed",
            confidence="confirmed",
        ),
        _finding(
            severity="info",
            title="Endpoint enumeration baseline",
            description="Baseline application response.",
            owasp_category="A02",
            affected_asset="http://t:3000/",
        ),
    ]
    return ReportData(
        report_id="asgard-77404d8c",
        target="http://t:3000",
        summary=ReportSummary(high=1, medium=1, info=1),
        findings=findings,
        technologies=[],
        scan_id="77404d8c",
        tenant_id="tenant-1",
        created_at="2026-10-14T20:59:13Z",
        timeline=[],
        remediation=["x"],
        hibp_pwned_password_summary={"new_exposures": 0, "total_tracked": 0},
    )


def _projected() -> ReportData:
    return classify_for_tier(_report_data(), ReportTier.ASGARD)


# ---------------------------------------------------------------------------
# Projection
# ---------------------------------------------------------------------------


def test_project_asgard_keeps_dark_web_strips_raw():
    projected = _projected()
    # Dark-web summary is kept (Asgard sells credential monitoring).
    assert projected.hibp_pwned_password_summary is not None
    # Raw artefacts / phase outputs / timeline are stripped.
    assert projected.raw_artifacts == []
    assert projected.phase_outputs == []
    assert projected.timeline == []


# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------


def test_payload_shape_and_contract():
    p = ap.build_asgard_payload(_projected(), {})
    assert set(p) == {
        "meta",
        "severity_counts",
        "findings",
        "tls_analysis",
        "header_analysis",
        "dark_web",
        "owasp_alignment",
        "ai_conclusions",
    }
    assert p["meta"]["tier"] == "asgard"
    assert p["meta"]["plan_price"] == "CA$1,891/month"
    assert p["meta"]["rescan_cadence"] == "4 rescans / month"
    # C1 — all findings present (no Top-N cap), each with remediation.
    assert len(p["findings"]) == 3
    for f in p["findings"]:
        assert f["remediation"]
    # High finding carries evidence + remediation (gate A-G1).
    high = next(f for f in p["findings"] if f["severity"] == "high")
    assert high["evidence"] and high["remediation"]
    assert high["owasp"] == "A03:2021 — Injection"


def test_tls_cleartext_marked_fail():
    p = ap.build_asgard_payload(_projected(), {})
    assert all(r["status"] == "fail" for r in p["tls_analysis"]["rows"])


def test_headers_present_derived_not_guessed():
    # No header data collected → present=False for all, summary says pending.
    p = ap.build_asgard_payload(_projected(), {})
    assert all(r["present"] is False for r in p["header_analysis"]["rows"])


def test_dark_web_counts_only():
    dw = ap.build_asgard_payload(_projected(), {})["dark_web"]
    assert dw["new_exposures"] == 0
    assert dw["rows"] == []  # never plaintext records


# ---------------------------------------------------------------------------
# AI conclusions — gate + fallback
# ---------------------------------------------------------------------------


def test_ai_rejects_skip_placeholder_falls_back():
    ctx = {
        "ai_sections": {
            "vulnerability_description": "AI generation skipped: could not generate content"
        }
    }
    ai = ap.build_ai_conclusions(_projected(), ap.severity_counts(_projected().findings), [], ctx)
    assert "skipped" not in ai["vulnerability_description"].lower()
    assert ai["vulnerability_description"]  # never empty


def test_ai_accepts_clean_llm_text():
    clean = "The assessment identified a probable SQL injection on the login endpoint and several configuration gaps."
    ctx = {"ai_sections": {"vulnerability_description": clean}}
    ai = ap.build_ai_conclusions(_projected(), ap.severity_counts(_projected().findings), [], ctx)
    assert ai["vulnerability_description"] == clean


# ---------------------------------------------------------------------------
# Machine formats — no leak + parity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["json", "xml", "csv"])
def test_machine_formats_no_leak(fmt):
    data = _projected()
    gen = {"json": generate_json, "xml": generate_xml, "csv": generate_csv}[fmt]
    out = gen(data, jinja_context={}, tier="asgard").decode("utf-8")
    low = out.lower()
    for marker in FORBIDDEN_MACHINE:
        assert marker not in low, f"{fmt} leaked {marker!r}"
    assert "x-amz-" not in low


def test_json_matches_schema_shape():
    p = json.loads(generate_json(_projected(), jinja_context={}, tier="asgard"))
    assert p["meta"]["tier"] == "asgard"
    for f in p["findings"]:
        assert {"id", "severity", "cwe", "owasp", "asset", "remediation"} <= set(f)


def test_xml_has_tier_and_location():
    root = ET.fromstring(generate_xml(_projected(), jinja_context={}, tier="asgard"))
    assert root.get("tier") == "asgard"
    assert root.get("schema") == "asgard-v1"
    asset = root.find(".//finding/location/asset")
    assert asset is not None and asset.text


def test_csv_header_matches_contract():
    csv_text = generate_csv(_projected(), jinja_context={}, tier="asgard").decode("utf-8")
    assert csv_text.splitlines()[0] == (
        "id,severity,title,cwe,owasp,cvss,cvss_vector,asset,status,confidence,remediation_summary"
    )


def test_finding_parity_across_formats():
    data = _projected()
    p = json.loads(generate_json(data, jinja_context={}, tier="asgard"))
    json_ids = sorted((f["id"], f["severity"]) for f in p["findings"])

    root = ET.fromstring(generate_xml(data, jinja_context={}, tier="asgard"))
    xml_ids = sorted((f.get("id"), f.get("severity")) for f in root.findall(".//finding"))

    csv_rows = list(
        _csv.reader(
            generate_csv(data, jinja_context={}, tier="asgard").decode("utf-8").splitlines()
        )
    )
    csv_ids = sorted((r[0], r[1]) for r in csv_rows[1:] if r)

    assert json_ids == xml_ids == csv_ids
    assert len(json_ids) == len(data.findings)


# ---------------------------------------------------------------------------
# HTML (also the PDF fallback source)
# ---------------------------------------------------------------------------


def test_html_has_paid_sections_no_leak():
    html = generate_html(_report_data(), jinja_context=None, tier="asgard").decode("utf-8")
    for s in (
        "Severity Summary",
        "TLS &amp; Transport Analysis",
        "HTTP Security Headers",
        "Leaked-Credential Monitoring",
        "OWASP Top 10 Alignment",
        "AI Conclusions",
        "Recommended remediation",
        "4 rescans / month",
    ):
        assert s in html, f"missing section: {s}"
    for s in FORBIDDEN_HTML:
        assert s not in html, f"forbidden string: {s}"
    assert "#00ff9d" in html  # dark theme


# ---------------------------------------------------------------------------
# Release gates (fail-closed)
# ---------------------------------------------------------------------------


def test_gates_pass_on_valid_payload():
    p = ap.build_asgard_payload(_projected(), {})
    rendered = {
        "json": generate_json(_projected(), jinja_context={}, tier="asgard"),
        "csv": generate_csv(_projected(), jinja_context={}, tier="asgard"),
    }
    report = gates.evaluate_asgard_release(p, rendered=rendered)
    assert report.ok, report.blockers()


def test_g1_blocks_high_without_evidence():
    p = ap.build_asgard_payload(_projected(), {})
    # Blank out the high finding's evidence.
    for f in p["findings"]:
        if f["severity"] == "high":
            f["evidence"] = ""
    report = gates.evaluate_asgard_release(p)
    assert not report.ok
    assert any(v.gate == "A-G1" for v in report.violations)


def test_g4_blocks_rawleak():
    p = ap.build_asgard_payload(_projected(), {})
    report = gates.evaluate_asgard_release(p, rendered={"json": b'{"object_key": "recon:abc"}'})
    assert any(v.gate == "A-G4" for v in report.violations)


def test_g2_blocks_missing_paid_section():
    p = ap.build_asgard_payload(_projected(), {})
    p.pop("dark_web")
    report = gates.evaluate_asgard_release(p)
    assert any(v.gate == "A-G2" for v in report.violations)


def test_gates_fail_closed_on_error():
    # A malformed payload (findings not a list) must produce a GATE-ERROR, not pass.
    report = gates.evaluate_asgard_release({"findings": 123})
    assert not report.ok
    assert any("GATE-ERROR" in v.detail for v in report.violations)
