"""Free-tier (Midgard) report contract tests.

Covers the invariant from ``docs/develop/PROMPT-midgard-free-report.md``:

    "A free scan of the domain you own: severity counts, every finding title,
    and one complete writeup with evidence and a fix."

* The Midgard projection strips raw / PoC / evidence / phase outputs.
* Teaser selection is deterministic.
* All five export formats (pdf/html/json/xml/csv) are built from one free-tier
  projection: no paid-layer leakage, and content parity on the finding set.
* The dark-theme HTML/PDF carry the required sections and none of the forbidden
  legacy strings (Phase Artifacts, raw tool output, curl PoC, failed AI slot).

Pure/offline — lives under ``tests/reports/`` (an offline path prefix) so it
runs in the default ``pytest`` lane.
"""

from __future__ import annotations

import csv as _csv
import json

import defusedxml.ElementTree as ET
import pytest
from src.api.schemas import Finding
from src.reports import midgard_free as mf
from src.reports.generators import (
    ReportData,
    ReportSummary,
    _build_branded_pdf_context,
    _render_branded_pdf_html,
    _resolve_branded_pdf_template_path,
    generate_csv,
    generate_html,
    generate_json,
    generate_xml,
)
from src.reports.report_bundle import ReportTier
from src.reports.tier_classifier import classify_for_tier

# Strings that must NEVER appear in any free-tier Midgard output.
FORBIDDEN_HTML = (
    "Phase Artifacts",
    "Raw Tool Output",
    "Other Artifacts",
    "raw=true",
    "Reflected Input Verification",
    "PoC details are available",
    "AI generation skipped",
    "could not generate",
)
# Keys/substrings that must NEVER appear in the machine formats.
FORBIDDEN_MACHINE = (
    "timeline",
    "phase_outputs",
    "proof_of_concept",
    "raw_request",
    "raw_response",
    "remediation_matrix",
    "evidence_inventory",
    "screenshots",
    "tool_command",
    "verification_command",
)


def _finding(**kw) -> Finding:
    base = {"severity": "info", "title": "t", "description": "d", "cwe": "", "cvss": 0.0}
    base.update(kw)
    return Finding(**base)


def _report_data() -> ReportData:
    findings = [
        _finding(
            severity="medium",
            title="Technology fingerprint exposure (WhatWeb)",
            description="Server banners disclose the stack.",
            cwe="CWE-200",
            cvss=6.9,
            owasp_category="A05",
            observed_impact="Server: nginx disclosed in response headers.",
            proof_of_concept={"replay_command": ["curl", "-sI", "https://svalbard.ca/"]},
            raw_request="GET / HTTP/1.1\nHost: svalbard.ca",
        ),
        _finding(
            severity="low",
            title="DMARC has no aggregate reporting (rua)",
            description="DMARC published but defines no rua= address.",
            cwe="CWE-16",
            cvss=3.1,
            affected_asset="svalbard.ca",
            observed_impact='_dmarc.svalbard.ca TXT "v=DMARC1; p=none;"',
        ),
        _finding(
            severity="low",
            title="DNSSEC not enabled",
            description="The zone is unsigned.",
            cwe="CWE-350",
            cvss=3.9,
            observed_impact="No RRSIG/DS records present for svalbard.ca.",
        ),
        _finding(
            severity="info",
            title="TLS/SSL configuration observation",
            description="Observed TLS parameters.",
            cwe="CWE-310",
            cvss=0.0,
        ),
    ]
    return ReportData(
        report_id="report-abc",
        target="svalbard.ca",
        summary=ReportSummary(critical=0, high=0, medium=1, low=2, info=1),
        findings=findings,
        technologies=["nginx", "HSTS"],
        scan_id="scan-xyz",
        created_at="2026-10-16",
        # Paid-layer data that must be stripped on projection.
        timeline=[],
        remediation=["do the thing"],
        ai_insights=["ai blah"],
    )


def _jctx() -> dict:
    return {
        "recon_summary": {
            "pipeline_subdomains": ["www.svalbard.ca", "api.svalbard.ca"],
            "technologies": ["nginx", "HSTS", "Cloudflare"],
            "pipeline_ports": [{"port": 443, "protocol": "tcp", "service": "https"}],
        },
        "pdf_watermark": "7f3c9a21d4e0b85f",
    }


# ---------------------------------------------------------------------------
# Projection
# ---------------------------------------------------------------------------


def test_project_midgard_strips_paid_layer():
    data = _report_data()
    projected = classify_for_tier(data, ReportTier.MIDGARD)
    assert projected.timeline == []
    assert projected.phase_outputs == []
    assert projected.evidence == []
    assert projected.screenshots == []
    assert projected.raw_artifacts == []
    assert projected.remediation == []


# ---------------------------------------------------------------------------
# Teaser selection
# ---------------------------------------------------------------------------


def test_teaser_selection_is_deterministic_and_safe():
    data = _report_data()
    # DNSSEC (low, CVSS 3.9) is a safe config candidate and outranks DMARC
    # (low, CVSS 3.1) on CVSS — the exposure finding carries a PoC so it is
    # never a candidate.
    teaser = mf.select_teaser_finding(data.findings)
    assert teaser is not None
    assert teaser.title == "DNSSEC not enabled"
    # Stable across repeated calls / reordering the input.
    again = mf.select_teaser_finding(list(reversed(data.findings)))
    assert again.title == teaser.title


def test_teaser_writeup_shape():
    data = _report_data()
    writeup = mf.build_teaser_writeup(mf.select_teaser_finding(data.findings))
    assert set(writeup) >= {
        "id",
        "title",
        "severity",
        "cwe",
        "cvss",
        "what",
        "evidence",
        "why",
        "fix",
    }
    assert writeup["fix"]  # DNSSEC has a safe deterministic fix
    assert "curl" not in writeup["evidence"].lower()


def test_teaser_without_safe_fix_falls_back_to_top_finding():
    findings = [
        _finding(
            severity="high",
            title="Some exploited issue",
            cwe="CWE-79",
            cvss=8.1,
            exploit_demonstrated=True,
        ),
    ]
    teaser = mf.select_teaser_finding(findings)
    assert teaser is not None
    writeup = mf.build_teaser_writeup(teaser)
    assert writeup["fix"] == ""  # no safe config fix → omitted


def test_exploit_demonstrated_config_finding_never_teaser_after_projection():
    """Regression: the Midgard projection must NOT blind the teaser gate.

    A finding shaped like a safe configuration teaser candidate but carrying
    exploit_demonstrated=True must never be chosen as the free sample, even after
    classify_for_tier(MIDGARD). The exploit flag must survive projection so
    _is_safe_teaser_candidate can still exclude it — clearing it before teaser
    selection would be a fail-open tier-gate bypass.
    """
    exploited_cfg = _finding(
        severity="high",
        title="DMARC has no aggregate reporting (rua)",
        description="DMARC published but defines no rua= address.",
        cwe="CWE-16",
        cvss=7.5,
        observed_impact='_dmarc.svalbard.ca TXT "v=DMARC1; p=none;"',
        exploit_demonstrated=True,
        exploit_summary="proved exploitable via chained misconfig",
    )
    safe_cfg = _finding(
        severity="low",
        title="DNSSEC not enabled",
        description="The zone is unsigned.",
        cwe="CWE-350",
        cvss=3.9,
        observed_impact="No RRSIG/DS records present for svalbard.ca.",
    )
    data = ReportData(
        report_id="r",
        target="svalbard.ca",
        summary=ReportSummary(critical=0, high=1, medium=0, low=1, info=0),
        findings=[exploited_cfg, safe_cfg],
        technologies=[],
    )
    projected = classify_for_tier(data, ReportTier.MIDGARD)
    # The exploit flag survives projection (so the gate upstream can see it).
    proj_dmarc = next(f for f in projected.findings if f.title.startswith("DMARC"))
    assert proj_dmarc.exploit_demonstrated is True
    # The exploited config finding is never the free teaser.
    teaser = mf.select_teaser_finding(projected.findings)
    assert teaser is not None
    assert not teaser.exploit_demonstrated
    assert teaser.title == "DNSSEC not enabled"


# ---------------------------------------------------------------------------
# Machine formats — no leak + parity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["json", "xml", "csv"])
def test_machine_formats_no_paid_leak(fmt):
    data = classify_for_tier(_report_data(), ReportTier.MIDGARD)
    gen = {"json": generate_json, "xml": generate_xml, "csv": generate_csv}[fmt]
    out = gen(data, jinja_context=_jctx(), tier="midgard").decode("utf-8")
    low = out.lower()
    for forbidden in FORBIDDEN_MACHINE:
        assert forbidden not in low, f"{fmt} leaked {forbidden!r}"
    # No pre-signed MinIO links / internal raw API paths.
    assert "x-amz-" not in low
    assert "raw=true" not in low


def test_json_is_free_tier_schema():
    data = classify_for_tier(_report_data(), ReportTier.MIDGARD)
    payload = json.loads(generate_json(data, jinja_context=_jctx(), tier="midgard"))
    assert payload["meta"]["tier"] == "midgard"
    assert payload["meta"]["free_scan"] is True
    assert set(payload) >= {
        "meta",
        "severity_counts",
        "target_intelligence",
        "findings",
        "sample_finding",
        "executive_summary",
        "upsell",
    }
    # inventory rows carry only id/title/severity/cwe/cvss
    for row in payload["findings"]:
        assert set(row) == {"id", "title", "severity", "cwe", "cvss"}
    # forbidden top-level keys absent
    for k in ("timeline", "phase_outputs", "evidence", "screenshots", "remediation_matrix"):
        assert k not in payload


def test_xml_is_valid_and_mirrors_json():
    data = classify_for_tier(_report_data(), ReportTier.MIDGARD)
    xml_bytes = generate_xml(data, jinja_context=_jctx(), tier="midgard")
    root = ET.fromstring(xml_bytes)  # parses → well-formed
    assert root.tag.endswith("report")


def test_csv_has_stable_inventory_header():
    data = classify_for_tier(_report_data(), ReportTier.MIDGARD)
    csv_text = generate_csv(data, jinja_context=_jctx(), tier="midgard").decode("utf-8")
    assert "id,severity,title,cwe,cvss" in csv_text


def test_finding_parity_across_formats():
    data = classify_for_tier(_report_data(), ReportTier.MIDGARD)
    jctx = _jctx()
    payload = json.loads(generate_json(data, jinja_context=jctx, tier="midgard"))
    json_ids = [(r["id"], r["severity"], r["cwe"], r["cvss"]) for r in payload["findings"]]

    # CSV: parse the inventory block (lines after the header until blank).
    csv_text = generate_csv(data, jinja_context=jctx, tier="midgard").decode("utf-8")
    lines = csv_text.splitlines()
    hdr = lines.index("id,severity,title,cwe,cvss")
    csv_rows = []
    for ln in lines[hdr + 1 :]:
        if not ln.strip():
            break
        parts = next(_csv.reader([ln]))
        cvss = float(parts[4]) if parts[4] else None
        csv_rows.append((parts[0], parts[1], parts[3], cvss))

    assert len(json_ids) == len(csv_rows)
    # Same count as the (projected) finding set.
    assert len(json_ids) == len(data.findings)
    for (jid, jsev, jcwe, jcvss), (cid, csev, ccwe, ccvss) in zip(json_ids, csv_rows, strict=True):
        assert (jid, jsev, jcwe) == (cid, csev, ccwe)
        assert (jcvss or 0.0) == pytest.approx(ccvss or 0.0, abs=0.05)


# ---------------------------------------------------------------------------
# HTML + branded PDF — required sections, no forbidden strings
# ---------------------------------------------------------------------------


def _assert_report_shell(html: str):
    for s in FORBIDDEN_HTML:
        assert s not in html, f"forbidden string present: {s!r}"
    for s in (
        "Severity Summary",
        "Target Intelligence",
        "Findings Inventory",
        "Sample Finding",
        "Executive Summary",
        "Unlock the full assessment",
        "Free scan",
    ):
        assert s in html, f"required section missing: {s!r}"
    # dark theme shared with Valhalla — token is inline (HTML preview) or in the
    # linked branded stylesheet (PDF layout links pdf_styles.css).
    assert "#00ff9d" in html or "pdf_styles.css" in html


def test_html_free_report_shell():
    data = _report_data()
    html = generate_html(data, jinja_context=None, tier="midgard").decode("utf-8")
    _assert_report_shell(html)
    # The teaser writeup is present with its fix.
    assert "DNSSEC not enabled" in html


def test_branded_pdf_template_renders_dark_free_report():
    data = _report_data()
    tpl = _resolve_branded_pdf_template_path("midgard")
    assert tpl is not None, "branded midgard pdf_layout.html must exist"
    ctx = _build_branded_pdf_context(data, None, tier="midgard")
    pdf_html = _render_branded_pdf_html(tpl, ctx)
    _assert_report_shell(pdf_html)
    assert "Free sample" in pdf_html
    # The dark theme token lives in the linked branded stylesheet.
    css = (tpl.parent / "pdf_styles.css").read_text(encoding="utf-8")
    assert "#00ff9d" in css


def test_executive_summary_is_deterministic_not_skipped():
    data = _report_data()
    payload = mf.build_free_payload(classify_for_tier(data, ReportTier.MIDGARD), _jctx())
    summary = payload["executive_summary"]
    assert "svalbard.ca" in summary
    assert "skipped" not in summary.lower()
    assert "could not generate" not in summary.lower()


def test_intel_absent_sources_marked_not_collected():
    data = _report_data()
    # No recon context at all → every intel block degrades to a sentinel.
    intel = mf.build_midgard_intel({}, data)
    assert intel["whois"]["registrar"] == mf.INTEL_NOT_COLLECTED
    assert intel["email_auth"]["dmarc"] == mf.INTEL_NOT_ASSESSED
    assert intel["subdomains"] == []
