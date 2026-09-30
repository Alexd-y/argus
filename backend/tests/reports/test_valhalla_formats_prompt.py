"""Formats prompt (CURSOR_VALHALLA_FORMATS_PROMPT) — regression tests C-xx.

Covers the four canonical text formats (JSON/MD/XML/HTML) quality defects.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from src.reports.renderers import render_html, render_json, render_markdown, render_xml
from src.reports.report_document import ReportFinding, ReportPoC, build_report_document

_TS = datetime(2026, 1, 1, tzinfo=UTC)


def _doc_with_finding(**kw):
    base = {
        "finding_id": "a9caa12d-55d8-5857-a001-c1f0710e3781",
        "title": "Missing HTTP security headers | with pipe",
        "severity": "medium",
        "verification_status": "suspected",
        "confidence": 0.95,
        "cwe": "CWE-693",
        "owasp_category": "A05:2021",
        "cvss_score": 5.3,
        "cvss_version": "3.1",
        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "evidence_ids": ["E-004"],
        "asset": "alleksy.com",
        "port": 443,
        "scheme": "https",
        "description": "Final 2xx response omits X-Frame-Options and CSP.",
        "poc": ReportPoC(
            tool="web_vuln_heuristics",
            http_request="GET https://alleksy.com",
            http_response="HTTP 200",
            discriminator="final 2xx omits X-Frame-Options, CSP",
            negative_control="baseline domain returns the headers",
        ),
    }
    base.update(kw)
    return build_report_document(
        scan_id="s1",
        tenant_id="t1",
        target="https://alleksy.com",
        findings=[ReportFinding(**base)],
        generated_at=_TS,
    )


# --------------------------------------------------------------------------- C-27
def test_md_no_empty_backtick_pairs():
    md = render_markdown(_doc_with_finding())
    assert "`` ``" not in md
    assert "` `" not in md
    # CVSS is rendered as a single readable cell, not three backtick groups.
    assert re.search(r"5\.3 \(3\.1/AV:N", md) or re.search(r"5\.3 \(AV:N", md)


def test_md_cvss_without_vector_marked_heuristic():
    md = render_markdown(_doc_with_finding(cvss_vector=None, cvss_version=None))
    assert "severity_basis: heuristic" in md
    assert "`` ``" not in md


# --------------------------------------------------------------------------- C-28
def test_md_card_structure_matches_layout():
    md = render_markdown(_doc_with_finding())
    assert "**Что обнаружено.**" in md
    assert "#### Доказательство" in md or "Доказательство" in md
    assert "| CVSS |" in md
    assert "| OWASP |" in md
    # Header carries index + severity + verification status + title.
    assert re.search(r"### 01 · MEDIUM · suspected — ", md)


def test_md_omits_not_assessed_fields():
    # A finding card must not print dump-style not_assessed filler rows or internal paths.
    md = render_markdown(
        _doc_with_finding(cwe=None, owasp_category=None, cvss_score=None, cvss_vector=None)
    )
    assert "- tool_run_id: `not_assessed`" not in md
    assert "- validator_id: `not_assessed`" not in md
    assert "- raw_artifact_ref:" not in md  # internal path never printed (C-29)
    assert "не сопоставлено" in md  # OWASP honestly marked, not blank


def test_md_escapes_pipes_in_values():
    md = render_markdown(_doc_with_finding())
    # The pipe in the title must be escaped so it does not break a table/inline.
    assert "with pipe" in md
    assert "|" not in md.split("with pipe")[0].splitlines()[-1].replace("\\|", "")


# --------------------------------------------------------------------------- C-28 (HTML/XML smoke)
def test_html_and_xml_still_render_finding():
    doc = _doc_with_finding()
    html = render_html(doc)
    xml = render_xml(doc)
    assert "a9caa12d-55d8-5857-a001-c1f0710e3781" in html
    assert "a9caa12d-55d8-5857-a001-c1f0710e3781" in xml


# --------------------------------------------------------------------------- C-25
def test_xml_has_namespace_and_validates_against_xsd():
    from src.reports.renderers.report_xml_schema import validate_valhalla_report_xml
    from src.reports.renderers.xml_renderer import VALHALLA_REPORT_XML_NS

    xml = render_xml(_doc_with_finding())
    assert f'xmlns="{VALHALLA_REPORT_XML_NS}"' in xml
    errors = validate_valhalla_report_xml(xml)
    assert errors == [], errors


# --------------------------------------------------------------------------- C-26
def test_xml_nil_vs_absent_semantics():
    # cvss_version is None → element carries xsi:nil, distinguishable from empty.
    xml = render_xml(_doc_with_finding(cvss_version=None))
    assert "xsi:nil" in xml


def test_xml_field_parity_with_json():
    import json as _json

    doc = _doc_with_finding()
    data = _json.loads(render_json(doc))
    f = data["findings"][0]
    xml = render_xml(doc)
    # Every non-empty scalar the JSON carries for the finding appears in the XML.
    for key in ("cvss_vector", "cwe", "owasp_category"):
        if f.get(key):
            assert str(f[key]) in xml, key


def test_xml_parser_rejects_external_entities():
    from src.reports.renderers.report_xml_schema import XmlSecurityError, safe_parse_xml

    xxe = "<?xml version='1.0'?><!DOCTYPE r [<!ENTITY x SYSTEM 'file:///etc/passwd'>]>" "<r>&x;</r>"
    try:
        safe_parse_xml(xxe)
        raise AssertionError("XXE was not blocked")
    except XmlSecurityError:
        pass


# --------------------------------------------------------------------------- Phase 3 (JSON)
def test_json_has_schema_ref_and_validates():
    import json as _json

    from src.reports.renderers.json_renderer import VALHALLA_REPORT_JSON_SCHEMA_ID
    from src.reports.renderers.report_json_schema import validate_valhalla_report_json

    doc = build_report_document(
        scan_id="s1",
        tenant_id="t1",
        target="https://alleksy.com",
        findings=[
            ReportFinding(
                finding_id="F-1",
                title="t",
                severity="medium",
                verification_status="suspected",
                confidence=0.95,
                cvss_score=5.3,
            )
        ],
        generation_status="ready",
        generated_at=_TS,
    )
    js = render_json(doc)
    data = _json.loads(js)
    assert data["$schema"] == VALHALLA_REPORT_JSON_SCHEMA_ID
    assert validate_valhalla_report_json(js) == []


# --------------------------------------------------------------------------- C-20
def test_cvss_zero_is_null():
    from src.reports.snapshot_builder import build_snapshot_from_report_data

    class _F:
        finding_id = "F-1"
        title = "x"
        severity = "info"
        cwe = None
        description = "d"
        validation_status = "unverified"
        confidence = "possible"
        evidence_refs = []
        proof_of_concept = None
        cvss_score = 0.0
        cvss_vector = None

    class _RD:
        findings = [_F()]
        evidence = []
        technologies = []
        target = "https://x"
        scan_id = "s1"
        tenant_id = "t1"

    doc = build_snapshot_from_report_data(_RD(), scan_meta={"scan_id": "s1"})
    assert doc.findings[0].cvss_score is None  # 0.0 is not a valid CVSS assessment


def test_json_key_order_deterministic():
    doc = _doc_with_finding()
    assert render_json(doc) == render_json(doc)  # byte-stable
    js = render_json(doc)
    assert js.index('"$schema"') < js.index('"target"')


# --------------------------------------------------------------------------- C-19
def test_owasp_mapping_table_covers_known_classes():
    from src.reports.owasp_classifier import classify_owasp

    assert classify_owasp("CWE-319").startswith("A02")  # TLS/crypto → A02
    assert classify_owasp("CWE-327").startswith("A02")
    assert classify_owasp("CWE-693").startswith("A05")  # missing headers → A05
    assert classify_owasp("CWE-89").startswith("A03")  # SQLi
    assert classify_owasp("CWE-918").startswith("A10")  # SSRF
    assert classify_owasp(None, "sqli").startswith("A03")  # class fallback
    assert classify_owasp(None, None, "TLS misconfiguration").startswith("A02")
    assert classify_owasp("CWE-99999") is None  # unmapped → None ("не сопоставлено")


def _snapshot_from(finding_obj):
    from src.reports.snapshot_builder import build_snapshot_from_report_data

    class _RD:
        findings = [finding_obj]
        evidence = []
        technologies = []
        target = "https://alleksy.com"
        scan_id = "s1"
        tenant_id = "t1"

    return build_snapshot_from_report_data(_RD(), scan_meta={"scan_id": "s1"})


class _RawFinding:
    def __init__(self, **kw):
        self.finding_id = "F-1"
        self.title = "x"
        self.severity = "medium"
        self.cwe = None
        self.description = "d"
        self.validation_status = "validated"
        self.confidence = "confirmed"
        self.evidence_refs = ["k1"]
        self.source_tool = "web_vuln_heuristics"
        self.proof_of_concept = None
        self.owasp_category = None
        self.__dict__.update(kw)


# --------------------------------------------------------------------------- C-19 (wired)
def test_owasp_reclassified_in_snapshot():
    # A missing-headers finding wrongly labelled A02 in source is corrected to A05.
    doc = _snapshot_from(
        _RawFinding(cwe="CWE-693", owasp_category="A02:2021", title="Missing headers")
    )
    assert doc.findings[0].owasp_category.startswith("A05")


# --------------------------------------------------------------------------- C-22
def test_5xx_infrastructure_response_downgrades_to_inconclusive():
    doc = _snapshot_from(
        _RawFinding(
            title="TLS/SSL configuration observation",
            cwe="CWE-693",
            cvss_score=5.3,
            proof_of_concept={"response": "HTTP 530 Cloudflare Tunnel error"},
        )
    )
    f = doc.findings[0]
    assert f.verification_status == "inconclusive"
    assert f.downgrade_reason == "target_unreachable_during_test"
    assert f.cvss_score is None


# --------------------------------------------------------------------------- C-21
def test_discriminator_mismatch_dropped_for_non_xss():
    doc = _snapshot_from(
        _RawFinding(
            title="Missing security headers",
            cwe="CWE-693",
            proof_of_concept={"discriminator": "http_reflection", "response": "HTTP 200"},
        )
    )
    poc = doc.findings[0].poc
    assert poc is None or poc.discriminator is None  # reflection discriminator dropped


# --------------------------------------------------------------------------- C-30
def test_single_step_chain_not_emitted():
    from src.reports.report_document import ReportFinding as _RF
    from src.reports.valhalla_narrative_builder import build_exploit_chains

    # One suspected finding → no hypothetical one-step chain.
    one = [_RF(finding_id="F-1", title="x", severity="medium", verification_status="suspected")]
    assert build_exploit_chains(one) == []


# --------------------------------------------------------------------------- Phase 9 (parity)
def test_content_parity_clean_bundle_has_no_blockers():
    from src.reports.renderers import render_html, render_json, render_markdown, render_xml
    from src.reports.report_content_parity import content_parity_blockers

    doc = _doc_with_finding()
    canon = {
        "json": render_json(doc).encode(),
        "md": render_markdown(doc).encode(),
        "xml": render_xml(doc).encode(),
        "html": render_html(doc).encode(),
    }
    assert content_parity_blockers(canon) == []


def test_content_parity_detects_finding_id_divergence():
    from src.reports.report_content_parity import content_parity_blockers

    js = '{"findings": [{"finding_id": "A", "severity": "high", "verification_status": "suspected"}], "unconfirmed_observations": []}'
    xml = (
        '<argus_report xmlns="urn:argus:valhalla-report:v2" schema_version="v2" '
        'snapshot_hash="h"><findings count="1">'
        '<finding finding_id="B" severity="high" verification_status="suspected"/>'
        "</findings></argus_report>"
    )
    blockers = content_parity_blockers({"json": js.encode(), "xml": xml.encode()})
    assert any("finding_id set differs" in b for b in blockers)


def test_content_parity_flags_internal_path():
    from src.reports.report_content_parity import content_parity_blockers

    leak = "00000000-0000-0000-0000-000000000001/d6fdd027-ecec-4791-aed2-ef21025d1c7f/poc/x.json"
    js = f'{{"findings": [], "unconfirmed_observations": [], "leak": "{leak}"}}'
    blockers = content_parity_blockers({"json": js.encode()})
    assert any("internal path" in b for b in blockers)


# --------------------------------------------------------------------------- Phase 6 (HTML)
def test_html_escapes_script_in_poc():
    from src.reports.report_document import ReportPoC

    doc = _doc_with_finding()
    doc.findings[0].poc = ReportPoC(http_response="<script>alert(1)</script>")
    html = render_html(doc)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_html_is_self_contained():
    html = render_html(_doc_with_finding()).lower()
    # No external resource loading: no <link>, no @import, no <script>, no remote src/href.
    assert "<link" not in html
    assert "@import" not in html
    assert "<script" not in html
    assert 'src="http' not in html and "src='http" not in html
    assert 'href="http' not in html and "href='http" not in html


def test_html_has_finding_anchor_and_toc():
    doc = _doc_with_finding()
    html = render_html(doc)
    fid = doc.findings[0].finding_id
    assert f'id="finding-{fid}"' in html
    assert f'href="#finding-{fid}"' in html


def test_md_html_section_headers_equal():
    from src.reports.report_content_parity import content_parity_blockers

    doc = _doc_with_finding()
    canon = {
        "md": render_markdown(doc).encode(),
        "html": render_html(doc).encode(),
    }
    blockers = [b for b in content_parity_blockers({"json": b'{"findings":[]}', **canon})]
    assert not any("section headers differ" in b for b in blockers), blockers


def test_severity_distribution_lists_finding_ids():
    from src.reports.renderers.markdown_renderer import severity_distribution

    doc = _doc_with_finding()
    dist = dict(severity_distribution(doc))
    fid = doc.findings[0].finding_id
    sev = doc.findings[0].severity.lower()
    assert fid in dist[sev]
    # C-31: the id appears in MD and HTML distribution tables (not a bare '—').
    assert fid in render_markdown(doc)
    assert fid in render_html(doc)
