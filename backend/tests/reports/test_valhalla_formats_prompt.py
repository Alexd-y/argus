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
