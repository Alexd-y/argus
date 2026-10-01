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
    blockers = content_parity_blockers({"json": b'{"findings":[]}', **canon})
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


# --------------------------------------------------------------------------- Phase 1 (one report)
def test_legacy_valhalla_pdf_disabled_by_default():
    # C-01: by default the legacy valhalla.html.j2 PDF is retired; only the
    # canonical bundle emits a single PDF. The flag exists for opt-in comparison.
    from src.core.config import Settings

    assert Settings().valhalla_legacy_pdf is False


# --------------------------------------------------------------------------- Phase 7 (C-19 OWASP)
def test_owasp_classifier_tls_and_headers_split():
    from src.reports.owasp_classifier import classify_owasp

    # C-19: TLS/crypto → A02, configuration/headers → A05 (the exact swap in the bug).
    assert classify_owasp(cwe="CWE-319").startswith("A02")  # cleartext transport
    assert classify_owasp(cwe=327).startswith("A02")  # broken crypto
    assert classify_owasp(cwe="CWE-693").startswith("A05")  # missing headers
    assert classify_owasp(cwe=89).startswith("A03")  # SQLi
    assert classify_owasp(cwe=918).startswith("A10")  # SSRF
    assert classify_owasp(cwe=None, confirmation_class=None, title="Weird") is None


# --------------------------------------------------------------------------- Phase 8 (LLM guards)
def test_prompt_placeholder_leak_blocked():
    from src.reports.prose_gate import find_prompt_artifacts

    # C-33: a prose slot containing an unfilled prompt placeholder is flagged.
    for leak in ("[Layer]", "[Config/file]", "[specific value]", "[curl command]"):
        assert find_prompt_artifacts(f"Remediation: {leak} must be set."), leak
    assert not find_prompt_artifacts("Enable HSTS on the edge and set a strict CSP.")


# ===========================================================================
# §12 — remaining named regression tests (close the explicit coverage gap).
# The behaviour already exists (326 green reports tests); these pin the exact
# C-xx acceptance names the prompt requires.
# ===========================================================================


def _multi_finding_doc():
    """A two-finding snapshot used by the cross-format parity tests."""
    return build_report_document(
        scan_id="s1",
        tenant_id="t1",
        target="https://alleksy.com",
        findings=[
            ReportFinding(
                finding_id="F-1",
                title="Missing HTTP security response headers",
                severity="medium",
                verification_status="suspected",
                confidence=0.9,
                cwe="CWE-693",
                owasp_category="A05:2021",
                cvss_score=5.3,
                cvss_version="3.1",
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            ),
            ReportFinding(
                finding_id="F-2",
                title="Weak TLS configuration",
                severity="low",
                verification_status="observed",
                confidence=0.6,
                cwe="CWE-327",
                owasp_category="A02:2021",
            ),
        ],
        generated_at=_TS,
    )


# --------------------------------------------------------------------------- Phase 9 parity
def test_finding_id_set_identical_across_formats():
    from src.reports.report_content_parity import content_parity_blockers

    doc = _multi_finding_doc()
    canon = {
        "json": render_json(doc).encode(),
        "md": render_markdown(doc).encode(),
        "xml": render_xml(doc).encode(),
        "html": render_html(doc).encode(),
    }
    blockers = content_parity_blockers(canon)
    assert not any("finding_id set differs" in b for b in blockers), blockers
    for fid in ("F-1", "F-2"):
        for fmt in canon:
            assert fid in canon[fmt].decode(), (fmt, fid)


def test_owasp_category_identical_across_formats():
    doc = _multi_finding_doc()
    for fmt in (render_json(doc), render_markdown(doc), render_xml(doc)):
        assert "A05:2021" in fmt
        assert "A02:2021" in fmt
    assert "A05:2021" in render_html(doc)


def test_unconfirmed_count_parity():
    from src.reports.report_content_parity import content_parity_blockers

    doc = build_report_document(
        scan_id="s1",
        tenant_id="t1",
        target="https://alleksy.com",
        findings=[ReportFinding(finding_id="F-1", title="x", severity="medium", confidence=0.9)],
        unconfirmed_observations=[
            ReportFinding(finding_id="U-1", title="probe", severity="info"),
            ReportFinding(finding_id="U-2", title="probe2", severity="info"),
        ],
        generated_at=_TS,
    )
    md = render_markdown(doc)
    assert "## Unconfirmed Observations (2)" in md
    blockers = content_parity_blockers({"json": render_json(doc).encode(), "md": md.encode()})
    assert not any("unconfirmed count" in b for b in blockers), blockers


def test_exactly_one_pdf_in_bundle():
    from src.reports.canonical_bundle import REQUIRED_CANONICAL_FORMATS, render_canonical_bundle

    doc = _doc_with_finding()
    bundle = render_canonical_bundle(
        doc, include_pdf=True, html_to_pdf=lambda _html: b"%PDF-1.4 single"
    )
    assert sum(1 for a in bundle if a.format == "pdf") == 1  # C-01: one PDF, never two
    assert set(REQUIRED_CANONICAL_FORMATS).issubset({a.format for a in bundle})


# --------------------------------------------------------------------------- Phase 3 JSON
def test_canonical_payload_byte_stable():
    doc1 = _multi_finding_doc()
    doc2 = _multi_finding_doc()
    # Hash excludes generated_at/snapshot_hash → identical input ⇒ identical hash.
    assert doc1.compute_hash() == doc2.compute_hash()
    assert render_json(doc1) == render_json(doc2)


def test_no_internal_paths_in_client_json():
    from src.reports.report_content_parity import content_parity_blockers

    doc = _multi_finding_doc()
    js = render_json(doc)
    # No tenant_id/object_key UUID-path leaks into the client JSON (C-29).
    assert not any("internal path" in b for b in content_parity_blockers({"json": js.encode()}))


def test_null_vs_not_applicable_vs_unknown_distinct():
    import json as _json

    from src.reports.report_document import NO_DATA_STATUSES

    # The three "no data" meanings are modelled distinctly, never one shared null.
    assert {"not_assessed", "out_of_scope"} <= NO_DATA_STATUSES
    # JSON keeps an unset scalar as literal null (not the MD "не сопоставлено" filler).
    doc = _doc_with_finding(owasp_category=None, cvss_score=None, cvss_vector=None)
    data = _json.loads(render_json(doc))
    assert data["findings"][0]["owasp_category"] is None
    assert "не сопоставлено" in render_markdown(doc)  # renderer-side marker, not in JSON


# --------------------------------------------------------------------------- Phase 2 containers
def test_passport_required_fields_not_empty():
    from src.reports.snapshot_completeness_gate import passport_blockers

    bare = _doc_with_finding()
    assert passport_blockers(bare)  # C-17: empty passport blocks release
    filled = build_report_document(
        scan_id="s1",
        tenant_id="t1",
        target="https://alleksy.com",
        execution_mode="production",
        scan_profile="deep",
        resolved_scan_mode="deep",
        started_at="2026-01-01T00:00:00+00:00",
        registry_versions={"tools": "1.0"},
        scope_summary={"in_scope": ["alleksy.com"]},
        findings=[ReportFinding(finding_id="F-1", title="x", severity="info")],
        generated_at=_TS,
    )
    assert passport_blockers(filled) == []


def test_limitations_nonempty_when_gate_failed():
    from src.reports.snapshot_completeness_gate import limitations_blockers

    failed = build_report_document(
        scan_id="s1",
        tenant_id="t1",
        target="https://x",
        wstg={"coverage_gate_passed": False},
        limitations=[],
        generated_at=_TS,
    )
    assert limitations_blockers(failed)  # C-11
    ok = build_report_document(
        scan_id="s1",
        tenant_id="t1",
        target="https://x",
        wstg={"coverage_gate_passed": False},
        limitations=["WSTG coverage below threshold (2% of catalogue)."],
        generated_at=_TS,
    )
    assert limitations_blockers(ok) == []


def test_md_limitations_not_none_when_present():
    # C-11 / §7.5: a populated limitations section never prints the "_none_" placeholder.
    doc = build_report_document(
        scan_id="s1",
        tenant_id="t1",
        target="https://x",
        limitations=["Target returned HTTP 530 during the test window."],
        generated_at=_TS,
    )
    md = render_markdown(doc)
    section = md.split("## Limitations", 1)[1]
    assert "Target returned HTTP 530" in section
    assert "_none_" not in section.split("##", 1)[0]


# --------------------------------------------------------------------------- Phase 7 semantics
def test_evidence_reference_has_hash_and_timestamp():
    from src.reports.report_document import ReportEvidenceRef
    from src.reports.snapshot_completeness_gate import evidence_blockers

    missing = build_report_document(
        scan_id="s1",
        tenant_id="t1",
        target="https://x",
        evidence_references=[ReportEvidenceRef(evidence_id="E-1", object_key="poc/x.json")],
        generated_at=_TS,
    )
    assert evidence_blockers(missing)  # C-23: no sha256/collected_at
    full = build_report_document(
        scan_id="s1",
        tenant_id="t1",
        target="https://x",
        evidence_references=[
            ReportEvidenceRef(
                evidence_id="E-1",
                object_key="poc/x.json",
                sha256="a" * 64,
                size=128,
                mime="application/json",
                collected_at_utc="2026-01-01T00:00:00+00:00",
                collector="web_vuln_heuristics/1.0",
            )
        ],
        generated_at=_TS,
    )
    assert evidence_blockers(full) == []


def test_pseudo_evidence_moved_to_producer_hint():
    from src.reports.report_document import ReportDocumentV1
    from src.reports.snapshot_completeness_gate import (
        finding_chain_blockers,
        finding_has_only_pseudo_evidence,
        is_pseudo_evidence,
    )

    assert is_pseudo_evidence("tool:testssl") is True
    assert is_pseudo_evidence("recon:asnmap") is True
    assert is_pseudo_evidence("E-001") is False
    f = ReportFinding(
        finding_id="F-1",
        title="x",
        severity="medium",
        verification_status="confirmed",
        evidence_ids=["tool:testssl"],
    )
    assert finding_has_only_pseudo_evidence(f) is True
    doc = ReportDocumentV1(scan_id="s1", tenant_id="t1", target="https://x", findings=[f])
    assert any("R-17" in b for b in finding_chain_blockers(doc))  # C-23: pseudo ≠ evidence


# --------------------------------------------------------------------------- Phase 8 LLM
def test_numbers_in_llm_text_are_substituted_not_generated():
    from src.reports.prose_gate import ProseSeverity, check_output_consistency

    # A model that invents its own severity totals is caught (R-10) — the app, not the
    # model, owns the numbers. Consistent counts pass; an inconsistent total blocks.
    bad = check_output_consistency(
        "9 finding(s) recorded (critical: 0, high: 0, medium: 1, low: 0, info: 0)."
    )
    assert any(v.rule == "counter_mismatch" and v.severity is ProseSeverity.BLOCK for v in bad)
    good = check_output_consistency(
        "9 finding(s) recorded (critical: 0, high: 0, medium: 3, low: 4, info: 2)."
    )
    assert not any(v.rule == "counter_mismatch" for v in good)


def test_errors_populated_when_llm_failed():
    from src.reports.llm_remediation.bundle import GenerationStatus
    from src.reports.llm_remediation.integration import generate_valhalla_llm_release
    from src.reports.llm_remediation.runner import LlmNotInvokedError

    def unavailable(system_prompt: str, user_prompt: str, kind: str) -> str:
        raise LlmNotInvokedError("budget ledger unavailable — denying paid cloud call")

    _doc, release = generate_valhalla_llm_release(
        [
            {
                "finding_id": "F-1",
                "title": "x",
                "severity": "medium",
                "verification_status": "suspected",
            }
        ],
        report_meta={"report_id": "R", "report_version": "v", "target": "alleksy.com"},
        llm_callable=unavailable,
        provider="cloud_deepseek",
        model="deepseek-chat",
        health_probe=True,
    )
    # C-32: a failed LLM pass never ships silently — errors[] is non-empty, not ready.
    assert release.manifest.generation_status is not GenerationStatus.READY
    assert release.manifest.errors
