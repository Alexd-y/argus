"""Phase C — ReportDocumentV1 v2: ordered section registry + 4-format rendering.

Asserts the full Valhalla contract (finding cards with PoC/remediation/closure,
engagement, methodology, surface, attack narrative, chains, conclusions, claims,
passport statuses) renders into JSON/MD/XML/HTML from one snapshot with parity.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from xml.etree.ElementTree import fromstring

from src.reports.renderers import render_html, render_json, render_markdown, render_xml
from src.reports.report_document import (
    ClientImpact,
    EngagementMetadata,
    ReportAttackStep,
    ReportClaim,
    ReportClosure,
    ReportConclusions,
    ReportEvidenceRef,
    ReportExploitChain,
    ReportFinding,
    ReportMethodologyRef,
    ReportPoC,
    ReportRemediation,
    ReportSurfaceItem,
    ReportTestExecution,
    build_report_document,
)
from src.reports.section_registry import SECTION_ORDER, iter_sections, section_ids

_TS = datetime(2026, 1, 1, tzinfo=UTC)


def _full_doc():
    finding = ReportFinding(
        finding_id="F-001",
        title="SQL Injection in /api/v1/search",
        severity="high",
        cwe="CWE-89",
        owasp_category="A03:2021",
        verification_status="confirmed",
        confidence=0.95,
        evidence_ids=["E-101", "E-102"],
        tool_run_id="TR-1",
        validator_id="sqlmap",
        cvss_version="3.1",
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=9.8,
        established_or_hypothesis="established",
        confirmation_class="sqli",
        poc=ReportPoC(
            tool="sqlmap 1.8.2",
            payload="' OR 1=1 --",
            command="curl -sS -G 'https://t/api' --data-urlencode 'q=x'",
            http_request="GET /api/v1/search?q=... HTTP/1.1",
            http_response="HTTP/1.1 500 ...",
            discriminator="DB error signature in body",
            negative_control="same request without payload → 200 clean",
            canary="argus-canary-7f3a",
            observed_impact="read one row of another tenant",
            evidence_ids=["E-101"],
            reproducibility="confirmed",
        ),
        remediation=ReportRemediation(
            status="generated_validated",
            permanent_fix="Use parameterised queries in search handler.",
            component="search_service.py",
            acceptance_criteria=["No error on quote payloads", "Prepared statements only"],
        ),
        closure=ReportClosure(
            permitted_status="not_retested",
            what_verified="Injection reproduced with discriminator.",
            residual_risk="High until parameterised.",
            next_step="Fix and retest.",
        ),
        claims=[
            ReportClaim(
                claim_id="CL-0001",
                claim_type="confirmed_vulnerability",
                text="The search parameter is SQL-injectable.",
                evidence_ids=["E-101"],
            )
        ],
    )
    downgraded = ReportFinding(
        finding_id="F-002",
        title="Reflected input (unconfirmed XSS)",
        severity="medium",
        verification_status="suspected",
        confidence=0.4,
        downgrade_reason="reflection of a string is not execution in a browser context",
    )
    return build_report_document(
        scan_id="scan-1",
        tenant_id="t-1",
        target="https://target.example",
        findings=[finding],
        evidence_references=[
            ReportEvidenceRef(evidence_id="E-101", kind="http", object_key="k101"),
            ReportEvidenceRef(evidence_id="E-102", kind="artifact", object_key="k102"),
        ],
        surface_inventory=[
            ReportSurfaceItem(host="target.example", port=443, service="nginx", version="1.24.0")
        ],
        unconfirmed_observations=[downgraded],
        test_executions=[
            ReportTestExecution(test_id="WSTG-ATHN-01", control="auth", result="passed")
        ],
        attack_narrative=[
            ReportAttackStep(
                order_index=1,
                phase="entry",
                description="Injected payload into search.",
                tactic="TA0001",
                technique_id="T1190",
                claim_ids=["CL-0001"],
            )
        ],
        exploit_chains=[
            ReportExploitChain(
                chain_id="CH-1",
                kind="proven",
                title="SQLi → tenant data read",
                outcome="cross-tenant read",
            )
        ],
        methodology=[ReportMethodologyRef(framework="OWASP WSTG", revision="4.2")],
        engagement=EngagementMetadata(
            testing_windows=["2026-01-01T00:00Z/01:00Z"],
            source_ips=["10.0.0.5"],
            canaries=["argus-canary-7f3a"],
        ),
        client_impact=ClientImpact(
            created_artifacts=["/tmp/argus_probe.txt"], removed=["/tmp/argus_probe.txt"]
        ),
        conclusions=ReportConclusions(
            executive_summary="One confirmed high-severity SQL injection.",
            business_risk="Cross-tenant data exposure.",
            closure_summary="Open until parameterised and retested.",
            priority_plan=[{"finding_ids": ["F-001"], "rationale": "Confirmed data exposure."}],
        ),
        claims=[
            ReportClaim(
                claim_id="CL-0001",
                claim_type="confirmed_vulnerability",
                text="The search parameter is SQL-injectable.",
                evidence_ids=["E-101"],
            )
        ],
        generation_status="ready",
        llm_analysis_status="completed",
        assessment_completeness="complete",
        evidence_integrity="verified",
        review_status="approved",
        verification_kit_ref="kits/scan-1.zip",
        generated_at=_TS,
    )


def test_schema_version_is_v2():
    assert _full_doc().schema_version == "v2"


def test_iter_sections_reports_present_for_populated_doc():
    doc = _full_doc()
    states = {s.section_id: s for s in iter_sections(doc)}
    assert set(states) == set(section_ids())
    for sid in (
        "passport",
        "executive_summary",
        "engagement",
        "methodology",
        "surface_inventory",
        "findings",
        "unconfirmed_observations",
        "test_executions",
        "attack_narrative",
        "exploit_chains",
        "business_risk",
        "priority_plan",
        "evidence_inventory",
        "client_impact",
        "claims",
    ):
        assert states[sid].present, sid


def test_iter_sections_empty_doc_reports_status_not_present():
    doc = build_report_document(scan_id="s", tenant_id="t", target="x", generated_at=_TS)
    states = {s.section_id: s for s in iter_sections(doc)}
    assert not states["findings"].present
    assert states["findings"].status == "no_findings"
    assert not states["engagement"].present


def test_poc_remediation_closure_render_in_all_text_formats():
    doc = _full_doc()
    md = render_markdown(doc)
    html = render_html(doc)
    xml = render_xml(doc)
    js = render_json(doc)
    for blob in (md, html, xml, js):
        assert (
            "Proof of Concept" in blob
            or "proof_of_concept" in blob
            or '"poc"' in blob
            or "Доказательство" in blob
        )
        assert "argus-canary-7f3a" in blob  # canary
        assert "parameterised" in blob.lower() or "parameterised queries" in blob  # remediation
        assert "not_retested" in blob  # closure permitted_status
        assert "AV:N/AC:L" in blob  # cvss vector


def test_downgrade_reason_present_in_all_formats():
    doc = _full_doc()
    reason = "reflection of a string is not execution"
    for blob in (render_markdown(doc), render_html(doc), render_xml(doc), render_json(doc)):
        assert reason in blob


def test_engagement_and_passport_in_all_formats():
    doc = _full_doc()
    for blob in (render_markdown(doc), render_html(doc), render_xml(doc), render_json(doc)):
        assert "10.0.0.5" in blob  # source IP (engagement)
        assert "completed" in blob  # llm_analysis_status
        assert "kits/scan-1.zip" in blob  # verification kit ref


def test_four_format_finding_parity():
    doc = _full_doc()
    data = json.loads(render_json(doc))
    fid = data["findings"][0]["finding_id"]
    snap = data["snapshot_hash"]
    root = fromstring(render_xml(doc))
    x_ids = {fe.get("finding_id") for fe in root.iter("finding")}
    assert fid in x_ids
    for blob in (render_markdown(doc), render_html(doc), render_xml(doc)):
        assert fid in blob
        assert snap in blob


def test_section_order_is_stable_and_findings_before_coverage():
    ids = [s.section_id for s in SECTION_ORDER]
    assert ids.index("findings") < ids.index("coverage")
    assert ids.index("passport") == 0
    assert ids.index("executive_summary") < ids.index("findings")
