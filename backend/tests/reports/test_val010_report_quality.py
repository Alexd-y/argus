"""VAL-010 — report quality: dedup, CVSS/exploit consistency, WSTG/OWASP/HIBP/remediation strings."""

from __future__ import annotations

from src.data_sources.hibp_pwned_passwords import finalize_hibp_pwned_password_summary
from src.reports.data_collector import FindingRow, ScanReportData, ScanRowData
from src.reports.finding_dedup import deduplicate_findings, merge_http_security_header_gaps
from src.reports.generators import build_owasp_compliance_rows
from src.services.reporting import findings_rows_for_jinja
from src.reports.report_quality_gate import (
    build_report_quality_gate,
    cvss_conflict_reason,
    normalize_findings_for_report,
    safe_section_text,
)
from src.reports.template_env import render_tier_report_html
from src.reports.valhalla_report_context import ValhallaReportContext, build_valhalla_report_context
from src.services.reporting import ReportGenerator


def test_deduplicates_security_header_findings() -> None:
    """VAL-002: same-URL header-gap variants merge; internal owasp stays 2025 A02; Valhalla UI uses A05:2021 label (see findings_rows_for_jinja)."""
    a = {
        "title": "Missing Security HTTP Response Headers",
        "cwe": "CWE-693",
        "affected_url": "https://app.example.com/",
        "description": "CSP missing.",
    }
    b = {
        "title": "Content-Security-Policy header is absent",
        "cwe": "CWE-693",
        "affected_url": "https://app.example.com",
        "description": "HSTS not enforced.",
    }
    merged = merge_http_security_header_gaps([a, b])
    assert len(merged) == 1
    assert merged[0]["title"] == "Missing or incomplete HTTP security response headers"
    assert merged[0].get("owasp_category") == "A02"

    out = deduplicate_findings([a, b])
    assert len(out) == 1


def test_valhalla_shows_a05_2021_for_security_misconfiguration_a02() -> None:
    data = ScanReportData(
        scan_id="s",
        tenant_id="t",
        findings=[
            FindingRow(
                id="m1",
                tenant_id="t",
                scan_id="s",
                severity="medium",
                title="Missing or incomplete HTTP security response headers",
                description="CSP missing.",
                cwe="CWE-693",
                owasp_category="A02",
            )
        ],
    )
    [row] = findings_rows_for_jinja(data, report_tier="valhalla")
    assert row.get("owasp_category") == "A02"
    assert row.get("owasp_display_code") == "A05:2021"
    rows = build_owasp_compliance_rows(
        [row],
        use_valhalla_owasp_2021_misconfig_labels=True,
    )
    a02 = next(r for r in rows if r["category_id"] == "A02")
    assert a02.get("display_category_code") == "A05:2021"


def test_cvss_fields_are_consistent() -> None:
    row = FindingRow(
        id="cvss-ok",
        tenant_id="t",
        scan_id="s",
        severity="high",
        title="XSS in search (validated)",
        description="Reflected in q param.",
        cwe="CWE-79",
        cvss=7.2,
        cvss_score=7.2,
        confidence="likely",
        proof_of_concept={
            "request_url": "https://x.test/q?q=%3Cscript%3E",
            "raw_response": "<html>ok</html>",
        },
    )
    [n] = normalize_findings_for_report([row])
    assert n.cvss == n.cvss_score == 7.2
    assert n.proof_of_concept and n.proof_of_concept.get("cvss_score") == 7.2
    assert "cvss_base_score" not in (n.proof_of_concept or {})
    assert cvss_conflict_reason(n) is None


def test_missing_headers_not_critical_without_exploit() -> None:
    [row] = normalize_findings_for_report(
        [
            FindingRow(
                id="hdr-crit",
                tenant_id="t",
                scan_id="s",
                severity="critical",
                title="Missing recommended HTTP response headers (CSP, HSTS)",
                description="Passive configuration observation.",
                cwe="CWE-693",
                cvss=None,
                proof_of_concept={"observed_headers": ["server: nginx"]},
            )
        ]
    )
    assert row.severity == "medium"
    assert row.cvss_score is not None
    assert row.exploit_demonstrated is False


def test_exploit_yes_requires_exploit_evidence() -> None:
    [no_evidence] = normalize_findings_for_report(
        [
            FindingRow(
                id="exp-no-poc",
                tenant_id="t",
                scan_id="s",
                severity="high",
                title="SQL injection in reports export",
                description="Unvalidated id parameter.",
                cwe="CWE-89",
                cvss=8.0,
                exploit_demonstrated=True,
                exploit_summary="claim only",
                proof_of_concept={"request_url": "https://app.test/export?id=1"},
            )
        ]
    )
    assert no_evidence.exploit_demonstrated is False
    assert no_evidence.exploit_summary is None

    [with_raw] = normalize_findings_for_report(
        [
            FindingRow(
                id="exp-raw",
                tenant_id="t",
                scan_id="s",
                severity="high",
                title="SQL injection in search",
                description="Union-based.",
                cwe="CWE-89",
                cvss=8.0,
                exploit_demonstrated=True,
                proof_of_concept={
                    "request_url": "https://app.test/s",
                    "raw_response": "You have an error in your SQL syntax; check union select",
                },
            )
        ]
    )
    assert with_raw.exploit_demonstrated is True


def test_no_stale_rate_limit_text_for_header_findings() -> None:
    data = ScanReportData(
        scan_id="s",
        tenant_id="t",
        findings=[
            FindingRow(
                id="hdr-only",
                tenant_id="t",
                scan_id="s",
                severity="medium",
                title="Strict-Transport-Security header is not set",
                description="HSTS missing on HTTPS entry points.",
                cwe="CWE-693",
                cvss=4.3,
                proof_of_concept={"observed_headers": ["server"]},
            )
        ],
    )
    gate = build_report_quality_gate(data)
    text = safe_section_text("executive_summary", data, gate)
    low = text.lower()
    assert "rate limit" not in low
    assert "429" not in low
    assert "brute" not in low


def test_data_breach_section_does_not_claim_no_breach_when_samples_zero() -> None:
    fin = finalize_hibp_pwned_password_summary(
        {
            "checks_run": 0,
            "pwned_count": 0,
        }
    )
    assert fin["data_breach_password_exposure"] == "unknown"
    note = (fin.get("breach_signal_note") or "").lower()
    assert "checks_run=0" in note
    assert "not evidence" in note


def test_wstg_zero_adds_not_comprehensive_warning() -> None:
    data = ScanReportData(
        scan_id="s",
        tenant_id="t",
        scan=ScanRowData(
            id="s",
            tenant_id="t",
            target_id=None,
            target_url="https://target.example",
            status="done",
            progress=100,
            phase="reporting",
            options={"scanType": "standard"},
        ),
        valhalla_context=ValhallaReportContext(
            wstg_coverage={
                "coverage_percentage": 0.0,
                "covered": 0,
                "partial": 0,
                "total_tests": 96,
                "by_category": {},
            }
        ),
    )
    ctx = ReportGenerator().prepare_template_context("valhalla", data, {})
    html = render_tier_report_html("valhalla", ctx)
    assert "not a comprehensive" in html.lower() or "not a full-scope" in html.lower()
    assert "0%" in html or "0 /" in html


def test_owasp_categories_not_assessed_when_coverage_zero() -> None:
    rows = build_owasp_compliance_rows(
        [],
        wstg_coverage={"coverage_percentage": 0.0, "covered": 0, "total_tests": 96, "by_category": {}},
    )
    for cr in rows:
        assert cr["assessed"] == "Not assessed"
        assert cr["assessment_result"] == "Not assessed"
        assert cr["findings_present"] == "Not assessed"
        assert cr["count"] == 0

    with_finding = build_owasp_compliance_rows(
        [{"owasp_category": "A02", "severity": "medium"}],
        wstg_coverage={"coverage_percentage": 0.0},
    )
    a02 = next(r for r in with_finding if r["category_id"] == "A02")
    assert a02["assessed"] == "Assessed"
    assert a02["count"] == 1


def test_remediation_does_not_include_x_xss_protection() -> None:
    hdr_finding = ScanReportData(
        scan_id="s",
        tenant_id="t",
        findings=[
            FindingRow(
                id="h1",
                tenant_id="t",
                scan_id="s",
                severity="medium",
                title="Content-Security-Policy header is missing",
                description="CSP is not configured.",
                cwe="CWE-693",
                cvss=4.3,
                proof_of_concept={"observed_headers": []},
            )
        ],
    )
    hgate = build_report_quality_gate(hdr_finding)
    remed = safe_section_text("remediation_step", hdr_finding, hgate)
    assert "x-xss" not in remed.lower()

    full = build_valhalla_report_context(
        tenant_id="t",
        scan_id="s",
        recon_results=None,
        tech_profile=None,
        anomalies_structured=None,
        raw_artifact_keys=[],
        phase_outputs=[],
        phase_inputs=[],
        findings=[],
        report_technologies=None,
        fetch_raw_bodies=False,
        harvester_enabled=True,
        trivy_enabled=True,
    )
    scan_data = ScanReportData(
        scan_id="s",
        tenant_id="t",
        valhalla_context=full,
    )
    tctx = ReportGenerator().prepare_template_context("valhalla", scan_data, {})
    html = render_tier_report_html("valhalla", tctx)
    assert "x-xss" not in html.lower()


def test_no_stack_specific_examples_without_detected_stack() -> None:
    data = ScanReportData(
        scan_id="s",
        tenant_id="t",
        valhalla_context=ValhallaReportContext(),
    )
    gate = build_report_quality_gate(data)
    text = safe_section_text("remediation_step", data, gate)
    low = text.lower()
    assert "nginx" not in low
    assert "express" not in low
    assert "spring" not in low
    assert "reverse proxy" in low or "middleware" in low
