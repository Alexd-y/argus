from __future__ import annotations

from src.api.schemas import Finding, ReportSummary
from src.findings.cvss import parse_cvss_vector
from src.reports.data_collector import FindingRow, ReportRowSlice, ScanReportData, ScanRowData
from src.reports.finding_metadata import estimate_cvss_vector
from src.reports.generators import ReportData
from src.reports.report_data_validation import validate_report_data
from src.reports.report_quality_gate import (
    HEADER_ONLY_DEFAULT_CVSS_SCORE,
    HEADER_ONLY_DEFAULT_CVSS_VECTOR,
    _tool_error_rows,
    build_report_quality_gate,
    evaluate_valhalla_engagement_title_and_full,
    normalize_findings_for_report,
    sanitize_ai_sections_for_quality,
    severity_cvss_band_mismatch_reason,
)
from src.reports.template_env import render_tier_report_html
from src.reports.valhalla_report_context import (
    ValhallaCoverageModel,
    ValhallaMandatorySectionsModel,
    ValhallaReportContext,
    ValhallaSectionEnvelopeModel,
    build_valhalla_report_context,
)
from src.services.reporting import ReportGenerator


def _rate_limit_row(title: str, fid: str = "f-rate") -> FindingRow:
    return FindingRow(
        id=fid,
        tenant_id="t",
        scan_id="s",
        severity="high",
        title=title,
        description="Rapid GET /signin requests did not return HTTP 429.",
        cwe="CWE-307",
        cvss=7.5,
        owasp_category="A07",
        confidence="confirmed",
        proof_of_concept={
            "request_method": "GET",
            "request_url": "https://svalbard.ca/signin",
            "response_statuses": [200, 200, 200, 200, 200],
        },
    )


def test_failed_tools_mark_domains_not_assessed() -> None:
    ctx = build_valhalla_report_context(
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
        tool_run_summaries=[
            ("testssl", "failed"),
            ("whatweb", "failed"),
            ("theHarvester", "failed"),
            ("nikto", "failed"),
            ("nmap", "failed"),
            ("trivy", "failed"),
        ],
    )

    mandatory = ctx.mandatory_sections
    assert mandatory.ssl_tls_analysis.status == "not_assessed"
    assert mandatory.tech_stack_structured.status == "not_assessed"
    assert mandatory.security_headers_analysis.status == "not_assessed"
    assert mandatory.leaked_emails.status == "not_assessed"
    assert mandatory.outdated_components.status == "not_assessed"
    assert ctx.coverage.sections["port_exposure"]["status"] == "not_assessed"
    assert "No conclusion can be drawn" in mandatory.ssl_tls_analysis.reason
    assert "No issues found" not in mandatory.ssl_tls_analysis.reason


def _valhalla_mandatory_all_completed() -> ValhallaMandatorySectionsModel:
    done = ValhallaSectionEnvelopeModel(status="completed", reason="")
    return ValhallaMandatorySectionsModel(
        tech_stack_structured=done,
        ssl_tls_analysis=done,
        security_headers_analysis=done,
        port_exposure=done,
        outdated_components=done,
        robots_sitemap_analysis=done,
        leaked_emails=done,
    )


def test_valhalla_report_mode_label_matches_evaluate_engagement_title_full() -> None:
    """RPT-001: gate.report_mode_label uses the same source as full Valhalla title logic."""
    findings = normalize_findings_for_report(
        [
            FindingRow(
                id="f-ev",
                tenant_id="t",
                scan_id="s",
                severity="high",
                title="Reflected XSS in search",
                description="Validated in q parameter.",
                cvss=7.2,
                evidence_refs=["artifact-1", "artifact-2"],
                proof_of_concept={
                    "request": "GET /search?q=%3Cscript%3E",
                    "response": "<html>reflected</html>",
                },
            )
        ]
    )
    vc = ValhallaReportContext(
        mandatory_sections=_valhalla_mandatory_all_completed(),
        wstg_coverage={
            "coverage_percentage": 75.0,
            "covered": 72,
            "partial": 0,
            "total_tests": 96,
            "by_category": {},
        },
        coverage=ValhallaCoverageModel(tool_errors_summary=[]),
    )
    data = ScanReportData(
        scan_id="s",
        tenant_id="t",
        report=ReportRowSlice(
            id="r1",
            tenant_id="t",
            target="https://example.com",
            scan_id="s",
            tier="valhalla",
            generation_status="ready",
        ),
        valhalla_context=vc,
        findings=findings,
    )
    gate = build_report_quality_gate(data)
    expected_title, full = evaluate_valhalla_engagement_title_and_full(
        wstg_coverage_pct=gate.wstg_coverage_pct,
        mandatory_section_status=dict(gate.section_status),
        findings=findings,
        tool_error_rows=_tool_error_rows(vc) or None,
    )
    assert gate.report_mode_label == expected_title
    assert gate.report_mode_label == "Valhalla Full Penetration Test Report"
    assert full is True


def test_valhalla_report_mode_label_matches_evaluate_engagement_title_partial_wstg() -> None:
    """RPT-001: low WSTG still keeps gate label aligned with evaluate_valhalla_engagement_title_and_full."""
    vc = ValhallaReportContext(
        mandatory_sections=_valhalla_mandatory_all_completed(),
        wstg_coverage={
            "coverage_percentage": 40.0,
            "covered": 10,
            "partial": 5,
            "total_tests": 96,
            "by_category": {},
        },
        coverage=ValhallaCoverageModel(tool_errors_summary=[]),
    )
    data = ScanReportData(
        scan_id="s",
        tenant_id="t",
        report=ReportRowSlice(
            id="r2",
            tenant_id="t",
            target="https://example.com",
            scan_id="s",
            tier="valhalla",
            generation_status="ready",
        ),
        valhalla_context=vc,
        findings=[],
    )
    gate = build_report_quality_gate(data)
    expected_title, full = evaluate_valhalla_engagement_title_and_full(
        wstg_coverage_pct=gate.wstg_coverage_pct,
        mandatory_section_status=dict(gate.section_status),
        findings=[],
        tool_error_rows=_tool_error_rows(vc) or None,
    )
    assert gate.report_mode_label == expected_title
    assert gate.report_mode_label == "Valhalla Security Assessment — Partial Coverage"
    assert full is False


def test_wstg_zero_of_96_triggers_limitation_banner() -> None:
    data = ScanReportData(
        scan_id="s",
        tenant_id="t",
        scan=ScanRowData(
            id="s",
            tenant_id="t",
            target_id=None,
            target_url="https://svalbard.ca",
            status="done",
            progress=100,
            phase="reporting",
            options={"scanType": "quick"},
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

    assert (
        "This assessment does not represent comprehensive application penetration testing. "
        "Several OWASP WSTG categories were not assessed or were only partially assessed."
    ) in html


def test_severity_cvss_band_mismatch_reason_when_assigned_severity_wrong() -> None:
    row = FindingRow(
        id="sev-mis",
        tenant_id="t",
        scan_id="s",
        severity="critical",
        title="Any",
        description="Body",
        cvss=4.0,
    )
    reason = severity_cvss_band_mismatch_reason(row)
    assert reason is not None
    assert "critical" in reason
    assert "4.0" in reason
    assert "medium" in reason


def test_severity_cvss_band_mismatch_reason_none_without_cvss_score() -> None:
    row = FindingRow(
        id="no-cvss",
        tenant_id="t",
        scan_id="s",
        severity="high",
        title="No score",
        description="No CVSS fields set.",
        cvss=None,
    )
    assert severity_cvss_band_mismatch_reason(row) is None


def test_quality_gate_warns_on_severity_cvss_band_mismatch() -> None:
    data = ScanReportData(
        scan_id="s",
        tenant_id="t",
        findings=[
            FindingRow(
                id="gate-mis",
                tenant_id="t",
                scan_id="s",
                severity="critical",
                title="Mismatch",
                description="cvss band does not match label",
                cvss=4.0,
            )
        ],
    )
    gate = build_report_quality_gate(data)
    assert any("inconsistent with cvss=4.0" in w and "expected medium" in w for w in gate.warnings)


def test_header_only_finding_gets_default_cvss_and_caps_exploit() -> None:
    [row] = normalize_findings_for_report(
        [
            FindingRow(
                id="hdr",
                tenant_id="t",
                scan_id="s",
                severity="critical",
                title="Missing HTTP security response headers",
                description="Content-Security-Policy and HSTS are not set.",
                cvss=None,
                proof_of_concept={"observed_headers": ["server"]},
            )
        ]
    )
    assert row.cvss_score == HEADER_ONLY_DEFAULT_CVSS_SCORE
    assert row.cvss == HEADER_ONLY_DEFAULT_CVSS_SCORE
    assert row.severity == "medium"
    assert row.cvss_vector == HEADER_ONLY_DEFAULT_CVSS_VECTOR
    assert row.exploit_demonstrated is False
    assert row.exploit_summary is None
    assert "cvss_base_score" not in (row.proof_of_concept or {})
    assert row.proof_of_concept is not None
    assert row.proof_of_concept.get("exploit_demonstrated") is False


def test_header_only_exploit_demonstrated_false_despite_true_flag() -> None:
    """Passive header evidence must not carry exploit_demonstrated=True (VAL-001)."""
    [row] = normalize_findings_for_report(
        [
            FindingRow(
                id="hdr-exp",
                tenant_id="t",
                scan_id="s",
                severity="high",
                title="Missing Content-Security-Policy header",
                description="HSTS and CSP are not configured.",
                cvss=None,
                exploit_demonstrated=True,
                exploit_summary="claimed",
                proof_of_concept={"observed_headers": ["server"]},
            )
        ]
    )
    assert row.cvss_score == HEADER_ONLY_DEFAULT_CVSS_SCORE
    assert row.severity == "medium"
    assert row.exploit_demonstrated is False
    assert row.exploit_summary is None
    assert row.proof_of_concept.get("exploit_demonstrated") is False


def test_header_only_high_cvss_is_capped_to_medium_band() -> None:
    [row] = normalize_findings_for_report(
        [
            FindingRow(
                id="hdr2",
                tenant_id="t",
                scan_id="s",
                severity="high",
                title="Incomplete security headers configuration",
                description="Several recommended security headers are missing.",
                cvss=9.1,
            )
        ]
    )
    assert row.cvss_score == 6.9
    assert row.severity == "medium"


def test_severity_cvss_mismatch_fails_report_validation() -> None:
    report = ReportData(
        report_id="r",
        target="https://svalbard.ca",
        summary=ReportSummary(medium=1),
        findings=[
            Finding(
                severity="critical",
                title="Inconsistent",
                description="Severity does not match CVSS.",
                cvss=4.0,
                cvss_score=4.0,
            )
        ],
        technologies=[],
    )
    result = validate_report_data(report, tier="midgard")
    assert result.ok is False
    assert "finding_severity_cvss_band_mismatch" in result.reason_codes


def test_cvss_conflict_fails_report_validation() -> None:
    report = ReportData(
        report_id="r",
        target="https://svalbard.ca",
        summary=ReportSummary(low=1),
        findings=[
            Finding(
                severity="low",
                title="Conflicting score",
                description="CVSS fields disagree.",
                cvss=3.7,
                proof_of_concept={"cvss_score": 7.5, "cvss_base_score": 7.5},
            )
        ],
        technologies=[],
    )

    result = validate_report_data(report, tier="midgard")
    assert result.ok is False
    assert "finding_cvss_conflict" in result.reason_codes


def test_duplicate_rate_limit_findings_merge_to_single_control_issue() -> None:
    findings = normalize_findings_for_report(
        [
            _rate_limit_row("Missing Rate Limiting on Login Path", "f1"),
            _rate_limit_row("No HTTP 429 observed on rapid login-path requests", "f2"),
        ]
    )

    assert len(findings) == 1
    assert findings[0].title == "Missing or insufficient rate limiting on login endpoint"
    assert findings[0].severity == "low"
    assert findings[0].validation_status == "unverified"
    assert findings[0].evidence_quality == "weak"


def test_weak_rate_limit_evidence_prevents_confirmed_status() -> None:
    [finding] = normalize_findings_for_report(
        [_rate_limit_row("Missing Rate Limiting on Login Path")]
    )

    assert finding.severity == "low"
    assert finding.cvss == 3.7
    assert finding.confidence in {"possible", "likely"}
    assert finding.validation_status == "unverified"
    assert finding.evidence_quality == "weak"
    assert finding.proof_of_concept["cvss_score"] == 3.7


def test_forbidden_phrases_are_replaced_with_limitation_language() -> None:
    data = ScanReportData(scan_id="s", tenant_id="t")
    gate = build_report_quality_gate(data)
    texts, warnings = sanitize_ai_sections_for_quality(
        {
            "business_risk": (
                "The target is relatively stable. This positive observation means no financial fraud risk."
            )
        },
        data,
        gate,
    )

    lower = texts["business_risk"].lower()
    assert "relatively stable" not in lower
    assert "positive observation" not in lower
    assert "financial fraud" not in lower
    assert warnings


def test_high_or_critical_without_evidence_is_blocked() -> None:
    findings = normalize_findings_for_report(
        [
            FindingRow(
                id="f-high",
                tenant_id="t",
                scan_id="s",
                severity="critical",
                title="Unsupported critical finding",
                description="No evidence.",
                cvss=9.0,
                confidence="confirmed",
            )
        ]
    )

    assert findings == []


def test_remediation_does_not_assume_stack_when_stack_unknown() -> None:
    data = ScanReportData(scan_id="s", tenant_id="t")
    gate = build_report_quality_gate(data)
    texts, warnings = sanitize_ai_sections_for_quality(
        {"remediation_step": "Use Express.js middleware and Nginx directives to rate limit."},
        data,
        gate,
    )

    lower = texts["remediation_step"].lower()
    assert "express" not in lower
    assert "nginx" not in lower
    assert "application middleware" in lower
    assert "identity provider" in lower
    assert warnings


def test_estimate_cvss_vector_matches_vector_after_context_adjustment() -> None:
    """Context tweaks must keep base_score/severity in sync with the final vector (CVSS3 parse)."""
    cv_xss = estimate_cvss_vector("CWE-79", context={"authenticated": True})
    assert cv_xss is not None
    assert "/PR:L/" in cv_xss.vector_string
    parsed_xss = parse_cvss_vector(cv_xss.vector_string)
    assert cv_xss.base_score == parsed_xss.base
    assert cv_xss.severity == parsed_xss.severity.lower()

    cv_sqli = estimate_cvss_vector("CWE-89", context={"local": True})
    assert cv_sqli is not None
    assert "/AV:L/" in cv_sqli.vector_string
    parsed_sqli = parse_cvss_vector(cv_sqli.vector_string)
    assert cv_sqli.base_score == parsed_sqli.base
    assert cv_sqli.severity == parsed_sqli.severity.lower()
    assert cv_sqli.base_score < 9.8
