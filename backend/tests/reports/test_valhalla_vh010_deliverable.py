"""VH-010 — Valhalla customer deliverable: appendices, sanitization, fallbacks, OWASP, quality gate."""



from __future__ import annotations



from pathlib import Path

from src.reports.data_collector import FindingRow, ScanReportData

from src.reports.finding_quality_filter import filter_valid_findings

from src.reports.generators import VALHALLA_OWASP_2021_SECURITY_MISCONFIGURATION_CODE, build_owasp_compliance_rows

from src.reports.report_quality_gate import (

    build_report_quality_gate,

    cvss_conflict_reason,

    evaluate_valhalla_engagement_title_and_full,

    normalize_findings_for_report,

    safe_section_text,

    sanitize_ai_sections_for_quality,

)

from src.reports import template_env

from src.reports.valhalla_finding_normalization import (

    header_gap_verification_commands,

    valhalla_header_finding_remediation_text,

)

from src.reports.valhalla_report_context import (

    DependencyAnalysisRow,

    SslTlsAnalysisModel,

    build_ssl_tls_table_rows,

    build_valhalla_report_context,

)

from src.reports.valhalla_report_context import _outdated_from_trivy_dependency_rows

from src.reports.valhalla_tool_health import (

    build_tool_health_summary_rows,

    sanitize_customer_tool_text,

    tool_health_rows_to_jinja,

)

from src.services.reporting import findings_rows_for_jinja





def _valhalla_template_root() -> Path:

    return template_env.report_templates_directory()





# --- VH-001 / template surface ---

def test_valhalla_removes_appendices() -> None:

    """Customer Valhalla main template wires Evidence Inventory / appendices partial, not legacy key slots."""

    v = (_valhalla_template_root() / "valhalla.html.j2").read_text(encoding="utf-8")
    base = (_valhalla_template_root() / "valhalla_secreport_base.html.j2").read_text(encoding="utf-8")
    partial = (_valhalla_template_root() / "partials" / "valhalla" / "appendices.html.j2").read_text(
        encoding="utf-8"
    )

    assert "partials/valhalla/appendices.html.j2" in v

    assert "valhalla_appendix" not in v

    assert "Appendix A" not in v
    assert "Valhalla Penetration Test Report" not in base
    assert 'id="appendices"' not in partial
    assert "valhalla-appendices-title" not in partial
    assert "<h2" not in partial or "Appendices" not in partial





def _tool_health_jinja_from_noisy_rows() -> list[dict[str, object]]:

    raw = [

        {

            "tool": "nuclei",

            "status": "failed",

            "note": "MCP connect error; minio presigned s3://bucket/x X-Amz-Date=1",

        },

        {

            "tool": "httpx",

            "status": "error",

            "note": "Error response from daemon: /var/run/docker.sock denied",

        },

    ]

    rows = build_tool_health_summary_rows(

        tool_run_summaries=[("nuclei", "failed"), ("httpx", "ok")],

        appendix_tool_names=["nuclei", "httpx"],

        raw_error_rows=raw,

    )

    return tool_health_rows_to_jinja(rows)





def test_no_minio_links_in_customer_report() -> None:

    j = _tool_health_jinja_from_noisy_rows()

    blob = " ".join(str(x.get("summary") or "") for x in j).lower()

    assert "minio" not in blob

    assert "s3://" not in blob

    assert "x-amz" not in blob





def test_no_docker_socket_errors_in_customer_report() -> None:

    j = _tool_health_jinja_from_noisy_rows()

    blob = " ".join(str(x.get("summary") or "") for x in j).lower()

    assert "docker.sock" not in blob

    assert "docker" not in blob or "[path]" in " ".join(str(x.get("summary") or "") for x in j).lower()





def test_tool_health_summary_normalizes_mcp_failures() -> None:

    out = sanitize_customer_tool_text("MCP stdio /var/run/docker.sock minio:9000 presigned s3://x")

    assert "docker.sock" not in out.lower()

    assert "minio" not in out.lower()

    assert "[storage]" in out or "[path]" in out


def test_tool_health_summary_hides_internal_wrapper_names() -> None:
    rows = build_tool_health_summary_rows(
        tool_run_summaries=[("sslscan_scan_glomsoposten_vercel_app_2_testssl_va_web_surface__sscan", "completed")],
        appendix_tool_names=["theharvester_scan_glomsoposten_vercel_app_3_theharvester_harvester"],
        raw_error_rows=[],
    )
    rendered = tool_health_rows_to_jinja(rows)
    blob = " ".join(str(row.get("tools") or "") for row in rendered).lower()
    assert "scan_glomsoposten" not in blob
    assert "web_surface" not in blob
    assert "testssl.sh" in blob or "sslscan" in blob
    assert "theharvester" in blob


def test_tool_health_summary_respects_mandatory_section_status() -> None:

    rows = build_tool_health_summary_rows(
        tool_run_summaries=[
            ("testssl", "completed"),
            ("whatweb", "completed"),
            ("nikto", "completed"),
            ("theHarvester", "completed"),
            ("nmap", "completed"),
        ],
        appendix_tool_names=["testssl", "whatweb", "nikto", "theHarvester", "nmap"],
        raw_error_rows=[],
        mandatory_section_status={
            "ssl_tls_analysis": "not_assessed",
            "tech_stack_structured": "not_assessed",
            "security_headers_analysis": "not_assessed",
            "leaked_emails": "no_data",
            "port_exposure": "not_assessed",
        },
    )
    j = {str(row["capability_id"]): row for row in tool_health_rows_to_jinja(rows)}

    assert j["tls_assessment"]["state_label"] == "Partial / inconclusive"
    assert j["technology_fingerprinting"]["state_label"] == "Partial / inconclusive"
    assert j["web_server_scan"]["state_label"] == "Partial / inconclusive"
    assert j["email_osint"]["state_label"] == "Partial / inconclusive"
    assert j["port_discovery"]["state_label"] == "Partial / inconclusive"
    assert "Completed" not in {j["tls_assessment"]["state_label"], j["port_discovery"]["state_label"]}





# --- VH-003 fallbacks (minimal recon / finding-driven paths) ---

def test_fallback_data_populates_tls() -> None:

    ctx = build_valhalla_report_context(

        tenant_id="t1",

        scan_id="s1",

        recon_results={

            "ssl_certs": {

                "fixture.example": [

                    {

                        "common_name": "fixture.example",

                        "issuer": "CN=Test CA",

                        "validity_not_before": "2024-01-01",

                        "validity_not_after": "2027-01-01",

                    }

                ],

            },

        },

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

    assert (ctx.ssl_tls_analysis.issuer or "").strip() or ctx.ssl_tls_table_rows

    if ctx.ssl_tls_table_rows:

        assert "fixture" in (ctx.ssl_tls_table_rows[0].domain or "").lower() or "EV-SSL" in (

            ctx.ssl_tls_table_rows[0].evidence_id or ""

        )





def test_fallback_data_populates_security_headers() -> None:

    ctx = build_valhalla_report_context(

        tenant_id="t1",

        scan_id="s1",

        recon_results=None,

        tech_profile=None,

        anomalies_structured=None,

        raw_artifact_keys=[],

        phase_outputs=[],

        phase_inputs=[],

        findings=[

            {

                "title": "Missing: Content-Security-Policy, Strict-Transport-Security",

                "description": "Review HTTP security response headers; CSP and HSTS absent.",

            },

        ],

        report_technologies=None,

        fetch_raw_bodies=False,

        harvester_enabled=True,

        trivy_enabled=True,

    )

    assert ctx.security_headers_analysis.rows

    assert "missing" in (ctx.security_headers_analysis.summary or "").lower() or ctx.security_headers_analysis.rows[0].get(

        "value_sample"

    )





def test_fallback_data_populates_tech_stack() -> None:

    ctx = build_valhalla_report_context(

        tenant_id="t1",

        scan_id="s1",

        recon_results={

            "tech_stack": [

                {

                    "host": "https://a.example",

                    "indicator_type": "platform",

                    "value": "openresty",

                    "evidence": "header",

                    "confidence": 0.85,

                },

            ],

        },

        tech_profile=None,

        anomalies_structured=None,

        raw_artifact_keys=[],

        phase_outputs=[],

        phase_inputs=[],

        findings=[],

        report_technologies=None,

        fetch_raw_bodies=False,

    )

    assert ctx.tech_stack_structured.web_server or any("openresty" in (r.name or "").lower() for r in ctx.tech_stack_table)





def test_fallback_data_populates_ports() -> None:

    ctx = build_valhalla_report_context(

        tenant_id="t1",

        scan_id="s1",

        recon_results=None,

        tech_profile=None,

        anomalies_structured=None,

        raw_artifact_keys=[],

        phase_outputs=[("recon", {"ports": [22, 80, 443], "live_hosts": ["a.example"]})],

        phase_inputs=[],

        findings=[],

        report_technologies=None,

        fetch_raw_bodies=False,

    )

    pe = ctx.port_exposure

    assert pe.summary_text or pe.open_port_hints or (pe.has_open_ports is True)





def test_fallback_data_populates_leaked_emails() -> None:

    ctx = build_valhalla_report_context(

        tenant_id="t1",

        scan_id="s1",

        recon_results=None,

        tech_profile=None,

        anomalies_structured=None,

        raw_artifact_keys=[],

        phase_outputs=[

            (

                "recon",

                {

                    "tool": "theHarvester",

                    "stdout": "harvested: user@example.com, other@org.test",

                },

            ),

        ],

        phase_inputs=[],

        findings=[],

        report_technologies=None,

        fetch_raw_bodies=False,

        harvester_enabled=True,

    )

    assert ctx.leaked_emails or "@" in (ctx.recon_pipeline_summary or "")





# --- OWASP / findings alignment ---

def test_owasp_mapping_security_headers_is_a05_2021() -> None:

    data = ScanReportData(

        scan_id="s",

        tenant_id="t",

        findings=[

            FindingRow(

                id="h1",

                tenant_id="t",

                scan_id="s",

                severity="medium",

                title="Missing or incomplete HTTP security response headers",

                description="CSP and HSTS not set. " + "x" * 12,

                cwe="CWE-693",

                owasp_category="A02",

            )

        ],

    )

    [row] = findings_rows_for_jinja(data, report_tier="valhalla")

    assert row.get("owasp_display_code") == VALHALLA_OWASP_2021_SECURITY_MISCONFIGURATION_CODE

    assert row.get("owasp_top10_2021") == "A05:2021"





def test_finding_table_uses_same_owasp_mapping_as_compliance_table() -> None:

    frow = {

        "id": "x1",

        "severity": "medium",

        "title": "Missing or incomplete HTTP security response headers",

        "description": "Gap in CSP configuration. " + "y" * 12,

        "owasp_category": "A02",

    }

    [jr] = findings_rows_for_jinja(

        ScanReportData(

            scan_id="s",

            tenant_id="t",

            findings=[

                FindingRow(

                    id="x1",

                    tenant_id="t",

                    scan_id="s",

                    severity="medium",

                    title=frow["title"],

                    description=frow["description"],

                    owasp_category="A02",

                )

            ],

        ),

        report_tier="valhalla",

    )

    ocode = str(jr.get("owasp_display_code") or jr.get("owasp_top10_2021") or "")

    crows = build_owasp_compliance_rows([frow], use_valhalla_owasp_2021_misconfig_labels=True)

    a02 = next(r for r in crows if r["category_id"] == "A02")

    assert a02.get("display_category_code") == ocode == "A05:2021"





# --- VH-007 wording ---

def test_no_x_xss_protection_recommendation() -> None:

    txt = valhalla_header_finding_remediation_text().lower()

    assert "set x-xss-protection: 1" not in txt

    assert "enable x-xss-protection" not in txt

    assert "do not rely" in txt





def test_no_unauthorized_access_claim_for_headers() -> None:

    data = ScanReportData(

        scan_id="s",

        tenant_id="t",

        findings=[

            FindingRow(

                id="hdr1",

                tenant_id="t",

                scan_id="s",

                severity="medium",

                title="Strict-Transport-Security header is not set",

                description="Passive observation of response headers. " + "z" * 12,

                cwe="CWE-693",

                cvss=4.3,

                proof_of_concept={"observed_headers": ["server: nginx"]},

            )

        ],

    )

    gate = build_report_quality_gate(data)

    for key in ("attack_scenarios", "exploit_chains", "executive_summary"):

        t = safe_section_text(key, data, gate).lower()

        assert "unauthorized access" not in t

        assert "unauthorized transactions" not in t





def test_no_exploit_available_without_exploit() -> None:

    rows = _outdated_from_trivy_dependency_rows(

        [

            DependencyAnalysisRow(

                package="acme",

                version="1.0.0",

                severity="medium",

                source="trivy",

                detail="CVE-2024-0001 in dependency",

            ),

        ],

        trivy_enabled=True,

    )

    assert rows

    assert rows[0].cves

    assert rows[0].exploit_available is False





def test_security_header_finding_has_commands() -> None:

    data = ScanReportData(

        scan_id="s",

        tenant_id="t",

        findings=[

            FindingRow(

                id="h2",

                tenant_id="t",

                scan_id="s",

                severity="medium",

                title="Content-Security-Policy header is absent",

                description="CSP not configured. " + "a" * 12,

                cwe="CWE-693",

                proof_of_concept={"request_url": "https://app.example.com/login"},

            )

        ],

    )

    [row] = findings_rows_for_jinja(data, report_tier="valhalla")

    cmds = row.get("verification_commands") or []

    assert any(str(c.get("command", "")).lower().find("curl") >= 0 for c in cmds if isinstance(c, dict))

    more = header_gap_verification_commands("https://app.example.com/")

    assert any("curl" in m.get("command", "").lower() for m in more)





# --- SSL table ---

def test_ssl_tls_table_has_real_values_when_artifacts_exist() -> None:

    recon = {

        "ssl_certs": {

            "svc.example": [

                {

                    "common_name": "svc.example",

                    "subject_alternative_names": ["svc.example"],

                    "issuer": "O=LE",

                    "validity_not_before": "2025-01-01",

                    "validity_not_after": "2026-01-01",

                }

            ],

        },

    }

    ssl_out = SslTlsAnalysisModel(

        protocols=["TLSv1.2", "TLSv1.3"],

        weak_protocols=[],

        weak_ciphers=[],

        hsts="max-age=31536000",

    )

    rows = build_ssl_tls_table_rows(recon, ssl_out, target_hint="https://svc.example")

    assert rows

    r0 = rows[0]

    assert (r0.domain or "").lower().find("example") >= 0

    assert (r0.issuer or "—") != ""





# --- Mandatory section semantics ---

def test_not_assessed_only_when_no_primary_or_fallback_data() -> None:

    # Finding-driven header matrix present ⇒ not a blind 'not_assessed' for this domain.

    ctx = build_valhalla_report_context(

        tenant_id="t1",

        scan_id="s1",

        recon_results=None,

        tech_profile=None,

        anomalies_structured=None,

        raw_artifact_keys=[],

        phase_outputs=[],

        phase_inputs=[],

        findings=[

            {

                "title": "Missing: X-Content-Type-Options, Referrer-Policy",

                "description": "Response headers review. " + "b" * 12,

            },

        ],

        report_technologies=None,

        fetch_raw_bodies=False,

    )

    m = ctx.mandatory_sections

    st = m.security_headers_analysis.status if m else ""

    assert st != "not_assessed"


def test_failed_primary_tool_with_fallback_data_is_partial_not_completed() -> None:

    ctx = build_valhalla_report_context(
        tenant_id="t1",
        scan_id="s1",
        recon_results={
            "tech_stack": [
                {
                    "host": "https://a.example",
                    "indicator_type": "platform",
                    "value": "openresty",
                    "evidence": "header",
                    "confidence": 0.85,
                }
            ]
        },
        tech_profile=None,
        anomalies_structured=None,
        raw_artifact_keys=[],
        phase_outputs=[],
        phase_inputs=[],
        findings=[],
        report_technologies=None,
        fetch_raw_bodies=False,
        tool_run_summaries=[("whatweb", "failed")],
    )

    assert ctx.mandatory_sections.tech_stack_structured.status == "parsed_from_fallback"
    tech_health = next(
        row for row in ctx.tool_health_summary if row.get("capability_id") == "technology_fingerprinting"
    )
    assert tech_health["state_label"] == "Partial / inconclusive"
    assert "Completed" not in tech_health["state_label"]





# --- Title / full Valhalla ---

def _good_finding_dict() -> dict[str, object]:

    return {

        "id": "g1",

        "severity": "high",

        "title": "SQL injection in report export",

        "description": "Parameter id is not sanitized. Evidence includes error-based response. " + "c" * 12,

        "cvss": 8.1,

        "cvss_score": 8.1,

        "proof_of_concept": {

            "request_url": "https://t.example/r?id=1'",

            "raw_response": "You have an error in your SQL syntax near",

        },

    }





def test_full_valhalla_title_only_when_coverage_threshold_met() -> None:

    mstat = {

        "tech_stack_structured": "partial",

        "ssl_tls_analysis": "partial",

        "security_headers_analysis": "partial",

        "port_exposure": "partial",

    }

    title, full = evaluate_valhalla_engagement_title_and_full(

        wstg_coverage_pct=75.0,

        mandatory_section_status=mstat,

        findings=[_good_finding_dict()],

        tool_error_rows=None,

    )

    assert "Full" in title

    assert full is True





def test_partial_title_when_coverage_low() -> None:

    mstat = {

        "tech_stack_structured": "partial",

        "ssl_tls_analysis": "partial",

        "security_headers_analysis": "partial",

        "port_exposure": "partial",

    }

    title, full = evaluate_valhalla_engagement_title_and_full(

        wstg_coverage_pct=40.0,

        mandatory_section_status=mstat,

        findings=[_good_finding_dict()],

        tool_error_rows=None,

    )

    assert "Partial" in title

    assert full is False


def test_header_only_ai_text_is_sanitized_to_a05_without_exaggeration() -> None:

    finding = FindingRow(
        id="f-hdr",
        tenant_id="t",
        scan_id="s",
        severity="medium",
        title="Missing or incomplete HTTP security response headers",
        description="Missing Content-Security-Policy and X-Content-Type-Options response headers.",
        cwe="CWE-693",
        cvss=4.3,
        owasp_category="A02",
        confidence="likely",
        evidence_refs=["curl -sI https://example.test"],
        proof_of_concept={
            "request_url": "https://example.test",
            "request_method": "HEAD",
            "response_status": 200,
        },
    )
    data = ScanReportData(scan_id="s", tenant_id="t", findings=[finding])
    gate = build_report_quality_gate(data)
    texts, warnings = sanitize_ai_sections_for_quality(
        {
            "vulnerability_description": (
                "The assessment identified a significant vulnerability. The absence of critical HTTP "
                "security headers could be exploited by attackers to compromise the application. OWASP A02."
            ),
            "compliance_check": "Security Misconfiguration (A02) was identified.",
        },
        data,
        gate,
        enforce_quality_gate=True,
    )

    blob = " ".join(texts.values()).lower()
    assert "significant vulnerability" not in blob
    assert "critical http" not in blob
    assert "compromise the application" not in blob
    assert "a02" not in blob
    assert "a05:2021" in texts["compliance_check"].lower()
    assert warnings





# --- Findings quality / CVSS ---

def test_unknown_finding_removed() -> None:

    bad = type("F", (), {"title": "Unknown finding", "description": "x" * 20})()

    assert filter_valid_findings([bad]) == []





def test_cvss_conflicts_normalized() -> None:

    f = FindingRow(

        id="c1",

        tenant_id="t",

        scan_id="s",

        severity="high",

        title="Issue",

        description="d" * 20,

        cvss=7.0,

        cvss_score=8.0,

        proof_of_concept={"request_url": "https://x.test/a", "raw_response": "ok"},

    )

    assert cvss_conflict_reason(f) is not None

    [n] = normalize_findings_for_report([f])

    assert cvss_conflict_reason(n) is None

    assert n.cvss == n.cvss_score
