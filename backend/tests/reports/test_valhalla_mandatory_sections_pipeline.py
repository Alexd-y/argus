"""Regression tests for Valhalla evidence-driven mandatory sections."""

from __future__ import annotations

import re
from types import SimpleNamespace
from unittest.mock import patch

from src.reports import template_env
from src.reports.generators import build_owasp_compliance_rows
from src.reports.report_quality_gate import (
    ReportQualityGate,
    build_report_quality_gate,
    sanitize_ai_sections_for_quality,
)
from src.reports.valhalla_report_context import build_valhalla_report_context
from src.reports.valhalla_tool_health import build_tool_health_summary_rows, tool_health_rows_to_jinja


def _artifact_context(*, findings: list[dict[str, object]] | None = None):
    keys = [
        ("t/s/recon/raw/20260101_000001_robots_txt.txt", "recon"),
        ("t/s/recon/raw/20260101_000002_sitemap_xml.xml", "recon"),
        ("t/s/vuln/raw/20260101_000003_tool_testssl_stdout.txt", "vuln_analysis"),
        ("t/s/vuln/raw/20260101_000004_package_json.json", "vuln_analysis"),
    ]

    def fake_download(key: str) -> bytes | None:
        low = key.lower()
        if "robots" in low:
            return b"User-agent: *\nDisallow: /_next/static/\nSitemap: https://example.test/sitemap.xml\n"
        if "sitemap" in low:
            return b"<urlset><loc>https://example.test/_next/static/app.js</loc></urlset>"
        if "testssl" in low:
            return (
                b"TLS 1.2 offered\nTLS 1.3 offered\nIssuer: CN=Let's Encrypt\n"
                b"Not Before: Jan 1 2026\nNot After: Jan 1 2030\n"
                b"Strict-Transport-Security: max-age=31536000\n"
            )
        if "package_json" in low:
            return b'{"dependencies":{"react":"18.2.0","next":"14.2.1"}}'
        return None

    with patch("src.reports.valhalla_report_context.download_by_key", side_effect=fake_download):
        return build_valhalla_report_context(
            tenant_id="tenant",
            scan_id="scan",
            recon_results={
                "target_url": "https://example.test/",
                "tech_stack": [
                    {
                        "host": "https://example.test",
                        "indicator_type": "platform",
                        "value": "cloudflare",
                        "evidence": "server header",
                    }
                ],
                "http_headers": {
                    "https://example.test/": {
                        "server": "cloudflare",
                        "strict-transport-security": "max-age=31536000",
                    }
                },
            },
            tech_profile=None,
            anomalies_structured=None,
            raw_artifact_keys=keys,
            phase_outputs=[("recon", {"ports": [443], "html": "contact security@example.test"})],
            phase_inputs=[],
            findings=findings or [],
            report_technologies=None,
            fetch_raw_bodies=True,
            harvester_enabled=True,
            trivy_enabled=True,
            tool_run_summaries=[
                ("whatweb", "completed"),
                ("testssl", "completed"),
                ("nikto", "completed"),
                ("nmap", "completed"),
                ("theHarvester", "completed"),
                ("trivy", "completed"),
            ],
        )


def test_mandatory_sections_populated_when_tool_health_completed() -> None:
    ctx = _artifact_context()
    statuses = ctx.coverage.sections
    for section in (
        "tech_stack_structured",
        "outdated_components",
        "ssl_tls_analysis",
        "security_headers_analysis",
        "leaked_emails",
        "port_exposure",
    ):
        assert statuses[section]["status"] not in {"not_assessed", "not_executed", "no_data"}


def test_tls_completed_requires_ssl_tls_table_values() -> None:
    ctx = _artifact_context()
    assert ctx.mandatory_sections.ssl_tls_analysis.status == "completed"
    assert ctx.ssl_tls_table_rows
    assert "Let's Encrypt" in ctx.ssl_tls_table_rows[0].issuer
    assert ctx.ssl_tls_table_rows[0].tls_1_2.startswith("yes")


def test_headers_finding_requires_security_headers_table() -> None:
    ctx = _artifact_context(
        findings=[
            {
                "id": "hdr",
                "title": "Missing or incomplete HTTP security response headers",
                "severity": "low",
                "affected_url": "https://example.test/",
                "evidence": "Missing: Content-Security-Policy, X-Content-Type-Options",
            }
        ]
    )
    assert ctx.security_headers_table_rows
    assert {r["status"] for r in ctx.security_headers_table_rows} <= {"present", "missing"}


def test_ports_completed_requires_port_exposure_table() -> None:
    ctx = _artifact_context()
    assert ctx.port_exposure_table_rows
    assert any(row.port == "443" for row in ctx.port_exposure_table_rows)


def test_tech_stack_completed_requires_tech_stack_table() -> None:
    ctx = _artifact_context()
    assert ctx.tech_stack_table
    assert any("Next.js" in row.name or "cloudflare" in row.name.lower() for row in ctx.tech_stack_table)


def test_leaked_emails_completed_uses_fallback_or_no_observed_items() -> None:
    ctx = _artifact_context()
    assert ctx.mandatory_sections.leaked_emails.status == "completed"
    assert ctx.leaked_email_rows
    assert "***" in ctx.leaked_email_rows[0].email


def test_outdated_components_not_executed_only_without_artifacts() -> None:
    ctx = _artifact_context()
    assert ctx.outdated_components
    assert ctx.mandatory_sections.outdated_components.status in {"completed", "partial"}

    empty = build_valhalla_report_context(
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
        trivy_enabled=True,
    )
    assert empty.mandatory_sections.outdated_components.status == "not_executed"


def test_tool_health_downgrades_when_parser_empty() -> None:
    rows = build_tool_health_summary_rows(
        tool_run_summaries=[("testssl", "completed")],
        appendix_tool_names=["testssl"],
        raw_error_rows=[],
        mandatory_section_status={"ssl_tls_analysis": "no_data"},
    )
    rendered = tool_health_rows_to_jinja(rows)
    assert rendered[0]["state_label"] == "Partial / inconclusive"


def test_wstg_coverage_maps_executed_artifacts() -> None:
    ctx = _artifact_context()
    assert ctx.wstg_coverage
    assert ctx.wstg_coverage["partial"] > 0
    assert ctx.wstg_coverage["coverage_percentage"] > 0


def test_wstg_not_zero_when_robots_sitemap_or_tls_or_headers_exist() -> None:
    ctx = _artifact_context()
    assert ctx.wstg_coverage_zero_executed is False
    assert ctx.wstg_coverage and ctx.wstg_coverage["partial"] > 0


def test_owasp_mapping_english_only() -> None:
    rows = build_owasp_compliance_rows([], wstg_coverage={"coverage_percentage": 0}, use_valhalla_owasp_2021_misconfig_labels=True)
    blob = " ".join(str(v) for row in rows for v in row.values())
    assert not re.search(r"[А-Яа-яЁё]", blob)


def test_security_headers_maps_to_a05_2021() -> None:
    rows = build_owasp_compliance_rows(
        [{"id": "hdr", "owasp_category": "A02", "title": "Missing headers"}],
        wstg_coverage={"coverage_percentage": 0},
        use_valhalla_owasp_2021_misconfig_labels=True,
    )
    row = next(r for r in rows if r["category_id"] == "A02")
    assert row["display_category_code"] == "A05:2021"


def test_rate_limit_maps_to_a07_2021() -> None:
    rows = build_owasp_compliance_rows(
        [{"id": "rl", "owasp_category": "A07", "title": "Missing rate limiting"}],
        wstg_coverage={"coverage_percentage": 0},
        use_valhalla_owasp_2021_misconfig_labels=True,
    )
    row = next(r for r in rows if r["category_id"] == "A07")
    assert row["display_category_code"] == "A07:2021"


def test_unassessed_categories_do_not_say_no_findings_present() -> None:
    rows = build_owasp_compliance_rows([], wstg_coverage={"coverage_percentage": 0}, use_valhalla_owasp_2021_misconfig_labels=True)
    assert all(row["findings_present"] != "No findings present" for row in rows)
    assert all(row["assessment_result"] == "Not assessed" for row in rows)


def test_no_appendices_wrapper() -> None:
    partial = (template_env.report_templates_directory() / "partials" / "valhalla" / "appendices.html.j2").read_text(encoding="utf-8")
    assert "valhalla-appendices-wrap" not in partial
    assert 'id="appendices"' not in partial
    assert "<h2>Evidence Inventory</h2>" in partial


def test_no_raw_api_links() -> None:
    env = template_env.get_report_jinja_environment()
    html = env.get_template("partials/active_web_scan.html.j2").render(
        tier="valhalla",
        tier_stubs={"valhalla": {"active_web_scan": True}},
        active_web_scan={"visible": True, "tools_run": ["nuclei"], "ai_summary_rows": [], "curl_xss_example": ""},
        scan_id="123e4567-e89b-12d3-a456-426614174000",
    )
    assert "GET /api/v1/scans" not in html


def test_no_internal_uuid_links() -> None:
    env = template_env.get_report_jinja_environment()
    html = env.get_template("partials/active_web_scan.html.j2").render(
        tier="valhalla",
        tier_stubs={"valhalla": {"active_web_scan": True}},
        active_web_scan={"visible": True, "tools_run": [], "ai_summary_rows": [], "curl_xss_example": ""},
        scan_id="123e4567-e89b-12d3-a456-426614174000",
    )
    assert "123e4567-e89b-12d3-a456-426614174000" not in html


def test_no_phase_artifacts_section() -> None:
    env = template_env.get_report_jinja_environment()
    html = env.get_template("partials/active_web_scan.html.j2").render(
        tier="valhalla",
        tier_stubs={"valhalla": {"active_web_scan": True}},
        active_web_scan={"visible": True, "tools_run": [], "ai_summary_rows": [], "curl_xss_example": ""},
        scan_id="s",
    )
    assert "Phase Artifacts" not in html


def test_no_ai_exaggeration_for_header_findings() -> None:
    data = SimpleNamespace(
        findings=[
            {
                "title": "Missing or incomplete HTTP security response headers",
                "description": "Missing CSP",
                "severity": "medium",
            }
        ],
        valhalla_context=_artifact_context(),
        scan=None,
        report=SimpleNamespace(tier="valhalla"),
    )
    gate = build_report_quality_gate(data)
    out, warnings = sanitize_ai_sections_for_quality(
        {"business_risk": "This significant vulnerability could be exploited by attackers to compromise the application."},
        data,
        gate,
    )
    assert warnings
    assert "significant vulnerability" not in out["business_risk"].lower()
    assert "compromise the application" not in out["business_risk"].lower()


def test_no_exploit_available_without_exploit() -> None:
    data = SimpleNamespace(findings=[], valhalla_context=_artifact_context(), scan=None, report=SimpleNamespace(tier="valhalla"))
    out, warnings = sanitize_ai_sections_for_quality(
        {"compliance_check": "exploit_available is true for this vulnerability."},
        data,
        ReportQualityGate(),
    )
    assert warnings
    assert "exploit_available" not in out["compliance_check"]


def test_evidence_inventory_has_parsed_summaries() -> None:
    ctx = _artifact_context()
    summaries = " ".join(row.summary for row in ctx.evidence_inventory)
    assert "References attached" not in summaries
    assert "Certificate issuer" in summaries
    assert "HTTP response headers parsed" in summaries
    assert "443/tcp" in summaries or "443/tcp open" in summaries
