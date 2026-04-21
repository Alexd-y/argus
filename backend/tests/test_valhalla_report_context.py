"""VHL-001 — valhalla_report_context builder and parsers."""

from __future__ import annotations

from unittest.mock import patch

from src.reports.valhalla_report_context import (
    ValhallaReportContext,
    build_appendix_tools,
    build_risk_matrix,
    build_valhalla_report_context,
)


def test_parse_robots_and_sitemap_from_downloaded_raw() -> None:
    robots_body = (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Sitemap: https://ex.example/sitemap.xml\n"
    )
    sitemap_body = (
        '<?xml version="1.0"?><urlset>'
        "<loc>https://ex.example/a</loc><loc>https://ex.example/b</loc>"
        "</urlset>"
    )

    def fake_download(key: str) -> bytes | None:
        if "robots" in key:
            return robots_body.encode()
        if "sitemap" in key:
            return sitemap_body.encode()
        return None

    keys = [
        ("t/s/recon/raw/20260101T000000_abc_robots_txt.txt", "recon"),
        ("t/s/recon/raw/20260101T000000_abc_sitemap_xml.xml", "recon"),
    ]

    with patch("src.reports.valhalla_report_context.download_by_key", side_effect=fake_download):
        ctx = build_valhalla_report_context(
            tenant_id="t",
            scan_id="s",
            recon_results=None,
            tech_profile=None,
            anomalies_structured=None,
            raw_artifact_keys=keys,
            phase_outputs=[],
            phase_inputs=[],
            findings=[],
            report_technologies=None,
            fetch_raw_bodies=True,
        )

    assert ctx.robots_txt_analysis.found is True
    assert "/admin/" in (ctx.robots_txt_analysis.disallowed_paths_sample or [])
    assert ctx.robots_txt_analysis.sitemap_hints
    assert ctx.sitemap_analysis.found is True
    assert ctx.sitemap_analysis.url_count == 2
    assert len(ctx.sitemap_analysis.sample_urls) == 2


def test_threat_and_exploit_excerpts_from_phase_outputs() -> None:
    ctx = build_valhalla_report_context(
        tenant_id="ten",
        scan_id="sc",
        recon_results=None,
        tech_profile=None,
        anomalies_structured=None,
        raw_artifact_keys=[],
        phase_outputs=[
            (
                "threat_modeling",
                {"threat_model": {"flows": [{"id": "f1"}], "note": "x" * 100}},
            ),
            ("exploitation", {"exploits": [{"id": "e1"}]}),
            ("post_exploitation", {"artifacts": []}),
        ],
        phase_inputs=[],
        findings=[],
        report_technologies=None,
        fetch_raw_bodies=False,
    )
    assert "flows" in ctx.threat_model_excerpt or "threat" in ctx.threat_model_excerpt.lower()
    assert "/api/v1/tenants/ten/scans/sc/phases/threat_modeling" == ctx.threat_model_phase_link
    assert ctx.exploitation_post_excerpt


def test_tech_stack_table_from_recon_results() -> None:
    recon = {
        "tech_stack": [
            {
                "host": "https://a.example",
                "indicator_type": "platform",
                "value": "nginx",
                "evidence": "Server header",
                "confidence": 0.9,
            }
        ]
    }
    ctx = build_valhalla_report_context(
        tenant_id="t",
        scan_id="s",
        recon_results=recon,
        tech_profile=None,
        anomalies_structured=None,
        raw_artifact_keys=[],
        phase_outputs=[("recon", {"ports": [80, 443]})],
        phase_inputs=[],
        findings=[],
        report_technologies=["PHP"],
        fetch_raw_bodies=False,
    )
    cats = {r.category for r in ctx.tech_stack_table}
    assert "web_server" in cats or "report" in cats
    assert any("nginx" in r.name for r in ctx.tech_stack_table)


def test_outdated_from_findings_cve() -> None:
    ctx = build_valhalla_report_context(
        tenant_id="t",
        scan_id="s",
        recon_results=None,
        tech_profile=None,
        anomalies_structured=None,
        raw_artifact_keys=[],
        phase_outputs=[],
        phase_inputs=[],
        findings=[
            {
                "title": "openssl — CVE-2023-0001 in scan",
                "description": "See CVE-2023-0001",
            }
        ],
        report_technologies=None,
        fetch_raw_bodies=False,
    )
    assert ctx.outdated_components
    assert any("CVE-2023-0001" in c for c in ctx.outdated_components[0].cves)
    assert ctx.outdated_components[0].recommendation


def test_default_empty_context() -> None:
    v = ValhallaReportContext()
    assert v.robots_txt_analysis.found is False
    assert v.sitemap_analysis.url_count == 0
    assert v.tech_stack_table == []
    assert v.risk_matrix.variant == "matrix"
    assert v.risk_matrix.cells == []
    assert v.risk_matrix.distribution == []
    assert v.critical_vulns == []
    assert v.appendix_tools == []


def test_appendix_tools_from_tool_runs_and_phase_fallback() -> None:
    ctx = build_valhalla_report_context(
        tenant_id="t",
        scan_id="s",
        recon_results=None,
        tech_profile=None,
        anomalies_structured=None,
        raw_artifact_keys=[],
        phase_outputs=[
            ("vuln_analysis", {"runs": [{"tool": "dalfox", "version": "2.8.0"}]}),
        ],
        phase_inputs=[],
        findings=[],
        report_technologies=None,
        fetch_raw_bodies=False,
        tool_runs=[("nuclei", {"version": "3.2.0"}), ("nmap", None)],
    )
    names = [x.name for x in ctx.appendix_tools]
    assert "nuclei" in names
    assert "nmap" in names
    assert "dalfox" in names
    dalfox = next(x for x in ctx.appendix_tools if x.name == "dalfox")
    assert dalfox.version == "2.8.0"
    nuclei = next(x for x in ctx.appendix_tools if x.name == "nuclei")
    assert nuclei.version == "3.2.0"
    nmap = next(x for x in ctx.appendix_tools if x.name == "nmap")
    assert nmap.version is None


def test_appendix_tools_raw_artifact_type_tool_stdout() -> None:
    tools = build_appendix_tools(
        tool_runs=None,
        phase_outputs=[],
        raw_artifact_types=["tool_httpx_stdout", "robots_txt", "tool_nuclei_stderr"],
    )
    names = {t.name for t in tools}
    assert names == {"httpx", "nuclei"}


def test_build_appendix_tools_prefers_db_before_phase_duplicate_name() -> None:
    tools = build_appendix_tools(
        tool_runs=[("httpx", {"tool_version": "1.2"})],
        phase_outputs=[("recon", {"tool": "httpx"})],
        raw_artifact_types=["tool_httpx_stdout"],
    )
    hx = [t for t in tools if t.name.lower() == "httpx"]
    assert len(hx) == 2
    assert any(t.version == "1.2" for t in hx)
    assert any(t.version is None for t in hx)


def test_risk_matrix_sparse_findings_vhq003() -> None:
    ctx = build_valhalla_report_context(
        tenant_id="t",
        scan_id="s",
        recon_results=None,
        tech_profile=None,
        anomalies_structured=None,
        raw_artifact_keys=[],
        phase_outputs=[],
        phase_inputs=[],
        findings=[
            {"id": "a1", "severity": "high", "title": "X", "cvss": 8.1},
            {"id": "a2", "severity": "low", "title": "Y", "cvss": 2.0},
        ],
        report_technologies=None,
        fetch_raw_bodies=False,
    )
    assert ctx.risk_matrix.variant == "matrix"
    assert ctx.risk_matrix.distribution == []
    by_key = {(c.impact, c.likelihood): c for c in ctx.risk_matrix.cells}
    assert ("high", "low") in by_key
    assert "a1" in by_key[("high", "low")].finding_ids
    assert ("low", "low") in by_key
    assert "a2" in by_key[("low", "low")].finding_ids


def test_risk_matrix_cia_and_likelihood_vhq003() -> None:
    vec_rce = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"
    vec_info = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"
    ctx = build_valhalla_report_context(
        tenant_id="t",
        scan_id="s",
        recon_results=None,
        tech_profile=None,
        anomalies_structured=None,
        raw_artifact_keys=[],
        phase_outputs=[],
        phase_inputs=[],
        findings=[
            {
                "id": "c1",
                "severity": "critical",
                "title": "RCE",
                "cvss": 9.8,
                "cvss_vector": vec_rce,
                "proof_of_concept": {"payload": "x"},
            },
            {"id": "c2", "severity": "low", "title": "Cookie", "cvss": 3.1},
            {
                "id": "c3",
                "severity": "medium",
                "title": "Info",
                "cvss": 5.5,
                "cvss_vector": vec_info,
            },
        ],
        report_technologies=None,
        fetch_raw_bodies=False,
    )
    assert ctx.risk_matrix.variant == "matrix"
    assert ctx.risk_matrix.distribution == []
    by_key = {(c.impact, c.likelihood): c for c in ctx.risk_matrix.cells}
    assert ("high", "medium") in by_key
    assert "c1" in by_key[("high", "medium")].finding_ids
    assert ("low", "low") in by_key
    assert "c2" in by_key[("low", "low")].finding_ids
    assert ("medium", "low") in by_key
    assert "c3" in by_key[("medium", "low")].finding_ids


def test_critical_vulns_cvss7_and_secondary_signal_vhq004() -> None:
    ctx = build_valhalla_report_context(
        tenant_id="t",
        scan_id="s",
        recon_results=None,
        tech_profile=None,
        anomalies_structured=None,
        raw_artifact_keys=[],
        phase_outputs=[],
        phase_inputs=[],
        findings=[
            {
                "id": "v1",
                "severity": "Critical",
                "title": "RCE",
                "cvss": 9.0,
                "description": "Confirmed in staging environment.",
            },
            {
                "id": "v2",
                "severity": "high",
                "title": "XSS",
                "cvss": 7.2,
                "proof_of_concept": {"html": "<img src=x>"},
            },
            {"id": "v3", "severity": "medium", "title": "Minor", "cvss": 4.0},
            {"id": "v4", "severity": "high", "title": "No signal", "cvss": 8.0, "description": "Generic text only."},
        ],
        report_technologies=None,
        fetch_raw_bodies=False,
    )
    ids = {v.vuln_id for v in ctx.critical_vulns}
    assert ids == {"v1", "v2"}
    xss = next(v for v in ctx.critical_vulns if v.vuln_id == "v2")
    assert xss.title == "XSS"
    assert xss.severity == "high"
    assert xss.cvss == 7.2
    assert xss.exploit_available is True


def test_build_risk_matrix_export() -> None:
    m = build_risk_matrix(
        [{"id": "z", "severity": "high", "cvss": 8.0, "title": "t", "proof_of_concept": {"a": 1}}]
    )
    assert len(m.cells) == 1
    assert m.cells[0].count == 1


def test_mandatory_sections_coverage_and_harvester_flag() -> None:
    ctx = build_valhalla_report_context(
        tenant_id="t",
        scan_id="s",
        recon_results=None,
        tech_profile=None,
        anomalies_structured=None,
        raw_artifact_keys=[],
        phase_outputs=[("recon", {"ports": [80]})],
        phase_inputs=[],
        findings=[],
        report_technologies=None,
        fetch_raw_bodies=False,
        harvester_enabled=False,
        tool_run_summaries=[("nuclei", "failed")],
    )
    expected_keys = {
        "tech_stack_structured",
        "outdated_components",
        "ssl_tls_analysis",
        "security_headers_analysis",
        "robots_sitemap_analysis",
        "leaked_emails",
    }
    assert set(ctx.coverage.sections.keys()) == expected_keys
    assert ctx.coverage.feature_flags["HARVESTER_ENABLED"] is False
    assert ctx.coverage.feature_flags["INCLUDE_MINIO"] is False
    assert "recon" in ctx.coverage.phases_executed
    assert ctx.mandatory_sections.leaked_emails.status == "not_executed"
    assert "HARVESTER_ENABLED=false" in ctx.mandatory_sections.leaked_emails.reason
    assert ctx.robots_sitemap_analysis.robots_txt.found is False
    assert ctx.robots_sitemap_analysis.merged.robots_found is False
    assert ctx.coverage.tool_errors_summary
    assert ctx.coverage.tool_errors_summary[0]["tool"] == "nuclei"


def test_raw_tool_empty_stdout_errors_drive_partial_statuses() -> None:
    keys = [
        ("t/s/vuln_analysis/raw/20260101T000000_000000_tool_whatweb_scan_target_stdout.txt", "vuln_analysis"),
        ("t/s/vuln_analysis/raw/20260101T000000_000001_tool_whatweb_scan_target_stderr.txt", "vuln_analysis"),
        ("t/s/vuln_analysis/raw/20260101T000000_000002_tool_whatweb_scan_target_meta.json", "vuln_analysis"),
        ("t/s/vuln_analysis/raw/20260101T000000_000003_tool_nikto_scan_target_stdout.txt", "vuln_analysis"),
        ("t/s/vuln_analysis/raw/20260101T000000_000004_tool_nikto_scan_target_stderr.txt", "vuln_analysis"),
        ("t/s/vuln_analysis/raw/20260101T000000_000005_tool_testssl_scan_target_stdout.txt", "vuln_analysis"),
        ("t/s/vuln_analysis/raw/20260101T000000_000006_tool_testssl_scan_target_stderr.txt", "vuln_analysis"),
        ("t/s/vuln_analysis/raw/20260101T000000_000007_tool_sslscan_scan_target_stdout.txt", "vuln_analysis"),
        ("t/s/vuln_analysis/raw/20260101T000000_000008_tool_sslscan_scan_target_stderr.txt", "vuln_analysis"),
        (
            "t/s/vuln_analysis/raw/20260101T000000_000009_tool_theharvester_scan_target_stdout.txt",
            "vuln_analysis",
        ),
        (
            "t/s/vuln_analysis/raw/20260101T000000_000010_tool_theharvester_scan_target_stderr.txt",
            "vuln_analysis",
        ),
    ]

    def fake_download(key: str) -> bytes | None:
        if key.endswith("_stdout.txt"):
            return b""
        if key.endswith("_meta.json"):
            return b'{"exit_code": 127, "error_reason": "exec_os_error"}'
        if key.endswith("_stderr.txt"):
            return b"sandbox: binary not found\n"
        return None

    with patch("src.reports.valhalla_report_context.download_by_key", side_effect=fake_download):
        ctx = build_valhalla_report_context(
            tenant_id="t",
            scan_id="s",
            recon_results=None,
            tech_profile=None,
            anomalies_structured=None,
            raw_artifact_keys=keys,
            phase_outputs=[("vuln_analysis", {"findings": []})],
            phase_inputs=[],
            findings=[],
            report_technologies=None,
            fetch_raw_bodies=True,
            harvester_enabled=True,
            trivy_enabled=True,
        )

    assert ctx.mandatory_sections.tech_stack_structured.status == "partial"
    assert ctx.mandatory_sections.ssl_tls_analysis.status == "partial"
    assert ctx.mandatory_sections.security_headers_analysis.status == "partial"
    assert ctx.mandatory_sections.leaked_emails.status == "partial"
    assert ctx.mandatory_sections.outdated_components.status == "not_executed"
    tools = {row["tool"]: row for row in ctx.coverage.tool_errors_summary}
    assert tools["whatweb"]["status"] == "failed"
    assert tools["nikto"]["status"] == "no_output"
    assert tools["testssl"]["status"] == "no_output"
    assert tools["sslscan"]["status"] == "no_output"
    assert tools["theharvester"]["status"] == "no_output"


def test_build_valhalla_minimal_context_patch_keys() -> None:
    from src.reports.valhalla_report_context import build_valhalla_minimal_context_patch

    patch = build_valhalla_minimal_context_patch(
        phase_outputs=[("vuln_analysis", None)],
        raw_artifact_keys=[],
        fetch_raw_bodies=False,
        harvester_enabled=False,
        trivy_enabled=False,
        tool_run_summaries=None,
    )
    assert "mandatory_sections" in patch and "coverage" in patch and "robots_sitemap_analysis" in patch
    assert "vuln_analysis" in patch["coverage"]["phases_executed"]
