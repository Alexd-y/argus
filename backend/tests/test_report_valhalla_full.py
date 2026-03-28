"""VHL / RPT — Valhalla HTML (production Jinja), JSON ``valhalla_report``, CSV sections (no network)."""

from __future__ import annotations

import csv
import io
import json
from unittest.mock import patch

import pytest

from src.api.schemas import Finding, ReportSummary
from src.reports.data_collector import (
    FindingRow,
    PhaseOutputRow,
    ReportRowSlice,
    ScanReportData,
    ScanRowData,
    TimelineRow,
)
from src.reports.generators import (
    ReportData,
    _VALHALLA_REPORT_SECTION_ORDER,
    build_valhalla_report_payload,
    generate_json,
    generate_valhalla_sections_csv,
)
from src.reports.template_env import get_report_jinja_environment, render_tier_report_html
from src.reports.valhalla_report_context import (
    AppendixToolEntryModel,
    CriticalVulnRefModel,
    DependencyAnalysisRow,
    OutdatedComponentRow,
    RiskMatrixCellModel,
    RiskMatrixModel,
    RobotsTxtAnalysisModel,
    SecurityHeadersAnalysisModel,
    SitemapAnalysisModel,
    SslTlsAnalysisModel,
    TechStackStructuredModel,
    TechStackTableRow,
    ValhallaReportContext,
)
from src.services.reporting import ReportGenerator


def _scan_valhalla_with_sample_vc() -> ScanReportData:
    vc = ValhallaReportContext(
        robots_txt_analysis=RobotsTxtAnalysisModel(
            found=True,
            disallowed_paths_sample=["/admin"],
            sitemap_hints=["https://fixture.example/sitemap.xml"],
        ),
        sitemap_analysis=SitemapAnalysisModel(
            found=True,
            url_count=2,
            sample_urls=["https://fixture.example/"],
        ),
        tech_stack_structured=TechStackStructuredModel(
            web_server="nginx/1.22",
            os="Linux",
            cms="",
            frameworks=[],
            js_libraries=[],
            ports_summary="443/tcp",
            services_summary="https",
        ),
        tech_stack_table=[
            TechStackTableRow(category="web", name="nginx", detail="1.22", source="probe"),
        ],
        outdated_components=[
            OutdatedComponentRow(
                component="openssl",
                installed_version="1.1.1",
                latest_stable="3.2",
                support_status="eol",
                cves=["CVE-2023-0001"],
                recommendation="Обновить до поддерживаемой ветки",
            ),
        ],
        leaked_emails=["u***@fixture.example"],
        ssl_tls_analysis=SslTlsAnalysisModel(
            issuer="CN=fixture",
            validity="2025 — 2026",
            protocols=["TLSv1.2", "TLSv1.3"],
            weak_ciphers=[],
            hsts="present",
        ),
        security_headers_analysis=SecurityHeadersAnalysisModel(
            summary="Fixture headers summary",
            rows=[
                {
                    "host": "fixture.example",
                    "header": "Strict-Transport-Security",
                    "value_sample": "max-age=",
                    "present": True,
                },
            ],
        ),
        dependency_analysis=[
            DependencyAnalysisRow(
                package="lodash",
                version="4.17.20",
                severity="medium",
                source="npm",
                detail="fixture",
            ),
        ],
        threat_model_excerpt="Fixture STRIDE excerpt for threat block.",
        exploitation_post_excerpt="Fixture exploitation phase excerpt.",
        risk_matrix=RiskMatrixModel(
            variant="matrix",
            cells=[
                RiskMatrixCellModel(
                    impact="high",
                    likelihood="medium",
                    finding_ids=["f-valhalla"],
                    count=1,
                ),
            ],
            distribution=[],
        ),
        critical_vulns=[
            CriticalVulnRefModel(
                vuln_id="CVE-2024-FIXTURE",
                title="Fixture critical",
                description="Краткое описание для шаблона.",
                severity="critical",
                cvss=9.1,
                exploit_available=True,
            ),
        ],
        appendix_tools=[AppendixToolEntryModel(name="nuclei", version="3.2.0")],
    )
    return ScanReportData(
        scan_id="scan-valhalla-full",
        tenant_id="tenant-valhalla-full",
        scan=ScanRowData(
            id="scan-valhalla-full",
            tenant_id="tenant-valhalla-full",
            target_id=None,
            target_url="https://fixture.example",
            status="done",
            progress=100,
            phase="reporting",
            options={
                "customer_email": "c@fixture.example",
                "object_text": "Fixture web app",
                "goal_text": "Fixture pentest goal",
            },
        ),
        report=ReportRowSlice(
            id="rep-valhalla-full",
            tenant_id="tenant-valhalla-full",
            target="https://fixture.example",
            scan_id="scan-valhalla-full",
            tier="valhalla",
            generation_status="pending",
            summary={"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
            technologies=["nginx"],
        ),
        findings=[
            FindingRow(
                id="f-valhalla",
                tenant_id="tenant-valhalla-full",
                scan_id="scan-valhalla-full",
                report_id="rep-valhalla-full",
                severity="critical",
                title="Fixture SQLi",
                description="Fixture description",
                cwe="CWE-89",
                cvss=9.0,
                cve="CVE-2024-FIXTURE",
            ),
        ],
        timeline=[
            TimelineRow(
                phase="recon",
                order_index=0,
                entry={"step": "fixture"},
                created_at="2026-03-27T00:00:00Z",
            ),
        ],
        phase_outputs=[
            PhaseOutputRow(
                phase="recon",
                output_data={"tool": "nmap", "stdout": "Fixture nmap line 1\n"},
                created_at=None,
            ),
        ],
        valhalla_context=vc,
    )


@patch("src.services.reporting.has_any_llm_key", return_value=True)
def test_valhalla_html_production_jinja_major_sections(_mock_llm: object) -> None:
    """Stable ``id=`` markers and RU/EN headings for Report Valhalla.md section order (VHL-004)."""
    gen = ReportGenerator()
    data = _scan_valhalla_with_sample_vc()
    ai_texts = {
        "executive_summary_valhalla": "Fixture executive (EN/RU slot).",
        "attack_scenarios": "Fixture attack scenarios.",
        "exploit_chains": "Fixture exploit chains.",
        "remediation_stages": "Fixture remediation stages.",
        "zero_day_potential": "Fixture zero-day narrative.",
        "prioritization_roadmap": "Fixture roadmap.",
        "hardening_recommendations": "Fixture hardening.",
        "vulnerability_description": "Fixture vuln description.",
        "remediation_step": "Fixture remediation step.",
        "business_risk": "Fixture business risk.",
        "compliance_check": "Fixture compliance.",
    }
    ctx = gen.prepare_template_context("valhalla", data, ai_texts)
    assert get_report_jinja_environment() is get_report_jinja_environment()

    html = render_tier_report_html("valhalla", ctx)

    section_checks: list[tuple[str, str]] = [
        ('id="valhalla-title"', "Титульный лист"),
        ('id="executive-summary"', "Executive Summary"),
        ('id="objectives"', "Объект, цели и задачи"),
        ('id="scope"', "Объём работ"),
        ('id="methodology"', "Методология и стандарты"),
        ('id="results-overview"', "Матрица рисков"),
        ('id="threat-modeling"', "Моделирование угроз"),
        ('id="findings"', "Findings"),
        ('id="exploitation"', "Exploit Chain"),
        ('id="remediation-priority"', "Рекомендации и приоритизация"),
        ('id="zero-day-potential"', "Zero-day"),
        ('id="conclusion"', "Заключение"),
        ('id="appendices"', "Приложения"),
    ]
    for marker, heading in section_checks:
        assert marker in html, f"missing marker {marker}"
        assert heading in html, f"missing heading {heading}"

    for appendix_heading in (
        "Приложение А. Список использованных инструментов",
        "Приложение Б. Фрагменты конфигураций",
        "Приложение В. Выдержки из журнала событий",
        "Приложение Г. Выдержка из nmap",
        "Приложение Д. Признаки APT",
        "Приложение Е. Результаты проверки утечек паролей",
    ):
        assert appendix_heading in html

    assert 'class="valhalla-tech-structured"' in html
    assert "Технологический стек и компоненты" in html
    assert "nginx/1.22" in html
    assert "Устаревшие компоненты" in html
    assert "openssl" in html
    assert "CVE-2023-0001" in html
    assert "Матрица рисков" in html
    assert "f-valhalla" in html
    assert "Критически важные уязвимости" in html
    assert "Fixture critical" in html
    assert "CVE-2024-FIXTURE" in html


def test_valhalla_json_and_payload_valhalla_report_key() -> None:
    data = ReportData(
        report_id="r-valhalla-json",
        target="https://json.fixture",
        summary=ReportSummary(
            critical=0,
            high=1,
            medium=0,
            low=0,
            info=0,
            technologies=[],
            sslIssues=0,
            headerIssues=0,
            leaksFound=False,
        ),
        findings=[
            Finding(severity="high", title="H", description="D", cwe="CWE-79", cvss=7.1),
        ],
        technologies=[],
        scan_id="s-json",
        tenant_id="t-json",
    )
    jctx = {
        "tier": "valhalla",
        "target": data.target,
        "scan_id": data.scan_id,
        "tenant_id": data.tenant_id,
        "valhalla_context": ValhallaReportContext().model_dump(mode="json"),
        "recon_summary": {"summary_counts": {"high": 1, "critical": 0}},
        "owasp_compliance_rows": [],
        "findings": [
            {
                "severity": "high",
                "title": "H",
                "description": "D",
                "cwe": "CWE-79",
                "cvss": 7.1,
            }
        ],
        "exploitation": [],
        "scan_artifacts": {"status": "skipped", "phase_blocks": []},
        "ai_sections": {
            "exploit_chains": "x",
            "remediation_stages": "y",
            "zero_day_potential": "z",
            "prioritization_roadmap": "p",
            "hardening_recommendations": "h",
        },
    }
    parsed = json.loads(generate_json(data, jinja_context=jctx).decode("utf-8"))
    assert "valhalla_report" in parsed
    assert parsed["valhalla_report"]["title_meta"]["tier"] == "valhalla"

    direct = build_valhalla_report_payload(jctx, data)
    assert direct["exploit_chains_text"] == "x"
    assert parsed["valhalla_report"]["exploit_chains_text"] == direct["exploit_chains_text"]


def test_valhalla_sections_csv_non_empty_rows() -> None:
    data = ReportData(
        report_id="r-csv-valhalla",
        target="https://csv.fixture",
        summary=ReportSummary(
            critical=0,
            high=0,
            medium=0,
            low=0,
            info=0,
            technologies=[],
            sslIssues=0,
            headerIssues=0,
            leaksFound=False,
        ),
        findings=[],
        technologies=[],
    )
    jctx = {
        "tier": "valhalla",
        "valhalla_context": ValhallaReportContext(
            robots_txt_analysis=RobotsTxtAnalysisModel(found=True),
        ).model_dump(mode="json"),
        "ai_sections": {},
        "recon_summary": {},
    }
    raw = generate_valhalla_sections_csv(data, jinja_context=jctx).decode("utf-8")
    reader = csv.reader(io.StringIO(raw))
    rows = list(reader)
    assert rows[0] == ["section", "content_markdown_or_json"]
    assert len(rows) == 1 + len(_VALHALLA_REPORT_SECTION_ORDER)
    section_keys = [r[0] for r in rows[1:]]
    assert section_keys == list(_VALHALLA_REPORT_SECTION_ORDER)
    assert all(len(r) >= 2 for r in rows[1:])
    # At least one non-empty payload cell (JSON blocks are never empty strings; text slots may be "").
    assert sum(1 for r in rows[1:] if (r[1] or "").strip()) >= 8


def test_valhalla_ai_payload_ssl_headers_or_fallback_messages_ru() -> None:
    """VDF-010: compact ssl/headers in AI payload when mock VC is filled, else RU fallbacks."""
    data = _scan_valhalla_with_sample_vc()
    p = ReportGenerator.build_ai_input_payload(data, tier="valhalla")
    fb = p.get("valhalla_fallback_messages_ru") or {}
    ssl_a = p.get("ssl_tls_analysis") or {}
    hdr_a = p.get("security_headers_analysis") or {}
    assert isinstance(fb, dict)
    assert "ssl_tls" in fb and "security_headers" in fb
    has_ssl = bool(ssl_a.get("protocols") or ssl_a.get("issuer"))
    has_hdr = bool(hdr_a.get("summary") or hdr_a.get("rows_sample"))
    assert has_ssl or bool((fb.get("ssl_tls") or "").strip())
    assert has_hdr or bool((fb.get("security_headers") or "").strip())
