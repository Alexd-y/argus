"""RPT-005 — ReportGenerator context, tier sections, generator delegation."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.reports.data_collector import (
    FindingRow,
    ReportRowSlice,
    ScanReportData,
    ScanRowData,
)
from src.services.reporting import (
    ReportGenerator,
    normalize_report_tier,
    report_tier_sections,
)


@pytest.fixture
def sample_scan_report_data() -> ScanReportData:
    return ScanReportData(
        scan_id="scan-1",
        tenant_id="tenant-1",
        scan=ScanRowData(
            id="scan-1",
            tenant_id="tenant-1",
            target_id=None,
            target_url="https://example.com",
            status="done",
            progress=100,
            phase="reporting",
            options=None,
        ),
        report=ReportRowSlice(
            id="rep-1",
            tenant_id="tenant-1",
            target="https://example.com",
            scan_id="scan-1",
            tier="asgard",
            generation_status="pending",
            summary={"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
            technologies=["nginx"],
        ),
        findings=[
            FindingRow(
                id="f1",
                tenant_id="tenant-1",
                scan_id="scan-1",
                report_id="rep-1",
                severity="critical",
                title="Test",
                description="Desc",
                cwe="79",
                cvss=7.5,
            )
        ],
    )


def test_report_tier_sections_counts() -> None:
    assert len(report_tier_sections("midgard")) == 2
    assert len(report_tier_sections("asgard")) == 5
    assert len(report_tier_sections("valhalla")) == 11
    assert "executive_summary" not in report_tier_sections("valhalla")
    assert "executive_summary_valhalla" in report_tier_sections("valhalla")
    assert "attack_scenarios" in report_tier_sections("valhalla")
    assert "remediation_stages" in report_tier_sections("valhalla")


def test_normalize_report_tier() -> None:
    assert normalize_report_tier("ASGARD") == "asgard"
    assert normalize_report_tier("unknown") == "midgard"


def test_build_ai_input_payload(sample_scan_report_data: ScanReportData) -> None:
    gen = ReportGenerator()
    p = gen.build_ai_input_payload(sample_scan_report_data)
    assert p["scan_id"] == "scan-1"
    assert p["finding_count"] == 1
    assert p["severity_counts"]["critical"] == 1
    assert p["findings"][0]["title"] == "Test"
    assert "owasp_category" not in p["findings"][0]
    assert "owasp_summary" not in p
    assert "owasp_category_reference_ru" not in p
    assert "owasp_compliance_table" in p
    assert len(p["owasp_compliance_table"]) == 10
    assert "valhalla_context" not in p


def test_build_ai_input_payload_valhalla_tier_adds_valhalla_context() -> None:
    gen = ReportGenerator()
    data = ScanReportData(scan_id="s1", tenant_id="t1", report=None)
    p = gen.build_ai_input_payload(data, tier="valhalla")
    assert "valhalla_context" in p
    assert "summary" in p["valhalla_context"]
    assert "appendix_tools" in p["valhalla_context"]
    assert p["valhalla_context"]["appendix_tools"] == []
    assert "tech_stack_structured" in p["valhalla_context"]
    ts = p["valhalla_context"]["tech_stack_structured"]
    assert "web_server" in ts and "frameworks" in ts
    assert "risk_matrix" in p["valhalla_context"]
    assert p["valhalla_context"]["risk_matrix"]["cells"] == []
    assert "critical_vulns" in p["valhalla_context"]
    assert p["valhalla_context"]["critical_vulns"] == []
    assert "owasp_compliance_table" in p


def test_build_ai_input_payload_valhalla_enriches_findings() -> None:
    gen = ReportGenerator()
    long_curl = "curl " + "x" * 800
    data = ScanReportData(
        scan_id="s1",
        tenant_id="t1",
        scan=ScanRowData(
            id="s1",
            tenant_id="t1",
            target_id=None,
            target_url="https://app.example.com/path",
            status="done",
            progress=100,
            phase="done",
            options=None,
        ),
        findings=[
            FindingRow(
                id="f1",
                tenant_id="t1",
                scan_id="s1",
                report_id="r1",
                severity="high",
                title="XSS CVE-2024-1000",
                description="d",
                cwe="CWE-79",
                cvss=8.2,
                owasp_category="A05",
                proof_of_concept={
                    "curl_command": long_curl,
                    "payload": "<script>alert(1)</script>",
                    "javascript_code": "alert(1)",
                    "parameter": "q",
                    "screenshot_key": "t1/s1/poc/screenshots/f1.png",
                    "target_url": "https://other.example/hit",
                    "cve_id": "CVE-2024-2000",
                },
            ),
        ],
    )
    p = gen.build_ai_input_payload(data, tier="valhalla")
    f0 = p["findings"][0]
    assert f0["finding_id"] == "f1"
    assert f0["exploit_available"] is True
    assert "CVE-2024-1000" in f0["cve_ids"]
    assert "CVE-2024-2000" in f0["cve_ids"]
    assert f0["description"] == "d"
    assert f0["cvss"] == 8.2
    assert f0["cwe"] == "CWE-79"
    assert f0["owasp_category"] == "A05"
    assert f0["affected_url"] == "https://other.example/hit"
    assert f0["affected_asset"] == "other.example"
    assert f0["parameter"] == "q"
    assert f0["screenshot_present"] is True
    assert len(f0["poc_curl"]) <= 600
    assert "poc_payload" in f0 and "<script>" in f0["poc_payload"]
    assert f0.get("poc_javascript") == "alert(1)"


def test_build_ai_input_payload_owasp_summary_and_per_finding_category() -> None:
    gen = ReportGenerator()
    data = ScanReportData(
        scan_id="s1",
        tenant_id="t1",
        findings=[
            FindingRow(
                id="a",
                tenant_id="t1",
                scan_id="s1",
                report_id="r1",
                severity="high",
                title="XSS",
                description="",
                cwe="CWE-79",
                cvss=7.0,
                owasp_category="A05",
            ),
            FindingRow(
                id="b",
                tenant_id="t1",
                scan_id="s1",
                report_id="r1",
                severity="medium",
                title="No OWASP",
                description="",
                cwe=None,
                cvss=0.0,
            ),
        ],
    )
    p = gen.build_ai_input_payload(data)
    assert p["findings"][0]["owasp_category"] == "A05"
    assert "owasp_category" not in p["findings"][1]
    osum = p["owasp_summary"]
    assert osum["counts"]["A05"] == 1
    assert osum["counts"]["A01"] == 0
    assert "A01" in osum["gap_categories"]
    assert osum["classified_finding_count"] == 1
    assert osum["unclassified_finding_count"] == 1
    ref = p.get("owasp_category_reference_ru")
    assert isinstance(ref, dict)
    assert "A05" in ref
    a5 = ref["A05"]
    assert "title_ru" in a5
    assert "how_to_fix" in a5
    assert "how_to_find" in a5
    assert "example_attack" in a5
    assert len(a5["how_to_fix"]) <= 400
    assert "A01" in ref and ref["A01"]["title_ru"]


def test_prepare_template_context_valhalla_defaults_embed_poc_inline(
    sample_scan_report_data: ScanReportData,
) -> None:
    gen = ReportGenerator()
    sample_scan_report_data.report = ReportRowSlice(
        id="rep-1",
        tenant_id="tenant-1",
        target="https://example.com",
        scan_id="scan-1",
        tier="valhalla",
        generation_status="pending",
        summary={"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
        technologies=[],
    )
    texts = {k: "x" for k in report_tier_sections("valhalla")}
    with patch("src.services.reporting.settings") as m:
        m.report_poc_embed_screenshot_inline = False
        ctx = gen.prepare_template_context("valhalla", sample_scan_report_data, texts)
    assert ctx["embed_poc_screenshot_inline"] is True


def test_prepare_template_context_valhalla_extra_can_disable_embed_poc(
    sample_scan_report_data: ScanReportData,
) -> None:
    gen = ReportGenerator()
    sample_scan_report_data.report = ReportRowSlice(
        id="rep-1",
        tenant_id="tenant-1",
        target="https://example.com",
        scan_id="scan-1",
        tier="valhalla",
        generation_status="pending",
        summary={"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
        technologies=[],
    )
    texts = {k: "x" for k in report_tier_sections("valhalla")}
    with patch("src.services.reporting.settings") as m:
        m.report_poc_embed_screenshot_inline = True
        ctx = gen.prepare_template_context(
            "valhalla",
            sample_scan_report_data,
            texts,
            extra={"embed_poc_screenshot_inline": False, "scan_artifacts": {"status": "skipped"}},
        )
    assert ctx["embed_poc_screenshot_inline"] is False
    assert ctx["scan_artifacts"]["status"] == "skipped"


def test_prepare_template_context_jinja_slots(sample_scan_report_data: ScanReportData) -> None:
    gen = ReportGenerator()
    texts = {"executive_summary": "ES", "vulnerability_description": "VD"}
    ctx = gen.prepare_template_context("midgard", sample_scan_report_data, texts)
    assert ctx["tier"] == "midgard"
    assert ctx["jinja"]["midgard"]["active"] is True
    assert ctx["jinja"]["asgard"]["active"] is False
    assert ctx["jinja"]["midgard"]["slots"]["executive_summary"] == "ES"
    assert "tier_stubs" in ctx


def test_ai_results_to_text_map() -> None:
    gen = ReportGenerator()
    m = gen.ai_results_to_text_map(
        {
            "executive_summary": {"status": "ok", "text": "A"},
            "remediation_step": {"status": "failed", "error": "x"},
        }
    )
    assert m == {"executive_summary": "A"}


def test_to_generator_report_data(sample_scan_report_data: ScanReportData) -> None:
    gen = ReportGenerator()
    rd = gen.to_generator_report_data(
        sample_scan_report_data,
        {"executive_summary": "Exec", "remediation_step": "Fix it", "vulnerability_description": "Vuln"},
    )
    assert rd.target == "https://example.com"
    assert rd.executive_summary == "Exec"
    assert rd.remediation == ["Fix it"]
    assert len(rd.ai_insights) >= 2


@pytest.mark.asyncio
async def test_build_context_sync_ai_mocked(sample_scan_report_data: ScanReportData) -> None:
    gen = ReportGenerator()
    mock_session = MagicMock()
    with patch.object(
        gen,
        "collect_scan_report_data",
        new_callable=AsyncMock,
        return_value=sample_scan_report_data,
    ):
        with patch.object(
            gen,
            "run_ai_sections_sync",
            return_value={
                "executive_summary": {"status": "ok", "text": "ok"},
                "vulnerability_description": {"status": "ok", "text": "vd"},
            },
        ):
            result = await gen.build_context(
                mock_session,
                "tenant-1",
                "scan-1",
                "midgard",
                sync_ai=True,
            )
    assert result.scan_report_data.scan_id == "scan-1"
    assert result.template_context["ai_sections"]["executive_summary"] == "ok"
    assert result.celery_task_ids is None


@pytest.mark.asyncio
async def test_build_context_async_celery_scheduled(sample_scan_report_data: ScanReportData) -> None:
    gen = ReportGenerator()
    mock_session = MagicMock()
    mock_delay = MagicMock()
    mock_delay.return_value.id = "task-xyz"

    with patch.object(
        gen,
        "collect_scan_report_data",
        new_callable=AsyncMock,
        return_value=sample_scan_report_data,
    ):
        with patch("src.tasks.ai_text_generation_task") as mock_task:
            mock_task.delay = mock_delay
            result = await gen.build_context(
                mock_session,
                "tenant-1",
                "scan-1",
                "midgard",
                sync_ai=False,
            )
    assert result.ai_section_results == {}
    assert result.celery_task_ids is not None
    assert mock_delay.call_count == len(report_tier_sections("midgard"))


def test_run_ai_sections_sync_llm_callable(sample_scan_report_data: ScanReportData) -> None:
    gen = ReportGenerator()
    out = gen.run_ai_sections_sync(
        "tenant-1",
        "scan-1",
        "midgard",
        sample_scan_report_data,
        redis_client=None,
        llm_callable=lambda _prompt, _payload: "section-body",
    )
    assert len(out) == len(report_tier_sections("midgard"))
    assert out["executive_summary"]["status"] == "ok"
    assert out["executive_summary"]["text"] == "section-body"
