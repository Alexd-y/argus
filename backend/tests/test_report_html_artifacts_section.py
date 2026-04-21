"""RAW-005 — Artifacts section in tiered HTML report (presigned / API hint, escaped names)."""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

import pytest

from src.reports.data_collector import (
    FindingRow,
    PhaseOutputRow,
    ReportRowSlice,
    ScanReportData,
    ScanRowData,
)
from src.reports.template_env import render_tier_report_html
from src.services.reporting import (
    ReportGenerator,
    _artifact_display_file_name,
    _is_raw_tool_output_file_name,
    _phase_bucket_for_artifact_key,
    ACTIVE_WEB_SCAN_CURL_XSS_EXAMPLE,
    build_active_web_scan_section_context,
    build_scan_artifacts_section_context,
)


def test_phase_bucket_for_artifact_key_phase_raw() -> None:
    assert _phase_bucket_for_artifact_key("t1/s1/recon/raw/x.txt", "t1", "s1") == "recon"
    assert _phase_bucket_for_artifact_key("t1/s1/threat_modeling/raw/a.json", "t1", "s1") == "threat_modeling"


def test_phase_bucket_for_artifact_key_legacy_raw() -> None:
    assert _phase_bucket_for_artifact_key("t1/s1/raw/legacy.txt", "t1", "s1") == "legacy_raw"


def test_phase_bucket_for_artifact_key_wrong_tenant() -> None:
    assert _phase_bucket_for_artifact_key("t1/s1/recon/raw/x.txt", "other", "s1") == "other"


def test_is_raw_tool_output_file_name_matches_upload_pattern() -> None:
    assert _is_raw_tool_output_file_name("20250101T120000_a1b2c3d4e5f6_tool_stdout.txt")
    assert not _is_raw_tool_output_file_name("0_a.txt")
    assert not _is_raw_tool_output_file_name("legacy_dump.log")


def test_artifact_display_file_name_does_not_split_inside_script_tag() -> None:
    evil = '"><script>alert(1)</script>.log'
    key = f"t1/s1/recon/raw/{evil}"
    assert _artifact_display_file_name(key, "t1", "s1") == evil


@patch("src.services.reporting.get_presigned_url_by_key", return_value="https://example.com/presigned")
@patch("src.services.reporting.list_scan_artifacts")
def test_build_scan_artifacts_groups_ordered_phases(mock_list, _mock_presign) -> None:
    mock_list.return_value = [
        {
            "key": "t1/s1/vuln_analysis/raw/1_out.txt",
            "size": 10,
            "last_modified": datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC),
            "content_type": "text/plain",
        },
        {
            "key": "t1/s1/recon/raw/0_a.txt",
            "size": 5,
            "last_modified": datetime(2025, 1, 2, 12, 0, 0, tzinfo=UTC),
            "content_type": "text/plain",
        },
    ]
    ctx = build_scan_artifacts_section_context("t1", "s1", attempt_listing=True)
    assert ctx["status"] == "ok"
    assert [b["phase_key"] for b in ctx["phase_blocks"]] == ["recon", "vuln_analysis"]
    assert ctx["phase_blocks"][0]["rows"][0]["download_url"] == "https://example.com/presigned"


@patch("src.services.reporting.get_presigned_url_by_key", return_value="https://example.com/p")
@patch("src.services.reporting.list_scan_artifacts")
def test_build_scan_artifacts_splits_tool_outputs_when_keys_match(mock_list, _mock_presign) -> None:
    mock_list.return_value = [
        {
            "key": "t1/s1/recon/raw/20250102T120000_abcdef012345_tool_stdout.txt",
            "size": 3,
            "last_modified": datetime(2025, 1, 2, 12, 0, 0, tzinfo=UTC),
            "content_type": "text/plain",
        },
        {
            "key": "t1/s1/recon/raw/other_file.json",
            "size": 2,
            "last_modified": datetime(2025, 1, 3, 12, 0, 0, tzinfo=UTC),
            "content_type": "application/json",
        },
    ]
    ctx = build_scan_artifacts_section_context("t1", "s1", attempt_listing=True)
    assert ctx["status"] == "ok"
    block = ctx["phase_blocks"][0]
    assert len(block["tool_output_rows"]) == 1
    assert block["tool_output_rows"][0]["file_name"].endswith("tool_stdout.txt")
    assert len(block["other_rows"]) == 1
    assert block["other_rows"][0]["file_name"] == "other_file.json"
    assert len(block["rows"]) == 2


@patch("src.services.reporting.list_scan_artifacts", return_value=None)
def test_build_scan_artifacts_storage_unavailable(_mock_list) -> None:
    ctx = build_scan_artifacts_section_context("t1", "s1", attempt_listing=True)
    assert ctx["status"] == "unavailable"
    assert ctx["phase_blocks"] == []


def test_build_scan_artifacts_skipped_when_disabled() -> None:
    ctx = build_scan_artifacts_section_context("t1", "s1", attempt_listing=False)
    assert ctx["status"] == "skipped"


@patch("src.services.reporting.get_presigned_url_by_key", return_value=None)
@patch("src.services.reporting.list_scan_artifacts")
def test_rpt008_artifacts_section_escapes_malicious_file_name(mock_list, _mock_presign) -> None:
    evil_name = '"><script>alert(1)</script>.log'
    mock_list.return_value = [
        {
            "key": f"t1/s1/recon/raw/{evil_name}",
            "size": 1,
            "last_modified": datetime(2025, 1, 1, tzinfo=UTC),
            "content_type": "text/plain",
        },
    ]
    scan_artifacts = build_scan_artifacts_section_context("t1", "s1", attempt_listing=True)
    assert scan_artifacts["status"] == "ok"

    data = ScanReportData(
        scan_id="s1",
        tenant_id="t1",
        scan=ScanRowData(
            id="s1",
            tenant_id="t1",
            target_id=None,
            target_url="https://x.example",
            status="done",
            progress=100,
            phase="reporting",
            options=None,
        ),
        report=ReportRowSlice(
            id="r1",
            tenant_id="t1",
            target="https://x.example",
            scan_id="s1",
            tier="midgard",
            generation_status="ready",
            summary={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            technologies=[],
        ),
        findings=[
            FindingRow(
                id="f1",
                tenant_id="t1",
                scan_id="s1",
                report_id="r1",
                severity="low",
                title="t",
                description="d",
                cwe=None,
                cvss=None,
            )
        ],
        timeline=[],
        phase_outputs=[],
    )
    gen = ReportGenerator()
    ctx = gen.prepare_template_context(
        "midgard",
        data,
        {"executive_summary": "ok"},
        extra={"scan_artifacts": scan_artifacts},
    )
    html = render_tier_report_html("midgard", ctx)
    assert 'id="scan-artifacts"' in html
    assert "Phase Artifacts" in html
    assert "<script>" not in html
    assert "&lt;script&gt;" in html


def _minimal_scan_report_data(*, tier: str = "midgard") -> ScanReportData:
    return ScanReportData(
        scan_id="scan-smoke",
        tenant_id="tenant-smoke",
        scan=ScanRowData(
            id="scan-smoke",
            tenant_id="tenant-smoke",
            target_id=None,
            target_url="https://smoke.example",
            status="done",
            progress=100,
            phase="reporting",
            options=None,
        ),
        report=ReportRowSlice(
            id="rep-smoke",
            tenant_id="tenant-smoke",
            target="https://smoke.example",
            scan_id="scan-smoke",
            tier=tier,
            generation_status="pending",
            summary={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            technologies=["nginx"],
        ),
        findings=[
            FindingRow(
                id="f1",
                tenant_id="tenant-smoke",
                scan_id="scan-smoke",
                report_id="rep-smoke",
                severity="high",
                title="Sample",
                description="Desc",
                cwe="79",
                cvss=6.1,
            )
        ],
        timeline=[],
        phase_outputs=[
            PhaseOutputRow(
                phase="exploitation",
                output_data={"status": "simulated", "detail": "fixture"},
                created_at=None,
            )
        ],
    )


@pytest.mark.parametrize("tier", ["midgard", "asgard", "valhalla"])
def test_rpt008_templates_include_artifacts_heading(tier: str) -> None:
    gen = ReportGenerator()
    data = _minimal_scan_report_data(tier=tier)
    ai_texts = {
        "executive_summary": "Exec line",
        "vulnerability_description": "Vuln line",
        "remediation_step": "Fix line",
        "business_risk": "Risk line",
        "compliance_check": "Comp line",
        "prioritization_roadmap": "Roadmap line",
        "hardening_recommendations": "Harden line",
        "executive_summary_valhalla": "Valhalla exec line",
    }
    ctx = gen.prepare_template_context(tier, data, ai_texts)
    html = render_tier_report_html(tier, ctx)
    assert 'id="scan-artifacts"' in html
    assert "Phase Artifacts" in html
    assert "/api/v1/scans/" in html
    assert "#scan-artifacts" in html
    assert "REPLACE_WITH_SAFE_ENCODED_TEST_STRING" in html
    assert "<script>" not in html


def test_artifacts_partial_shows_tool_outputs_subsection() -> None:
    with (
        patch("src.services.reporting.get_presigned_url_by_key", return_value="https://p.example/x"),
        patch("src.services.reporting.list_scan_artifacts") as mock_list,
    ):
        mock_list.return_value = [
            {
                "key": "t1/s1/recon/raw/20250102T120000_abcdef012345_nmap_stdout.txt",
                "size": 1,
                "last_modified": datetime(2025, 1, 2, tzinfo=UTC),
                "content_type": "text/plain",
            },
            {
                "key": "t1/s1/recon/raw/notes.json",
                "size": 2,
                "last_modified": datetime(2025, 1, 3, tzinfo=UTC),
                "content_type": "application/json",
            },
        ]
        ctx = build_scan_artifacts_section_context("t1", "s1", attempt_listing=True)

    data = _minimal_scan_report_data()
    gen = ReportGenerator()
    html = render_tier_report_html(
        "midgard",
        gen.prepare_template_context("midgard", data, {"executive_summary": "x"}, extra={"scan_artifacts": ctx}),
    )
    assert "Raw Tool Outputs" in html
    assert "Other Artifacts" in html


def test_owasp008_json_export_merges_jinja_ai_and_scan_artifacts() -> None:
    import json

    from src.api.schemas import Finding, ReportSummary
    from src.reports.generators import ReportData, generate_json

    data = ReportData(
        report_id="r-owasp",
        target="https://owasp.example",
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
        findings=[
            Finding(severity="low", title="T", description="D", cwe=None, cvss=1.0),
        ],
        technologies=[],
        scan_id="s-owasp",
    )
    scan_artifacts = {
        "status": "ok",
        "phase_blocks": [
            {
                "phase_key": "recon",
                "phase_label": "Разведка",
                "phase_query": "recon",
                "rows": [{"file_name": "x.txt", "key": "k", "size": 1, "last_modified": "z", "download_url": None}],
                "tool_output_rows": [],
                "other_rows": [{"file_name": "x.txt", "key": "k", "size": 1, "last_modified": "z", "download_url": None}],
            }
        ],
    }
    jctx = {"ai_sections": {"executive_summary": "E"}, "scan_artifacts": scan_artifacts}
    jctx["active_web_scan"] = build_active_web_scan_section_context(
        "asgard", scan_artifacts, {"executive_summary": "E"}
    )
    parsed = json.loads(generate_json(data, jinja_context=jctx).decode("utf-8"))
    assert parsed["ai_sections"] == {"executive_summary": "E"}
    assert parsed["scan_artifacts"]["status"] == "ok"
    assert parsed["scan_artifacts"]["phase_blocks"][0]["phase_key"] == "recon"
    assert "active_web_scan" in parsed
    assert parsed["active_web_scan"].get("curl_xss_example") == ACTIVE_WEB_SCAN_CURL_XSS_EXAMPLE


def test_build_active_web_scan_extracts_tools_from_artifact_names() -> None:
    scan_artifacts = {
        "status": "ok",
        "phase_blocks": [
            {
                "phase_key": "vuln_analysis",
                "phase_label": "Анализ уязвимостей",
                "phase_query": "vuln_analysis",
                "rows": [
                    {
                        "file_name": "20250102T120000_abcdef012345_tool_dalfox_scan_j1_stdout.txt",
                        "key": "k1",
                        "size": 1,
                        "last_modified": "z",
                        "download_url": None,
                    },
                    {
                        "file_name": "20250102T120000_abcdef012345_tool_va_active_scan_plan.json",
                        "key": "k2",
                        "size": 2,
                        "last_modified": "z",
                        "download_url": None,
                    },
                ],
                "tool_output_rows": [],
                "other_rows": [],
            }
        ],
    }
    ctx = build_active_web_scan_section_context(
        "asgard",
        scan_artifacts,
        {"vulnerability_description": "XSS noted in dynamic tests."},
    )
    assert ctx["visible"] is True
    assert "dalfox" in ctx["tools_run"]
    assert "va_active_scan" in ctx["tools_run"]
    assert any(r["section_key"] == "vulnerability_description" for r in ctx["ai_summary_rows"])


def test_midgard_hides_active_web_scan_without_signals() -> None:
    data = _minimal_scan_report_data(tier="midgard")
    gen = ReportGenerator()
    ctx = gen.prepare_template_context(
        "midgard",
        data,
        {"executive_summary": "only exec"},
        extra={"scan_artifacts": {"status": "skipped", "phase_blocks": []}},
    )
    assert ctx["active_web_scan"]["visible"] is False
    html = render_tier_report_html("midgard", ctx)
    assert "Active Web Scan" not in html.lower() or "active_web_scan" not in html


def test_active_web_scan_section_escapes_ai_xss_payload() -> None:
    data = _minimal_scan_report_data(tier="valhalla")
    gen = ReportGenerator()
    ctx = gen.prepare_template_context(
        "valhalla",
        data,
        {
            "executive_summary_valhalla": "e",
            "vulnerability_description": '<script>alert(1)</script>',
            "remediation_step": "r",
            "business_risk": "b",
            "compliance_check": "c",
            "prioritization_roadmap": "p",
            "hardening_recommendations": "h",
        },
    )
    html = render_tier_report_html("valhalla", ctx)
    assert "<script>" not in html
