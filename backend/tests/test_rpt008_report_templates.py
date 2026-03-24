"""RPT-008 — Jinja2 tier templates smoke + autoescape."""

from __future__ import annotations

import pytest
from src.reports.data_collector import (
    FindingRow,
    PhaseOutputRow,
    ReportRowSlice,
    ScanReportData,
    ScanRowData,
)
from src.reports.template_env import get_report_jinja_environment, render_tier_report_html
from src.services.reporting import ReportGenerator


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


def test_rpt008_jinja_environment_uses_templates_dir() -> None:
    env = get_report_jinja_environment()
    assert env.autoescape is True
    assert env.get_template("midgard.html.j2")


@pytest.mark.parametrize("tier", ["midgard", "asgard", "valhalla"])
def test_rpt008_render_tier_smoke(tier: str) -> None:
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
    assert "<!DOCTYPE html>" in html
    assert "ARGUS Security Report" in html
    assert "Recon summary" in html
    assert "Findings" in html
    assert "AI Conclusions" in html
    if tier == "valhalla":
        assert "Exploitation" in html
        assert "exploitation" in html.lower()
    else:
        assert "id=\"exploitation\"" not in html


def test_rpt008_autoescape_finding_title() -> None:
    gen = ReportGenerator()
    data = _minimal_scan_report_data()
    data.findings[0].title = "<script>alert(1)</script>"
    ctx = gen.prepare_template_context("midgard", data, {"executive_summary": "ok"})
    html = render_tier_report_html("midgard", ctx)
    assert "<script>" not in html
    assert "&lt;script&gt;" in html
