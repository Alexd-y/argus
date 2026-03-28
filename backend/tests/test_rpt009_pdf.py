"""RPT-009 — PDF from HTML (WeasyPrint), JSON field order; integration tests may be skipped."""

import json
import sys
from unittest.mock import MagicMock, patch

import pytest
from src.api.schemas import Finding, ReportSummary
from src.reports.generators import (
    ReportData,
    build_valhalla_report_payload,
    generate_csv,
    generate_json,
    generate_pdf,
    generate_valhalla_sections_csv,
)

from tests.weasyprint_skips import WSP_REASON, WSP_SKIP


def test_generate_pdf_weasyprint_mocked() -> None:
    """PDF path renders HTML then calls WeasyPrint; no native libs required when mocked."""
    sample = ReportData(
        report_id="r-mock",
        target="https://example.com",
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
            Finding(
                severity="low",
                title="T",
                description="D",
                cwe="CWE-200",
                cvss=1.0,
            )
        ],
        technologies=[],
        created_at="2026-03-20T00:00:00Z",
        scan_id="s-mock",
        ai_insights=[],
    )
    fake_pdf = b"%PDF-1.4 mocked pdf bytes"
    mock_html_cls = MagicMock()
    doc = MagicMock()
    doc.write_pdf.return_value = fake_pdf
    mock_html_cls.return_value = doc

    fake_weasy = MagicMock()
    fake_weasy.HTML = mock_html_cls

    with patch.dict(sys.modules, {"weasyprint": fake_weasy}):
        out = generate_pdf(sample)

    assert out == fake_pdf
    mock_html_cls.assert_called_once()
    call_kw = mock_html_cls.call_args[1]
    assert "string" in call_kw
    assert "ARGUS Security Report" in call_kw["string"]
    assert "base_url" in call_kw
    doc.write_pdf.assert_called_once_with()


def test_generate_json_top_level_key_order() -> None:
    """Export JSON uses a stable top-level and summary key order (RPT-009)."""
    data = ReportData(
        report_id="r-order",
        target="https://order.example",
        summary=ReportSummary(
            critical=1,
            high=2,
            medium=3,
            low=4,
            info=5,
            technologies=["a", "b"],
            sslIssues=1,
            headerIssues=2,
            leaksFound=True,
        ),
        findings=[
            Finding(severity="high", title="X", description="Y", cwe="CWE-79", cvss=7.0),
        ],
        technologies=["a", "b"],
        created_at="2026-03-20T12:00:00Z",
        scan_id="s-order",
        ai_insights=["note"],
        timeline=[],
        phase_outputs=[],
        evidence=[],
        screenshots=[],
        executive_summary="exec",
        remediation=["fix"],
    )
    content = generate_json(data)
    parsed = json.loads(content.decode("utf-8"))
    assert list(parsed.keys()) == [
        "report_id",
        "target",
        "scan_id",
        "created_at",
        "metadata",
        "executive_summary",
        "summary",
        "findings",
        "technologies",
        "timeline",
        "phase_outputs",
        "evidence",
        "screenshots",
        "ai_conclusions",
        "remediation",
        "ai_sections",
        "scan_artifacts",
        "active_web_scan",
        "raw_artifacts",
    ]
    assert list(parsed["summary"].keys()) == [
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "technologies",
        "sslIssues",
        "headerIssues",
        "leaksFound",
    ]
    assert list(parsed["findings"][0].keys()) == [
        "severity",
        "title",
        "description",
        "cwe",
        "cvss",
    ]
    assert list(parsed["metadata"].keys()) == [
        "report_id",
        "target",
        "scan_id",
        "created_at",
        "technologies",
    ]


def test_generate_json_csv_findings_sorted_by_severity() -> None:
    """Same findings in different input order → JSON and CSV both emit critical before low (RPT-009)."""
    data = ReportData(
        report_id="r-sort",
        target="https://sort.example",
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
            Finding(severity="low", title="L", description="", cwe=None, cvss=1.0),
            Finding(severity="critical", title="C", description="", cwe=None, cvss=9.0),
        ],
        technologies=[],
    )
    j = json.loads(generate_json(data).decode("utf-8"))
    assert [f["severity"] for f in j["findings"]] == ["critical", "low"]
    csv_text = generate_csv(data).decode("utf-8")
    lines = csv_text.strip().split("\n")
    assert lines[1].startswith("critical,")
    assert lines[2].startswith("low,")


def test_generate_json_nested_dict_key_sorting() -> None:
    """Timeline entry dicts get sorted keys for deterministic JSON."""
    from src.reports.generators import PhaseOutputEntry, TimelineEntry

    data = ReportData(
        report_id="r-nest",
        target="https://nest.example",
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
        timeline=[
            TimelineEntry(
                phase="p1",
                order_index=0,
                entry={"zebra": 1, "alpha": 2},
                created_at="2026-03-20T00:00:00Z",
            )
        ],
        phase_outputs=[
            PhaseOutputEntry(phase="p1", output_data={"b": 1, "a": 2}),
        ],
    )
    content = generate_json(data)
    raw = content.decode("utf-8")
    assert raw.index('"alpha"') < raw.index('"zebra"')
    assert raw.index('"a"') < raw.index('"b"')


def test_vhl005_valhalla_json_includes_valhalla_report() -> None:
    data = ReportData(
        report_id="r-vhl",
        target="https://vhl.example",
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
            Finding(severity="high", title="H", description="D", cwe="CWE-89", cvss=8.0),
        ],
        technologies=[],
        scan_id="s-vhl",
        tenant_id="t-vhl",
    )
    jctx = {
        "tier": "valhalla",
        "target": data.target,
        "scan_id": data.scan_id,
        "tenant_id": data.tenant_id,
        "valhalla_context": {
            "robots_txt_analysis": {"found": False},
            "sitemap_analysis": {"found": False, "url_count": 0, "sample_urls": []},
            "tech_stack_table": [],
            "outdated_components": [],
            "leaked_emails": [],
            "ssl_tls_analysis": {},
            "security_headers_analysis": {"rows": []},
            "dependency_analysis": [],
            "threat_model": {},
            "threat_model_excerpt": "",
            "threat_model_phase_link": "",
            "exploitation_post_excerpt": "",
            "risk_matrix": {"variant": "matrix", "cells": [], "distribution": []},
            "critical_vulns": [],
        },
        "recon_summary": {"summary_counts": {"high": 1}},
        "owasp_compliance_rows": [],
        "findings": [
            {
                "severity": "high",
                "title": "H",
                "description": "D",
                "cwe": "CWE-89",
                "cvss": 8.0,
            }
        ],
        "exploitation": [],
        "scan_artifacts": {"status": "skipped", "phase_blocks": []},
        "ai_sections": {
            "exploit_chains": "chain text",
            "remediation_stages": "stage text",
            "zero_day_potential": "zero text",
            "prioritization_roadmap": "road",
            "hardening_recommendations": "hard",
        },
    }
    parsed = json.loads(generate_json(data, jinja_context=jctx).decode("utf-8"))
    assert "valhalla_report" in parsed
    vr = parsed["valhalla_report"]
    assert vr["exploit_chains_text"] == "chain text"
    assert vr["remediation_stages_text"] == "stage text"
    assert vr["zero_day_text"] == "zero text"
    assert "road" in vr["conclusion_text"] and "hard" in vr["conclusion_text"]
    assert vr["title_meta"]["tier"] == "valhalla"
    assert len(vr["findings"]) == 1


def test_vhl005_valhalla_sections_csv_roundtrip() -> None:
    data = ReportData(
        report_id="r-csv",
        target="https://csv.example",
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
    jctx = {"tier": "valhalla", "valhalla_context": {}, "ai_sections": {}, "recon_summary": {}}
    raw = generate_valhalla_sections_csv(data, jinja_context=jctx).decode("utf-8")
    lines = [ln for ln in raw.strip().split("\n") if ln]
    assert lines[0].startswith("section,")
    assert "title_meta" in raw
    payload = build_valhalla_report_payload(jctx, data)
    assert set(payload.keys()) == set(
        [
            "title_meta",
            "executive_summary_counts",
            "owasp_compliance",
            "robots_sitemap",
            "tech_stack",
            "outdated_components",
            "emails",
            "ssl_tls",
            "headers",
            "dependencies",
            "risk_matrix",
            "critical_vulns",
            "threat_modeling_ref",
            "findings",
            "exploit_chains_text",
            "remediation_stages_text",
            "zero_day_text",
            "conclusion_text",
            "appendices",
        ]
    )


@pytest.mark.weasyprint_pdf
@pytest.mark.skipif(WSP_SKIP, reason=WSP_REASON)
def test_generate_pdf_integration_smoke() -> None:
    """End-to-end PDF bytes when WeasyPrint and OS libs are available."""
    data = ReportData(
        report_id="r-int",
        target="https://integration.example",
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
        created_at="2026-03-20T00:00:00Z",
        scan_id="s-int",
        ai_insights=[],
    )
    out = generate_pdf(data)
    assert isinstance(out, bytes)
    assert out[:4] == b"%PDF"
    assert len(out) > 100
