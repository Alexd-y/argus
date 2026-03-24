"""RPT-009 — PDF from HTML (WeasyPrint), JSON field order; integration tests may be skipped."""

import json
import sys
from unittest.mock import MagicMock, patch

import pytest
from src.api.schemas import Finding, ReportSummary
from src.reports.generators import ReportData, generate_csv, generate_json, generate_pdf

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
