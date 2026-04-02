"""T1 — severity histogram vs executive totals; same ``data.findings`` as report / AI / Jinja.

``severity_counts`` in the AI payload is a raw histogram (keys lowercased; empty → ``unknown``).
``executive_severity_totals`` and template ``severity_counts`` / ``recon_summary.summary_counts``
use the top-5 buckets (``informational`` → ``info``).
"""

from __future__ import annotations

from src.api.schemas import Finding, ReportSummary
from src.reports.data_collector import (
    FindingRow,
    ReportRowSlice,
    ScanReportData,
    ScanRowData,
    executive_severity_totals_from_finding_rows,
    severity_histogram_from_finding_rows,
)
from src.reports.generators import ReportData
from src.reports.jinja_minimal_context import minimal_jinja_context_from_report_data
from src.services.reporting import ReportGenerator, recon_summary_for_jinja


def _row(
    fid: str,
    severity: str,
    *,
    tenant_id: str = "t",
    scan_id: str = "s",
) -> FindingRow:
    return FindingRow(
        id=fid,
        tenant_id=tenant_id,
        scan_id=scan_id,
        report_id=None,
        severity=severity,
        title="T",
        description="",
        cwe=None,
        cvss=None,
    )


def test_executive_severity_totals_empty_findings() -> None:
    assert executive_severity_totals_from_finding_rows([]) == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    assert severity_histogram_from_finding_rows([]) == {}


def test_informational_maps_to_info_executive_histogram_keeps_label() -> None:
    rows = [_row("a", "informational"), _row("b", "Informational")]
    ex = executive_severity_totals_from_finding_rows(rows)
    assert ex["info"] == 2
    assert ex["critical"] == ex["high"] == ex["medium"] == ex["low"] == 0
    hist = severity_histogram_from_finding_rows(rows)
    assert hist.get("informational") == 2


def test_executive_skips_empty_and_unknown_severity_histogram_counts_unknown() -> None:
    rows = [_row("a", ""), _row("b", "   "), _row("c", "not_a_bucket")]
    ex = executive_severity_totals_from_finding_rows(rows)
    assert sum(ex.values()) == 0
    hist = severity_histogram_from_finding_rows(rows)
    assert hist.get("unknown") == 2
    assert hist.get("not_a_bucket") == 1


def test_build_ai_input_payload_severity_fields_from_same_findings_list() -> None:
    rows = [_row("1", "critical"), _row("2", "informational"), _row("3", "")]
    data = ScanReportData(scan_id="s", tenant_id="t", findings=rows)
    p = ReportGenerator.build_ai_input_payload(data, tier="midgard")
    assert p["finding_count"] == 3
    assert p["severity_counts"] == severity_histogram_from_finding_rows(data.findings)
    assert p["executive_severity_totals"] == executive_severity_totals_from_finding_rows(data.findings)
    assert p["executive_severity_totals"]["critical"] == 1
    assert p["executive_severity_totals"]["info"] == 1


def test_prepare_template_context_severity_counts_equals_executive_totals() -> None:
    rows = [_row("1", "high"), _row("2", "low")]
    data = ScanReportData(
        scan_id="s",
        tenant_id="t",
        scan=ScanRowData(
            id="s",
            tenant_id="t",
            target_id=None,
            target_url="https://example.com",
            status="done",
            progress=100,
            phase="reporting",
            options=None,
        ),
        findings=rows,
    )
    gen = ReportGenerator()
    ctx = gen.prepare_template_context(
        "midgard",
        data,
        {},
        extra={"scan_artifacts": {"status": "skipped", "phase_blocks": []}},
    )
    want = executive_severity_totals_from_finding_rows(data.findings)
    assert ctx["severity_counts"] == want
    assert ctx["severity_counts"]["high"] == 1
    assert ctx["severity_counts"]["low"] == 1
    assert ctx["findings_count"] == 2


def test_recon_summary_summary_counts_aligns_with_findings_not_stale_report_summary() -> None:
    data = ScanReportData(
        scan_id="s",
        tenant_id="t",
        report=ReportRowSlice(
            id="r",
            tenant_id="t",
            target="https://x",
            scan_id="s",
            tier="midgard",
            generation_status="ready",
            summary={"critical": 99, "high": 99, "medium": 0, "low": 0, "info": 0},
            technologies=[],
        ),
        findings=[_row("f", "medium")],
    )
    rec = recon_summary_for_jinja(data)
    assert rec["summary_counts"]["critical"] == 0
    assert rec["summary_counts"]["high"] == 0
    assert rec["summary_counts"]["medium"] == 1
    assert rec["summary_counts"]["low"] == 0
    assert rec["summary_counts"]["info"] == 0


def test_recon_summary_empty_findings_zeros_all_buckets() -> None:
    data = ScanReportData(
        scan_id="s",
        tenant_id="t",
        report=ReportRowSlice(
            id="r",
            tenant_id="t",
            target="https://x",
            scan_id="s",
            tier="midgard",
            generation_status="ready",
            summary={"critical": 5, "high": 1},
            technologies=[],
        ),
        findings=[],
    )
    rec = recon_summary_for_jinja(data)
    for k in ("critical", "high", "medium", "low", "info"):
        assert rec["summary_counts"][k] == 0


def test_minimal_jinja_recon_summary_and_severity_match_findings() -> None:
    rd = ReportData(
        report_id="r",
        target="https://z",
        summary=ReportSummary(critical=10, high=10, medium=0, low=0, info=0),
        findings=[
            Finding(severity="low", title="a", description=""),
            Finding(severity="informational", title="b", description=""),
        ],
        technologies=[],
    )
    ctx = minimal_jinja_context_from_report_data(rd, "midgard")
    want = {"critical": 0, "high": 0, "medium": 0, "low": 1, "info": 1}
    assert ctx["severity_counts"] == want
    assert ctx["recon_summary"]["summary_counts"] == want
