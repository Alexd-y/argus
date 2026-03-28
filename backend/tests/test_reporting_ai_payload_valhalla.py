"""VHQ-007 — Valhalla AI payload: findings enrichment + compact valhalla_context block."""

from __future__ import annotations

from src.reports.data_collector import FindingRow, ReportRowSlice, ScanReportData, ScanRowData
from src.reports.valhalla_report_context import (
    CriticalVulnRefModel,
    RiskMatrixCellModel,
    RiskMatrixModel,
    ValhallaReportContext,
)
from src.services.reporting import ReportGenerator


def test_build_ai_payload_valhalla_includes_risk_matrix_and_critical_vulns_compact() -> None:
    vc = ValhallaReportContext(
        risk_matrix=RiskMatrixModel(
            variant="matrix",
            cells=[
                RiskMatrixCellModel(
                    impact="high",
                    likelihood="high",
                    finding_ids=["a", "b", "c"],
                    count=3,
                ),
            ],
            distribution=[],
        ),
        critical_vulns=[
            CriticalVulnRefModel(
                vuln_id="fid-1",
                title="Critical issue",
                description="Short",
                cvss=9.0,
                exploit_available=True,
                severity="critical",
            ),
        ],
    )
    data = ScanReportData(
        scan_id="s-vhq",
        tenant_id="t-vhq",
        scan=ScanRowData(
            id="s-vhq",
            tenant_id="t-vhq",
            target_id=None,
            target_url="https://vhq.example",
            status="done",
            progress=100,
            phase="reporting",
            options=None,
        ),
        report=ReportRowSlice(
            id="r-vhq",
            tenant_id="t-vhq",
            target="https://vhq.example",
            scan_id="s-vhq",
            tier="valhalla",
            generation_status="pending",
            summary={"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
            technologies=[],
        ),
        findings=[
            FindingRow(
                id="fid-1",
                tenant_id="t-vhq",
                scan_id="s-vhq",
                report_id="r-vhq",
                severity="critical",
                title="SQLi",
                description="D" * 500,
                cwe="CWE-89",
                cvss=9.0,
            ),
        ],
        valhalla_context=vc,
    )
    p = ReportGenerator.build_ai_input_payload(data, tier="valhalla")
    for k in (
        "tech_stack_structured",
        "ssl_tls_analysis",
        "security_headers_analysis",
        "outdated_components_table",
        "robots_sitemap_analysis",
        "valhalla_fallback_messages_ru",
    ):
        assert k in p
    vctx = p["valhalla_context"]
    assert "risk_matrix" in vctx
    assert vctx["risk_matrix"]["cells"][0]["impact"] == "high"
    assert vctx["risk_matrix"]["cells"][0]["count"] == 3
    assert len(vctx["risk_matrix"]["cells"][0]["finding_ids"]) == 3

    assert "critical_vulns" in vctx
    assert vctx["critical_vulns"][0]["vuln_id"] == "fid-1"
    assert vctx["critical_vulns"][0]["exploit_available"] is True

    f0 = p["findings"][0]
    assert f0["finding_id"] == "fid-1"
    assert len(f0["description"]) <= 400
    assert f0["exploit_available"] is False
    assert f0["cve_ids"] == []


def test_compact_risk_matrix_finding_ids_capped_at_24() -> None:
    ids = [f"id-{i}" for i in range(30)]
    vc = ValhallaReportContext(
        risk_matrix=RiskMatrixModel(
            variant="matrix",
            cells=[
                RiskMatrixCellModel(
                    impact="medium",
                    likelihood="medium",
                    finding_ids=ids,
                    count=30,
                ),
            ],
            distribution=[],
        ),
    )
    data = ScanReportData(
        scan_id="s-cap",
        tenant_id="t-cap",
        valhalla_context=vc,
    )
    p = ReportGenerator.build_ai_input_payload(data, tier="valhalla")
    cell0 = p["valhalla_context"]["risk_matrix"]["cells"][0]
    assert cell0["count"] == 30
    assert len(cell0["finding_ids"]) == 24
    assert cell0["finding_ids"][0] == "id-0"
    assert cell0["finding_ids"][-1] == "id-23"
