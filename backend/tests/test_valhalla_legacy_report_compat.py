"""T10 — старые отчёты / findings без новых XSS-полей: контекст Valhalla и HTML без ошибок."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from src.reports.data_collector import FindingRow, ScanReportData
from src.reports.template_env import get_report_jinja_environment
from src.reports.valhalla_report_context import (
    build_valhalla_report_context,
    serialize_xss_structured_for_ai,
)
from src.services.reporting import ReportGenerator, findings_rows_for_jinja


def _legacy_xss_finding_dict() -> dict:
    """Только parameter + payload (как в старых экспортах), без reflection_context / verification_method."""
    return {
        "id": "legacy-xss-1",
        "severity": "high",
        "title": "Reflected XSS",
        "cwe": "CWE-79",
        "description": "Parameter reflects input.",
        "proof_of_concept": {
            "parameter": "search",
            "payload": "<script>alert(document.domain)</script>",
            "curl_command": "curl -sS 'https://example.com/?search=test'",
        },
    }


def test_legacy_finding_builds_valhalla_context_and_ai_serialization() -> None:
    f = _legacy_xss_finding_dict()
    ctx = build_valhalla_report_context(
        tenant_id="t-legacy",
        scan_id="s-legacy",
        recon_results=None,
        tech_profile=None,
        anomalies_structured=None,
        raw_artifact_keys=[],
        phase_outputs=[],
        phase_inputs=[],
        findings=[f],
        report_technologies=None,
        fetch_raw_bodies=False,
    )
    assert len(ctx.xss_structured) >= 1
    dumped = serialize_xss_structured_for_ai(ctx.xss_structured)
    assert "search" in dumped
    assert "<script>" in dumped or "script" in dumped

    data = ScanReportData(
        scan_id="s-legacy",
        tenant_id="t-legacy",
        valhalla_context=ctx,
    )
    payload = ReportGenerator.build_ai_input_payload(data, tier="valhalla")
    xs = payload["valhalla_context"]["xss_structured"]
    assert isinstance(xs, list)
    assert len(xs) >= 1


@patch(
    "src.services.reporting.get_finding_poc_screenshot_presigned_url",
    return_value=None,
)
def test_legacy_finding_jinja_findings_table_renders_without_error(_mock_presign: object) -> None:
    f = _legacy_xss_finding_dict()
    row = FindingRow(
        id=f["id"],
        tenant_id="t-legacy",
        scan_id="s-legacy",
        report_id="r-legacy",
        severity=f["severity"],
        title=f["title"],
        description=f.get("description"),
        cwe=f.get("cwe"),
        proof_of_concept=f["proof_of_concept"],
    )
    data = ScanReportData(scan_id="s-legacy", tenant_id="t-legacy", findings=[row])
    rows = findings_rows_for_jinja(data)
    env = get_report_jinja_environment()
    html = env.get_template("partials/valhalla/findings_table.html.j2").render(
        findings=rows,
        embed_poc_screenshot_inline=False,
        owasp_top10_labels={},
    )
    assert "Reflected XSS" in html
    assert "<script>alert(document.domain)</script>" not in html
    assert "script" in html.lower()


def test_json_roundtrip_legacy_finding_still_parses() -> None:
    raw = json.dumps(_legacy_xss_finding_dict(), ensure_ascii=False)
    f = json.loads(raw)
    ctx = build_valhalla_report_context(
        tenant_id="t1",
        scan_id="s1",
        recon_results=None,
        tech_profile=None,
        anomalies_structured=None,
        raw_artifact_keys=[],
        phase_outputs=[],
        phase_inputs=[],
        findings=[f],
        report_technologies=None,
        fetch_raw_bodies=False,
    )
    assert ctx.xss_structured


@pytest.mark.parametrize(
    "minimal_poc",
    [
        {},
        {"parameter": "x"},
    ],
)
def test_cwe79_minimal_poc_valhalla_no_crash(minimal_poc: dict) -> None:
    """CWE-79 + пустой/минимальный PoC — квалификация XSS без новых полей не падает."""
    f: dict = {
        "id": "cwe79-min",
        "title": "Cross-site scripting",
        "cwe": "CWE-79",
        "proof_of_concept": minimal_poc,
    }
    ctx = build_valhalla_report_context(
        tenant_id="t1",
        scan_id="s1",
        recon_results=None,
        tech_profile=None,
        anomalies_structured=None,
        raw_artifact_keys=[],
        phase_outputs=[],
        phase_inputs=[],
        findings=[f],
        report_technologies=None,
        fetch_raw_bodies=False,
    )
    serialize_xss_structured_for_ai(ctx.xss_structured)
