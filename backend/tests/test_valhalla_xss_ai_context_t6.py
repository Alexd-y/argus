"""T6 — XSS PoC fields flow into Valhalla context and compact AI payload. T7 — Valhalla HTML XSS subsection."""

from __future__ import annotations

import json
from unittest.mock import patch

from src.reports.data_collector import FindingRow, ScanReportData
from src.reports.template_env import get_report_jinja_environment
from src.reports.valhalla_report_context import (
    build_valhalla_report_context,
    serialize_xss_structured_for_ai,
)
from src.services.reporting import ReportGenerator, findings_rows_for_jinja


def _synthetic_xss_finding() -> dict:
    return {
        "id": "xss-finding-1",
        "severity": "high",
        "title": "Reflected XSS in search",
        "cwe": "CWE-79",
        "description": "Reflected markup in search results.",
        "proof_of_concept": {
            "parameter": "q",
            "payload_entered": "<svg/onload=alert(1)>",
            "payload_reflected": True,
            "payload_used": "<svg/onload=alert(1)>",
            "reflection_context": "html_unquoted_attribute",
            "verification_method": "browser",
            "verified_via_browser": True,
            "browser_alert_text": "1",
            "poc_narrative": "Opened search page, submitted payload; alert fired with text 1.",
            "screenshot_key": "tenants/t1/scans/s1/xss_verify.png",
            "poc_screenshot_url": "https://minio.example/presign/xss-cap.png",
        },
    }


def test_xss_structured_serializes_expected_substrings() -> None:
    ctx = build_valhalla_report_context(
        tenant_id="t1",
        scan_id="s1",
        recon_results=None,
        tech_profile=None,
        anomalies_structured=None,
        raw_artifact_keys=[],
        phase_outputs=[],
        phase_inputs=[],
        findings=[_synthetic_xss_finding()],
        report_technologies=None,
        fetch_raw_bodies=False,
    )
    assert len(ctx.xss_structured) == 1
    row0 = ctx.xss_structured[0]
    assert row0.parameter == "q"
    assert row0.verified_via_browser is True
    assert row0.verification_method == "browser"
    assert row0.reflection_context == "html_unquoted_attribute"
    assert "xss_verify.png" in (row0.artifact_keys[0] if row0.artifact_keys else "")
    assert row0.artifact_urls and "minio.example" in row0.artifact_urls[0]

    block = serialize_xss_structured_for_ai(ctx.xss_structured)
    for needle in (
        '"parameter": "q"',
        "payload_entered",
        "payload_used",
        "payload_reflected",
        "reflection_context",
        "verification_method",
        "verified_via_browser",
        "browser_alert_text",
        "artifact_keys",
        "html_unquoted_attribute",
        "xss_verify.png",
        "artifact_urls",
        "minio.example",
    ):
        assert needle in block, f"missing substring: {needle}"


def test_compact_valhalla_ai_payload_includes_xss_structured() -> None:
    ctx = build_valhalla_report_context(
        tenant_id="t1",
        scan_id="s1",
        recon_results=None,
        tech_profile=None,
        anomalies_structured=None,
        raw_artifact_keys=[],
        phase_outputs=[],
        phase_inputs=[],
        findings=[_synthetic_xss_finding()],
        report_technologies=None,
        fetch_raw_bodies=False,
    )
    data = ScanReportData(scan_id="s1", tenant_id="t1", valhalla_context=ctx)
    payload = ReportGenerator.build_ai_input_payload(data, tier="valhalla")
    xs = payload["valhalla_context"]["xss_structured"]
    assert len(xs) == 1
    dumped = json.dumps(xs, ensure_ascii=False)
    assert "q" in dumped
    assert "html_unquoted_attribute" in dumped
    assert "browser" in dumped
    assert "xss_verify.png" in dumped
    assert "artifact_urls" in dumped
    assert "minio.example" in dumped


@patch(
    "src.services.reporting.get_finding_poc_screenshot_presigned_url",
    return_value="https://minio.example/presign/xss-cap.png",
)
def test_valhalla_findings_html_includes_xss_detail_labels(_mock_presign: object) -> None:
    fd = _synthetic_xss_finding()
    row = FindingRow(
        id=fd["id"],
        tenant_id="t1",
        scan_id="s1",
        report_id="r1",
        severity=fd["severity"],
        title=fd["title"],
        description=fd.get("description"),
        cwe=fd.get("cwe"),
        proof_of_concept=fd["proof_of_concept"],
    )
    data = ScanReportData(scan_id="s1", tenant_id="t1", findings=[row])
    rows = findings_rows_for_jinja(data)
    env = get_report_jinja_environment()
    html = env.get_template("partials/valhalla/findings_table.html.j2").render(
        findings=rows,
        embed_poc_screenshot_inline=False,
        owasp_top10_labels={},
    )
    assert "valhalla-xss-poc-detail" in html
    for label in (
        "Payload entered",
        "Payload reflected",
        "Reflection context",
        "Verification line",
        "PoC narrative",
        "PoC screenshot",
    ):
        assert label in html, f"missing label: {label}"
    assert 'class="finding-poc-xss-screenshot-link"' in html
    assert "minio.example/presign/xss-cap.png" in html
    assert "verification_method: browser" in html
    assert "verified_via_browser: yes" in html
    assert "poc_screenshot_url: present" in html
    assert "<svg/onload=alert(1)>" not in html
    assert "&lt;svg/onload=alert(1)&gt;" in html
    assert "html_unquoted_attribute" in html
    assert "Opened search page" in html
