"""RPT: PoC block in HTML findings table + JSON finding dict (tier gating)."""

from __future__ import annotations

import json
from unittest.mock import patch

from src.api.schemas import Finding
from src.reports.data_collector import FindingRow, ScanReportData
from src.reports.generators import ReportData, ReportSummary, generate_json
from src.reports.jinja_minimal_context import minimal_jinja_context_from_report_data
from src.services.reporting import findings_rows_for_jinja, render_findings_table_html


def test_findings_table_owasp_column_and_compliance_asgard() -> None:
    data = ScanReportData(
        scan_id="s1",
        tenant_id="t1",
        findings=[
            FindingRow(
                id="f1",
                tenant_id="t1",
                scan_id="s1",
                severity="high",
                title="XSS",
                description="Reflected",
                cwe="CWE-79",
                cvss=7.2,
                owasp_category="A05",
            ),
            FindingRow(
                id="f2",
                tenant_id="t1",
                scan_id="s1",
                severity="medium",
                title="BAC",
                description="d",
                cwe="CWE-22",
                cvss=5.0,
                owasp_category="A01",
            ),
        ],
    )
    rows = findings_rows_for_jinja(data)
    html = render_findings_table_html("asgard", rows)
    assert "OWASP Top 10:2025 Compliance" in html
    assert "owasp-compliance-table" in html
    assert "Категория OWASP" in html
    assert ">A05<" in html or "A05" in html
    assert "Инъекции" in html
    assert "owasp-compliance-warn" in html
    assert "owasp-compliance-0" in html


def test_findings_table_owasp_hidden_midgard() -> None:
    data = ScanReportData(
        scan_id="s1",
        tenant_id="t1",
        findings=[
            FindingRow(
                id="f1",
                tenant_id="t1",
                scan_id="s1",
                severity="high",
                title="X",
                description="d",
                owasp_category="A05",
            )
        ],
    )
    rows = findings_rows_for_jinja(data)
    html = render_findings_table_html("midgard", rows)
    assert "OWASP Top 10:2025 Compliance" not in html
    assert "Категория OWASP" not in html


def test_findings_table_poc_valhalla_shows_curl_js_parameter_payload() -> None:
    data = ScanReportData(
        scan_id="s1",
        tenant_id="t1",
        findings=[
            FindingRow(
                id="f1",
                tenant_id="t1",
                scan_id="s1",
                severity="high",
                title="XSS",
                description="Reflected",
                cwe="CWE-79",
                cvss=7.2,
                proof_of_concept={
                    "tool": "xsstrike",
                    "parameter": "q",
                    "payload": '"><svg onload=alert(1)>',
                    "javascript_code": "<script>alert(1)</script>",
                    "curl_command": "curl -sS -G 'https://ex.test/x?q=1'",
                },
            )
        ],
    )
    rows = findings_rows_for_jinja(data)
    html = render_findings_table_html("valhalla", rows)
    assert 'class="finding-poc"' in html
    assert "<code>" in html
    assert "curl -sS -G" in html
    assert "alert(1)" in html
    assert "<code>q</code>" in html
    assert "svg onload=alert(1)" in html


def test_findings_table_poc_midgard_stub_only() -> None:
    data = ScanReportData(
        scan_id="s1",
        tenant_id="t1",
        findings=[
            FindingRow(
                id="f1",
                tenant_id="t1",
                scan_id="s1",
                severity="high",
                title="XSS",
                description="x",
                cwe="CWE-79",
                cvss=7.2,
                proof_of_concept={"tool": "t", "curl_command": "curl x"},
            )
        ],
    )
    rows = findings_rows_for_jinja(data)
    html = render_findings_table_html("midgard", rows)
    assert "Подробности PoC доступны" in html
    assert "curl x" not in html


def test_findings_table_poc_asgard_tool_only_shows_no_poc_message() -> None:
    data = ScanReportData(
        scan_id="s1",
        tenant_id="t1",
        findings=[
            FindingRow(
                id="f1",
                tenant_id="t1",
                scan_id="s1",
                severity="high",
                title="X",
                description="d",
                proof_of_concept={"tool": "dalfox"},
            )
        ],
    )
    rows = findings_rows_for_jinja(data)
    html = render_findings_table_html("asgard", rows)
    assert "No PoC available" in html


def test_generate_json_includes_proof_of_concept() -> None:
    f = Finding(
        severity="high",
        title="t",
        description="d",
        cwe="CWE-79",
        cvss=7.0,
        proof_of_concept={
            "tool": "test",
            "curl_command": "curl -v 'https://a.test/'",
            "javascript_code": "<script>alert(1)</script>",
        },
    )
    data = ReportData(
        report_id="r1",
        target="https://a.test",
        summary=ReportSummary(),
        findings=[f],
        technologies=[],
    )
    raw = generate_json(data).decode("utf-8")
    assert "alert(1)" in raw
    assert "curl -v" in raw
    parsed = json.loads(raw)
    assert parsed["findings"][0]["proof_of_concept"]["javascript_code"] == "<script>alert(1)</script>"


@patch("src.services.reporting.get_finding_poc_screenshot_presigned_url")
def test_findings_rows_jinja_sets_poc_screenshot_url(mock_presign) -> None:
    mock_presign.return_value = "https://presigned.example/obj"
    data = ScanReportData(
        scan_id="s1",
        tenant_id="t1",
        findings=[
            FindingRow(
                id="f1",
                tenant_id="t1",
                scan_id="s1",
                severity="high",
                title="X",
                description="d",
                proof_of_concept={
                    "tool": "t",
                    "screenshot_key": "t1/s1/poc/screenshots/f1.png",
                    "curl_command": "curl x",
                },
            )
        ],
    )
    rows = findings_rows_for_jinja(data)
    assert rows[0].get("poc_screenshot_url") == "https://presigned.example/obj"
    mock_presign.assert_called_once()
    html_asgard = render_findings_table_html("asgard", rows)
    assert 'href="https://presigned.example/obj"' in html_asgard
    assert 'rel="noopener noreferrer"' in html_asgard
    assert ">Screenshot</a>" in html_asgard
    assert "<img " not in html_asgard


@patch("src.services.reporting.get_finding_poc_screenshot_presigned_url")
def test_findings_table_poc_embeds_inline_screenshot_when_flag(mock_presign) -> None:
    mock_presign.return_value = "https://presigned.example/poc.png"
    data = ScanReportData(
        scan_id="s1",
        tenant_id="t1",
        findings=[
            FindingRow(
                id="f1",
                tenant_id="t1",
                scan_id="s1",
                severity="high",
                title="X",
                description="d",
                proof_of_concept={
                    "tool": "t",
                    "screenshot_key": "t1/s1/poc/screenshots/f1.png",
                },
            )
        ],
    )
    rows = findings_rows_for_jinja(data)
    html = render_findings_table_html("valhalla", rows, embed_poc_screenshot_inline=True)
    assert 'src="https://presigned.example/poc.png"' in html
    assert 'class="finding-poc-screenshot-thumb"' in html


def test_findings_table_poc_shows_response_snippet_asgard() -> None:
    data = ScanReportData(
        scan_id="s1",
        tenant_id="t1",
        findings=[
            FindingRow(
                id="f1",
                tenant_id="t1",
                scan_id="s1",
                severity="high",
                title="X",
                description="d",
                proof_of_concept={
                    "tool": "dalfox",
                    "response_snippet": "<div>PAYLOAD</div>",
                },
            )
        ],
    )
    rows = findings_rows_for_jinja(data)
    assert rows[0]["proof_of_concept"].get("response_snippet") == "<div>PAYLOAD</div>"
    html = render_findings_table_html("asgard", rows)
    assert "Response snippet" in html
    assert "&lt;div&gt;PAYLOAD&lt;/div&gt;" in html


def test_minimal_jinja_context_finding_dict_has_poc() -> None:
    f = Finding(
        severity="low",
        title="L",
        description="D",
        proof_of_concept={"curl_command": "curl x", "javascript_code": "alert(1)"},
    )
    data = ReportData(
        report_id="r2",
        target="t",
        summary=ReportSummary(),
        findings=[f],
        technologies=[],
    )
    ctx = minimal_jinja_context_from_report_data(data, tier="asgard")
    assert ctx["findings"][0].get("proof_of_concept", {}).get("curl_command") == "curl x"


def test_poc_schema_response_capped() -> None:
    from src.recon.vulnerability_analysis.active_scan.poc_schema import build_proof_of_concept

    long_r = "R" * 2000
    d = build_proof_of_concept("nuclei", response=long_r)
    assert len(d["response"]) == 1024


def test_extract_response_snippet_around_payload() -> None:
    from src.recon.vulnerability_analysis.active_scan.poc_schema import (
        build_poc_url_with_query_param,
        extract_response_snippet_around_payload,
    )

    body = "prefix " + "<x>" * 30 + "PAYLOAD" + "</x>" * 30 + " suffix"
    sn = extract_response_snippet_around_payload(body, "PAYLOAD")
    assert sn is not None
    assert "PAYLOAD" in sn
    assert len(sn) <= 500

    u = build_poc_url_with_query_param("https://ex.com/a?z=1", "q", "<s>")
    assert u is not None
    assert "q=%3Cs%3E" in u or "<s>" in u


def test_infer_javascript_code_from_payload_detects_alert() -> None:
    from src.recon.vulnerability_analysis.active_scan.poc_schema import infer_javascript_code_from_payload

    assert infer_javascript_code_from_payload("abcalert(1)") == "abcalert(1)"
    assert infer_javascript_code_from_payload("plain") is None
