"""WEB-009: Integration tests — active web scan pipeline, XSS detection on alf.nu.

Tests cover:
- URL parameter extraction
- Intel finding normalization (CVSS, CWE, PoC)
- CVSS post-processing
- Full run_vuln_analysis bridge with mocked active scan
- Dalfox adapter normalization
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

ALF_NU_TARGET = "https://alf.nu/alert1?world=alert&level=alert0"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


# ---------------------------------------------------------------------------
# 1. Static URL parameter extraction (no network)
# ---------------------------------------------------------------------------

def test_extract_url_query_params_alf_nu() -> None:
    from src.orchestration.handlers import _extract_url_query_params

    params = _extract_url_query_params(ALF_NU_TARGET)
    assert len(params) >= 2
    names = {p["param"] for p in params}
    assert "world" in names
    assert "level" in names
    for p in params:
        assert p["method"] == "GET"
        assert "alf.nu" in p["url"]


def test_extract_url_query_params_no_query() -> None:
    from src.orchestration.handlers import _extract_url_query_params

    params = _extract_url_query_params("https://example.com/page")
    assert params == []


# ---------------------------------------------------------------------------
# 2. HTML form parsing
# ---------------------------------------------------------------------------

def test_parse_forms_from_html_simple_form() -> None:
    from src.orchestration.handlers import _parse_forms_from_html

    html = """
    <html><body>
    <form method="POST" action="/login">
      <input name="username" type="text"/>
      <input name="password" type="password"/>
    </form>
    </body></html>
    """
    forms = _parse_forms_from_html(html, "https://example.com/")
    assert len(forms) == 2
    input_names = {f["input_name"] for f in forms}
    assert "username" in input_names
    assert "password" in input_names
    assert forms[0]["method"] == "POST"


def test_parse_forms_from_html_empty() -> None:
    from src.orchestration.handlers import _parse_forms_from_html

    forms = _parse_forms_from_html("<html></html>", "https://example.com/")
    assert forms == []


# ---------------------------------------------------------------------------
# 3. Async URL params + forms extraction (mocked HTTP)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_extract_url_params_and_forms_with_mock_http() -> None:
    from src.orchestration.handlers import _extract_url_params_and_forms

    mock_response = MagicMock()
    mock_response.headers = {"content-type": "text/html"}
    mock_response.text = '<form method="POST"><input name="q" type="text"/></form>'
    mock_response.url = ALF_NU_TARGET

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("src.orchestration.handlers.httpx.AsyncClient", return_value=mock_client):
        params, forms = await _extract_url_params_and_forms(ALF_NU_TARGET)

    assert len(params) >= 2
    assert any(p["param"] == "world" for p in params)
    assert any(p["param"] == "level" for p in params)
    assert len(forms) >= 1
    assert forms[0]["input_name"] == "q"


@pytest.mark.asyncio
async def test_extract_url_params_and_forms_http_timeout() -> None:
    """Timeout should not crash; returns static params only."""
    import httpx
    from src.orchestration.handlers import _extract_url_params_and_forms

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

    with patch("src.orchestration.handlers.httpx.AsyncClient", return_value=mock_client):
        params, forms = await _extract_url_params_and_forms(ALF_NU_TARGET)

    assert len(params) >= 2
    assert forms == []


# ---------------------------------------------------------------------------
# 4. Intel finding normalization
# ---------------------------------------------------------------------------

def test_normalize_intel_finding_xss_high_cvss() -> None:
    from src.orchestration.handlers import _normalize_intel_finding

    raw = {
        "type": "xss",
        "source": "dalfox",
        "data": {
            "type": "Reflected XSS",
            "name": "XSS in world parameter",
            "url": "https://alf.nu/alert1?world=<script>alert(1)</script>",
            "param": "world",
            "severity": "high",
            "cwe": "CWE-79",
            "cvss_score": 7.2,
            "poc": "https://alf.nu/alert1?world=<script>alert(1)</script>",
        },
    }
    result = _normalize_intel_finding(raw)
    assert result["cvss"] is not None
    assert result["cvss"] >= 7.0
    assert result["cwe"] == "CWE-79"
    assert "curl" in result["description"]
    assert result["source"] == "active_scan"


def test_normalize_intel_finding_xss_auto_cvss() -> None:
    """XSS finding without explicit CVSS should still get >= 7.0."""
    from src.orchestration.handlers import _normalize_intel_finding

    raw = {
        "type": "xss",
        "source": "dalfox",
        "data": {
            "type": "XSS",
            "name": "XSS found",
            "severity": "high",
        },
    }
    result = _normalize_intel_finding(raw)
    assert result["cvss"] is not None
    assert result["cvss"] >= 7.0
    assert result["cwe"] == "CWE-79"


def test_normalize_intel_finding_reflected_xss_label_floors_cvss() -> None:
    """OWASP-004: human-readable 'Reflected XSS' (alf.nu / dalfox) must floor CVSS at 7+."""
    from src.orchestration.handlers import _normalize_intel_finding

    raw = {
        "finding_type": "vulnerability",
        "data": {
            "type": "Reflected XSS",
            "name": "XSS",
            "url": "https://alf.nu/alert1",
            "severity": "medium",
        },
    }
    result = _normalize_intel_finding(raw)
    assert result["cvss"] is not None
    assert result["cvss"] >= 7.0
    assert result["cwe"] == "CWE-79"


def test_normalize_intel_finding_generic() -> None:
    from src.orchestration.handlers import _normalize_intel_finding

    raw = {
        "type": "info",
        "source": "nuclei",
        "data": {
            "type": "exposed_panel",
            "name": "Admin panel exposed",
            "severity": "medium",
        },
    }
    result = _normalize_intel_finding(raw)
    assert result["severity"] == "medium"
    assert result["source"] == "active_scan"


def test_normalize_intel_finding_cwe79_from_poc_xss_alert() -> None:
    """OWASP-007: CWE-79 when PoC encodes XSS + alert(1) even if type label is not XSS-specific."""
    from src.orchestration.handlers import _normalize_intel_finding

    raw = {
        "type": "xss",
        "source": "xsstrike",
        "data": {
            "type": "suspicious_reflection",
            "name": "Reflected input",
            "severity": "medium",
            "url": "https://example.test/search",
            "poc": "https://example.test/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        },
    }
    result = _normalize_intel_finding(raw)
    assert result["cwe"] == "CWE-79"
    assert result["cvss"] is not None
    assert result["cvss"] >= 7.0


# ---------------------------------------------------------------------------
# 5. PoC generation
# ---------------------------------------------------------------------------

def test_generate_poc_with_poc_url() -> None:
    from src.orchestration.handlers import _generate_poc

    data = {
        "poc": "https://alf.nu/alert1?world=<script>alert(1)</script>",
        "param": "world",
    }
    poc = _generate_poc(data)
    assert "curl" in poc
    assert "alf.nu" in poc
    assert "world" in poc


def test_generate_poc_with_url_only() -> None:
    from src.orchestration.handlers import _generate_poc

    data = {"url": "https://example.com/test?id=1"}
    poc = _generate_poc(data)
    assert "curl" in poc
    assert "example.com" in poc


def test_generate_poc_empty() -> None:
    from src.orchestration.handlers import _generate_poc

    assert _generate_poc({}) == ""


# ---------------------------------------------------------------------------
# 6. CVSS post-processing
# ---------------------------------------------------------------------------

def test_postprocess_findings_cvss_xss_floor() -> None:
    from src.orchestration.handlers import _postprocess_findings_cvss

    findings = [
        {"title": "Reflected XSS in world param", "severity": "high", "source": "active_scan", "cvss": None},
        {"title": "Info leak", "severity": "low", "source": "llm", "cvss": 3.1},
    ]
    result = _postprocess_findings_cvss(findings)
    xss = next(f for f in result if "XSS" in f["title"])
    assert xss["cvss"] is not None
    assert xss["cvss"] >= 7.0
    assert xss["cwe"] == "CWE-79"
    assert result[0]["cvss"] >= result[-1]["cvss"]


def test_postprocess_findings_cvss_sqli() -> None:
    from src.orchestration.handlers import _postprocess_findings_cvss

    findings = [{"title": "SQL Injection in id param", "severity": "critical", "source": "active_scan", "cvss": None}]
    result = _postprocess_findings_cvss(findings)
    assert result[0]["cvss"] is not None
    assert result[0]["cvss"] >= 8.0
    assert result[0]["cwe"] == "CWE-89"


def test_postprocess_findings_preserves_existing_cvss() -> None:
    from src.orchestration.handlers import _postprocess_findings_cvss

    findings = [{"title": "Some finding", "severity": "info", "cvss": 2.0}]
    result = _postprocess_findings_cvss(findings)
    assert result[0]["cvss"] == 2.0


# ---------------------------------------------------------------------------
# 7. Full run_vuln_analysis with mocked active scan pipeline
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_vuln_analysis_active_scan_bridge() -> None:
    """When sandbox is enabled, active scan produces XSS findings with CVSS >= 7.0."""
    from src.orchestration.handlers import run_vuln_analysis
    from src.orchestration.phases import VulnAnalysisOutput

    mock_bundle_result = MagicMock()
    mock_bundle_result.intel_findings = [
        {
            "type": "xss",
            "source": "dalfox",
            "data": {
                "type": "Reflected XSS",
                "name": "XSS in world parameter (dalfox)",
                "url": "https://alf.nu/alert1?world=%3Cscript%3Ealert(1)%3C/script%3E",
                "param": "world",
                "severity": "high",
                "cwe": "CWE-79",
                "cvss_score": 7.5,
                "poc": "https://alf.nu/alert1?world=%3Cscript%3Ealert(1)%3C/script%3E",
            },
        },
        {
            "type": "xss",
            "source": "xsstrike",
            "data": {
                "type": "Reflected XSS",
                "name": "XSS in level parameter (xsstrike)",
                "url": "https://alf.nu/alert1?level=%3Cscript%3Ealert(1)%3C/script%3E",
                "param": "level",
                "severity": "high",
                "cwe": "CWE-79",
                "cvss_score": 7.4,
                "poc": "https://alf.nu/alert1?level=%3Cscript%3Ealert(1)%3C/script%3E",
            },
        },
    ]

    with (
        patch("src.orchestration.handlers.settings") as mock_settings,
        patch("src.orchestration.handlers.run_va_active_scan_phase", new_callable=AsyncMock, return_value=mock_bundle_result),
        patch("src.orchestration.handlers.ai_vuln_analysis", new_callable=AsyncMock, return_value=VulnAnalysisOutput(findings=[])),
        patch("src.orchestration.handlers._extract_url_params_and_forms", new_callable=AsyncMock, return_value=([{"url": "https://alf.nu/alert1", "param": "world", "value": "alert", "method": "GET"}], [])),
        patch("src.orchestration.handlers.run_web_vuln_heuristics", new_callable=AsyncMock, return_value=[]),
        patch("src.orchestration.handlers.RawPhaseSink"),
    ):
        mock_settings.sandbox_enabled = True
        mock_settings.va_custom_xss_poc_enabled = False

        result = await run_vuln_analysis(
            threat_model={},
            assets=["alf.nu"],
            target=ALF_NU_TARGET,
            tenant_id="test-tenant",
            scan_id="test-scan-001",
        )

    assert isinstance(result, VulnAnalysisOutput)
    assert len(result.findings) >= 1
    xss_findings = [
        f for f in result.findings
        if "xss" in f.get("title", "").lower() or "XSS" in f.get("title", "")
    ]
    assert len(xss_findings) >= 1
    assert xss_findings[0]["cvss"] >= 7.0
    assert xss_findings[0]["source"] == "active_scan"
    assert xss_findings[0].get("cwe") == "CWE-79"
    assert any("alert(1)" in (f.get("description") or "").lower() for f in xss_findings)


@pytest.mark.asyncio
async def test_run_vuln_analysis_minio_sink_uploads_active_scan_intel() -> None:
    """OWASP-007: RawPhaseSink (MinIO) stores normalized intel when VA phase returns dalfox/xsstrike rows."""
    from src.orchestration.handlers import run_vuln_analysis
    from src.orchestration.phases import VulnAnalysisOutput

    mock_sink = MagicMock()
    mock_sink_class = MagicMock(return_value=mock_sink)

    mock_bundle_result = MagicMock()
    mock_bundle_result.intel_findings = [
        {
            "type": "xss",
            "source": "dalfox",
            "data": {
                "type": "Reflected XSS",
                "name": "XSS (dalfox)",
                "url": "https://alf.nu/alert1?world=test",
                "param": "world",
                "severity": "high",
                "cwe": "CWE-79",
                "cvss_score": 7.3,
                "poc": "https://alf.nu/alert1?world=%3Cscript%3Ealert(1)%3C/script%3E",
            },
        },
        {
            "type": "xss",
            "source": "xsstrike",
            "data": {
                "type": "Reflected XSS",
                "name": "XSS (xsstrike)",
                "url": "https://alf.nu/alert1?level=x",
                "param": "level",
                "severity": "high",
                "cwe": "CWE-79",
                "cvss_score": 7.6,
                "poc": "https://alf.nu/alert1?level=%3Cscript%3Ealert(1)%3C/script%3E",
            },
        },
    ]

    with (
        patch("src.orchestration.handlers.settings") as mock_settings,
        patch(
            "src.orchestration.handlers.run_va_active_scan_phase",
            new_callable=AsyncMock,
            return_value=mock_bundle_result,
        ),
        patch(
            "src.orchestration.handlers.ai_vuln_analysis",
            new_callable=AsyncMock,
            return_value=VulnAnalysisOutput(findings=[]),
        ),
        patch(
            "src.orchestration.handlers._extract_url_params_and_forms",
            new_callable=AsyncMock,
            return_value=([], []),
        ),
        patch("src.orchestration.handlers.run_web_vuln_heuristics", new_callable=AsyncMock, return_value=[]),
        patch("src.orchestration.handlers.RawPhaseSink", mock_sink_class),
    ):
        mock_settings.sandbox_enabled = True
        mock_settings.va_custom_xss_poc_enabled = False

        await run_vuln_analysis(
            threat_model={},
            assets=["alf.nu"],
            target=ALF_NU_TARGET,
            tenant_id="tenant-owasp-007",
            scan_id="scan-owasp-007",
        )

    mock_sink_class.assert_called_once_with("tenant-owasp-007", "scan-owasp-007", "vuln_analysis")
    mock_sink.upload_json.assert_called_once()
    args, _kwargs = mock_sink.upload_json.call_args
    assert args[0] == "active_scan_findings"
    payload = args[1]
    assert payload["count"] == 2
    assert len(payload["findings"]) == 2
    for f in payload["findings"]:
        assert f.get("cwe") == "CWE-79"
        assert (f.get("cvss") or 0) >= 7.0
        blob = f"{f.get('title', '')} {f.get('description', '')}".lower()
        assert "alert(1)" in blob
    assert any("dalfox" in (x.get("title") or "").lower() for x in payload["findings"])
    assert any("xsstrike" in (x.get("title") or "").lower() for x in payload["findings"])


@pytest.mark.asyncio
async def test_run_vuln_analysis_sandbox_disabled_fallback() -> None:
    """When sandbox is disabled, only LLM findings returned."""
    from src.orchestration.handlers import run_vuln_analysis
    from src.orchestration.phases import VulnAnalysisOutput

    llm_findings = [{"title": "Generic finding", "severity": "info", "cvss": 2.0}]

    with (
        patch("src.orchestration.handlers.settings") as mock_settings,
        patch("src.orchestration.handlers.ai_vuln_analysis", new_callable=AsyncMock, return_value=VulnAnalysisOutput(findings=llm_findings)),
        patch("src.orchestration.handlers.run_web_vuln_heuristics", new_callable=AsyncMock, return_value=[]),
    ):
        mock_settings.sandbox_enabled = False

        result = await run_vuln_analysis(
            threat_model={}, assets=[], target=ALF_NU_TARGET,
        )

    assert len(result.findings) >= 1
    assert result.findings[0]["title"] == "Generic finding"


# ---------------------------------------------------------------------------
# 8. Dalfox adapter CVSS normalization
# ---------------------------------------------------------------------------

def test_dalfox_normalize_findings_cvss_floor() -> None:
    from src.recon.vulnerability_analysis.active_scan.dalfox_adapter import (
        normalize_dalfox_findings,
    )

    raw_entries = [
        {
            "type": "Reflected XSS",
            "url": "https://alf.nu/alert1?world=%3Cscript%3Ealert(1)%3C/script%3E",
            "payload": "<script>alert(1)</script>",
            "param": "world",
        }
    ]
    findings = normalize_dalfox_findings(raw_entries)
    assert len(findings) >= 1
    data = findings[0].get("data", {})
    assert data.get("cvss_score", 0) >= 7.0
    assert data.get("cwe") == "CWE-79"


def test_dalfox_fixture_alf_nu_alert1() -> None:
    """Parse the real dalfox fixture file for alf.nu alert1."""
    import json
    from src.recon.vulnerability_analysis.active_scan.dalfox_adapter import (
        normalize_dalfox_findings,
        parse_dalfox_stdout,
    )

    fixture = FIXTURES / "dalfox_alf_nu_alert1_xss.jsonl"
    if not fixture.exists():
        pytest.skip("dalfox fixture not found")

    raw = fixture.read_text(encoding="utf-8")
    parsed = parse_dalfox_stdout(raw)
    assert len(parsed) >= 1

    findings = normalize_dalfox_findings(parsed)
    assert len(findings) >= 1
    for f in findings:
        data = f.get("data", {})
        assert data.get("cvss_score", 0) >= 7.0


# ---------------------------------------------------------------------------
# 9. Build active scan context
# ---------------------------------------------------------------------------

def test_build_active_scan_context_non_empty() -> None:
    from src.orchestration.handlers import _build_active_scan_context

    findings = [
        {"title": "XSS in world", "severity": "high", "cwe": "CWE-79", "cvss": 7.2, "description": "Reflected XSS"},
    ]
    ctx = _build_active_scan_context(findings)
    assert "XSS" in ctx
    assert "7.2" in ctx
    assert "CWE-79" in ctx


def test_build_active_scan_context_empty() -> None:
    from src.orchestration.handlers import _build_active_scan_context

    assert _build_active_scan_context([]) == ""
