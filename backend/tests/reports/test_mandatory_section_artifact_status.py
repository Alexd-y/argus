"""Coverage for mandatory section status: artifact_missing_body vs parser_error paths."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from src.reports.valhalla_report_context import (
    PortExposureSummaryModel,
    RobotsSitemapMergedSummaryModel,
    RobotsTxtAnalysisModel,
    SecurityHeadersAnalysisModel,
    SitemapAnalysisModel,
    SslTlsAnalysisModel,
    TechStackStructuredModel,
    _compute_mandatory_sections_and_coverage,
)


def test_artifact_missing_body_when_whatweb_meta_but_no_fetch() -> None:
    raw_keys = [("scan_123_tool_whatweb_stdout.txt", "recon")]
    raw_hints = {
        "has_whatweb": True,
        "has_robots": False,
        "has_sitemap": False,
        "has_tls": False,
        "has_harvester": False,
        "has_headers": False,
        "has_dependency": False,
        "has_email_fallback": False,
        "has_ports": False,
    }
    mand, _cov = _compute_mandatory_sections_and_coverage(
        structured=TechStackStructuredModel(),
        tech_table=[],
        outdated=[],
        ssl_out=SslTlsAnalysisModel(),
        sec_hdr=SecurityHeadersAnalysisModel(),
        security_headers_from_findings=False,
        robots=RobotsTxtAnalysisModel(),
        sitemap=SitemapAnalysisModel(),
        robots_sitemap_merged=RobotsSitemapMergedSummaryModel(),
        final_emails=[],
        merged_http_headers={},
        deps=[],
        fetch_raw_bodies=False,
        harvester_enabled=False,
        trivy_enabled=False,
        phase_outputs=[],
        raw_artifact_keys=raw_keys,
        raw_hints=raw_hints,
        tool_run_summaries=[("whatweb", "success")],
        feature_flags={},
        fallback_messages={k: None for k in ("tech_stack", "outdated", "ssl_tls", "security_headers", "robots_sitemap", "leaked_emails")},
        port_data=PortExposureSummaryModel(),
    )
    assert mand.tech_stack_structured.status == "artifact_missing_body"


def test_artifact_missing_body_tls_when_meta_only_no_body() -> None:
    raw_keys = [("scan_123_tool_testssl_scan_job_meta.txt", "recon")]
    raw_hints = {
        "has_whatweb": False,
        "has_robots": False,
        "has_sitemap": False,
        "has_tls": True,
        "has_harvester": False,
        "has_headers": False,
        "has_dependency": False,
        "has_email_fallback": False,
        "has_ports": False,
    }
    kwargs = dict(
        structured=TechStackStructuredModel(),
        tech_table=[],
        outdated=[],
        ssl_out=SslTlsAnalysisModel(),
        sec_hdr=SecurityHeadersAnalysisModel(),
        security_headers_from_findings=False,
        robots=RobotsTxtAnalysisModel(),
        sitemap=SitemapAnalysisModel(),
        robots_sitemap_merged=RobotsSitemapMergedSummaryModel(),
        final_emails=[],
        merged_http_headers={},
        deps=[],
        fetch_raw_bodies=True,
        harvester_enabled=False,
        trivy_enabled=False,
        phase_outputs=[],
        raw_artifact_keys=raw_keys,
        raw_hints=raw_hints,
        tool_run_summaries=[("testssl", "success")],
        feature_flags={},
        fallback_messages={k: None for k in ("tech_stack", "outdated", "ssl_tls", "security_headers", "robots_sitemap", "leaked_emails")},
        port_data=PortExposureSummaryModel(),
    )
    with patch("src.reports.valhalla_report_context._safe_download_raw", return_value=None):
        mand, _ = _compute_mandatory_sections_and_coverage(**kwargs)
    assert mand.ssl_tls_analysis.status == "artifact_missing_body"


def test_raw_artifact_has_non_empty_body_for_needles() -> None:
    from src.reports.valhalla_report_context import raw_artifact_has_non_empty_body_for_needles

    keys = [("20260101_tool_nikto_scan_abc_stdout.txt", "vuln_analysis")]
    with patch("src.reports.valhalla_report_context._safe_download_raw", return_value=b"Server: nginx"):
        assert raw_artifact_has_non_empty_body_for_needles(keys, True, ("nikto",))
    with patch("src.reports.valhalla_report_context._safe_download_raw", return_value=b""):
        assert not raw_artifact_has_non_empty_body_for_needles(keys, True, ("nikto",))


def test_apply_security_header_table_gap_to_findings() -> None:
    from src.reports.report_quality_gate import apply_security_header_table_gap_to_findings

    vc = SimpleNamespace(
        security_headers_analysis=SimpleNamespace(rows=[]),
        security_headers_table_rows=[],
    )
    finding = {
        "title": "Missing Content-Security-Policy",
        "description": "HTTP response lacks CSP header",
        "severity": "high",
        "cvss": 7.0,
        "confidence": "likely",
        "proof_of_concept": {},
    }
    [out] = apply_security_header_table_gap_to_findings([finding], vc)
    assert out["confidence"] == "advisory"
    assert "Insufficient raw HTTP" in str(out.get("applicability_notes", ""))
    assert out["severity"] == "low"
    assert out.get("cvss") == 3.7


def test_threat_model_inference_dropped_by_normalize() -> None:
    from src.reports.report_quality_gate import normalize_findings_for_report

    out = normalize_findings_for_report(
        [
            {
                "title": "TM hypothesis",
                "description": "x",
                "severity": "low",
                "cwe": "CWE-200",
                "evidence_type": "threat_model_inference",
                "proof_of_concept": {"request_url": "https://a/"},
            }
        ]
    )
    assert out == []


def test_xss_dedup_merges_same_url_cwe() -> None:
    from src.reports.report_quality_gate import normalize_findings_for_report

    f1 = {
        "title": "Reflected XSS",
        "description": "a",
        "cwe": "CWE-79",
        "severity": "high",
        "affected_url": "https://ex.test/page",
        "proof_of_concept": {"request_url": "https://ex.test/page?p=1", "payload": "alert(1)"},
    }
    f2 = {
        "title": "XSS in page",
        "description": "b",
        "cwe": "CWE-79",
        "severity": "high",
        "affected_url": "https://ex.test/page",
        "proof_of_concept": {"request_url": "https://ex.test/page?p=1", "payload": "alert(1)"},
    }
    out = normalize_findings_for_report([f1, f2])
    assert len([x for x in out if "xss" in str(x.get("title", "")).lower() or "cwe-79" in str(x.get("cwe", "")).lower()]) == 1
