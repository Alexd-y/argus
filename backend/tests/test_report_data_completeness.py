"""Test report data completeness — no section should be no_data when artifacts exist."""

from src.reports.finding_metadata import CvssVector, estimate_cvss_vector
from src.reports.valhalla_report_context import (
    TechStackStructuredModel,
    _build_port_exposure_summary,
    _parse_harvester_emails,
    _parse_testssl_text_output,
    _security_headers_from_findings,
    _security_headers_from_host_map,
    _security_headers_from_raw_http_responses,
    build_port_exposure_table_rows,
)


def test_testssl_text_parser() -> None:
    stdout = (
        "TLS 1.2   offered (OK)\n"
        "TLS 1.3   offered (OK)\n"
        "SSLv3     not offered (OK)\n"
    )
    result = _parse_testssl_text_output(stdout)
    assert len(result.protocols) >= 2
    assert "TLS 1.2" in result.protocols
    assert "TLS 1.3" in result.protocols


def test_testssl_weak_protocol_detected() -> None:
    stdout = "SSLv3     offered\nTLS 1.0   offered\nTLS 1.2   offered (OK)\n"
    result = _parse_testssl_text_output(stdout)
    assert len(result.weak_protocols) >= 1


def test_testssl_empty_input() -> None:
    result = _parse_testssl_text_output("")
    assert result.protocols == []
    assert result.weak_ciphers == []


def test_harvester_email_parser() -> None:
    stdout = "john@example.com\nadmin@example.com\nnoreply@example.com\n"
    emails = _parse_harvester_emails(stdout)
    assert any("j" in e for e in emails)
    assert not any("noreply" in e for e in emails)


def test_harvester_email_admin_filtered() -> None:
    stdout = "admin@example.com\nwebmaster@example.com\n"
    emails = _parse_harvester_emails(stdout)
    assert len(emails) == 0


def test_harvester_real_email_kept() -> None:
    stdout = "realuser@company.org\nanotheruser@company.org\n"
    emails = _parse_harvester_emails(stdout)
    assert len(emails) == 2


def test_cvss_vector_estimation() -> None:
    cv = estimate_cvss_vector("CWE-79")
    assert cv is not None
    assert isinstance(cv, CvssVector)
    assert "CVSS:3.1" in cv.vector_string


def test_cvss_unknown_cwe() -> None:
    cv = estimate_cvss_vector("CWE-99999")
    assert cv is None


def test_cvss_sql_injection() -> None:
    cv = estimate_cvss_vector("CWE-89")
    assert cv is not None
    assert cv.base_score >= 9.0
    assert cv.severity == "critical"


def test_testssl_vulnerability_not_false_positive() -> None:
    stdout = "Heartbleed (CVE-2014-0160)   not vulnerable (OK)\n"
    result = _parse_testssl_text_output(stdout)
    weak = result.weak_ciphers
    assert not any("Heartbleed" in str(w) for w in weak)


def test_testssl_vulnerability_detected() -> None:
    stdout = "Heartbleed   VULNERABLE\n"
    result = _parse_testssl_text_output(stdout)
    assert any("Heartbleed" in str(w) for w in result.weak_ciphers)


def test_openssl_text_parser_extracts_certificate_metadata() -> None:
    stdout = (
        "subject=CN = glomsoposten.vercel.app\n"
        "issuer=C = US, O = Let's Encrypt, CN = E1\n"
        "notBefore=Apr 01 00:00:00 2026 GMT\n"
        "notAfter=Jun 30 23:59:59 2026 GMT\n"
        "TLSv1.3 accepted\n"
    )
    result = _parse_testssl_text_output(stdout)
    assert "Let's Encrypt" in (result.issuer or "")
    assert "Jun 30" in (result.validity or "")
    assert "TLS 1.3" in result.protocols


def test_sslscan_xml_text_parser_extracts_tls_values() -> None:
    stdout = """
    <document>
      <ssltest sslversion="TLSv1.2" />
      <ssltest sslversion="TLSv1.3" />
      <certificate>
        <issuer>Let's Encrypt E1</issuer>
        <not-valid-before>2026-04-01</not-valid-before>
        <not-valid-after>2026-06-30</not-valid-after>
      </certificate>
    </document>
    """
    result = _parse_testssl_text_output(stdout)
    assert "Let's Encrypt" in (result.issuer or "")
    assert "2026-06-30" in (result.validity or "")
    assert {"TLS 1.2", "TLS 1.3"}.issubset(set(result.protocols))


def test_generic_header_finding_populates_header_matrix() -> None:
    sec = _security_headers_from_findings(
        [
            {
                "title": "Missing or incomplete HTTP security response headers",
                "description": "Recommended browser security headers are missing or incomplete.",
                "affected_url": "https://app.example/",
            }
        ]
    )
    assert sec.rows
    assert any(r["header"] == "Content-Security-Policy" and r["present"] is False for r in sec.rows)


def test_raw_http_response_headers_populate_missing_header_matrix(monkeypatch) -> None:
    raw = (
        b"HTTP/2 200\r\n"
        b"server: Vercel\r\n"
        b"strict-transport-security: max-age=63072000\r\n"
        b"content-type: text/html\r\n\r\n"
        b"<html></html>"
    )
    monkeypatch.setattr(
        "src.reports.valhalla_report_context._safe_download_raw",
        lambda _key: raw,
    )
    header_map = _security_headers_from_raw_http_responses(
        [("tool_http_audit_response_stdout.txt", "vuln_analysis")],
        fetch_bodies=True,
    )
    sec = _security_headers_from_host_map(header_map)
    assert sec.rows
    csp = next(r for r in sec.rows if r["header"] == "Content-Security-Policy")
    assert csp["present"] is False
    hsts = next(r for r in sec.rows if r["header"] == "Strict-Transport-Security")
    assert hsts["present"] is True


def test_https_response_artifact_confirms_443_port_fallback() -> None:
    port_data = _build_port_exposure_summary(
        nmap_blob="",
        ports=None,
        structured=TechStackStructuredModel(),
        raw_artifact_keys=[],
        fetch_bodies=False,
        target_hint="https://glomsoposten.vercel.app/",
        tls_observed=False,
        http_observed=True,
    )
    rows = build_port_exposure_table_rows(
        port_data,
        target_hint="https://glomsoposten.vercel.app/",
    )
    assert any(r.port == "443" and r.service == "https" for r in rows)


def test_https_raw_artifact_key_confirms_443_port_fallback() -> None:
    port_data = _build_port_exposure_summary(
        nmap_blob="",
        ports=None,
        structured=TechStackStructuredModel(),
        raw_artifact_keys=[("recon/security_headers.json", "recon")],
        fetch_bodies=False,
        target_hint="https://glomsoposten.vercel.app/",
        tls_observed=False,
        http_observed=False,
    )
    rows = build_port_exposure_table_rows(
        port_data,
        target_hint="https://glomsoposten.vercel.app/",
    )
    assert any(r.port == "443" and r.service == "https" for r in rows)


def test_cvss_context_authenticated() -> None:
    cv = estimate_cvss_vector("CWE-79", context={"authenticated": True})
    assert cv is not None
    assert "/PR:L/" in cv.vector_string
