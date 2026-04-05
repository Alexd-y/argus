"""Test report data completeness — no section should be no_data when artifacts exist."""

from src.reports.finding_metadata import CvssVector, estimate_cvss_vector
from src.reports.valhalla_report_context import (
    _parse_harvester_emails,
    _parse_testssl_text_output,
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


def test_cvss_context_authenticated() -> None:
    cv = estimate_cvss_vector("CWE-79", context={"authenticated": True})
    assert cv is not None
    assert "/PR:L/" in cv.vector_string
