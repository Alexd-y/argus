"""Unit tests for the passive HTTP audit analyzer (WB-P5a)."""

from __future__ import annotations

from src.pipeline.contracts.finding_dto import ConfidenceLevel, FindingCategory
from src.web_workbench.passive.analyzer import (
    PassiveSeverity,
    analyze,
    check_cookies,
    check_cors,
    check_info_disclosure,
    check_reflected_input,
    check_security_headers,
)
from src.web_workbench.proxy.transport import NormalizedRequest, NormalizedResponse


def _request(raw: bytes) -> NormalizedRequest:
    return NormalizedRequest.parse(raw)


def _response(raw: bytes) -> NormalizedResponse:
    return NormalizedResponse.parse(raw)


_GET = _request(b"GET /page?q=hello HTTP/1.1\r\nHost: app.example.com\r\n\r\n")


def _codes(findings) -> set[str]:
    return {f.code for f in findings}


def test_security_headers_all_missing_on_https() -> None:
    resp = _response(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
    codes = _codes(check_security_headers(_GET, resp, secure=True))
    assert {"missing-hsts", "missing-nosniff", "missing-csp", "clickjacking"} <= codes


def test_hsts_not_flagged_on_plain_http() -> None:
    resp = _response(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n")
    codes = _codes(check_security_headers(_GET, resp, secure=False))
    assert "missing-hsts" not in codes


def test_security_headers_present_are_not_flagged() -> None:
    resp = _response(
        b"HTTP/1.1 200 OK\r\n"
        b"Strict-Transport-Security: max-age=63072000\r\n"
        b"X-Content-Type-Options: nosniff\r\n"
        b"Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\n"
        b"\r\n"
    )
    findings = check_security_headers(_GET, resp, secure=True)
    assert findings == []


def test_csp_frame_ancestors_suppresses_clickjacking() -> None:
    resp = _response(
        b"HTTP/1.1 200 OK\r\n"
        b"X-Content-Type-Options: nosniff\r\n"
        b"Content-Security-Policy: frame-ancestors 'none'\r\n"
        b"\r\n"
    )
    codes = _codes(check_security_headers(_GET, resp, secure=True))
    assert "clickjacking" not in codes


def test_cookie_flags_flagged_on_https() -> None:
    resp = _response(b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc123\r\n\r\n")
    findings = check_cookies(_GET, resp, secure=True)
    codes = _codes(findings)
    assert codes == {
        "cookie-missing-secure",
        "cookie-missing-httponly",
        "cookie-missing-samesite",
    }
    # Evidence carries the cookie NAME, never its value.
    assert all(f.evidence == "sid" for f in findings)


def test_secure_cookie_not_flagged_for_secure() -> None:
    resp = _response(
        b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=abc; Secure; HttpOnly; SameSite=Strict\r\n\r\n"
    )
    assert check_cookies(_GET, resp, secure=True) == []


def test_info_disclosure_requires_version_digit() -> None:
    with_version = _response(b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n")
    assert _codes(check_info_disclosure(_GET, with_version)) == {"version-disclosure"}
    no_version = _response(b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")
    assert check_info_disclosure(_GET, no_version) == []


def test_cors_wildcard_with_credentials() -> None:
    resp = _response(
        b"HTTP/1.1 200 OK\r\n"
        b"Access-Control-Allow-Origin: *\r\n"
        b"Access-Control-Allow-Credentials: true\r\n"
        b"\r\n"
    )
    findings = check_cors(_GET, resp)
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.CORS
    assert findings[0].severity is PassiveSeverity.MEDIUM


def test_cors_wildcard_without_credentials_not_flagged() -> None:
    resp = _response(b"HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\n\r\n")
    assert check_cors(_GET, resp) == []


def test_reflected_query_param() -> None:
    req = _request(b"GET /s?term=injectme HTTP/1.1\r\nHost: app\r\n\r\n")
    findings = check_reflected_input(req, b"<div>results for injectme</div>")
    assert len(findings) == 1
    assert findings[0].code == "reflected-input"
    assert findings[0].confidence is ConfidenceLevel.SUSPECTED
    assert findings[0].evidence == "term"


def test_reflected_form_body_param() -> None:
    req = _request(
        b"POST /s HTTP/1.1\r\nHost: app\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
    )
    findings = check_reflected_input(req, b"echo: needle123", request_body=b"q=needle123")
    assert _codes(findings) == {"reflected-input"}


def test_short_values_not_reflected() -> None:
    req = _request(b"GET /s?x=ab HTTP/1.1\r\nHost: app\r\n\r\n")
    assert check_reflected_input(req, b"contains ab twice ab") == []


def test_analyze_aggregates_and_dedups() -> None:
    req = _request(b"GET /p?q=reflectme HTTP/1.1\r\nHost: app.example.com\r\n\r\n")
    resp = _response(
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.58\r\n"
        b"Set-Cookie: a=1\r\n"
        b"Set-Cookie: a=1\r\n"  # duplicate -> deduped
        b"\r\n"
    )
    findings = analyze(req, resp, b"echo reflectme", secure=True)
    codes = _codes(findings)
    assert "version-disclosure" in codes
    assert "reflected-input" in codes
    assert "missing-hsts" in codes
    # Duplicate Set-Cookie collapses to one finding per (code, location, evidence).
    secure_cookie = [f for f in findings if f.code == "cookie-missing-secure"]
    assert len(secure_cookie) == 1
