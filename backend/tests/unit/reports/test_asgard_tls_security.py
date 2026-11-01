"""Asgard TLS analysis: security-control correctness + injection safety.

Regressions from the Target-Intelligence wiring:
- HSTS 'not offered' must be FAIL, never a false pass on a truthy string.
- An expired / not-yet-valid certificate must be FAIL, not pass.
- Issuer presence is informational, not a trust 'pass'.
- Certificate-derived strings (issuer/subject/SAN) are endpoint-controlled, so
  Markdown/HTML/control-char injection must be neutralised, while legitimate
  wildcard names (*.example.com) survive.
"""

from __future__ import annotations

from src.reports.asgard_paid import (
    _hsts_status,
    _sanitize_cert_value,
    _validity_status,
    build_tls_analysis,
)


class _RD:
    def __init__(self, created_at: str = "2026-11-01T00:00:00Z") -> None:
        self.target = "https://svalbard.ca"
        self.created_at = created_at
        self.findings: list = []


def _ctx(ssl: dict) -> dict:
    return {"valhalla_context": {"ssl_tls_analysis": ssl, "ssl_tls_table_rows": [{"domain": "x"}]}}


def test_hsts_not_offered_is_fail() -> None:
    assert _hsts_status("not offered,{") == ("Absent", "fail")
    assert _hsts_status("max-age=0") == ("max-age=0", "fail")
    disp, st = _hsts_status("max-age=63072000; includeSubDomains")
    assert st == "pass" and "63072000" in disp


def test_validity_window() -> None:
    assert _validity_status("2020-01-01", "2021-01-01", "2026-11-01") == "fail"  # expired
    assert _validity_status("2030-01-01", "2031-01-01", "2026-11-01") == "fail"  # not yet valid
    assert _validity_status("2026-10-16", "2027-01-14", "2026-11-01") == "pass"
    assert _validity_status("", "", "2026-11-01") == "not assessed"


def test_sanitize_neutralises_injection_keeps_wildcard() -> None:
    dirty = "*.svalbard.ca\n## PWNED [a](http://evil) `x` <b>"
    clean = _sanitize_cert_value(dirty)
    assert "\n" not in clean
    assert "#" not in clean and "[" not in clean and "<" not in clean and "`" not in clean
    assert clean.startswith("*.svalbard.ca")  # wildcard preserved


def test_build_tls_analysis_rows_reflect_real_posture() -> None:
    ssl = {
        "issuer": "YR1 (Let's Encrypt from US)",
        "subject": "*.svalbard.ca",
        "san": ["*.svalbard.ca", "svalbard.ca"],
        "valid_from": "2026-10-16",
        "valid_to": "2027-01-14",
        "protocols": ["TLS 1.2", "TLS 1.3"],
        "weak_protocols": [],
        "hsts": "not offered,{",
    }
    out = build_tls_analysis(_RD(), _ctx(ssl))
    by_check = {r["check"]: r for r in out["rows"]}
    assert by_check["Certificate Issuer"]["status"] == "info"  # not 'pass'
    assert by_check["Certificate Subject"]["result"] == "*.svalbard.ca"
    assert "*.svalbard.ca" in by_check["Certificate Subject"]["detail"]  # SAN listed
    assert by_check["Validity"]["status"] == "pass"
    assert by_check["HSTS"]["status"] == "fail"  # 'not offered' is not a pass
    assert by_check["Negotiated protocols"]["status"] == "pass"
