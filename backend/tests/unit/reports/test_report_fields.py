"""Block 4.3/4.4 — description + how-to-fix guarantees in finding metadata."""

from __future__ import annotations

from src.reports.finding_metadata import apply_default_finding_metadata


def _meta(f: dict) -> dict:
    apply_default_finding_metadata(f)
    return f


def test_empty_description_filled_from_title():
    f = _meta({"title": "Incomplete security HTTP headers", "severity": "medium"})
    assert f["description"]
    assert "Incomplete security HTTP headers" in f["description"]


def test_security_header_remediation_default():
    f = _meta({"title": "Missing security HTTP headers", "severity": "low"})
    assert "Content-Security-Policy" in f["remediation"]
    # Bridged to the field the report renders as remediation.
    assert f["applicability_notes"] == f["remediation"][:8000]


def test_tls_weakness_remediation_default():
    f = _meta({"title": "TLS configuration weakness", "cwe": "CWE-326", "severity": "medium"})
    assert "TLS 1.3" in f["remediation"]


def test_rate_limit_remediation_default():
    f = _meta({"title": "Missing rate limiting on login endpoint", "severity": "low"})
    assert "rate limiting" in f["remediation"].lower()


def test_explicit_remediation_preserved_and_bridged():
    f = _meta({
        "title": "SPF record missing",
        "severity": "medium",
        "remediation": "Publish v=spf1 ... -all",
    })
    assert f["remediation"] == "Publish v=spf1 ... -all"
    assert f["applicability_notes"] == "Publish v=spf1 ... -all"


def test_unrelated_finding_gets_no_forced_remediation():
    f = _meta({"title": "Reflected XSS", "cwe": "CWE-79", "severity": "high"})
    # XSS is not in the default-remediation classes; no forced fill.
    assert not f.get("remediation")
