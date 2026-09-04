"""Block 2.2 — DNSSEC analyzer tests on fixed dig +dnssec samples."""

from __future__ import annotations

from src.recon.dns_security.dnssec import analyze_dnssec, dnssec_signed

D = "alleksy.com"

_SIGNED = """\
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 3
alleksy.com.  3600 IN DNSKEY 257 3 13 mdsswUyr3D...
alleksy.com.  3600 IN RRSIG DNSKEY 13 2 3600 20260101 ...
"""

_UNSIGNED = """\
;; flags: qr rd ra; QUERY: 1, ANSWER: 1
alleksy.com.  3600 IN A 1.2.3.4
"""

_BROKEN_DS = """\
;; flags: qr rd ra
alleksy.com.  3600 IN DS 12345 13 2 ABCDEF...
"""


def test_signed_zone_no_finding():
    assert dnssec_signed(_SIGNED) is True
    assert analyze_dnssec(D, _SIGNED) == []


def test_unsigned_zone_low_finding():
    f = analyze_dnssec(D, _UNSIGNED)
    assert len(f) == 1
    assert "DNSSEC not enabled" in f[0]["title"]
    assert f[0]["severity"] == "low"
    assert f[0]["cwe"] == "CWE-350"


def test_broken_chain_medium():
    f = analyze_dnssec(D, _BROKEN_DS)
    assert len(f) == 1
    assert "chain broken" in f[0]["title"].lower()
    assert f[0]["severity"] == "medium"


def test_empty_output_treated_as_unsigned():
    f = analyze_dnssec(D, "")
    assert len(f) == 1
    assert f[0]["remediation"]
