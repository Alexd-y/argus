"""Block 2.3 — SPF/DMARC/DKIM analyzer tests on fixed TXT samples."""

from __future__ import annotations

from src.recon.dns_security.email_auth import (
    analyze_dkim,
    analyze_dmarc,
    analyze_email_auth,
    analyze_spf,
)

D = "alleksy.com"


def _titles(findings):
    return [f["title"] for f in findings]


class TestSPF:
    def test_missing_spf(self):
        f = analyze_spf(D, [])
        assert len(f) == 1
        assert "SPF record missing" in f[0]["title"]
        assert f[0]["severity"] == "medium"
        assert "-all" in f[0]["remediation"]

    def test_hard_fail_is_clean(self):
        assert analyze_spf(D, ["v=spf1 include:_spf.google.com -all"]) == []

    def test_plus_all_is_high(self):
        f = analyze_spf(D, ["v=spf1 +all"])
        assert f and f[0]["severity"] == "high"

    def test_bare_all_is_high(self):
        f = analyze_spf(D, ["v=spf1 all"])
        assert f and f[0]["severity"] == "high"

    def test_softfail_is_low(self):
        f = analyze_spf(D, ["v=spf1 include:example.com ~all"])
        assert f and f[0]["severity"] == "low"

    def test_all_substring_not_false_positive(self):
        # "install"/"installer" contain "all" but are not the 'all' mechanism.
        f = analyze_spf(D, ["v=spf1 include:mail.installer.com redirect=install.example -all"])
        assert f == []  # terminal -all => clean, no false +all HIGH

    def test_bare_all_among_includes(self):
        f = analyze_spf(D, ["v=spf1 include:x.com all"])
        assert f and f[0]["severity"] == "high"

    def test_multiple_spf(self):
        f = analyze_spf(D, ["v=spf1 -all", "v=spf1 include:x -all"])
        assert any("Multiple SPF" in t for t in _titles(f))


class TestDMARC:
    def test_missing_dmarc(self):
        f = analyze_dmarc(D, [])
        assert len(f) == 1
        assert "DMARC record missing" in f[0]["title"]

    def test_p_none_flagged(self):
        f = analyze_dmarc(D, ["v=DMARC1; p=none; rua=mailto:d@alleksy.com"])
        assert any("monitor-only" in t for t in _titles(f))

    def test_p_reject_with_rua_clean(self):
        f = analyze_dmarc(D, ["v=DMARC1; p=reject; rua=mailto:d@alleksy.com"])
        assert f == []

    def test_missing_rua(self):
        f = analyze_dmarc(D, ["v=DMARC1; p=reject"])
        assert any("aggregate reporting" in t for t in _titles(f))


class TestDKIM:
    def test_no_dkim_across_selectors(self):
        f = analyze_dkim(D, {"default": ["not a dkim record"], "google": []})
        assert len(f) == 1
        assert f[0]["severity"] == "low"

    def test_valid_dkim_clean(self):
        f = analyze_dkim(D, {"default": ["v=DKIM1; k=rsa; p=MIGfMA0GCSq..."]})
        assert f == []

    def test_no_selectors_probed_no_finding(self):
        assert analyze_dkim(D, {}) == []


class TestCombined:
    def test_all_missing_yields_three(self):
        f = analyze_email_auth(D, txt_records=[], dmarc_txt_records=[], dkim_records_by_selector={"default": [""]})
        titles = _titles(f)
        assert any("SPF record missing" in t for t in titles)
        assert any("DMARC record missing" in t for t in titles)
        assert any("DKIM not detected" in t for t in titles)

    def test_all_findings_carry_evidence_and_remediation(self):
        f = analyze_email_auth(D, txt_records=[], dmarc_txt_records=[])
        assert all(x["evidence"] and x["remediation"] for x in f)
