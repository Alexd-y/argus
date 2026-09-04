"""Block 2.1 — DNS record parser + AXFR/CAA analyzer tests."""

from __future__ import annotations

from src.recon.dns_security.dns_records import (
    analyze_axfr,
    analyze_caa,
    parse_dns_records,
)

D = "alleksy.com"

_DIG_ANY = """\
;; ANSWER SECTION:
alleksy.com.        3600  IN  A      93.184.216.34
alleksy.com.        3600  IN  AAAA   2606:2800:220:1:248:1893:25c8:1946
alleksy.com.        3600  IN  MX     10 mail.alleksy.com.
alleksy.com.        3600  IN  NS     ns1.alleksy.com.
alleksy.com.        3600  IN  TXT    "v=spf1 -all"
alleksy.com.        3600  IN  CAA    0 issue "letsencrypt.org"
"""

_AXFR_OK = """\
alleksy.com.  3600 IN SOA ns1.alleksy.com. admin.alleksy.com. 1 7200 3600 1209600 3600
alleksy.com.  3600 IN NS  ns1.alleksy.com.
www.alleksy.com. 3600 IN A 1.2.3.4
internal.alleksy.com. 3600 IN A 10.0.0.5
alleksy.com.  3600 IN SOA ns1.alleksy.com. admin.alleksy.com. 1 7200 3600 1209600 3600
"""

_AXFR_REFUSED = "; Transfer failed.\n"


class TestParseRecords:
    def test_demux_by_type(self):
        rec = parse_dns_records(_DIG_ANY)
        assert rec["A"] == ["93.184.216.34"]
        assert "2606:2800:220:1:248:1893:25c8:1946" in rec["AAAA"]
        assert rec["MX"] == ["10 mail.alleksy.com"]
        assert rec["NS"] == ["ns1.alleksy.com"]
        assert rec["TXT"] == ["v=spf1 -all"]
        assert rec["CAA"][0].startswith("0 issue")

    def test_empty(self):
        assert parse_dns_records("") == {}


class TestAXFR:
    def test_successful_transfer_high_finding(self):
        f = analyze_axfr(D, _AXFR_OK, nameserver="ns1.alleksy.com")
        assert len(f) == 1
        assert f[0]["severity"] == "high"
        assert f[0]["cwe"] == "CWE-538"

    def test_refused_transfer_no_finding(self):
        assert analyze_axfr(D, _AXFR_REFUSED) == []

    def test_empty_no_finding(self):
        assert analyze_axfr(D, "") == []


class TestCAA:
    def test_missing_caa_low_finding(self):
        f = analyze_caa(D, {"A": ["1.2.3.4"]})
        assert len(f) == 1
        assert f[0]["severity"] == "low"

    def test_present_caa_clean(self):
        assert analyze_caa(D, {"CAA": ['0 issue "letsencrypt.org"']}) == []
