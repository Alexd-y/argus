"""Unit tests for recon artifact parsers."""

from pathlib import Path

import pytest

from src.recon.parsers.whois_parser import parse_whois
from src.recon.parsers.dns_parser import parse_dns
from src.recon.parsers.resolved_parser import parse_resolved
from src.recon.parsers.cname_parser import parse_cname
from src.recon.parsers.http_probe_parser import parse_http_probe


# --- WHOIS Parser ---


class TestWhoisParser:
    """Tests for whois_parser.parse_whois."""

    def test_valid_whois_full(self, tmp_path):
        content = """
Domain Name: example.com
Registrar: GoDaddy.com, LLC
Registrant Name: John Doe
Registrant Organization: Acme Inc
Creation Date: 2020-01-15T12:00:00Z
Registry Expiry Date: 2025-01-15T12:00:00Z
Name Server: ns1.example.com
Name Server: ns2.example.com
"""
        f = tmp_path / "whois.txt"
        f.write_text(content, encoding="utf-8")
        result = parse_whois(f)
        assert result["registrar"] == "GoDaddy.com, LLC"
        assert result["expiry"] == "2025-01-15T12:00:00Z"
        assert result["creation_date"] == "2020-01-15T12:00:00Z"
        assert result["registrant"] in ("John Doe", "Acme Inc")
        assert "ns1.example.com" in result["nameservers"]
        assert "ns2.example.com" in result["nameservers"]

    def test_valid_whois_single_record(self, tmp_path):
        content = "Registrar: Namecheap\nRegistry Expiry Date: 2024-06-01"
        f = tmp_path / "whois.txt"
        f.write_text(content, encoding="utf-8")
        result = parse_whois(f)
        assert result["registrar"] == "Namecheap"
        assert result["expiry"] == "2024-06-01"
        assert result["nameservers"] == []
        assert result["registrant"] == ""
        assert result["creation_date"] == ""

    def test_missing_file_returns_empty(self, tmp_path):
        missing = tmp_path / "nonexistent_whois.txt"
        assert not missing.exists()
        result = parse_whois(missing)
        assert result == {
            "registrar": "",
            "expiry": "",
            "nameservers": [],
            "registrant": "",
            "creation_date": "",
        }

    def test_empty_file_returns_empty(self, tmp_path):
        f = tmp_path / "whois.txt"
        f.write_text("", encoding="utf-8")
        result = parse_whois(f)
        assert result["registrar"] == ""
        assert result["nameservers"] == []

    def test_whitespace_only_returns_empty(self, tmp_path):
        f = tmp_path / "whois.txt"
        f.write_text("   \n\t  \n", encoding="utf-8")
        result = parse_whois(f)
        assert result["registrar"] == ""
        assert result["nameservers"] == []

    def test_malformed_data_no_exception(self, tmp_path):
        f = tmp_path / "whois.txt"
        f.write_text("garbage\n{invalid}\n\x00binary", encoding="utf-8", errors="replace")
        result = parse_whois(f)
        assert isinstance(result, dict)
        assert "registrar" in result
        assert result["nameservers"] == []

    def test_accepts_path_object(self, tmp_path):
        content = "Registrar: Test Registrar"
        f = tmp_path / "whois.txt"
        f.write_text(content, encoding="utf-8")
        result = parse_whois(Path(f))
        assert result["registrar"] == "Test Registrar"

    def test_accepts_str_path(self, tmp_path):
        content = "Registrar: Test Registrar"
        f = tmp_path / "whois.txt"
        f.write_text(content, encoding="utf-8")
        result = parse_whois(str(f))
        assert result["registrar"] == "Test Registrar"


# --- DNS Parser ---


class TestDnsParser:
    """Tests for dns_parser.parse_dns."""

    def test_valid_ns_file(self, tmp_path):
        content = "example.com.  nameserver = ns1.example.com.\nexample.com.  nameserver = ns2.example.com."
        f = tmp_path / "ns.txt"
        f.write_text(content, encoding="utf-8")
        result = parse_dns(f)
        assert len(result) == 2
        assert result[0]["type"] == "NS"
        assert result[0]["value"] == "ns1.example.com."
        assert result[1]["value"] == "ns2.example.com."

    def test_valid_mx_file(self, tmp_path):
        content = "example.com.  MX preference = 10, mail exchanger = mail.example.com."
        f = tmp_path / "mx.txt"
        f.write_text(content, encoding="utf-8")
        result = parse_dns(f)
        assert len(result) == 1
        assert result[0]["type"] == "MX"
        assert result[0]["value"] == "mail.example.com."

    def test_valid_txt_file(self, tmp_path):
        content = 'example.com.  text = "v=spf1 include:_spf.example.com ~all"'
        f = tmp_path / "txt.txt"
        f.write_text(content, encoding="utf-8")
        result = parse_dns(f)
        assert len(result) == 1
        assert result[0]["type"] == "TXT"
        assert "spf1" in result[0]["value"]

    def test_valid_caa_file(self, tmp_path):
        content = 'example.com.  0 issue "letsencrypt.org"'
        f = tmp_path / "caa.txt"
        f.write_text(content, encoding="utf-8")
        result = parse_dns(f)
        assert len(result) == 1
        assert result[0]["type"] == "CAA"
        assert "letsencrypt" in result[0]["value"].lower()

    def test_valid_dns_records_mixed(self, tmp_path):
        content = """example.com.  192.0.2.1
example.com.  2001:db8::1
example.com.  nameserver = ns.example.com.
"""
        f = tmp_path / "dns_records.txt"
        f.write_text(content, encoding="utf-8")
        result = parse_dns(f)
        assert len(result) == 3
        types = {r["type"] for r in result}
        assert "A" in types
        assert "AAAA" in types
        assert "NS" in types

    def test_missing_file_returns_empty_list(self, tmp_path):
        missing = tmp_path / "nonexistent_dns.txt"
        result = parse_dns(missing)
        assert result == []

    def test_empty_file_returns_empty_list(self, tmp_path):
        f = tmp_path / "ns.txt"
        f.write_text("", encoding="utf-8")
        result = parse_dns(f)
        assert result == []

    def test_comments_skipped(self, tmp_path):
        content = "; comment\n  \n; another\n"
        f = tmp_path / "ns.txt"
        f.write_text(content, encoding="utf-8")
        result = parse_dns(f)
        assert result == []

    def test_malformed_data_no_exception(self, tmp_path):
        f = tmp_path / "ns.txt"
        f.write_text("not valid dns\n{json}\n\x00\xff", encoding="utf-8", errors="replace")
        result = parse_dns(f)
        assert isinstance(result, list)
        assert result == []

    def test_single_record(self, tmp_path):
        content = "example.com.  nameserver = ns.example.com."
        f = tmp_path / "ns.txt"
        f.write_text(content, encoding="utf-8")
        result = parse_dns(f)
        assert len(result) == 1
        assert result[0]["type"] == "NS"


# --- Resolved Parser ---


class TestResolvedParser:
    """Tests for resolved_parser.parse_resolved."""

    def test_valid_resolved_full(self, tmp_path):
        content = """autodiscover.example.com -> 52.96.165.8, 52.96.164.248
www.example.com -> 93.184.216.34
api.example.com -> 10.0.0.1, 10.0.0.2
"""
        f = tmp_path / "resolved.txt"
        f.write_text(content, encoding="utf-8")
        result = parse_resolved(f)
        assert len(result) == 3
        assert result["autodiscover.example.com"] == ["52.96.165.8", "52.96.164.248"]
        assert result["www.example.com"] == ["93.184.216.34"]
        assert result["api.example.com"] == ["10.0.0.1", "10.0.0.2"]

    def test_single_record(self, tmp_path):
        content = "sub.example.com -> 1.2.3.4"
        f = tmp_path / "resolved.txt"
        f.write_text(content, encoding="utf-8")
        result = parse_resolved(f)
        assert result == {"sub.example.com": ["1.2.3.4"]}

    def test_missing_file_returns_empty_dict(self, tmp_path):
        missing = tmp_path / "nonexistent_resolved.txt"
        result = parse_resolved(missing)
        assert result == {}

    def test_empty_file_returns_empty_dict(self, tmp_path):
        f = tmp_path / "resolved.txt"
        f.write_text("", encoding="utf-8")
        result = parse_resolved(f)
        assert result == {}

    def test_comments_skipped(self, tmp_path):
        content = "; comment\nsub.example.com -> 1.2.3.4\n  ; inline"
        f = tmp_path / "resolved.txt"
        f.write_text(content, encoding="utf-8")
        result = parse_resolved(f)
        assert result == {"sub.example.com": ["1.2.3.4"]}

    def test_malformed_line_skipped(self, tmp_path):
        content = "valid.sub.com -> 1.2.3.4\ninvalid-no-arrow\nother.sub.com -> 5.6.7.8"
        f = tmp_path / "resolved.txt"
        f.write_text(content, encoding="utf-8")
        result = parse_resolved(f)
        assert "valid.sub.com" in result
        assert "other.sub.com" in result
        assert "invalid-no-arrow" not in result

    def test_malformed_data_no_exception(self, tmp_path):
        f = tmp_path / "resolved.txt"
        f.write_text("{invalid json}\n\x00\xff", encoding="utf-8", errors="replace")
        result = parse_resolved(f)
        assert isinstance(result, dict)
        assert result == {}

    def test_single_ip(self, tmp_path):
        content = "host.example.com -> 192.168.1.1"
        f = tmp_path / "resolved.txt"
        f.write_text(content, encoding="utf-8")
        result = parse_resolved(f)
        assert result["host.example.com"] == ["192.168.1.1"]


# --- CNAME Parser ---


class TestCnameParser:
    """Tests for cname_parser.parse_cname."""

    def test_valid_cname_full(self, tmp_path):
        content = "host,record_type,value,comment\nwww.example.com,CNAME,cdn.example.com,CDN\napi.example.com,CNAME,api-backend.example.com,"
        f = tmp_path / "cname_map.csv"
        f.write_text(content, encoding="utf-8", newline="")
        result = parse_cname(f)
        assert len(result) == 2
        assert result[0]["host"] == "www.example.com"
        assert result[0]["record_type"] == "CNAME"
        assert result[0]["value"] == "cdn.example.com"
        assert result[0]["comment"] == "CDN"
        assert result[1]["host"] == "api.example.com"
        assert result[1]["comment"] == ""

    def test_single_record(self, tmp_path):
        content = "host,record_type,value,comment\nsub.example.com,CNAME,target.example.com,test"
        f = tmp_path / "cname_map.csv"
        f.write_text(content, encoding="utf-8", newline="")
        result = parse_cname(f)
        assert len(result) == 1
        assert result[0]["host"] == "sub.example.com"
        assert result[0]["value"] == "target.example.com"

    def test_missing_file_returns_empty_list(self, tmp_path):
        missing = tmp_path / "nonexistent_cname.csv"
        result = parse_cname(missing)
        assert result == []

    def test_empty_csv_returns_empty_list(self, tmp_path):
        content = "host,record_type,value,comment\n"
        f = tmp_path / "cname_map.csv"
        f.write_text(content, encoding="utf-8", newline="")
        result = parse_cname(f)
        assert result == []

    def test_header_only_returns_empty_list(self, tmp_path):
        content = "host,record_type,value,comment"
        f = tmp_path / "cname_map.csv"
        f.write_text(content, encoding="utf-8", newline="")
        result = parse_cname(f)
        assert result == []

    def test_malformed_csv_no_exception(self, tmp_path):
        f = tmp_path / "cname_map.csv"
        f.write_text('host,record_type,value,comment\n"unclosed', encoding="utf-8", errors="replace")
        result = parse_cname(f)
        assert isinstance(result, list)

    def test_missing_columns_handled(self, tmp_path):
        content = "host,record_type\nonly,two"
        f = tmp_path / "cname_map.csv"
        f.write_text(content, encoding="utf-8", newline="")
        result = parse_cname(f)
        assert len(result) == 1
        assert result[0]["host"] == "only"
        assert result[0]["record_type"] == "two"
        assert result[0].get("value", "") == ""
        assert result[0].get("comment", "") == ""


# --- HTTP Probe Parser ---


class TestHttpProbeParser:
    """Tests for http_probe_parser.parse_http_probe."""

    def test_valid_http_probe_full(self, tmp_path):
        content = """host,url,scheme,status,title,server,redirect
example.com,https://example.com/,https,200,Example Domain,nginx,
api.example.com,https://api.example.com/,https,301,,,https://api.example.com/v1/
"""
        f = tmp_path / "http_probe.csv"
        f.write_text(content, encoding="utf-8", newline="")
        result = parse_http_probe(f)
        assert len(result) == 2
        assert result[0]["host"] == "example.com"
        assert result[0]["url"] == "https://example.com/"
        assert result[0]["scheme"] == "https"
        assert result[0]["status"] == "200"
        assert result[0]["title"] == "Example Domain"
        assert result[0]["server"] == "nginx"
        assert result[0]["redirect"] == ""
        assert result[1]["status"] == "301"
        assert "api.example.com" in result[1]["redirect"] or "v1" in result[1]["redirect"]

    def test_single_record(self, tmp_path):
        content = "host,url,scheme,status,title,server,redirect\nwww.example.com,https://www.example.com/,https,200,Home,,"
        f = tmp_path / "http_probe.csv"
        f.write_text(content, encoding="utf-8", newline="")
        result = parse_http_probe(f)
        assert len(result) == 1
        assert result[0]["host"] == "www.example.com"
        assert result[0]["status"] == "200"

    def test_missing_file_returns_empty_list(self, tmp_path):
        missing = tmp_path / "nonexistent_http_probe.csv"
        result = parse_http_probe(missing)
        assert result == []

    def test_empty_csv_returns_empty_list(self, tmp_path):
        content = "host,url,scheme,status,title,server,redirect\n"
        f = tmp_path / "http_probe.csv"
        f.write_text(content, encoding="utf-8", newline="")
        result = parse_http_probe(f)
        assert result == []

    def test_header_only_returns_empty_list(self, tmp_path):
        content = "host,url,scheme,status,title,server,redirect"
        f = tmp_path / "http_probe.csv"
        f.write_text(content, encoding="utf-8", newline="")
        result = parse_http_probe(f)
        assert result == []

    def test_malformed_csv_no_exception(self, tmp_path):
        f = tmp_path / "http_probe.csv"
        f.write_text('host,url,scheme,status,title,server,redirect\n"unclosed', encoding="utf-8", errors="replace")
        result = parse_http_probe(f)
        assert isinstance(result, list)

    def test_accepts_path_object(self, tmp_path):
        content = "host,url,scheme,status,title,server,redirect\ntest.com,https://test.com/,https,200,,,"
        f = tmp_path / "http_probe.csv"
        f.write_text(content, encoding="utf-8", newline="")
        result = parse_http_probe(Path(f))
        assert len(result) == 1
        assert result[0]["host"] == "test.com"
