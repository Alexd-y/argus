"""Block 2.4 — subdomain enumeration parser tests."""

from __future__ import annotations

from src.recon.dns_security.subdomains import parse_subdomains

D = "alleksy.com"

_SUBFINDER = "www.alleksy.com\nmail.alleksy.com\napi.alleksy.com\n"
_AMASS = (
    "blog.alleksy.com (FQDN) --> a_record --> 1.2.3.4\n"
    "cdn.alleksy.com (FQDN) --> cname_record --> x.cloudfront.net\n"
)
_DNSX = "shop.alleksy.com [A] [93.184.216.34]\n"


def test_subfinder_plain_lines():
    subs = parse_subdomains([_SUBFINDER], D)
    assert subs == ["api.alleksy.com", "mail.alleksy.com", "www.alleksy.com"]


def test_amass_verbose_reduced_to_host():
    subs = parse_subdomains([_AMASS], D)
    assert "blog.alleksy.com" in subs
    assert "cdn.alleksy.com" in subs
    assert all(" " not in s for s in subs)


def test_dnsx_format():
    assert parse_subdomains([_DNSX], D) == ["shop.alleksy.com"]


def test_merge_and_dedup_across_sources():
    subs = parse_subdomains([_SUBFINDER, _AMASS, _DNSX, "www.alleksy.com\n"], D)
    assert len(subs) == len(set(subs))
    assert "www.alleksy.com" in subs and "blog.alleksy.com" in subs


def test_out_of_scope_filtered():
    subs = parse_subdomains(["evil.example.com\nwww.alleksy.com\n"], D)
    assert subs == ["www.alleksy.com"]


def test_wildcard_and_trailing_dot_normalized():
    subs = parse_subdomains(["*.alleksy.com\napi.alleksy.com.\n"], D)
    assert "alleksy.com" in subs
    assert "api.alleksy.com" in subs


def test_apex_domain_accepted():
    assert parse_subdomains(["alleksy.com\n"], D) == ["alleksy.com"]
