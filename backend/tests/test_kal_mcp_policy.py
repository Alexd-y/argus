"""KAL-002 — MCP KAL policy allowlist and hydra gates."""

from __future__ import annotations

import pytest

from src.recon.mcp.policy import (
    KAL_OPERATION_CATEGORIES,
    evaluate_kal_mcp_policy,
    kal_argv_has_injection_risk,
    normalize_kal_binary,
)


def test_normalize_kal_binary_testssl() -> None:
    assert normalize_kal_binary("/opt/testssl.sh") == "testssl.sh"
    assert normalize_kal_binary("TestSSL.SH") == "testssl.sh"


@pytest.mark.parametrize(
    ("category", "argv", "opt_in", "server_on", "allowed"),
    [
        ("network_scanning", ["nmap", "-Pn", "1.2.3.4"], False, False, True),
        ("network_scanning", ["masscan", "1.2.3.4", "-p", "80"], False, False, True),
        ("network_scanning", ["naabu", "-host", "example.com", "-top-ports", "100", "-silent"], False, False, True),
        ("bruteforce_testing", ["hydra", "-l", "a", "1.2.3.4", "ssh"], True, True, False),
        ("password_audit", ["hydra", "-l", "a", "1.2.3.4", "ssh"], True, False, False),
        ("password_audit", ["hydra", "-l", "a", "1.2.3.4", "ssh"], False, True, False),
        ("password_audit", ["hydra", "-l", "a", "1.2.3.4", "ssh"], True, True, True),
        ("ssl_analysis", ["openssl", "s_client", "-connect", "x:443"], False, False, True),
        ("ssl_analysis", ["openssl", "req", "-x509"], False, False, False),
        ("dns_enumeration", ["dig", "example.com"], False, False, True),
        ("dns_enumeration", ["dnsrecon", "-d", "example.com", "-t", "std"], False, False, True),
        ("dns_enumeration", ["fierce", "-dns", "example.com"], False, False, True),
        ("dns_enumeration", ["amass", "enum", "-passive", "-d", "example.com"], False, False, True),
        ("dns_enumeration", ["amass", "intel", "-whois", "-d", "example.com"], False, False, False),
        ("api_testing", ["nuclei", "-u", "https://x"], False, False, True),
        ("vuln_intel", ["searchsploit", "apache 2.4", "--json"], False, False, True),
        ("vuln_intel", ["nmap", "-sV", "x"], False, False, False),
        ("url_history", ["gau", "example.com"], False, False, True),
        ("url_history", ["waybackurls", "example.com"], False, False, True),
        ("url_history", ["katana", "-u", "https://x", "-d", "2", "-silent"], False, False, True),
        ("url_history", ["nuclei", "-u", "x"], False, False, False),
        ("js_analysis", ["linkfinder", "-i", "/tmp/x.js", "-o", "cli"], False, False, True),
        ("js_analysis", ["unfurl", "https://x/?a=1"], False, False, True),
        ("js_analysis", ["gau", "x"], False, False, False),
        ("asn_mapping", ["asnmap", "-d", "example.com", "-silent", "-json"], False, False, True),
        ("asn_mapping", ["nmap", "-sV", "x"], False, False, False),
        ("web_screenshots", ["gowitness", "-q", "scan", "single", "-u", "https://x", "-s", "/tmp/gw"], False, False, True),
        ("web_screenshots", ["httpx", "-u", "https://x"], False, False, False),
    ],
)
def test_evaluate_kal_mcp_policy_matrix(
    category: str,
    argv: list[str],
    opt_in: bool,
    server_on: bool,
    allowed: bool,
) -> None:
    d = evaluate_kal_mcp_policy(
        category=category,
        argv=argv,
        password_audit_opt_in=opt_in,
        server_password_audit_enabled=server_on,
    )
    assert d.allowed is allowed


def test_unknown_category_denied() -> None:
    d = evaluate_kal_mcp_policy(
        category="not_a_category",
        argv=["nmap", "x"],
        password_audit_opt_in=False,
        server_password_audit_enabled=False,
    )
    assert not d.allowed
    assert d.reason == "unknown_category"


def test_kal_operation_categories_contains_expected() -> None:
    assert "password_audit" in KAL_OPERATION_CATEGORIES
    assert "bruteforce_testing" in KAL_OPERATION_CATEGORIES
    assert "vuln_intel" in KAL_OPERATION_CATEGORIES
    assert "url_history" in KAL_OPERATION_CATEGORIES
    assert "js_analysis" in KAL_OPERATION_CATEGORIES
    assert "asn_mapping" in KAL_OPERATION_CATEGORIES
    assert "web_screenshots" in KAL_OPERATION_CATEGORIES


def test_argv_injection_pattern() -> None:
    assert kal_argv_has_injection_risk(["nmap", "1.2.3.4;rm"])
    assert not kal_argv_has_injection_risk(["nmap", "-sV", "example.com"])
