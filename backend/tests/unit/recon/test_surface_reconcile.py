"""Block 1.1 — deterministic recon surface reconciliation.

Fixed stdout samples reproduce the alleksy.com plumbing bug: naabu empty on a
live HTTPS host where testssl clearly probed :443, plus WhatWeb output whose
technologies were being dropped.
"""

from __future__ import annotations

from src.recon.surface_reconcile import (
    parse_open_ports,
    parse_technologies,
    reconcile_ports,
    tls_probe_succeeded,
)

_NMAP_STDOUT = """\
Nmap scan report for alleksy.com (1.2.3.4)
PORT     STATE SERVICE
80/tcp   open  http
443/tcp  open  https
8080/tcp closed http-proxy
"""

_NAABU_STDOUT = "alleksy.com:80\nalleksy.com:443\n"

_HTTPX_STDOUT = "https://alleksy.com:8443 [200]\nhttps://alleksy.com [200]\n"

_WHATWEB_STDOUT = (
    "https://alleksy.com/ [200 OK] nginx, HTTPServer[nginx], "
    "Cloudflare, jQuery, Bootstrap, HSTS"
)

_TESTSSL_STDOUT = "Testing protocols on alleksy.com:443\nTLSv1.2 offered\n"


class TestParseOpenPorts:
    def test_nmap_open_ports(self):
        assert parse_open_ports({"nmap": {"stdout": _NMAP_STDOUT}}) == {80, 443}

    def test_naabu_hostport(self):
        assert parse_open_ports({"naabu": {"stdout": _NAABU_STDOUT}}) == {80, 443}

    def test_httpx_url_port(self):
        assert 8443 in parse_open_ports({"httpx": {"stdout": _HTTPX_STDOUT}})

    def test_empty_naabu_yields_nothing(self):
        assert parse_open_ports({"naabu": {"stdout": ""}}) == set()


class TestTlsProbe:
    def test_testssl_success_is_live(self):
        assert tls_probe_succeeded({"testssl": {"success": True, "stdout": _TESTSSL_STDOUT}})

    def test_no_tls_tool_is_false(self):
        assert tls_probe_succeeded({"dig": {"stdout": "some dns output"}}) is False


class TestTechnologies:
    def test_whatweb_tokens_extracted(self):
        techs = parse_technologies({"whatweb": {"stdout": _WHATWEB_STDOUT}})
        assert "Nginx" in techs
        assert "Cloudflare" in techs
        assert "Jquery" in techs

    def test_no_tech_tool_empty(self):
        assert parse_technologies({"dig": {"stdout": "nginx here but not a tech tool"}}) == []


class TestReconcilePorts:
    def test_443_added_when_tls_live_but_naabu_empty(self):
        """The core alleksy.com bug: live TLS, empty naabu, LLM reported nothing."""
        tool_results = {
            "naabu": {"stdout": "", "success": False},
            "testssl": {"stdout": _TESTSSL_STDOUT, "success": True},
        }
        ports = reconcile_ports([], tool_results, "https://alleksy.com")
        assert 443 in ports

    def test_union_of_llm_and_parsed(self):
        tool_results = {"nmap": {"stdout": _NMAP_STDOUT}}
        ports = reconcile_ports([22], tool_results, "https://alleksy.com")
        assert set(ports) == {22, 80, 443}

    def test_empty_https_host_falls_back_to_443(self):
        ports = reconcile_ports([], {}, "https://alleksy.com")
        assert ports == [443]

    def test_empty_http_host_falls_back_to_80(self):
        ports = reconcile_ports([], {}, "http://alleksy.com")
        assert ports == [80]

    def test_no_signal_no_scheme_stays_empty(self):
        # Bare non-URL target with no tool output and no TLS: nothing to seed.
        assert reconcile_ports([], {}, "alleksy.com") == []
