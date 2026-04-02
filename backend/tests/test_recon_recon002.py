"""RECON-002 — passive subdomain policy, argv builders, inventory merge."""

import json

from src.recon.mcp.policy import evaluate_kal_mcp_policy
from src.recon.recon_dns_sandbox import dedupe_subdomain_intel_rows
from src.recon.recon_subdomain_inventory import merge_subdomain_hosts_into_tool_results
from src.recon.recon_subdomain_passive import (
    build_assetfinder_recon_argv,
    build_findomain_recon_argv,
    build_subfinder_recon_argv,
    build_theharvester_recon_subdomain_argv,
)


def test_subfinder_argv_shape() -> None:
    assert build_subfinder_recon_argv("example.com") == [
        "subfinder",
        "-d",
        "example.com",
        "-silent",
        "-nW",
    ]


def test_policy_allows_subfinder_passive_argv() -> None:
    d = evaluate_kal_mcp_policy(
        category="dns_enumeration",
        argv=["subfinder", "-d", "example.com", "-silent"],
        password_audit_opt_in=False,
        server_password_audit_enabled=False,
    )
    assert d.allowed


def test_policy_denies_theharvester_bad_source() -> None:
    d = evaluate_kal_mcp_policy(
        category="dns_enumeration",
        argv=["theHarvester", "-d", "example.com", "-b", "google,crtsh", "-l", "100"],
        password_audit_opt_in=False,
        server_password_audit_enabled=False,
    )
    assert not d.allowed
    assert d.reason == "theharvester_source_not_allowed"


def test_policy_allows_theharvester_passive_sources() -> None:
    d = evaluate_kal_mcp_policy(
        category="dns_enumeration",
        argv=["theHarvester", "-d", "example.com", "-b", "crtsh,urlscan", "-l", "100"],
        password_audit_opt_in=False,
        server_password_audit_enabled=False,
    )
    assert d.allowed


def test_assetfinder_and_findomain_argv() -> None:
    assert build_assetfinder_recon_argv("ex.com") == ["assetfinder", "--subs-only", "ex.com"]
    assert build_findomain_recon_argv("ex.com") == ["findomain", "-t", "ex.com", "--quiet"]


def test_dedupe_intel_by_hostname() -> None:
    rows = [
        {
            "data": {"hostname": "a.example.com"},
            "source_tool": "x",
        },
        {
            "data": {"hostname": "a.example.com"},
            "source_tool": "y",
        },
        {
            "data": {"hostname": "b.example.com"},
            "source_tool": "z",
        },
    ]
    out = dedupe_subdomain_intel_rows(rows)
    assert len(out) == 2


def test_merge_subdomain_hosts_tool_results() -> None:
    tool_results: dict = {
        "crtsh": {"success": True, "stdout": '["www.example.com","www.example.com"]'},
        "subfinder": {"stdout": "api.example.com\n"},
    }
    merge_subdomain_hosts_into_tool_results(tool_results, domain="example.com")
    merged = tool_results.get("subdomains_merged")
    assert merged and merged.get("success")
    hosts = json.loads(merged["stdout"])
    assert set(hosts) == {"www.example.com", "api.example.com"}


def test_theharvester_argv_shape() -> None:
    argv = build_theharvester_recon_subdomain_argv("example.com")
    assert argv[0] == "theHarvester"
    assert argv[argv.index("-d") + 1] == "example.com"
    b_idx = argv.index("-b")
    assert "crtsh" in argv[b_idx + 1]
    assert argv[argv.index("-l") + 1].isdigit()
