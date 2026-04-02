"""VA active scan MCP tool allowlist (OWASP-001, OWASP2-001)."""

from __future__ import annotations

import pytest

from src.recon.mcp.policy import (
    VA_ACTIVE_SCAN_ALLOWED_TOOLS,
    VA_ACTIVE_SCAN_MCP_OPERATIONS,
    VA_ACTIVE_SCAN_POLICY_ID,
    evaluate_va_active_scan_tool_policy,
    is_va_active_scan_mcp_operation,
    resolve_va_active_scan_tool_canonical,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("dalfox", "dalfox"),
        ("DalFox", "dalfox"),
        ("DAL_FOX", "dalfox"),
        ("dal-fox", "dalfox"),
        ("xsstrike", "xsstrike"),
        ("XS_Strike", "xsstrike"),
        ("ffuf", "ffuf"),
        ("FFUF", "ffuf"),
        ("sqlmap", "sqlmap"),
        ("SQL_MAP", "sqlmap"),
        ("sql-map", "sqlmap"),
        ("nuclei", "nuclei"),
        ("NUCLEI", "nuclei"),
        ("gobuster", "gobuster"),
        ("Go_Buster", "gobuster"),
        (" gobuster ", "gobuster"),
        ("wfuzz", "wfuzz"),
        ("WFUZZ", "wfuzz"),
        ("wf_uzz", "wfuzz"),
        ("wf-uzz", "wfuzz"),
        ("commix", "commix"),
        ("COMMIX", "commix"),
        ("com_mix", "commix"),
        ("com-mix", "commix"),
        ("whatweb", "whatweb"),
        ("What_Web", "whatweb"),
        ("nikto", "nikto"),
        ("NIKTO", "nikto"),
        ("testssl", "testssl"),
        ("testssl.sh", "testssl"),
        ("sslscan", "sslscan"),
        ("SSL_Scan", "sslscan"),
        ("feroxbuster", "feroxbuster"),
        ("hydra", "hydra"),
        ("medusa", "medusa"),
        ("mitmdump", "mitmdump"),
        ("tcpdump", "tcpdump"),
        ("theHarvester", "theharvester"),
        ("THE_HARVESTER", "theharvester"),
        ("gospider", "gospider"),
        ("GoSpider", "gospider"),
        ("parsero", "parsero"),
    ],
)
def test_resolve_canonical_normalizes_and_allowlists(raw: str, expected: str) -> None:
    assert resolve_va_active_scan_tool_canonical(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "zap",
        "unknown_scanner",
        "sqlmap_extra_suffix_not_allowed",
        "metasploit",
    ],
)
def test_resolve_canonical_unknown_is_none(raw: str) -> None:
    assert resolve_va_active_scan_tool_canonical(raw) is None


def test_allowed_tools_frozenset_matches_policy() -> None:
    assert VA_ACTIVE_SCAN_ALLOWED_TOOLS == frozenset(
        {
            "dalfox",
            "xsstrike",
            "ffuf",
            "sqlmap",
            "nuclei",
            "gobuster",
            "wfuzz",
            "commix",
            "whatweb",
            "nikto",
            "testssl",
            "sslscan",
            "feroxbuster",
            "hydra",
            "medusa",
            "mitmdump",
            "tcpdump",
            "theharvester",
            "gospider",
            "parsero",
        }
    )


@pytest.mark.parametrize(
    "tool",
    [
        "dalfox",
        "xsstrike",
        "ffuf",
        "sqlmap",
        "nuclei",
        "gobuster",
        "wfuzz",
        "commix",
        "whatweb",
        "nikto",
        "testssl",
        "sslscan",
        "feroxbuster",
        "hydra",
        "medusa",
        "mitmdump",
        "tcpdump",
        "theharvester",
        "gospider",
        "parsero",
    ],
)
def test_evaluate_allowed_each_canonical(tool: str) -> None:
    d = evaluate_va_active_scan_tool_policy(tool_name=tool)
    assert d.allowed is True
    assert d.reason == "allowed"
    assert d.policy_id == VA_ACTIVE_SCAN_POLICY_ID


def test_evaluate_denied_unknown_tool() -> None:
    d = evaluate_va_active_scan_tool_policy(tool_name="w3af")
    assert d.allowed is False
    assert d.reason == "active_scan_tool_not_allowlisted"
    assert d.policy_id == VA_ACTIVE_SCAN_POLICY_ID


def test_evaluate_denied_empty_name() -> None:
    d = evaluate_va_active_scan_tool_policy(tool_name="")
    assert d.allowed is False
    assert d.reason == "active_scan_tool_not_allowlisted"


def test_va_active_scan_mcp_operations_frozenset() -> None:
    assert VA_ACTIVE_SCAN_MCP_OPERATIONS == frozenset(
        {
            "run_dalfox",
            "run_xsstrike",
            "run_ffuf",
            "run_sqlmap",
            "run_nuclei",
            "run_whatweb",
            "run_nikto",
            "run_testssl",
        }
    )


@pytest.mark.parametrize(
    ("op", "expected"),
    [
        ("run_dalfox", True),
        ("RUN_SQLMAP", True),
        ("run-nuclei", True),
        ("run_whatweb", True),
        ("RUN_TESTSSL", True),
        ("run_other", False),
        ("", False),
    ],
)
def test_is_va_active_scan_mcp_operation(op: str, expected: bool) -> None:
    assert is_va_active_scan_mcp_operation(op) is expected
