"""SecurityVerdict canonical gate shape + declared-scope adoption (§8)."""

from __future__ import annotations

from src.orchestration.execution_mode_context import (
    evaluate_declared_scope,
    target_in_declared_scope,
)
from src.security.verdict import SecurityVerdict


def test_allow_and_deny_constructors() -> None:
    allow = SecurityVerdict.allow("ok", target="x")
    assert allow.allowed and bool(allow) and allow.code == "" and allow.detail == {"target": "x"}
    deny = SecurityVerdict.deny("OUT_OF_SCOPE", "nope")
    assert not deny.allowed and not bool(deny) and deny.code == "OUT_OF_SCOPE"


def test_log_extra_shape() -> None:
    extra = SecurityVerdict.deny("X", "why", host="h").log_extra("gate_denied")
    assert extra["event"] == "gate_denied"
    assert extra["allowed"] is False
    assert extra["code"] == "X"
    assert extra["host"] == "h"


def test_declared_scope_allows_when_no_scope() -> None:
    v = evaluate_declared_scope("evil.com", {})
    assert v.allowed and v.reason == "no_declared_scope"


def test_declared_scope_denies_out_of_scope() -> None:
    opts = {"lab_allowed_targets": ["svalbard.ca"]}
    v = evaluate_declared_scope("attacker.com", opts)
    assert not v.allowed and v.code == "OUT_OF_DECLARED_SCOPE"
    # bool wrapper agrees
    assert target_in_declared_scope("attacker.com", opts) is False
    assert target_in_declared_scope("api.svalbard.ca", opts) is True


def test_declared_scope_fail_closed_on_unparseable() -> None:
    v = evaluate_declared_scope("x", {"lab_allowed_targets": {"bad": "shape"}})
    assert not v.allowed and v.code == "SCOPE_UNPARSEABLE"


def test_argv_network_destinations_extracts_only_urls_and_ips() -> None:
    from src.recon.mcp.kal_executor import _argv_network_destinations

    argv = [
        "nuclei",
        "-u",
        "https://api.svalbard.ca/x",
        "-t",
        "50",  # threads — NOT a destination (must not be extracted)
        "--target=10.0.0.5",
        "203.0.113.9",
        "-w",
        "wordlist.txt",  # dotted but not a URL/IP -> ignored
    ]
    dests = _argv_network_destinations(argv)
    assert dests == ["api.svalbard.ca", "10.0.0.5", "203.0.113.9"]
    # "50" and "wordlist.txt" are not misclassified as hosts.
    assert "50" not in dests and "wordlist.txt" not in dests
