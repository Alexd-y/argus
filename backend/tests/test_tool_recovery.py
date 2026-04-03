"""Unit tests for ToolRecoverySystem and command rewrite helpers."""

from __future__ import annotations

import pytest

from src.cache.tool_recovery import (
    MAX_RECOVERY_ATTEMPTS,
    TOOL_ALTERNATIVES,
    ToolRecoverySystem,
    _replace_tool_in_command,
)


@pytest.fixture
def recovery() -> ToolRecoverySystem:
    return ToolRecoverySystem()


def test_stateful_tool_returns_no_alternatives(recovery: ToolRecoverySystem) -> None:
    assert recovery.is_stateful("sqlmap") is True
    assert recovery.get_alternatives("sqlmap") == []
    assert recovery.should_retry("sqlmap", attempt=1) is False
    assert recovery.next_alternative("sqlmap", attempt=1) is None


def test_nmap_has_alternatives(recovery: ToolRecoverySystem) -> None:
    alts = recovery.get_alternatives("nmap")
    assert alts == TOOL_ALTERNATIVES["nmap"]
    assert "rustscan" in alts
    assert recovery.is_stateful("nmap") is False
    assert recovery.should_retry("nmap", attempt=1) is True
    assert recovery.next_alternative("nmap", attempt=1) == alts[0]


def test_should_retry_respects_max_attempts(recovery: ToolRecoverySystem) -> None:
    assert recovery.should_retry("nmap", attempt=MAX_RECOVERY_ATTEMPTS) is False


def test_replace_tool_in_command_first_token() -> None:
    cmd = _replace_tool_in_command("nmap -p 80 127.0.0.1", "nmap", "rustscan")
    assert cmd.startswith("rustscan ")
    assert "127.0.0.1" in cmd
    assert "nmap" not in cmd.split()[0]


def test_replace_tool_in_command_preserves_quoted_args() -> None:
    cmd = _replace_tool_in_command('nmap -p 80 "my host"', "nmap", "rustscan")
    assert "rustscan" in cmd
    assert "my host" in cmd


def test_replace_tool_in_command_no_match_when_wrong_binary() -> None:
    original = "curl -s http://x"
    assert _replace_tool_in_command(original, "nmap", "rustscan") == original


def test_replace_tool_in_command_case_insensitive_match() -> None:
    out = _replace_tool_in_command("Nmap -sn 10.0.0.1", "nmap", "rustscan")
    assert out.split()[0] == "rustscan"


def test_replace_tool_in_command_empty_string() -> None:
    assert _replace_tool_in_command("", "nmap", "rustscan") == ""


def test_build_recovery_info_shape(recovery: ToolRecoverySystem) -> None:
    attempts = [
        {"tool": "nmap", "exit_code": 1, "error_type": "nonzero_exit", "duration_sec": 0.1},
    ]
    info = recovery.build_recovery_info("nmap", "rustscan", attempts, from_cache=False)
    expected_keys = {
        "original_tool",
        "final_tool",
        "recovery_used",
        "attempts",
        "total_attempts",
        "is_stateful",
        "from_cache",
        "alternatives_available",
    }
    assert set(info.keys()) == expected_keys
    assert info["original_tool"] == "nmap"
    assert info["final_tool"] == "rustscan"
    assert info["recovery_used"] is True
    assert info["attempts"] == attempts
    assert info["total_attempts"] == 1
    assert info["is_stateful"] is False
    assert info["from_cache"] is False
    assert info["alternatives_available"] == recovery.get_alternatives("nmap")


def test_build_recovery_info_stateful_no_alts(recovery: ToolRecoverySystem) -> None:
    info = recovery.build_recovery_info("sqlmap", "sqlmap", [], from_cache=True)
    assert info["is_stateful"] is True
    assert info["alternatives_available"] == []
    assert info["recovery_used"] is False
    assert info["from_cache"] is True
