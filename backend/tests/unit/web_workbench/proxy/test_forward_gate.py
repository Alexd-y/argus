"""Unit tests for the mandatory proxy forward gate (WB-P2a, SI-WB-1)."""

from __future__ import annotations

from src.pipeline.contracts.tool_job import TargetSpec
from src.policy.scope import ScopeKind, ScopeRule
from src.web_workbench.projects.service import ProjectScopeService
from src.web_workbench.proxy.forward_gate import (
    REASON_OUT_OF_SCOPE,
    REASON_PREFLIGHT_DENIED,
    REASON_UNRESOLVABLE_TARGET,
    ForwardGate,
    ForwardOutcome,
)
from src.web_workbench.proxy.transport import NormalizedRequest

_RULES = (ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com"),)


def _gate(**kw: object) -> ForwardGate:
    return ForwardGate(ProjectScopeService(_RULES), **kw)  # type: ignore[arg-type]


def _req(host: str, path: str = "/") -> NormalizedRequest:
    return NormalizedRequest.parse(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())


def test_in_scope_forwards() -> None:
    decision = _gate().evaluate(_req("app.example.com"))
    assert decision.outcome is ForwardOutcome.FORWARD
    assert decision.allowed is True
    assert decision.reason is None


def test_out_of_scope_blocked() -> None:
    decision = _gate().evaluate(_req("evil.attacker.tld"))
    assert decision.outcome is ForwardOutcome.BLOCKED
    assert decision.reason == REASON_OUT_OF_SCOPE
    assert decision.allowed is False
    assert decision.scope_summary is not None


def test_unresolvable_target_blocked() -> None:
    req = NormalizedRequest.parse(b"GET /x HTTP/1.1\r\nAccept: */*\r\n\r\n")
    decision = _gate().evaluate(req)
    assert decision.reason == REASON_UNRESOLVABLE_TARGET


def test_preflight_hook_can_deny_in_scope_target() -> None:
    def deny(_target: TargetSpec, _port: int) -> tuple[bool, str | None]:
        return False, "ownership_missing"

    decision = _gate(preflight_hook=deny).evaluate(_req("app.example.com"))
    assert decision.outcome is ForwardOutcome.BLOCKED
    assert decision.reason == "ownership_missing"


def test_preflight_hook_default_reason() -> None:
    def deny(_target: TargetSpec, _port: int) -> tuple[bool, str | None]:
        return False, None

    decision = _gate(preflight_hook=deny).evaluate(_req("app.example.com"))
    assert decision.reason == REASON_PREFLIGHT_DENIED


def test_preflight_hook_allows() -> None:
    def allow(_target: TargetSpec, _port: int) -> tuple[bool, str | None]:
        return True, None

    decision = _gate(preflight_hook=allow).evaluate(_req("app.example.com"))
    assert decision.allowed is True
