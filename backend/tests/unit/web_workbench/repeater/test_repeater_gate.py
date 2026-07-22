"""Unit tests for Repeater scope-gated replay (WB-P3b).

The security-critical assertion: a blocked replay NEVER invokes the sender.
"""

from __future__ import annotations

import pytest

from src.policy.scope import ScopeKind, ScopeRule
from src.web_workbench.message_editor.engine import HttpMessageError
from src.web_workbench.proxy.forward_gate import (
    REASON_OUT_OF_SCOPE,
    REASON_PREFLIGHT_DENIED,
    REASON_UNRESOLVABLE_TARGET,
    ForwardOutcome,
)
from src.web_workbench.projects.service import ProjectScopeService
from src.web_workbench.repeater.engine import RawResponse, RepeaterService


class _SpySender:
    """Records how many times it is asked to send (must be 0 when blocked)."""

    def __init__(self) -> None:
        self.calls = 0

    def send(self, request: object, body: bytes) -> RawResponse:  # noqa: ARG002
        self.calls += 1
        return RawResponse(status_code=200, raw=b"HTTP/1.1 200 OK\r\n\r\n", duration_ms=3)


def _raw(host: str) -> bytes:
    return f"GET /account HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()


def _scope() -> ProjectScopeService:
    return ProjectScopeService([ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com")])


def test_in_scope_replay_invokes_sender_once() -> None:
    service = RepeaterService(_scope())
    sender = _SpySender()
    result = service.replay(_raw("app.example.com"), sender)
    assert result.forwarded is True
    assert result.outcome is ForwardOutcome.FORWARD
    assert result.response is not None
    assert result.response.status_code == 200
    assert sender.calls == 1


def test_out_of_scope_replay_blocked_and_sender_untouched() -> None:
    service = RepeaterService(_scope())
    sender = _SpySender()
    result = service.replay(_raw("evil.attacker.test"), sender)
    assert result.forwarded is False
    assert result.outcome is ForwardOutcome.BLOCKED
    assert result.reason == REASON_OUT_OF_SCOPE
    assert result.response is None
    assert sender.calls == 0  # nothing left the process


def test_preflight_hook_denies_before_send() -> None:
    def deny(_target: object, _port: int) -> tuple[bool, str | None]:
        return False, None

    service = RepeaterService(_scope(), preflight_hook=deny)
    sender = _SpySender()
    result = service.replay(_raw("app.example.com"), sender)
    assert result.forwarded is False
    assert result.reason == REASON_PREFLIGHT_DENIED
    assert sender.calls == 0


def test_preflight_hook_allows_after_scope() -> None:
    def allow(_target: object, _port: int) -> tuple[bool, str | None]:
        return True, None

    service = RepeaterService(_scope(), preflight_hook=allow)
    sender = _SpySender()
    result = service.replay(_raw("app.example.com"), sender)
    assert result.forwarded is True
    assert sender.calls == 1


def test_unresolvable_target_blocked() -> None:
    service = RepeaterService(_scope())
    sender = _SpySender()
    # origin-form target with no Host header cannot be resolved.
    result = service.replay(b"GET /x HTTP/1.1\r\n\r\n", sender)
    assert result.forwarded is False
    assert result.reason == REASON_UNRESOLVABLE_TARGET
    assert sender.calls == 0


def test_malformed_request_raises() -> None:
    service = RepeaterService(_scope())
    sender = _SpySender()
    with pytest.raises(HttpMessageError):
        service.replay(b"garbage-without-request-line\r\n\r\n", sender)
    assert sender.calls == 0
