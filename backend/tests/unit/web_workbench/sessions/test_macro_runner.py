"""Unit tests for session macro replay (WB-P6b, offline).

Asserts split-plane secret substitution, gate-first (a blocked step aborts
fail-closed), cookie carry-over, and match-rule based auth detection.
"""

from __future__ import annotations

import base64

import pytest

from src.policy.scope import ScopeKind, ScopeRule
from src.web_workbench.proxy.forward_gate import ForwardGate
from src.web_workbench.projects.service import ProjectScopeService
from src.web_workbench.repeater.engine import RawResponse
from src.web_workbench.sessions.macro_runner import (
    MacroError,
    MacroRunner,
    MacroStep,
    parse_steps,
)

_LOGIN_RAW = (
    b"POST /login HTTP/1.1\r\n"
    b"Host: app.example.com\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
    b"user=alice&pw={{PW}}"
)


def _gate(host_pattern: str = "example.com") -> ForwardGate:
    return ForwardGate(
        ProjectScopeService([ScopeRule(kind=ScopeKind.DOMAIN, pattern=host_pattern)])
    )


class _CookieSender:
    """Captures the last sent body and returns a Set-Cookie response."""

    def __init__(self) -> None:
        self.last_body = b""
        self.calls = 0

    def send(self, request, body: bytes) -> RawResponse:  # noqa: ARG002
        self.calls += 1
        self.last_body = body
        raw = (
            b"HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123; Path=/; HttpOnly\r\n\r\nWelcome alice"
        )
        return RawResponse(status_code=200, raw=raw, duration_ms=5)


def _resolver(mapping: dict[str, str]):
    def _resolve(ref: str) -> str:
        return mapping[ref]

    return _resolve


def test_establish_substitutes_secret_and_extracts_cookie() -> None:
    steps = [MacroStep(raw_request=_LOGIN_RAW, secret_refs={"{{PW}}": "vault://pw"})]
    sender = _CookieSender()
    runner = MacroRunner(_gate(), sender)
    session = runner.establish(
        steps, {"cookie_present": "session"}, _resolver({"vault://pw": "s3cr3t"})
    )
    assert session.authenticated is True
    assert session.blocked is False
    assert session.cookies == {"session": "abc123"}
    assert session.cookie_header() == "session=abc123"
    # The resolved secret reached the wire; the placeholder did not.
    assert b"pw=s3cr3t" in sender.last_body
    assert b"{{PW}}" not in sender.last_body


def test_blocked_step_aborts_fail_closed() -> None:
    out_of_scope = b"POST /login HTTP/1.1\r\nHost: evil.test\r\n\r\n"
    steps = [MacroStep(raw_request=out_of_scope)]
    sender = _CookieSender()
    runner = MacroRunner(_gate(), sender)
    session = runner.establish(steps, None, _resolver({}))
    assert session.blocked is True
    assert session.authenticated is False
    assert session.block_reason == "out_of_scope"
    assert sender.calls == 0  # SI-WB-1: nothing sent


def test_match_rules_failure_marks_unauthenticated() -> None:
    steps = [MacroStep(raw_request=_LOGIN_RAW, secret_refs={"{{PW}}": "vault://pw"})]
    runner = MacroRunner(_gate(), _CookieSender())
    session = runner.establish(
        steps, {"body_contains": "Dashboard"}, _resolver({"vault://pw": "s3cr3t"})
    )
    assert session.authenticated is False  # body has "Welcome", not "Dashboard"


def test_cookie_carried_across_steps() -> None:
    class _RecordingSender:
        def __init__(self) -> None:
            self.cookies_seen: list[str | None] = []

        def send(self, request, body):  # noqa: ARG002
            self.cookies_seen.append(request.header("Cookie"))
            return RawResponse(
                status_code=200,
                raw=b"HTTP/1.1 200 OK\r\nSet-Cookie: session=abc123\r\n\r\nok",
                duration_ms=1,
            )

    step1 = MacroStep(raw_request=_LOGIN_RAW, secret_refs={"{{PW}}": "vault://pw"})
    step2 = MacroStep(raw_request=b"GET /me HTTP/1.1\r\nHost: app.example.com\r\n\r\n")
    sender = _RecordingSender()
    runner = MacroRunner(_gate(), sender)
    runner.establish([step1, step2], None, _resolver({"vault://pw": "x"}))
    assert sender.cookies_seen[0] is None  # first step has no session yet
    assert sender.cookies_seen[1] == "session=abc123"  # second carries it


def test_parse_steps_rejects_empty() -> None:
    with pytest.raises(MacroError):
        parse_steps([])


def test_parse_steps_rejects_bad_base64() -> None:
    with pytest.raises(MacroError):
        parse_steps([{"raw_request_base64": "!!!not-base64!!!"}])


def test_parse_steps_roundtrip() -> None:
    encoded = base64.b64encode(_LOGIN_RAW).decode()
    steps = parse_steps([{"raw_request_base64": encoded, "secret_refs": {"{{PW}}": "ref"}}])
    assert steps[0].raw_request == _LOGIN_RAW
    assert steps[0].secret_refs == {"{{PW}}": "ref"}
