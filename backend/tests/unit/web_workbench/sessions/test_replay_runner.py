"""Unit tests for owner/attacker authorization replay (WB-P6b, offline).

Asserts gate-first replay, IDOR detection via the shared oracle when an attacker
reads the owner's sensitive data, unauth-access classification for the anonymous
principal, and NO finding when the attacker is denied.
"""

from __future__ import annotations

from src.policy.scope import ScopeKind, ScopeRule
from src.web_workbench.checks.authorization_analyzer import AuthzClass
from src.web_workbench.proxy.forward_gate import ForwardGate
from src.web_workbench.projects.service import ProjectScopeService
from src.web_workbench.repeater.engine import RawResponse
from src.web_workbench.sessions.replay_runner import (
    AuthorizationReplayRunner,
    PrincipalRequest,
)

_TARGET = b"GET /api/orders/12345 HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
_VICTIM_JSON = b'{"order_id":12345,"ssn":"111-22-3333","owner":"alice"}'


def _gate() -> ForwardGate:
    return ForwardGate(
        ProjectScopeService([ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com")])
    )


class _IdorSender:
    """Returns the victim's data to everyone except principals denied by cookie."""

    def send(self, request, body: bytes) -> RawResponse:  # noqa: ARG002
        cookie = request.header("Cookie") or ""
        if "denied" in cookie:
            raw = b"HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{}"
            return RawResponse(status_code=403, raw=raw, duration_ms=1)
        raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + _VICTIM_JSON
        return RawResponse(status_code=200, raw=raw, duration_ms=1)


def test_idor_detected_when_attacker_reads_owner_data() -> None:
    runner = AuthorizationReplayRunner(_gate(), _IdorSender())
    outcome = runner.run(
        _TARGET,
        PrincipalRequest(principal="alice", role="owner", cookie_header="session=owner"),
        [PrincipalRequest(principal="mallory", role="attacker", cookie_header="session=attacker")],
        sensitive_fields=["ssn"],
    )
    assert outcome.owner_forwarded is True
    assert outcome.owner_status == 200
    assert len(outcome.findings) == 1
    assert outcome.findings[0].classification is AuthzClass.IDOR
    assert outcome.findings[0].object_id == "12345"


def test_anonymous_principal_classified_unauth_access() -> None:
    runner = AuthorizationReplayRunner(_gate(), _IdorSender())
    outcome = runner.run(
        _TARGET,
        PrincipalRequest(principal="alice", role="owner", cookie_header="session=owner"),
        [PrincipalRequest(principal="anon", role="anonymous", cookie_header=None)],
        sensitive_fields=["ssn"],
    )
    assert len(outcome.findings) == 1
    assert outcome.findings[0].classification is AuthzClass.UNAUTH_ACCESS


def test_denied_attacker_yields_no_finding() -> None:
    runner = AuthorizationReplayRunner(_gate(), _IdorSender())
    outcome = runner.run(
        _TARGET,
        PrincipalRequest(principal="alice", role="owner", cookie_header="session=owner"),
        [PrincipalRequest(principal="mallory", role="attacker", cookie_header="session=denied")],
        sensitive_fields=["ssn"],
    )
    assert outcome.findings == ()


def test_out_of_scope_owner_short_circuits() -> None:
    target = b"GET /api/orders/1 HTTP/1.1\r\nHost: evil.test\r\n\r\n"
    runner = AuthorizationReplayRunner(_gate(), _IdorSender())
    outcome = runner.run(
        target,
        PrincipalRequest(principal="alice", role="owner", cookie_header="session=owner"),
        [PrincipalRequest(principal="mallory", role="attacker", cookie_header="session=attacker")],
        sensitive_fields=["ssn"],
    )
    assert outcome.owner_forwarded is False
    assert outcome.findings == ()
    assert outcome.blocked_principals == ("alice",)
