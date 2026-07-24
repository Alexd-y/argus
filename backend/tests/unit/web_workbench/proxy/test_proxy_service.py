"""Unit tests for the proxy flow processor core (WB-P2b-2, offline).

Exercises the pure security + capture core of the MITM daemon without mitmproxy:
the mandatory gate verdict, capture-payload construction, intercept ergonomics,
and sink persistence.
"""

from __future__ import annotations

import pytest

from src.policy.scope import ScopeKind, ScopeRule
from src.web_workbench.proxy.forward_gate import ForwardDecision, ForwardGate, ForwardOutcome
from src.web_workbench.proxy.intercept_rules import (
    InterceptAction,
    InterceptRule,
    InterceptRuleSet,
)
from src.web_workbench.proxy.repository import CaptureInput
from src.web_workbench.proxy.service import ProxyFlowProcessor, ProxyIdentity
from src.web_workbench.proxy.transport import NormalizedRequest, NormalizedResponse
from src.web_workbench.projects.service import ProjectScopeService

_IDENTITY = ProxyIdentity(tenant_id="t-1", project_id="p-1", listener_id="l-1")


class _FakeSink:
    def __init__(self) -> None:
        self.captures: list[CaptureInput] = []

    async def record(self, capture: CaptureInput) -> None:
        self.captures.append(capture)


def _gate() -> ForwardGate:
    return ForwardGate(
        ProjectScopeService([ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com")])
    )


def _request(host: str = "app.example.com", path: str = "/orders?id=1") -> NormalizedRequest:
    return NormalizedRequest.parse(
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\r\n".encode()
    )


def _response() -> NormalizedResponse:
    return NormalizedResponse.parse(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n")


def _processor(sink: _FakeSink, **kwargs) -> ProxyFlowProcessor:
    return ProxyFlowProcessor(_gate(), identity=_IDENTITY, sink=sink, **kwargs)


def test_in_scope_request_is_allowed() -> None:
    decision = _processor(_FakeSink()).evaluate(_request())
    assert decision.allowed is True


def test_out_of_scope_request_is_blocked() -> None:
    decision = _processor(_FakeSink()).evaluate(_request(host="evil.test"))
    assert decision.allowed is False
    assert decision.reason == "out_of_scope"


def test_build_capture_for_forwarded_flow() -> None:
    proc = _processor(_FakeSink())
    request = _request()
    decision = proc.evaluate(request)
    capture = proc.build_capture(
        request=request,
        decision=decision,
        request_body=b"",
        response=_response(),
        response_body=b'{"ok":true}',
    )
    assert capture.method == "GET"
    assert capture.scheme == "https"
    assert capture.host == "app.example.com"
    assert capture.port == 443
    assert capture.path == "/orders"
    assert capture.query == "id=1"
    assert capture.forward_outcome == str(ForwardOutcome.FORWARD.value)
    assert capture.in_scope is True
    assert capture.status_code == 200
    assert capture.source == "proxy"
    assert capture.listener_id == "l-1"


def test_build_capture_for_blocked_flow_marks_out_of_scope() -> None:
    proc = _processor(_FakeSink())
    request = _request(host="evil.test")
    decision = proc.evaluate(request)
    capture = proc.build_capture(
        request=request,
        decision=decision,
        request_body=None,
        response=None,
        response_body=None,
    )
    assert capture.forward_outcome == str(ForwardOutcome.BLOCKED.value)
    assert capture.in_scope is False
    assert capture.block_reason == "out_of_scope"
    assert capture.status_code is None


def test_preflight_denied_capture_is_in_scope_but_blocked() -> None:
    # scope passes, preflight denies → in_scope True, outcome blocked.
    gate = ForwardGate(
        ProjectScopeService([ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com")]),
        preflight_hook=lambda _t, _p: (False, "preflight_denied"),
    )
    proc = ProxyFlowProcessor(gate, identity=_IDENTITY, sink=_FakeSink())
    request = _request()
    decision = proc.evaluate(request)
    capture = proc.build_capture(
        request=request, decision=decision, request_body=None, response=None, response_body=None
    )
    assert capture.forward_outcome == str(ForwardOutcome.BLOCKED.value)
    assert capture.in_scope is True
    assert capture.block_reason == "preflight_denied"


def test_intercept_action_disabled_by_default() -> None:
    rules = InterceptRuleSet(
        rules=(InterceptRule(action=InterceptAction.INTERCEPT, path_prefix="/orders"),)
    )
    proc = _processor(_FakeSink(), intercept_rules=rules, intercept_enabled=False)
    assert proc.intercept_action(_request()) is InterceptAction.PASS


def test_intercept_action_enabled_matches_rule() -> None:
    rules = InterceptRuleSet(
        rules=(InterceptRule(action=InterceptAction.INTERCEPT, path_prefix="/orders"),)
    )
    proc = _processor(_FakeSink(), intercept_rules=rules, intercept_enabled=True)
    assert proc.intercept_action(_request(path="/orders")) is InterceptAction.INTERCEPT
    assert proc.intercept_action(_request(path="/public")) is InterceptAction.PASS


async def test_record_forwards_capture_to_sink() -> None:
    sink = _FakeSink()
    proc = _processor(sink)
    request = _request()
    capture = proc.build_capture(
        request=request,
        decision=proc.evaluate(request),
        request_body=b"",
        response=_response(),
        response_body=b"{}",
    )
    await proc.record(capture)
    assert sink.captures == [capture]


def test_negative_capture_cap_rejected() -> None:
    with pytest.raises(ValueError, match="max_capture_bytes"):
        _processor(_FakeSink(), max_capture_bytes=-1)


# ---------------------------------------------------------------------------
# Daemon bootstrap pure helpers (no mitmproxy / DB required)
# ---------------------------------------------------------------------------


class TestResolveListenEndpoint:
    def test_defaults(self, monkeypatch) -> None:
        from src.web_workbench.proxy import service

        monkeypatch.delenv("WB_PROXY_LISTEN_HOST", raising=False)
        monkeypatch.delenv("WB_PROXY_LISTEN_PORT", raising=False)
        assert service._resolve_listen_endpoint() == ("0.0.0.0", 8080)

    def test_env_override(self, monkeypatch) -> None:
        from src.web_workbench.proxy import service

        monkeypatch.setenv("WB_PROXY_LISTEN_HOST", "127.0.0.1")
        monkeypatch.setenv("WB_PROXY_LISTEN_PORT", "9090")
        assert service._resolve_listen_endpoint() == ("127.0.0.1", 9090)

    def test_invalid_port_raises(self, monkeypatch) -> None:
        from src.web_workbench.proxy import service

        monkeypatch.setenv("WB_PROXY_LISTEN_PORT", "not-a-port")
        with pytest.raises(RuntimeError, match="WB_PROXY_LISTEN_PORT"):
            service._resolve_listen_endpoint()

    def test_out_of_range_port_raises(self, monkeypatch) -> None:
        from src.web_workbench.proxy import service

        monkeypatch.setenv("WB_PROXY_LISTEN_PORT", "70000")
        with pytest.raises(RuntimeError, match="out of range"):
            service._resolve_listen_endpoint()


class TestWriteCaMaterial:
    def test_writes_bundle_and_cert(self, tmp_path) -> None:
        import os

        from src.web_workbench.proxy import service

        confdir = str(tmp_path / "wb-ca")
        key_pem = b"-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n"
        cert_pem = b"-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n"

        bundle = service._write_ca_material(
            confdir, private_key_pem=key_pem, certificate_pem=cert_pem
        )

        assert bundle == os.path.join(confdir, "mitmproxy-ca.pem")
        with open(bundle, "rb") as fh:
            data = fh.read()
        # KEY precedes CERT in the combined mitmproxy bundle.
        assert data.index(b"PRIVATE KEY") < data.index(b"CERTIFICATE")
        assert b"KEY" in data and b"CERT" in data

        cert_only = os.path.join(confdir, "mitmproxy-ca-cert.pem")
        with open(cert_only, "rb") as fh:
            assert fh.read() == cert_pem

        if os.name == "posix":
            assert (os.stat(bundle).st_mode & 0o777) == 0o600
