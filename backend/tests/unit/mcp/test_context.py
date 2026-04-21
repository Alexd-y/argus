"""Unit tests for :mod:`src.mcp.context`.

The call-context plumbing wires together authentication, the audit logger,
and FastMCP's per-call ``Context`` object. Tests assert:

* Auth overrides win over header parsing (for unit tests).
* The audit logger fixture is honoured globally.
* Header / transport extraction is defensive against the FastMCP context
  shape changing across SDK releases.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from src.mcp.audit_logger import MCPAuditLogger, make_default_audit_logger
from src.mcp.auth import MCPAuthContext
from src.mcp.context import (
    MCPCallContext,
    build_call_context,
    get_audit_logger,
    set_audit_logger,
    set_auth_override,
)
from src.mcp.exceptions import AuthenticationError


def _fake_ctx_with_headers(headers: dict[str, str]) -> Any:
    """Mimic enough of FastMCP's Context for ``_extract_headers``."""
    request = SimpleNamespace(headers=headers)
    request_context = SimpleNamespace(request=request, meta=None)
    return SimpleNamespace(request_context=request_context, request_id="req-1")


class TestAuditOverride:
    def test_set_and_get_audit_logger(self) -> None:
        logger = make_default_audit_logger()
        set_audit_logger(logger)
        assert get_audit_logger() is logger

    def test_get_creates_default_when_unset(self) -> None:
        set_audit_logger(None)
        first = get_audit_logger()
        second = get_audit_logger()
        assert isinstance(first, MCPAuditLogger)
        assert first is second  # cached

    def test_unset_returns_none_then_default(self) -> None:
        set_audit_logger(None)
        assert isinstance(get_audit_logger(), MCPAuditLogger)


class TestAuthOverride:
    def test_override_used_when_set(self, auth_ctx: MCPAuthContext) -> None:
        set_auth_override(auth_ctx)
        ctx = build_call_context(None)
        assert ctx.auth is auth_ctx
        assert ctx.transport == "stdio"

    def test_override_cleared(self) -> None:
        set_auth_override(None)
        ctx = build_call_context(None)
        assert ctx.auth.method == "stdio_local"


class TestBuildCallContext:
    def test_no_ctx_falls_back_to_stdio(self, auth_ctx: MCPAuthContext) -> None:
        set_auth_override(auth_ctx)
        ctx = build_call_context(None)
        assert isinstance(ctx, MCPCallContext)
        assert ctx.headers == {}
        assert ctx.request_id is None

    def test_request_id_propagated(self, auth_ctx: MCPAuthContext) -> None:
        set_auth_override(auth_ctx)
        fake = _fake_ctx_with_headers({})
        ctx = build_call_context(fake)
        assert ctx.request_id == "req-1"

    def test_headers_extracted(self, auth_ctx: MCPAuthContext) -> None:
        set_auth_override(auth_ctx)
        fake = _fake_ctx_with_headers(
            {"Authorization": "Bearer abc", "X-Tenant-ID": "t1"}
        )
        ctx = build_call_context(fake)
        assert ctx.headers.get("Authorization") == "Bearer abc"
        assert ctx.headers.get("X-Tenant-ID") == "t1"

    def test_unauthenticated_http_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        set_auth_override(None)
        monkeypatch.setenv("MCP_REQUIRE_AUTH", "true")
        fake = _fake_ctx_with_headers({})
        with pytest.raises(AuthenticationError):
            build_call_context(fake)

    def test_call_context_is_frozen(self, auth_ctx: MCPAuthContext) -> None:
        set_auth_override(auth_ctx)
        ctx = build_call_context(None)
        with pytest.raises(Exception):
            ctx.transport = "http"  # type: ignore[misc]


class TestMCPCallContextDataclass:
    def test_default_headers_empty_dict(self, auth_ctx: MCPAuthContext) -> None:
        ctx = MCPCallContext(
            auth=auth_ctx,
            audit=make_default_audit_logger(),
            request_id=None,
            transport="stdio",
        )
        assert ctx.headers == {}
