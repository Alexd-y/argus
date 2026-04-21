"""Per-call context propagation for MCP tools / resources / prompts.

The FastMCP framework injects a :class:`mcp.server.fastmcp.Context` into
every handler that requests it. We extend that with a tiny
:class:`MCPCallContext` dataclass that bundles the authenticated context,
the audit logger, and a request id so the actual tool body is one
``ctx_local = build_call_context(ctx)`` away from a fully-isolated call
environment.

Usage::

    @mcp.tool()
    async def my_tool(payload: MyInput, ctx: Context) -> MyOutput:
        local = build_call_context(ctx)
        local.audit.record_tool_call(...)
        ...
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, TypeAlias

from mcp.server.fastmcp import Context

from src.mcp.audit_logger import MCPAuditLogger, make_default_audit_logger
from src.mcp.auth import MCPAuthContext, authenticate
from src.mcp.exceptions import AuthenticationError

_logger = logging.getLogger(__name__)

MCPContext: TypeAlias = Context[Any, Any, Any]
"""Concrete Context alias used across the MCP layer.

The framework's :class:`Context` carries three opaque generics
(``ServerSessionT`` / ``LifespanContextT`` / ``RequestT``) that we never
inspect; aliasing them to ``Any`` keeps ``mypy --strict`` happy without
forcing every call site to thread phantom type parameters."""


@dataclass(frozen=True, slots=True)
class MCPCallContext:
    """Per-call context derived from the FastMCP :class:`Context`."""

    auth: MCPAuthContext
    audit: MCPAuditLogger
    request_id: str | None
    transport: str
    headers: Mapping[str, str] = field(default_factory=dict)


_AUDIT_OVERRIDE: MCPAuditLogger | None = None
_AUTH_OVERRIDE: MCPAuthContext | None = None
_RATE_LIMITER: object | None = None
_NOTIFICATION_DISPATCHER: object | None = None


def set_audit_logger(audit: MCPAuditLogger | None) -> None:
    """Inject a process-wide audit logger (set by server bootstrap / tests)."""
    global _AUDIT_OVERRIDE
    _AUDIT_OVERRIDE = audit


def set_auth_override(ctx: MCPAuthContext | None) -> None:
    """Force the auth context for unit tests (bypasses header parsing)."""
    global _AUTH_OVERRIDE
    _AUTH_OVERRIDE = ctx


def get_audit_logger() -> MCPAuditLogger:
    """Return the bound audit logger (or a fresh in-memory one for stdio)."""
    global _AUDIT_OVERRIDE
    if _AUDIT_OVERRIDE is None:
        _AUDIT_OVERRIDE = make_default_audit_logger()
    return _AUDIT_OVERRIDE


def set_rate_limiter(limiter: object | None) -> None:
    """Inject the process-wide :class:`TokenBucketLimiter`.

    Loosely typed (``object | None``) to keep this module free of a hard
    import on :mod:`src.mcp.runtime.rate_limiter` (which would create an
    import cycle through :mod:`src.mcp.tools._runtime`). Callers in the
    MCP server bootstrap typecast at the call-site.
    """
    global _RATE_LIMITER
    _RATE_LIMITER = limiter


def get_rate_limiter() -> object | None:
    """Return the injected rate limiter, if any (``None`` disables limiting)."""
    return _RATE_LIMITER


def set_notification_dispatcher(dispatcher: object | None) -> None:
    """Inject the process-wide :class:`NotificationDispatcher`.

    Mirrors :func:`set_rate_limiter` — the dispatcher is opaque from this
    module's perspective so we don't pull in the notifications package
    here.
    """
    global _NOTIFICATION_DISPATCHER
    _NOTIFICATION_DISPATCHER = dispatcher


def get_notification_dispatcher() -> object | None:
    """Return the injected notification dispatcher, if any."""
    return _NOTIFICATION_DISPATCHER


def _extract_headers(ctx: MCPContext | None) -> Mapping[str, str]:
    """Pull HTTP headers from the FastMCP context if present.

    FastMCP stores the underlying request scope on its ``request_context``
    when running over HTTP/SSE; we walk it defensively because the shape
    can change between MCP SDK releases.
    """
    if ctx is None:
        return {}
    request_context = getattr(ctx, "request_context", None)
    if request_context is None:
        return {}
    candidates: list[Mapping[str, str]] = []

    request_attr = getattr(request_context, "request", None)
    if request_attr is not None:
        headers_obj = getattr(request_attr, "headers", None)
        if headers_obj is not None and hasattr(headers_obj, "items"):
            try:
                candidates.append({k: v for k, v in headers_obj.items()})
            except Exception:  # pragma: no cover — defensive
                pass

    meta = getattr(request_context, "meta", None)
    if isinstance(meta, Mapping):
        headers_meta = meta.get("headers") if isinstance(meta, dict) else None
        if isinstance(headers_meta, Mapping):
            candidates.append(headers_meta)

    merged: dict[str, str] = {}
    for source in candidates:
        for key, value in source.items():
            if isinstance(key, str) and isinstance(value, (str, bytes)):
                merged[key] = value.decode() if isinstance(value, bytes) else value
    return merged


def _detect_transport(ctx: MCPContext | None) -> str:
    """Best-effort transport identification.

    Stdio mode keeps ``request_context`` shallow; HTTP / SSE transports
    populate ``request_context.request`` (Starlette request).
    """
    if ctx is None:
        return "stdio"
    request_context = getattr(ctx, "request_context", None)
    if request_context is None:
        return "stdio"
    request_attr = getattr(request_context, "request", None)
    if request_attr is None:
        return "stdio"
    return os.environ.get("MCP_TRANSPORT", "http")


def build_call_context(ctx: MCPContext | None) -> MCPCallContext:
    """Construct a :class:`MCPCallContext` from a FastMCP ``Context``.

    Raises:
        AuthenticationError: when authentication is required but absent.
    """
    headers = _extract_headers(ctx)
    transport = _detect_transport(ctx)

    if _AUTH_OVERRIDE is not None:
        auth_ctx = _AUTH_OVERRIDE
    else:
        try:
            auth_ctx = authenticate(headers=headers, transport=transport)
        except AuthenticationError:
            raise

    request_id = getattr(ctx, "request_id", None) if ctx is not None else None
    return MCPCallContext(
        auth=auth_ctx,
        audit=get_audit_logger(),
        request_id=str(request_id) if request_id is not None else None,
        transport=transport,
        headers=headers,
    )


__all__ = [
    "MCPCallContext",
    "MCPContext",
    "build_call_context",
    "get_audit_logger",
    "get_notification_dispatcher",
    "get_rate_limiter",
    "set_audit_logger",
    "set_auth_override",
    "set_notification_dispatcher",
    "set_rate_limiter",
]
