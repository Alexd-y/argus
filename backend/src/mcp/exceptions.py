"""Typed exceptions for the ARGUS MCP server (Backlog/dev1_md §13).

The MCP server NEVER leaks raw service-side stack traces to the LLM client.
Every public tool / resource entry point converts internal errors into one of
the closed-taxonomy exceptions defined here. The FastMCP framework serialises
the resulting message via the JSON-RPC error channel; the message MUST stay
short, free of secrets, and drawn from the closed taxonomy below.

Conventions
-----------
* ``code`` — short identifier suitable for telemetry / metrics.
* ``message`` — operator-safe human-readable summary; **no** raw exception
  text, **no** SQL strings, **no** stack frames.
* ``http_status`` — best-effort mapping when the HTTP/SSE transport is
  enabled; the ``stdio`` transport ignores it.
"""

from __future__ import annotations

from typing import Final


class MCPError(Exception):
    """Base class for every MCP server error surfaced to clients.

    Attributes:
        code: Closed-taxonomy identifier (``snake_case``).
        message: Operator-safe summary; safe to send to the LLM client.
        http_status: Suggested HTTP status when running over HTTP/SSE.
    """

    code: str = "mcp_error"
    http_status: int = 500

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code

    def __str__(self) -> str:
        return f"[{self.code}] {self.message}"


class AuthenticationError(MCPError):
    """Bearer token / API key missing, malformed, or rejected."""

    code = "mcp_auth_unauthenticated"
    http_status = 401


class AuthorizationError(MCPError):
    """Caller authenticated but lacks permission for the requested action."""

    code = "mcp_auth_forbidden"
    http_status = 403


class TenantMismatchError(MCPError):
    """Tenant header / token scope disagrees with the resource's owner."""

    code = "mcp_tenant_mismatch"
    http_status = 403


class ScopeViolationError(MCPError):
    """Target is not in the customer's authorised scope (default-deny)."""

    code = "mcp_scope_violation"
    http_status = 403


class ApprovalRequiredError(MCPError):
    """High-risk / destructive action lacks a valid signed approval."""

    code = "mcp_approval_required"
    http_status = 403


class PolicyDeniedError(MCPError):
    """Tenant policy explicitly denies the requested action."""

    code = "mcp_policy_denied"
    http_status = 403


class ResourceNotFoundError(MCPError):
    """Requested resource does not exist (or is not readable by this tenant)."""

    code = "mcp_resource_not_found"
    http_status = 404


class ValidationError(MCPError):
    """Pydantic validation failed for an MCP tool / resource argument."""

    code = "mcp_validation_error"
    http_status = 422


class RateLimitedError(MCPError):
    """Per-tool / per-tenant rate limit exceeded."""

    code = "mcp_rate_limited"
    http_status = 429


class UpstreamServiceError(MCPError):
    """An internal ARGUS service raised an error we could not recover from."""

    code = "mcp_upstream_error"
    http_status = 502


_ALL_ERROR_CODES: Final[frozenset[str]] = frozenset(
    {
        AuthenticationError.code,
        AuthorizationError.code,
        TenantMismatchError.code,
        ScopeViolationError.code,
        ApprovalRequiredError.code,
        PolicyDeniedError.code,
        ResourceNotFoundError.code,
        ValidationError.code,
        RateLimitedError.code,
        UpstreamServiceError.code,
    }
)


def is_known_error_code(code: str) -> bool:
    """Return ``True`` iff ``code`` belongs to the closed MCP error taxonomy."""
    return code in _ALL_ERROR_CODES


__all__ = [
    "MCPError",
    "AuthenticationError",
    "AuthorizationError",
    "TenantMismatchError",
    "ScopeViolationError",
    "ApprovalRequiredError",
    "PolicyDeniedError",
    "ResourceNotFoundError",
    "ValidationError",
    "RateLimitedError",
    "UpstreamServiceError",
    "is_known_error_code",
]
