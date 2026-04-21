"""Authentication for the ARGUS MCP server (Backlog/dev1_md §13).

Three authentication channels are supported, evaluated in order:

1. **Static bearer token** — env ``MCP_AUTH_TOKEN``. Mandatory in HTTP/SSE
   mode. Compared with :func:`hmac.compare_digest` to keep timing-leaks at
   bay.
2. **JWT bearer token** — same secret/algorithm as the FastAPI app
   (:class:`src.core.auth.AuthContext`). Lets the same operator session
   talk to both the HTTP API and the MCP server.
3. **API key** — ``X-API-Key`` header from ``ARGUS_API_KEYS`` env (CSV).

In ``stdio`` mode the server treats the parent process as already-trusted
(the operator chose to spawn it) and falls back to
:data:`Settings.default_tenant_id` when no token is supplied. HTTP mode
ALWAYS demands one of the channels above.

The module purposefully does NOT depend on FastAPI: the MCP handler may
run inside ``stdio`` mode where there is no HTTP request object. Callers
pass headers / env explicitly.
"""

from __future__ import annotations

import hmac
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass

from src.core.auth import _decode_jwt
from src.core.config import settings
from src.mcp.exceptions import AuthenticationError

_logger = logging.getLogger(__name__)

_MCP_AUTH_HEADER = "authorization"
_MCP_API_KEY_HEADER = "x-api-key"
_BEARER_PREFIX = "bearer "

_API_KEYS_ENV = "ARGUS_API_KEYS"


@dataclass(frozen=True, slots=True)
class MCPAuthContext:
    """Authentication context for a single MCP call.

    Attributes:
        user_id: Caller identity (e.g. ``mcp-static-token`` or a JWT ``sub``).
        tenant_id: Tenant scope this call operates within. The MCP layer
            enforces tenant isolation by always passing this value down to
            internal services.
        method: How the caller authenticated (``static_token`` /
            ``jwt`` / ``api_key`` / ``stdio_local``).
        is_admin: ``True`` when the caller authenticated via the
            admin-API key channel; admin tools / resources may opt in.
    """

    user_id: str
    tenant_id: str
    method: str
    is_admin: bool = False


def _normalise_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    """Lower-case header keys for case-insensitive lookup."""
    if not headers:
        return {}
    return {str(key).lower(): str(value) for key, value in headers.items()}


def _allowed_api_keys() -> frozenset[str]:
    raw = os.environ.get(_API_KEYS_ENV) or ""
    return frozenset(part.strip() for part in raw.split(",") if part.strip())


def _admin_api_key() -> str | None:
    return (settings.admin_api_key or "").strip() or None


def _static_token() -> str | None:
    raw = (settings.mcp_auth_token or "").strip()
    return raw or None


def _try_static_token(presented: str) -> bool:
    expected = _static_token()
    if not expected:
        return False
    if not presented:
        return False
    return hmac.compare_digest(expected.encode("utf-8"), presented.encode("utf-8"))


def _try_jwt(presented: str) -> dict[str, object] | None:
    payload = _decode_jwt(presented)
    if not payload:
        return None
    if payload.get("type") != "access":
        return None
    sub = payload.get("sub")
    tenant_id = payload.get("tenant_id")
    if not sub or not tenant_id:
        return None
    return payload


def _try_api_key(presented: str) -> tuple[bool, bool]:
    """Return ``(matched, is_admin)``."""
    if not presented:
        return False, False
    admin = _admin_api_key()
    if admin and hmac.compare_digest(admin.encode("utf-8"), presented.encode("utf-8")):
        return True, True
    for key in _allowed_api_keys():
        if hmac.compare_digest(key.encode("utf-8"), presented.encode("utf-8")):
            return True, False
    return False, False


def _resolve_tenant_from_headers(headers: Mapping[str, str], fallback: str) -> str:
    raw = headers.get("x-tenant-id", "")
    cleaned = raw.strip() if isinstance(raw, str) else ""
    return cleaned or fallback


def authenticate(
    *,
    headers: Mapping[str, str] | None = None,
    transport: str = "stdio",
    require_auth: bool | None = None,
) -> MCPAuthContext:
    """Authenticate one MCP call.

    Args:
        headers: Lower-cased mapping of request headers (HTTP/SSE only).
        transport: ``stdio`` or ``http`` / ``streamable-http`` / ``sse``.
        require_auth: When set, overrides the transport-default for whether
            authentication is mandatory. Used by tests and by the
            ``MCP_REQUIRE_AUTH`` env override.

    Raises:
        AuthenticationError: when the credentials are missing / malformed
            and ``require_auth`` is true.
    """
    canonical_headers = _normalise_headers(headers)
    auth_value = canonical_headers.get(_MCP_AUTH_HEADER, "").strip()
    api_key_value = canonical_headers.get(_MCP_API_KEY_HEADER, "").strip()

    presented_bearer: str | None = None
    if auth_value.lower().startswith(_BEARER_PREFIX):
        presented_bearer = auth_value[len(_BEARER_PREFIX) :].strip() or None

    auth_required = (
        require_auth if require_auth is not None else _is_auth_required(transport)
    )

    if presented_bearer:
        if _try_static_token(presented_bearer):
            tenant_id = _resolve_tenant_from_headers(
                canonical_headers, settings.mcp_stdio_tenant_id
            )
            return MCPAuthContext(
                user_id="mcp-static-token",
                tenant_id=tenant_id,
                method="static_token",
                is_admin=False,
            )
        jwt_payload = _try_jwt(presented_bearer)
        if jwt_payload is not None:
            return MCPAuthContext(
                user_id=str(jwt_payload["sub"]),
                tenant_id=str(jwt_payload["tenant_id"]),
                method="jwt",
                is_admin=False,
            )

    if api_key_value:
        matched, is_admin = _try_api_key(api_key_value)
        if matched:
            tenant_id = _resolve_tenant_from_headers(
                canonical_headers, settings.mcp_stdio_tenant_id
            )
            return MCPAuthContext(
                user_id="argus-api-key" if not is_admin else "argus-admin",
                tenant_id=tenant_id,
                method="api_key",
                is_admin=is_admin,
            )

    if auth_required:
        _logger.warning(
            "mcp.auth.missing_or_invalid",
            extra={
                "transport": transport,
                "had_bearer": bool(presented_bearer),
                "had_api_key": bool(api_key_value),
            },
        )
        raise AuthenticationError(
            "Authentication required: provide a bearer token (Authorization "
            "header) or an API key (X-API-Key header)."
        )

    tenant_id = _resolve_tenant_from_headers(
        canonical_headers, settings.mcp_stdio_tenant_id
    )
    return MCPAuthContext(
        user_id=settings.mcp_stdio_actor_id or "mcp-stdio-local",
        tenant_id=tenant_id,
        method="stdio_local",
        is_admin=False,
    )


def _is_auth_required(transport: str) -> bool:
    """True for any HTTP-style transport, false for stdio."""
    transport_lc = (transport or "stdio").lower()
    if transport_lc in {"stdio", "stdio_local"}:
        return _bool_env("MCP_REQUIRE_AUTH", default=False)
    return _bool_env("MCP_REQUIRE_AUTH", default=True)


def _bool_env(name: str, *, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


__all__ = [
    "MCPAuthContext",
    "authenticate",
]
