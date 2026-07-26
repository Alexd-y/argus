"""Authentication for the ARGUS MCP server (Backlog/dev1_md §13).

Three authentication channels are supported, evaluated in order:

1. **Static bearer token** — env ``MCP_AUTH_TOKEN``. Mandatory in HTTP/SSE
   mode. Compared with :func:`hmac.compare_digest` to keep timing-leaks at
   bay.
2. **JWT bearer token** — same secret/algorithm as the FastAPI app
   (:class:`src.core.auth.AuthContext`). Lets the same operator session
   talk to both the HTTP API and the MCP server.
3. **API key** — ``X-API-Key`` header from ``ARGUS_API_KEYS`` env (CSV),
   using the same ``key`` / ``key:tenant_uuid`` format as the HTTP API.

Tenant binding (SEC-001)
------------------------
For every *authenticated* channel the tenant is derived from the credential
itself — the JWT ``tenant_id`` claim, the tenant bound to the API key, or the
MCP tenant configured for the static token. A client-supplied ``X-Tenant-ID``
header may only **restate** that tenant; a disagreeing value is a cross-tenant
pivot attempt and raises :class:`~src.mcp.exceptions.TenantMismatchError`.
This mirrors :func:`src.core.tenant.get_current_tenant_id` on the HTTP side.

In ``stdio`` mode the server treats the parent process as already-trusted
(the operator chose to spawn it) and falls back to
:data:`Settings.mcp_stdio_tenant_id` when no token is supplied. That
unauthenticated path still honours ``X-Tenant-ID`` and logs a warning whenever a
non-default tenant is selected without credentials. Unlike the HTTP API — which
has no anonymous path at all — this remains reachable, so keep
``MCP_REQUIRE_AUTH=true`` for any transport that is not a local stdio pipe.
HTTP mode ALWAYS demands one of the channels above.

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
from src.mcp.exceptions import AuthenticationError, TenantMismatchError

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


def _configured_api_keys() -> dict[str, str]:
    """Service API keys mapped to the tenant each key is bound to.

    Same ``ARGUS_API_KEYS`` format as the HTTP API (see
    :func:`src.core.auth._configured_api_keys`): comma-separated ``key`` or
    ``key:tenant_uuid`` entries. A plain key stays bound to
    :data:`Settings.mcp_stdio_tenant_id` — the MCP default — so existing
    single-tenant deployments keep working.
    """
    raw = os.environ.get(_API_KEYS_ENV) or ""
    result: dict[str, str] = {}
    for entry in (part.strip() for part in raw.split(",")):
        if not entry:
            continue
        key, _, tenant_id = entry.rpartition(":")
        if key.strip() and tenant_id.strip():
            result[key.strip()] = tenant_id.strip()
        else:
            result[entry] = settings.mcp_stdio_tenant_id
    return result


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


def _try_api_key(presented: str) -> tuple[str | None, bool]:
    """Return ``(bound_tenant_id, is_admin)``; ``(None, False)`` when unknown."""
    if not presented:
        return None, False
    probe = presented.encode("utf-8")
    admin = _admin_api_key()
    if admin and hmac.compare_digest(admin.encode("utf-8"), probe):
        return settings.mcp_stdio_tenant_id, True
    for key, tenant_id in _configured_api_keys().items():
        if hmac.compare_digest(key.encode("utf-8"), probe):
            return tenant_id, False
    return None, False


def _requested_tenant(headers: Mapping[str, str]) -> str | None:
    """The client-supplied ``X-Tenant-ID`` hint, or ``None`` when absent/blank."""
    raw = headers.get("x-tenant-id", "")
    cleaned = raw.strip() if isinstance(raw, str) else ""
    return cleaned or None


def _bind_tenant(headers: Mapping[str, str], bound_tenant: str, *, method: str) -> str:
    """Confirm an authenticated call's tenant against the ``X-Tenant-ID`` hint.

    The header may only restate the tenant the credential is bound to. It used to
    *select* the tenant, which let any valid MCP credential reach another
    tenant's data.
    """
    requested = _requested_tenant(headers)
    if requested is not None and requested != bound_tenant:
        _logger.warning(
            "mcp.auth.tenant_mismatch",
            extra={
                "method": method,
                "auth_tenant": bound_tenant,
                "requested_tenant": requested,
            },
        )
        raise TenantMismatchError(
            "X-Tenant-ID does not match the authenticated tenant."
        )
    return bound_tenant


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
            # The static token carries no identity of its own, so it is bound to
            # the configured MCP tenant rather than to whatever the client asks for.
            return MCPAuthContext(
                user_id="mcp-static-token",
                tenant_id=_bind_tenant(
                    canonical_headers,
                    settings.mcp_stdio_tenant_id,
                    method="static_token",
                ),
                method="static_token",
                is_admin=False,
            )
        jwt_payload = _try_jwt(presented_bearer)
        if jwt_payload is not None:
            return MCPAuthContext(
                user_id=str(jwt_payload["sub"]),
                tenant_id=_bind_tenant(
                    canonical_headers,
                    str(jwt_payload["tenant_id"]),
                    method="jwt",
                ),
                method="jwt",
                is_admin=False,
            )

    if api_key_value:
        bound_tenant, is_admin = _try_api_key(api_key_value)
        if bound_tenant is not None:
            return MCPAuthContext(
                user_id="argus-api-key" if not is_admin else "argus-admin",
                tenant_id=_bind_tenant(
                    canonical_headers, bound_tenant, method="api_key"
                ),
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

    # Unauthenticated local path: the operator spawned the process, so the header
    # still selects the tenant. Surface it in the log so the residual risk stays
    # observable — this is the only anonymous tenant selection left in ARGUS.
    requested_tenant = _requested_tenant(canonical_headers)
    if requested_tenant is not None and requested_tenant != settings.mcp_stdio_tenant_id:
        _logger.warning(
            "mcp.auth.unauthenticated_tenant_header",
            extra={"transport": transport, "requested_tenant": requested_tenant},
        )
    return MCPAuthContext(
        user_id=settings.mcp_stdio_actor_id or "mcp-stdio-local",
        tenant_id=requested_tenant or settings.mcp_stdio_tenant_id,
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
