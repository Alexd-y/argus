"""Tenant resolution helpers for the ARGUS MCP server (Backlog/dev1_md §13).

The MCP server enforces strict tenant isolation:

* Every tool / resource / prompt sees a single :class:`MCPAuthContext`
  whose ``tenant_id`` is the **only** trusted tenant for the call.
* Caller-supplied ``tenant_id`` arguments (e.g. ``approvals.list(tenant_id=...)``)
  are validated against the authenticated tenant; a mismatch raises
  :class:`TenantMismatchError` instead of silently downgrading the scope.
* The legacy ``X-Tenant-ID`` header is honoured but only as a *narrowing*
  hint — when present it must equal the authenticated tenant.

This module is dependency-free (no FastAPI / no DB) so it stays usable from
both transports.
"""

from __future__ import annotations

import logging
from uuid import UUID

from src.mcp.auth import MCPAuthContext
from src.mcp.exceptions import TenantMismatchError, ValidationError

_logger = logging.getLogger(__name__)


def assert_tenant_match(auth: MCPAuthContext, claimed_tenant_id: str | None) -> str:
    """Resolve the effective tenant id for an MCP call.

    Args:
        auth: Authenticated context carrying the trusted tenant id.
        claimed_tenant_id: Optional caller-supplied tenant id. When present
            it must equal the authenticated tenant; otherwise the call is
            rejected.

    Returns:
        The authenticated tenant id (stringified) for downstream use.

    Raises:
        ValidationError: when the supplied id is malformed.
        TenantMismatchError: when the supplied id disagrees with the
            authenticated tenant.
    """
    auth_tenant = (auth.tenant_id or "").strip()
    if not auth_tenant:
        _logger.error("mcp.tenancy.missing_authenticated_tenant")
        raise TenantMismatchError(
            "MCP authentication context is missing a tenant identifier."
        )

    if claimed_tenant_id is None:
        return auth_tenant

    cleaned = str(claimed_tenant_id).strip()
    if not cleaned:
        return auth_tenant

    _validate_tenant_id_shape(cleaned)

    if cleaned != auth_tenant:
        _logger.warning(
            "mcp.tenancy.cross_tenant_attempt",
            extra={
                "claimed_tenant_id": cleaned,
                "auth_tenant_id": auth_tenant,
                "method": auth.method,
            },
        )
        raise TenantMismatchError(
            "Provided tenant_id does not match the authenticated tenant scope."
        )
    return auth_tenant


def assert_tenant_owns_resource(
    auth: MCPAuthContext,
    *,
    resource_kind: str,
    resource_tenant_id: str | None,
) -> None:
    """Verify the authenticated tenant owns ``resource_tenant_id``.

    Used by ``findings.get`` / ``scan.status`` / etc. to short-circuit a
    cross-tenant lookup *before* any sensitive payload is built.
    """
    auth_tenant = (auth.tenant_id or "").strip()
    cleaned = (resource_tenant_id or "").strip()
    if not auth_tenant or not cleaned:
        raise TenantMismatchError(
            f"Cannot verify {resource_kind} ownership without tenant context."
        )
    if cleaned != auth_tenant:
        _logger.warning(
            "mcp.tenancy.resource_owner_mismatch",
            extra={
                "resource_kind": resource_kind,
                "resource_tenant_id": cleaned,
                "auth_tenant_id": auth_tenant,
            },
        )
        raise TenantMismatchError(f"{resource_kind} belongs to a different tenant.")


def _validate_tenant_id_shape(value: str) -> None:
    if len(value) > 64:
        raise ValidationError("tenant_id must be at most 64 characters long.")
    try:
        UUID(value)
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValidationError("tenant_id must be a valid UUID string.") from exc


__all__ = [
    "assert_tenant_match",
    "assert_tenant_owns_resource",
]
