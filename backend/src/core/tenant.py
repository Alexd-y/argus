"""Tenant context — current tenant for RLS and authorization.

MVP: uses DEFAULT_TENANT_ID from env. Optional X-Tenant-ID header for MCP/API clients.
When auth is implemented: extract from JWT/session.
"""

from fastapi import Header

from src.core.config import settings


def get_current_tenant_id(
    x_tenant_id: str | None = Header(None, alias="X-Tenant-ID"),
) -> str:
    """
    Return current tenant ID for the request.
    Uses X-Tenant-ID header when provided (e.g. by MCP client), else DEFAULT_TENANT_ID.
    """
    if x_tenant_id and x_tenant_id.strip():
        return x_tenant_id.strip()
    return settings.default_tenant_id
