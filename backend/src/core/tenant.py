"""Tenant context — resolve the current tenant, bound to the authenticated identity.

SEC-001: the tenant is derived from the authenticated principal (JWT / API key),
never from a client-supplied ``X-Tenant-ID`` header alone. Behaviour:

* Authenticated request — the principal's ``tenant_id`` is authoritative. An
  ``X-Tenant-ID`` header that disagrees with it is a cross-tenant pivot attempt
  and is rejected with ``403``. A matching (or absent) header is accepted.
* Unauthenticated request — rejected with ``401`` when ``require_tenant_auth`` is
  enabled (recommended for production). When disabled (default, for backward
  compatibility) the legacy header/default-tenant behaviour is preserved, and a
  security warning is logged whenever a non-default tenant is selected without
  credentials so the residual risk is observable.
"""

import logging
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status

from src.core.auth import AuthContext, get_optional_auth
from src.core.config import settings

logger = logging.getLogger(__name__)


async def get_current_tenant_id(
    auth: Annotated[AuthContext | None, Depends(get_optional_auth)],
    x_tenant_id: Annotated[str | None, Header(alias="X-Tenant-ID")] = None,
) -> str:
    """Resolve the tenant for the current request (see module docstring)."""
    header_tenant = (
        x_tenant_id.strip() if x_tenant_id and x_tenant_id.strip() else None
    )

    if auth is not None:
        if header_tenant is not None and header_tenant != auth.tenant_id:
            logger.warning(
                "Rejected X-Tenant-ID that does not match authenticated tenant",
                extra={
                    "event_type": "tenant_mismatch",
                    "auth_tenant": auth.tenant_id,
                    "requested_tenant": header_tenant,
                    "is_api_key": auth.is_api_key,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Tenant mismatch",
            )
        return auth.tenant_id

    if settings.require_tenant_auth:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if header_tenant is not None and header_tenant != settings.default_tenant_id:
        logger.warning(
            "Unauthenticated request selected a non-default tenant via header; "
            "set REQUIRE_TENANT_AUTH=true to enforce authentication (SEC-001)",
            extra={
                "event_type": "unauthenticated_tenant_header",
                "requested_tenant": header_tenant,
            },
        )
        return header_tenant

    return settings.default_tenant_id
