"""FastAPI authorization dependency wiring the ABAC engine into routes (F-M05).

The ABAC engine in :mod:`src.auth.abac` was fully implemented but never
enforced on any endpoint — 6 roles / 7 actions / 11 resource types of dead
policy code. This module bridges authN → authZ with a single opt-in,
fail-safe dependency factory: :func:`require_access`.

Rollout is staged through two settings so enabling policy on a live tenant
never causes a surprise outage:

======================  ==================  =====================================
``abac_enabled``        ``abac_enforce``    Behaviour
======================  ==================  =====================================
``False`` (default)     (ignored)           Passthrough — no-op.
``True``                ``False``           Advisory — evaluate + log, never block.
``True``                ``True``            Enforcing — a deny raises HTTP 403.
======================  ==================  =====================================

The dependency is *authorization only*. Authentication remains owned by
``get_optional_auth`` / ``get_required_auth``; an anonymous request is passed
through untouched so this layer can never convert a 401 into a 403.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from src.auth.abac import (
    ABACEngine,
    AccessAction,
    AccessRequest,
    ResourceType,
    Role,
)
from src.core.auth import AuthContext, get_optional_auth
from src.core.config import settings

logger = logging.getLogger(__name__)

# Stateless for our usage: we never trigger the elevation path (no
# ``elevation_reason``), so a single shared instance is safe across requests.
_engine = ABACEngine()


def _resolve_role(auth: AuthContext) -> Role:
    """Map the principal's role string to a :class:`Role`.

    Falls back to ``settings.abac_default_role`` when the token carries no
    role, and to the least-privileged :attr:`Role.VIEWER` when the resolved
    string is not a known role — a misconfiguration must never silently grant
    more access than intended.
    """
    raw = (auth.role or settings.abac_default_role or "").strip().lower()
    try:
        return Role(raw)
    except ValueError:
        logger.warning(
            "abac_unknown_role_fallback_viewer",
            extra={
                "raw_role": raw,
                "user_id": auth.user_id,
                "tenant_id": auth.tenant_id,
            },
        )
        return Role.VIEWER


def require_access(
    action: AccessAction,
    resource_type: ResourceType,
    *,
    resource_id_param: str | None = None,
) -> Callable[..., Awaitable[AuthContext | None]]:
    """Build a FastAPI dependency that evaluates (or enforces) an ABAC policy.

    ``action`` / ``resource_type`` describe the operation the wrapped route
    performs. ``resource_id_param``, when set, names a path parameter whose
    value is recorded in the audit log (the current policy does not gate on
    resource identity, but the audit trail benefits from it).

    Returns the resolved :class:`AuthContext` (or ``None`` for anonymous
    requests) so routes can keep using the dependency's return value.
    """

    async def _dependency(
        request: Request,
        auth: Annotated[AuthContext | None, Depends(get_optional_auth)],
    ) -> AuthContext | None:
        # Master switch off, or nothing to authorize (authN handled upstream).
        if not settings.abac_enabled or auth is None:
            return auth

        resource_id = ""
        if resource_id_param:
            resource_id = str(request.path_params.get(resource_id_param, ""))

        role = _resolve_role(auth)
        decision = _engine.evaluate(
            AccessRequest(
                user_id=auth.user_id,
                tenant_id=auth.tenant_id,
                role=role,
                action=action,
                resource_type=resource_type,
                resource_id=resource_id,
                # MFA / device posture are not yet plumbed through the request
                # pipeline. Assume satisfied so advisory mode surfaces *role*
                # gaps only, not MFA noise. Tighten once session posture is
                # threaded through.
                mfa_verified=True,
                device_trusted=True,
            ),
        )

        if decision.allowed:
            return auth

        log_fields = {
            "user_id": auth.user_id,
            "tenant_id": auth.tenant_id,
            "role": role.value,
            "action": action.value,
            "resource_type": resource_type.value,
            "resource_id": resource_id,
            "reason": decision.reason,
            "enforced": settings.abac_enforce,
        }
        if settings.abac_enforce:
            logger.warning("abac_denied", extra=log_fields)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied by policy",
            )
        logger.warning("abac_denied_advisory", extra=log_fields)
        return auth

    return _dependency


__all__ = ["require_access"]
