"""Admin emergency-stop API — POST/GET /admin/system/emergency/* (T31, ARG-052).

Operator-facing kill-switch control surface backed by
:class:`src.policy.kill_switch.KillSwitchService` (Redis JSON flags) and the
existing ``audit_logs`` table (append-only). Designed to compose with the
``PolicyEngine`` hook (see :mod:`src.policy.policy_engine`) so an active
global stop or per-tenant throttle short-circuits all subsequent tool
dispatches with a closed-taxonomy deny reason.

Surface
-------

* ``POST /system/emergency/stop_all`` — super-admin only. Sets the global
  Redis flag (no TTL) AND fans out a ``status="cancelled"`` update to every
  non-terminal scan across every tenant. Atomic per-tenant: a partial
  Postgres / Redis failure does not leave the system in an unknown state
  because the Redis flag is what the policy engine consults for FUTURE
  dispatches.
* ``POST /system/emergency/resume_all`` — super-admin only. Clears the
  global flag. Idempotent at the API layer (no flag → 409
  ``emergency_not_active``); subsequent retries with no flag fail loudly so
  operators do not assume their resume succeeded.
* ``POST /system/emergency/throttle`` — admin (own tenant) or super-admin
  (any tenant). Sets per-tenant Redis flag with TTL ``duration_minutes*60``.
* ``GET /system/emergency/status`` — admin (own tenant) or super-admin
  (cross-tenant). Snapshot of global + per-tenant active throttles.
* ``GET /system/emergency/audit-trail`` — admin (own tenant) or super-admin
  (cross-tenant). Recent emergency.* AuditLog rows projected for the T30 UI.

RBAC matrix
-----------

==========================  ===========  ===========================  ============
Endpoint                    operator     admin                        super-admin
==========================  ===========  ===========================  ============
``POST stop_all``           403          403                          allow
``POST resume_all``         403          403                          allow
``POST throttle``           403          allow (own tenant only)      allow
``GET status``              403          allow (own tenant scope)     allow
``GET audit-trail``         403          allow (own tenant filter)    allow
==========================  ===========  ===========================  ============

Audit attribution
-----------------

Operator identity is taken from ``X-Operator-Subject`` (best-effort header,
see ``admin_bulk_ops._operator_subject_dep``) and hashed via
:func:`src.core.observability.user_id_hash` BEFORE persisting (raw subject
never leaks into Redis or Postgres). ``X-Admin-Tenant`` carries the role's
session tenant context for RBAC enforcement; mismatches return 403 with
``forbidden`` detail (closed taxonomy, no internals).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Final
from uuid import UUID

from fastapi import Depends, HTTPException, Query, status
from sqlalchemy import String, cast, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.routers.admin import (
    _audit_logs_filtered_select,
    _redact_audit_details,
    require_admin,
    router,
)
from src.api.routers.admin_bulk_ops import _operator_subject_dep
from src.api.routers.admin_findings import (
    _admin_role_dep,
    _admin_tenant_dep,
)
from src.api.schemas import (
    EmergencyAuditTrailItem,
    EmergencyAuditTrailResponse,
    EmergencyGlobalStateOut,
    EmergencyResumeAllRequest,
    EmergencyResumeAllResponse,
    EmergencyStatusResponse,
    EmergencyStopAllRequest,
    EmergencyStopAllResponse,
    EmergencyTenantThrottleOut,
    EmergencyThrottleRequest,
    EmergencyThrottleResponse,
)
from src.core.config import settings
from src.core.observability import tenant_hash, user_id_hash
from src.db.models import AuditLog, Scan, Tenant, gen_uuid
from src.db.session import async_session_factory
from src.policy.kill_switch import (
    EmergencyAlreadyActiveError,
    EmergencyNotActiveError,
    GlobalEmergencyState,
    KillSwitchService,
    KillSwitchUnavailableError,
    TenantThrottleState,
    get_kill_switch_service,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Closed-taxonomy detail strings (kept short — no internals leak).
# ---------------------------------------------------------------------------


_DETAIL_FORBIDDEN: Final[str] = "forbidden"
_DETAIL_TENANT_REQUIRED: Final[str] = "tenant_id is required for this role"
_DETAIL_TENANT_HEADER_REQUIRED: Final[str] = (
    "X-Admin-Tenant header is required for this role"
)
_DETAIL_TENANT_MISMATCH: Final[str] = "tenant mismatch"
_DETAIL_TENANT_NOT_FOUND: Final[str] = "tenant not found"
_DETAIL_EMERGENCY_ACTIVE: Final[str] = "emergency_already_active"
_DETAIL_EMERGENCY_INACTIVE: Final[str] = "emergency_not_active"
_DETAIL_STORE_UNAVAILABLE: Final[str] = "emergency_store_unavailable"

#: Audit-log ``action`` taxonomy persisted by these endpoints.
EVENT_STOP_ALL: Final[str] = "emergency.stop_all"
EVENT_RESUME_ALL: Final[str] = "emergency.resume_all"
EVENT_THROTTLE: Final[str] = "emergency.throttle"

#: Mirror of admin_bulk_ops._TERMINAL_SCAN_STATUSES — kept local to avoid an
#: implicit cross-router import dependency on a private symbol.
_TERMINAL_SCAN_STATUSES: Final[frozenset[str]] = frozenset(
    {"completed", "failed", "cancelled"}
)


def _system_tenant_id() -> str:
    """Bookkeeping tenant for cross-tenant audit rows (stop_all / resume_all).

    Reuses :attr:`Settings.default_tenant_id` — seeded by Alembic migration
    ``004_seed_default_tenant.py`` so the FK ``audit_logs.tenant_id ->
    tenants.id`` is always satisfied even on a fresh DB.
    """
    return settings.default_tenant_id


# ---------------------------------------------------------------------------
# Dependency helpers
# ---------------------------------------------------------------------------


def _kill_switch_dep() -> KillSwitchService:
    """FastAPI dependency: build a :class:`KillSwitchService` per request."""
    return get_kill_switch_service()


def _require_super_admin(role: str) -> None:
    """Raise 403 unless ``role == 'super-admin'``."""
    if role != "super-admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=_DETAIL_FORBIDDEN
        )


def _require_admin_or_super(role: str) -> None:
    """Raise 403 unless role is ``admin`` or ``super-admin`` (operator → 403)."""
    if role not in {"admin", "super-admin"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=_DETAIL_FORBIDDEN
        )


def _enforce_tenant_scope(
    *, role: str, role_tenant: str | None, target_tenant: str | None
) -> str | None:
    """Resolve the tenant filter for read endpoints (status / audit-trail).

    * super-admin: ``target_tenant`` optional (None → cross-tenant).
    * admin: ``target_tenant`` REQUIRED and MUST equal ``role_tenant``.
    * operator + others: 403.
    """
    if role == "super-admin":
        return target_tenant
    if role == "admin":
        if not target_tenant:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=_DETAIL_TENANT_REQUIRED,
            )
        if not role_tenant:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=_DETAIL_TENANT_HEADER_REQUIRED,
            )
        if role_tenant != target_tenant:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=_DETAIL_TENANT_MISMATCH,
            )
        return target_tenant
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=_DETAIL_FORBIDDEN)


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _now_naive() -> datetime:
    """Postgres ``DateTime(timezone=True)`` accepts both — keep audit_logs in UTC."""
    return _utcnow()


# ---------------------------------------------------------------------------
# Cross-tenant bulk-cancel helper used by stop_all
# ---------------------------------------------------------------------------


async def _cancel_all_active_scans(db: AsyncSession) -> tuple[int, int, int]:
    """Cancel every non-terminal scan across every tenant. SQL-level update.

    Returns ``(cancelled_count, skipped_terminal_count, tenants_affected)``.

    Performs ONE bulk ``UPDATE ... RETURNING`` per call (no per-row loop, no
    separate ``SELECT count()``). The single-statement design eliminates the
    count-then-update race where a scan inserted between the two queries gets
    cancelled but is not counted, causing ``audit_logs.details.cancelled_count``
    to drift below the real cancellation cardinality. ``cancelled_count`` and
    ``tenants_affected`` are now derived from the actual returned row set in
    one round-trip.

    ``skipped_terminal_count`` is always 0 — the bulk-update path filters
    terminal scans in the WHERE clause, so they are never touched and no
    distinction is recorded between "would have skipped" vs "not selected".

    RLS is intentionally NOT engaged: this is a global super-admin action and
    the policy must span every tenant.
    """
    stmt = (
        update(Scan)
        .where(Scan.status.notin_(_TERMINAL_SCAN_STATUSES))
        .values(status="cancelled", phase="cancelled")
        .returning(Scan.id, Scan.tenant_id)
    )
    rows = (await db.execute(stmt)).all()
    cancelled_count = len(rows)
    tenants_affected = len({row.tenant_id for row in rows})
    # always 0 — bulk update path does not distinguish terminal vs non-terminal.
    return cancelled_count, 0, tenants_affected


# ---------------------------------------------------------------------------
# Audit-emit helper — keeps the canonical ``AuditLog`` schema in one place.
# ---------------------------------------------------------------------------


def _emit_audit(
    db: AsyncSession,
    *,
    audit_id: str,
    tenant_id: str,
    action: str,
    operator_subject: str,
    details: dict[str, object],
) -> None:
    """Add an ``AuditLog`` row to the session (commit handled by caller)."""
    op_hash = user_id_hash(operator_subject)
    payload: dict[str, object] = {
        "operator_user_id_hash": op_hash,
        **details,
    }
    db.add(
        AuditLog(
            id=audit_id,
            tenant_id=tenant_id,
            user_id=None,
            action=action,
            resource_type="emergency",
            resource_id=audit_id,
            details=payload,
            ip_address=None,
        )
    )


# ---------------------------------------------------------------------------
# POST /admin/system/emergency/stop_all  — super-admin only.
# ---------------------------------------------------------------------------


@router.post(
    "/system/emergency/stop_all",
    response_model=EmergencyStopAllResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Global emergency stop — super-admin only (T31)",
)
async def emergency_stop_all(
    body: EmergencyStopAllRequest,
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    operator_subject: str = Depends(_operator_subject_dep),
    kill_switch: KillSwitchService = Depends(_kill_switch_dep),
) -> EmergencyStopAllResponse:
    """Set the global Redis flag AND cancel every active scan cross-tenant.

    Order of operations:

    1. RBAC: super-admin only (admin/operator → 403).
    2. ``KillSwitchService.set_global`` — fail fast (409) if already active.
    3. Bulk cancel cross-tenant — single SQL ``UPDATE``.
    4. Audit emit ``emergency.stop_all`` row.
    5. Structured log + 202 response.
    """
    _require_super_admin(role)

    activated_at = _utcnow()
    try:
        global_state: GlobalEmergencyState = await asyncio.to_thread(
            kill_switch.set_global,
            reason=body.reason,
            operator_subject=operator_subject,
            activated_at=activated_at,
        )
    except EmergencyAlreadyActiveError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=_DETAIL_EMERGENCY_ACTIVE,
        ) from exc
    except KillSwitchUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_DETAIL_STORE_UNAVAILABLE,
        ) from exc

    try:
        async with async_session_factory() as session:
            (
                cancelled_count,
                skipped_terminal_count,
                tenants_affected,
            ) = await _cancel_all_active_scans(session)
            audit_id = gen_uuid()
            _emit_audit(
                session,
                audit_id=audit_id,
                tenant_id=_system_tenant_id(),
                action=EVENT_STOP_ALL,
                operator_subject=operator_subject,
                details={
                    "reason": body.reason,
                    "activated_at": global_state.activated_at.isoformat(),
                    "cancelled_count": cancelled_count,
                    "skipped_terminal_count": skipped_terminal_count,
                    "tenants_affected": tenants_affected,
                },
            )
            await session.commit()
    except Exception:
        # Audit / DB write failed — best-effort: clear the Redis flag so the
        # operator knows the action did not complete. Do not swallow the
        # exception (let exception handler surface 500).
        try:
            await asyncio.to_thread(kill_switch.clear_global)
        except Exception:  # pragma: no cover — defensive cleanup
            logger.warning(
                "kill_switch.global.cleanup_failed_after_audit_error",
                extra={
                    "event": "argus.kill_switch.global.cleanup_failed_after_audit_error",
                },
            )
        raise

    logger.info(
        "admin.emergency.stop_all",
        extra={
            "event": "argus.admin.emergency.stop_all",
            "user_id_hash": user_id_hash(operator_subject),
            "audit_id": audit_id,
            "cancelled_count": cancelled_count,
            "tenants_affected": tenants_affected,
            "activated_at": global_state.activated_at.isoformat(),
        },
    )

    return EmergencyStopAllResponse(
        status="stopped",
        cancelled_count=cancelled_count,
        skipped_terminal_count=skipped_terminal_count,
        tenants_affected=tenants_affected,
        activated_at=global_state.activated_at,
        audit_id=audit_id,
    )


# ---------------------------------------------------------------------------
# POST /admin/system/emergency/resume_all  — super-admin only.
# ---------------------------------------------------------------------------


@router.post(
    "/system/emergency/resume_all",
    response_model=EmergencyResumeAllResponse,
    summary="Lift global emergency stop — super-admin only (T31)",
)
async def emergency_resume_all(
    body: EmergencyResumeAllRequest,
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    operator_subject: str = Depends(_operator_subject_dep),
    kill_switch: KillSwitchService = Depends(_kill_switch_dep),
) -> EmergencyResumeAllResponse:
    """Clear the global Redis flag and emit ``emergency.resume_all`` audit row.

    Returns 409 ``emergency_not_active`` when no global stop is in effect so
    operators get a loud signal that their resume call did NOT toggle state.
    """
    _require_super_admin(role)

    try:
        await asyncio.to_thread(kill_switch.clear_global)
    except EmergencyNotActiveError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=_DETAIL_EMERGENCY_INACTIVE,
        ) from exc
    except KillSwitchUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=_DETAIL_STORE_UNAVAILABLE,
        ) from exc

    resumed_at = _utcnow()
    audit_id = gen_uuid()
    async with async_session_factory() as session:
        _emit_audit(
            session,
            audit_id=audit_id,
            tenant_id=_system_tenant_id(),
            action=EVENT_RESUME_ALL,
            operator_subject=operator_subject,
            details={
                "reason": body.reason,
                "resumed_at": resumed_at.isoformat(),
            },
        )
        await session.commit()

    logger.info(
        "admin.emergency.resume_all",
        extra={
            "event": "argus.admin.emergency.resume_all",
            "user_id_hash": user_id_hash(operator_subject),
            "audit_id": audit_id,
            "resumed_at": resumed_at.isoformat(),
        },
    )
    return EmergencyResumeAllResponse(
        status="resumed",
        resumed_at=resumed_at,
        audit_id=audit_id,
    )


# ---------------------------------------------------------------------------
# POST /admin/system/emergency/throttle  — admin (own tenant) or super-admin.
# ---------------------------------------------------------------------------


@router.post(
    "/system/emergency/throttle",
    response_model=EmergencyThrottleResponse,
    summary="Throttle a single tenant for a bounded duration (T31)",
)
async def emergency_throttle(
    body: EmergencyThrottleRequest,
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
    operator_subject: str = Depends(_operator_subject_dep),
    kill_switch: KillSwitchService = Depends(_kill_switch_dep),
) -> EmergencyThrottleResponse:
    """Set a per-tenant Redis throttle flag with TTL.

    RBAC:

    * ``operator`` → 403.
    * ``admin`` → may throttle ONLY ``role_tenant`` (mismatch → 403).
    * ``super-admin`` → any tenant.
    """
    _require_admin_or_super(role)
    target_tenant = str(body.tenant_id)

    if role == "admin":
        if not role_tenant:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=_DETAIL_TENANT_HEADER_REQUIRED,
            )
        if role_tenant != target_tenant:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=_DETAIL_TENANT_MISMATCH,
            )

    async with async_session_factory() as session:
        tenant_exists = await session.execute(
            select(func.count(Tenant.id)).where(
                cast(Tenant.id, String) == target_tenant
            )
        )
        if int(tenant_exists.scalar_one()) == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=_DETAIL_TENANT_NOT_FOUND,
            )

        duration_seconds = int(body.duration_minutes) * 60
        activated_at = _utcnow()
        try:
            throttle_state: TenantThrottleState = await asyncio.to_thread(
                kill_switch.set_tenant_throttle,
                target_tenant,
                duration_seconds=duration_seconds,
                reason=body.reason,
                operator_subject=operator_subject,
                activated_at=activated_at,
            )
        except KillSwitchUnavailableError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=_DETAIL_STORE_UNAVAILABLE,
            ) from exc

        audit_id = gen_uuid()
        _emit_audit(
            session,
            audit_id=audit_id,
            tenant_id=target_tenant,
            action=EVENT_THROTTLE,
            operator_subject=operator_subject,
            details={
                "tenant_id_hash": tenant_hash(target_tenant),
                "reason": body.reason,
                "duration_minutes": int(body.duration_minutes),
                "activated_at": throttle_state.activated_at.isoformat(),
                "expires_at": throttle_state.expires_at.isoformat(),
            },
        )
        await session.commit()

    logger.info(
        "admin.emergency.throttle",
        extra={
            "event": "argus.admin.emergency.throttle",
            "tenant_id_hash": tenant_hash(target_tenant),
            "user_id_hash": user_id_hash(operator_subject),
            "audit_id": audit_id,
            "duration_minutes": int(body.duration_minutes),
            "expires_at": throttle_state.expires_at.isoformat(),
        },
    )
    return EmergencyThrottleResponse(
        status="throttled",
        tenant_id=target_tenant,
        duration_minutes=body.duration_minutes,
        expires_at=throttle_state.expires_at,
        audit_id=audit_id,
    )


# ---------------------------------------------------------------------------
# GET /admin/system/emergency/status  — admin (scoped) or super-admin.
# ---------------------------------------------------------------------------


@router.get(
    "/system/emergency/status",
    response_model=EmergencyStatusResponse,
    summary="Current global + per-tenant emergency posture (T31)",
)
async def emergency_status(
    tenant_id: UUID | None = Query(
        default=None,
        description="Optional tenant filter; required for non-super-admin roles",
    ),
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
    operator_subject: str = Depends(_operator_subject_dep),
    kill_switch: KillSwitchService = Depends(_kill_switch_dep),
) -> EmergencyStatusResponse:
    """Snapshot the kill-switch posture for the operator status banner."""
    _require_admin_or_super(role)
    target = str(tenant_id) if tenant_id is not None else None
    effective_tenant = _enforce_tenant_scope(
        role=role, role_tenant=role_tenant, target_tenant=target
    )

    tenant_filter: list[str] | None
    if effective_tenant is not None:
        tenant_filter = [effective_tenant]
    elif role == "super-admin":
        tenant_filter = None
    else:  # pragma: no cover — _enforce_tenant_scope raises before here
        tenant_filter = []

    snapshot = await asyncio.to_thread(
        kill_switch.get_status,
        tenant_ids=tenant_filter,
    )

    global_out = EmergencyGlobalStateOut(active=False)
    if snapshot.global_state is not None:
        global_out = EmergencyGlobalStateOut(
            active=True,
            reason=snapshot.global_state.reason,
            activated_at=snapshot.global_state.activated_at,
        )

    throttles = [
        EmergencyTenantThrottleOut(
            tenant_id=t.tenant_id,
            reason=t.reason,
            activated_at=t.activated_at,
            expires_at=t.expires_at,
            duration_seconds=t.duration_seconds,
        )
        for t in snapshot.tenant_throttles
    ]

    logger.info(
        "admin.emergency.status",
        extra={
            "event": "argus.admin.emergency.status",
            "user_id_hash": user_id_hash(operator_subject),
            "role": role,
            "tenant_id_hash": (
                tenant_hash(effective_tenant) if effective_tenant else None
            ),
            "global_active": global_out.active,
            "tenant_throttles_count": len(throttles),
        },
    )

    return EmergencyStatusResponse(
        global_state=global_out,
        tenant_throttles=throttles,
        queried_at=_utcnow(),
    )


# ---------------------------------------------------------------------------
# GET /admin/system/emergency/audit-trail
# ---------------------------------------------------------------------------


_EMERGENCY_AUDIT_ACTIONS: Final[tuple[str, ...]] = (
    EVENT_STOP_ALL,
    EVENT_RESUME_ALL,
    EVENT_THROTTLE,
)


@router.get(
    "/system/emergency/audit-trail",
    response_model=EmergencyAuditTrailResponse,
    summary="Recent emergency.* audit rows for the T30 trail viewer (T31)",
)
async def emergency_audit_trail(
    tenant_id: UUID | None = Query(
        default=None,
        description="Optional tenant filter; required for non-super-admin roles",
    ),
    limit: int = Query(default=50, ge=1, le=200),
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
    operator_subject: str = Depends(_operator_subject_dep),
) -> EmergencyAuditTrailResponse:
    """Return up to ``limit`` recent ``emergency.*`` audit rows."""
    _require_admin_or_super(role)
    target = str(tenant_id) if tenant_id is not None else None
    effective_tenant = _enforce_tenant_scope(
        role=role, role_tenant=role_tenant, target_tenant=target
    )

    stmt = _audit_logs_filtered_select(
        tenant_id=effective_tenant,
        search=None,
        since=None,
        until=None,
        event_type=None,
    ).where(AuditLog.action.in_(_EMERGENCY_AUDIT_ACTIONS))
    stmt = stmt.limit(limit + 1)
    async with async_session_factory() as session:
        rows = list((await session.execute(stmt)).scalars().all())

    has_more = len(rows) > limit
    if has_more:
        rows = rows[:limit]

    items: list[EmergencyAuditTrailItem] = []
    for row in rows:
        raw_details = (
            _redact_audit_details(dict(row.details))
            if isinstance(row.details, dict)
            else None
        )
        reason: str | None = None
        op_hash: str | None = None
        if isinstance(raw_details, dict):
            raw_reason = raw_details.get("reason")
            if isinstance(raw_reason, str):
                reason = raw_reason
            raw_op = raw_details.get("operator_user_id_hash")
            if isinstance(raw_op, str):
                op_hash = raw_op
        items.append(
            EmergencyAuditTrailItem(
                audit_id=str(row.id),
                event_type=row.action,  # type: ignore[arg-type]
                tenant_id_hash=tenant_hash(str(row.tenant_id)),
                operator_subject_hash=op_hash,
                reason=reason,
                details=raw_details,
                created_at=row.created_at,
            )
        )

    logger.info(
        "admin.emergency.audit_trail",
        extra={
            "event": "argus.admin.emergency.audit_trail",
            "user_id_hash": user_id_hash(operator_subject),
            "role": role,
            "tenant_id_hash": (
                tenant_hash(effective_tenant) if effective_tenant else None
            ),
            "result_count": len(items),
            "limit": limit,
            "has_more": has_more,
        },
    )

    return EmergencyAuditTrailResponse(items=items, limit=limit, has_more=has_more)


__all__ = [
    "EVENT_RESUME_ALL",
    "EVENT_STOP_ALL",
    "EVENT_THROTTLE",
    "emergency_audit_trail",
    "emergency_resume_all",
    "emergency_status",
    "emergency_stop_all",
    "emergency_throttle",
]
