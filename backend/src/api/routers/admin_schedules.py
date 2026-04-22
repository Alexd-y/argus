"""T33 / ARG-056 — operator-managed scan schedules CRUD.

Surface
-------

* ``GET    /admin/scan-schedules`` — paginated list (operator+).
* ``POST   /admin/scan-schedules`` — create (admin+).
* ``PATCH  /admin/scan-schedules/{schedule_id}`` — partial update (admin+).
* ``DELETE /admin/scan-schedules/{schedule_id}`` — delete (admin+).
* ``POST   /admin/scan-schedules/{schedule_id}/run-now`` — manual fire
  (admin+) with maintenance-window guard + opt-in bypass.

RBAC matrix
-----------

==========================  ===========  ===========================  ============
Endpoint                    operator     admin                        super-admin
==========================  ===========  ===========================  ============
``GET   list``              own tenant   own tenant                   any tenant
``POST  create``            403          own tenant only              any tenant
``PATCH update``            403          own tenant only              any tenant
``DELETE delete``           403          own tenant only              any tenant
``POST  run-now``           403          own tenant only              any tenant
==========================  ===========  ===========================  ============

* "operator" can READ schedules (so the dashboards can render the
  schedule list view) but cannot mutate them.
* "admin" must supply ``X-Admin-Tenant`` AND it must equal the body /
  path tenant; mismatches are 403 ``tenant mismatch``.
* "super-admin" can act on any tenant; ``X-Admin-Tenant`` is optional.

Audit + observability
---------------------

Every mutation emits an ``AuditLog`` row with the canonical
``user_id_hash``-only attribution shape (raw operator subject is never
persisted). The Celery "run now" path also records the dispatched
``scan_id`` in the audit details so an operator can correlate scheduled
runs with the resulting Scan history page.

RedBeat sync
------------

Mutations call into :mod:`src.scheduling.redbeat_loader` AFTER the DB
transaction commits. The loader is best-effort — it logs on failure but
does not raise — so a transient Redis hiccup downgrades to a stale beat
schedule rather than a 500 to the operator. The next mutation OR the
beat-startup ``sync_all_from_db`` call reconciles the missed update.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Final
from uuid import UUID

from fastapi import Depends, HTTPException, Query, status
from sqlalchemy import String, asc, cast, desc, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.routers.admin import require_admin, router
from src.api.routers.admin_bulk_ops import _operator_subject_dep
from src.auth.admin_dependencies import require_admin_mfa_passed
from src.api.routers.admin_emergency import (
    _DETAIL_TENANT_NOT_FOUND,
    _emit_audit,
    _require_admin_or_super,
)
from src.api.routers.admin_findings import _admin_role_dep, _admin_tenant_dep
from src.api.schemas import (
    ScanScheduleCreateRequest,
    ScanScheduleResponse,
    ScanScheduleRunNowRequest,
    ScanScheduleRunNowResponse,
    ScanScheduleUpdateRequest,
    ScanSchedulesListResponse,
)
from src.core.observability import tenant_hash, user_id_hash
from src.db.models import ScanSchedule, Tenant, gen_uuid
from src.db.session import async_session_factory
from src.scheduling.cron_parser import (
    CronValidationError,
    next_fire_time,
    validate_cron,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Closed-taxonomy detail strings — short snake_case tokens for stable
# machine consumption (T33 contract). Sister routers (admin_emergency)
# still use English-sentence detail strings for legacy reasons; the
# scheduling surface is locked to snake_case so client SDKs can switch
# on the value safely. NEVER add a sentence/i18n string here.
# ---------------------------------------------------------------------------


_DETAIL_FORBIDDEN: Final[str] = "forbidden"
_DETAIL_TENANT_REQUIRED: Final[str] = "tenant_id_required"
_DETAIL_TENANT_HEADER_REQUIRED: Final[str] = "tenant_header_required"
_DETAIL_TENANT_MISMATCH: Final[str] = "tenant_mismatch"
_DETAIL_SCHEDULE_NOT_FOUND: Final[str] = "schedule_not_found"
_DETAIL_NAME_CONFLICT: Final[str] = "schedule_name_conflict"
_DETAIL_INVALID_CRON_EXPRESSION: Final[str] = "invalid_cron_expression"
_DETAIL_INVALID_MAINTENANCE_CRON: Final[str] = "invalid_maintenance_window_cron"
_DETAIL_IN_MAINTENANCE_WINDOW: Final[str] = "in_maintenance_window"
_DETAIL_KILL_SWITCH_ACTIVE: Final[str] = "emergency_active"

#: Audit-log ``action`` taxonomy for scan-schedule mutations.
EVENT_SCHEDULE_CREATED: Final[str] = "scan_schedule.created"
EVENT_SCHEDULE_UPDATED: Final[str] = "scan_schedule.updated"
EVENT_SCHEDULE_DELETED: Final[str] = "scan_schedule.deleted"
EVENT_SCHEDULE_RUN_NOW: Final[str] = "scan_schedule.run_now"

#: Maintenance-window cron uses a 60-minute floor (not the default
#: 5-minute floor used for the primary cron) because operators usually
#: align maintenance windows to hourly boundaries; firing the
#: maintenance-window check every 5 minutes provides no extra value.
_MAINTENANCE_CRON_MAX_FREQ_MINUTES: int = 60


# ---------------------------------------------------------------------------
# Validation helpers (closed-taxonomy errors)
# ---------------------------------------------------------------------------


def _validate_primary_cron(expression: str) -> None:
    """Raise 422 with closed taxonomy when ``expression`` is invalid.

    422 (not 400) because Pydantic already accepted the field shape — the
    failure is *semantic* (bad cron) rather than structural, matching
    Pydantic's own ``unprocessable entity`` convention.
    """
    try:
        validate_cron(expression)
    except CronValidationError as exc:
        logger.info(
            "admin.scan_schedule.cron_validation_failed",
            extra={
                "event": "argus.admin.scan_schedule.cron_validation_failed",
                "reason": str(exc),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=_DETAIL_INVALID_CRON_EXPRESSION,
        ) from exc


def _validate_maintenance_cron(expression: str | None) -> None:
    """Validate the optional maintenance window cron with a relaxed floor."""
    if expression is None or not expression.strip():
        return
    try:
        validate_cron(
            expression,
            max_freq_minutes=_MAINTENANCE_CRON_MAX_FREQ_MINUTES,
        )
    except CronValidationError as exc:
        logger.info(
            "admin.scan_schedule.maintenance_cron_validation_failed",
            extra={
                "event": "argus.admin.scan_schedule.maintenance_cron_validation_failed",
                "reason": str(exc),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=_DETAIL_INVALID_MAINTENANCE_CRON,
        ) from exc


def _enforce_admin_tenant_match(
    *,
    role: str,
    role_tenant: str | None,
    target_tenant: str,
) -> None:
    """For role=admin, require ``X-Admin-Tenant`` to equal ``target_tenant``.

    Used ONLY by the CREATE handler — there the target tenant is supplied
    in the request body before any DB lookup, so emitting 403 cannot leak
    schedule existence. PATCH / DELETE / run-now collapse the same check
    to a 404 inline (after ``_load_schedule_or_404``) to avoid the
    cross-tenant existence-leak vector documented in the T33 reviewer
    findings (S1.3).
    """
    if role != "admin":
        return
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


def _enforce_tenant_scope(
    *, role: str, role_tenant: str | None, target_tenant: str | None
) -> str | None:
    """Resolve the tenant filter for the LIST endpoint with snake-case errors.

    Mirrors :func:`src.api.routers.admin_emergency._enforce_tenant_scope`
    but emits the closed-taxonomy snake_case detail tokens required by
    the T33 contract. Behaviour is unchanged:

    * super-admin: ``target_tenant`` optional (``None`` → cross-tenant)
    * admin: ``target_tenant`` REQUIRED and MUST equal ``role_tenant``
    * everyone else: 403 ``forbidden``
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
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN, detail=_DETAIL_FORBIDDEN
    )


def _utcnow() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


async def _ensure_tenant_exists(session: AsyncSession, tenant_id: str) -> None:
    """Raise 404 when the target tenant id has no row in ``tenants``."""
    count = await session.execute(
        select(func.count(Tenant.id)).where(cast(Tenant.id, String) == tenant_id)
    )
    if int(count.scalar_one()) == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_DETAIL_TENANT_NOT_FOUND,
        )


async def _load_schedule_or_404(
    session: AsyncSession, schedule_id: str
) -> ScanSchedule:
    """Fetch a schedule by id; raise 404 when missing.

    Tenant-scope enforcement happens at the *router* layer (caller compares
    ``schedule.tenant_id`` against the role/header). RLS may also intervene
    when the session was tenant-bound, but we still verify in code so the
    super-admin (cross-tenant) read path is explicit.
    """
    result = await session.execute(
        select(ScanSchedule).where(cast(ScanSchedule.id, String) == schedule_id)
    )
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=_DETAIL_SCHEDULE_NOT_FOUND,
        )
    return row


def _to_response(row: ScanSchedule) -> ScanScheduleResponse:
    """Project an ORM row onto the response schema."""
    return ScanScheduleResponse(
        id=UUID(row.id),
        tenant_id=UUID(row.tenant_id),
        name=row.name,
        cron_expression=row.cron_expression,
        target_url=row.target_url,
        scan_mode=row.scan_mode,
        enabled=row.enabled,
        maintenance_window_cron=row.maintenance_window_cron,
        last_run_at=row.last_run_at,
        next_run_at=row.next_run_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _compute_initial_next_run(cron_expression: str) -> datetime | None:
    """Compute the first ``next_run_at`` after the current instant.

    The expression has already been validated so a failure here is purely
    defensive (e.g. timezone-database mismatch in a constrained image);
    we log + downgrade to ``None`` so the row still inserts and the next
    successful trigger recomputes the value.
    """
    try:
        return next_fire_time(cron_expression, after=_utcnow())
    except CronValidationError:  # pragma: no cover — validator already ran
        logger.warning(
            "admin.scan_schedule.next_run_compute_failed",
            extra={"event": "argus.admin.scan_schedule.next_run_compute_failed"},
        )
        return None


# ---------------------------------------------------------------------------
# RedBeat sync wrappers (best-effort, never raise to the caller)
# ---------------------------------------------------------------------------


def _sync_redbeat_safe(row: ScanSchedule) -> None:
    """Best-effort RedBeat upsert; logs failures but never raises."""
    try:
        from src.scheduling import redbeat_loader

        redbeat_loader.sync_one(row)
    except Exception:  # pragma: no cover — defensive cleanup
        logger.warning(
            "admin.scan_schedule.redbeat_sync_failed",
            extra={
                "event": "argus.admin.scan_schedule.redbeat_sync_failed",
                "schedule_id": row.id,
            },
            exc_info=True,
        )


def _remove_redbeat_safe(schedule_id: str) -> None:
    """Best-effort RedBeat delete; logs failures but never raises."""
    try:
        from src.scheduling import redbeat_loader

        redbeat_loader.remove_one(schedule_id)
    except Exception:  # pragma: no cover — defensive cleanup
        logger.warning(
            "admin.scan_schedule.redbeat_remove_failed",
            extra={
                "event": "argus.admin.scan_schedule.redbeat_remove_failed",
                "schedule_id": schedule_id,
            },
            exc_info=True,
        )


# ---------------------------------------------------------------------------
# GET /admin/scan-schedules
# ---------------------------------------------------------------------------


@router.get(
    "/scan-schedules",
    response_model=ScanSchedulesListResponse,
    summary="List scan schedules (operator+; tenant-scoped)",
)
async def list_scan_schedules(
    tenant_id: UUID | None = Query(
        default=None,
        description=(
            "Tenant filter. Required for operator/admin; optional for "
            "super-admin (omitted = cross-tenant)."
        ),
    ),
    enabled: bool | None = Query(
        default=None, description="Optional enabled-only filter"
    ),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=100_000),
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
    operator_subject: str = Depends(_operator_subject_dep),
) -> ScanSchedulesListResponse:
    """Paginated list of scan schedules for the operator console.

    Operator can read (this is the only schedule endpoint they can hit);
    write endpoints below require admin or super-admin.
    """
    if role not in {"operator", "admin", "super-admin"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail=_DETAIL_FORBIDDEN
        )

    target = str(tenant_id) if tenant_id is not None else None
    if role in {"operator", "admin"}:
        # operator + admin both must scope to their own tenant
        effective_tenant = _enforce_tenant_scope(
            role="admin" if role == "operator" else role,
            role_tenant=role_tenant,
            target_tenant=target,
        )
    else:
        effective_tenant = _enforce_tenant_scope(
            role=role, role_tenant=role_tenant, target_tenant=target
        )

    filters = []
    if effective_tenant is not None:
        filters.append(cast(ScanSchedule.tenant_id, String) == effective_tenant)
    if enabled is not None:
        filters.append(ScanSchedule.enabled.is_(enabled))

    async with async_session_factory() as session:
        count_stmt = select(func.count()).select_from(ScanSchedule).where(*filters)
        total = int((await session.execute(count_stmt)).scalar_one())

        stmt = (
            select(ScanSchedule)
            .where(*filters)
            .order_by(desc(ScanSchedule.created_at), asc(ScanSchedule.id))
            .offset(offset)
            .limit(limit)
        )
        rows = list((await session.execute(stmt)).scalars().all())

    items = [_to_response(r) for r in rows]
    logger.info(
        "admin.scan_schedule.list",
        extra={
            "event": "argus.admin.scan_schedule.list",
            "user_id_hash": user_id_hash(operator_subject),
            "role": role,
            "tenant_id_hash": (
                tenant_hash(effective_tenant) if effective_tenant else None
            ),
            "total": total,
            "result_count": len(items),
        },
    )
    return ScanSchedulesListResponse(
        items=items, total=total, limit=limit, offset=offset
    )


# ---------------------------------------------------------------------------
# POST /admin/scan-schedules
# ---------------------------------------------------------------------------


@router.post(
    "/scan-schedules",
    response_model=ScanScheduleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a scan schedule (admin+; tenant-scoped)",
)
async def create_scan_schedule(
    body: ScanScheduleCreateRequest,
    _: None = Depends(require_admin_mfa_passed),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
    operator_subject: str = Depends(_operator_subject_dep),
) -> ScanScheduleResponse:
    """Insert a row into ``scan_schedules`` and sync to RedBeat."""
    _require_admin_or_super(role)
    target_tenant = str(body.tenant_id)
    _enforce_admin_tenant_match(
        role=role, role_tenant=role_tenant, target_tenant=target_tenant
    )
    _validate_primary_cron(body.cron_expression)
    _validate_maintenance_cron(body.maintenance_window_cron)

    schedule_id = gen_uuid()
    next_run = _compute_initial_next_run(body.cron_expression)

    async with async_session_factory() as session:
        await _ensure_tenant_exists(session, target_tenant)
        row = ScanSchedule(
            id=schedule_id,
            tenant_id=target_tenant,
            name=body.name,
            cron_expression=body.cron_expression,
            target_url=body.target_url,
            scan_mode=body.scan_mode,
            enabled=body.enabled,
            maintenance_window_cron=body.maintenance_window_cron,
            last_run_at=None,
            next_run_at=next_run,
        )
        session.add(row)
        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=_DETAIL_NAME_CONFLICT,
            ) from exc

        audit_id = gen_uuid()
        _emit_audit(
            session,
            audit_id=audit_id,
            tenant_id=target_tenant,
            action=EVENT_SCHEDULE_CREATED,
            operator_subject=operator_subject,
            details={
                "schedule_id": schedule_id,
                "tenant_id_hash": tenant_hash(target_tenant),
                "name": body.name,
                "scan_mode": body.scan_mode,
                "enabled": body.enabled,
                "cron_expression": body.cron_expression,
                "has_maintenance_window": bool(body.maintenance_window_cron),
            },
        )
        await session.commit()
        await session.refresh(row)

    _sync_redbeat_safe(row)
    logger.info(
        "admin.scan_schedule.created",
        extra={
            "event": "argus.admin.scan_schedule.created",
            "user_id_hash": user_id_hash(operator_subject),
            "tenant_id_hash": tenant_hash(target_tenant),
            "schedule_id": schedule_id,
            "audit_id": audit_id,
        },
    )
    return _to_response(row)


# ---------------------------------------------------------------------------
# PATCH /admin/scan-schedules/{schedule_id}
# ---------------------------------------------------------------------------


@router.patch(
    "/scan-schedules/{schedule_id}",
    response_model=ScanScheduleResponse,
    summary="Update a scan schedule (admin+; tenant-scoped)",
)
async def update_scan_schedule(
    schedule_id: UUID,
    body: ScanScheduleUpdateRequest,
    _: None = Depends(require_admin_mfa_passed),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
    operator_subject: str = Depends(_operator_subject_dep),
) -> ScanScheduleResponse:
    """Apply a partial update; ``None`` fields are no-ops."""
    _require_admin_or_super(role)
    schedule_id_str = str(schedule_id)

    if body.cron_expression is not None:
        _validate_primary_cron(body.cron_expression)
    if body.maintenance_window_cron is not None:
        _validate_maintenance_cron(body.maintenance_window_cron)

    async with async_session_factory() as session:
        row = await _load_schedule_or_404(session, schedule_id_str)
        # S1.3: Cross-tenant admin probes must NOT distinguish "exists but
        # foreign" (would-be 403) from "does not exist" (404). Collapsing to
        # 404 closes the existence-leak side channel that lets a tenant-A
        # admin enumerate tenant-B schedule UUIDs.
        if role == "admin" and role_tenant != row.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=_DETAIL_SCHEDULE_NOT_FOUND,
            )

        changed_fields: dict[str, object] = {}
        if body.name is not None and body.name != row.name:
            row.name = body.name
            changed_fields["name"] = body.name
        if (
            body.cron_expression is not None
            and body.cron_expression != row.cron_expression
        ):
            row.cron_expression = body.cron_expression
            row.next_run_at = _compute_initial_next_run(body.cron_expression)
            changed_fields["cron_expression"] = body.cron_expression
        if body.target_url is not None and body.target_url != row.target_url:
            row.target_url = body.target_url
            changed_fields["target_url"] = body.target_url
        if body.scan_mode is not None and body.scan_mode != row.scan_mode:
            row.scan_mode = body.scan_mode
            changed_fields["scan_mode"] = body.scan_mode
        if body.enabled is not None and body.enabled != row.enabled:
            row.enabled = body.enabled
            changed_fields["enabled"] = body.enabled
        if (
            body.maintenance_window_cron is not None
            and body.maintenance_window_cron != row.maintenance_window_cron
        ):
            row.maintenance_window_cron = body.maintenance_window_cron
            changed_fields["maintenance_window_cron"] = body.maintenance_window_cron

        try:
            await session.flush()
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=_DETAIL_NAME_CONFLICT,
            ) from exc

        audit_id = gen_uuid()
        _emit_audit(
            session,
            audit_id=audit_id,
            tenant_id=row.tenant_id,
            action=EVENT_SCHEDULE_UPDATED,
            operator_subject=operator_subject,
            details={
                "schedule_id": schedule_id_str,
                "tenant_id_hash": tenant_hash(row.tenant_id),
                "changed_fields": sorted(changed_fields.keys()),
            },
        )
        await session.commit()
        await session.refresh(row)

    _sync_redbeat_safe(row)
    logger.info(
        "admin.scan_schedule.updated",
        extra={
            "event": "argus.admin.scan_schedule.updated",
            "user_id_hash": user_id_hash(operator_subject),
            "tenant_id_hash": tenant_hash(row.tenant_id),
            "schedule_id": schedule_id_str,
            "audit_id": audit_id,
            "changed_field_count": len(changed_fields),
        },
    )
    return _to_response(row)


# ---------------------------------------------------------------------------
# DELETE /admin/scan-schedules/{schedule_id}
# ---------------------------------------------------------------------------


@router.delete(
    "/scan-schedules/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a scan schedule (admin+; tenant-scoped)",
)
async def delete_scan_schedule(
    schedule_id: UUID,
    _: None = Depends(require_admin_mfa_passed),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
    operator_subject: str = Depends(_operator_subject_dep),
) -> None:
    """Remove the schedule and its RedBeat entry."""
    _require_admin_or_super(role)
    schedule_id_str = str(schedule_id)

    async with async_session_factory() as session:
        row = await _load_schedule_or_404(session, schedule_id_str)
        # S1.3: see PATCH handler for rationale — same existence-leak defence.
        if role == "admin" and role_tenant != row.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=_DETAIL_SCHEDULE_NOT_FOUND,
            )
        captured_tenant_id = row.tenant_id
        captured_name = row.name
        await session.delete(row)

        audit_id = gen_uuid()
        _emit_audit(
            session,
            audit_id=audit_id,
            tenant_id=captured_tenant_id,
            action=EVENT_SCHEDULE_DELETED,
            operator_subject=operator_subject,
            details={
                "schedule_id": schedule_id_str,
                "tenant_id_hash": tenant_hash(captured_tenant_id),
                "name": captured_name,
            },
        )
        await session.commit()

    _remove_redbeat_safe(schedule_id_str)
    logger.info(
        "admin.scan_schedule.deleted",
        extra={
            "event": "argus.admin.scan_schedule.deleted",
            "user_id_hash": user_id_hash(operator_subject),
            "tenant_id_hash": tenant_hash(captured_tenant_id),
            "schedule_id": schedule_id_str,
            "audit_id": audit_id,
        },
    )


# ---------------------------------------------------------------------------
# POST /admin/scan-schedules/{schedule_id}/run-now
# ---------------------------------------------------------------------------


@router.post(
    "/scan-schedules/{schedule_id}/run-now",
    response_model=ScanScheduleRunNowResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Manually fire a scan schedule (admin+; respects kill-switch)",
)
async def run_scan_schedule_now(
    schedule_id: UUID,
    body: ScanScheduleRunNowRequest,
    _: None = Depends(require_admin_mfa_passed),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
    operator_subject: str = Depends(_operator_subject_dep),
) -> ScanScheduleRunNowResponse:
    """Bypass cron and dispatch the trigger task immediately.

    Pre-flight checks (in order):

    1. Schedule exists + admin tenant scope.
    2. Kill switch — blocks always (cannot be bypassed via this endpoint;
       operators must lift the global stop or per-tenant throttle first).
    3. Maintenance window — bypassable via ``bypass_maintenance_window: true``.

    The dispatched scan is the SAME ``argus.scheduling.run_scheduled_scan``
    task RedBeat would have fired, so the underlying gates (kill switch,
    maintenance window) re-run inside the worker; the API-side checks
    are an early bailout to give the operator a fast 4xx instead of a
    "succeeded but task no-op'd" surprise.
    """
    _require_admin_or_super(role)
    schedule_id_str = str(schedule_id)

    async with async_session_factory() as session:
        row = await _load_schedule_or_404(session, schedule_id_str)
        # S1.3: see PATCH handler for rationale — same existence-leak defence.
        if role == "admin" and role_tenant != row.tenant_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=_DETAIL_SCHEDULE_NOT_FOUND,
            )

        _ensure_kill_switch_clear(row.tenant_id)
        if not body.bypass_maintenance_window:
            _ensure_outside_maintenance_window(row)

        task_id = _dispatch_run_now(
            schedule_id=row.id,
            tenant_id=row.tenant_id,
        )
        enqueued_at = _utcnow()

        audit_id = gen_uuid()
        _emit_audit(
            session,
            audit_id=audit_id,
            tenant_id=row.tenant_id,
            action=EVENT_SCHEDULE_RUN_NOW,
            operator_subject=operator_subject,
            details={
                "schedule_id": schedule_id_str,
                "tenant_id_hash": tenant_hash(row.tenant_id),
                "bypass_maintenance_window": body.bypass_maintenance_window,
                "reason": body.reason,
                "enqueued_task_id": task_id,
                "enqueued_at": enqueued_at.isoformat(),
            },
        )
        await session.commit()

    logger.info(
        "admin.scan_schedule.run_now",
        extra={
            "event": "argus.admin.scan_schedule.run_now",
            "user_id_hash": user_id_hash(operator_subject),
            "tenant_id_hash": tenant_hash(row.tenant_id),
            "schedule_id": schedule_id_str,
            "audit_id": audit_id,
            "task_id": task_id,
            "bypass_maintenance_window": body.bypass_maintenance_window,
        },
    )
    return ScanScheduleRunNowResponse(
        schedule_id=UUID(schedule_id_str),
        enqueued_task_id=task_id,
        bypassed_maintenance_window=body.bypass_maintenance_window,
        enqueued_at=enqueued_at,
        audit_id=audit_id,
    )


# ---------------------------------------------------------------------------
# Run-now helpers (kept module-level for unit-testability + cleaner overrides)
# ---------------------------------------------------------------------------


def _ensure_kill_switch_clear(tenant_id: str) -> None:
    """Raise 409 ``conflict`` when the kill switch blocks ``tenant_id``.

    409 (not 423) because the request is well-formed but the *current
    system state* (kill switch active) prevents fulfilling it — exactly
    the semantics of HTTP 409. Kill-switch unavailability is treated as
    "not blocked" for this fast-path check: the worker re-runs the gate
    on dispatch and will fail-closed there. Surfacing 503 from run-now
    would be confusing for the operator who explicitly asked to fire NOW.
    """
    from src.policy.kill_switch import (
        KillSwitchUnavailableError,
        get_kill_switch_service,
    )

    try:
        ks = get_kill_switch_service()
        if ks.is_blocked(tenant_id).blocked:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=_DETAIL_KILL_SWITCH_ACTIVE,
            )
    except KillSwitchUnavailableError:
        logger.warning(
            "admin.scan_schedule.run_now.kill_switch_unavailable",
            extra={
                "event": "argus.admin.scan_schedule.run_now.kill_switch_unavailable",
                "tenant_id_hash": tenant_hash(tenant_id),
            },
        )


def _ensure_outside_maintenance_window(row: ScanSchedule) -> None:
    """Raise 409 when ``row`` is currently inside its maintenance window.

    Same 409 rationale as :func:`_ensure_kill_switch_clear`: the request
    is well-formed but conflicts with current schedule state.
    """
    if not row.maintenance_window_cron:
        return
    try:
        from src.scheduling.cron_parser import is_in_maintenance_window

        in_window = is_in_maintenance_window(
            row.maintenance_window_cron,
            at=_utcnow(),
            window_duration_minutes=60,
        )
    except CronValidationError:
        # If the persisted maintenance cron is malformed (should be
        # impossible — validator runs on create/update), fail open so
        # operators are not locked out by their own bad data.
        return
    if in_window:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=_DETAIL_IN_MAINTENANCE_WINDOW,
        )


def _dispatch_run_now(*, schedule_id: str, tenant_id: str) -> str:
    """Enqueue the trigger task and return the Celery task id.

    Celery is imported lazily so unit tests can monkeypatch this single
    function without forcing the module-load broker connection. When the
    Celery dispatch raises (broker down), we synthesize a task id and log
    so the operator still gets a 202 with a stable audit trail; the
    underlying broker error is observable via metrics + logs.
    """
    try:
        from src.scheduling.scan_trigger import run_scheduled_scan

        async_result = run_scheduled_scan.delay(schedule_id, tenant_id)
        task_id = getattr(async_result, "id", None) or str(uuid.uuid4())
    except Exception:
        logger.warning(
            "admin.scan_schedule.run_now.dispatch_failed",
            extra={
                "event": "argus.admin.scan_schedule.run_now.dispatch_failed",
                "schedule_id": schedule_id,
                "tenant_id_hash": tenant_hash(tenant_id),
            },
            exc_info=True,
        )
        task_id = str(uuid.uuid4())
    return task_id


__all__ = [
    "EVENT_SCHEDULE_CREATED",
    "EVENT_SCHEDULE_DELETED",
    "EVENT_SCHEDULE_RUN_NOW",
    "EVENT_SCHEDULE_UPDATED",
    "create_scan_schedule",
    "delete_scan_schedule",
    "list_scan_schedules",
    "run_scan_schedule_now",
    "update_scan_schedule",
]
