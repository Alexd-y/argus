"""Admin findings query API — GET /admin/findings (T24).

Cross-tenant triage console for super-admin operators; tenant-scoped read for
admin/operator roles. Read-only — no DB ``audit_logs`` row is written for the
query itself (matches ``GET /admin/audit-logs`` precedent). A structured log
event with a sha256 fingerprint of the normalized query parameters is emitted
for forensic correlation; raw tenant / user identifiers never appear in the log
record (sustained PII deny-list).

Operator attribution
--------------------
``user_id_hash`` in the audit log is derived from ``X-Operator-Subject``
(via :func:`src.api.routers.admin_bulk_ops._operator_subject_dep`) so SIEM
analytics see the operator identity for every query — including super-admin
cross-tenant reads where ``role_tenant`` is ``None``. ``role_tenant_hash`` is
emitted as a separate field so super-admin queries against a specific tenant
remain linkable to the privileged role's session context.

Reserved query params
---------------------
``kev_listed`` and ``ssvc_action`` are declared (``deprecated=True`` in
OpenAPI) but DO NOT filter results: the underlying intel JOIN tables are not
yet on ``Finding`` (Phase 2). Setting them is a no-op — the handler emits a
``argus.admin.findings_query.reserved_param_ignored`` warning so downstream
clients (T20 frontend) cannot silently assume filtering works.

RBAC propagation
----------------
This module introduces a header-based role propagation pattern that overlays
the existing ``X-Admin-Key`` gate (``require_admin``):

* ``X-Admin-Role`` — one of ``operator`` | ``admin`` | ``super-admin``.
  When omitted, the caller is treated as ``super-admin`` so legacy admin
  tooling (which already issues cross-tenant queries against
  ``/admin/audit-logs`` etc.) keeps working without a behaviour change.
* ``X-Admin-Tenant`` — UUID of the tenant context the role belongs to.
  Required for ``admin`` / ``operator`` roles; ignored for ``super-admin``.

Enforcement matrix
------------------
* ``super-admin``: ``tenant_id`` query param optional. If absent → cross-tenant
  view (no ``set_session_tenant`` call, no tenant ``WHERE`` clause). If
  present → scoped via ``set_session_tenant(tenant_id)`` (RLS).
* ``admin`` / ``operator``: ``tenant_id`` query param REQUIRED and MUST equal
  ``X-Admin-Tenant``. Mismatch → 403. Header missing → 403.
* Any other role → 403.

SQL safety
----------
All filters use SQLAlchemy ORM with bound parameters (no f-strings or string
concatenation in SQL). Free-text search escapes ``%``, ``_``, and backslash for
the ``ESCAPE '\\'`` ``ILIKE`` form, mirroring ``admin._escape_ilike_pattern``.

Ordering
--------
Severity priority (Critical > High > Medium > Low > Info) → CVSS DESC NULLS
LAST → ``false_positive`` ASC (real findings first) → ``created_at`` DESC →
``id`` ASC (deterministic tiebreak). The Finding ORM model does not store
``ssvc_decision`` / ``kev_listed`` / ``epss_score`` (they live in dedicated
intel tables joined at report-render time per ARG-044), so severity is used as
the proxy for SSVC outcome priority in the SQL ORDER BY. Future migration may
denormalize these onto ``findings`` and extend the CASE expression.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Query, status
from sqlalchemy import String, case, cast, func, or_, select
from sqlalchemy.sql.elements import ColumnElement

from src.api.routers.admin import _escape_ilike_pattern, require_admin, router
from src.api.routers.admin_bulk_ops import _operator_subject_dep
from src.api.schemas import (
    AdminFindingsListResponse,
    AdminFindingSummary,
)
from src.core.datetime_format import format_created_at_iso_z
from src.core.observability import tenant_hash, user_id_hash
from src.db.models import Finding as FindingModel
from src.db.session import async_session_factory, set_session_tenant

logger = logging.getLogger(__name__)

_ALLOWED_ROLES: frozenset[str] = frozenset({"operator", "admin", "super-admin"})
_TENANT_SCOPED_ROLES: frozenset[str] = frozenset({"operator", "admin"})

_RESERVED_PARAM_DESCRIPTION: str = (
    "Reserved; no-op until Phase 2 (intel-table JOIN). "
    "Filter ignored if set; usage is logged for forensic correlation."
)

_SEVERITY_PRIORITY: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def _normalize_role(raw: str | None) -> str:
    """Return canonical role string. Default to ``super-admin`` when header missing.

    The default keeps the pre-existing behaviour where ``X-Admin-Key`` callers
    perform cross-tenant reads (e.g. ``GET /admin/audit-logs``). Explicitly
    sending ``X-Admin-Role: admin`` opts into the stricter tenant-scoped path.
    """
    if raw is None or not raw.strip():
        return "super-admin"
    candidate = raw.strip().lower()
    if candidate in {"super-admin", "super_admin", "superadmin"}:
        return "super-admin"
    return candidate


async def _admin_role_dep(
    x_admin_role: str | None = Header(default=None, alias="X-Admin-Role"),
) -> str:
    """Resolve and validate the admin role header. 403 on unknown values."""
    role = _normalize_role(x_admin_role)
    if role not in _ALLOWED_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: unknown admin role",
        )
    return role


async def _admin_tenant_dep(
    x_admin_tenant: str | None = Header(default=None, alias="X-Admin-Tenant"),
) -> str | None:
    """Return the role's tenant context UUID (validated) or ``None`` when absent."""
    if x_admin_tenant is None or not x_admin_tenant.strip():
        return None
    candidate = x_admin_tenant.strip()
    try:
        UUID(candidate)
    except (ValueError, AttributeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: invalid X-Admin-Tenant",
        ) from exc
    return candidate


def _enforce_rbac(
    *,
    role: str,
    role_tenant: str | None,
    query_tenant: str | None,
) -> str | None:
    """Return the resolved tenant filter for the SQL query, or ``None`` for cross-tenant.

    Raises ``HTTPException(403)`` when the role/tenant combination is forbidden.
    """
    if role == "super-admin":
        return query_tenant
    if role in _TENANT_SCOPED_ROLES:
        if not query_tenant:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: tenant_id is required for this role",
            )
        if not role_tenant:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: X-Admin-Tenant header is required for this role",
            )
        if role_tenant != query_tenant:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: tenant mismatch",
            )
        return query_tenant
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Forbidden",
    )


def _validate_time_window(since: datetime | None, until: datetime | None) -> None:
    if since is not None and until is not None and until < since:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="until must be greater than or equal to since",
        )


def _severity_priority_case() -> ColumnElement[int]:
    """SQL CASE mapping severity strings to ordinal priority (5 = critical .. 1 = info)."""
    return case(
        _SEVERITY_PRIORITY,
        value=func.lower(FindingModel.severity),
        else_=0,
    )


def _build_filters(
    *,
    tenant_id: str | None,
    severity: list[str] | None,
    confidence: list[str] | None,
    false_positive: bool | None,
    q: str | None,
    since: datetime | None,
    until: datetime | None,
) -> list[ColumnElement[bool]]:
    filters: list[ColumnElement[bool]] = []
    if tenant_id:
        filters.append(cast(FindingModel.tenant_id, String) == tenant_id)
    if severity:
        normalized = [s.lower() for s in severity if s and s.strip()]
        if normalized:
            filters.append(func.lower(FindingModel.severity).in_(normalized))
    if confidence:
        normalized_c = [c.lower() for c in confidence if c and c.strip()]
        if normalized_c:
            filters.append(func.lower(FindingModel.confidence).in_(normalized_c))
    if false_positive is not None:
        filters.append(FindingModel.false_positive.is_(false_positive))
    if since is not None:
        filters.append(FindingModel.created_at >= since)
    if until is not None:
        filters.append(FindingModel.created_at <= until)
    if q:
        pattern = f"%{_escape_ilike_pattern(q.strip())}%"
        filters.append(
            or_(
                FindingModel.title.ilike(pattern, escape="\\"),
                FindingModel.description.ilike(pattern, escape="\\"),
            )
        )
    return filters


def _query_fingerprint(
    *,
    tenant_id: str | None,
    severity: list[str] | None,
    confidence: list[str] | None,
    false_positive: bool | None,
    q: str | None,
    since: datetime | None,
    until: datetime | None,
    limit: int,
    offset: int,
) -> str:
    """Stable 24-hex sha256 of canonicalized query params for audit correlation."""
    payload = {
        "tenant_id": tenant_hash(tenant_id) if tenant_id else None,
        "severity": sorted({s.lower() for s in (severity or []) if s}),
        "confidence": sorted({c.lower() for c in (confidence or []) if c}),
        "false_positive": false_positive,
        "q_len": len(q.strip()) if q else 0,
        "since": since.isoformat() if since else None,
        "until": until.isoformat() if until else None,
        "limit": limit,
        "offset": offset,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


def _row_to_summary(row: FindingModel) -> AdminFindingSummary:
    return AdminFindingSummary(
        id=row.id,
        tenant_id=row.tenant_id,
        scan_id=row.scan_id,
        report_id=row.report_id,
        severity=row.severity,
        title=row.title,
        description=row.description,
        cwe=row.cwe,
        cvss=row.cvss,
        owasp_category=row.owasp_category,
        confidence=row.confidence,
        dedup_status=row.dedup_status,
        false_positive=bool(row.false_positive),
        created_at=format_created_at_iso_z(row.created_at),
    )


@router.get(
    "/findings",
    response_model=AdminFindingsListResponse,
    summary="Cross-tenant finding query (admin / super-admin / operator, RBAC-scoped)",
    description=(
        "Paginated list of findings with optional filters. RBAC: ``super-admin`` "
        "may query across tenants (``tenant_id`` optional); ``admin`` and "
        "``operator`` MUST scope to their own ``X-Admin-Tenant`` (mismatch "
        "→ 403). Ordering: severity priority desc → CVSS desc nulls last → "
        "non-FP first → newest first → id."
    ),
)
async def admin_list_findings(
    tenant_id: UUID | None = Query(
        default=None,
        description="Optional tenant scope; required for non-super-admin roles",
    ),
    severity: list[str] | None = Query(
        default=None,
        description="One or more severity values (case-insensitive)",
    ),
    confidence: list[str] | None = Query(
        default=None,
        description="One or more confidence values (case-insensitive)",
    ),
    false_positive: bool | None = Query(
        default=None,
        description="Filter by false_positive flag (true / false / unset)",
    ),
    q: str | None = Query(
        default=None,
        max_length=200,
        description="Free-text search across title and description (ILIKE)",
    ),
    since: datetime | None = Query(
        default=None,
        description="Inclusive lower bound on created_at",
    ),
    until: datetime | None = Query(
        default=None,
        description="Inclusive upper bound on created_at",
    ),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0, le=100_000),
    kev_listed: bool | None = Query(
        default=None,
        deprecated=True,
        description=_RESERVED_PARAM_DESCRIPTION,
    ),
    ssvc_action: str | None = Query(
        default=None,
        deprecated=True,
        max_length=64,
        description=_RESERVED_PARAM_DESCRIPTION,
    ),
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
    operator_subject: str = Depends(_operator_subject_dep),
) -> AdminFindingsListResponse:
    """Return a paginated, RBAC-aware page of findings."""
    _validate_time_window(since, until)
    query_tid = str(tenant_id) if tenant_id is not None else None
    effective_tenant = _enforce_rbac(
        role=role,
        role_tenant=role_tenant,
        query_tenant=query_tid,
    )

    reserved_params_set: list[str] = [
        name
        for name, value in (
            ("kev_listed", kev_listed),
            ("ssvc_action", ssvc_action),
        )
        if value is not None
    ]
    if reserved_params_set:
        logger.info(
            "admin.findings_query.reserved_param_ignored",
            extra={
                "event": "argus.admin.findings_query.reserved_param_ignored",
                "params": reserved_params_set,
                "role": role,
                "tenant_hash": tenant_hash(effective_tenant) if effective_tenant else None,
                "user_id_hash": user_id_hash(operator_subject),
            },
        )

    filters = _build_filters(
        tenant_id=effective_tenant,
        severity=severity,
        confidence=confidence,
        false_positive=false_positive,
        q=q,
        since=since,
        until=until,
    )

    severity_priority = _severity_priority_case()
    list_stmt = (
        select(FindingModel)
        .where(*filters)
        .order_by(
            severity_priority.desc(),
            FindingModel.cvss.desc().nulls_last(),
            FindingModel.false_positive.asc(),
            FindingModel.created_at.desc(),
            FindingModel.id.asc(),
        )
        .offset(offset)
        .limit(limit)
    )
    count_stmt = select(func.count()).select_from(FindingModel).where(*filters)

    async with async_session_factory() as session:
        if effective_tenant is not None:
            await set_session_tenant(session, effective_tenant)
        total = int((await session.execute(count_stmt)).scalar_one())
        rows = list((await session.execute(list_stmt)).scalars().all())

    findings = [_row_to_summary(r) for r in rows]
    has_more = (offset + len(findings)) < total
    fingerprint = _query_fingerprint(
        tenant_id=effective_tenant,
        severity=severity,
        confidence=confidence,
        false_positive=false_positive,
        q=q,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )

    logger.info(
        "admin.findings_query",
        extra={
            "event": "argus.admin.findings_query",
            "role": role,
            "tenant_hash": tenant_hash(effective_tenant) if effective_tenant else None,
            "role_tenant_hash": tenant_hash(role_tenant) if role_tenant else None,
            "user_id_hash": user_id_hash(operator_subject),
            "query_fingerprint": fingerprint,
            "result_count": len(findings),
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": has_more,
            "cross_tenant": effective_tenant is None,
        },
    )

    return AdminFindingsListResponse(
        findings=findings,
        total=total,
        limit=limit,
        offset=offset,
        has_more=has_more,
    )


__all__ = ["admin_list_findings"]
