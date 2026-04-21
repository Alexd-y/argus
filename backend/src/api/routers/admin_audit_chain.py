"""Admin audit chain integrity verification — POST /admin/audit-logs/verify-chain (T25).

Re-computes the SHA-256 hash chain (see ``src.policy.audit.verify_audit_log_chain``)
across the ``audit_logs`` rows in a bounded time-window and returns an OK / DRIFT
verdict for the admin audit-viewer (T22 frontend).

Why POST (not GET)
------------------
Read-only at the database layer (no row is created or mutated). POST is used
for *semantic clarity*: the call is a side-effect-free **compute** that may
exercise non-trivial CPU on a large window, and corporate API gateways /
audit pipes treat it as a discrete admin action worth logging at the
request-method level. The body is empty (``{}``); all parameters travel as
typed query-string values consistent with the sibling list / export routes.

Operator attribution
--------------------
``user_id_hash`` in the structured log is derived from ``X-Operator-Subject``
(via :func:`src.api.routers.admin_bulk_ops._operator_subject_dep`) so SIEM
analytics see who triggered the verification — including super-admin
cross-tenant sweeps where ``role_tenant`` is ``None``.

RBAC
----
This endpoint is stricter than ``GET /admin/findings`` (T24): ``operator``
role is denied (chain verification can leak the *shape* of admin activity
across tenants and is therefore an admin-or-above privilege). Header model
matches T24:

* ``X-Admin-Role``: ``admin`` | ``super-admin`` (any other → 403)
* ``X-Admin-Tenant``: required for ``admin`` role; ignored for ``super-admin``

Time-window guard
-----------------
The maximum verification window is **90 days**. A request that violates the
cap fails fast with HTTP 400 (closed-taxonomy error string, no internals
leaked). The cap is a defence-in-depth guardrail against accidental DOS via
hour-long replays of historic audit volume; CI runs comfortably below the
2 s p95 target on the planned 10⁴-event reference dataset (linear ~1µs per
row of canonical-JSON + SHA-256 work).

SQL safety
----------
Filters travel through the existing :func:`_audit_logs_filtered_select`
helper (parameterized SQLAlchemy ORM only) and the chain-verify select
overrides ordering to ASC ``created_at`` / ``id`` — no f-strings or string
concatenation in the WHERE clause.

Hard row cap
------------
The query is capped at :data:`_AUDIT_CHAIN_MAX_ROWS` (= 100 000) rows per
request. With the 90-day window guard above, this cap is generous (typical
windows have ≪10⁴ rows) but defends against a synthetic dataset blowing
the request worker's memory.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import Body, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.routers.admin import (
    _audit_logs_filtered_select,
    _validate_audit_time_window,
    require_admin,
    router,
)
from src.api.routers.admin_bulk_ops import _operator_subject_dep
from src.api.routers.admin_findings import (
    _admin_role_dep,
    _admin_tenant_dep,
)
from src.api.schemas import AuditChainVerifyResponse
from src.core.observability import tenant_hash, user_id_hash
from src.db.models import AuditLog
from src.db.session import get_db
from src.policy.audit import verify_audit_log_chain

logger = logging.getLogger(__name__)

_CHAIN_VERIFY_ALLOWED_ROLES: frozenset[str] = frozenset({"admin", "super-admin"})
_AUDIT_CHAIN_MAX_WINDOW_DAYS: int = 90
_AUDIT_CHAIN_MAX_ROWS: int = 100_000


def _enforce_chain_verify_rbac(
    *,
    role: str,
    role_tenant: str | None,
    query_tenant: str | None,
) -> str | None:
    """Return the resolved tenant filter or raise 403 on RBAC violation.

    * ``operator`` → 403 unconditionally (chain verification is admin+).
    * ``admin`` → requires ``query_tenant`` AND ``role_tenant`` AND match.
    * ``super-admin`` → ``query_tenant`` optional (None ⇒ cross-tenant).
    """
    if role not in _CHAIN_VERIFY_ALLOWED_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: chain verification requires admin or super-admin",
        )
    if role == "super-admin":
        return query_tenant
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


def _resolve_chain_window(
    since: datetime | None,
    until: datetime | None,
) -> tuple[datetime, datetime]:
    """Resolve effective ``(since, until)`` for the verify-chain query.

    Defaults: when both bounds are absent, the implicit window is "last
    :data:`_AUDIT_CHAIN_MAX_WINDOW_DAYS` days" anchored to ``utcnow`` —
    matching the cap so operators do not need to specify timestamps for the
    common "verify recent activity" case while still bounding worker time.
    Open-ended bounds are anchored to ``utcnow`` (upper) or ``until - cap``
    (lower) consistently so the cap check below has a stable comparison.
    """
    now = datetime.now(tz=timezone.utc)
    effective_until = until if until is not None else now
    effective_since = (
        since
        if since is not None
        else effective_until - timedelta(days=_AUDIT_CHAIN_MAX_WINDOW_DAYS)
    )
    return effective_since, effective_until


def _validate_chain_window_max_days(
    effective_since: datetime,
    effective_until: datetime,
) -> None:
    """Reject windows wider than :data:`_AUDIT_CHAIN_MAX_WINDOW_DAYS` (HTTP 400).

    Operates on already-resolved bounds (see :func:`_resolve_chain_window`)
    so explicit and default windows share the same enforcement path.
    """
    span = effective_until - effective_since
    if span > timedelta(days=_AUDIT_CHAIN_MAX_WINDOW_DAYS):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Time window exceeds maximum of "
                f"{_AUDIT_CHAIN_MAX_WINDOW_DAYS} days for chain verification"
            ),
        )


def _query_fingerprint(
    *,
    tenant_id: str | None,
    since: datetime | None,
    until: datetime | None,
    event_type: str | None,
) -> str:
    """Stable 24-hex sha256 of the normalized verify-chain query for audit correlation.

    The raw ``tenant_id`` is hashed (never logged in clear) so the fingerprint
    survives log redaction while remaining join-able to the request that
    produced it.
    """
    payload = {
        "tenant_id": tenant_hash(tenant_id) if tenant_id else None,
        "since": since.isoformat() if since else None,
        "until": until.isoformat() if until else None,
        "event_type": event_type,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


@router.post(
    "/audit-logs/verify-chain",
    response_model=AuditChainVerifyResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify audit-log hash chain integrity (admin / super-admin)",
    description=(
        "Replay the SHA-256 hash chain over ``audit_logs`` rows in the requested "
        "time-window and return an OK / DRIFT verdict. RBAC: ``admin`` or "
        "``super-admin`` only (``operator`` denied). Maximum window: "
        f"{_AUDIT_CHAIN_MAX_WINDOW_DAYS} days; over-cap requests fail fast with 400."
    ),
)
async def admin_verify_audit_chain(
    _body: dict[str, Any] = Body(default_factory=dict),
    tenant_id: UUID | None = Query(
        default=None,
        description=(
            "Optional tenant scope; required for ``admin`` role, optional for "
            "``super-admin`` (omit for cross-tenant chain verification)."
        ),
    ),
    since: datetime | None = Query(
        default=None,
        description="Inclusive lower bound on ``created_at``.",
    ),
    until: datetime | None = Query(
        default=None,
        description="Inclusive upper bound on ``created_at``.",
    ),
    event_type: str | None = Query(
        default=None,
        max_length=100,
        description="Exact match for the persisted action / event type.",
    ),
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
    operator_subject: str = Depends(_operator_subject_dep),
    db: AsyncSession = Depends(get_db),
) -> AuditChainVerifyResponse:
    """Return the chain verdict for the requested audit-log time-window."""
    _validate_audit_time_window(since, until)
    effective_since, effective_until = _resolve_chain_window(since, until)
    _validate_chain_window_max_days(effective_since, effective_until)

    query_tid = str(tenant_id) if tenant_id is not None else None
    effective_tenant = _enforce_chain_verify_rbac(
        role=role,
        role_tenant=role_tenant,
        query_tenant=query_tid,
    )

    base_stmt = _audit_logs_filtered_select(
        tenant_id=effective_tenant,
        search=None,
        since=effective_since,
        until=effective_until,
        event_type=event_type,
    )
    chain_stmt = (
        base_stmt.order_by(None)
        .order_by(AuditLog.created_at.asc(), AuditLog.id.asc())
        .limit(_AUDIT_CHAIN_MAX_ROWS)
    )

    result = await db.execute(chain_stmt)
    rows = list(result.scalars().all())
    verdict = verify_audit_log_chain(rows)

    fingerprint = _query_fingerprint(
        tenant_id=effective_tenant,
        since=since,
        until=until,
        event_type=event_type,
    )

    logger.info(
        "admin.audit_chain_verify",
        extra={
            "event": "argus.admin.audit_chain_verify",
            "role": role,
            "tenant_hash": tenant_hash(effective_tenant) if effective_tenant else None,
            "role_tenant_hash": tenant_hash(role_tenant) if role_tenant else None,
            "user_id_hash": user_id_hash(operator_subject),
            "query_fingerprint": fingerprint,
            "ok": verdict.ok,
            "verified_count": verdict.verified_count,
            "last_verified_index": verdict.last_verified_index,
            "cross_tenant": effective_tenant is None,
        },
    )

    return AuditChainVerifyResponse(
        ok=verdict.ok,
        verified_count=verdict.verified_count,
        last_verified_index=verdict.last_verified_index,
        drift_event_id=verdict.drift_event_id,
        drift_detected_at=verdict.drift_detected_at,
    )


__all__ = ["admin_verify_audit_chain"]
