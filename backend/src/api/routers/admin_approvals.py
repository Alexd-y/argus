"""Approvals Admin API (WP D) — human-in-the-loop queue, fail-closed.

GET  /api/v1/admin/approvals                 — list approvals (?tenant_id=&status=)
POST /api/v1/admin/approvals/{id}/decide     — approve/deny with a mandatory reason

A destructive/sensitive action is enqueued as ``pending`` and is not executable
until approved. Every decision records ``decided_by`` + ``decision_reason`` on the
row **and** appends an immutable ``audit_logs`` entry in the *same* transaction.
MFA-gated; the tenant travels explicitly (no session principal under the legacy
``X-Admin-Key`` shim) and is set as the RLS tenant before any read/write.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel

from src.api.routers.admin_findings import (
    _admin_role_dep,
    _admin_tenant_dep,
    _enforce_rbac,
)
from src.auth.admin_dependencies import require_admin_mfa_passed
from src.auth.admin_sessions import SessionPrincipal
from src.db.session import async_session_factory, set_session_tenant
from src.governance import stores
from src.governance.audit import record_decision_audit

router = APIRouter(prefix="/admin/approvals", tags=["admin_approvals"])


class ApprovalDecision(BaseModel):
    tenant_id: str
    approve: bool
    reason: str


class ApprovalResponse(BaseModel):
    id: str
    tenant_id: str
    scan_id: str | None
    action: str
    target: str
    status: str
    reason: str | None
    decided_by: str | None
    decision_reason: str | None
    decided_at: datetime | None


def _to_response(row) -> ApprovalResponse:
    return ApprovalResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        scan_id=row.scan_id,
        action=row.action,
        target=row.target,
        status=row.status,
        reason=row.reason,
        decided_by=row.decided_by,
        decision_reason=row.decision_reason,
        decided_at=row.decided_at,
    )


def _require_tenant(tenant_id: str) -> str:
    try:
        uuid.UUID(str(tenant_id))
    except (ValueError, AttributeError, TypeError) as exc:
        raise HTTPException(status_code=400, detail="invalid tenant_id") from exc
    return tenant_id


async def _operator_subject(
    request: Request,
    x_operator_subject: Annotated[str | None, Header(alias="X-Operator-Subject")] = None,
) -> str:
    """Resolve the operator subject for audit attribution.

    A verified session principal (cookie/bearer flow) wins; otherwise the
    best-effort ``X-Operator-Subject`` header (legacy ``X-Admin-Key`` shim); else
    the ``"admin_api"`` sentinel. Never trusted for authz — attribution only.
    """
    principal = getattr(request.state, "admin_session", None)
    if isinstance(principal, SessionPrincipal):
        return principal.subject[:256]
    if x_operator_subject and x_operator_subject.strip():
        return x_operator_subject.strip()[:256]
    return "admin_api"


@router.get("", response_model=list[ApprovalResponse])
async def list_approvals(
    _: Annotated[None, Depends(require_admin_mfa_passed)],
    role: Annotated[str, Depends(_admin_role_dep)],
    role_tenant: Annotated[str | None, Depends(_admin_tenant_dep)],
    tenant_id: str = Query(...),
    status: str | None = None,
) -> list[ApprovalResponse]:
    tenant_id = _require_tenant(tenant_id)
    _enforce_rbac(role=role, role_tenant=role_tenant, query_tenant=tenant_id)
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        rows = await stores.list_approvals(session, tenant_id=tenant_id, status=status)
        return [_to_response(r) for r in rows]


@router.post("/{approval_id}/decide", response_model=ApprovalResponse)
async def decide_approval(
    approval_id: str,
    body: ApprovalDecision,
    _: Annotated[None, Depends(require_admin_mfa_passed)],
    operator_subject: Annotated[str, Depends(_operator_subject)],
    role: Annotated[str, Depends(_admin_role_dep)],
    role_tenant: Annotated[str | None, Depends(_admin_tenant_dep)],
) -> ApprovalResponse:
    tenant_id = _require_tenant(body.tenant_id)
    _enforce_rbac(role=role, role_tenant=role_tenant, query_tenant=tenant_id)
    if not body.reason.strip():
        raise HTTPException(status_code=400, detail="a decision reason is required")

    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        approval = await stores.get_approval(session, approval_id)
        if approval is None or approval.tenant_id != tenant_id:
            raise HTTPException(status_code=404, detail="approval not found")

        # Atomic decision — closes the TOCTOU race: a conditional UPDATE that only
        # transitions a still-``pending`` row. ``None`` means another request already
        # decided it (or it is no longer pending) → 409, with no state change / resume.
        updated = await stores.decide_approval_if_pending(
            session,
            approval_id=approval_id,
            tenant_id=tenant_id,
            approve=body.approve,
            decided_by=operator_subject,
            reason=body.reason,
        )
        if updated is None:
            raise HTTPException(status_code=409, detail="approval already decided")

        # Immutable audit — atomic with the decision (same transaction).
        await record_decision_audit(
            session,
            tenant_id=tenant_id,
            user_id=operator_subject,
            action="governance.approval.decided",
            resource_type="approval",
            resource_id=approval_id,
            details={
                "approve": body.approve,
                "status": updated.status,
                "action": updated.action,
                "target": updated.target,
                "reason": body.reason,
            },
        )

        # WP D — approving an exploitation approval drives the EXISTING resume path
        # (no second gate). The scan transition is itself atomic + conditional on
        # ``awaiting_approval`` (``approve_scan_if_awaiting``): a scan in any other
        # state is never force-transitioned and never double re-dispatched.
        resume: tuple[str, str, str, dict] | None = None
        if body.approve and updated.action == "exploitation" and updated.scan_id:
            scan = await stores.approve_scan_if_awaiting(
                session, scan_id=updated.scan_id, tenant_id=tenant_id
            )
            if scan is not None:
                resume = (
                    str(scan.id),
                    scan.tenant_id,
                    scan.target_url or "",
                    dict(scan.options or {}),
                )

        resp = _to_response(updated)
        await session.commit()

    if resume is not None:
        # Dispatch AFTER commit so the resumed task observes the approved status.
        from src.policy.scan_queue import _dispatch_scan_phase

        _dispatch_scan_phase(
            scan_id=resume[0], tenant_id=resume[1], target_url=resume[2], options=resume[3]
        )
    return resp
