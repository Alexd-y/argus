"""Admin bulk operations — POST /admin/scans/bulk-cancel, /admin/findings/bulk-suppress.

Bulk ID lists are capped by request schema ``max_length`` (see ``AdminBulk*Request``).

Operator attribution in audit metadata: ``X-Operator-Subject`` (see
``_operator_subject_dep``) is best-effort when the header is set; it does not
establish identity by itself. Real enforcement is ``X-Admin-Key`` plus future
session-bound identity. Callers must not treat the header as trustworthy for
compliance-critical deployments unless bound to a verified identity model.
"""

from __future__ import annotations

import hashlib
import logging

from fastapi import Depends, Header, Request, status
from sqlalchemy import String, cast, select, update

from src.api.routers.admin import router
from src.auth.admin_dependencies import require_admin_mfa_passed
from src.auth.admin_sessions import SessionPrincipal
from src.api.schemas import (
    AdminBulkFindingSuppressRequest,
    AdminBulkFindingSuppressResponse,
    AdminBulkScanCancelRequest,
    AdminBulkScanCancelResponse,
    BulkFindingSuppressItemResult,
    BulkScanCancelItemResult,
)
from src.core.observability import tenant_hash, user_id_hash
from src.db.models import AuditLog, Finding as FindingModel, Scan, gen_uuid
from src.db.session import async_session_factory, set_session_tenant

logger = logging.getLogger(__name__)

_TERMINAL_SCAN_STATUSES = frozenset({"completed", "failed", "cancelled"})


def _sorted_ids_fingerprint(ids: list[str]) -> str:
    return hashlib.sha256("|".join(sorted(ids)).encode()).hexdigest()[:24]


async def _operator_subject_dep(
    request: Request,
    x_operator_subject: str | None = Header(None, alias="X-Operator-Subject"),
) -> str:
    """Resolve the operator subject for audit attribution.

    Order of precedence (ISS-T20-003 Phase 1, B6-T08):

    1. ``request.state.admin_session`` set by :func:`require_admin` when the
       new cookie-session flow authenticates the request — this is the only
       *trustworthy* source because the subject is bound to a verified
       bcrypt + CSPRNG session row.
    2. ``X-Operator-Subject`` header — best-effort attribution kept for the
       legacy ``X-Admin-Key`` shim (``ADMIN_AUTH_MODE=cookie`` and the
       ``both``-mode fallback). Never trust the header for compliance
       decisions; the audit log captures it as "claimed", not "verified".
    3. The literal ``"admin_api"`` sentinel when no signal is available.
    """
    principal = getattr(request.state, "admin_session", None)
    if isinstance(principal, SessionPrincipal):
        return principal.subject[:256]

    if x_operator_subject and x_operator_subject.strip():
        return x_operator_subject.strip()[:256]
    return "admin_api"


@router.post(
    "/scans/bulk-cancel",
    response_model=AdminBulkScanCancelResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Bulk-cancel scans for a tenant (admin)",
)
async def admin_bulk_cancel_scans(
    body: AdminBulkScanCancelRequest,
    _: None = Depends(require_admin_mfa_passed),
    operator_subject: str = Depends(_operator_subject_dep),
) -> AdminBulkScanCancelResponse:
    """Cancel many scans in one request. Idempotent: already-terminal scans are skipped."""
    tenant_id = str(body.tenant_id)
    raw_ids = [str(x) for x in dict.fromkeys(body.scan_ids)]

    results: list[BulkScanCancelItemResult] = []
    cancelled_count = 0
    skipped_terminal_count = 0
    not_found_count = 0

    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)

        for scan_id in raw_ids:
            res = await session.execute(
                select(Scan).where(
                    cast(Scan.id, String) == scan_id,
                    cast(Scan.tenant_id, String) == tenant_id,
                )
            )
            row = res.scalar_one_or_none()
            if not row:
                not_found_count += 1
                results.append(
                    BulkScanCancelItemResult(scan_id=scan_id, status="not_found")
                )
                continue
            if row.status in _TERMINAL_SCAN_STATUSES:
                skipped_terminal_count += 1
                results.append(
                    BulkScanCancelItemResult(scan_id=scan_id, status="skipped_terminal")
                )
                continue
            await session.execute(
                update(Scan)
                .where(
                    cast(Scan.id, String) == scan_id,
                    cast(Scan.tenant_id, String) == tenant_id,
                )
                .values(status="cancelled", phase="cancelled")
            )
            cancelled_count += 1
            results.append(
                BulkScanCancelItemResult(scan_id=scan_id, status="cancelled")
            )

        audit_id = gen_uuid()
        actor_h = user_id_hash(operator_subject)
        details: dict[str, object] = {
            "operation": "bulk_scan_cancel",
            "requested_count": len(raw_ids),
            "cancelled_count": cancelled_count,
            "skipped_terminal_count": skipped_terminal_count,
            "not_found_count": not_found_count,
            "request_ids_fingerprint": _sorted_ids_fingerprint(raw_ids),
            "operator_user_id_hash": actor_h,
        }
        session.add(
            AuditLog(
                id=audit_id,
                tenant_id=tenant_id,
                user_id=None,
                action="bulk_scan_cancel",
                resource_type="bulk_operation",
                resource_id=audit_id,
                details=details,
                ip_address=None,
            )
        )
        await session.commit()

    logger.info(
        "admin.bulk_scan_cancel",
        extra={
            "event": "argus.admin.bulk_scan_cancel",
            "tenant_hash": tenant_hash(tenant_id),
            "user_id_hash": user_id_hash(operator_subject),
            "audit_id": audit_id,
            "cancelled_count": cancelled_count,
            "skipped_terminal_count": skipped_terminal_count,
            "not_found_count": not_found_count,
        },
    )

    return AdminBulkScanCancelResponse(
        cancelled_count=cancelled_count,
        skipped_terminal_count=skipped_terminal_count,
        not_found_count=not_found_count,
        audit_id=audit_id,
        results=results,
    )


@router.post(
    "/findings/bulk-suppress",
    response_model=AdminBulkFindingSuppressResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Bulk-suppress findings (false positive) for a tenant (admin)",
)
async def admin_bulk_suppress_findings(
    body: AdminBulkFindingSuppressRequest,
    _: None = Depends(require_admin_mfa_passed),
    operator_subject: str = Depends(_operator_subject_dep),
) -> AdminBulkFindingSuppressResponse:
    """Mark many findings as suppressed (false positive). Idempotent if already suppressed."""
    tenant_id = str(body.tenant_id)
    reason = body.reason.strip()

    raw_ids = [str(x) for x in dict.fromkeys(body.finding_ids)]

    results: list[BulkFindingSuppressItemResult] = []
    suppressed_count = 0
    skipped_already_suppressed_count = 0
    not_found_count = 0

    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)

        for finding_id in raw_ids:
            res = await session.execute(
                select(FindingModel).where(
                    cast(FindingModel.id, String) == finding_id,
                    cast(FindingModel.tenant_id, String) == tenant_id,
                )
            )
            row = res.scalar_one_or_none()
            if not row:
                not_found_count += 1
                results.append(
                    BulkFindingSuppressItemResult(
                        finding_id=finding_id, status="not_found"
                    )
                )
                continue
            if row.false_positive is True:
                skipped_already_suppressed_count += 1
                results.append(
                    BulkFindingSuppressItemResult(
                        finding_id=finding_id, status="skipped_already_suppressed"
                    )
                )
                continue
            await session.execute(
                update(FindingModel)
                .where(
                    cast(FindingModel.id, String) == finding_id,
                    cast(FindingModel.tenant_id, String) == tenant_id,
                )
                .values(
                    false_positive=True,
                    false_positive_reason=reason,
                    dedup_status="false_positive",
                )
            )
            suppressed_count += 1
            results.append(
                BulkFindingSuppressItemResult(
                    finding_id=finding_id, status="suppressed"
                )
            )

        audit_id = gen_uuid()
        actor_h = user_id_hash(operator_subject)
        details: dict[str, object] = {
            "operation": "bulk_finding_suppress",
            "requested_count": len(raw_ids),
            "suppressed_count": suppressed_count,
            "skipped_already_suppressed_count": skipped_already_suppressed_count,
            "not_found_count": not_found_count,
            "request_ids_fingerprint": _sorted_ids_fingerprint(raw_ids),
            "operator_user_id_hash": actor_h,
            "reason_length": len(reason),
        }
        session.add(
            AuditLog(
                id=audit_id,
                tenant_id=tenant_id,
                user_id=None,
                action="bulk_finding_suppress",
                resource_type="bulk_operation",
                resource_id=audit_id,
                details=details,
                ip_address=None,
            )
        )
        await session.commit()

    logger.info(
        "admin.bulk_finding_suppress",
        extra={
            "event": "argus.admin.bulk_finding_suppress",
            "tenant_hash": tenant_hash(tenant_id),
            "user_id_hash": user_id_hash(operator_subject),
            "audit_id": audit_id,
            "suppressed_count": suppressed_count,
            "skipped_already_suppressed_count": skipped_already_suppressed_count,
            "not_found_count": not_found_count,
        },
    )

    return AdminBulkFindingSuppressResponse(
        suppressed_count=suppressed_count,
        skipped_already_suppressed_count=skipped_already_suppressed_count,
        not_found_count=not_found_count,
        audit_id=audit_id,
        results=results,
    )


__all__ = ["admin_bulk_cancel_scans", "admin_bulk_suppress_findings"]
