"""Immutable-audit writes for governance decisions (WP D).

A single thin helper that appends one row to the append-only ``audit_logs``
table (RLS + DB triggers forbid UPDATE/DELETE — see migration
``002_rls_and_audit_immutable``). It is deliberately tiny and side-effect-only:
it ``session.add``\\ s the row and flushes, leaving the ``commit`` to the caller
so the audit entry lands in the *same* transaction as the decision it records.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import AuditLog

__all__ = ["record_decision_audit"]


async def record_decision_audit(
    session: AsyncSession,
    *,
    tenant_id: str,
    user_id: str | None,
    action: str,
    resource_type: str,
    resource_id: str,
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
) -> None:
    """Append one immutable audit row describing a governance decision.

    Flushes but does not commit — the caller owns the transaction so the audit
    entry is atomic with the state change it attests to.
    """
    session.add(
        AuditLog(
            tenant_id=tenant_id,
            # ``user_id`` is a free-form varchar(36) here (no FK); the operator
            # subject can be a non-UUID sentinel ("admin_api"), so truncate.
            user_id=(user_id or None) and str(user_id)[:36],
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id)[:36],
            details=details,
            ip_address=ip_address,
        )
    )
    await session.flush()
