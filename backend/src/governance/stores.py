"""Async DAOs for governance + rotation persistence (WP C/D).

Thin, tenant-scoped data access over the ``engagements`` / ``approvals`` /
``llm_rotation_states`` tables. The DAOs defer all *policy* to the pure modules:

* rotation position ↔ :class:`src.llm.rotation.LLMRotation` (``state`` / ``from_state``);
* scope decisions ↔ :func:`src.governance.engagement.assert_in_scope`
  (via :func:`engagement_row_to_dataclass`);
* approval decisions ↔ :func:`src.governance.approvals.decide`.

No HTTP, no business logic beyond read/write + the fail-closed decision helper.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import ApprovalRecord, EngagementRecord, LLMRotationState
from src.governance.engagement import Engagement
from src.llm.rotation import LLMRotation

__all__ = [
    "create_engagement",
    "decide_approval",
    "engagement_row_to_dataclass",
    "enqueue_approval",
    "enqueue_approval_once",
    "get_approval",
    "get_engagement",
    "list_approvals",
    "load_rotation",
    "revoke_engagement",
    "save_rotation",
]


# ---------------------------------------------------------------- rotation (WP C)


async def _find_rotation(
    session: AsyncSession, tenant_id: str, scan_id: str | None, role: str
) -> LLMRotationState | None:
    stmt = select(LLMRotationState).where(
        LLMRotationState.tenant_id == tenant_id,
        (
            LLMRotationState.scan_id.is_(scan_id)
            if scan_id is None
            else LLMRotationState.scan_id == scan_id
        ),
        LLMRotationState.role == role,
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def save_rotation(
    session: AsyncSession,
    *,
    tenant_id: str,
    role: str,
    rotation: LLMRotation,
    scan_id: str | None = None,
) -> None:
    """Upsert the rotation cursor for ``(tenant, scan, role)``."""
    state = rotation.state()
    row = await _find_rotation(session, tenant_id, scan_id, role)
    if row is None:
        session.add(
            LLMRotationState(
                tenant_id=tenant_id,
                scan_id=scan_id,
                role=role,
                profile_ids=state["profile_ids"],
                cursor=state["cursor"],
                excluded=state["excluded"],
            )
        )
    else:
        row.profile_ids = state["profile_ids"]
        row.cursor = state["cursor"]
        row.excluded = state["excluded"]
    await session.flush()


async def load_rotation(
    session: AsyncSession, *, tenant_id: str, role: str, scan_id: str | None = None
) -> LLMRotation | None:
    """Rebuild the persisted :class:`LLMRotation`, or ``None`` if none stored."""
    row = await _find_rotation(session, tenant_id, scan_id, role)
    if row is None:
        return None
    return LLMRotation.from_state(
        {"profile_ids": row.profile_ids, "cursor": row.cursor, "excluded": row.excluded}
    )


# ------------------------------------------------------------ engagements (WP A/D)


async def create_engagement(
    session: AsyncSession,
    *,
    tenant_id: str,
    allowed_targets: list[str],
    allowed_tenants: list[str],
    allowed_actions: list[str],
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    max_rate_per_target: int | None = None,
    signature: str | None = None,
) -> EngagementRecord:
    row = EngagementRecord(
        tenant_id=tenant_id,
        allowed_targets=list(allowed_targets),
        allowed_tenants=list(allowed_tenants),
        allowed_actions=list(allowed_actions),
        window_start=window_start,
        window_end=window_end,
        max_rate_per_target=max_rate_per_target,
        signature=signature,
    )
    session.add(row)
    await session.flush()
    return row


async def get_engagement(session: AsyncSession, engagement_id: str) -> EngagementRecord | None:
    return await session.get(EngagementRecord, engagement_id)


async def revoke_engagement(session: AsyncSession, engagement_id: str) -> EngagementRecord | None:
    """Revoke (never delete) — the row stays for the audit trail."""
    row = await session.get(EngagementRecord, engagement_id)
    if row is None:
        return None
    row.revoked = True
    await session.flush()
    return row


def engagement_row_to_dataclass(row: EngagementRecord) -> Engagement:
    """Convert a DB row to the pure :class:`Engagement` for ``assert_in_scope``."""
    return Engagement(
        engagement_id=row.id,
        allowed_targets=tuple(row.allowed_targets or ()),
        allowed_tenants=tuple(row.allowed_tenants or ()),
        allowed_actions=tuple(row.allowed_actions or ()),
        window_start=row.window_start,
        window_end=row.window_end,
        max_rate_per_target=row.max_rate_per_target,
        revoked=bool(row.revoked),
    )


# -------------------------------------------------------------- approvals (WP D)


async def enqueue_approval(
    session: AsyncSession,
    *,
    tenant_id: str,
    action: str,
    target: str,
    scan_id: str | None = None,
    reason: str = "",
) -> ApprovalRecord:
    """Enqueue a human-in-the-loop approval item (status starts ``pending``)."""
    row = ApprovalRecord(
        tenant_id=tenant_id,
        scan_id=scan_id,
        action=action,
        target=target,
        reason=reason,
        status="pending",
    )
    session.add(row)
    await session.flush()
    return row


async def enqueue_approval_once(
    session: AsyncSession,
    *,
    tenant_id: str,
    action: str,
    target: str,
    scan_id: str | None = None,
    reason: str = "",
) -> ApprovalRecord:
    """Enqueue a pending approval, but only if an identical pending one is absent.

    Idempotent on ``(tenant_id, scan_id, action)`` so a resumed/retried scan does
    not pile up duplicate pending rows. Returns the existing pending row when one
    is already queued, else the newly-enqueued row.
    """
    stmt = select(ApprovalRecord).where(
        ApprovalRecord.tenant_id == tenant_id,
        ApprovalRecord.action == action,
        ApprovalRecord.status == "pending",
        (
            ApprovalRecord.scan_id.is_(scan_id)
            if scan_id is None
            else ApprovalRecord.scan_id == scan_id
        ),
    )
    existing = (await session.execute(stmt)).scalars().first()
    if existing is not None:
        return existing
    return await enqueue_approval(
        session,
        tenant_id=tenant_id,
        action=action,
        target=target,
        scan_id=scan_id,
        reason=reason,
    )


async def get_approval(session: AsyncSession, approval_id: str) -> ApprovalRecord | None:
    """Fetch a single approval by id (tenant scoping is enforced by the caller)."""
    return await session.get(ApprovalRecord, approval_id)


async def list_approvals(
    session: AsyncSession, *, tenant_id: str, status: str | None = None
) -> list[ApprovalRecord]:
    stmt = select(ApprovalRecord).where(ApprovalRecord.tenant_id == tenant_id)
    if status is not None:
        stmt = stmt.where(ApprovalRecord.status == status)
    return list((await session.execute(stmt)).scalars().all())


async def decide_approval(
    session: AsyncSession,
    *,
    approval_id: str,
    approve: bool,
    decided_by: str,
    reason: str,
) -> ApprovalRecord | None:
    """Apply an approve/deny decision (reason mandatory) via the pure gate."""
    row = await session.get(ApprovalRecord, approval_id)
    if row is None:
        return None
    if not str(reason).strip():
        raise ValueError("an approval/denial decision requires a non-empty reason")
    row.status = "approved" if approve else "denied"
    row.decided_by = decided_by
    row.decision_reason = reason
    row.decided_at = datetime.now(UTC)
    await session.flush()
    return row
