"""Async persistence for scan quotas (Block 4.6).

Bridges the pure :class:`QuotaState` logic with the ``ScanQuota`` table:
load-or-create a tenant's quota row, roll the monthly period on read, and
persist consume / bonus-grant mutations. Tenant isolation relies on the caller
passing an authenticated ``tenant_id`` (RLS also enforced at the DB layer).
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import String, cast, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import ScanQuota
from src.quota.service import QuotaState, add_one_month


def _row_to_state(row: ScanQuota) -> QuotaState:
    return QuotaState(
        tier=row.tier,
        period_start=row.period_start,
        period_end=row.period_end,
        used_this_period=row.used_this_period,
        bonus_credits=row.bonus_credits,
        bonus_used_this_period=row.bonus_used_this_period,
    )


def _apply_state(row: ScanQuota, state: QuotaState) -> None:
    row.tier = state.tier
    row.period_start = state.period_start
    row.period_end = state.period_end
    row.used_this_period = state.used_this_period
    row.bonus_credits = state.bonus_credits
    row.bonus_used_this_period = state.bonus_used_this_period


async def _load_row(session: AsyncSession, tenant_id: str) -> ScanQuota | None:
    result = await session.execute(
        select(ScanQuota).where(cast(ScanQuota.tenant_id, String) == tenant_id)
    )
    return result.scalar_one_or_none()


async def _get_or_create_row(
    session: AsyncSession, tenant_id: str, tier: str
) -> ScanQuota:
    row = await _load_row(session, tenant_id)
    now = datetime.now(UTC)
    if row is None:
        row = ScanQuota(
            tenant_id=tenant_id,
            tier=str(tier).lower(),
            period_start=now,
            period_end=add_one_month(now),
        )
        session.add(row)
        await session.flush()
        return row
    # Keep the tier in sync with the caller's current plan.
    if tier and row.tier != str(tier).lower():
        row.tier = str(tier).lower()
    # Roll the period forward if expired.
    state = _row_to_state(row)
    if state.refresh(now):
        _apply_state(row, state)
        await session.flush()
    return row


async def get_quota_snapshot(
    session: AsyncSession, tenant_id: str, tier: str
) -> dict[str, object]:
    """Return the current quota snapshot (frontend ``ScanQuota`` shape)."""
    row = await _get_or_create_row(session, tenant_id, tier)
    return _row_to_state(row).snapshot()


async def consume_scan(
    session: AsyncSession, tenant_id: str, tier: str
) -> tuple[bool, str | None]:
    """Spend one scan credit for the tenant. Returns (ok, source)."""
    row = await _get_or_create_row(session, tenant_id, tier)
    state = _row_to_state(row)
    ok, source = state.consume()
    if ok:
        _apply_state(row, state)
        await session.flush()
    return ok, source


async def add_bonus_credits(
    session: AsyncSession,
    tenant_id: str,
    tier: str,
    quantity: int,
    *,
    stripe_customer_id: str | None = None,
    stripe_subscription_id: str | None = None,
) -> dict[str, object]:
    """Grant bonus scan credits (capped) and return the updated snapshot."""
    row = await _get_or_create_row(session, tenant_id, tier)
    state = _row_to_state(row)
    state.add_bonus(quantity)
    _apply_state(row, state)
    if stripe_customer_id:
        row.stripe_customer_id = stripe_customer_id
    if stripe_subscription_id:
        row.stripe_subscription_id = stripe_subscription_id
    await session.flush()
    return _row_to_state(row).snapshot()


__all__ = [
    "add_bonus_credits",
    "consume_scan",
    "get_quota_snapshot",
]
