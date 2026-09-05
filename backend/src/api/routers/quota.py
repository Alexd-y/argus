"""Quota router — GET /api/v1/quota (Block 4.6).

Returns the authenticated tenant's scan quota (included + bonus, remaining,
period) in the frontend ``ScanQuota`` shape. Tier is taken from an explicit
``tier`` query param when provided, else the tenant's most recent subscription
plan, else ``free``.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import String, cast, select

from src.core.config import settings
from src.core.tenant import get_current_tenant_id
from src.db.models import Subscription
from src.db.session import async_session_factory, set_session_tenant
from src.quota.repository import get_quota_snapshot
from src.quota.service import TIER_SCANS
from src.quota.stripe_client import create_checkout_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/quota", tags=["quota"])

_VALID_TIERS = frozenset(TIER_SCANS.keys())


class QuotaResponse(BaseModel):
    """Scan quota snapshot (mirrors frontend ``ScanQuota``)."""

    included: int
    extra: int
    extraCap: int = Field(description="Max purchasable extra scans.")
    used: int
    remaining: int
    capacity: int
    periodEnd: str
    canRetest: bool
    canBuyExtra: bool


async def _resolve_tier(session, tenant_id: str, explicit: str | None) -> str:
    if explicit and explicit.lower() in _VALID_TIERS:
        return explicit.lower()
    result = await session.execute(
        select(Subscription.plan)
        .where(cast(Subscription.tenant_id, String) == tenant_id)
        .order_by(Subscription.created_at.desc())
        .limit(1)
    )
    plan = (result.scalar_one_or_none() or "").lower()
    return plan if plan in _VALID_TIERS else "free"


@router.get("", response_model=QuotaResponse)
async def get_quota(
    tier: str | None = Query(None, description="Override tier (free|standard|premium)."),
    tenant_id: str = Depends(get_current_tenant_id),
) -> QuotaResponse:
    """Return the current tenant's scan quota."""
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        resolved_tier = await _resolve_tier(session, tenant_id, tier)
        snapshot = await get_quota_snapshot(session, tenant_id, resolved_tier)
        await session.commit()
    return QuotaResponse(**snapshot)


class CheckoutRequest(BaseModel):
    """Buy-more-scans request."""

    quantity: int = Field(1, ge=1, le=3, description="Number of extra scans to purchase.")
    tier: str | None = Field(None, description="Override tier for the entitlement.")


class CheckoutResponse(BaseModel):
    """Checkout result. ``url`` redirects to Stripe; ``stubbed`` when unconfigured."""

    url: str | None = None
    stubbed: bool = False
    reason: str | None = None


def _purchase_base_url() -> str:
    return (settings.public_report_base_url or settings.vercel_frontend_url or "").rstrip("/")


@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout(
    body: CheckoutRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> CheckoutResponse:
    """Start a Stripe Checkout Session to buy extra scans.

    When Stripe is not configured, returns ``stubbed=True`` with the intended
    route/reason so the frontend can still wire the flow without a live charge.
    """
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        resolved_tier = await _resolve_tier(session, tenant_id, body.tier)
    base = _purchase_base_url()
    url = await create_checkout_session(
        tenant_id=tenant_id,
        tier=resolved_tier,
        quantity=body.quantity,
        success_url=f"{base}/?purchase=success" if base else "/?purchase=success",
        cancel_url=f"{base}/?purchase=cancel" if base else "/?purchase=cancel",
    )
    if url:
        return CheckoutResponse(url=url)
    return CheckoutResponse(stubbed=True, reason="stripe_not_configured")
