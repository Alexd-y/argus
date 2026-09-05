"""Stripe billing webhook — POST /api/v1/billing/webhook (Block 4.6c).

Mounted WITHOUT tenant auth (Stripe calls it): authenticity is established by
verifying the ``Stripe-Signature`` HMAC instead. On ``checkout.session.completed``
the purchased bonus scan credits are granted to the tenant recorded in the
session metadata.
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, HTTPException, Request, status

from src.core.config import settings
from src.db.session import async_session_factory, set_session_tenant
from src.quota.repository import add_bonus_credits
from src.quota.stripe_client import verify_webhook_signature

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/billing", tags=["billing"])


@router.post("/webhook")
async def stripe_webhook(request: Request) -> dict[str, bool]:
    """Handle Stripe webhook events (signature-verified)."""
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    if not verify_webhook_signature(payload, sig, settings.stripe_webhook_secret):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid signature")

    try:
        event = json.loads(payload)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="invalid payload"
        ) from None

    if event.get("type") == "checkout.session.completed":
        obj = (event.get("data") or {}).get("object") or {}
        metadata = obj.get("metadata") or {}
        tenant_id = str(metadata.get("tenant_id") or "").strip()
        tier = str(metadata.get("tier") or "free").strip().lower()
        try:
            quantity = int(metadata.get("quantity", 1))
        except (ValueError, TypeError):
            quantity = 1
        if tenant_id and quantity > 0:
            async with async_session_factory() as session:
                await set_session_tenant(session, tenant_id)
                await add_bonus_credits(
                    session,
                    tenant_id,
                    tier,
                    quantity,
                    stripe_customer_id=str(obj.get("customer") or "") or None,
                    stripe_subscription_id=str(obj.get("subscription") or "") or None,
                )
                await session.commit()
            logger.info(
                "stripe_credits_granted",
                extra={"event": "stripe_credits_granted", "quantity": quantity},
            )

    return {"received": True}
