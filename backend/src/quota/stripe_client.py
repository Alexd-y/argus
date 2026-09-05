"""Stripe integration for scan-credit purchase (Block 4.6c).

No SDK dependency: Checkout Sessions are created via the Stripe REST API with
httpx, and webhook signatures are verified manually per Stripe's scheme
(``Stripe-Signature: t=<ts>,v1=<hmac>``). Gated on ``settings.stripe_secret_key``
— when unset, checkout returns ``None`` so the caller can serve a stub.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time

import httpx

from src.core.config import settings

logger = logging.getLogger(__name__)

_CHECKOUT_ENDPOINT = "https://api.stripe.com/v1/checkout/sessions"
_TIMEOUT = 15.0
_DEFAULT_TOLERANCE = 300  # seconds


def stripe_enabled() -> bool:
    return bool(settings.stripe_secret_key and settings.stripe_extra_scan_price_id)


async def create_checkout_session(
    *,
    tenant_id: str,
    tier: str,
    quantity: int,
    success_url: str,
    cancel_url: str,
) -> str | None:
    """Create a Stripe Checkout Session for ``quantity`` extra scans.

    Returns the hosted checkout URL, or ``None`` when Stripe is not configured
    (caller serves a stub) or the API call fails. Never raises.
    """
    if not stripe_enabled():
        logger.info("stripe_disabled", extra={"event": "stripe_disabled"})
        return None
    quantity = max(1, min(quantity, 3))
    # Stripe expects application/x-www-form-urlencoded with bracket notation.
    form = {
        "mode": "payment",
        "success_url": success_url,
        "cancel_url": cancel_url,
        "line_items[0][price]": settings.stripe_extra_scan_price_id,
        "line_items[0][quantity]": str(quantity),
        "metadata[tenant_id]": tenant_id,
        "metadata[tier]": tier,
        "metadata[quantity]": str(quantity),
    }
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                _CHECKOUT_ENDPOINT,
                data=form,
                headers={"Authorization": f"Bearer {settings.stripe_secret_key}"},
            )
    except httpx.HTTPError as exc:
        logger.warning("stripe_checkout_failed", extra={"error": str(exc)})
        return None
    if resp.status_code >= 400:
        logger.warning("stripe_checkout_rejected", extra={"status_code": resp.status_code})
        return None
    url = resp.json().get("url")
    return str(url) if url else None


def verify_webhook_signature(
    payload: bytes,
    sig_header: str,
    secret: str,
    *,
    tolerance: int = _DEFAULT_TOLERANCE,
    now: int | None = None,
) -> bool:
    """Verify a Stripe webhook signature (``t=..,v1=..``) with HMAC-SHA256.

    Enforces the timestamp tolerance to reject replays. Uses constant-time
    comparison. Returns False on any malformed input (never raises).
    """
    if not secret or not sig_header or not payload:
        return False
    parts: dict[str, list[str]] = {}
    for item in sig_header.split(","):
        key, _, value = item.strip().partition("=")
        if key and value:
            parts.setdefault(key, []).append(value)
    timestamps = parts.get("t")
    signatures = parts.get("v1")
    if not timestamps or not signatures:
        return False
    try:
        ts = int(timestamps[0])
    except (ValueError, TypeError):
        return False
    current = now if now is not None else int(time.time())
    if abs(current - ts) > tolerance:
        return False
    signed_payload = f"{ts}.".encode() + payload
    expected = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, candidate) for candidate in signatures)


__all__ = ["create_checkout_session", "stripe_enabled", "verify_webhook_signature"]
