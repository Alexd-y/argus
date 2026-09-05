"""Resend transactional email client (Block 4.7).

Thin async wrapper over the Resend HTTP API (https://resend.com/docs). Gated on
``settings.resend_api_key`` — when unset, sending is a logged no-op so
non-production environments never attempt delivery. Never raises: delivery
failures are logged and reported via the boolean return so callers (e.g. the
reporting phase) are never broken by email problems.
"""

from __future__ import annotations

import logging

import httpx

from src.core.config import settings
from src.notifications.email_templates import (
    purchase_confirmation_email,
    quota_low_email,
    report_ready_email,
)

logger = logging.getLogger(__name__)

_RESEND_ENDPOINT = "https://api.resend.com/emails"
_TIMEOUT = 10.0


def _report_view_url(scan_id: str) -> str:
    base = (settings.public_report_base_url or settings.vercel_frontend_url or "").rstrip("/")
    return f"{base}/scan/{scan_id}" if base else f"/scan/{scan_id}"


def _buy_url(target: str) -> str:
    base = (settings.public_report_base_url or settings.vercel_frontend_url or "").rstrip("/")
    return f"{base}/?buy=1" if base else "/?buy=1"


async def send_email(
    to: str,
    subject: str,
    html: str,
    *,
    text: str | None = None,
) -> bool:
    """Send one email via Resend. Returns True on accepted delivery.

    Returns False (no raise) when Resend is not configured or the API rejects
    the request, so callers can fire-and-forget without breaking their flow.
    """
    to = (to or "").strip()
    if not settings.resend_api_key:
        logger.info("resend_disabled", extra={"event": "resend_disabled", "reason": "no_api_key"})
        return False
    if not to or "@" not in to:
        logger.warning("resend_invalid_recipient", extra={"event": "resend_invalid_recipient"})
        return False

    payload: dict[str, object] = {
        "from": settings.resend_from_email,
        "to": [to],
        "subject": subject,
        "html": html,
    }
    if text:
        payload["text"] = text

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.post(
                _RESEND_ENDPOINT,
                headers={
                    "Authorization": f"Bearer {settings.resend_api_key}",
                    "Content-Type": "application/json",
                },
                json=payload,
            )
    except httpx.HTTPError as exc:
        logger.warning("resend_send_failed", extra={"event": "resend_send_failed", "error": str(exc)})
        return False

    if resp.status_code >= 400:
        # Never log the response body verbatim (may echo the API key context).
        logger.warning(
            "resend_send_rejected",
            extra={"event": "resend_send_rejected", "status_code": resp.status_code},
        )
        return False
    logger.info("resend_send_ok", extra={"event": "resend_send_ok", "status_code": resp.status_code})
    return True


async def notify_report_ready(*, to_email: str | None, target: str, scan_id: str) -> bool:
    """Send the 'report ready' email for a completed scan (fire-and-forget)."""
    if not to_email:
        return False
    subject, html, text = report_ready_email(target, scan_id, _report_view_url(scan_id))
    return await send_email(to_email, subject, html, text=text)


async def notify_quota_low(*, to_email: str | None, target: str, remaining: int) -> bool:
    """Send the 'quota running low' email (fire-and-forget)."""
    if not to_email:
        return False
    subject, html, text = quota_low_email(target, remaining, _buy_url(target))
    return await send_email(to_email, subject, html, text=text)


async def notify_purchase(
    *, to_email: str | None, target: str, credits: int, receipt_url: str | None = None
) -> bool:
    """Send the 'purchase confirmation' email (fire-and-forget)."""
    if not to_email:
        return False
    subject, html, text = purchase_confirmation_email(target, credits, receipt_url)
    return await send_email(to_email, subject, html, text=text)


__all__ = [
    "notify_purchase",
    "notify_quota_low",
    "notify_report_ready",
    "send_email",
]
