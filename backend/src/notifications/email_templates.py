"""Transactional email templates for customer notifications (Block 4.7).

Pure functions returning ``(subject, html, text)`` for Resend delivery. All
user-controlled values (target, addresses) are HTML-escaped to prevent
injection into the email body. No secrets or credentials are ever included.
"""

from __future__ import annotations

from html import escape

_BRAND = "Ragnarok by Svalbard Security"
_FOOTER_HTML = (
    '<hr style="border:none;border-top:1px solid #eee;margin:24px 0">'
    '<p style="color:#888;font-size:12px">'
    f"{_BRAND} — authorized testing only. "
    "You received this because a scan was requested for your address."
    "</p>"
)


def _wrap(title: str, body_html: str) -> str:
    return (
        '<div style="font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:560px;'
        'margin:0 auto;color:#1a1a1a">'
        f'<h2 style="color:#6d28d9;margin:0 0 16px">{escape(title)}</h2>'
        f"{body_html}"
        f"{_FOOTER_HTML}"
        "</div>"
    )


def report_ready_email(target: str, scan_id: str, view_url: str) -> tuple[str, str, str]:
    """Email sent when a scan report is ready to view."""
    safe_target = escape(target)
    safe_url = escape(view_url, quote=True)
    subject = f"Your security report for {target} is ready"
    html = _wrap(
        "Your report is ready",
        f'<p>The security assessment for <strong>{safe_target}</strong> has finished '
        "and your report is ready to view.</p>"
        f'<p style="margin:24px 0">'
        f'<a href="{safe_url}" style="background:#6d28d9;color:#fff;text-decoration:none;'
        'padding:10px 18px;border-radius:6px;display:inline-block">View report</a></p>'
        f'<p style="color:#888;font-size:12px">Or open: {safe_url}</p>',
    )
    text = (
        f"Your security report for {target} is ready.\n"
        f"View it here: {view_url}\n"
    )
    return subject, html, text


def quota_low_email(target: str, remaining: int, buy_url: str) -> tuple[str, str, str]:
    """Email sent when a subscriber's scan quota is running low."""
    safe_target = escape(target)
    safe_url = escape(buy_url, quote=True)
    subject = f"You have {remaining} scan(s) left"
    html = _wrap(
        "Your scan quota is running low",
        f"<p>You have <strong>{remaining}</strong> scan(s) remaining for "
        f"<strong>{safe_target}</strong> this period.</p>"
        f'<p style="margin:24px 0">'
        f'<a href="{safe_url}" style="background:#6d28d9;color:#fff;text-decoration:none;'
        'padding:10px 18px;border-radius:6px;display:inline-block">Buy more scans</a></p>',
    )
    text = f"You have {remaining} scan(s) left for {target}. Buy more: {buy_url}\n"
    return subject, html, text


def purchase_confirmation_email(
    target: str, credits: int, receipt_url: str | None = None
) -> tuple[str, str, str]:
    """Email confirming a scan-credit purchase."""
    safe_target = escape(target)
    subject = f"Purchase confirmed — {credits} scan credit(s)"
    receipt_html = (
        f'<p style="margin:24px 0"><a href="{escape(receipt_url, quote=True)}" '
        'style="color:#6d28d9">View receipt</a></p>'
        if receipt_url
        else ""
    )
    html = _wrap(
        "Purchase confirmed",
        f"<p>Thank you — <strong>{credits}</strong> scan credit(s) have been added for "
        f"<strong>{safe_target}</strong>.</p>{receipt_html}",
    )
    text = f"Purchase confirmed: {credits} scan credit(s) added for {target}.\n"
    return subject, html, text


__all__ = [
    "purchase_confirmation_email",
    "quota_low_email",
    "report_ready_email",
]
