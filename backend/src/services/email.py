"""Async email service for admin password resets (Gmail SMTP / generic).

Uses aiosmtplib for non-blocking send. When ``SMTP_HOST`` is empty or
``SMTP_USER`` is empty, :func:`send_reset_email` returns ``None`` (email
disabled) and the caller should return 503.
"""

from __future__ import annotations

import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from urllib.parse import urljoin

from aiosmtplib import SMTP

from src.core.config import settings

logger = logging.getLogger(__name__)

_RESET_PATH = "/admin/login/confirm-reset"


def _build_reset_url(base_url: str, token: str) -> str:
    path = f"{_RESET_PATH}?token={token}"
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _render_reset_html(reset_url: str, otp_code: str) -> str:
    return (
        "<!DOCTYPE html>\n"
        "<html><head><meta charset='utf-8'></head>\n"
        "<body style='font-family:sans-serif;max-width:600px;margin:0 auto;padding:20px'>\n"
        "<h2 style='color:#1a1a2e'>ARGUS — Password Reset</h2>\n"
        "<p>You requested a password reset for your ARGUS admin account.</p>\n"
        "<p>Click the link below to set a new password (or copy it to your browser):</p>\n"
        f"<p><a href='{reset_url}' style='display:inline-block;padding:12px 24px;"
        "background:#4f46e5;color:#fff;text-decoration:none;border-radius:6px'>"
        "Reset Password</a></p>\n"
        f"<p style='margin-top:16px'>Or enter this OTP code on the confirmation page:"
        f" <strong style='font-size:1.2em;letter-spacing:0.15em'>{otp_code}</strong></p>\n"
        "<hr style='border:none;border-top:1px solid #eee;margin:20px 0'>\n"
        "<p style='color:#666;font-size:0.85em'>"
        "This link expires in {ttl} minutes. If you did not request this reset, "
        "ignore this email — your password remains unchanged.</p>\n"
        "</body></html>"
    )


def _render_reset_text(reset_url: str, otp_code: str) -> str:
    return (
        "ARGUS — Password Reset\n\n"
        "You requested a password reset for your ARGUS admin account.\n\n"
        f"Reset link: {reset_url}\n\n"
        f"OTP code: {otp_code}\n\n"
        "This link expires in {ttl} minutes. If you did not request this reset, "
        "ignore this email — your password remains unchanged.\n"
    )


async def send_reset_email(
    to_address: str,
    token: str,
    otp_code: str,
    base_url: str,
) -> bool:
    """Send a password-reset email with a link + OTP code.

    Returns ``True`` if the email was accepted by the SMTP server.
    Returns ``False`` if SMTP is not configured (empty host/password).
    Raises :class:`aiosmtplib.SMTPException` on transient failures.
    """
    if not settings.smtp_host or not settings.smtp_user or not settings.smtp_password:
        logger.warning("SMTP not configured — password-reset email skipped")
        return False

    reset_url = _build_reset_url(base_url, token)
    ttl = settings.admin_reset_token_ttl_minutes
    html_body = _render_reset_html(reset_url, otp_code).replace("{ttl}", str(ttl))
    text_body = _render_reset_text(reset_url, otp_code).replace("{ttl}", str(ttl))

    from_addr = settings.smtp_from or settings.smtp_user

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "ARGUS — Password Reset"
    msg["From"] = from_addr
    msg["To"] = to_address
    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    smtp = SMTP(
        hostname=settings.smtp_host,
        port=settings.smtp_port,
        use_tls=settings.smtp_use_tls,
    )

    try:
        await smtp.connect()
        if not settings.smtp_use_tls:
            await smtp.starttls()
        await smtp.login(settings.smtp_user, settings.smtp_password)
        await smtp.send_message(msg)
        logger.info("Password-reset email sent to %s", to_address)
        return True
    except Exception:
        logger.exception("Failed to send password-reset email to %s", to_address)
        raise
    finally:
        try:
            await smtp.quit()
        except Exception:
            pass
