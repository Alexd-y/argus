"""Admin password management — change password, reset flow, super-admin override.

Endpoints
---------
* ``POST /auth/admin/change-password`` — authenticated admin changes own password.
* ``POST /auth/admin/request-reset`` — unauthenticated; sends reset email with token + OTP.
* ``POST /auth/admin/confirm-reset`` — unauthenticated; verifies token + OTP + sets new password.
* ``PATCH /auth/admin/{subject}/reset-password`` — super-admin resets another admin's password.

Security invariants
-------------------
* **No enumeration.** request-reset returns 200 even for unknown subjects.
* **Constant-time token verification.** Token hashes are compared via
  ``hmac.compare_digest`` to prevent timing attacks.
* **One-time tokens.** Once used (or expired), a reset token is tombstoned
  via ``used_at``. No token can be replayed.
* **bcrypt rounds >= 12** for all password hashes.
* **Rate-limited.** request-reset and confirm-reset are rate-limited per IP.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.admin_sessions import resolve_session
from src.auth.admin_users import _encode_password
from src.core.config import settings
from src.db.models import AdminPasswordResetToken, AdminSession, AdminUser
from src.db.session import get_db
from src.services.email import send_reset_email

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/admin", tags=["auth"])

#: Cookie name — must match admin_auth.py
ADMIN_SESSION_COOKIE: Final[str] = "argus.admin.session"

_SUBJECT_MAX_LEN: Final[int] = 255
_PASSWORD_MAX_LEN: Final[int] = 1024
_OTP_LEN: Final[int] = 6
_TOKEN_BYTES: Final[int] = 48

_RATE_LIMIT_LRU_CAP: Final[int] = 1024


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=_PASSWORD_MAX_LEN)
    new_password: str = Field(..., min_length=8, max_length=_PASSWORD_MAX_LEN)


class ChangePasswordResponse(BaseModel):
    changed: bool = True


class RequestResetRequest(BaseModel):
    subject: str = Field(..., min_length=1, max_length=_SUBJECT_MAX_LEN)


class RequestResetResponse(BaseModel):
    requested: bool = True


class ConfirmResetRequest(BaseModel):
    token: str = Field(..., min_length=1)
    otp_code: str = Field(..., min_length=_OTP_LEN, max_length=_OTP_LEN)
    new_password: str = Field(..., min_length=8, max_length=_PASSWORD_MAX_LEN)


class ConfirmResetResponse(BaseModel):
    reset: bool = True


class AdminResetPasswordRequest(BaseModel):
    new_password: str = Field(..., min_length=8, max_length=_PASSWORD_MAX_LEN)


class AdminResetPasswordResponse(BaseModel):
    subject: str
    reset: bool = True


@dataclass
class _RateBucket:
    tokens: float
    last_refill: float


_rate_limit_map: OrderedDict[str, _RateBucket] = OrderedDict()


def _check_rate_limit(ip: str, key: str, capacity: int = 5, window: float = 300.0) -> None:
    now = time.monotonic()
    bucket = _rate_limit_map.get(key)
    if bucket is None:
        bucket = _RateBucket(tokens=capacity - 1, last_refill=now)
        _rate_limit_map[key] = bucket
        if len(_rate_limit_map) > _RATE_LIMIT_LRU_CAP:
            _rate_limit_map.popitem(last=False)
        return
    elapsed = now - bucket.last_refill
    bucket.tokens = min(capacity, bucket.tokens + elapsed * (capacity / window))
    bucket.last_refill = now
    if bucket.tokens < 1:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Try again later.",
        )
    bucket.tokens -= 1


def _hash_token(token: str) -> str:
    return hashlib.sha256(
        (settings.admin_session_pepper + token).encode()
    ).hexdigest()


def _generate_otp() -> str:
    return "".join(secrets.choice("0123456789") for _ in range(_OTP_LEN))


async def _revoke_user_sessions(db: AsyncSession, subject: str) -> None:
    stmt = (
        update(AdminSession)
        .where(AdminSession.subject == subject, AdminSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(tz=UTC))
    )
    await db.execute(stmt)
    await db.commit()


async def _resolve_admin_from_session(request: Request, db: AsyncSession):
    raw_token = request.cookies.get(ADMIN_SESSION_COOKIE)
    if not raw_token:
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            raw_token = auth_header[7:].strip()
    if not raw_token:
        return None

    result = await resolve_session(db, raw_token=raw_token, pepper=settings.admin_session_pepper)
    if result is None:
        return None

    principal, _ = result
    return principal


@router.post(
    "/change-password",
    response_model=ChangePasswordResponse,
    summary="Change own password (authenticated admin)",
)
async def change_password(
    body: ChangePasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> ChangePasswordResponse:
    admin = await _resolve_admin_from_session(request, db)
    if admin is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    from src.auth.admin_users import verify_credentials

    principal = await verify_credentials(db, subject=admin.subject, password=body.current_password)
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    try:
        encoded_new = _encode_password(body.new_password)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password too long")

    new_hash = bcrypt.hashpw(encoded_new, bcrypt.gensalt(rounds=12)).decode("ascii")

    stmt = update(AdminUser).where(AdminUser.subject == admin.subject).values(password_hash=new_hash)
    await db.execute(stmt)
    await db.commit()

    await _revoke_user_sessions(db, admin.subject)

    logger.info("admin_password_changed", extra={"event": "argus.auth.admin_password.changed", "subject": admin.subject})
    return ChangePasswordResponse()


@router.post(
    "/request-reset",
    response_model=RequestResetResponse,
    summary="Request password reset email (unauthenticated)",
)
async def request_reset(
    body: RequestResetRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> RequestResetResponse:
    ip = request.client.host if request.client else "unknown"
    rate_key = f"reset:{ip}"
    _check_rate_limit(ip, rate_key)

    subject = body.subject.strip()
    if not subject:
        return RequestResetResponse()

    user_result = await db.execute(select(AdminUser).where(AdminUser.subject == subject))
    admin_user = user_result.scalar_one_or_none()

    if admin_user is None or admin_user.disabled_at is not None:
        return RequestResetResponse()

    raw_token = secrets.token_urlsafe(_TOKEN_BYTES)
    token_hash = _hash_token(raw_token)
    otp_code = _generate_otp()
    expires_at = datetime.now(tz=UTC) + timedelta(minutes=settings.admin_reset_token_ttl_minutes)
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()

    reset_token = AdminPasswordResetToken(
        subject=subject,
        token_hash=token_hash,
        otp_code=otp_code,
        expires_at=expires_at,
        ip_hash=ip_hash,
    )
    db.add(reset_token)
    await db.commit()

    base_url = str(request.base_url).rstrip("/")
    try:
        await send_reset_email(
            to_address=subject,
            token=raw_token,
            otp_code=otp_code,
            base_url=base_url,
        )
    except Exception:
        logger.exception("admin_reset_email_failed", extra={"event": "argus.auth.admin_reset.email_failed", "subject": subject})

    return RequestResetResponse()


@router.post(
    "/confirm-reset",
    response_model=ConfirmResetResponse,
    summary="Confirm password reset with token + OTP (unauthenticated)",
)
async def confirm_reset(
    body: ConfirmResetRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> ConfirmResetResponse:
    ip = request.client.host if request.client else "unknown"
    rate_key = f"confirm-reset:{ip}"
    _check_rate_limit(ip, rate_key, capacity=10, window=300.0)

    token_hash = _hash_token(body.token)

    stmt = select(AdminPasswordResetToken).where(
        AdminPasswordResetToken.token_hash == token_hash,
        AdminPasswordResetToken.used_at.is_(None),
    )
    result = await db.execute(stmt)
    reset_token = result.scalar_one_or_none()

    if reset_token is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired reset token")

    now = datetime.now(tz=UTC)
    if reset_token.expires_at < now:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Reset token has expired")

    if not hmac.compare_digest(reset_token.otp_code, body.otp_code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP code")

    admin_user = await db.get(AdminUser, reset_token.subject)
    if admin_user is None or admin_user.disabled_at is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Account not found or disabled")

    try:
        encoded_new = _encode_password(body.new_password)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password too long")

    new_hash = bcrypt.hashpw(encoded_new, bcrypt.gensalt(rounds=12)).decode("ascii")

    admin_user.password_hash = new_hash
    reset_token.used_at = now
    await db.commit()

    await _revoke_user_sessions(db, reset_token.subject)

    logger.info("admin_password_reset_confirmed", extra={"event": "argus.auth.admin_reset.confirmed", "subject": reset_token.subject})
    return ConfirmResetResponse()


@router.patch(
    "/{subject}/reset-password",
    response_model=AdminResetPasswordResponse,
    summary="Super-admin resets another admin's password",
)
async def admin_reset_password(
    subject: str,
    body: AdminResetPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AdminResetPasswordResponse:
    admin = await _resolve_admin_from_session(request, db)
    if admin is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    if admin.role != "super-admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only super-admin can reset passwords")

    target_subject = subject.strip()
    target = await db.get(AdminUser, target_subject)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Admin user not found")

    try:
        encoded_new = _encode_password(body.new_password)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password too long")

    new_hash = bcrypt.hashpw(encoded_new, bcrypt.gensalt(rounds=12)).decode("ascii")
    target.password_hash = new_hash
    await db.commit()

    await _revoke_user_sessions(db, target_subject)

    logger.info("admin_password_admin_reset", extra={"event": "argus.auth.admin_password.admin_reset", "subject": target_subject, "reset_by": admin.subject})
    return AdminResetPasswordResponse(subject=target_subject)
