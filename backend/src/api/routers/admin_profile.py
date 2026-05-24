"""Admin profile & session management — /auth/admin/me, sessions list, revoke.

Endpoints
---------
* ``GET /auth/admin/me`` — returns the calling admin's profile (subject, role,
  mfa_enabled, created_at). Authenticated via session cookie.
* ``GET /auth/admin/sessions`` — lists the caller's active sessions (created_at,
  last_used_at, expires_at, ip_hash prefix, user_agent_hash). Current session
  flagged.
* ``DELETE /auth/admin/sessions/{session_hash_prefix}`` — revoke a session by
  its hash prefix (first 8 chars of session_token_hash). The caller can only
  revoke their own sessions; the current session is excluded.

Security
--------
* **Session-based auth required.** All endpoints resolve the session from the
  ``argus.admin.session`` cookie (same resolver as ``whoami``).
* **No cross-user access.** Session list and revocation are scoped to the
  calling admin's ``subject``.
* **Hash prefixes.** The list returns only the first 8 hex chars of
  ``session_token_hash`` for UI identification — this is NOT enough to
  reconstruct the full hash or replay a session.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Annotated, Final

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.admin_sessions import resolve_session
from src.api.routers.admin_auth import ADMIN_SESSION_COOKIE as _SESSION_COOKIE_NAME
from src.core.config import settings
from src.core.datetime_format import format_created_at_iso_z
from src.db.models import AdminSession, AdminUser
from src.db.session import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/admin", tags=["auth"])

_HASH_PREFIX_LEN: Final[int] = 8


class AdminProfileResponse(BaseModel):
    subject: str
    role: str
    tenant_id: str | None = None
    mfa_enabled: bool = False
    created_at: str | None = None
    disabled_at: str | None = None


class SessionItem(BaseModel):
    session_hash_prefix: str
    created_at: str
    last_used_at: str
    expires_at: str
    is_current: bool = False


class SessionListResponse(BaseModel):
    sessions: list[SessionItem]


class RevokeSessionResponse(BaseModel):
    revoked: bool


def _bearer_session(authorization: str | None) -> str | None:
    if not authorization:
        return None
    raw = authorization.strip()
    prefix = "bearer "
    if len(raw) < len(prefix) or raw[: len(prefix)].lower() != prefix:
        return None
    return raw[len(prefix) :].strip() or None


async def _resolve_caller(
    request_cookie: str | None,
    authorization: str | None,
    db: AsyncSession,
) -> tuple[dict[str, object], str]:
    raw_token = request_cookie or _bearer_session(authorization)
    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    principal = await resolve_session(db, session_id=raw_token, ip=None, user_agent=None)
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    return {
        "subject": principal.subject,
        "role": principal.role,
        "tenant_id": principal.tenant_id,
    }, raw_token


@router.get(
    "/me",
    response_model=AdminProfileResponse,
    summary="Get current admin profile",
)
async def get_admin_profile(
    db: Annotated[AsyncSession, Depends(get_db)],
    cookie_session: Annotated[
        str | None, Cookie(alias=_SESSION_COOKIE_NAME)
    ] = None,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> AdminProfileResponse:
    caller, _ = await _resolve_caller(cookie_session, authorization, db)
    subject = caller["subject"]

    result = await db.execute(select(AdminUser).where(AdminUser.subject == subject))
    admin_user = result.scalar_one_or_none()
    if admin_user is None or admin_user.disabled_at is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account not found or disabled")

    return AdminProfileResponse(
        subject=admin_user.subject,
        role=admin_user.role,
        tenant_id=admin_user.tenant_id,
        mfa_enabled=admin_user.mfa_enabled,
        created_at=format_created_at_iso_z(admin_user.created_at) if admin_user.created_at else None,
        disabled_at=format_created_at_iso_z(admin_user.disabled_at) if admin_user.disabled_at else None,
    )


@router.get(
    "/sessions",
    response_model=SessionListResponse,
    summary="List active sessions for current admin",
)
async def list_admin_sessions(
    db: Annotated[AsyncSession, Depends(get_db)],
    cookie_session: Annotated[
        str | None, Cookie(alias=_SESSION_COOKIE_NAME)
    ] = None,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> SessionListResponse:
    caller, raw_token = await _resolve_caller(cookie_session, authorization, db)
    subject = caller["subject"]

    from src.auth.admin_sessions import hash_session_token

    current_hash = ""
    if raw_token and settings.admin_session_pepper:
        try:
            current_hash = hash_session_token(raw_token)
        except ValueError:
            pass

    now = datetime.now(tz=timezone.utc)
    stmt = (
        select(AdminSession)
        .where(
            AdminSession.subject == subject,
            AdminSession.revoked_at.is_(None),
            AdminSession.expires_at > now,
        )
        .order_by(AdminSession.last_used_at.desc())
    )
    result = await db.execute(stmt)
    rows = result.scalars().all()

    sessions: list[SessionItem] = []
    for row in rows:
        prefix = row.session_token_hash[:_HASH_PREFIX_LEN]
        sessions.append(
            SessionItem(
                session_hash_prefix=prefix,
                created_at=format_created_at_iso_z(row.created_at),
                last_used_at=format_created_at_iso_z(row.last_used_at),
                expires_at=format_created_at_iso_z(row.expires_at),
                is_current=(row.session_token_hash == current_hash),
            )
        )

    return SessionListResponse(sessions=sessions)


@router.delete(
    "/sessions/{session_hash_prefix}",
    response_model=RevokeSessionResponse,
    summary="Revoke another active session by hash prefix",
)
async def revoke_admin_session(
    session_hash_prefix: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    cookie_session: Annotated[
        str | None, Cookie(alias=_SESSION_COOKIE_NAME)
    ] = None,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> RevokeSessionResponse:
    caller, raw_token = await _resolve_caller(cookie_session, authorization, db)
    subject = caller["subject"]

    from src.auth.admin_sessions import hash_session_token as _hash_session

    current_hash = ""
    if raw_token and settings.admin_session_pepper:
        try:
            current_hash = _hash_session(raw_token)
        except ValueError:
            pass

    prefix = session_hash_prefix.strip()[:_HASH_PREFIX_LEN]
    if not prefix:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid session identifier")

    now = datetime.now(tz=timezone.utc)
    stmt = (
        select(AdminSession)
        .where(
            AdminSession.subject == subject,
            AdminSession.revoked_at.is_(None),
            AdminSession.expires_at > now,
            AdminSession.session_token_hash.startswith(prefix),
        )
    )
    result = await db.execute(stmt)
    target = result.scalar_one_or_none()

    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")

    if target.session_token_hash == current_hash:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot revoke the current session. Use logout instead.",
        )

    target.revoked_at = now
    await db.commit()

    logger.info(
        "admin_session_revoked_by_user",
        extra={
            "event": "argus.auth.admin_session.revoked_by_user",
            "subject": subject,
            "revoked_prefix": prefix,
        },
    )
    return RevokeSessionResponse(revoked=True)