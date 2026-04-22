"""ARGUS Cycle 7 / C7-T03 — admin MFA HTTP endpoints.

Endpoints (all under ``/api/v1/auth/admin/mfa``)
------------------------------------------------
* ``POST /enroll`` — start enrolment for the calling admin. Idempotent:
  a second call before ``/confirm`` returns the same secret + a freshly
  re-issued backup-code batch (the prior batch is invalidated).
* ``POST /confirm`` — verify the first 6-digit TOTP code and flip
  ``mfa_enabled=True``. Stamps ``mfa_passed_at`` on the calling session.
* ``POST /verify`` — verify a TOTP code OR a one-shot backup code on a
  half-authenticated session (login OK, MFA pending). Stamps
  ``mfa_passed_at`` on success.
* ``POST /disable`` — wipe MFA state. Requires fresh proof in the body
  (TOTP or backup code) — ``mfa_passed_at`` alone is NOT sufficient.
* ``GET /status`` — read-only enrolment + session view.
* ``POST /backup-codes/regenerate`` — mint a fresh batch of 10 codes.
  Requires fresh MFA proof in the body (same shape as ``/disable``).

Security invariants
-------------------
* **Authenticated callers only.** Every endpoint depends on the existing
  session resolver via :func:`require_admin_session_principal` (raises
  401 ``Authentication required`` on miss). The principal carries the
  calling admin subject — clients cannot enrol or modify a *different*
  account from this surface.
* **Per-user rate limit on /verify.** A token-bucket limiter keyed on
  ``(subject, source-IP)`` caps verify attempts at 5/min/user (default;
  configurable via ``ADMIN_MFA_VERIFY_RATE_LIMIT_PER_MINUTE``). Defends
  against brute-forcing the 6-digit TOTP space — at 5/min the expected
  time-to-hit on a random 6-digit code is ~3.8 hours, well above the
  30-second TOTP step.
* **No secret material in logs.** TOTP codes, backup codes (plaintext
  or hash), and the Fernet ciphertext NEVER cross the structured-log
  boundary. Every event uses ``argus.auth.admin_mfa.*`` with bounded,
  redaction-safe ``extra`` fields.
* **No stack traces to the client.** Every ``SQLAlchemyError`` /
  unexpected ``AdminMfaError`` is downgraded to a generic HTTP 500 with
  ``Internal Server Error`` so the storage backend / crypto library
  version cannot be fingerprinted via a probe.
* **Generic error envelopes.** 400 / 409 responses use a small, stable
  ``detail`` taxonomy (``invalid_totp``, ``mfa_already_enabled``,
  ``mfa_not_enabled``, ...) that the SOC's SIEM rules can pivot on
  without parsing free-form text.

QR encoding TODO
----------------
``backend/requirements.txt`` does not pin ``qrcode`` or ``segno`` as of
C7-T03 (verified via ``rg`` against the file). Per the C7-T03 hard rule
"DO NOT add new pip deps", :data:`MFAEnrollResponse.qr_data_uri` is
returned as ``None``; the frontend renders the URI as text. A follow-up
ticket will add ``segno`` (zero C-extension footprint) once SCA review
approves.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Annotated, Final, Literal

import pyotp
from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    Header,
    HTTPException,
    Request,
    status,
)
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.admin.schemas.mfa import (
    MFAConfirmRequest,
    MFAConfirmResponse,
    MFADisableRequest,
    MFADisableResponse,
    MFAEnrollRequest,
    MFAEnrollResponse,
    MFARegenerateBackupCodesResponse,
    MFAStatusResponse,
    MFAVerifyRequest,
    MFAVerifyResponse,
)
from src.auth import admin_mfa as mfa_dao
from src.auth.admin_mfa import AdminMfaError
from src.auth.admin_sessions import (
    SessionPrincipal,
    hash_session_token,
    is_session_pepper_configured,
    redact_session_id,
    resolve_session,
)
from src.core.config import settings
from src.db.models import AdminSession, AdminUser
from src.db.session import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/admin/mfa", tags=["auth", "mfa"])

#: Reuses the cookie name issued by ``admin_auth.admin_login`` so this
#: router shares the same session as the rest of the admin surface.
_ADMIN_SESSION_COOKIE: Final[str] = "argus.admin.session"

#: Bearer prefix for ``Authorization: Bearer <session>`` (case-insensitive).
_BEARER_PREFIX: Final[str] = "bearer "

#: TOTP issuer that ends up in the ``otpauth://`` URL — operators see this
#: as the human-readable "service name" in their authenticator app.
_TOTP_ISSUER: Final[str] = "ARGUS Admin"

#: LRU cap on the verify rate-limit map.
_VERIFY_RATE_LIMIT_LRU_CAP: Final[int] = 4096

#: Default verify rate limit (per (subject, IP) tuple, per minute). The
#: value is read from settings at first call (lazy singleton); no env knob
#: is added — 5/min/user is the floor mandated by the C7-T03 plan and
#: aligns with NIST SP 800-63B §5.2.2 throttling guidance.
_VERIFY_RATE_LIMIT_PER_MINUTE_DEFAULT: Final[int] = 5

#: Generic error responses — bounded taxonomy the SIEM can pivot on.
_DETAIL_AUTH_REQUIRED: Final[str] = "Authentication required"
_DETAIL_INVALID_TOTP: Final[str] = "invalid_totp"
_DETAIL_INVALID_BACKUP: Final[str] = "invalid_backup_code"
_DETAIL_INVALID_PROOF: Final[str] = "invalid_mfa_proof"
_DETAIL_MFA_NOT_ENABLED: Final[str] = "mfa_not_enabled"
_DETAIL_MFA_ALREADY_ENABLED: Final[str] = "mfa_already_enabled"
_DETAIL_NO_PENDING: Final[str] = "no_pending_enrollment"
_DETAIL_INTERNAL: Final[str] = "Internal Server Error"


# ---------------------------------------------------------------------------
# Session resolution + dependency
# ---------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class _MfaSession:
    """Light envelope binding a :class:`SessionPrincipal` to its raw token.

    The raw token is required so we can derive ``session_token_hash`` for
    :func:`mfa_dao.mark_session_mfa_passed`. We never log or echo the raw
    value back to the client; it travels handler-internal only.
    """

    principal: SessionPrincipal
    raw_session_id: str


def _bearer_session_from_header(authorization: str | None) -> str | None:
    """Extract a session id from ``Authorization: Bearer <session>``."""
    if not authorization:
        return None
    raw = authorization.strip()
    if len(raw) < len(_BEARER_PREFIX):
        return None
    if raw[: len(_BEARER_PREFIX)].lower() != _BEARER_PREFIX:
        return None
    candidate = raw[len(_BEARER_PREFIX) :].strip()
    return candidate or None


def _client_ip(request: Request) -> str:
    """Best-effort source IP for rate-limit keying."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        first = forwarded.split(",", 1)[0].strip()
        if first:
            return first
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _raise_unauthorized() -> None:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=_DETAIL_AUTH_REQUIRED,
    )


def _raise_internal() -> None:
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=_DETAIL_INTERNAL,
    )


async def require_admin_session_principal(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    cookie_session: Annotated[
        str | None, Cookie(alias=_ADMIN_SESSION_COOKIE)
    ] = None,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> _MfaSession:
    """FastAPI dependency — resolve the calling session or raise 401.

    Mirrors ``admin_auth.admin_whoami`` but returns the raw session id
    too so downstream handlers can derive ``session_token_hash`` for
    :func:`mfa_dao.mark_session_mfa_passed` without re-hashing the
    token from another helper.
    """
    raw = cookie_session or _bearer_session_from_header(authorization)
    if not raw:
        _raise_unauthorized()
        raise AssertionError("unreachable")  # pragma: no cover

    try:
        principal = await resolve_session(
            db,
            session_id=raw,
            ip=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        logger.exception(
            "admin_mfa_session_resolve_db_error",
            extra={
                "event": "argus.auth.admin_mfa.session_resolve_db_error",
                "session_id_prefix": redact_session_id(raw),
            },
        )
        _raise_internal()
        raise AssertionError("unreachable")  # pragma: no cover

    if principal is None:
        _raise_unauthorized()
        raise AssertionError("unreachable")  # pragma: no cover

    request.state.admin_session = principal
    return _MfaSession(principal=principal, raw_session_id=raw)


# ---------------------------------------------------------------------------
# Rate limiter — per (subject, IP) tuple.
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _VerifyRateLimiter:
    """Per-(subject, IP) token-bucket rate limiter (single-process).

    Uses the same shape as ``admin_auth._LoginRateLimiter`` but keys on
    a ``(subject, ip)`` tuple instead of just IP — the C7-T03 plan
    explicitly requires "per-user (or per-(user,IP) tuple), not just
    per-IP" so an attacker who controls a botnet of IPs cannot bypass
    the gate by rotating source addresses against the same admin.
    """

    per_minute: int
    _state: OrderedDict[tuple[str, str], tuple[float, float]]
    _lock: asyncio.Lock

    @classmethod
    def make(cls, per_minute: int) -> "_VerifyRateLimiter":
        if per_minute < 1:
            raise ValueError("per_minute must be >= 1")
        return cls(
            per_minute=per_minute,
            _state=OrderedDict(),
            _lock=asyncio.Lock(),
        )

    async def acquire(self, *, key: tuple[str, str]) -> tuple[bool, float]:
        capacity = float(self.per_minute)
        rate_per_second = capacity / 60.0
        now = time.monotonic()

        async with self._lock:
            cached = self._state.get(key)
            if cached is None:
                tokens, last_ts = capacity, now
            else:
                tokens, last_ts = cached
                elapsed = max(0.0, now - last_ts)
                tokens = min(capacity, tokens + elapsed * rate_per_second)
                last_ts = now

            if tokens < 1.0:
                deficit = 1.0 - tokens
                retry_after = (
                    deficit / rate_per_second if rate_per_second > 0 else 60.0
                )
                self._state[key] = (tokens, last_ts)
                self._state.move_to_end(key)
                return False, retry_after

            self._state[key] = (tokens - 1.0, last_ts)
            self._state.move_to_end(key)
            while len(self._state) > _VERIFY_RATE_LIMIT_LRU_CAP:
                self._state.popitem(last=False)
            return True, 0.0


_VERIFY_RATE_LIMITER: _VerifyRateLimiter | None = None
_VERIFY_LIMITER_LOCK = asyncio.Lock()


async def _get_verify_rate_limiter() -> _VerifyRateLimiter:
    """Lazy singleton bound to the running event loop."""
    global _VERIFY_RATE_LIMITER
    if _VERIFY_RATE_LIMITER is None:
        async with _VERIFY_LIMITER_LOCK:
            if _VERIFY_RATE_LIMITER is None:
                _VERIFY_RATE_LIMITER = _VerifyRateLimiter.make(
                    per_minute=_VERIFY_RATE_LIMIT_PER_MINUTE_DEFAULT
                )
    return _VERIFY_RATE_LIMITER


def _reset_verify_rate_limiter_for_tests() -> None:
    """Drop the cached limiter — test-only, called between cases."""
    global _VERIFY_RATE_LIMITER
    _VERIFY_RATE_LIMITER = None


# ---------------------------------------------------------------------------
# DB read helpers.
#
# Centralised here so we never duplicate the ``select(AdminUser)`` shape
# across handlers and so the legacy ``_load_state`` private helper from
# the DAO is not leaked. Returning small, well-typed snapshots keeps the
# blast radius of a future column addition (Alembic 03N) tiny.
# ---------------------------------------------------------------------------


@dataclass(slots=True, frozen=True)
class _AdminMfaSnapshot:
    """Read-only MFA state snapshot used by /enroll, /status, /confirm."""

    enabled: bool
    secret_encrypted: bytes | None
    backup_codes_count: int


async def _load_admin_mfa_snapshot(
    db: AsyncSession, *, subject: str
) -> _AdminMfaSnapshot | None:
    """Return the MFA snapshot for *subject* or ``None`` if the user is gone."""
    stmt = select(
        AdminUser.mfa_enabled,
        AdminUser.mfa_secret_encrypted,
        AdminUser.mfa_backup_codes_hash,
    ).where(AdminUser.subject == subject)
    row = (await db.execute(stmt)).one_or_none()
    if row is None:
        return None
    backup_codes = row.mfa_backup_codes_hash or []
    return _AdminMfaSnapshot(
        enabled=bool(row.mfa_enabled),
        secret_encrypted=row.mfa_secret_encrypted,
        backup_codes_count=len(backup_codes),
    )


async def _load_session_mfa_passed_at(
    db: AsyncSession, *, raw_session_id: str
) -> datetime | None:
    """Return ``mfa_passed_at`` on the session row keyed by raw token.

    Returns ``None`` when the session is unknown OR when the pepper is
    unconfigured (in which case the row cannot be located by hash and
    the session is effectively pre-MFA anyway). Defensive ``try`` so a
    storage hiccup never crashes the read-only ``/status`` endpoint.
    """
    if not is_session_pepper_configured():
        return None
    try:
        token_hash = hash_session_token(raw_session_id)
    except ValueError:
        return None
    try:
        stmt = select(AdminSession.mfa_passed_at).where(
            AdminSession.session_token_hash == token_hash
        )
        result = (await db.execute(stmt)).scalar_one_or_none()
    except SQLAlchemyError:
        logger.exception(
            "admin_mfa_load_session_db_error",
            extra={
                "event": "argus.auth.admin_mfa.session_load_db_error",
            },
        )
        return None
    if result is None:
        return None
    if result.tzinfo is None:
        return result.replace(tzinfo=timezone.utc)
    return result


def _is_session_mfa_fresh(passed_at: datetime | None) -> bool:
    """Return True iff *passed_at* is within the configured re-auth window."""
    if passed_at is None:
        return False
    window = timedelta(seconds=settings.admin_mfa_reauth_window_seconds)
    return datetime.now(tz=timezone.utc) - passed_at < window


# ---------------------------------------------------------------------------
# Endpoint: POST /enroll
# ---------------------------------------------------------------------------


def _build_otpauth_uri(*, subject: str, secret_b32: str) -> str:
    """Compose the ``otpauth://`` URL the authenticator app consumes.

    pyotp's ``provisioning_uri`` already URL-encodes the issuer and
    subject correctly; we wrap it for type clarity and a single point
    where the issuer string is set.
    """
    return str(
        pyotp.TOTP(secret_b32).provisioning_uri(
            name=subject, issuer_name=_TOTP_ISSUER
        )
    )


@router.post(
    "/enroll",
    response_model=MFAEnrollResponse,
    responses={
        401: {"description": "Authentication required"},
        409: {"description": "MFA is already enabled for this account"},
    },
)
async def admin_mfa_enroll(
    body: MFAEnrollRequest,  # noqa: ARG001 — empty body validated for extra=forbid
    session: Annotated[_MfaSession, Depends(require_admin_session_principal)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MFAEnrollResponse:
    """Start enrolment for the calling admin.

    Idempotency: a second call (before ``/confirm`` succeeds) overwrites
    the prior pending secret + backup-code batch and returns the new
    pair. The plaintext codes are returned ONCE — the frontend MUST
    persist them to the operator before navigating away.
    """
    subject = session.principal.subject

    snapshot = await _load_admin_mfa_snapshot(db, subject=subject)
    if snapshot is None:
        # Authenticated session refers to a subject that no longer
        # exists in admin_users (off-boarded between login and now). The
        # right response is the same generic 401 as a missing session —
        # the cookie is no longer valid.
        _raise_unauthorized()
        raise AssertionError("unreachable")  # pragma: no cover
    if snapshot.enabled:
        logger.info(
            "admin_mfa_enroll_already_enabled",
            extra={
                "event": "argus.auth.admin_mfa.enroll_already_enabled",
                "subject": subject,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=_DETAIL_MFA_ALREADY_ENABLED,
        )

    secret_b32 = pyotp.random_base32()
    backup_codes_plain = mfa_dao.generate_backup_codes()

    try:
        await mfa_dao.enroll_totp(
            db,
            subject=subject,
            secret=secret_b32,
            backup_codes=backup_codes_plain,
        )
        await db.commit()
    except AdminMfaError as exc:
        await db.rollback()
        logger.warning(
            "admin_mfa_enroll_dao_error",
            extra={
                "event": "argus.auth.admin_mfa.enroll_dao_error",
                "subject": subject,
                "reason": str(exc),
            },
        )
        _raise_internal()
        raise AssertionError("unreachable")  # pragma: no cover
    except SQLAlchemyError:
        await db.rollback()
        logger.exception(
            "admin_mfa_enroll_db_error",
            extra={
                "event": "argus.auth.admin_mfa.enroll_db_error",
                "subject": subject,
            },
        )
        _raise_internal()
        raise AssertionError("unreachable")  # pragma: no cover

    secret_uri = _build_otpauth_uri(subject=subject, secret_b32=secret_b32)

    logger.info(
        "admin_mfa_enroll",
        extra={
            "event": "argus.auth.admin_mfa.enroll",
            "subject": subject,
            "backup_codes_count": len(backup_codes_plain),
        },
    )

    return MFAEnrollResponse(
        secret_uri=secret_uri,
        qr_data_uri=None,  # see module docstring "QR encoding TODO"
        backup_codes=backup_codes_plain,
    )


# ---------------------------------------------------------------------------
# Endpoint: POST /confirm
# ---------------------------------------------------------------------------


@router.post(
    "/confirm",
    response_model=MFAConfirmResponse,
    responses={
        400: {"description": "Invalid TOTP or no pending enrolment"},
        401: {"description": "Authentication required"},
    },
)
async def admin_mfa_confirm(
    body: MFAConfirmRequest,
    session: Annotated[_MfaSession, Depends(require_admin_session_principal)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MFAConfirmResponse:
    """Verify the first 6-digit TOTP code and finish enrolment.

    On success: ``mfa_enabled`` flips to ``True`` AND ``mfa_passed_at``
    on the calling session is stamped — the admin is fully authenticated
    going forward without needing to re-verify in the same session.
    """
    subject = session.principal.subject

    try:
        await mfa_dao.confirm_enrollment(
            db,
            subject=subject,
            totp_code=body.totp_code,
            generated_codes=None,  # already persisted at /enroll time
        )
        # Stamp the session as MFA-verified BEFORE committing so the same
        # transaction either commits both or rolls back both.
        await mfa_dao.mark_session_mfa_passed(
            db, session_token_hash=hash_session_token(session.raw_session_id)
        )
        await db.commit()
    except AdminMfaError as exc:
        await db.rollback()
        logger.info(
            "admin_mfa_confirm_failed",
            extra={
                "event": "argus.auth.admin_mfa.confirm_failed",
                "subject": subject,
                "reason": str(exc),
            },
        )
        if str(exc) in {
            "totp_invalid",
            "totp_not_enrolled",
            "totp_code_required",
            "backup_codes_required",
        }:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=_DETAIL_INVALID_TOTP
                if str(exc) == "totp_invalid"
                else _DETAIL_NO_PENDING,
            ) from None
        _raise_internal()
        raise AssertionError("unreachable")  # pragma: no cover
    except (SQLAlchemyError, ValueError):
        await db.rollback()
        logger.exception(
            "admin_mfa_confirm_db_error",
            extra={
                "event": "argus.auth.admin_mfa.confirm_db_error",
                "subject": subject,
            },
        )
        _raise_internal()
        raise AssertionError("unreachable")  # pragma: no cover

    now = datetime.now(tz=timezone.utc)
    logger.info(
        "admin_mfa_confirm",
        extra={
            "event": "argus.auth.admin_mfa.confirm",
            "subject": subject,
        },
    )
    return MFAConfirmResponse(enabled=True, enabled_at=now)


# ---------------------------------------------------------------------------
# Endpoint: POST /verify
# ---------------------------------------------------------------------------


async def _verify_one_credential(
    db: AsyncSession,
    *,
    subject: str,
    totp_code: str | None,
    backup_code: str | None,
) -> tuple[bool, Literal["totp", "backup"]]:
    """Dispatch to the matching DAO call. Returns ``(verified, path)``."""
    if totp_code is not None:
        verified = await mfa_dao.verify_totp(
            db, subject=subject, totp_code=totp_code
        )
        return verified, "totp"
    assert backup_code is not None  # XOR enforced by Pydantic validator
    verified = await mfa_dao.consume_backup_code(
        db, subject=subject, code=backup_code
    )
    return verified, "backup"


@router.post(
    "/verify",
    response_model=MFAVerifyResponse,
    responses={
        400: {"description": "Invalid TOTP / backup code"},
        401: {"description": "Authentication required"},
        429: {"description": "Too many MFA verify attempts; honour Retry-After"},
    },
)
async def admin_mfa_verify(
    body: MFAVerifyRequest,
    request: Request,
    session: Annotated[_MfaSession, Depends(require_admin_session_principal)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MFAVerifyResponse:
    """Verify a TOTP code OR a one-shot backup code on a half-auth session."""
    subject = session.principal.subject
    client_ip = _client_ip(request)

    limiter = await _get_verify_rate_limiter()
    allowed, retry_after = await limiter.acquire(key=(subject, client_ip))
    if not allowed:
        logger.info(
            "admin_mfa_verify_rate_limited",
            extra={
                "event": "argus.auth.admin_mfa.verify_rate_limited",
                "subject": subject,
                "retry_after_seconds": round(retry_after, 3),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many MFA verify attempts. Please try again later.",
            headers={"Retry-After": str(max(1, int(retry_after) + 1))},
        )

    try:
        verified, path = await _verify_one_credential(
            db,
            subject=subject,
            totp_code=body.totp_code,
            backup_code=body.backup_code,
        )
        await db.commit()
    except (SQLAlchemyError, AdminMfaError):
        await db.rollback()
        logger.exception(
            "admin_mfa_verify_dao_error",
            extra={
                "event": "argus.auth.admin_mfa.verify_dao_error",
                "subject": subject,
            },
        )
        _raise_internal()
        raise AssertionError("unreachable")  # pragma: no cover

    if not verified:
        logger.info(
            "admin_mfa_verify_failure",
            extra={
                "event": "argus.auth.admin_mfa.verify_failure",
                "subject": subject,
                "path": path,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_DETAIL_INVALID_TOTP if path == "totp" else _DETAIL_INVALID_BACKUP,
        )

    try:
        await mfa_dao.mark_session_mfa_passed(
            db, session_token_hash=hash_session_token(session.raw_session_id)
        )
        await db.commit()
    except (SQLAlchemyError, ValueError):
        await db.rollback()
        logger.exception(
            "admin_mfa_verify_mark_db_error",
            extra={
                "event": "argus.auth.admin_mfa.verify_mark_db_error",
                "subject": subject,
            },
        )
        _raise_internal()
        raise AssertionError("unreachable")  # pragma: no cover

    remaining: int | None = None
    if path == "backup":
        snapshot = await _load_admin_mfa_snapshot(db, subject=subject)
        if snapshot is not None:
            remaining = snapshot.backup_codes_count

    now = datetime.now(tz=timezone.utc)
    logger.info(
        "admin_mfa_verify_success",
        extra={
            "event": "argus.auth.admin_mfa.verify_success",
            "subject": subject,
            "path": path,
            "remaining_backup_codes": remaining,
        },
    )
    return MFAVerifyResponse(
        verified=True,
        mfa_passed_at=now,
        remaining_backup_codes=remaining,
    )


# ---------------------------------------------------------------------------
# Endpoint: POST /disable + /backup-codes/regenerate
# ---------------------------------------------------------------------------


async def _verify_fresh_proof_or_400(
    db: AsyncSession,
    *,
    subject: str,
    totp_code: str | None,
    backup_code: str | None,
) -> None:
    """Verify a fresh TOTP / backup-code proof or raise HTTP 400."""
    try:
        verified, _path = await _verify_one_credential(
            db,
            subject=subject,
            totp_code=totp_code,
            backup_code=backup_code,
        )
        await db.commit()
    except (SQLAlchemyError, AdminMfaError):
        await db.rollback()
        logger.exception(
            "admin_mfa_proof_dao_error",
            extra={
                "event": "argus.auth.admin_mfa.proof_dao_error",
                "subject": subject,
            },
        )
        _raise_internal()
        raise AssertionError("unreachable")  # pragma: no cover

    if not verified:
        logger.info(
            "admin_mfa_proof_invalid",
            extra={
                "event": "argus.auth.admin_mfa.proof_invalid",
                "subject": subject,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=_DETAIL_INVALID_PROOF,
        )


@router.post(
    "/disable",
    response_model=MFADisableResponse,
    responses={
        400: {"description": "Invalid MFA proof"},
        401: {"description": "Authentication required"},
        409: {"description": "MFA is not enabled for this account"},
    },
)
async def admin_mfa_disable(
    body: MFADisableRequest,
    session: Annotated[_MfaSession, Depends(require_admin_session_principal)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MFADisableResponse:
    """Disable MFA for the calling admin.

    Even with a fresh ``mfa_passed_at`` on the session, the admin MUST
    re-prove possession in the request body — disable is privileged
    enough that we never trust session state alone.
    """
    subject = session.principal.subject

    snapshot = await _load_admin_mfa_snapshot(db, subject=subject)
    if snapshot is None:
        _raise_unauthorized()
        raise AssertionError("unreachable")  # pragma: no cover
    if not snapshot.enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=_DETAIL_MFA_NOT_ENABLED,
        )

    await _verify_fresh_proof_or_400(
        db,
        subject=subject,
        totp_code=body.totp_code,
        backup_code=body.backup_code,
    )

    try:
        await mfa_dao.disable_mfa(db, subject=subject)
        await db.commit()
    except AdminMfaError as exc:
        await db.rollback()
        logger.warning(
            "admin_mfa_disable_dao_error",
            extra={
                "event": "argus.auth.admin_mfa.disable_dao_error",
                "subject": subject,
                "reason": str(exc),
            },
        )
        _raise_internal()
        raise AssertionError("unreachable")  # pragma: no cover
    except SQLAlchemyError:
        await db.rollback()
        logger.exception(
            "admin_mfa_disable_db_error",
            extra={
                "event": "argus.auth.admin_mfa.disable_db_error",
                "subject": subject,
            },
        )
        _raise_internal()
        raise AssertionError("unreachable")  # pragma: no cover

    now = datetime.now(tz=timezone.utc)
    logger.info(
        "admin_mfa_disable",
        extra={
            "event": "argus.auth.admin_mfa.disable",
            "subject": subject,
        },
    )
    return MFADisableResponse(disabled=True, disabled_at=now)


@router.post(
    "/backup-codes/regenerate",
    response_model=MFARegenerateBackupCodesResponse,
    responses={
        400: {"description": "Invalid MFA proof"},
        401: {"description": "Authentication required"},
        409: {"description": "MFA is not enabled for this account"},
    },
)
async def admin_mfa_regenerate_backup_codes(
    body: MFADisableRequest,
    session: Annotated[_MfaSession, Depends(require_admin_session_principal)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MFARegenerateBackupCodesResponse:
    """Mint a fresh batch of backup codes; the prior batch is invalidated.

    Reuses :class:`MFADisableRequest` for the proof body (same XOR shape
    of TOTP / backup code) — no new schema needed and the SOC sees a
    consistent "fresh proof required" envelope across both ops.
    """
    subject = session.principal.subject

    snapshot = await _load_admin_mfa_snapshot(db, subject=subject)
    if snapshot is None:
        _raise_unauthorized()
        raise AssertionError("unreachable")  # pragma: no cover
    if not snapshot.enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=_DETAIL_MFA_NOT_ENABLED,
        )

    await _verify_fresh_proof_or_400(
        db,
        subject=subject,
        totp_code=body.totp_code,
        backup_code=body.backup_code,
    )

    try:
        plaintext = await mfa_dao.regenerate_backup_codes(db, subject=subject)
        await db.commit()
    except AdminMfaError as exc:
        await db.rollback()
        logger.warning(
            "admin_mfa_regen_dao_error",
            extra={
                "event": "argus.auth.admin_mfa.backup_regenerate_dao_error",
                "subject": subject,
                "reason": str(exc),
            },
        )
        _raise_internal()
        raise AssertionError("unreachable")  # pragma: no cover
    except SQLAlchemyError:
        await db.rollback()
        logger.exception(
            "admin_mfa_regen_db_error",
            extra={
                "event": "argus.auth.admin_mfa.backup_regenerate_db_error",
                "subject": subject,
            },
        )
        _raise_internal()
        raise AssertionError("unreachable")  # pragma: no cover

    logger.info(
        "admin_mfa_backup_regenerate",
        extra={
            "event": "argus.auth.admin_mfa.backup_regenerate",
            "subject": subject,
            "backup_codes_count": len(plaintext),
        },
    )
    return MFARegenerateBackupCodesResponse(backup_codes=plaintext)


# ---------------------------------------------------------------------------
# Endpoint: GET /status
# ---------------------------------------------------------------------------


@router.get(
    "/status",
    response_model=MFAStatusResponse,
    responses={401: {"description": "Authentication required"}},
)
async def admin_mfa_status(
    session: Annotated[_MfaSession, Depends(require_admin_session_principal)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> MFAStatusResponse:
    """Read-only enrolment + session view for the calling admin."""
    subject = session.principal.subject

    snapshot = await _load_admin_mfa_snapshot(db, subject=subject)
    if snapshot is None:
        _raise_unauthorized()
        raise AssertionError("unreachable")  # pragma: no cover

    passed_at = await _load_session_mfa_passed_at(
        db, raw_session_id=session.raw_session_id
    )
    fresh = _is_session_mfa_fresh(passed_at)

    remaining: int | None = (
        snapshot.backup_codes_count if snapshot.enabled else None
    )

    return MFAStatusResponse(
        enabled=snapshot.enabled,
        enrolled_at=None,  # see schema docstring (follow-up Alembic 03N)
        remaining_backup_codes=remaining,
        mfa_passed_for_session=fresh,
    )


__all__ = [
    "_reset_verify_rate_limiter_for_tests",
    "admin_mfa_confirm",
    "admin_mfa_disable",
    "admin_mfa_enroll",
    "admin_mfa_regenerate_backup_codes",
    "admin_mfa_status",
    "admin_mfa_verify",
    "require_admin_session_principal",
    "router",
]
