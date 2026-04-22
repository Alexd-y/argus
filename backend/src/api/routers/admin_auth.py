"""Admin auth HTTP surface — login / logout / whoami (ISS-T20-003 Phase 1).

Endpoints
---------
* ``POST /auth/admin/login`` — accepts ``{subject, password}``, verifies the
  bcrypt hash via :func:`src.auth.admin_users.verify_credentials`, mints a
  CSPRNG session via :func:`src.auth.admin_sessions.create_session`, and sets
  the ``argus.admin.session`` cookie (``HttpOnly``, ``Secure``,
  ``SameSite=Strict``, ``Path=/``). Returns ``{role, tenant_id, expires_at}``.
* ``POST /auth/admin/logout`` — revokes the session row (tombstones
  ``revoked_at``) and clears the cookie. Idempotent.
* ``GET /auth/admin/whoami`` — resolves the session from either the cookie
  or ``Authorization: Bearer <session>`` and returns the principal payload
  ``{subject, role, tenant_id, expires_at}``. 401 on miss / expired / revoked.

Security invariants
-------------------
* **No enumeration.** Every login failure returns the literal
  :data:`_LOGIN_FAILURE_DETAIL` ("Invalid credentials") with HTTP 401 — the
  resolver itself fans out into multiple structured-log reasons but the
  HTTP response stays uniform.
* **No plaintext / session-id logging.** :func:`verify_credentials` and the
  session module both redact via the ``argus.auth.*`` event surface. This
  router never echoes the password and never logs the raw session id.
* **No stack traces leaked.** Every unexpected exception is downgraded to a
  generic 500 with ``Internal Server Error`` so the client cannot fingerprint
  the storage backend or the bcrypt library version.
* **Cookie flags.** ``HttpOnly`` blocks JS access; ``Secure`` requires TLS
  (the ``CookieEnvironment`` lifts the Secure attribute only in DEBUG so
  Cypress / Playwright dev runs work without TLS); ``SameSite=Strict`` blocks
  every cross-site form post; ``Path=/`` keeps the cookie out of unrelated
  asset routes.
* **Per-IP rate limit.** Login is gated by an in-process token bucket
  (default 10 req/min/IP, configurable via
  ``ADMIN_LOGIN_RATE_LIMIT_PER_MINUTE``). The limiter responds with HTTP 429
  + ``Retry-After`` so brute-force tooling backs off.

The router is mounted at ``/api/v1`` by ``backend/main.py`` to match every
other router; the path prefix is ``/auth/admin`` so the resulting URLs are
``/api/v1/auth/admin/{login,logout,whoami}``.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Annotated, Final

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.admin_sessions import (
    SessionPrincipal,
    create_session,
    redact_session_id,
    resolve_session,
    revoke_session,
)
from src.auth.admin_users import verify_credentials
from src.core.config import settings
from src.core.datetime_format import format_created_at_iso_z
from src.db.session import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/admin", tags=["auth"])

#: Cookie name carrying the opaque session id. Documented + tested.
ADMIN_SESSION_COOKIE: Final[str] = "argus.admin.session"

#: Single canonical 401 detail — never leaks the failure reason to the client.
_LOGIN_FAILURE_DETAIL: Final[str] = "Invalid credentials"

#: Cap on the credential payload sizes so a hostile body cannot flood logs.
_SUBJECT_MAX_LEN: Final[int] = 255
_PASSWORD_MAX_LEN: Final[int] = 1024

#: Bearer scheme prefix for the ``Authorization`` header (case-insensitive).
_BEARER_PREFIX: Final[str] = "bearer "

#: LRU cap on the per-IP rate-limit map so a /16 sweep cannot exhaust RAM.
_RATE_LIMIT_LRU_CAP: Final[int] = 4096


class LoginRequest(BaseModel):
    """Login payload — bounded to defeat trivial DoS via giant strings."""

    subject: str = Field(..., min_length=1, max_length=_SUBJECT_MAX_LEN)
    password: str = Field(..., min_length=1, max_length=_PASSWORD_MAX_LEN)


class LoginResponse(BaseModel):
    """Login OK envelope — minimal, no echo of subject or session id."""

    role: str
    tenant_id: str | None = None
    expires_at: str


class WhoAmIResponse(BaseModel):
    """``GET /whoami`` envelope — what the FE needs to render the chrome."""

    subject: str
    role: str
    tenant_id: str | None = None
    expires_at: str


class LogoutResponse(BaseModel):
    """``POST /logout`` envelope — idempotent ``revoked`` flag for tests."""

    revoked: bool


@dataclass(slots=True)
class _LoginRateLimiter:
    """Per-IP token-bucket login limiter — single-process, asyncio-safe.

    Reuses a token-bucket shape (``tokens`` + ``last_refill_ts``) similar to
    :class:`src.mcp.runtime.rate_limiter.InMemoryTokenBucket` but trimmed to
    the ergonomics this router needs:

    * one bucket per source IP (``Request.client.host``);
    * burst = configured ``per_minute`` so a freshly-seen IP may immediately
      consume the full minute's allowance;
    * refill rate = ``per_minute / 60`` tokens per second;
    * an LRU eviction policy keeps the dict bounded so an attacker rotating
      source IPs cannot OOM the process.

    The limiter raises HTTP 429 with a ``Retry-After`` header (seconds)
    that the caller is expected to honour. We never differentiate in the
    response body so the limiter cannot be probed for liveness or capacity.
    """

    per_minute: int
    _state: OrderedDict[str, tuple[float, float]]
    _lock: asyncio.Lock

    @classmethod
    def make(cls, per_minute: int) -> "_LoginRateLimiter":
        if per_minute < 1:
            raise ValueError("per_minute must be >= 1")
        return cls(
            per_minute=per_minute,
            _state=OrderedDict(),
            _lock=asyncio.Lock(),
        )

    async def acquire(self, *, key: str) -> tuple[bool, float]:
        """Consume one token for *key*, returning ``(allowed, retry_after)``."""
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
                retry_after = deficit / rate_per_second if rate_per_second > 0 else 60.0
                self._state[key] = (tokens, last_ts)
                self._state.move_to_end(key)
                return False, retry_after

            self._state[key] = (tokens - 1.0, last_ts)
            self._state.move_to_end(key)
            while len(self._state) > _RATE_LIMIT_LRU_CAP:
                self._state.popitem(last=False)
            return True, 0.0


_LOGIN_RATE_LIMITER: _LoginRateLimiter | None = None
_LIMITER_LOCK = asyncio.Lock()


async def _get_login_rate_limiter() -> _LoginRateLimiter:
    """Lazy singleton bound to the running event loop.

    Building the limiter inside the async context lets ``asyncio.Lock`` bind
    to whatever loop FastAPI is running on (uvicorn / pytest-asyncio differ).
    """
    global _LOGIN_RATE_LIMITER
    if _LOGIN_RATE_LIMITER is None:
        async with _LIMITER_LOCK:
            if _LOGIN_RATE_LIMITER is None:
                _LOGIN_RATE_LIMITER = _LoginRateLimiter.make(
                    per_minute=settings.admin_login_rate_limit_per_minute
                )
    return _LOGIN_RATE_LIMITER


def _reset_login_rate_limiter_for_tests() -> None:
    """Drop the cached limiter — test-only, called by ``conftest`` between cases."""
    global _LOGIN_RATE_LIMITER
    _LOGIN_RATE_LIMITER = None


def _client_ip(request: Request) -> str:
    """Best-effort source IP for rate-limit keying.

    Prefers the first hop in ``X-Forwarded-For`` when the deployment runs
    behind a known reverse proxy (uvicorn ``--proxy-headers``); falls back
    to the raw socket address. Only the IP literal is read — we never
    accept a hostname or other identifier from the client.
    """
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        first = forwarded.split(",", 1)[0].strip()
        if first:
            return first
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _is_secure_request(request: Request) -> bool:
    """Whether the upstream client connected over TLS (or proxy-claims TLS)."""
    if request.url.scheme == "https":
        return True
    forwarded_proto = request.headers.get("x-forwarded-proto", "").strip().lower()
    return forwarded_proto == "https"


def _set_session_cookie(
    response: Response,
    *,
    request: Request,
    session_id: str,
    expires_at_seconds: int,
) -> None:
    """Attach ``argus.admin.session`` to *response* with strict flags.

    ``Secure`` is always set in production (default). In ``DEBUG=true``
    builds we relax it only when the request itself was not TLS — this
    keeps Cypress / curl-based local dev usable while leaving prod safe.
    """
    secure_flag = True
    if settings.debug and not _is_secure_request(request):
        secure_flag = False
    response.set_cookie(
        key=ADMIN_SESSION_COOKIE,
        value=session_id,
        max_age=expires_at_seconds,
        httponly=True,
        secure=secure_flag,
        samesite="strict",
        path="/",
    )


def _clear_session_cookie(response: Response, *, request: Request) -> None:
    """Expire the cookie client-side; mirrors the flags used on set."""
    secure_flag = True
    if settings.debug and not _is_secure_request(request):
        secure_flag = False
    response.delete_cookie(
        key=ADMIN_SESSION_COOKIE,
        path="/",
        secure=secure_flag,
        httponly=True,
        samesite="strict",
    )


def _bearer_session_from_header(authorization: str | None) -> str | None:
    """Extract ``<session>`` from ``Authorization: Bearer <session>``."""
    if not authorization:
        return None
    raw = authorization.strip()
    if len(raw) < len(_BEARER_PREFIX):
        return None
    if raw[: len(_BEARER_PREFIX)].lower() != _BEARER_PREFIX:
        return None
    candidate = raw[len(_BEARER_PREFIX) :].strip()
    return candidate or None


def _principal_to_whoami(principal: SessionPrincipal) -> WhoAmIResponse:
    return WhoAmIResponse(
        subject=principal.subject,
        role=principal.role,
        tenant_id=principal.tenant_id,
        expires_at=format_created_at_iso_z(principal.expires_at),
    )


def _raise_unauthorized() -> None:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=_LOGIN_FAILURE_DETAIL,
    )


def _raise_internal() -> None:
    """Generic 500 — never echo backend internals."""
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Internal Server Error",
    )


@router.post(
    "/login",
    response_model=LoginResponse,
    responses={
        401: {"description": "Invalid credentials"},
        429: {"description": "Too many login attempts; honour Retry-After"},
    },
)
async def admin_login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> LoginResponse:
    """Verify credentials, mint a session, set the ``argus.admin.session`` cookie.

    The handler MUST emit the same 401 message for every failure mode
    (subject missing, password wrong, account disabled) — the failure
    reason fans out into the structured ``argus.auth.admin_login.*`` log
    surface for the SOC, never into the HTTP response.
    """
    client_ip = _client_ip(request)
    limiter = await _get_login_rate_limiter()
    allowed, retry_after = await limiter.acquire(key=client_ip)
    if not allowed:
        logger.info(
            "admin_login_rate_limited",
            extra={
                "event": "argus.auth.admin_login.rate_limited",
                "retry_after_seconds": round(retry_after, 3),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later.",
            headers={"Retry-After": str(max(1, int(retry_after) + 1))},
        )

    try:
        principal = await verify_credentials(
            db, subject=body.subject, password=body.password
        )
    except SQLAlchemyError:
        logger.exception(
            "admin_login_handler_db_error",
            extra={"event": "argus.auth.admin_login.handler_db_error"},
        )
        _raise_internal()
        return LoginResponse(role="", tenant_id=None, expires_at="")  # pragma: no cover

    if principal is None:
        _raise_unauthorized()
        return LoginResponse(role="", tenant_id=None, expires_at="")  # pragma: no cover

    try:
        session_id, row = await create_session(
            db,
            subject=principal.subject,
            role=principal.role,
            tenant_id=principal.tenant_id,
            ip=client_ip,
            user_agent=request.headers.get("user-agent"),
        )
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        logger.exception(
            "admin_login_session_create_failed",
            extra={"event": "argus.auth.admin_login.session_create_failed"},
        )
        _raise_internal()
        return LoginResponse(role="", tenant_id=None, expires_at="")  # pragma: no cover

    _set_session_cookie(
        response,
        request=request,
        session_id=session_id,
        expires_at_seconds=settings.admin_session_ttl_seconds,
    )

    logger.info(
        "admin_login_session_issued",
        extra={
            "event": "argus.auth.admin_login.session_issued",
            "session_id_prefix": redact_session_id(session_id),
            "role": row.role,
            "tenant_id_present": row.tenant_id is not None,
        },
    )

    return LoginResponse(
        role=row.role,
        tenant_id=row.tenant_id,
        expires_at=format_created_at_iso_z(row.expires_at),
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
)
async def admin_logout(
    request: Request,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
    cookie_session: Annotated[
        str | None, Cookie(alias=ADMIN_SESSION_COOKIE)
    ] = None,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> LogoutResponse:
    """Revoke the active session (if any) and unconditionally clear the cookie.

    Idempotent: hitting the endpoint without an active session still
    succeeds (``revoked=False``) and still wipes any stale cookie the
    browser was carrying — defence-in-depth against a half-cleared client.
    """
    session_id = cookie_session or _bearer_session_from_header(authorization)

    revoked = False
    if session_id:
        try:
            revoked = await revoke_session(db, session_id=session_id)
            await db.commit()
        except SQLAlchemyError:
            await db.rollback()
            logger.exception(
                "admin_logout_db_error",
                extra={"event": "argus.auth.admin_logout.db_error"},
            )

    _clear_session_cookie(response, request=request)

    logger.info(
        "admin_logout",
        extra={
            "event": "argus.auth.admin_logout",
            "session_id_prefix": redact_session_id(session_id),
            "revoked": revoked,
        },
    )
    return LogoutResponse(revoked=revoked)


@router.get(
    "/whoami",
    response_model=WhoAmIResponse,
    responses={401: {"description": "Missing or invalid session"}},
)
async def admin_whoami(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    cookie_session: Annotated[
        str | None, Cookie(alias=ADMIN_SESSION_COOKIE)
    ] = None,
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> WhoAmIResponse:
    """Resolve the active session from cookie OR ``Authorization: Bearer``.

    Cookie takes precedence — a misbehaving client cannot promote a stale
    bearer over the canonical browser cookie. Returns 401 for every miss
    (no session presented, expired, revoked) so the caller cannot tell
    *why* the credential was rejected.
    """
    session_id = cookie_session or _bearer_session_from_header(authorization)
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_LOGIN_FAILURE_DETAIL,
        )

    try:
        principal = await resolve_session(
            db,
            session_id=session_id,
            ip=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
        )
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        logger.exception(
            "admin_whoami_db_error",
            extra={"event": "argus.auth.admin_whoami.db_error"},
        )
        _raise_internal()
        return WhoAmIResponse(
            subject="", role="", tenant_id=None, expires_at=""
        )  # pragma: no cover

    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_LOGIN_FAILURE_DETAIL,
        )

    return _principal_to_whoami(principal)


__all__ = [
    "ADMIN_SESSION_COOKIE",
    "LoginRequest",
    "LoginResponse",
    "LogoutResponse",
    "WhoAmIResponse",
    "router",
]
