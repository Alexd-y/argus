"""Admin authorization dependencies — :func:`require_admin` + MFA gate.

This module is the single source of truth for the two admin authorization
dependencies that every privileged route hangs off:

* :func:`require_admin` — dual-mode admin gate (ISS-T20-003 Phase 1):
  accepts either the new ``argus.admin.session`` cookie / bearer token
  (CSPRNG opaque ids hashed at-rest, see :mod:`auth.admin_sessions`) or
  the legacy ``X-Admin-Key`` shim. The mode is governed by
  :data:`settings.admin_auth_mode` (``"cookie" | "session" | "both"``).
* :func:`require_admin_mfa_passed` — C7-T03 policy gate. Sits on top of
  :func:`require_admin` and additionally enforces a fresh MFA proof for
  the configured roles (``ADMIN_MFA_ENFORCE_ROLES``). Routes that mutate
  user/tenant/role state or expose secrets opt in by depending on this
  function instead of :func:`require_admin`.

Why one module? :func:`require_admin_mfa_passed` is implemented as a
FastAPI dependency on top of :func:`require_admin` (``Depends(...)``).
Co-locating both functions avoids a circular import that would otherwise
arise between ``api.routers.admin`` (the historic home of the gate) and
this module (the MFA hardening layer). For backwards compatibility,
:mod:`api.routers.admin` re-exports :func:`require_admin` and the
helpers below, so every existing
``from src.api.routers.admin import require_admin`` keeps working.

Threat-model summary for the MFA gate
-------------------------------------
The C7-T03 gate makes two orthogonal checks (each short-circuits on its
own outcome):

1. **Enrollment gate.** When the operator's role is in
   :data:`Settings.admin_mfa_enforce_roles` (env-driven, default
   ``["super-admin"]``) and the underlying ``AdminUser.mfa_enabled``
   flag is False, the gate raises **403 + ``X-MFA-Enrollment-Required:
   true``** with detail ``"mfa_enrollment_required"``. A freshly
   bootstrapped super-admin therefore cannot reach a write surface
   without first walking through ``/api/v1/auth/admin/mfa/enroll`` +
   ``/confirm``.

2. **Reauthentication freshness gate.** When the user is
   MFA-enabled, the gate looks up the active session row's
   ``mfa_passed_at`` (set by :func:`admin_mfa.mark_session_mfa_passed`
   on a successful ``/verify`` or ``/confirm``). If the timestamp is
   ``NULL`` or older than
   :data:`Settings.admin_mfa_reauth_window_seconds`, the gate raises
   **401 + ``X-MFA-Required: true``** with detail ``"mfa_required"``.
   The handler-side audit log line carries
   ``argus.auth.admin_mfa.gate_blocked`` so SecOps can correlate the
   bounce with the operator's session.

Bypass surface (intentional)
----------------------------
* **Empty enforcement set** — if ``ADMIN_MFA_ENFORCE_ROLES`` is set to
  the empty string the gate degrades to a no-op. A WARNING is logged
  exactly once at process startup via :func:`log_mfa_enforcement_state`
  so an operator-induced misconfiguration does not silently disable the
  security control.
* **Legacy ``X-Admin-Key`` shim** — when the request authenticates via
  the legacy key (no session principal on ``request.state``), there is
  no ``mfa_passed_at`` to consult and the gate cannot enforce MFA. The
  request is allowed through to keep the dual-mode bridge intact;
  operators who want strict MFA must switch ``ADMIN_AUTH_MODE`` away
  from the ``"both"`` fallback.

Response shape
--------------
The two failure paths return the standard FastAPI error envelope::

    HTTP/1.1 401 Unauthorized
    X-MFA-Required: true
    Content-Type: application/json

    {"detail": "mfa_required"}

and::

    HTTP/1.1 403 Forbidden
    X-MFA-Enrollment-Required: true
    Content-Type: application/json

    {"detail": "mfa_enrollment_required"}

Both detail strings are *machine codes* (snake_case, no PII, no role
names) so the frontend can branch on them without parsing English.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Final, NoReturn

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth.admin_sessions import (
    SessionPrincipal,
    hash_session_token,
    is_session_pepper_configured,
    redact_session_id,
    resolve_session,
)
from src.core.config import settings
from src.db.models import AdminSession, AdminUser
from src.db.session import async_session_factory, get_db

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# require_admin (dual-mode) + helpers — moved here from
# ``src.api.routers.admin`` in C7-T03 to break the circular import that
# would otherwise arise between admin.py and the MFA gate. Public names
# are re-exported from ``src.api.routers.admin`` for backwards
# compatibility (every existing
# ``from src.api.routers.admin import require_admin`` keeps working).
# ---------------------------------------------------------------------------


admin_key_header = APIKeyHeader(name="X-Admin-Key", auto_error=False)

#: Cookie carrying the new CSPRNG admin session id (mirrors admin_auth router).
_ADMIN_SESSION_COOKIE: Final[str] = "argus.admin.session"

#: Bearer prefix in the ``Authorization`` header (case-insensitive comparison).
_BEARER_PREFIX_LOWER: Final[str] = "bearer "

#: Generic 401 detail for the new session-mode rejections — never leaks the
#: failure reason. The legacy fallback path keeps the historic
#: ``"Invalid X-Admin-Key"`` detail to avoid breaking existing test contracts.
_SESSION_AUTH_DETAIL: Final[str] = "Authentication required"


def _bearer_session_from_authorization(authorization: str | None) -> str | None:
    """Extract a session id from ``Authorization: Bearer <session>``."""
    if not authorization:
        return None
    raw = authorization.strip()
    if len(raw) < len(_BEARER_PREFIX_LOWER):
        return None
    if raw[: len(_BEARER_PREFIX_LOWER)].lower() != _BEARER_PREFIX_LOWER:
        return None
    candidate = raw[len(_BEARER_PREFIX_LOWER) :].strip()
    return candidate or None


def _extract_session_id(request: Request) -> str | None:
    """Return the presented session id (cookie wins over bearer) or ``None``."""
    cookie_value = request.cookies.get(_ADMIN_SESSION_COOKIE)
    if cookie_value:
        return cookie_value
    return _bearer_session_from_authorization(request.headers.get("authorization"))


async def _try_resolve_admin_session(
    request: Request,
) -> SessionPrincipal | None:
    """Resolve the session against the DB in a self-contained transaction.

    A dedicated ``async_session_factory()`` scope keeps the resolver out
    of the route's own ``get_db`` lifecycle: the sliding-window
    ``UPDATE`` is committed even when the route handler aborts mid-
    flight (4xx / 5xx), so a long-lived browser session does not
    silently expire because of an unrelated business-logic failure
    further down the dependency chain.
    """
    session_id = _extract_session_id(request)
    if not session_id:
        return None
    try:
        async with async_session_factory() as db:
            principal = await resolve_session(
                db,
                session_id=session_id,
                ip=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
            )
            await db.commit()
            return principal
    except SQLAlchemyError:
        logger.exception(
            "admin_session_resolve_db_error",
            extra={
                "event": "argus.auth.admin_session.resolve_db_error",
                "session_id_prefix": redact_session_id(session_id),
            },
        )
        return None


def _legacy_admin_key_check(admin_key: str | None) -> None:
    """Enforce the legacy ``X-Admin-Key`` shim — historic error wording.

    Preserves the exact ``"Invalid X-Admin-Key"`` 401 detail and the
    ``"ADMIN_API_KEY not configured"`` 403 detail because numerous
    existing unit tests assert on the literal strings (search references
    in ``backend/tests/unit/api/test_admin_*``).
    """
    expected = settings.admin_api_key
    if not expected:
        if settings.debug:
            return
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="ADMIN_API_KEY not configured",
        )
    if not admin_key or admin_key != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid X-Admin-Key",
        )


async def require_admin(
    request: Request,
    admin_key: str | None = Depends(admin_key_header),
) -> None:
    """Dual-mode admin gate (ISS-T20-003 Phase 1 backend, B6-T08).

    Supports three modes via :data:`settings.admin_auth_mode`:

    * ``"cookie"`` — *legacy* path only. Accepts the ``X-Admin-Key``
      shim and rejects everything else. Kept for the bridge window
      before the frontend (B6-T09) is migrated.
    * ``"session"`` — *new* path only. Accepts the
      ``argus.admin.session`` cookie or an
      ``Authorization: Bearer <session>`` header. Returns 401 with the
      generic :data:`_SESSION_AUTH_DETAIL` for every miss (no
      enumeration).
    * ``"both"`` (default) — try the new session first; if the resolver
      returns ``None`` (no cookie, expired, revoked) **and** the caller
      supplied an ``X-Admin-Key``, fall back to the legacy shim. Falls
      through to the legacy code path on missing session, so existing
      ``X-Admin-Key`` clients keep working without code change.

    On a successful session resolve the principal is stashed at
    ``request.state.admin_session`` so downstream dependencies (for
    example :func:`src.api.routers.admin_bulk_ops._operator_subject_dep`)
    can use the *real* operator subject for audit attribution instead of
    the best-effort ``X-Operator-Subject`` header.
    """
    mode = settings.admin_auth_mode

    if mode in ("session", "both"):
        principal = await _try_resolve_admin_session(request)
        if principal is not None:
            request.state.admin_session = principal
            return

    if mode == "session":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=_SESSION_AUTH_DETAIL,
        )

    _legacy_admin_key_check(admin_key)


# ---------------------------------------------------------------------------
# require_admin_mfa_passed (C7-T03)
# ---------------------------------------------------------------------------


#: Detail code emitted on stale ``mfa_passed_at`` (or NULL on an enabled
#: account). Matches the snake_case convention used everywhere else in
#: the admin surface (``mfa_already_enabled``, ``invalid_totp``, etc.).
_DETAIL_MFA_REQUIRED: Final[str] = "mfa_required"

#: Detail code emitted when the operator's role demands MFA but the
#: account is not yet enrolled. Forces a trip through the enrolment
#: ceremony before any sensitive call lands.
_DETAIL_MFA_ENROLLMENT_REQUIRED: Final[str] = "mfa_enrollment_required"

#: Header name for the freshness-gate signal — the frontend reads it to
#: decide whether to surface a re-auth prompt vs. an enrolment prompt.
_HEADER_MFA_REQUIRED: Final[str] = "X-MFA-Required"
_HEADER_MFA_ENROLLMENT_REQUIRED: Final[str] = "X-MFA-Enrollment-Required"


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _normalize_enforce_role(raw: str) -> str:
    """Map the loose role spelling to the canonical taxonomy.

    Mirrors :func:`src.auth.admin_sessions._normalize_role` but never
    raises — unknown roles are returned as-is so a typo in the env var
    surfaces as "no users match" instead of a startup crash. The
    canonical hyphen form (``super-admin``) is what session principals
    carry, so the equality check below is always against that form.
    """
    candidate = (raw or "").strip().lower()
    if candidate in {"super_admin", "superadmin", "super-admin"}:
        return "super-admin"
    return candidate


def _enforcement_roles() -> frozenset[str]:
    """Return the canonicalised enforcement role set from settings."""
    return frozenset(_normalize_enforce_role(r) for r in settings.admin_mfa_enforce_roles if r)


def log_mfa_enforcement_state() -> None:
    """Emit a one-shot startup log line describing the gate's posture.

    Called from :func:`backend.main.lifespan` so an operator running
    with ``ADMIN_MFA_ENFORCE_ROLES`` empty sees a WARNING in the boot
    log instead of silently shipping with the gate disabled. The non-
    empty path is logged at INFO so the SIEM has a deterministic
    fingerprint of the enforcement scope.
    """
    roles = sorted(_enforcement_roles())
    if not roles:
        logger.warning(
            "admin_mfa_enforcement_disabled",
            extra={
                "event": "argus.auth.admin_mfa.enforcement_disabled",
                "reason": "empty_enforce_roles",
                "reauth_window_seconds": settings.admin_mfa_reauth_window_seconds,
            },
        )
        return
    logger.info(
        "admin_mfa_enforcement_enabled",
        extra={
            "event": "argus.auth.admin_mfa.enforcement_enabled",
            "enforced_roles": roles,
            "reauth_window_seconds": settings.admin_mfa_reauth_window_seconds,
        },
    )


async def _load_admin_mfa_enabled(db: AsyncSession, subject: str) -> bool:
    """Look up ``mfa_enabled`` for *subject*; ``False`` on miss / DB error.

    A missing ``admin_users`` row is treated as "not enrolled" because
    the session principal already proved the subject exists; the
    deployment anomaly is logged but does not crash the request loop.
    A hard DB error is also treated as "not enrolled" so the gate
    fails closed (the 403 enrolment-required path is the safer of the
    two error responses — it won't lock out a fresh-MFA operator).
    """
    stmt = select(AdminUser.mfa_enabled).where(AdminUser.subject == subject)
    try:
        result = await db.execute(stmt)
    except SQLAlchemyError:
        logger.exception(
            "admin_mfa_gate_lookup_db_error",
            extra={
                "event": "argus.auth.admin_mfa.gate_lookup_db_error",
                "subject": subject,
            },
        )
        return False
    enabled = result.scalar_one_or_none()
    if enabled is None:
        return False
    return bool(enabled)


async def _load_session_mfa_passed_at(
    db: AsyncSession,
    *,
    raw_session_id: str,
) -> datetime | None:
    """Return ``mfa_passed_at`` for the active (non-revoked) session row.

    Returns ``None`` when the session id resolves to no row (revoked,
    expired, or pepper-misconfigured), which the caller treats as
    "MFA never satisfied" and surfaces the standard 401.
    """
    if not is_session_pepper_configured():
        return None
    try:
        token_hash = hash_session_token(raw_session_id)
    except ValueError:
        return None
    stmt = (
        select(AdminSession.mfa_passed_at)
        .where(AdminSession.session_token_hash == token_hash)
        .where(AdminSession.revoked_at.is_(None))
    )
    try:
        result = await db.execute(stmt)
    except SQLAlchemyError:
        logger.exception(
            "admin_mfa_gate_session_lookup_db_error",
            extra={
                "event": "argus.auth.admin_mfa.gate_session_lookup_db_error",
                "session_id_prefix": redact_session_id(raw_session_id),
            },
        )
        return None
    return result.scalar_one_or_none()


def _is_mfa_fresh(passed_at: datetime | None) -> bool:
    """Compare *passed_at* against the configured reauth window.

    ``NULL`` is treated as "never passed" → not fresh. A naive
    timestamp is coerced to UTC so a SQLite test fixture (which strips
    tz info on read) does not crash the comparison.
    """
    if passed_at is None:
        return False
    if passed_at.tzinfo is None:
        passed_at = passed_at.replace(tzinfo=timezone.utc)
    threshold = _utcnow() - timedelta(seconds=settings.admin_mfa_reauth_window_seconds)
    return passed_at >= threshold


def _raise_mfa_required(*, subject: str | None) -> NoReturn:
    logger.info(
        "admin_mfa_gate_blocked_reauth",
        extra={
            "event": "argus.auth.admin_mfa.gate_blocked",
            "reason": "stale_or_missing_mfa_passed_at",
            "subject": subject,
        },
    )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=_DETAIL_MFA_REQUIRED,
        headers={_HEADER_MFA_REQUIRED: "true"},
    )


def _raise_mfa_enrollment_required(*, subject: str | None) -> NoReturn:
    logger.info(
        "admin_mfa_gate_blocked_enrollment",
        extra={
            "event": "argus.auth.admin_mfa.gate_blocked",
            "reason": "role_requires_mfa_but_not_enrolled",
            "subject": subject,
        },
    )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=_DETAIL_MFA_ENROLLMENT_REQUIRED,
        headers={_HEADER_MFA_ENROLLMENT_REQUIRED: "true"},
    )


async def require_admin_mfa_passed(
    request: Request,
    _admin_gate: None = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Gate sensitive admin routes on a fresh MFA challenge.

    Order of checks (each one short-circuits on its own outcome):

    1. **Empty enforcement set** — degrade to no-op. The startup log
       line warned operators that the control is off.
    2. **Legacy auth path** — no ``SessionPrincipal`` on
       ``request.state`` means the caller authenticated via the
       ``X-Admin-Key`` shim; there is no session row to check. Pass
       through to keep the dual-mode bridge intact.
    3. **Role outside enforcement set** — pass through. Only the
       configured roles (e.g. ``super-admin``) are subject to the
       gate; other admins keep their existing surface unchanged.
    4. **Account not enrolled** — raise 403 with
       ``X-MFA-Enrollment-Required``. Forces an enrolment ceremony.
    5. **``mfa_passed_at`` stale or NULL** — raise 401 with
       ``X-MFA-Required``. Forces a fresh ``/verify`` against TOTP /
       backup code.
    6. **Otherwise** — pass through. The handler runs.

    The dependency runs *after* :func:`require_admin`, so the request
    has already been authenticated. We only ever escalate to a stricter
    error code; we never demote a 401 from the underlying gate.
    """
    enforce = _enforcement_roles()
    if not enforce:
        return

    principal = getattr(request.state, "admin_session", None)
    if not isinstance(principal, SessionPrincipal):
        return

    if principal.role not in enforce:
        return

    enabled = await _load_admin_mfa_enabled(db, principal.subject)
    if not enabled:
        _raise_mfa_enrollment_required(subject=principal.subject)

    raw_session_id = _extract_session_id(request)
    if not raw_session_id:
        _raise_mfa_required(subject=principal.subject)

    passed_at = await _load_session_mfa_passed_at(db, raw_session_id=raw_session_id)
    if not _is_mfa_fresh(passed_at):
        _raise_mfa_required(subject=principal.subject)


__all__ = [
    "admin_key_header",
    "log_mfa_enforcement_state",
    "require_admin",
    "require_admin_mfa_passed",
]
