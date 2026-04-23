"""Admin session lifecycle — create / revoke / resolve (ISS-T20-003 Phase 1+2c).

Design invariants
-----------------
* **Session id is opaque + CSPRNG.** ``secrets.token_urlsafe(48)`` produces
  64 URL-safe base64 chars — > 256 bits of entropy. The id is treated as a
  bearer secret by every downstream layer.
* **At-rest hashing.** The raw token never persists. Every row stores
  ``session_token_hash = HMAC-SHA256(ADMIN_SESSION_PEPPER, raw_token)``;
  resolver looks up by hash. A DB dump or read-only SQLi cannot be replayed
  without the (server-side, non-persisted) pepper. HMAC is used (not
  ``sha256(pepper||raw)``) so the construction is provably resistant to
  length-extension and matches the canonical "keyed hash" primitive
  expected by ops/SecOps tooling. See Alembic 030.
* **Lookup is constant-time.** ``hmac.compare_digest`` guards the equality
  check against timing oracles. Even though we look up by an indexed unique
  column, the resolver re-validates equality of the persisted hash against
  the freshly computed hash before treating the row as a hit.
* **Sliding window TTL.** Each successful resolution extends both
  ``last_used_at`` and ``expires_at`` to ``now() + ADMIN_SESSION_TTL_SECONDS``
  so an active operator never gets logged out mid-flow.
* **No PII in the row.** Raw IP / User-Agent never touch the database — we
  store sha256 fingerprints (``ip_hash``, ``user_agent_hash``) for forensic
  correlation. The hashes are not used in any equality check; they exist to
  let the audit team pin a session to a specific client without storing the
  client identifier in clear.
* **Tombstone-only revocation.** ``revoked_at`` is set on logout / admin
  revoke; the row is not deleted so audit trails stay intact. The resolver
  refuses any row with a non-NULL ``revoked_at``.
* **Logging discipline.** The full session id is NEVER logged. Every log
  line uses :func:`redact_session_id` (first 6 chars + ``"..."``) so a leaked
  log file cannot be replayed as a valid cookie.
* **Fail-safe.** When ``ADMIN_SESSION_PEPPER`` is unset, session-mode logins
  refuse with a clear error and the resolver returns ``None``. Cookie-mode
  (``X-Admin-Key`` shim) keeps working so a forgotten config knob never
  bricks admin access entirely.

Post Alembic 031 — single resolution path
-----------------------------------------
The 030 → 031 grace window has been closed (C7-T07 / ISS-T20-003 Phase 2c).
The legacy raw ``session_id`` column is dropped; ``session_token_hash`` is
the sole primary key. Both code paths previously gated by
``ADMIN_SESSION_LEGACY_RAW_WRITE`` / ``ADMIN_SESSION_LEGACY_RAW_FALLBACK``
have been removed: ``create_session`` writes only the hash, ``revoke_session``
and ``resolve_session`` look up only by hash, and there is no opportunistic
backfill. Any session minted before Alembic 030 (``session_token_hash``
NULL) was unreachable post-031 and must be re-issued.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Final, cast

from sqlalchemy import CursorResult, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.db.models import AdminSession

logger = logging.getLogger(__name__)

#: Number of CSPRNG bytes consumed per session id (URL-safe base64 → ~64 chars).
_SESSION_ID_BYTES: Final[int] = 48

#: Closed taxonomy for the role column — mirrored in ``admin_users.role``
#: and the ``X-Admin-Role`` header on legacy admin routes.
ALLOWED_ROLES: Final[frozenset[str]] = frozenset(
    {"operator", "admin", "super-admin"}
)

#: Number of leading chars retained when redacting a session id for logs.
_REDACT_PREFIX_LEN: Final[int] = 6


@dataclass(frozen=True, slots=True)
class SessionPrincipal:
    """Resolved admin session — what the request handler is allowed to see.

    Intentionally stripped: the raw ``session_id`` is NOT carried here so a
    handler that accidentally logs the principal cannot leak the bearer
    secret. ``ip_hash`` / ``user_agent_hash`` are also withheld — the
    handler has no business comparing them.
    """

    subject: str
    role: str
    tenant_id: str | None
    expires_at: datetime
    created_at: datetime
    last_used_at: datetime


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _sha256_hex(value: str | None) -> str:
    """Stable 64-char sha256 fingerprint of *value* (forensic only)."""
    raw = (value or "").encode("utf-8", errors="replace")
    return hashlib.sha256(raw).hexdigest()


def redact_session_id(session_id: str | None) -> str:
    """Render a session id safe for logs — first 6 chars + ``...``.

    Returns ``"<empty>"`` when the id is missing so the log line stays
    grep-able even on early-return failure paths.
    """
    if not session_id:
        return "<empty>"
    return session_id[:_REDACT_PREFIX_LEN] + "..."


def generate_session_id() -> str:
    """Mint a fresh CSPRNG session id (~64 chars, URL-safe base64)."""
    return secrets.token_urlsafe(_SESSION_ID_BYTES)


def is_session_pepper_configured() -> bool:
    """Return True iff ``ADMIN_SESSION_PEPPER`` is configured (non-empty)."""
    return bool((settings.admin_session_pepper or "").strip())


def hash_session_token(raw_token: str) -> str:
    """Hash *raw_token* with the server pepper using HMAC-SHA256.

    Returns ``HMAC-SHA256(pepper, raw_token).hexdigest()`` — 64 hex chars,
    the canonical at-rest form for ``admin_sessions.session_token_hash``.
    HMAC (not naive ``sha256(pepper||raw)``) is used so the primitive is
    provably resistant to length-extension and matches the keyed-hash
    construction expected by SecOps tooling.

    Raises :class:`ValueError` when the pepper is empty so callers fail
    loudly at session-create time. The resolver path uses
    :func:`is_session_pepper_configured` to short-circuit gracefully so a
    missing pepper never crashes the request loop — it just declines
    session-mode auth.
    """
    if not raw_token:
        raise ValueError("raw_token must be non-empty")
    pepper = (settings.admin_session_pepper or "").strip()
    if not pepper:
        raise ValueError(
            "ADMIN_SESSION_PEPPER is unset — refuse to create or resolve "
            "session without an at-rest pepper (ISS-T20-003 hardening)."
        )
    return hmac.new(
        pepper.encode("utf-8"),
        raw_token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _normalize_role(role: str) -> str:
    """Map the loose role spelling to the canonical taxonomy.

    Raises :class:`ValueError` for anything outside :data:`ALLOWED_ROLES` so
    a misconfigured caller fails loudly at session-create time, not later
    when a guard tries to enforce it.
    """
    if not role or not role.strip():
        raise ValueError("role must be non-empty")
    candidate = role.strip().lower()
    if candidate in {"super_admin", "superadmin", "super-admin"}:
        candidate = "super-admin"
    if candidate not in ALLOWED_ROLES:
        raise ValueError(f"unknown admin role: {role!r}")
    return candidate


def _normalize_tenant_id(tenant_id: str | None) -> str | None:
    if tenant_id is None:
        return None
    candidate = tenant_id.strip()
    return candidate or None


async def create_session(
    db: AsyncSession,
    *,
    subject: str,
    role: str,
    tenant_id: str | None,
    ip: str | None,
    user_agent: str | None,
    ttl_seconds: int | None = None,
) -> tuple[str, AdminSession]:
    """Mint a fresh session row and return ``(session_id, AdminSession)``.

    The caller is responsible for committing the session (``db.commit()``);
    this function only ``add()``-s the row so the surrounding transaction
    can include the audit-log entry in the same atomic write.

    ``ttl_seconds`` overrides ``settings.admin_session_ttl_seconds`` —
    primarily useful in tests that need to assert sliding-window math
    without waiting on a 12 h clock.
    """
    if not subject or not subject.strip():
        raise ValueError("subject must be non-empty")
    canonical_subject = subject.strip()
    canonical_role = _normalize_role(role)
    canonical_tenant = _normalize_tenant_id(tenant_id)

    ttl = ttl_seconds if ttl_seconds is not None else settings.admin_session_ttl_seconds
    if ttl <= 0:
        raise ValueError("ttl_seconds must be positive")

    session_id = generate_session_id()
    token_hash = hash_session_token(session_id)
    now = _utcnow()
    expires_at = now + timedelta(seconds=ttl)

    row = AdminSession(
        session_token_hash=token_hash,
        subject=canonical_subject,
        role=canonical_role,
        tenant_id=canonical_tenant,
        created_at=now,
        expires_at=expires_at,
        last_used_at=now,
        ip_hash=_sha256_hex(ip),
        user_agent_hash=_sha256_hex(user_agent),
        revoked_at=None,
    )
    db.add(row)

    logger.info(
        "admin_session_created",
        extra={
            "event": "argus.auth.admin_session.created",
            "session_id_prefix": redact_session_id(session_id),
            "role": canonical_role,
            "tenant_id_present": canonical_tenant is not None,
            "ttl_seconds": ttl,
        },
    )
    return session_id, row


async def revoke_session(
    db: AsyncSession,
    *,
    session_id: str,
) -> bool:
    """Set ``revoked_at = now()`` for *session_id* if not already revoked.

    Returns ``True`` when a row was tombstoned, ``False`` when the row was
    missing or already revoked. Idempotent — calling twice on the same id
    is a no-op on the second call. Callers commit the transaction.

    Lookup is by ``session_token_hash`` only — the legacy raw ``session_id``
    column was dropped in Alembic 031 (C7-T07 / ISS-T20-003 Phase 2c). When
    the pepper is unset (so no hash can be computed) the call is a safe
    no-op so a misconfigured deploy does not crash the request loop.
    """
    if not session_id or not is_session_pepper_configured():
        return False

    try:
        token_hash = hash_session_token(session_id)
    except ValueError:
        return False

    now = _utcnow()
    stmt = (
        update(AdminSession)
        .where(
            AdminSession.session_token_hash == token_hash,
            AdminSession.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )
    # ``cast``: SQLAlchemy 2.x returns ``Result[Any]`` from ``execute()``,
    # but UPDATE statements always materialise a ``CursorResult`` whose
    # ``.rowcount`` reports affected rows. Mypy needs the down-cast.
    result = cast(CursorResult[Any], await db.execute(stmt))
    revoked = (result.rowcount or 0) > 0

    logger.info(
        "admin_session_revoked",
        extra={
            "event": "argus.auth.admin_session.revoked",
            "session_id_prefix": redact_session_id(session_id),
            "tombstoned": revoked,
        },
    )
    return revoked


async def resolve_session(
    db: AsyncSession,
    *,
    session_id: str | None,
    ip: str | None = None,
    user_agent: str | None = None,
    ttl_seconds: int | None = None,
) -> SessionPrincipal | None:
    """Look up *session_id*, validate, and (on hit) slide the TTL forward.

    Returns ``None`` when the session is missing, expired, revoked, or
    fails the constant-time equality check. The caller MUST treat ``None``
    as "unauthenticated" without further introspection — every "why"
    branch is logged here so the handler does not need to differentiate.

    On a hit the row's ``last_used_at`` and ``expires_at`` are pushed
    forward to ``now() + ttl`` (sliding window). The caller commits.

    ``ip`` and ``user_agent`` are accepted for symmetry with
    :func:`create_session` but are NOT compared against the stored hashes.
    Mobile / corporate-NAT clients legitimately rotate IPs mid-session;
    binding the session to ``ip_hash`` would force log-outs every commute.
    The hashes remain a *forensic* surrogate, not an enforcement key.
    """
    if not session_id:
        return None

    ttl = ttl_seconds if ttl_seconds is not None else settings.admin_session_ttl_seconds
    now = _utcnow()

    row = await _lookup_session_row(db, session_id)
    if row is None:
        logger.info(
            "admin_session_resolve_miss",
            extra={
                "event": "argus.auth.admin_session.resolve_miss",
                "session_id_prefix": redact_session_id(session_id),
                "reason": "not_found",
            },
        )
        return None

    if row.revoked_at is not None:
        logger.info(
            "admin_session_resolve_miss",
            extra={
                "event": "argus.auth.admin_session.resolve_miss",
                "session_id_prefix": redact_session_id(session_id),
                "reason": "revoked",
            },
        )
        return None

    expires_at = _ensure_aware(row.expires_at)
    if expires_at <= now:
        logger.info(
            "admin_session_resolve_miss",
            extra={
                "event": "argus.auth.admin_session.resolve_miss",
                "session_id_prefix": redact_session_id(session_id),
                "reason": "expired",
            },
        )
        return None

    new_expires_at = now + timedelta(seconds=ttl)
    update_stmt = (
        update(AdminSession)
        .where(AdminSession.session_token_hash == row.session_token_hash)
        .values(last_used_at=now, expires_at=new_expires_at)
    )
    await db.execute(update_stmt)

    logger.debug(
        "admin_session_resolved",
        extra={
            "event": "argus.auth.admin_session.resolved",
            "session_id_prefix": redact_session_id(session_id),
            "role": row.role,
            "tenant_id_present": row.tenant_id is not None,
        },
    )

    return SessionPrincipal(
        subject=row.subject,
        role=row.role,
        tenant_id=row.tenant_id,
        expires_at=new_expires_at,
        created_at=_ensure_aware(row.created_at),
        last_used_at=now,
    )


async def _lookup_session_row(
    db: AsyncSession, session_id: str
) -> AdminSession | None:
    """Return the session row matching *session_id*, or ``None``.

    Lookup is by ``session_token_hash`` only — the legacy raw ``session_id``
    column was dropped in Alembic 031. Returns ``None`` when the pepper is
    unset (resolver is then permanently miss-only by construction) or when
    no row matches.

    Defence-in-depth: ``hmac.compare_digest`` re-validates equality of the
    persisted hash against the freshly computed hash, so an ORM-cache or
    dialect quirk cannot turn a coincidental hit into a timing oracle.
    """
    if not is_session_pepper_configured():
        return None
    try:
        token_hash = hash_session_token(session_id)
    except ValueError:
        return None
    stmt = select(AdminSession).where(
        AdminSession.session_token_hash == token_hash
    )
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None:
        return None
    if row.session_token_hash and hmac.compare_digest(
        row.session_token_hash, token_hash
    ):
        return row
    logger.warning(
        "admin_session_resolve_mismatch",
        extra={
            "event": "argus.auth.admin_session.resolve_mismatch",
            "session_id_prefix": redact_session_id(session_id),
        },
    )
    return None


def _ensure_aware(dt: datetime) -> datetime:
    """Return *dt* with UTC tzinfo when it was loaded as naive (SQLite)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
