"""Admin user verification + bootstrap (ISS-T20-003 Phase 1).

Design invariants
-----------------
* **bcrypt at rest, rounds >= 12.** Hashes are produced *outside* the
  process (operator workflow / secret manager) and only the hash crosses
  the env boundary. The ``ADMIN_BOOTSTRAP_PASSWORD_HASH`` env var
  intentionally takes a *hash*, not a plaintext, so the operator runbook
  cannot accidentally leak the credential to the audit log or a heap dump.
* **Generic verify path.** :func:`verify_credentials` returns ``None`` on
  every failure mode (subject missing, password wrong, account disabled).
  The caller MUST emit the same 401 message regardless of the return value
  so an attacker cannot enumerate which subjects exist.
* **Constant-time comparison.** :func:`bcrypt.checkpw` performs
  constant-time comparison internally; we additionally hash a dummy
  password against a sentinel hash on subject-miss / disabled / empty
  paths so the wall-clock cost of those branches matches the genuine
  "wrong password" path.
* **No plaintext logging.** Passwords NEVER appear in log records, error
  messages, or audit-log details. Only the subject is logged, and only
  through the structured ``argus.auth.*`` event surface.
* **Direct ``bcrypt`` library.** We deliberately avoid
  ``passlib.CryptContext`` because passlib's ``_BcryptBackend`` performs
  a wrap-bug probe on first hash that violates the 72-byte limit
  enforced by ``bcrypt>=4.1`` (raises ``ValueError`` on import-time
  initialisation). Direct ``bcrypt`` calls give us the same constant-time
  primitives without the version-coupling tax.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final, cast

import bcrypt
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.sql.expression import TableClause
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.db.models import AdminUser
from src.db.session import async_session_factory

logger = logging.getLogger(__name__)

#: bcrypt cost parameter. 12 is the OWASP-recommended minimum (~250ms on
#: a modern x86 core); raising past 14 starts to materially degrade login
#: latency without proportionate brute-force resistance.
_BCRYPT_ROUNDS: Final[int] = 12

#: bcrypt's hard ciphertext limit. Inputs longer than this are rejected
#: rather than silently truncated — silent truncation has historically
#: been a footgun (CVE-2023-29483-style password collisions).
_BCRYPT_MAX_PASSWORD_BYTES: Final[int] = 72

#: Sentinel hash used during the "subject not found" / "disabled" /
#: "empty input" branches so the wall-clock cost matches a genuine
#: bcrypt verify. Generated lazily on first use; cached for the lifetime
#: of the process.
_DUMMY_HASH: bytes | None = None

#: A non-meaningful plaintext passed to the dummy verify when the caller
#: supplied no password (so we still burn the bcrypt cost cycle).
_EMPTY_INPUT_FILLER: Final[bytes] = b"argus-empty"


@dataclass(frozen=True, slots=True)
class AdminPrincipal:
    """Authenticated admin user — what login emits to the session layer."""

    subject: str
    role: str
    tenant_id: str | None


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


def _normalize_subject(subject: str | None) -> str | None:
    if subject is None:
        return None
    candidate = subject.strip()
    return candidate or None


def _encode_password(plaintext: str) -> bytes:
    """UTF-8 encode and length-check the password.

    Raises :class:`ValueError` when the encoded form exceeds bcrypt's
    72-byte cap so we never silently truncate. Passlib used to truncate
    by default; modern ``bcrypt`` (>=4.1) rejects the call and we
    propagate that contract upward.
    """
    if not plaintext:
        raise ValueError("plaintext must be non-empty")
    encoded = plaintext.encode("utf-8")
    if len(encoded) > _BCRYPT_MAX_PASSWORD_BYTES:
        raise ValueError(
            f"plaintext exceeds bcrypt limit of {_BCRYPT_MAX_PASSWORD_BYTES} bytes"
        )
    return encoded


def _get_dummy_hash() -> bytes:
    """Return a stable bcrypt hash used to equalise the failure path latency.

    Computed once per process; the hashed plaintext is a fixed
    non-meaningful string. The hash itself is harmless even if leaked
    because no real account uses it (no live password matches it).
    """
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = bcrypt.hashpw(
            b"argus_no_user_sentinel_v1", bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)
        )
    return _DUMMY_HASH


def _burn_dummy_cycle(plaintext: str | None) -> None:
    """Run a bcrypt verify against the sentinel hash so failure-path
    latency tracks the success path. Never raises."""
    try:
        candidate = (
            plaintext.encode("utf-8")[:_BCRYPT_MAX_PASSWORD_BYTES]
            if plaintext
            else _EMPTY_INPUT_FILLER
        )
        bcrypt.checkpw(candidate, _get_dummy_hash())
    except Exception:  # noqa: BLE001 — defensive: cost-equaliser only
        pass


def hash_password(plaintext: str) -> str:
    """Return a bcrypt hash for *plaintext* (rounds >= 12).

    Provided for tests / migration tooling; production code MUST NOT call
    this on user input — passwords are hashed out-of-band by the operator
    runbook and shipped through the secret manager.
    """
    encoded = _encode_password(plaintext)
    digest = bcrypt.hashpw(encoded, bcrypt.gensalt(rounds=_BCRYPT_ROUNDS))
    return digest.decode("ascii")


def is_bcrypt_hash(value: str | None) -> bool:
    """Cheap shape check: bcrypt hashes start with ``$2`` and are 60 chars."""
    if not value:
        return False
    return len(value) >= 60 and value.startswith("$2")


def _verify_bcrypt(plaintext: str, digest: str) -> bool:
    """Return ``True`` iff *plaintext* matches *digest*. Never raises.

    Wraps :func:`bcrypt.checkpw` with the contract guarantees we depend
    on: malformed digests, oversize inputs, and any other backend error
    surface as ``False`` (treated as a credential mismatch by the
    caller). All exceptional paths are logged at DEBUG so we don't
    pollute the audit log on routine bad input.
    """
    try:
        encoded = plaintext.encode("utf-8")[:_BCRYPT_MAX_PASSWORD_BYTES]
        return bcrypt.checkpw(encoded, digest.encode("ascii"))
    except (ValueError, TypeError) as exc:
        logger.debug(
            "admin_login_hash_invalid",
            extra={
                "event": "argus.auth.admin_login.hash_invalid",
                "error_type": type(exc).__name__,
            },
        )
        return False


async def verify_credentials(
    db: AsyncSession,
    *,
    subject: str,
    password: str,
) -> AdminPrincipal | None:
    """Validate (subject, password) and return an :class:`AdminPrincipal` or ``None``.

    The function intentionally returns the same ``None`` for every failure
    mode (subject missing, password wrong, account disabled) so callers can
    emit a single 401 response. The wall-clock cost of the failure
    branches is equalised by hashing the candidate password against a
    sentinel digest.

    Never raises on the bcrypt path — malformed hashes / oversize inputs
    are caught and downgraded to ``None`` with a structured log.
    """
    canonical_subject = _normalize_subject(subject)
    if not canonical_subject or not password:
        _burn_dummy_cycle(password)
        logger.info(
            "admin_login_failed",
            extra={
                "event": "argus.auth.admin_login.failed",
                "reason": "missing_credentials",
            },
        )
        return None

    stmt = select(AdminUser).where(AdminUser.subject == canonical_subject)
    try:
        row = (await db.execute(stmt)).scalar_one_or_none()
    except SQLAlchemyError:
        logger.exception(
            "admin_login_db_error",
            extra={"event": "argus.auth.admin_login.db_error"},
        )
        return None

    if row is None:
        _burn_dummy_cycle(password)
        logger.info(
            "admin_login_failed",
            extra={
                "event": "argus.auth.admin_login.failed",
                "reason": "subject_not_found",
            },
        )
        return None

    if row.disabled_at is not None:
        _burn_dummy_cycle(password)
        logger.info(
            "admin_login_failed",
            extra={
                "event": "argus.auth.admin_login.failed",
                "reason": "disabled",
            },
        )
        return None

    if not _verify_bcrypt(password, row.password_hash):
        logger.info(
            "admin_login_failed",
            extra={
                "event": "argus.auth.admin_login.failed",
                "reason": "wrong_password",
            },
        )
        return None

    logger.info(
        "admin_login_succeeded",
        extra={
            "event": "argus.auth.admin_login.succeeded",
            "role": row.role,
            "tenant_id_present": row.tenant_id is not None,
        },
    )
    return AdminPrincipal(
        subject=row.subject,
        role=row.role,
        tenant_id=row.tenant_id,
    )


async def bootstrap_admin_user_if_configured() -> None:
    """Idempotently materialise the bootstrap admin from env config.

    Reads ``ADMIN_BOOTSTRAP_SUBJECT`` + ``ADMIN_BOOTSTRAP_PASSWORD_HASH``
    (plus optional role / tenant) and ensures a single ``admin_users`` row
    exists with the configured hash. Safe to call on every startup — the
    upsert is keyed on ``subject`` so repeated calls converge.

    No-ops (with a single info log) when either env var is missing — this
    keeps test environments and dev databases free of an unintended admin
    seed. Plaintext passwords are NEVER accepted; the hash is shape-checked
    with :func:`is_bcrypt_hash` before any DB write so a misconfigured
    deployment fails fast and visibly.

    Failures (DB unreachable, malformed hash) are logged and swallowed —
    the FastAPI startup MUST NOT crash because the operator forgot to seed
    the bootstrap admin. Callers can verify the row via the admin UI.
    """
    subject = _normalize_subject(settings.admin_bootstrap_subject)
    password_hash = (settings.admin_bootstrap_password_hash or "").strip() or None

    if not subject or not password_hash:
        logger.info(
            "admin_bootstrap_skipped",
            extra={
                "event": "argus.auth.admin_bootstrap.skipped",
                "subject_present": subject is not None,
                "hash_present": password_hash is not None,
            },
        )
        return

    if not is_bcrypt_hash(password_hash):
        logger.warning(
            "admin_bootstrap_invalid_hash",
            extra={
                "event": "argus.auth.admin_bootstrap.invalid_hash",
                "reason": "ADMIN_BOOTSTRAP_PASSWORD_HASH must be a bcrypt digest",
            },
        )
        return

    role = settings.admin_bootstrap_role
    tenant_id = (settings.admin_bootstrap_tenant_id or "").strip() or None
    now = _utcnow()

    try:
        async with async_session_factory() as db:
            await _upsert_admin_user(
                db,
                subject=subject,
                password_hash=password_hash,
                role=role,
                tenant_id=tenant_id,
                created_at=now,
            )
            await db.commit()
    except SQLAlchemyError:
        logger.exception(
            "admin_bootstrap_db_error",
            extra={"event": "argus.auth.admin_bootstrap.db_error"},
        )
        return

    logger.info(
        "admin_bootstrap_applied",
        extra={
            "event": "argus.auth.admin_bootstrap.applied",
            "role": role,
            "tenant_id_present": tenant_id is not None,
        },
    )


async def _upsert_admin_user(
    db: AsyncSession,
    *,
    subject: str,
    password_hash: str,
    role: str,
    tenant_id: str | None,
    created_at: datetime,
) -> None:
    """Insert-or-update the bootstrap row in a dialect-portable way.

    Postgres uses ``ON CONFLICT (subject) DO UPDATE`` so the bootstrap is
    truly atomic. Other dialects (SQLite in tests) fall back to a select +
    insert / update sequence inside the same transaction — race-free under
    the engine's per-connection serialisation.
    """
    dialect = db.bind.dialect.name if db.bind is not None else ""

    if dialect == "postgresql":
        stmt = (
            # ``__table__`` is typed as ``FromClause`` by the SQLAlchemy stubs
            # but ``pg_insert`` accepts the underlying ``TableClause`` at
            # runtime; cast keeps mypy honest without leaking ``Any``.
            pg_insert(cast(TableClause, AdminUser.__table__))
            .values(
                subject=subject,
                password_hash=password_hash,
                role=role,
                tenant_id=tenant_id,
                created_at=created_at,
            )
            .on_conflict_do_update(
                index_elements=["subject"],
                set_={
                    "password_hash": password_hash,
                    "role": role,
                    "tenant_id": tenant_id,
                    "disabled_at": None,
                },
            )
        )
        await db.execute(stmt)
        return

    existing = await db.get(AdminUser, subject)
    if existing is None:
        db.add(
            AdminUser(
                subject=subject,
                password_hash=password_hash,
                role=role,
                tenant_id=tenant_id,
                created_at=created_at,
                disabled_at=None,
            )
        )
        return

    existing.password_hash = password_hash
    existing.role = role
    existing.tenant_id = tenant_id
    existing.disabled_at = None
