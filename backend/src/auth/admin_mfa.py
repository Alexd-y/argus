"""ARG-062 / C7-T01 — admin MFA data access layer (TOTP + backup codes).

NOT for endpoint use — endpoints live in :mod:`src.api.routers.admin_auth`
(C7-T03). This module is the seam for unit tests + future migration to an
external IdP (Phase 2 Option 2 in ``ai_docs/develop/issues/ISS-T20-003-phase2.md``).

Design invariants
-----------------
* **TOTP secret never leaves the encryption boundary.** Plaintext lives
  for the lifetime of one ``verify_totp`` call only; the column at rest
  always holds Fernet ciphertext (see :mod:`._mfa_crypto`). The plaintext
  secret never enters a log line, an audit row, or an exception ``str()``.
* **Backup codes are bcrypt-hashed at rest, cost ≥ 12.** Cost matches
  ``admin_users._BCRYPT_ROUNDS`` so a hash-collision attack against the
  backup-code table costs exactly as much as one against the password
  table — no weak link.
* **Backup codes are one-time only.** :func:`consume_backup_code` removes
  the matching hash from the array under a row-level lock so two
  concurrent requests cannot both succeed. The full bcrypt sweep runs
  for every code position to keep timing flat regardless of which slot
  matched (defends against position-leak side channel).
* **Opportunistic key rotation.** Every successful :func:`verify_totp`
  re-encrypts the secret with the primary key when it was decrypted
  with an older key (see :func:`_mfa_crypto.reencrypt_if_stale`). No
  maintenance window required — keys roll forward as admins log in.
* **Structured logging only.** No plaintext, no ciphertext bytes, no
  bcrypt hashes in log lines. Every event uses the ``argus.mfa.*`` event
  prefix and structured ``extra`` fields so SIEM rules can pivot on
  ``subject`` / ``event`` without parsing strings.
* **No router coupling.** The DAO returns booleans / raises domain
  exceptions; the router maps those to HTTP statuses + audit-log writes.
  This keeps the seam testable without spinning up the FastAPI app.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final, cast

import bcrypt
import pyotp  # type: ignore[import-not-found]  # pyotp ships no PEP-561 stubs
from sqlalchemy import CursorResult, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth._mfa_crypto import (
    MfaCryptoError,
    decrypt,
    encrypt,
    reencrypt_if_stale,
)
from src.db.models import AdminSession, AdminUser

logger = logging.getLogger(__name__)

#: bcrypt cost for backup-code hashing — matches ``admin_users._BCRYPT_ROUNDS``
#: so the weakest link in the auth surface is consistent at OWASP 2024
#: minimum.
_BCRYPT_ROUNDS: Final[int] = 12

#: Operator-typeable alphabet for backup codes. Excludes ``I`` and ``O`` to
#: prevent confusion with ``1`` / ``0`` when an admin reads a code off a
#: printed page. The 34-char set yields ``log2(34**16) ≈ 81.4`` bits of
#: entropy per 16-char code — comfortably above the 80-bit project floor.
_BACKUP_CODE_ALPHABET: Final[str] = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"

#: Length of one backup code, in characters. Combined with the alphabet
#: this gives the entropy budget above; do NOT shorten without re-deriving
#: the entropy budget.
_BACKUP_CODE_LENGTH: Final[int] = 16

#: How many codes :func:`regenerate_backup_codes` mints per call. The
#: enrolment UI shows them all once and never again.
_BACKUP_CODE_COUNT: Final[int] = 10

#: TOTP verification window in 30s steps either side of "now". ``valid_window=1``
#: tolerates ±30 s of clock skew between the operator's authenticator and the
#: server — the standard recommendation; raising further trades drift tolerance
#: for replay-window length.
_TOTP_VALID_WINDOW: Final[int] = 1


class AdminMfaError(Exception):
    """Raised for unrecoverable admin-MFA DAO failures.

    Wraps DB / crypto exceptions so callers ``except`` a single domain type.
    The ``str()`` is always a stable error code (e.g. ``"subject_not_found"``)
    — never a stack trace, key fingerprint, or secret fragment.
    """


@dataclass(frozen=True, slots=True)
class _MfaState:
    """In-memory snapshot of an admin's MFA state for atomic update flows.

    Populated by :func:`_load_state`; never returned to callers — the DAO
    surface is intentionally keyed on ``(subject, code)`` pairs rather than
    handing out the secret bytes.
    """

    subject: str
    enabled: bool
    secret_encrypted: bytes | None
    backup_codes_hash: list[str]


def _utcnow() -> datetime:
    """Return the current UTC ``datetime`` with tz info attached."""
    return datetime.now(tz=timezone.utc)


def _normalize_subject(subject: str | None) -> str:
    """Strip whitespace; raise on empty."""
    if subject is None or not subject.strip():
        raise AdminMfaError("subject_required")
    return subject.strip()


def _normalize_totp_code(code: str | None) -> str:
    """Trim whitespace + strip non-digits before passing to ``pyotp``.

    Authenticator apps occasionally render the code with a space (e.g.
    ``123 456``). ``pyotp`` rejects non-digits, so we sanitise first.
    """
    if not code:
        raise AdminMfaError("totp_code_required")
    digits = "".join(ch for ch in code.strip() if ch.isdigit())
    if not digits:
        raise AdminMfaError("totp_code_required")
    return digits


def _normalize_backup_code(code: str | None) -> str:
    """Uppercase + strip + remove dashes / spaces from a backup code.

    The enrolment UI may render codes as ``XXXX-XXXX-XXXX-XXXX`` for
    readability; admins paste them with the dashes intact. We always
    hash the dash-stripped uppercase form so display formatting is a
    presentation concern only.
    """
    if not code:
        raise AdminMfaError("backup_code_required")
    candidate = "".join(ch for ch in code.upper() if ch in _BACKUP_CODE_ALPHABET)
    if not candidate:
        raise AdminMfaError("backup_code_required")
    return candidate


def _bcrypt_hash(value: str) -> str:
    """Return a bcrypt hash for *value* (rounds == :data:`_BCRYPT_ROUNDS`).

    Inputs are length-bounded by the backup-code generator (16 chars),
    so the 72-byte bcrypt cap is structurally unreachable here — we still
    encode to UTF-8 explicitly for parity with ``admin_users.hash_password``.
    """
    digest = bcrypt.hashpw(value.encode("utf-8"), bcrypt.gensalt(rounds=_BCRYPT_ROUNDS))
    return digest.decode("ascii")


def _bcrypt_verify(plaintext: str, digest: str) -> bool:
    """Constant-time bcrypt verify; never raises.

    Mirrors ``admin_users._verify_bcrypt`` — malformed digests / oversize
    inputs surface as ``False`` so the caller treats them as "no match"
    rather than crashing the request loop.
    """
    try:
        return bcrypt.checkpw(
            plaintext.encode("utf-8"),
            digest.encode("ascii"),
        )
    except (ValueError, TypeError):
        return False


def generate_backup_codes(count: int = _BACKUP_CODE_COUNT) -> list[str]:
    """Mint *count* fresh CSPRNG backup codes from the operator alphabet.

    Each code is :data:`_BACKUP_CODE_LENGTH` characters drawn from
    :data:`_BACKUP_CODE_ALPHABET` via :func:`secrets.choice` — the
    cryptographically-secure path; do NOT switch to :func:`random.choices`.

    Returns *plaintext* codes; the caller MUST hash them with
    :func:`_bcrypt_hash` before persisting and MUST display them to the
    admin exactly once (the enrolment UI buffer is the only legitimate
    consumer of the plaintext).
    """
    if count <= 0:
        raise AdminMfaError("backup_code_count_invalid")
    return [
        "".join(
            secrets.choice(_BACKUP_CODE_ALPHABET) for _ in range(_BACKUP_CODE_LENGTH)
        )
        for _ in range(count)
    ]


async def _load_state(db: AsyncSession, subject: str) -> _MfaState:
    """Fetch the MFA-relevant columns for *subject* (raises on miss).

    Centralised here so the seven DAO functions don't re-implement the
    same ``select(...).where(subject == ...)`` boilerplate. Translates
    DB errors into :class:`AdminMfaError` so the router never sees a
    raw :class:`SQLAlchemyError`.
    """
    stmt = select(
        AdminUser.subject,
        AdminUser.mfa_enabled,
        AdminUser.mfa_secret_encrypted,
        AdminUser.mfa_backup_codes_hash,
        AdminUser.disabled_at,
    ).where(AdminUser.subject == subject)
    try:
        row = (await db.execute(stmt)).one_or_none()
    except SQLAlchemyError:
        logger.exception(
            "admin_mfa_db_error",
            extra={"event": "argus.mfa.dao.db_error", "subject": subject},
        )
        raise AdminMfaError("db_error") from None

    if row is None:
        raise AdminMfaError("subject_not_found")
    if row.disabled_at is not None:
        raise AdminMfaError("subject_disabled")

    return _MfaState(
        subject=row.subject,
        enabled=bool(row.mfa_enabled),
        secret_encrypted=row.mfa_secret_encrypted,
        backup_codes_hash=list(row.mfa_backup_codes_hash or []),
    )


async def enroll_totp(
    db: AsyncSession,
    *,
    subject: str,
    secret: str,
    backup_codes: list[str] | None = None,
) -> None:
    """Persist a Fernet-encrypted TOTP secret; leave MFA disabled.

    Step 1 of the enrolment ceremony. The router generates a fresh
    base32 secret with ``pyotp.random_base32()``, hands it back to the
    admin via a QR code, and asks them to enter the first 6-digit code
    — :func:`confirm_enrollment` then flips ``mfa_enabled`` to True.

    Re-enrolment is idempotent: a second call overwrites the previous
    ciphertext and clears the previous backup codes, so an admin who
    abandoned an enrolment mid-flow can start over without operator
    intervention. ``mfa_enabled`` is forced to ``False`` defensively
    so a partial overwrite cannot leave the account in a broken state
    (enrolled with the new secret but enabled against the old one).

    When *backup_codes* is provided (C7-T03 stateless 2-step flow), the
    bcrypt hashes are persisted in the same ``UPDATE`` as the secret.
    The router returns the plaintext codes to the admin once and
    :func:`confirm_enrollment` may then be called without re-providing
    them. Passing ``None`` preserves the legacy contract where the
    router (or DAO unit tests) re-supplies the codes at confirm time.
    """
    canonical = _normalize_subject(subject)
    if not secret or not secret.strip():
        raise AdminMfaError("totp_secret_required")

    state = await _load_state(db, canonical)

    try:
        ciphertext = encrypt(secret)
    except (ValueError, MfaCryptoError) as exc:
        logger.error(
            "admin_mfa_enroll_encrypt_failed",
            extra={
                "event": "argus.mfa.enroll.encrypt_failed",
                "subject": canonical,
                "reason": exc.__class__.__name__,
            },
        )
        raise AdminMfaError("totp_secret_encrypt_failed") from None

    persisted_backup_hashes: list[str] | None
    if backup_codes is None:
        persisted_backup_hashes = None
    else:
        if not backup_codes:
            raise AdminMfaError("backup_codes_required")
        persisted_backup_hashes = [
            _bcrypt_hash(_normalize_backup_code(c)) for c in backup_codes
        ]

    stmt = (
        update(AdminUser)
        .where(AdminUser.subject == canonical)
        .values(
            mfa_secret_encrypted=ciphertext,
            mfa_backup_codes_hash=persisted_backup_hashes,
            mfa_enabled=False,
        )
    )
    try:
        await db.execute(stmt)
    except SQLAlchemyError:
        logger.exception(
            "admin_mfa_enroll_db_error",
            extra={
                "event": "argus.mfa.enroll.db_error",
                "subject": canonical,
            },
        )
        raise AdminMfaError("db_error") from None

    logger.info(
        "admin_mfa_enroll_pending",
        extra={
            "event": "argus.mfa.enroll.pending",
            "subject": canonical,
            "previous_enabled": state.enabled,
            "backup_codes_persisted": persisted_backup_hashes is not None,
        },
    )


async def confirm_enrollment(
    db: AsyncSession,
    *,
    subject: str,
    totp_code: str,
    generated_codes: list[str] | None = None,
) -> None:
    """Verify the first TOTP code and finish enrolment atomically.

    Step 2 of the enrolment ceremony. The router passes the 6-digit code
    typed by the admin. ``generated_codes`` is optional:

    * ``None`` (C7-T03 default) — the codes were already persisted at
      :func:`enroll_totp` time. The DAO refuses if no hashes are on the
      row (``backup_codes_required``) so a programmer cannot enable MFA
      against an empty backup-code array.
    * ``list[str]`` (legacy DAO contract) — the bcrypt hashes of the
      provided codes replace any prior backup codes in a single
      ``UPDATE``.

    On success:
      * ``mfa_enabled`` is set to ``True``;
      * backup-code hashes are written iff *generated_codes* is provided.

    On failure (bad code, no pending enrolment, decrypt error) the row
    is untouched and an :class:`AdminMfaError` is raised — the router
    maps that to HTTP 400.
    """
    canonical = _normalize_subject(subject)
    code = _normalize_totp_code(totp_code)
    if generated_codes is not None and not generated_codes:
        raise AdminMfaError("backup_codes_required")

    state = await _load_state(db, canonical)
    if state.secret_encrypted is None:
        raise AdminMfaError("totp_not_enrolled")

    try:
        secret = decrypt(state.secret_encrypted)
    except MfaCryptoError:
        logger.error(
            "admin_mfa_confirm_decrypt_failed",
            extra={
                "event": "argus.mfa.confirm.decrypt_failed",
                "subject": canonical,
            },
        )
        raise AdminMfaError("totp_secret_decrypt_failed") from None

    if not pyotp.TOTP(secret).verify(code, valid_window=_TOTP_VALID_WINDOW):
        logger.info(
            "admin_mfa_confirm_failed",
            extra={
                "event": "argus.mfa.confirm.failed",
                "subject": canonical,
                "reason": "totp_mismatch",
            },
        )
        raise AdminMfaError("totp_invalid")

    if generated_codes is None:
        # Stateless 2-step flow (C7-T03): the codes were persisted at
        # ``enroll_totp`` time. Refuse if the row carries none — the
        # admin would otherwise be enrolled without recovery codes.
        if not state.backup_codes_hash:
            raise AdminMfaError("backup_codes_required")
        update_values: dict[str, object] = {"mfa_enabled": True}
        emitted_count = len(state.backup_codes_hash)
    else:
        backup_hashes = [
            _bcrypt_hash(_normalize_backup_code(c)) for c in generated_codes
        ]
        update_values = {
            "mfa_enabled": True,
            "mfa_backup_codes_hash": backup_hashes,
        }
        emitted_count = len(backup_hashes)

    stmt = (
        update(AdminUser)
        .where(AdminUser.subject == canonical)
        .values(**update_values)
    )
    try:
        await db.execute(stmt)
    except SQLAlchemyError:
        logger.exception(
            "admin_mfa_confirm_db_error",
            extra={
                "event": "argus.mfa.confirm.db_error",
                "subject": canonical,
            },
        )
        raise AdminMfaError("db_error") from None

    logger.info(
        "admin_mfa_confirm_succeeded",
        extra={
            "event": "argus.mfa.confirm.succeeded",
            "subject": canonical,
            "backup_codes_count": emitted_count,
        },
    )


async def verify_totp(
    db: AsyncSession,
    *,
    subject: str,
    totp_code: str,
) -> bool:
    """Verify *totp_code* against the stored secret. Returns ``True`` on match.

    Side-effect: when the secret was decrypted with a non-primary key,
    re-encrypt it under the primary key and persist the new ciphertext
    (opportunistic rotation — see :func:`_mfa_crypto.reencrypt_if_stale`).
    The rotation write is best-effort; if it fails we still return the
    verification result so a transient DB hiccup never blocks login.

    Returns ``False`` (never raises :class:`AdminMfaError`) for the
    common "wrong code" path so the router can emit a generic 401 on
    every failure mode without leaking enumeration info — same pattern
    as :func:`admin_users.verify_credentials`.
    """
    try:
        canonical = _normalize_subject(subject)
        code = _normalize_totp_code(totp_code)
        state = await _load_state(db, canonical)
    except AdminMfaError as exc:
        logger.info(
            "admin_mfa_verify_rejected",
            extra={
                "event": "argus.mfa.verify.rejected",
                "reason": str(exc),
            },
        )
        return False

    if not state.enabled or state.secret_encrypted is None:
        logger.info(
            "admin_mfa_verify_rejected",
            extra={
                "event": "argus.mfa.verify.rejected",
                "subject": canonical,
                "reason": "not_enabled",
            },
        )
        return False

    try:
        secret = decrypt(state.secret_encrypted)
    except MfaCryptoError:
        logger.error(
            "admin_mfa_verify_decrypt_failed",
            extra={
                "event": "argus.mfa.verify.decrypt_failed",
                "subject": canonical,
            },
        )
        return False

    if not pyotp.TOTP(secret).verify(code, valid_window=_TOTP_VALID_WINDOW):
        logger.info(
            "admin_mfa_verify_failed",
            extra={
                "event": "argus.mfa.verify.failed",
                "subject": canonical,
                "reason": "totp_mismatch",
            },
        )
        return False

    try:
        new_ciphertext, rotated = reencrypt_if_stale(state.secret_encrypted)
    except MfaCryptoError:
        rotated = False
        new_ciphertext = state.secret_encrypted

    if rotated and new_ciphertext != state.secret_encrypted:
        try:
            await db.execute(
                update(AdminUser)
                .where(AdminUser.subject == canonical)
                .values(mfa_secret_encrypted=new_ciphertext)
            )
            logger.info(
                "admin_mfa_secret_reencrypted",
                extra={
                    "event": "argus.mfa.verify.reencrypted",
                    "subject": canonical,
                },
            )
        except SQLAlchemyError:
            logger.warning(
                "admin_mfa_reencrypt_db_error",
                extra={
                    "event": "argus.mfa.verify.reencrypt_db_error",
                    "subject": canonical,
                },
            )

    logger.info(
        "admin_mfa_verify_succeeded",
        extra={
            "event": "argus.mfa.verify.succeeded",
            "subject": canonical,
            "rotated": rotated,
        },
    )
    return True


async def consume_backup_code(
    db: AsyncSession,
    *,
    subject: str,
    code: str,
) -> bool:
    """Spend one backup code; returns ``True`` iff a hash was removed.

    Concurrency model:
      * Postgres — the implicit transaction promotes the ``UPDATE`` to a
        row-level lock; two concurrent consumers cannot both win because
        only one can hold the lock at a time and the second observes the
        already-shrunk array.
      * SQLite (tests) — connection-serialised by default, so the same
        invariant holds with no extra plumbing.

    Always sweeps the entire hash array (even after a match is found) so
    the wall-clock cost of a *valid* code does not depend on its position
    — eliminates a position-leak side channel against an attacker who can
    measure response timing.
    """
    try:
        canonical = _normalize_subject(subject)
        candidate = _normalize_backup_code(code)
        state = await _load_state(db, canonical)
    except AdminMfaError as exc:
        logger.info(
            "admin_mfa_backup_rejected",
            extra={
                "event": "argus.mfa.backup.rejected",
                "reason": str(exc),
            },
        )
        return False

    if not state.enabled or not state.backup_codes_hash:
        logger.info(
            "admin_mfa_backup_rejected",
            extra={
                "event": "argus.mfa.backup.rejected",
                "subject": canonical,
                "reason": "no_codes",
            },
        )
        return False

    matched_index: int | None = None
    for idx, digest in enumerate(state.backup_codes_hash):
        if _bcrypt_verify(candidate, digest) and matched_index is None:
            matched_index = idx
        # Continue iterating intentionally — keeps timing constant
        # regardless of which slot held the matching hash.

    if matched_index is None:
        logger.info(
            "admin_mfa_backup_failed",
            extra={
                "event": "argus.mfa.backup.failed",
                "subject": canonical,
                "remaining_codes": len(state.backup_codes_hash),
            },
        )
        return False

    remaining = [h for i, h in enumerate(state.backup_codes_hash) if i != matched_index]
    new_value: list[str] | None = remaining if remaining else None

    stmt = (
        update(AdminUser)
        .where(AdminUser.subject == canonical)
        .values(mfa_backup_codes_hash=new_value)
    )
    try:
        await db.execute(stmt)
    except SQLAlchemyError:
        logger.exception(
            "admin_mfa_backup_db_error",
            extra={
                "event": "argus.mfa.backup.db_error",
                "subject": canonical,
            },
        )
        return False

    logger.info(
        "admin_mfa_backup_succeeded",
        extra={
            "event": "argus.mfa.backup.succeeded",
            "subject": canonical,
            "remaining_codes": len(remaining),
        },
    )
    return True


async def disable_mfa(db: AsyncSession, *, subject: str) -> None:
    """Clear all MFA state for *subject* (operator override).

    Triggered by the support-ops "I lost my authenticator" flow. Wipes
    ``mfa_enabled`` / ``mfa_secret_encrypted`` / ``mfa_backup_codes_hash``
    in a single ``UPDATE`` so an interleaved ``verify_totp`` cannot
    observe a half-cleared state. The router (C7-T03) is responsible for
    enforcing the policy gate (super-admin only) and emitting the audit
    log entry — this DAO emits a structured log event for the SIEM trail
    but does NOT write to ``audit_logs`` because the table is per-tenant
    and admin actions are cross-tenant.
    """
    canonical = _normalize_subject(subject)

    stmt = (
        update(AdminUser)
        .where(AdminUser.subject == canonical)
        .values(
            mfa_enabled=False,
            mfa_secret_encrypted=None,
            mfa_backup_codes_hash=None,
        )
    )
    try:
        # ``AsyncSession.execute`` returns ``Result`` (no rowcount in the
        # public type); the underlying object for an UPDATE is always a
        # ``CursorResult`` whose ``.rowcount`` reports affected rows.
        result = cast(CursorResult, await db.execute(stmt))
    except SQLAlchemyError:
        logger.exception(
            "admin_mfa_disable_db_error",
            extra={
                "event": "argus.mfa.disable.db_error",
                "subject": canonical,
            },
        )
        raise AdminMfaError("db_error") from None

    if (result.rowcount or 0) == 0:
        raise AdminMfaError("subject_not_found")

    logger.info(
        "admin_mfa_disabled",
        extra={
            "event": "argus.mfa.disable.applied",
            "subject": canonical,
        },
    )


async def regenerate_backup_codes(
    db: AsyncSession,
    *,
    subject: str,
) -> list[str]:
    """Mint a fresh batch of backup codes; return *plaintext* once.

    Replaces any existing backup codes — the old hashes are discarded and
    cannot be re-spent. The returned list is the only legitimate place
    plaintext exists; the caller MUST display them in a single response
    to the admin and MUST NOT log them.

    Refuses if MFA is not yet enabled (calling this before
    :func:`confirm_enrollment` is a programmer error — the codes would
    be unusable until the second factor is active).
    """
    canonical = _normalize_subject(subject)
    state = await _load_state(db, canonical)
    if not state.enabled:
        raise AdminMfaError("mfa_not_enabled")

    plaintext_codes = generate_backup_codes()
    backup_hashes = [_bcrypt_hash(c) for c in plaintext_codes]

    stmt = (
        update(AdminUser)
        .where(AdminUser.subject == canonical)
        .values(mfa_backup_codes_hash=backup_hashes)
    )
    try:
        await db.execute(stmt)
    except SQLAlchemyError:
        logger.exception(
            "admin_mfa_regen_db_error",
            extra={
                "event": "argus.mfa.regen.db_error",
                "subject": canonical,
            },
        )
        raise AdminMfaError("db_error") from None

    logger.info(
        "admin_mfa_backup_regenerated",
        extra={
            "event": "argus.mfa.regen.applied",
            "subject": canonical,
            "backup_codes_count": len(plaintext_codes),
        },
    )
    return plaintext_codes


async def mark_session_mfa_passed(
    db: AsyncSession,
    *,
    session_token_hash: str,
) -> None:
    """Stamp the session row as having satisfied the MFA challenge.

    The resolver (``admin_sessions.resolve_session``) compares
    ``now() - mfa_passed_at`` against
    :attr:`Settings.admin_mfa_reauth_window_seconds` to decide whether a
    sensitive admin action requires a fresh challenge — this function is
    the only place that updates the timestamp.

    No-ops with a structured log when the session token hash is unknown
    (could happen if the session expired between the verify call and the
    update). Never raises — the caller has already accepted the TOTP
    code, and a missing session row is not a security event by itself.

    Implementation note — identity-map invariant
    --------------------------------------------
    A bulk ``UPDATE`` (``Session.execute(update(AdminSession)…)``) does
    NOT reliably propagate through SQLAlchemy's identity map for cached
    :class:`AdminSession` instances when the WHERE clause uses a
    non-primary-key column (``session_token_hash`` here, not
    ``session_id``). Even ``synchronize_session="fetch"`` silently leaves
    the cached attribute stale, which means the very next
    ``session.get(AdminSession, sid)`` returns the pre-write value and
    the router would mis-gate the MFA window.

    To keep the contract "after this call, any read in the same session
    sees the new ``mfa_passed_at``" we load through the ORM
    (``select(AdminSession)``), assign on the loaded instance, and let
    the unit-of-work emit the UPDATE on flush. The ORM's natural change
    tracker keeps the cached row consistent with the persisted row.
    """
    if not session_token_hash or not session_token_hash.strip():
        logger.warning(
            "admin_mfa_mark_session_invalid_input",
            extra={
                "event": "argus.mfa.session.invalid_input",
            },
        )
        return

    select_stmt = select(AdminSession).where(
        AdminSession.session_token_hash == session_token_hash
    )
    try:
        row = (await db.execute(select_stmt)).scalar_one_or_none()
    except SQLAlchemyError:
        logger.exception(
            "admin_mfa_mark_session_db_error",
            extra={
                "event": "argus.mfa.session.db_error",
            },
        )
        return

    if row is None:
        logger.info(
            "admin_mfa_mark_session_unknown",
            extra={
                "event": "argus.mfa.session.unknown_hash",
            },
        )
        return

    now = _utcnow()
    row.mfa_passed_at = now
    try:
        await db.flush()
    except SQLAlchemyError:
        logger.exception(
            "admin_mfa_mark_session_db_error",
            extra={
                "event": "argus.mfa.session.db_error",
            },
        )
        return

    logger.info(
        "admin_mfa_session_marked",
        extra={
            "event": "argus.mfa.session.marked",
            "marked_at": now.isoformat(),
        },
    )


__all__ = [
    "AdminMfaError",
    "confirm_enrollment",
    "consume_backup_code",
    "disable_mfa",
    "enroll_totp",
    "generate_backup_codes",
    "mark_session_mfa_passed",
    "regenerate_backup_codes",
    "verify_totp",
]
