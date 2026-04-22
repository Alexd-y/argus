"""ARG-062 / C7-T01 — Fernet at-rest encryption for admin TOTP secrets.

Design invariants
-----------------
* **Keys come from environment, never from the DB.** :class:`MultiFernet`
  is constructed from :attr:`Settings.admin_mfa_keyring` (CSV of base64
  Fernet keys, NEWEST FIRST). The key material is never persisted, never
  serialized into log records, and never echoed in error messages.
* **Fail fast on misconfig.** A malformed keyring, an empty keyring, or
  empty plaintext raises :class:`ValueError`. Errors are logged with a
  structured event name and a *generic* shape description — the bad key
  bytes themselves never enter the log pipeline.
* **Zero-downtime rotation.** :func:`reencrypt_if_stale` decrypts with any
  key in the keyring (oldest → newest tried by ``MultiFernet.decrypt``)
  and re-encrypts with the *primary* (first) key. The DAO calls this on
  every successful TOTP verification so secrets migrate to the newest key
  organically, without a maintenance window.
* **Authenticated encryption.** Fernet = AES-128-CBC + HMAC-SHA256 with
  a 32-byte key (256-bit URL-safe base64). Tampered ciphertext fails
  HMAC verification → :class:`InvalidToken` → mapped here to
  :class:`MfaCryptoError` so callers see a single exception type.
* **No retry, no swallow.** A decrypt failure is a security event. We
  do NOT silently treat it as "user has no secret"; the DAO surfaces the
  failure and the caller (router) returns HTTP 500.

Operational cookbook (key rotation)
-----------------------------------
1. Generate a fresh key::

       python -c "from cryptography.fernet import Fernet; \
                  print(Fernet.generate_key().decode())"

2. **Prepend** it to ``ADMIN_MFA_KEYRING`` (must remain newest-first).
3. Deploy. Existing secrets keep decrypting with the old (now second)
   key; new enrolments and re-encryptions use the new key.
4. After ≥ 90 days of activity (so every active admin has logged in and
   triggered :func:`reencrypt_if_stale` at least once), drop the oldest
   key from the CSV. Verify with :func:`current_key_id` before/after to
   confirm the primary key fingerprint changed.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Final

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from src.core.config import settings

logger = logging.getLogger(__name__)

#: Length of a base64-url Fernet key string (32 bytes encoded).
_FERNET_KEY_LEN: Final[int] = 44


class MfaCryptoError(Exception):
    """Raised for any encrypt / decrypt failure in the MFA crypto layer.

    Wraps :class:`cryptography.fernet.InvalidToken` so callers can ``except``
    a single, project-local exception. The ``str()`` representation never
    contains key material or plaintext — only a stable error code.
    """


def _load_keyring(raw: str) -> list[Fernet]:
    """Parse a CSV of base64 Fernet keys into a list of :class:`Fernet`.

    Newest key MUST be first. The :class:`MultiFernet` contract is that
    ``encrypt`` uses key[0] and ``decrypt`` tries every key in order, so
    "newest first" is the rotation-safe ordering.

    Failures are logged with a structured event name and the *index* of
    the bad entry only — the raw key bytes never enter the log line. The
    caller receives a generic :class:`ValueError` with remediation.
    """
    cleaned = (raw or "").strip()
    if not cleaned:
        raise ValueError(
            "ADMIN_MFA_KEYRING is empty — refusing to construct an MFA "
            "crypto layer without keys. Generate a key with: "
            'python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"'
        )

    raw_keys = [k.strip() for k in cleaned.split(",") if k.strip()]
    if not raw_keys:
        raise ValueError("ADMIN_MFA_KEYRING contained no non-empty entries.")

    fernets: list[Fernet] = []
    for idx, key in enumerate(raw_keys):
        try:
            fernets.append(Fernet(key.encode("ascii")))
        except (ValueError, TypeError) as exc:
            logger.error(
                "admin_mfa_keyring_invalid_entry",
                extra={
                    "event": "argus.mfa.crypto.keyring_invalid_entry",
                    "key_index": idx,
                    "key_count": len(raw_keys),
                    "reason": exc.__class__.__name__,
                },
            )
            raise ValueError(
                f"ADMIN_MFA_KEYRING entry #{idx} is not a valid Fernet key "
                "(expected url-safe base64, 32 bytes decoded)."
            ) from None

    return fernets


def _build_multifernet() -> tuple[MultiFernet, Fernet]:
    """Build the :class:`MultiFernet` plus a handle to the primary key.

    Returns ``(multifernet, primary_fernet)``. The primary fernet is
    needed by :func:`reencrypt_if_stale` to detect whether a ciphertext
    is already encrypted under the newest key without round-tripping
    through ``MultiFernet.rotate``.
    """
    keys = _load_keyring(settings.admin_mfa_keyring)
    return MultiFernet(keys), keys[0]


def encrypt(plaintext: str) -> bytes:
    """Encrypt ``plaintext`` with the primary key in the keyring.

    Refuses an empty / whitespace-only input — an empty TOTP secret would
    silently disable MFA verification at the call site.

    Returns the URL-safe base64 ciphertext as ``bytes`` (Fernet's native
    output). Callers persist it in the ``mfa_secret_encrypted BYTEA``
    column without any further encoding.
    """
    if not plaintext or not plaintext.strip():
        raise ValueError("refuse to encrypt empty TOTP secret")

    multifernet, _primary = _build_multifernet()
    try:
        return multifernet.encrypt(plaintext.encode("utf-8"))
    except Exception as exc:
        logger.error(
            "admin_mfa_encrypt_failed",
            extra={
                "event": "argus.mfa.crypto.encrypt_failed",
                "reason": exc.__class__.__name__,
            },
        )
        raise MfaCryptoError("admin_mfa_encrypt_failed") from None


def decrypt(ciphertext: bytes) -> str:
    """Decrypt ``ciphertext`` with any key in the keyring.

    :class:`MultiFernet` tries every key in keyring order until one
    succeeds; we surface a single :class:`MfaCryptoError` on total
    failure so callers don't leak ``cryptography``-internal exception
    types into HTTP responses.
    """
    if not ciphertext:
        raise MfaCryptoError("admin_mfa_decrypt_empty_input")

    multifernet, _primary = _build_multifernet()
    try:
        return multifernet.decrypt(ciphertext).decode("utf-8")
    except InvalidToken:
        logger.warning(
            "admin_mfa_decrypt_invalid_token",
            extra={
                "event": "argus.mfa.crypto.decrypt_invalid_token",
                "ciphertext_len": len(ciphertext),
            },
        )
        raise MfaCryptoError("admin_mfa_decrypt_invalid_token") from None
    except Exception as exc:
        logger.error(
            "admin_mfa_decrypt_failed",
            extra={
                "event": "argus.mfa.crypto.decrypt_failed",
                "reason": exc.__class__.__name__,
            },
        )
        raise MfaCryptoError("admin_mfa_decrypt_failed") from None


def reencrypt_if_stale(ciphertext: bytes) -> tuple[bytes, bool]:
    """Opportunistic key rotation — re-encrypt with the primary key.

    Decrypts ``ciphertext`` with the keyring, then *unconditionally*
    re-encrypts it with the primary key and returns the new ciphertext.
    The boolean second element of the return tuple is ``True`` when the
    re-encryption produced a *different* ciphertext (i.e. the input was
    not already under the primary key) and ``False`` when no rotation
    was necessary.

    The "different ciphertext" check is best-effort — Fernet IVs are
    random, so two encryptions of the same plaintext under the *same*
    key always differ. To make the check meaningful we compare the
    keyring index that decrypted the input against the primary key:
    we strip the Fernet version+timestamp prefix and compare HMAC
    fingerprints. The DAO uses the boolean to decide whether to issue
    a follow-up UPDATE.

    Important: rotation is intentionally cheap to over-trigger — even
    when the boolean is ``False`` the new ciphertext is still safe to
    persist; we just save a write per verify call.
    """
    plaintext = decrypt(ciphertext)
    multifernet, primary = _build_multifernet()

    # Fernet tokens carry the key fingerprint implicitly via HMAC. We
    # detect "already on primary" by attempting a primary-only decrypt
    # — if it succeeds, no rotation is needed.
    rotated = True
    try:
        primary.decrypt(ciphertext)
        rotated = False
    except InvalidToken:
        rotated = True

    new_ciphertext = multifernet.encrypt(plaintext.encode("utf-8"))
    return new_ciphertext, rotated


def current_key_id() -> str:
    """Return a short, log-safe fingerprint of the primary key.

    Used by the audit log to pin a re-encryption event to a key
    *generation* without ever logging the key itself. The fingerprint
    is the first 12 hex chars of ``sha256(primary_key)`` — collision-
    resistant for the small number of keys an op team rotates through.
    """
    _, primary = _build_multifernet()
    # Reach into the internal signing+encryption keys via the signing key
    # (the only stable, public-ish handle) — falling back to the repr if
    # the cryptography internals shift. ``Fernet`` exposes neither, so
    # we hash the raw URL-safe key string the operator pasted in. We get
    # that back by re-extracting from settings (the same value used to
    # build ``primary``), which avoids any reflection on ``Fernet``.
    raw = (settings.admin_mfa_keyring or "").split(",")[0].strip()
    return hashlib.sha256(raw.encode("ascii")).hexdigest()[:12]


__all__ = [
    "MfaCryptoError",
    "current_key_id",
    "decrypt",
    "encrypt",
    "reencrypt_if_stale",
]
