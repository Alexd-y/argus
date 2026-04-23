"""ARG-062 / C7-T01 — async DAO tests for ``src.auth.admin_mfa``.

Coverage strategy
-----------------
The DAO is a thin façade over :mod:`src.auth._mfa_crypto`,
:mod:`src.db.models`, and ``bcrypt`` / ``pyotp``. The crypto layer is
exercised exhaustively in ``test_mfa_crypto.py`` and the migration shape
in ``test_032_admin_mfa_columns_migration.py``; this file owns the *DAO
contract* — the public surface the C7-T03 router will call:

* :func:`generate_backup_codes` — alphabet + count + entropy;
* :func:`enroll_totp` — Fernet ciphertext lands in ``mfa_secret_encrypted``,
  ``mfa_enabled`` stays ``False`` until confirmation;
* :func:`confirm_enrollment` — happy path + invalid-TOTP path;
* :func:`verify_totp` — current TOTP succeeds, stale TOTP fails, and
  opportunistic re-encryption fires when the keyring rotates;
* :func:`consume_backup_code` — one-time semantics + unknown-code rejection;
* :func:`disable_mfa` — wipes the three MFA columns + emits the SIEM event;
* :func:`regenerate_backup_codes` — replaces hashes on disk;
* :func:`mark_session_mfa_passed` — stamps ``admin_sessions.mfa_passed_at``;
* logging hygiene — secret material never lands in a log record;
* bcrypt cost — backup-code hashes meet the project floor of 12 rounds.

Persistence model
-----------------
Tests share the per-test in-memory aiosqlite engine wired by
``backend/tests/auth/conftest.py``. The ``session`` fixture commits
each DAO call individually so subsequent ``await session.refresh(...)``
loads see the persisted state — this matches the production router
pattern where each HTTP request is its own transaction.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any, Final

import pyotp  # type: ignore[import-not-found]  # pyotp ships no PEP-561 stubs
import pytest
from cryptography.fernet import Fernet
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from src.auth import admin_mfa as admin_mfa_module
from src.auth._mfa_crypto import MfaCryptoError, decrypt
from src.auth.admin_mfa import (
    AdminMfaError,
    confirm_enrollment,
    consume_backup_code,
    disable_mfa,
    enroll_totp,
    generate_backup_codes,
    mark_session_mfa_passed,
    regenerate_backup_codes,
    verify_totp,
)
from src.auth.admin_sessions import create_session
from src.auth.admin_users import hash_password
from src.core.config import settings
from src.db.models import AdminSession, AdminUser

from .conftest import MfaKeyring

#: Stable subject used by every test that doesn't care about subject identity.
_SUBJECT: Final[str] = "mfa-tests@argus.example"

#: Operator-readable backup-code alphabet — must stay byte-equivalent to the
#: ``_BACKUP_CODE_ALPHABET`` constant in :mod:`src.auth.admin_mfa`. We pin it
#: locally (rather than reaching into the DAO's underscore-prefixed name) so a
#: drift between docstring and implementation surfaces in the test, not in
#: production. The alphabet itself is documented in the module docstring of
#: :mod:`src.auth.admin_mfa`.
_BACKUP_CODE_ALPHABET: Final[str] = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"

#: Compiled regex: 16 chars from the operator alphabet, anchored. Mirrors
#: the worker's ``_BACKUP_CODE_LENGTH`` × ``_BACKUP_CODE_ALPHABET`` contract.
_BACKUP_CODE_RE: Final[re.Pattern[str]] = re.compile(
    rf"^[{_BACKUP_CODE_ALPHABET}]{{16}}$"
)


# ---------------------------------------------------------------------------
# Local seeding helpers — kept in-file so the test file stays runnable in
# isolation (``pytest backend/tests/auth/test_admin_mfa_dao.py -v``).
# ---------------------------------------------------------------------------


async def _seed_admin(
    session: AsyncSession,
    *,
    subject: str = _SUBJECT,
    role: str = "admin",
) -> AdminUser:
    """Insert a minimal :class:`AdminUser` row and return the ORM instance.

    All MFA-state columns are left at their schema defaults (``mfa_enabled
    = False``, secret/codes ``NULL``) so tests can drive the enrolment
    flow from a known clean baseline.
    """
    row = AdminUser(
        subject=subject,
        password_hash=hash_password("not-the-prod-password-but-bcrypt-shaped"),
        role=role,
        tenant_id=None,
        created_at=datetime.now(tz=timezone.utc),
        disabled_at=None,
    )
    session.add(row)
    await session.commit()
    return row


async def _enrol_and_confirm(
    session: AsyncSession,
    *,
    subject: str = _SUBJECT,
) -> tuple[str, list[str]]:
    """Run the full enrol → confirm cycle; return ``(secret, backup_codes)``.

    Centralised so every test that needs an MFA-enabled admin can reach
    that state in three lines without duplicating the ``pyotp`` /
    ``generate_backup_codes`` plumbing.
    """
    secret = pyotp.random_base32()
    codes = generate_backup_codes()
    await enroll_totp(session, subject=subject, secret=secret)
    await session.commit()
    await confirm_enrollment(
        session,
        subject=subject,
        totp_code=pyotp.TOTP(secret).now(),
        generated_codes=codes,
    )
    await session.commit()
    return secret, codes


def _records_with_event(
    records: Iterable[logging.LogRecord], event: str
) -> list[logging.LogRecord]:
    """Filter caplog records by the structured ``event`` ``extra`` field."""
    return [r for r in records if getattr(r, "event", None) == event]


# ---------------------------------------------------------------------------
# (1) generate_backup_codes — count, length, alphabet, regex.
# ---------------------------------------------------------------------------


def test_generate_backup_codes_returns_ten_alphabet_constrained_codes() -> None:
    """Default invocation yields 10 codes; each matches the operator alphabet."""
    codes = generate_backup_codes()

    assert len(codes) == 10, (
        f"default backup-code batch size must be 10, got {len(codes)}"
    )
    assert len(set(codes)) == 10, (
        "10 codes from a CSPRNG must not collide — collision rate is "
        f"≈ 4.5e-25; got duplicates: {[c for c in codes if codes.count(c) > 1]!r}"
    )
    for code in codes:
        assert _BACKUP_CODE_RE.match(code), (
            f"backup code {code!r} violates alphabet/length contract "
            f"(regex {_BACKUP_CODE_RE.pattern!r})"
        )
        for ch in code:
            assert ch in _BACKUP_CODE_ALPHABET, (
                f"backup code character {ch!r} not in operator alphabet"
            )
            assert ch not in {"I", "O"}, (
                "backup code must exclude confusable letters I/O — "
                f"got {ch!r} in {code!r}"
            )


# ---------------------------------------------------------------------------
# (2) enroll_totp persists ciphertext; mfa_enabled stays False.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enroll_totp_persists_ciphertext_but_keeps_mfa_disabled(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Step-1 enrolment writes ciphertext only — MFA stays OFF until confirm."""
    await _seed_admin(session)
    secret = pyotp.random_base32()

    with caplog.at_level(logging.DEBUG):
        await enroll_totp(session, subject=_SUBJECT, secret=secret)
        await session.commit()

    refreshed = await session.get(AdminUser, _SUBJECT)
    assert refreshed is not None
    assert refreshed.mfa_enabled is False, (
        "enroll_totp must NOT flip mfa_enabled — that's confirm_enrollment's job"
    )
    assert refreshed.mfa_secret_encrypted is not None, (
        "enroll_totp must persist a non-NULL Fernet ciphertext"
    )
    assert refreshed.mfa_secret_encrypted != secret.encode("utf-8"), (
        "enroll_totp must not write the plaintext secret to disk"
    )
    # Round-trip the ciphertext through the same crypto layer to prove
    # it's a valid Fernet token under the active keyring.
    assert decrypt(refreshed.mfa_secret_encrypted) == secret
    assert refreshed.mfa_backup_codes_hash is None, (
        "enroll_totp must wipe any pre-existing backup codes (re-enrolment "
        "safety) — none should be set yet"
    )

    assert secret not in caplog.text, (
        "enroll_totp must NOT log the plaintext TOTP secret"
    )
    assert mfa_keyring.primary not in caplog.text, (
        "enroll_totp must NOT log the Fernet keyring material"
    )


# ---------------------------------------------------------------------------
# (3) confirm_enrollment — valid TOTP enables MFA + persists 10 bcrypt hashes.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_confirm_enrollment_with_valid_totp_enables_mfa(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Valid TOTP code flips ``mfa_enabled`` and writes 10 bcrypt hashes."""
    await _seed_admin(session)
    secret = pyotp.random_base32()
    codes = generate_backup_codes()

    await enroll_totp(session, subject=_SUBJECT, secret=secret)
    await session.commit()

    with caplog.at_level(logging.DEBUG):
        await confirm_enrollment(
            session,
            subject=_SUBJECT,
            totp_code=pyotp.TOTP(secret).now(),
            generated_codes=codes,
        )
        await session.commit()

    refreshed = await session.get(AdminUser, _SUBJECT)
    assert refreshed is not None
    assert refreshed.mfa_enabled is True, "confirm_enrollment must enable MFA"
    assert refreshed.mfa_backup_codes_hash is not None
    assert len(refreshed.mfa_backup_codes_hash) == 10
    for digest in refreshed.mfa_backup_codes_hash:
        assert digest.startswith("$2"), (
            f"backup-code hash {digest[:8]!r} is not a bcrypt digest"
        )
    # No raw plaintext code may appear among the persisted hashes.
    for raw in codes:
        assert raw not in refreshed.mfa_backup_codes_hash, (
            "raw backup code must NEVER land in the persisted column"
        )

    assert secret not in caplog.text
    for raw in codes:
        assert raw not in caplog.text, (
            "confirm_enrollment must NOT log raw backup codes"
        )


# ---------------------------------------------------------------------------
# (4) confirm_enrollment with invalid TOTP raises + leaves row untouched.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_confirm_enrollment_with_invalid_totp_raises_and_does_not_enable(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Invalid TOTP raises ``AdminMfaError("totp_invalid")``; row untouched.

    The DAO contract is "raise on confirm failure, return None on success"
    — the router maps the raise to HTTP 400 and the absence of a raise to
    HTTP 204. A False return would silently re-enable a partial enrolment
    and break that contract.
    """
    await _seed_admin(session)
    secret = pyotp.random_base32()
    codes = generate_backup_codes()

    await enroll_totp(session, subject=_SUBJECT, secret=secret)
    await session.commit()

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(AdminMfaError, match="totp_invalid"):
            await confirm_enrollment(
                session,
                subject=_SUBJECT,
                totp_code="000000",
                generated_codes=codes,
            )
        # No commit — pending changes (if any) must not survive a failed
        # confirm anyway. Defensive rollback to mirror router behaviour.
        await session.rollback()

    refreshed = await session.get(AdminUser, _SUBJECT)
    assert refreshed is not None
    assert refreshed.mfa_enabled is False, "failed confirm must NOT enable MFA"
    assert refreshed.mfa_backup_codes_hash is None, (
        "failed confirm must NOT persist backup codes"
    )

    assert secret not in caplog.text
    for raw in codes:
        assert raw not in caplog.text, (
            "failed confirm must NOT log the candidate backup codes"
        )


# ---------------------------------------------------------------------------
# (5) verify_totp — current code OK, stale code rejected.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_totp_accepts_current_and_rejects_stale_code(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Current TOTP returns True; a code from 5 minutes ago returns False."""
    await _seed_admin(session)
    secret, _ = await _enrol_and_confirm(session)

    totp = pyotp.TOTP(secret)
    current_code = totp.now()
    # 5 minutes back — well outside the ``valid_window=1`` (±30s) tolerance.
    stale_code = totp.at(int(time.time()) - 300)
    assert current_code != stale_code, (
        "test pre-condition: current and stale TOTP windows must differ"
    )

    with caplog.at_level(logging.DEBUG):
        accepted = await verify_totp(session, subject=_SUBJECT, totp_code=current_code)
        rejected = await verify_totp(session, subject=_SUBJECT, totp_code=stale_code)
        await session.commit()

    assert accepted is True, "current TOTP code must verify"
    assert rejected is False, (
        "TOTP code from 300 s ago is outside ±30 s window — must reject"
    )
    assert secret not in caplog.text, "verify_totp must NOT log the plaintext secret"


# ---------------------------------------------------------------------------
# (6) verify_totp triggers opportunistic re-encryption after key rotation.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_totp_reencrypts_secret_after_keyring_rotation(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A successful verify under a non-primary key swaps the stored ciphertext.

    Flow:
      1. Pin keyring to ``[secondary]`` only.
      2. Enrol + confirm — secret is now encrypted under SECONDARY.
      3. Rotate keyring to ``[primary, secondary]`` (newest-first).
      4. verify_totp with a fresh code → should succeed AND opportunistically
         re-encrypt under PRIMARY.
      5. Reload the row — ciphertext must differ from the pre-verify value
         AND the new ciphertext must decrypt under PRIMARY only.
    """
    # Step 1 + 2 — enrol while only the OLD key is active.
    monkeypatch.setattr(settings, "admin_mfa_keyring", mfa_keyring.secondary)

    await _seed_admin(session)
    secret, _ = await _enrol_and_confirm(session)

    pre_row = await session.get(AdminUser, _SUBJECT)
    assert pre_row is not None
    pre_ciphertext = pre_row.mfa_secret_encrypted
    assert pre_ciphertext is not None

    # Confirm pre-rotation ciphertext is decryptable by SECONDARY only.
    secondary_only = Fernet(mfa_keyring.secondary.encode("ascii"))
    assert secondary_only.decrypt(pre_ciphertext).decode("utf-8") == secret

    # Step 3 — operator pre-pends a brand-new primary.
    monkeypatch.setattr(settings, "admin_mfa_keyring", mfa_keyring.csv)

    with caplog.at_level(logging.DEBUG):
        # Step 4 — verify under the rotated keyring.
        ok = await verify_totp(
            session,
            subject=_SUBJECT,
            totp_code=pyotp.TOTP(secret).now(),
        )
        await session.commit()

    assert ok is True, "verify under rotated keyring must still succeed"

    # Step 5 — ciphertext must have rotated.
    post_row = await session.get(AdminUser, _SUBJECT)
    assert post_row is not None
    post_ciphertext = post_row.mfa_secret_encrypted
    assert post_ciphertext is not None
    assert post_ciphertext != pre_ciphertext, (
        "verify_totp must opportunistically re-encrypt with the new "
        "primary key when the keyring has rotated"
    )

    primary_only = Fernet(mfa_keyring.primary.encode("ascii"))
    assert primary_only.decrypt(post_ciphertext).decode("utf-8") == secret, (
        "post-rotation ciphertext must decrypt under the new primary key"
    )

    # No secret material in any log line.
    assert secret not in caplog.text
    assert mfa_keyring.primary not in caplog.text
    assert mfa_keyring.secondary not in caplog.text


# ---------------------------------------------------------------------------
# (7) consume_backup_code — single-use semantics.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_consume_backup_code_is_single_use(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A code that was consumed once must be rejected on the second attempt."""
    await _seed_admin(session)
    _, codes = await _enrol_and_confirm(session)

    target_code = codes[0]

    with caplog.at_level(logging.DEBUG):
        first = await consume_backup_code(session, subject=_SUBJECT, code=target_code)
        await session.commit()
        second = await consume_backup_code(session, subject=_SUBJECT, code=target_code)
        await session.commit()

    assert first is True, "first redemption of a fresh backup code must succeed"
    assert second is False, (
        "double-spend defence: a redeemed code must NEVER verify again"
    )

    refreshed = await session.get(AdminUser, _SUBJECT)
    assert refreshed is not None
    remaining = refreshed.mfa_backup_codes_hash or []
    assert len(remaining) == 9, (
        f"successful consume must shrink the array by exactly one; "
        f"got {len(remaining)} remaining"
    )

    for raw_code in codes:
        assert raw_code not in caplog.text, (
            "consume_backup_code must NOT log the candidate raw code"
        )


# ---------------------------------------------------------------------------
# (8) consume_backup_code with an unknown code returns False; row untouched.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_consume_backup_code_with_unknown_code_does_not_modify_row(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Unknown code → False; ``mfa_backup_codes_hash`` is unchanged."""
    await _seed_admin(session)
    _, _ = await _enrol_and_confirm(session)

    pre = await session.get(AdminUser, _SUBJECT)
    assert pre is not None
    pre_hashes = list(pre.mfa_backup_codes_hash or [])
    assert len(pre_hashes) == 10, "test pre-condition: 10 hashes seeded"

    bogus = "ZZZZZZZZZZZZZZZZ"  # in alphabet, but not a real code

    with caplog.at_level(logging.DEBUG):
        rejected = await consume_backup_code(session, subject=_SUBJECT, code=bogus)
        await session.commit()

    assert rejected is False, "unknown code must be rejected"

    post = await session.get(AdminUser, _SUBJECT)
    assert post is not None
    post_hashes = list(post.mfa_backup_codes_hash or [])
    assert post_hashes == pre_hashes, (
        "rejected backup-code attempt must NOT mutate the persisted array"
    )

    assert bogus not in caplog.text, (
        "consume_backup_code must NOT log the candidate code"
    )


# ---------------------------------------------------------------------------
# (8a) consume_backup_code — Compare-and-Swap concurrency guard.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_backup_code_concurrent_consume_only_one_succeeds(
    session_factory: Any,
    mfa_keyring: MfaKeyring,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Two consumers seeing identical pre-state → CAS lets exactly one win.

    DEBUG-3 (cycle-7-T03 follow-up). Reproduces the
    ``READ COMMITTED`` race that the original implementation allowed:

      1. Caller A loads ``backup_codes_hash = [h₀, h₁, …, h₉]``.
      2. Caller B loads the same array (no row lock on either SELECT).
      3. Both compute the post-state ``[h₁, …, h₉]``.
      4. Without CAS: both UPDATEs land, both return ``True`` →
         single-use violation.

    To force step 1 + 2 deterministically (single-connection SQLite +
    sync bcrypt would otherwise serialise the consumers and the second
    SELECT would observe the post-commit state, masking the race) we
    monkey-patch :func:`admin_mfa_module._load_state` to replay the
    same captured snapshot for both calls. The CAS predicate
    (``WHERE mfa_backup_codes_hash = <pre_state>``) then makes the
    second UPDATE see ``rowcount = 0``, log
    ``argus.mfa.backup.cas_lost`` and return ``False``.

    Post-conditions
    ---------------
    * Exactly one of ``(winner_a, winner_b)`` is ``True``.
    * The persisted array shrinks by exactly one slot (proving the
      winner's UPDATE landed and the loser's did NOT add a second
      mutation on top).
    * The loser logs the ``cas_lost`` SIEM event.
    """
    async with session_factory() as setup:
        await _seed_admin(setup)
        _, codes = await _enrol_and_confirm(setup)

    target = codes[0]

    async with session_factory() as snapshot:
        cached = await admin_mfa_module._load_state(snapshot, _SUBJECT)

    cached_hashes = list(cached.backup_codes_hash)

    real_load_state = admin_mfa_module._load_state

    async def _frozen_load_state(
        session_arg: AsyncSession,
        subject: str,
    ) -> admin_mfa_module._MfaState:
        # Force every consumer to see the same pre-state, simulating two
        # concurrent SELECTs under READ COMMITTED that observed the row
        # before either UPDATE committed.
        if subject == _SUBJECT:
            return admin_mfa_module._MfaState(
                subject=cached.subject,
                enabled=cached.enabled,
                secret_encrypted=cached.secret_encrypted,
                backup_codes_hash=list(cached_hashes),
            )
        return await real_load_state(session_arg, subject)

    monkeypatch.setattr(admin_mfa_module, "_load_state", _frozen_load_state)

    async def attempt() -> bool:
        async with session_factory() as s:
            r = await consume_backup_code(s, subject=_SUBJECT, code=target)
            await s.commit()
            return r

    import asyncio as _asyncio

    with caplog.at_level(logging.WARNING):
        results = await _asyncio.gather(attempt(), attempt())

    winners = [r for r in results if r is True]
    losers = [r for r in results if r is False]
    assert len(winners) == 1 and len(losers) == 1, (
        "CAS must let EXACTLY one concurrent consumer win and reject the "
        f"other (anti-double-spend); got results={results!r}"
    )

    async with session_factory() as inspect:
        row = await inspect.get(AdminUser, _SUBJECT)
        assert row is not None
        persisted = list(row.mfa_backup_codes_hash or [])
    assert len(persisted) == len(cached_hashes) - 1, (
        "winner's UPDATE must shrink the array by exactly one slot — "
        f"pre={len(cached_hashes)} post={len(persisted)} "
        "(if both UPDATEs landed, the loser's would re-write the same "
        "post-state on top of the winner's, masking the bug; with CAS "
        "the loser does NOT write at all)"
    )

    cas_lost_records = _records_with_event(
        caplog.records, "argus.mfa.backup.cas_lost"
    )
    assert len(cas_lost_records) == 1, (
        "loser MUST emit a single `argus.mfa.backup.cas_lost` SIEM "
        f"warning so SOC can alert on race patterns; got "
        f"{len(cas_lost_records)} record(s)"
    )

    for raw in codes:
        assert raw not in caplog.text, (
            "concurrent consume must NOT log the candidate raw code"
        )


# ---------------------------------------------------------------------------
# (9) disable_mfa — wipes columns + emits structured event.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_disable_mfa_zeroes_columns_and_emits_event(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``disable_mfa`` clears the three MFA columns + logs SIEM event."""
    await _seed_admin(session)
    secret, codes = await _enrol_and_confirm(session)

    pre = await session.get(AdminUser, _SUBJECT)
    assert pre is not None
    assert pre.mfa_enabled is True
    assert pre.mfa_secret_encrypted is not None
    assert pre.mfa_backup_codes_hash is not None

    with caplog.at_level(logging.DEBUG):
        await disable_mfa(session, subject=_SUBJECT)
        await session.commit()

    post = await session.get(AdminUser, _SUBJECT)
    assert post is not None
    assert post.mfa_enabled is False, "disable_mfa must clear mfa_enabled"
    assert post.mfa_secret_encrypted is None, (
        "disable_mfa must wipe mfa_secret_encrypted"
    )
    assert post.mfa_backup_codes_hash is None, (
        "disable_mfa must wipe mfa_backup_codes_hash"
    )

    applied_records = _records_with_event(caplog.records, "argus.mfa.disable.applied")
    assert applied_records, (
        "disable_mfa must emit the structured SIEM event "
        "`argus.mfa.disable.applied` for the audit trail"
    )

    assert secret not in caplog.text, "disable_mfa must NOT log the plaintext secret"
    for raw in codes:
        assert raw not in caplog.text, "disable_mfa must NOT log raw backup codes"


@pytest.mark.asyncio
async def test_disable_mfa_raises_when_subject_unknown(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
) -> None:
    """No row matched → ``AdminMfaError("subject_not_found")``."""
    _ = mfa_keyring  # crypto layer is not invoked in this path, but the
    # fixture keeps the keyring well-formed in case future hardening
    # adds a sanity ``encrypt`` check on the disable path.

    with pytest.raises(AdminMfaError, match="subject_not_found"):
        await disable_mfa(session, subject="ghost@nowhere.invalid")


# ---------------------------------------------------------------------------
# (10) regenerate_backup_codes — fresh batch + fresh hashes.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_regenerate_backup_codes_replaces_previous_batch(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``regenerate_backup_codes`` mints 10 fresh codes; persisted hashes change."""
    await _seed_admin(session)
    _, _ = await _enrol_and_confirm(session)

    pre_row = await session.get(AdminUser, _SUBJECT)
    assert pre_row is not None
    pre_hashes = list(pre_row.mfa_backup_codes_hash or [])
    assert len(pre_hashes) == 10

    with caplog.at_level(logging.DEBUG):
        new_codes = await regenerate_backup_codes(session, subject=_SUBJECT)
        await session.commit()

    assert len(new_codes) == 10, "regenerate must mint 10 fresh codes"
    assert len(set(new_codes)) == 10, "fresh codes must not collide"
    for code in new_codes:
        assert _BACKUP_CODE_RE.match(code), (
            f"regenerated code {code!r} violates alphabet/length contract"
        )

    post_row = await session.get(AdminUser, _SUBJECT)
    assert post_row is not None
    post_hashes = list(post_row.mfa_backup_codes_hash or [])
    assert len(post_hashes) == 10
    assert set(post_hashes).isdisjoint(set(pre_hashes)), (
        "regenerate must REPLACE every previous bcrypt hash — sharing any "
        "single hash would mean a previous code is still spendable"
    )

    for raw in new_codes:
        assert raw not in caplog.text, (
            "regenerate_backup_codes must NOT log raw plaintext codes"
        )


@pytest.mark.asyncio
async def test_regenerate_backup_codes_refuses_when_mfa_disabled(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
) -> None:
    """Calling regenerate before MFA is enabled is a programmer error."""
    _ = mfa_keyring
    await _seed_admin(session)

    with pytest.raises(AdminMfaError, match="mfa_not_enabled"):
        await regenerate_backup_codes(session, subject=_SUBJECT)


# ---------------------------------------------------------------------------
# (11) mark_session_mfa_passed — stamps the AdminSession row.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mark_session_mfa_passed_stamps_timestamp(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
) -> None:
    """A matched ``session_token_hash`` row gets a fresh ``mfa_passed_at``."""
    _ = mfa_keyring
    sid, asession = await create_session(
        session,
        subject=_SUBJECT,
        role="admin",
        tenant_id=None,
        ip="203.0.113.7",
        user_agent="argus-tests/1.0",
    )
    await session.commit()

    assert asession.mfa_passed_at is None, (
        "freshly minted session must start with mfa_passed_at = NULL"
    )
    token_hash = asession.session_token_hash
    assert token_hash is not None, (
        "test pre-condition: 030 must populate session_token_hash on insert"
    )

    before_ts = datetime.now(tz=timezone.utc)
    await mark_session_mfa_passed(session, session_token_hash=token_hash)
    await session.commit()
    after_ts = datetime.now(tz=timezone.utc)

    refreshed = await session.get(AdminSession, sid)
    assert refreshed is not None
    assert refreshed.mfa_passed_at is not None, (
        "mark_session_mfa_passed must stamp mfa_passed_at"
    )
    stamped = refreshed.mfa_passed_at
    if stamped.tzinfo is None:
        stamped = stamped.replace(tzinfo=timezone.utc)
    assert before_ts <= stamped <= after_ts, (
        f"mfa_passed_at must be a fresh UTC timestamp; got {stamped!r} "
        f"outside [{before_ts!r}, {after_ts!r}]"
    )


@pytest.mark.asyncio
async def test_mark_session_mfa_passed_is_silent_for_unknown_hash(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
) -> None:
    """Unknown hash → no-op, no exception (race-safe between verify + update)."""
    _ = mfa_keyring
    # Generate a 64-char hex string that no row owns.
    fake_hash = "f" * 64

    # Must not raise — the contract is "best effort, never block login".
    await mark_session_mfa_passed(session, session_token_hash=fake_hash)
    await session.commit()


# ---------------------------------------------------------------------------
# (12) Full end-to-end secret leakage scan — enrol → confirm → verify → disable.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_secret_material_in_logs_end_to_end(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The full enrolment + verify + disable cycle must not leak any secret.

    The negative-space invariant: if the DAO ever evolves to a
    ``logger.info("user verified with %s", secret)`` style log line,
    this test fails on that line. We capture at DEBUG to cover the
    chattiest possible logging level.
    """
    await _seed_admin(session)
    secret = pyotp.random_base32()
    codes = generate_backup_codes()

    with caplog.at_level(logging.DEBUG):
        await enroll_totp(session, subject=_SUBJECT, secret=secret)
        await session.commit()
        await confirm_enrollment(
            session,
            subject=_SUBJECT,
            totp_code=pyotp.TOTP(secret).now(),
            generated_codes=codes,
        )
        await session.commit()
        await verify_totp(
            session,
            subject=_SUBJECT,
            totp_code=pyotp.TOTP(secret).now(),
        )
        await consume_backup_code(session, subject=_SUBJECT, code=codes[0])
        await session.commit()
        await disable_mfa(session, subject=_SUBJECT)
        await session.commit()

    assert secret not in caplog.text, (
        f"plaintext TOTP secret leaked into log records (searched for {secret[:6]!r}…)"
    )
    for raw in codes:
        assert raw not in caplog.text, (
            f"raw backup code leaked into log records ({raw[:6]!r}…)"
        )
    assert mfa_keyring.primary not in caplog.text
    assert mfa_keyring.secondary not in caplog.text


# ---------------------------------------------------------------------------
# (13) bcrypt cost on persisted backup-code hashes is exactly 12.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_persisted_backup_code_hashes_use_bcrypt_cost_12(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
) -> None:
    """Every persisted backup-code hash carries the ``$2b$12$`` prefix.

    Project floor: cost ≥ 12 (matches ``admin_users._BCRYPT_ROUNDS``).
    A drop to cost 10 would shave the brute-force budget by ≈ 4×; we
    pin the literal value so a future "let's speed up tests" patch
    cannot silently reduce production strength.
    """
    await _seed_admin(session)
    await _enrol_and_confirm(session)

    row = await session.get(AdminUser, _SUBJECT)
    assert row is not None
    assert row.mfa_backup_codes_hash is not None
    assert len(row.mfa_backup_codes_hash) == 10

    for digest in row.mfa_backup_codes_hash:
        assert digest.startswith("$2b$12$"), (
            f"backup-code bcrypt cost must be exactly 12; got prefix {digest[:7]!r}"
        )
        # Sanity-check overall bcrypt structure: 60-char canonical length.
        assert len(digest) == 60, (
            f"bcrypt digest must be 60 chars; got {len(digest)} for {digest[:8]!r}…"
        )


# ---------------------------------------------------------------------------
# (14) Coverage extension — defensive paths, normalisation, DB-error wrappers.
#
# These tests pin the negative-space behaviour of the DAO that the happy-path
# tests above cannot reach: input normalisation rejects, ``_load_state`` miss
# / disabled subjects, encrypt / decrypt failure paths, and SQLAlchemyError
# translation in every public function. They are kept in the same file so a
# single ``pytest backend/tests/auth/test_admin_mfa_dao.py -v`` exercises the
# full DAO contract — no test runner discovery dependency.
# ---------------------------------------------------------------------------


def _override_execute_to_fail(
    session_obj: AsyncSession,
    *,
    fail_after: int = 0,
) -> None:
    """Override ``session_obj.execute`` so the (``fail_after`` + 1)th call raises.

    Direct attribute override (not pytest monkeypatch) — the per-test
    ``session`` fixture is rolled back + discarded after the test, so
    leaking the override has no cross-test effect. ``fail_after=0``
    (default) means the very first execute call raises.

    Why this seam: ``_load_state`` and the half-dozen update flows all
    funnel through ``await session_obj.execute(...)``, so a single seam
    covers every SQLAlchemyError translation path in the DAO without
    needing a real broken database connection.
    """
    real_execute = session_obj.execute
    counter = {"n": 0}

    async def _broken(*args: Any, **kwargs: Any) -> Any:
        if counter["n"] >= fail_after:
            raise SQLAlchemyError("simulated execute error (test injection)")
        counter["n"] += 1
        return await real_execute(*args, **kwargs)

    session_obj.execute = _broken  # type: ignore[method-assign]


def _override_flush_to_fail(session_obj: AsyncSession) -> None:
    """Override ``session_obj.flush`` so every call raises ``SQLAlchemyError``.

    Used by the ``mark_session_mfa_passed`` flush-failure test — the SELECT
    must succeed (so the DAO finds the row and stages a mutation) but the
    flush must blow up so the SQLAlchemyError handler runs.
    """

    async def _broken(*args: Any, **kwargs: Any) -> None:
        raise SQLAlchemyError("simulated flush error (test injection)")

    session_obj.flush = _broken  # type: ignore[method-assign]


# ---- (14a) Normalisation guards — empty / whitespace input is refused. ----


@pytest.mark.parametrize("subject", ["", "   ", "\t\n"])
@pytest.mark.asyncio
async def test_enroll_totp_rejects_empty_subject(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    subject: str,
) -> None:
    """``_normalize_subject`` raises on empty / whitespace-only input."""
    _ = mfa_keyring
    with pytest.raises(AdminMfaError, match=r"^subject_required$"):
        await enroll_totp(session, subject=subject, secret="JBSWY3DPEHPK3PXP")


@pytest.mark.parametrize("secret", ["", "   ", "\t"])
@pytest.mark.asyncio
async def test_enroll_totp_rejects_empty_secret(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    secret: str,
) -> None:
    """A blank TOTP secret is structurally invalid — refuse before any DB I/O."""
    _ = mfa_keyring
    with pytest.raises(AdminMfaError, match=r"^totp_secret_required$"):
        await enroll_totp(session, subject=_SUBJECT, secret=secret)


@pytest.mark.parametrize("code", ["", "   ", "abc-def-ghi"])
@pytest.mark.asyncio
async def test_confirm_enrollment_rejects_non_digit_totp_code(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    code: str,
) -> None:
    """Empty or all-non-digit TOTP codes are rejected before ``_load_state``."""
    _ = mfa_keyring
    with pytest.raises(AdminMfaError, match=r"^totp_code_required$"):
        await confirm_enrollment(
            session,
            subject=_SUBJECT,
            totp_code=code,
            generated_codes=["ABCDEFGHJKLMNPQR"],
        )


@pytest.mark.asyncio
async def test_confirm_enrollment_rejects_empty_generated_codes(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
) -> None:
    """Caller cannot finalise enrolment without backup codes — would break recovery."""
    _ = mfa_keyring
    with pytest.raises(AdminMfaError, match=r"^backup_codes_required$"):
        await confirm_enrollment(
            session,
            subject=_SUBJECT,
            totp_code="123456",
            generated_codes=[],
        )


@pytest.mark.parametrize("count", [0, -1, -10])
def test_generate_backup_codes_rejects_non_positive_count(count: int) -> None:
    """Asking for ≤ 0 codes is a programmer bug — refuse loudly, never silently."""
    with pytest.raises(AdminMfaError, match=r"^backup_code_count_invalid$"):
        generate_backup_codes(count)


@pytest.mark.parametrize("code", ["", "@@@@", "----"])
@pytest.mark.asyncio
async def test_consume_backup_code_returns_false_for_invalid_code(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    code: str,
) -> None:
    """Empty / non-alphabet-only codes are rejected via the rejected-event path.

    Pins ``_normalize_backup_code`` — its raise gets caught one frame up
    in ``consume_backup_code``'s blanket ``AdminMfaError`` handler so the
    public surface always returns ``False`` rather than 500-ing the
    request. Both raise sites (empty / no-alphabet-chars) are exercised.
    """
    _ = mfa_keyring
    await _seed_admin(session)

    result = await consume_backup_code(session, subject=_SUBJECT, code=code)

    assert result is False, (
        "blank / unparseable codes must surface as no-match, never an exception"
    )


# ---- (14b) ``_load_state`` — unknown / disabled subject + DB error. -------


@pytest.mark.asyncio
async def test_enroll_totp_raises_when_subject_unknown(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
) -> None:
    """``_load_state`` raises ``subject_not_found`` for non-existent admins."""
    _ = mfa_keyring
    with pytest.raises(AdminMfaError, match=r"^subject_not_found$"):
        await enroll_totp(
            session,
            subject="nobody@example.com",
            secret="JBSWY3DPEHPK3PXP",
        )


@pytest.mark.asyncio
async def test_enroll_totp_raises_when_subject_disabled(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
) -> None:
    """A soft-deleted admin (``disabled_at`` set) cannot start MFA enrolment."""
    _ = mfa_keyring
    user = await _seed_admin(session)
    user.disabled_at = datetime.now(tz=timezone.utc)
    await session.commit()

    with pytest.raises(AdminMfaError, match=r"^subject_disabled$"):
        await enroll_totp(
            session,
            subject=_SUBJECT,
            secret="JBSWY3DPEHPK3PXP",
        )


@pytest.mark.asyncio
async def test_enroll_totp_wraps_load_state_db_error(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A SQLAlchemyError on ``_load_state`` is translated to ``db_error``."""
    _ = mfa_keyring
    await _seed_admin(session)
    _override_execute_to_fail(session)

    with caplog.at_level(logging.ERROR):
        with pytest.raises(AdminMfaError, match=r"^db_error$"):
            await enroll_totp(
                session,
                subject=_SUBJECT,
                secret="JBSWY3DPEHPK3PXP",
            )

    assert _records_with_event(caplog.records, "argus.mfa.dao.db_error"), (
        "DB error must produce a structured `argus.mfa.dao.db_error` log event"
    )


# ---- (14c) ``enroll_totp`` — encrypt failure + UPDATE failure. ------------


@pytest.mark.asyncio
async def test_enroll_totp_wraps_encrypt_failure(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Crypto-layer failure surfaces as ``totp_secret_encrypt_failed`` (no leakage)."""
    _ = mfa_keyring
    await _seed_admin(session)

    leak_canary = "JBSWY3DPEHPK3PXP-the-real-secret"

    def _broken_encrypt(_secret: str) -> bytes:
        raise MfaCryptoError("simulated keyring outage")

    monkeypatch.setattr(admin_mfa_module, "encrypt", _broken_encrypt)

    with caplog.at_level(logging.ERROR):
        with pytest.raises(AdminMfaError, match=r"^totp_secret_encrypt_failed$"):
            await enroll_totp(session, subject=_SUBJECT, secret=leak_canary)

    assert leak_canary not in caplog.text, (
        "plaintext secret must never appear in a log line, even on encrypt failure"
    )
    assert _records_with_event(caplog.records, "argus.mfa.enroll.encrypt_failed")


@pytest.mark.asyncio
async def test_enroll_totp_wraps_update_db_error(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A DB failure on the persisting UPDATE is wrapped as ``db_error``."""
    _ = mfa_keyring
    await _seed_admin(session)
    # SELECT in _load_state succeeds (call #1); UPDATE fails (call #2).
    _override_execute_to_fail(session, fail_after=1)

    with caplog.at_level(logging.ERROR):
        with pytest.raises(AdminMfaError, match=r"^db_error$"):
            await enroll_totp(
                session,
                subject=_SUBJECT,
                secret="JBSWY3DPEHPK3PXP",
            )

    assert _records_with_event(caplog.records, "argus.mfa.enroll.db_error")


# ---- (14d) ``confirm_enrollment`` — no-pending, decrypt failure, DB error. -


@pytest.mark.asyncio
async def test_confirm_enrollment_raises_when_no_pending_secret(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
) -> None:
    """Confirming without a prior :func:`enroll_totp` call is a programmer bug."""
    _ = mfa_keyring
    await _seed_admin(session)

    with pytest.raises(AdminMfaError, match=r"^totp_not_enrolled$"):
        await confirm_enrollment(
            session,
            subject=_SUBJECT,
            totp_code="123456",
            generated_codes=["ABCDEFGHJKLMNPQR"],
        )


@pytest.mark.asyncio
async def test_confirm_enrollment_wraps_decrypt_failure(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """If the at-rest secret can't decrypt, refuse with a stable error code."""
    _ = mfa_keyring
    await _seed_admin(session)
    await enroll_totp(session, subject=_SUBJECT, secret="JBSWY3DPEHPK3PXP")
    await session.commit()

    def _broken_decrypt(_blob: bytes) -> str:
        raise MfaCryptoError("simulated wrong key")

    monkeypatch.setattr(admin_mfa_module, "decrypt", _broken_decrypt)

    with caplog.at_level(logging.ERROR):
        with pytest.raises(AdminMfaError, match=r"^totp_secret_decrypt_failed$"):
            await confirm_enrollment(
                session,
                subject=_SUBJECT,
                totp_code="123456",
                generated_codes=generate_backup_codes(),
            )

    assert _records_with_event(caplog.records, "argus.mfa.confirm.decrypt_failed")


@pytest.mark.asyncio
async def test_confirm_enrollment_wraps_update_db_error(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A DB failure on the finalisation UPDATE is wrapped as ``db_error``."""
    _ = mfa_keyring
    await _seed_admin(session)
    secret = pyotp.random_base32()
    await enroll_totp(session, subject=_SUBJECT, secret=secret)
    await session.commit()

    # SELECT in _load_state (call #1) succeeds; UPDATE (call #2) fails.
    _override_execute_to_fail(session, fail_after=1)

    with caplog.at_level(logging.ERROR):
        with pytest.raises(AdminMfaError, match=r"^db_error$"):
            await confirm_enrollment(
                session,
                subject=_SUBJECT,
                totp_code=pyotp.TOTP(secret).now(),
                generated_codes=generate_backup_codes(),
            )

    assert _records_with_event(caplog.records, "argus.mfa.confirm.db_error")


# ---- (14e) ``verify_totp`` — never raises; returns False on every failure. -


@pytest.mark.asyncio
async def test_verify_totp_returns_false_for_unknown_subject(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``_load_state`` failures are swallowed and surfaced as ``False`` (no enumeration)."""
    _ = mfa_keyring

    with caplog.at_level(logging.INFO):
        result = await verify_totp(
            session,
            subject="nobody@example.com",
            totp_code="123456",
        )

    assert result is False
    assert _records_with_event(caplog.records, "argus.mfa.verify.rejected")


@pytest.mark.asyncio
async def test_verify_totp_returns_false_when_mfa_disabled(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An admin with ``mfa_enabled = False`` cannot pass second-factor."""
    _ = mfa_keyring
    await _seed_admin(session)  # MFA disabled by default

    with caplog.at_level(logging.INFO):
        result = await verify_totp(
            session,
            subject=_SUBJECT,
            totp_code="123456",
        )

    assert result is False
    rejected = _records_with_event(caplog.records, "argus.mfa.verify.rejected")
    assert rejected, "must emit a structured rejection event for SIEM"
    assert any(getattr(r, "reason", None) == "not_enabled" for r in rejected)


@pytest.mark.asyncio
async def test_verify_totp_returns_false_when_decrypt_fails(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A crypto outage during ``verify`` is logged and returns ``False`` (no raise)."""
    _ = mfa_keyring
    await _seed_admin(session)
    await _enrol_and_confirm(session)

    def _broken_decrypt(_blob: bytes) -> str:
        raise MfaCryptoError("simulated keyring outage")

    monkeypatch.setattr(admin_mfa_module, "decrypt", _broken_decrypt)

    with caplog.at_level(logging.ERROR):
        result = await verify_totp(
            session,
            subject=_SUBJECT,
            totp_code="123456",
        )

    assert result is False, "verify_totp must never raise on crypto failure"
    assert _records_with_event(caplog.records, "argus.mfa.verify.decrypt_failed")


@pytest.mark.asyncio
async def test_verify_totp_succeeds_when_reencrypt_raises(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failure in opportunistic re-encryption never blocks a valid TOTP."""
    _ = mfa_keyring
    await _seed_admin(session)
    secret, _codes = await _enrol_and_confirm(session)

    def _broken_reencrypt(_blob: bytes) -> tuple[bytes, bool]:
        raise MfaCryptoError("simulated rotation failure")

    monkeypatch.setattr(admin_mfa_module, "reencrypt_if_stale", _broken_reencrypt)

    result = await verify_totp(
        session,
        subject=_SUBJECT,
        totp_code=pyotp.TOTP(secret).now(),
    )

    assert result is True, (
        "reencrypt_if_stale failure is a soft, non-blocking error — login must succeed"
    )


@pytest.mark.asyncio
async def test_verify_totp_succeeds_when_rotation_update_fails(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A DB failure on the rotation UPDATE is logged but doesn't fail the login."""
    _ = mfa_keyring
    await _seed_admin(session)
    secret, _codes = await _enrol_and_confirm(session)

    rotated_blob = b"rotated-fake-ciphertext"

    def _force_rotation(_blob: bytes) -> tuple[bytes, bool]:
        return rotated_blob, True

    monkeypatch.setattr(admin_mfa_module, "reencrypt_if_stale", _force_rotation)
    # SELECT in _load_state (call #1) succeeds; rotation UPDATE (call #2) fails.
    _override_execute_to_fail(session, fail_after=1)

    with caplog.at_level(logging.WARNING):
        result = await verify_totp(
            session,
            subject=_SUBJECT,
            totp_code=pyotp.TOTP(secret).now(),
        )

    assert result is True, (
        "verify must still succeed even when rotation persistence fails"
    )
    assert _records_with_event(caplog.records, "argus.mfa.verify.reencrypt_db_error")


# ---- (14f) ``consume_backup_code`` — defensive paths. ---------------------


@pytest.mark.asyncio
async def test_consume_backup_code_returns_false_for_unknown_subject(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Unknown subjects burn no row updates; return ``False`` + log a rejection."""
    _ = mfa_keyring

    with caplog.at_level(logging.INFO):
        result = await consume_backup_code(
            session,
            subject="nobody@example.com",
            code="ABCDEFGHJKLMNPQR",
        )

    assert result is False
    assert _records_with_event(caplog.records, "argus.mfa.backup.rejected")


@pytest.mark.asyncio
async def test_consume_backup_code_returns_false_when_no_codes_set(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An admin without persisted backup codes returns ``False`` (no exceptions)."""
    _ = mfa_keyring
    await _seed_admin(session)  # no backup codes; mfa_enabled = False

    with caplog.at_level(logging.INFO):
        result = await consume_backup_code(
            session,
            subject=_SUBJECT,
            code="ABCDEFGHJKLMNPQR",
        )

    assert result is False
    rejected = _records_with_event(caplog.records, "argus.mfa.backup.rejected")
    assert rejected
    assert any(getattr(r, "reason", None) == "no_codes" for r in rejected)


@pytest.mark.asyncio
async def test_consume_backup_code_returns_false_on_update_db_error(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A DB failure on the consuming UPDATE is logged and surfaced as ``False``."""
    _ = mfa_keyring
    await _seed_admin(session)
    _, codes = await _enrol_and_confirm(session)

    # SELECT (load_state, call #1) succeeds; UPDATE (call #2) fails.
    _override_execute_to_fail(session, fail_after=1)

    with caplog.at_level(logging.ERROR):
        result = await consume_backup_code(
            session,
            subject=_SUBJECT,
            code=codes[0],
        )

    assert result is False, (
        "consume_backup_code never raises — DB errors must be surfaced as False"
    )
    assert _records_with_event(caplog.records, "argus.mfa.backup.db_error")


@pytest.mark.asyncio
async def test_consume_backup_code_handles_malformed_digest(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
) -> None:
    """A malformed bcrypt digest in the backup-codes array returns ``False`` cleanly.

    Defends ``_bcrypt_verify``'s ``(ValueError, TypeError)`` handler — a
    row corrupted by manual DB intervention or a half-finished migration
    must fail closed, not crash the request loop. We mutate the row
    directly to inject the bad digest because the public DAO surface
    refuses to persist anything but well-formed bcrypt hashes.
    """
    _ = mfa_keyring
    await _seed_admin(session)
    await _enrol_and_confirm(session)

    user = await session.get(AdminUser, _SUBJECT)
    assert user is not None
    user.mfa_backup_codes_hash = ["this-is-not-a-bcrypt-digest"]
    await session.commit()

    result = await consume_backup_code(
        session,
        subject=_SUBJECT,
        code="ABCDEFGHJKLMNPQR",
    )
    await session.commit()

    assert result is False, "malformed digest must surface as no-match, never a crash"


# ---- (14g) ``disable_mfa`` / ``regenerate_backup_codes`` — DB error wrap. -


@pytest.mark.asyncio
async def test_disable_mfa_wraps_update_db_error(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A DB failure during the wipe UPDATE bubbles up as ``AdminMfaError("db_error")``."""
    _ = mfa_keyring
    await _seed_admin(session)
    _override_execute_to_fail(session)

    with caplog.at_level(logging.ERROR):
        with pytest.raises(AdminMfaError, match=r"^db_error$"):
            await disable_mfa(session, subject=_SUBJECT)

    assert _records_with_event(caplog.records, "argus.mfa.disable.db_error")


@pytest.mark.asyncio
async def test_regenerate_backup_codes_wraps_update_db_error(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A DB failure during regen UPDATE bubbles up as ``AdminMfaError("db_error")``."""
    _ = mfa_keyring
    await _seed_admin(session)
    await _enrol_and_confirm(session)

    # SELECT (load_state, call #1) succeeds; UPDATE (call #2) fails.
    _override_execute_to_fail(session, fail_after=1)

    with caplog.at_level(logging.ERROR):
        with pytest.raises(AdminMfaError, match=r"^db_error$"):
            await regenerate_backup_codes(session, subject=_SUBJECT)

    assert _records_with_event(caplog.records, "argus.mfa.regen.db_error")


# ---- (14h) ``mark_session_mfa_passed`` — invalid input + DB errors. -------


@pytest.mark.parametrize("token_hash", ["", "   "])
@pytest.mark.asyncio
async def test_mark_session_mfa_passed_no_op_for_invalid_input(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
    token_hash: str,
) -> None:
    """Empty / whitespace-only hash → log a structured warning and return (no raise)."""
    _ = mfa_keyring

    with caplog.at_level(logging.WARNING):
        await mark_session_mfa_passed(session, session_token_hash=token_hash)

    assert _records_with_event(caplog.records, "argus.mfa.session.invalid_input")


@pytest.mark.asyncio
async def test_mark_session_mfa_passed_swallows_select_db_error(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """SQLAlchemyError on SELECT must be logged and swallowed (never blocks login)."""
    _ = mfa_keyring
    _override_execute_to_fail(session)

    with caplog.at_level(logging.ERROR):
        # Must not raise — the contract is "best effort, never block login".
        await mark_session_mfa_passed(session, session_token_hash="f" * 64)

    assert _records_with_event(caplog.records, "argus.mfa.session.db_error")


@pytest.mark.asyncio
async def test_mark_session_mfa_passed_swallows_flush_db_error(
    session: AsyncSession,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A flush failure post-mutation is logged and swallowed (best-effort)."""
    _ = mfa_keyring
    _sid, asession = await create_session(
        session,
        subject=_SUBJECT,
        role="admin",
        tenant_id=None,
        ip="203.0.113.7",
        user_agent="argus-tests/1.0",
    )
    await session.commit()
    token_hash = asession.session_token_hash
    assert token_hash is not None

    _override_flush_to_fail(session)

    with caplog.at_level(logging.ERROR):
        await mark_session_mfa_passed(session, session_token_hash=token_hash)

    assert _records_with_event(caplog.records, "argus.mfa.session.db_error")
