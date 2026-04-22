"""bcrypt + bootstrap tests for ``src.auth.admin_users`` (B6-T08).

Covers the contract documented in :mod:`src.auth.admin_users`:

* ``hash_password`` produces a *valid bcrypt* digest with rounds >= 12;
* ``is_bcrypt_hash`` recognises canonical passlib bcrypt output and
  rejects every non-bcrypt string;
* ``verify_credentials`` returns ``None`` for every failure mode (subject
  missing, subject unknown, account disabled, password wrong, malformed
  hash) without ever raising and without leaking which path failed;
* ``bootstrap_admin_user_if_configured`` is idempotent, refuses
  plaintext / non-bcrypt env input, and re-enables a previously
  soft-deleted admin when the operator rotates the bootstrap config.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from src.auth.admin_users import (
    AdminPrincipal,
    bootstrap_admin_user_if_configured,
    hash_password,
    is_bcrypt_hash,
    verify_credentials,
)
from src.core.config import settings
from src.db.models import AdminUser

from .conftest import TEST_ADMIN_SUBJECT, TEST_PLAINTEXT_PASSWORD


# ---------------------------------------------------------------------------
# hash_password / is_bcrypt_hash
# ---------------------------------------------------------------------------


def test_hash_password_emits_passlib_bcrypt() -> None:
    digest = hash_password(TEST_PLAINTEXT_PASSWORD)
    assert is_bcrypt_hash(digest)
    assert digest.startswith("$2"), "passlib bcrypt hashes start with '$2'"
    assert len(digest) >= 60


def test_hash_password_rounds_cost_meets_minimum() -> None:
    """Rounds parameter encoded into the hash must be >= 12 (security floor)."""
    digest = hash_password(TEST_PLAINTEXT_PASSWORD)
    assert digest.startswith("$2"), "passlib bcrypt format expected"
    parts = digest.split("$")
    assert len(parts) >= 4, f"unexpected bcrypt format: {digest!r}"
    rounds = int(parts[2])
    assert rounds >= 12, (
        f"bcrypt rounds must be >= 12 per security policy, got {rounds}"
    )


def test_hash_password_rejects_empty_plaintext() -> None:
    with pytest.raises(ValueError, match="plaintext"):
        hash_password("")


def test_is_bcrypt_hash_rejects_non_bcrypt() -> None:
    assert is_bcrypt_hash(None) is False
    assert is_bcrypt_hash("") is False
    assert is_bcrypt_hash("plaintext-not-a-hash") is False
    assert is_bcrypt_hash("$argon2i$v=19$...") is False
    assert is_bcrypt_hash("$2") is False, "must require minimum length"


# ---------------------------------------------------------------------------
# verify_credentials
# ---------------------------------------------------------------------------


async def _seed_admin(
    session,
    *,
    subject: str = TEST_ADMIN_SUBJECT,
    plaintext: str = TEST_PLAINTEXT_PASSWORD,
    role: str = "admin",
    tenant_id: str | None = None,
    disabled_at: datetime | None = None,
    password_hash: str | None = None,
) -> AdminUser:
    row = AdminUser(
        subject=subject,
        password_hash=password_hash or hash_password(plaintext),
        role=role,
        tenant_id=tenant_id,
        created_at=datetime.now(timezone.utc),
        disabled_at=disabled_at,
    )
    session.add(row)
    await session.commit()
    return row


async def test_verify_credentials_happy_path_returns_principal(session) -> None:
    await _seed_admin(session)

    principal = await verify_credentials(
        session, subject=TEST_ADMIN_SUBJECT, password=TEST_PLAINTEXT_PASSWORD
    )
    assert isinstance(principal, AdminPrincipal)
    assert principal.subject == TEST_ADMIN_SUBJECT
    assert principal.role == "admin"
    assert principal.tenant_id is None


async def test_verify_credentials_normalizes_subject_whitespace(session) -> None:
    await _seed_admin(session)
    principal = await verify_credentials(
        session,
        subject="  " + TEST_ADMIN_SUBJECT + "  ",
        password=TEST_PLAINTEXT_PASSWORD,
    )
    assert principal is not None
    assert principal.subject == TEST_ADMIN_SUBJECT


async def test_verify_credentials_returns_none_for_wrong_password(session) -> None:
    await _seed_admin(session)
    assert (
        await verify_credentials(
            session, subject=TEST_ADMIN_SUBJECT, password="not the password"
        )
        is None
    )


async def test_verify_credentials_returns_none_for_unknown_subject(
    session,
) -> None:
    """Unknown subject path MUST equalise wall-clock cost (constant-time).

    We cannot assert on absolute timing in CI, so we assert on the contract:
    the call returns ``None`` and never raises (the equaliser path lives
    inside the function and is exercised here).
    """
    await _seed_admin(session)
    result = await verify_credentials(
        session, subject="nobody@nowhere.invalid", password=TEST_PLAINTEXT_PASSWORD
    )
    assert result is None


async def test_verify_credentials_returns_none_for_disabled_account(session) -> None:
    await _seed_admin(session, disabled_at=datetime.now(timezone.utc))
    assert (
        await verify_credentials(
            session, subject=TEST_ADMIN_SUBJECT, password=TEST_PLAINTEXT_PASSWORD
        )
        is None
    )


async def test_verify_credentials_returns_none_for_empty_credentials(
    session,
) -> None:
    await _seed_admin(session)
    assert await verify_credentials(session, subject="", password="x") is None
    assert (
        await verify_credentials(session, subject=TEST_ADMIN_SUBJECT, password="")
        is None
    )
    assert await verify_credentials(session, subject="   ", password="x") is None


async def test_verify_credentials_returns_none_for_malformed_hash(session) -> None:
    """Operator pasting a non-bcrypt blob into ``password_hash`` MUST NOT raise."""
    await _seed_admin(
        session, password_hash="not-a-bcrypt-hash-at-all-but-long-enough"
    )
    result = await verify_credentials(
        session, subject=TEST_ADMIN_SUBJECT, password=TEST_PLAINTEXT_PASSWORD
    )
    assert result is None, "malformed hash must downgrade to None silently"


async def test_verify_credentials_does_not_log_password(
    session, caplog: pytest.LogCaptureFixture
) -> None:
    """No bcrypt path should emit the plaintext password in any log line."""
    await _seed_admin(session)
    caplog.set_level("DEBUG", logger="src.auth.admin_users")

    await verify_credentials(
        session, subject=TEST_ADMIN_SUBJECT, password=TEST_PLAINTEXT_PASSWORD
    )
    await verify_credentials(
        session, subject=TEST_ADMIN_SUBJECT, password="wrong-password-xyz"
    )

    for record in caplog.records:
        msg = record.getMessage()
        assert TEST_PLAINTEXT_PASSWORD not in msg
        assert "wrong-password-xyz" not in msg


# ---------------------------------------------------------------------------
# bootstrap_admin_user_if_configured
# ---------------------------------------------------------------------------


@pytest.fixture
def _bootstrap_env(monkeypatch: pytest.MonkeyPatch):
    """Helper to point ``settings.admin_bootstrap_*`` at well-formed values."""

    def _apply(
        *,
        subject: str | None = TEST_ADMIN_SUBJECT,
        password_hash: str | None = None,
        role: str = "admin",
        tenant_id: str | None = None,
    ) -> str | None:
        monkeypatch.setattr(settings, "admin_bootstrap_subject", subject)
        monkeypatch.setattr(
            settings, "admin_bootstrap_password_hash", password_hash
        )
        monkeypatch.setattr(settings, "admin_bootstrap_role", role)
        monkeypatch.setattr(settings, "admin_bootstrap_tenant_id", tenant_id)
        return password_hash

    return _apply


async def test_bootstrap_no_op_when_subject_missing(
    patch_async_session_factory, _bootstrap_env, session_factory
) -> None:
    digest = hash_password(TEST_PLAINTEXT_PASSWORD)
    _bootstrap_env(subject=None, password_hash=digest)

    await bootstrap_admin_user_if_configured()

    async with session_factory() as s:
        rows = (await s.execute(_select_admin_users())).scalars().all()
        assert rows == [], "no admin row may be created without a subject"


async def test_bootstrap_no_op_when_hash_missing(
    patch_async_session_factory, _bootstrap_env, session_factory
) -> None:
    _bootstrap_env(subject=TEST_ADMIN_SUBJECT, password_hash=None)

    await bootstrap_admin_user_if_configured()

    async with session_factory() as s:
        rows = (await s.execute(_select_admin_users())).scalars().all()
        assert rows == [], "no admin row may be created without a hash"


async def test_bootstrap_creates_admin_when_configured(
    patch_async_session_factory, _bootstrap_env, session_factory
) -> None:
    digest = hash_password(TEST_PLAINTEXT_PASSWORD)
    _bootstrap_env(
        subject=TEST_ADMIN_SUBJECT,
        password_hash=digest,
        role="super-admin",
    )

    await bootstrap_admin_user_if_configured()

    async with session_factory() as s:
        row = await s.get(AdminUser, TEST_ADMIN_SUBJECT)
        assert row is not None
        assert row.password_hash == digest
        assert row.role == "super-admin"
        assert row.tenant_id is None
        assert row.disabled_at is None


async def test_bootstrap_is_idempotent_and_replaces_hash(
    patch_async_session_factory, _bootstrap_env, session_factory
) -> None:
    """Running the bootstrap twice MUST upsert (not duplicate) the row."""
    first_digest = hash_password(TEST_PLAINTEXT_PASSWORD)
    second_digest = hash_password("rotated-password-9817")
    _bootstrap_env(subject=TEST_ADMIN_SUBJECT, password_hash=first_digest)

    await bootstrap_admin_user_if_configured()

    _bootstrap_env(subject=TEST_ADMIN_SUBJECT, password_hash=second_digest)
    await bootstrap_admin_user_if_configured()

    async with session_factory() as s:
        rows = (await s.execute(_select_admin_users())).scalars().all()
        assert len(rows) == 1, "bootstrap MUST upsert, never duplicate"
        assert rows[0].password_hash == second_digest


async def test_bootstrap_re_enables_disabled_admin(
    patch_async_session_factory, _bootstrap_env, session_factory
) -> None:
    digest = hash_password(TEST_PLAINTEXT_PASSWORD)

    async with session_factory() as s:
        s.add(
            AdminUser(
                subject=TEST_ADMIN_SUBJECT,
                password_hash=digest,
                role="admin",
                tenant_id=None,
                created_at=datetime.now(timezone.utc),
                disabled_at=datetime.now(timezone.utc),
            )
        )
        await s.commit()

    _bootstrap_env(subject=TEST_ADMIN_SUBJECT, password_hash=digest)
    await bootstrap_admin_user_if_configured()

    async with session_factory() as s:
        row = await s.get(AdminUser, TEST_ADMIN_SUBJECT)
        assert row is not None
        assert row.disabled_at is None, (
            "bootstrap must re-enable the row when the operator rotates the seed"
        )


async def test_bootstrap_rejects_non_bcrypt_hash(
    patch_async_session_factory, _bootstrap_env, session_factory
) -> None:
    """``ADMIN_BOOTSTRAP_PASSWORD_HASH`` must be bcrypt; plaintext is refused."""
    _bootstrap_env(
        subject=TEST_ADMIN_SUBJECT,
        password_hash="this-is-clearly-plaintext-not-a-bcrypt-hash",
    )

    await bootstrap_admin_user_if_configured()

    async with session_factory() as s:
        rows = (await s.execute(_select_admin_users())).scalars().all()
        assert rows == [], (
            "non-bcrypt input must NOT be accepted as a password hash"
        )


async def test_bootstrap_strips_subject_whitespace_and_empty_tenant(
    patch_async_session_factory, _bootstrap_env, session_factory
) -> None:
    """Whitespace-padded subject + empty-string tenant id are normalised."""
    digest = hash_password(TEST_PLAINTEXT_PASSWORD)
    _bootstrap_env(
        subject="  " + TEST_ADMIN_SUBJECT + "  ",
        password_hash=digest,
        tenant_id="   ",
    )

    await bootstrap_admin_user_if_configured()

    async with session_factory() as s:
        row = await s.get(AdminUser, TEST_ADMIN_SUBJECT)
        assert row is not None
        assert row.tenant_id is None


def _select_admin_users():
    """Tiny helper so the SELECT statement does not get inlined ten times."""
    from sqlalchemy import select

    return select(AdminUser)
