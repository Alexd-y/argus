"""ISS-T20-003 hardening — at-rest hashing of admin session tokens.

Critical follow-up tests for B6-T08: defends the contract that the raw
CSPRNG bearer token NEVER reaches the database. Every persistence /
resolve / revoke path must round-trip through
``HMAC-SHA256(ADMIN_SESSION_PEPPER, raw_token)``; a database dump under a
different pepper must be fully unreplayable.

Coverage matrix
---------------
1. ``hash_session_token`` is deterministic and pepper-bound.
2. ``create_session`` writes ``session_token_hash`` and refuses without
   the pepper (fail-loud at mint time).
3. ``resolve_session`` declines gracefully when the pepper is missing
   instead of crashing the request loop.
4. A row inserted with a hash computed under a *different* pepper is
   unreachable — i.e. simulates the DB-leak attack.
5. ``revoke_session`` works via the (now sole) hash path.
6. Module surface contract: ``is_session_pepper_configured`` reflects
   the live setting and the public helpers stay re-exported.

History note
------------
Tests for the 030 → 031 grace-window legacy fallback path were removed in
Cycle 7 / C7-T07 once Alembic 031 dropped the legacy ``session_id`` column
and ``ADMIN_SESSION_LEGACY_RAW_*`` flags. The "no legacy path" invariant is
now asserted by ``test_admin_sessions_no_legacy_path`` (positive AND
negative coverage of the cleanup).

Test isolation
--------------
Every test pulls the per-test ``session`` fixture from
``backend/tests/auth/conftest.py`` (in-memory aiosqlite + revisions
028 + 030 + 031 + 032 applied). The pepper defaults to the deterministic
value set in conftest; tests that need to flip it use ``monkeypatch``
against the ``settings`` singleton — which is *exactly* how the
production resolver reads it, so the toggle stays representative.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import insert, select

from src.auth import admin_sessions as admin_sessions_module
from src.auth.admin_sessions import (
    create_session,
    hash_session_token,
    is_session_pepper_configured,
    resolve_session,
    revoke_session,
)
from src.core.config import settings
from src.db.models import AdminSession

# ---------------------------------------------------------------------------
# Local helpers — keep test bodies focused on the security invariant.
# ---------------------------------------------------------------------------

_DEFAULT_TEST_PEPPER: str = "test-pepper-iss-t20-003-not-for-prod-32chars-min"
_ALT_PEPPER: str = "completely-different-pepper-for-leak-attack-sim"


def _expected_hash(pepper: str, raw_token: str) -> str:
    """Mirror ``hash_session_token`` without going through the module guard.

    Independent re-implementation: if the production helper drifts
    (e.g. someone swaps the primitive), this comparison fires.
    """
    return hmac.new(
        pepper.encode("utf-8"),
        raw_token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


async def _fetch_row_by_hash(session, *, token_hash: str) -> AdminSession | None:
    """Force a cache-bypassing reload so post-update column values land."""
    session.expire_all()
    stmt = select(AdminSession).where(AdminSession.session_token_hash == token_hash)
    return (await session.execute(stmt)).scalar_one_or_none()


# ---------------------------------------------------------------------------
# 1. Deterministic / pepper-bound hash function
# ---------------------------------------------------------------------------


def test_hash_session_token_deterministic_same_pepper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``hash_session_token`` is a pure function of (pepper, raw_token)."""
    monkeypatch.setattr(settings, "admin_session_pepper", _DEFAULT_TEST_PEPPER)
    raw = "deterministic-fixed-token-payload"
    first = hash_session_token(raw)
    second = hash_session_token(raw)
    assert first == second
    assert first == _expected_hash(_DEFAULT_TEST_PEPPER, raw)


def test_hash_session_token_differs_for_different_pepper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same raw token + different pepper → different digests (no overlap)."""
    raw = "fixed-token-for-pepper-comparison"
    monkeypatch.setattr(settings, "admin_session_pepper", _DEFAULT_TEST_PEPPER)
    digest_default = hash_session_token(raw)
    monkeypatch.setattr(settings, "admin_session_pepper", _ALT_PEPPER)
    digest_alt = hash_session_token(raw)
    assert digest_default != digest_alt, (
        "pepper must change the hash — otherwise a leaked DB stays replayable"
    )
    assert digest_default == _expected_hash(_DEFAULT_TEST_PEPPER, raw)
    assert digest_alt == _expected_hash(_ALT_PEPPER, raw)


# ---------------------------------------------------------------------------
# 2. create_session writes the hash; refuses without a pepper
# ---------------------------------------------------------------------------


async def test_create_session_persists_token_hash(session) -> None:
    """The persisted row must carry ``HMAC-SHA256(pepper, raw_token)``."""
    raw_token, row = await create_session(
        session,
        subject="alice@example.com",
        role="admin",
        tenant_id=None,
        ip="203.0.113.7",
        user_agent="argus-tests/1.0",
    )
    await session.commit()

    assert row.session_token_hash is not None
    assert len(row.session_token_hash) == 64, "sha256 hex digest is 64 chars"
    assert row.session_token_hash == _expected_hash(
        _DEFAULT_TEST_PEPPER, raw_token
    ), "session_token_hash must equal HMAC-SHA256(pepper, raw_token)"
    assert row.session_token_hash != raw_token, (
        "raw token and hash must never coincide"
    )


async def test_pepper_missing_create_session_refuses(
    session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without a pepper ``create_session`` MUST fail loudly at mint time.

    Hashing is the *only* at-rest representation; minting a row with
    ``session_token_hash=NULL`` would silently regress to the pre-030
    leakable schema, so the function raises rather than degrading.
    """
    monkeypatch.setattr(settings, "admin_session_pepper", "")
    assert not is_session_pepper_configured()

    with pytest.raises(ValueError, match="ADMIN_SESSION_PEPPER"):
        await create_session(
            session,
            subject="alice@example.com",
            role="admin",
            tenant_id=None,
            ip=None,
            user_agent=None,
        )


# ---------------------------------------------------------------------------
# 3. resolver — fail-safe when pepper is missing
# ---------------------------------------------------------------------------


async def test_pepper_missing_resolver_returns_none_gracefully(
    session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resolver MUST return ``None`` (no exception) when the pepper is unset.

    A misconfigured pepper must NEVER bring down the request loop — it
    must simply refuse session-mode auth so the cookie-mode shim keeps
    serving legitimate requests.
    """
    raw_token, _ = await create_session(
        session,
        subject="alice@example.com",
        role="admin",
        tenant_id=None,
        ip=None,
        user_agent=None,
    )
    await session.commit()

    monkeypatch.setattr(settings, "admin_session_pepper", "")

    principal = await resolve_session(session, session_id=raw_token)
    assert principal is None, (
        "missing pepper must short-circuit to None, not raise"
    )


# ---------------------------------------------------------------------------
# 4. DB-leak attack simulation — different pepper makes hashes unreplayable
# ---------------------------------------------------------------------------


async def test_db_leak_attack_with_different_pepper_fails(
    session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Row inserted under pepper ``A`` must NOT resolve under pepper ``B``.

    Models the real attack: an adversary exfiltrates the ``admin_sessions``
    table (DB dump, backup leak, read-only SQLi). With a fresh, unknown
    pepper running on the live host, every leaked hash must be useless.
    """
    raw_token = "attacker-knows-this-raw-token-from-leak"
    digest_under_alt_pepper = _expected_hash(_ALT_PEPPER, raw_token)
    now = datetime.now(timezone.utc)
    await session.execute(
        insert(AdminSession).values(
            session_token_hash=digest_under_alt_pepper,
            subject="victim@example.com",
            role="admin",
            tenant_id=None,
            created_at=now,
            expires_at=now + timedelta(hours=12),
            last_used_at=now,
            ip_hash="0" * 64,
            user_agent_hash="0" * 64,
            revoked_at=None,
        )
    )
    await session.commit()

    monkeypatch.setattr(settings, "admin_session_pepper", _DEFAULT_TEST_PEPPER)

    principal = await resolve_session(session, session_id=raw_token)
    assert principal is None, (
        "row hashed under a different pepper must be unreachable — "
        "otherwise the DB leak is replayable"
    )


# ---------------------------------------------------------------------------
# 5. revoke_session — hash path
# ---------------------------------------------------------------------------


async def test_revoke_session_works_via_hash(session) -> None:
    """A session minted post-030 revokes via the ``session_token_hash`` lookup."""
    raw_token, _ = await create_session(
        session,
        subject="alice@example.com",
        role="admin",
        tenant_id=None,
        ip=None,
        user_agent=None,
    )
    await session.commit()

    revoked = await revoke_session(session, session_id=raw_token)
    await session.commit()

    assert revoked is True

    row = await _fetch_row_by_hash(
        session, token_hash=hash_session_token(raw_token)
    )
    assert row is not None, (
        "revoke is tombstone-only — the row must remain for audit"
    )
    assert row.revoked_at is not None, "revoked_at must be set on tombstone"

    second = await revoke_session(session, session_id=raw_token)
    assert second is False, (
        "second revoke is a no-op (idempotent) — must return False"
    )


# ---------------------------------------------------------------------------
# 6. Module surface contract — ``is_session_pepper_configured`` reflects state
# ---------------------------------------------------------------------------


def test_is_session_pepper_configured_reflects_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The helper must mirror the live ``settings.admin_session_pepper`` value."""
    monkeypatch.setattr(settings, "admin_session_pepper", _DEFAULT_TEST_PEPPER)
    assert is_session_pepper_configured() is True

    monkeypatch.setattr(settings, "admin_session_pepper", "")
    assert is_session_pepper_configured() is False

    monkeypatch.setattr(settings, "admin_session_pepper", "   \t\n  ")
    assert is_session_pepper_configured() is False, (
        "whitespace-only pepper carries zero entropy — must read as missing"
    )


def test_module_exports_hash_helpers() -> None:
    """``hash_session_token`` and ``is_session_pepper_configured`` are public.

    Migration 030 + the resolver both consume these helpers; renaming /
    moving them is a contract break and this test fails loudly to flag it.
    """
    assert hasattr(admin_sessions_module, "hash_session_token")
    assert hasattr(admin_sessions_module, "is_session_pepper_configured")
