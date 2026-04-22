"""ISS-T20-003 hardening — at-rest hashing of admin session tokens.

Critical follow-up tests for B6-T08: defends the contract that the raw
CSPRNG bearer token NEVER reaches the database. Every persistence /
resolve / revoke path must round-trip through
``sha256(ADMIN_SESSION_PEPPER || raw_token)``; a database dump under a
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
5. The 030 → 031 grace window: legacy rows (``session_token_hash`` NULL,
   ``session_id`` populated with the raw token) resolve via the legacy
   fallback, opportunistically backfill on first hit, and disable cleanly
   when ``admin_session_legacy_raw_fallback=False``.
6. ``revoke_session`` works through both the hash path and the legacy
   fallback path.

Test isolation
--------------
Every test pulls the per-test ``session`` fixture from
``backend/tests/auth/conftest.py`` (in-memory aiosqlite + revisions
028 + 030 applied). The pepper defaults to the deterministic value set
in conftest; tests that need to flip it use ``monkeypatch`` against the
``settings`` singleton — which is *exactly* how the production resolver
reads it, so the toggle stays representative.
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


async def _insert_legacy_row(
    session,
    *,
    raw_session_id: str,
    subject: str = "legacy@example.com",
    role: str = "admin",
    ttl_seconds: int = 3600,
) -> None:
    """Write a row that mimics a pre-030 token: only ``session_id`` populated.

    Bypasses ``create_session`` on purpose — the migration's grace-window
    fallback is the ONLY path through which such a row can appear, and
    the resolver must still accept it for one TTL after the deploy.
    """
    now = datetime.now(timezone.utc)
    await session.execute(
        insert(AdminSession).values(
            session_id=raw_session_id,
            session_token_hash=None,
            subject=subject,
            role=role,
            tenant_id=None,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
            last_used_at=now,
            ip_hash="0" * 64,
            user_agent_hash="0" * 64,
            revoked_at=None,
        )
    )
    await session.commit()


async def _fetch_row(session, *, session_id: str) -> AdminSession | None:
    """Force a cache-bypassing reload so ``session_token_hash`` updates land."""
    session.expire_all()
    stmt = select(AdminSession).where(AdminSession.session_id == session_id)
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
    """The persisted row must carry ``sha256(pepper + raw_token)``."""
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
    ), "session_token_hash must equal sha256(pepper + raw_token)"
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
    monkeypatch.setattr(settings, "admin_session_legacy_raw_fallback", False)

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
            session_id=digest_under_alt_pepper,
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
    monkeypatch.setattr(settings, "admin_session_legacy_raw_fallback", False)

    principal = await resolve_session(session, session_id=raw_token)
    assert principal is None, (
        "row hashed under a different pepper must be unreachable — "
        "otherwise the DB leak is replayable"
    )


# ---------------------------------------------------------------------------
# 5. Grace-window fallback: legacy rows + opportunistic backfill
# ---------------------------------------------------------------------------


async def test_legacy_raw_fallback_hits_when_hash_missing(
    session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pre-030 row (``session_token_hash`` NULL) resolves via the legacy path."""
    raw_session_id = "legacy-grace-window-token-must-still-resolve"
    await _insert_legacy_row(session, raw_session_id=raw_session_id)
    monkeypatch.setattr(settings, "admin_session_legacy_raw_fallback", True)

    principal = await resolve_session(session, session_id=raw_session_id)
    await session.commit()

    assert principal is not None
    assert principal.subject == "legacy@example.com"


async def test_legacy_raw_fallback_disabled_rejects_old_row(
    session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the grace flag flipped OFF, legacy rows are unreachable.

    This is the "two-TTL deadline" state — by the time we run Alembic 031
    the operator MUST have flipped the fallback off, otherwise the
    legacy column drop will silently sever every active session.
    """
    raw_session_id = "legacy-token-after-grace-window-closes"
    await _insert_legacy_row(session, raw_session_id=raw_session_id)
    monkeypatch.setattr(settings, "admin_session_legacy_raw_fallback", False)

    principal = await resolve_session(session, session_id=raw_session_id)
    assert principal is None, (
        "legacy fallback OFF + no hash on row → resolver must miss"
    )


async def test_opportunistic_backfill_runs_once_per_legacy_row(
    session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """First legacy hit backfills ``session_token_hash``; second hit uses it.

    Verifies the resolver upgrades a pre-030 row in place on first
    contact so subsequent traffic skips the legacy fallback entirely
    — that's how the grace window actually shrinks instead of dragging
    every active session along forever.
    """
    raw_session_id = "legacy-token-for-backfill-verification"
    await _insert_legacy_row(session, raw_session_id=raw_session_id)
    monkeypatch.setattr(settings, "admin_session_pepper", _DEFAULT_TEST_PEPPER)
    monkeypatch.setattr(settings, "admin_session_legacy_raw_fallback", True)

    pre_row = await _fetch_row(session, session_id=raw_session_id)
    assert pre_row is not None
    assert pre_row.session_token_hash is None, (
        "test pre-condition: legacy row starts with NULL hash"
    )

    first = await resolve_session(session, session_id=raw_session_id)
    await session.commit()
    assert first is not None, "first resolve must hit via legacy fallback"

    after_first = await _fetch_row(session, session_id=raw_session_id)
    assert after_first is not None
    expected_hash = _expected_hash(_DEFAULT_TEST_PEPPER, raw_session_id)
    assert after_first.session_token_hash == expected_hash, (
        "first resolve must opportunistically backfill session_token_hash"
    )

    monkeypatch.setattr(settings, "admin_session_legacy_raw_fallback", False)
    second = await resolve_session(session, session_id=raw_session_id)
    await session.commit()
    assert second is not None, (
        "after backfill the row resolves via the hash path — fallback OFF "
        "must NOT prevent the second hit"
    )

    after_second = await _fetch_row(session, session_id=raw_session_id)
    assert after_second is not None
    assert after_second.session_token_hash == expected_hash, (
        "second resolve must not perturb the (already-backfilled) hash"
    )


# ---------------------------------------------------------------------------
# 6. revoke_session — both code paths
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

    row = await _fetch_row(session, session_id=raw_token)
    assert row is not None, (
        "revoke is tombstone-only — the row must remain for audit"
    )
    assert row.revoked_at is not None, "revoked_at must be set on tombstone"

    second = await revoke_session(session, session_id=raw_token)
    assert second is False, (
        "second revoke is a no-op (idempotent) — must return False"
    )


async def test_revoke_session_works_via_legacy_fallback(
    session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pre-030 legacy row revokes via the ``session_id`` fallback path."""
    raw_session_id = "legacy-token-to-be-revoked"
    await _insert_legacy_row(session, raw_session_id=raw_session_id)
    monkeypatch.setattr(settings, "admin_session_legacy_raw_fallback", True)

    revoked = await revoke_session(session, session_id=raw_session_id)
    await session.commit()
    assert revoked is True, (
        "legacy row must revoke via the session_id fallback during the grace "
        "window"
    )

    row = await _fetch_row(session, session_id=raw_session_id)
    assert row is not None, "tombstone preserves the row for audit"
    assert row.revoked_at is not None


# ---------------------------------------------------------------------------
# 7. Module surface contract — ``is_session_pepper_configured`` reflects state
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


# ---------------------------------------------------------------------------
# 8. Module re-exports stay public surface
# ---------------------------------------------------------------------------


def test_module_exports_hash_helpers() -> None:
    """``hash_session_token`` and ``is_session_pepper_configured`` are public.

    Migration 030 + the resolver both consume these helpers; renaming /
    moving them is a contract break and this test fails loudly to flag it.
    """
    assert hasattr(admin_sessions_module, "hash_session_token")
    assert hasattr(admin_sessions_module, "is_session_pepper_configured")
