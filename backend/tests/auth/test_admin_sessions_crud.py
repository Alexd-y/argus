"""CRUD + sliding-window tests for ``src.auth.admin_sessions`` (B6-T08).

Exercises the contract documented in :mod:`src.auth.admin_sessions`:

* ``create_session`` mints a CSPRNG id, persists the row with hashed IP /
  UA, and rejects malformed inputs;
* ``revoke_session`` is idempotent and returns ``False`` for unknown ids;
* ``resolve_session`` returns ``None`` for missing / unknown / revoked /
  expired ids and slides ``last_used_at`` + ``expires_at`` forward on hit;
* ``redact_session_id`` never echoes the full id;
* ``generate_session_id`` produces high-entropy unique tokens.

Tests run against an in-memory aiosqlite engine with revision 028
applied (see ``conftest.py``). No HTTP layer involved.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from src.auth.admin_sessions import (
    SessionPrincipal,
    create_session,
    generate_session_id,
    hash_session_token,
    redact_session_id,
    resolve_session,
    revoke_session,
)
from src.db.models import AdminSession

# ---------------------------------------------------------------------------
# create_session
# ---------------------------------------------------------------------------


async def test_create_session_returns_id_and_persisted_row(session) -> None:
    session_id, row = await create_session(
        session,
        subject="alice@example.com",
        role="admin",
        tenant_id=None,
        ip="203.0.113.7",
        user_agent="argus-tests/1.0",
    )
    await session.commit()

    assert isinstance(session_id, str)
    assert len(session_id) >= 60, "session id must carry >256 bits of entropy"
    expected_hash = hash_session_token(session_id)
    assert row.session_token_hash == expected_hash, (
        "row PK must be the keyed at-rest digest, never the raw token"
    )
    assert row.subject == "alice@example.com"
    assert row.role == "admin"
    assert row.tenant_id is None
    assert row.revoked_at is None
    assert row.ip_hash and row.ip_hash != "203.0.113.7", (
        "raw IP must never reach the database"
    )
    assert row.user_agent_hash and "argus-tests" not in row.user_agent_hash

    fetched = await session.get(AdminSession, expected_hash)
    assert fetched is not None and fetched.session_token_hash == expected_hash


async def test_create_session_normalizes_role_aliases(session) -> None:
    """Loose ``super_admin`` / ``Super-Admin`` spelling is canonicalised."""
    _, row = await create_session(
        session,
        subject="root@example.com",
        role="Super_Admin",
        tenant_id=None,
        ip=None,
        user_agent=None,
    )
    await session.commit()
    assert row.role == "super-admin"


async def test_create_session_strips_subject_whitespace(session) -> None:
    _, row = await create_session(
        session,
        subject="  bob@example.com  ",
        role="operator",
        tenant_id="11111111-1111-1111-1111-111111111111",
        ip="10.0.0.1",
        user_agent="curl/8",
    )
    await session.commit()
    assert row.subject == "bob@example.com"
    assert row.tenant_id == "11111111-1111-1111-1111-111111111111"


async def test_create_session_rejects_empty_subject(session) -> None:
    with pytest.raises(ValueError, match="subject"):
        await create_session(
            session,
            subject="   ",
            role="admin",
            tenant_id=None,
            ip=None,
            user_agent=None,
        )


async def test_create_session_rejects_unknown_role(session) -> None:
    with pytest.raises(ValueError, match="unknown admin role"):
        await create_session(
            session,
            subject="x@example.com",
            role="root",
            tenant_id=None,
            ip=None,
            user_agent=None,
        )


async def test_create_session_rejects_non_positive_ttl(session) -> None:
    with pytest.raises(ValueError, match="ttl_seconds"):
        await create_session(
            session,
            subject="x@example.com",
            role="admin",
            tenant_id=None,
            ip=None,
            user_agent=None,
            ttl_seconds=0,
        )


# ---------------------------------------------------------------------------
# resolve_session — happy path + sliding window
# ---------------------------------------------------------------------------


async def test_resolve_session_returns_principal_on_hit(session) -> None:
    sid, _ = await create_session(
        session,
        subject="alice@example.com",
        role="admin",
        tenant_id=None,
        ip=None,
        user_agent=None,
        ttl_seconds=3600,
    )
    await session.commit()

    principal = await resolve_session(session, session_id=sid)
    await session.commit()

    assert isinstance(principal, SessionPrincipal)
    assert principal.subject == "alice@example.com"
    assert principal.role == "admin"
    assert principal.tenant_id is None
    assert principal.expires_at.tzinfo is not None


async def test_resolve_session_extends_ttl_sliding_window(session) -> None:
    """``resolve_session`` MUST push ``expires_at`` and ``last_used_at`` forward."""
    sid, row = await create_session(
        session,
        subject="alice@example.com",
        role="admin",
        tenant_id=None,
        ip=None,
        user_agent=None,
        ttl_seconds=3600,
    )
    await session.commit()
    initial_expires = row.expires_at
    initial_last_used = row.last_used_at

    await asyncio.sleep(0.05)

    principal = await resolve_session(session, session_id=sid, ttl_seconds=7200)
    await session.commit()
    assert principal is not None

    refreshed = await session.get(AdminSession, hash_session_token(sid))
    assert refreshed is not None
    assert _ensure_aware(refreshed.expires_at) > _ensure_aware(initial_expires), (
        "sliding window: resolve must push expires_at forward"
    )
    assert _ensure_aware(refreshed.last_used_at) > _ensure_aware(initial_last_used), (
        "sliding window: resolve must push last_used_at forward"
    )


async def test_resolve_session_returns_none_for_missing_id(session) -> None:
    assert await resolve_session(session, session_id=None) is None
    assert await resolve_session(session, session_id="") is None


async def test_resolve_session_returns_none_for_unknown_id(session) -> None:
    bogus = generate_session_id()
    assert await resolve_session(session, session_id=bogus) is None


async def test_resolve_session_returns_none_for_revoked(session) -> None:
    sid, _ = await create_session(
        session,
        subject="alice@example.com",
        role="admin",
        tenant_id=None,
        ip=None,
        user_agent=None,
    )
    revoked = await revoke_session(session, session_id=sid)
    await session.commit()
    assert revoked is True

    assert await resolve_session(session, session_id=sid) is None


async def test_resolve_session_returns_none_for_expired(session) -> None:
    """Mutate ``expires_at`` into the past and confirm the resolver refuses it."""
    sid, _ = await create_session(
        session,
        subject="alice@example.com",
        role="admin",
        tenant_id=None,
        ip=None,
        user_agent=None,
    )
    await session.commit()

    fetched = await session.get(AdminSession, hash_session_token(sid))
    assert fetched is not None
    fetched.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    await session.commit()

    assert await resolve_session(session, session_id=sid) is None


# ---------------------------------------------------------------------------
# revoke_session
# ---------------------------------------------------------------------------


async def test_revoke_session_returns_true_first_time_false_second_time(
    session,
) -> None:
    sid, _ = await create_session(
        session,
        subject="alice@example.com",
        role="admin",
        tenant_id=None,
        ip=None,
        user_agent=None,
    )
    await session.commit()

    first = await revoke_session(session, session_id=sid)
    await session.commit()
    second = await revoke_session(session, session_id=sid)
    await session.commit()

    assert first is True
    assert second is False, "revoke must be idempotent on already-revoked rows"


async def test_revoke_session_unknown_id_returns_false(session) -> None:
    assert await revoke_session(session, session_id="nonexistent") is False
    assert await revoke_session(session, session_id="") is False


async def test_revoke_session_sets_revoked_at_timestamp(session) -> None:
    sid, _ = await create_session(
        session,
        subject="alice@example.com",
        role="admin",
        tenant_id=None,
        ip=None,
        user_agent=None,
    )
    await session.commit()

    await revoke_session(session, session_id=sid)
    await session.commit()

    fetched = await session.get(AdminSession, hash_session_token(sid))
    assert fetched is not None
    assert fetched.revoked_at is not None


# ---------------------------------------------------------------------------
# redact_session_id + generate_session_id
# ---------------------------------------------------------------------------


def test_redact_session_id_keeps_only_prefix() -> None:
    full = generate_session_id()
    redacted = redact_session_id(full)
    assert redacted.endswith("...")
    assert len(redacted) <= 9, "redaction must keep the prefix small"
    assert full[:6] in redacted
    assert full not in redacted


def test_redact_session_id_handles_empty() -> None:
    assert redact_session_id(None) == "<empty>"
    assert redact_session_id("") == "<empty>"


def test_generate_session_id_is_unique_high_entropy() -> None:
    samples = {generate_session_id() for _ in range(64)}
    assert len(samples) == 64, "CSPRNG must produce distinct ids"
    for sid in samples:
        assert len(sid) >= 60


# ---------------------------------------------------------------------------
# IP / UA hashing — store digest, never plaintext
# ---------------------------------------------------------------------------


async def test_ip_and_ua_are_hashed_not_stored_plaintext(session) -> None:
    sid, _ = await create_session(
        session,
        subject="alice@example.com",
        role="admin",
        tenant_id=None,
        ip="198.51.100.42",
        user_agent="Mozilla/5.0 (X11; Linux x86_64)",
    )
    await session.commit()

    fetched = await session.get(AdminSession, hash_session_token(sid))
    assert fetched is not None
    assert "198.51.100.42" not in fetched.ip_hash
    assert "Mozilla" not in fetched.user_agent_hash
    assert len(fetched.ip_hash) == 64, "sha256 hex digest is 64 chars"
    assert len(fetched.user_agent_hash) == 64


async def test_resolve_session_does_not_re_validate_ip_or_ua(session) -> None:
    """Sliding-window resolve must accept rotating IPs / UAs (commute attacks)."""
    sid, _ = await create_session(
        session,
        subject="alice@example.com",
        role="admin",
        tenant_id=None,
        ip="198.51.100.1",
        user_agent="ua-A",
    )
    await session.commit()

    principal = await resolve_session(
        session, session_id=sid, ip="203.0.113.99", user_agent="ua-B"
    )
    await session.commit()
    assert principal is not None, (
        "rotating IPs/UAs must NOT log the operator out (legit corporate NAT)"
    )


# ---------------------------------------------------------------------------
# Index sanity — ix_admin_sessions_subject_revoked exists and is queryable.
# ---------------------------------------------------------------------------


async def test_subject_revoked_index_supports_revoke_lookups(session) -> None:
    """The (subject, revoked_at) index lets the bulk-revoke path stay fast."""
    for n in range(3):
        await create_session(
            session,
            subject="alice@example.com",
            role="admin",
            tenant_id=None,
            ip=None,
            user_agent=f"agent-{n}",
        )
    await session.commit()

    stmt = (
        select(AdminSession)
        .where(AdminSession.subject == "alice@example.com")
        .where(AdminSession.revoked_at.is_(None))
    )
    rows = (await session.execute(stmt)).scalars().all()
    assert len(rows) == 3


def _ensure_aware(dt: datetime) -> datetime:
    """Promote naive datetimes (SQLite quirk) to UTC for safe comparisons."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
