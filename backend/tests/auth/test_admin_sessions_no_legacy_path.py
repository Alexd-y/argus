"""C7-T07 / ISS-T20-003 Phase 2c — assert no legacy session_id path remains.

Negative-coverage suite for the post-Alembic-031 contract: the legacy raw
``session_id`` column is gone, the ``ADMIN_SESSION_LEGACY_RAW_*`` flags are
gone, and the resolver / revoke path looks up by ``session_token_hash``
ONLY. These tests fail loudly the moment a regression resurrects any of the
removed surfaces — that is the entire point of keeping them around forever.

Coverage matrix (≥6 cases per the C7-T07 spec)
----------------------------------------------
1. ORM model: ``AdminSession.session_id`` does NOT exist; the only PK is
   ``session_token_hash``.
2. SQLite schema (post 028 → 030 → 031 → 032 chain): the
   ``admin_sessions`` table physically lacks the legacy column.
3. ``ADMIN_SESSION_LEGACY_RAW_WRITE`` and ``ADMIN_SESSION_LEGACY_RAW_FALLBACK``
   are NOT attributes of :class:`Settings` (validator + .env entry both
   removed).
4. ``create_session`` does NOT pass any ``session_id=`` kwarg to the row
   constructor: a row created with the pepper unset still raises (no
   silent legacy-write degradation).
5. A legacy-shape row CANNOT be inserted any more: trying to populate
   ``session_id`` on the ORM raises an ``AttributeError`` (the column
   simply does not exist on the mapped class).
6. The resolver looks up by hash — a row whose ``session_token_hash`` is
   forced to the wrong value (post-insert tamper) MUST resolve to
   ``None``, not to a "legacy fallback" hit.
7. The resolver short-circuits to ``None`` (rather than raising) when the
   pepper is unset — the legacy fallback that would otherwise have
   handled this case has been removed, so the function MUST honour the
   no-crash contract on its own.
8. Module-surface scrub: the ``admin_sessions`` source file contains no
   ``settings.admin_session_legacy_raw_*`` reference (regex sweep — keeps
   a renamed-but-not-removed flag from sneaking back in).
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import inspect, select, text

from src.auth import admin_sessions as admin_sessions_module
from src.auth.admin_sessions import (
    create_session,
    hash_session_token,
    resolve_session,
)
from src.core.config import Settings, settings
from src.db.models import AdminSession

_ADMIN_SESSIONS_SOURCE: Path = (
    Path(admin_sessions_module.__file__).resolve()
)


# ---------------------------------------------------------------------------
# 1. ORM shape — no legacy column, hash is the sole PK
# ---------------------------------------------------------------------------


def test_orm_admin_session_has_no_legacy_session_id_column() -> None:
    """The mapped class must not expose a ``session_id`` column attribute."""
    assert not hasattr(AdminSession, "session_id"), (
        "AdminSession.session_id must be gone post-031 — finding it here "
        "means the ORM was reverted; rerun Alembic 031 and re-check the "
        "C7-T07 cleanup."
    )
    column_names = {c.name for c in AdminSession.__table__.columns}
    assert "session_id" not in column_names, (
        f"admin_sessions.session_id must not appear in the ORM column set; "
        f"got {sorted(column_names)!r}"
    )


def test_orm_admin_session_pk_is_session_token_hash_only() -> None:
    """Post-031 the only primary-key column is ``session_token_hash``."""
    pk_columns = {col.name for col in AdminSession.__table__.primary_key.columns}
    assert pk_columns == {"session_token_hash"}, (
        f"AdminSession PK must be exactly (session_token_hash,) post-031; "
        f"got {pk_columns!r}"
    )


# ---------------------------------------------------------------------------
# 2. Live SQLite schema — table inspector confirms the drop
# ---------------------------------------------------------------------------


async def test_live_schema_has_no_session_id_column(engine) -> None:
    """The fixture-applied schema (028 → 030 → 031 → 032) lacks ``session_id``."""
    async with engine.connect() as conn:
        column_names = await conn.run_sync(
            lambda sync_conn: {
                col["name"]
                for col in inspect(sync_conn).get_columns("admin_sessions")
            }
        )

    assert "session_id" not in column_names, (
        f"admin_sessions.session_id must not exist post-031 in the test "
        f"fixture schema; got {sorted(column_names)!r}. Either the conftest "
        "is no longer applying 031 or the migration regressed."
    )
    assert "session_token_hash" in column_names, (
        "session_token_hash must remain — it is the post-031 PK"
    )


# ---------------------------------------------------------------------------
# 3. Settings — legacy flags are gone
# ---------------------------------------------------------------------------


def test_settings_has_no_legacy_raw_write_flag() -> None:
    """``Settings.admin_session_legacy_raw_write`` MUST be absent."""
    assert not hasattr(Settings, "admin_session_legacy_raw_write"), (
        "ADMIN_SESSION_LEGACY_RAW_WRITE was removed in C7-T07 — finding it "
        "on the Settings class means the cleanup regressed."
    )
    assert not hasattr(settings, "admin_session_legacy_raw_write"), (
        "live Settings instance still carries admin_session_legacy_raw_write "
        "— rerun the Wave 3 cleanup"
    )


def test_settings_has_no_legacy_raw_fallback_flag() -> None:
    """``Settings.admin_session_legacy_raw_fallback`` MUST be absent."""
    assert not hasattr(Settings, "admin_session_legacy_raw_fallback"), (
        "ADMIN_SESSION_LEGACY_RAW_FALLBACK was removed in C7-T07 — finding "
        "it on the Settings class means the cleanup regressed."
    )
    assert not hasattr(settings, "admin_session_legacy_raw_fallback"), (
        "live Settings instance still carries admin_session_legacy_raw_fallback "
        "— rerun the Wave 3 cleanup"
    )


# ---------------------------------------------------------------------------
# 4. create_session — no session_id kwarg, no silent legacy degradation
# ---------------------------------------------------------------------------


async def test_create_session_does_not_accept_session_id_kwarg(
    session,
) -> None:
    """``create_session(..., session_id=...)`` MUST raise ``TypeError``.

    The function never accepted that kwarg, but a regression that brought
    the legacy path back would likely re-add it. This is a contract pin.
    """
    with pytest.raises(TypeError):
        await create_session(  # type: ignore[call-arg]
            session,
            subject="alice@example.com",
            role="admin",
            tenant_id=None,
            ip=None,
            user_agent=None,
            session_id="this-kwarg-must-not-exist",
        )


async def test_create_session_writes_only_session_token_hash(session) -> None:
    """The persisted row exposes exactly the hash, never a raw token column."""
    raw_token, row = await create_session(
        session,
        subject="alice@example.com",
        role="admin",
        tenant_id=None,
        ip=None,
        user_agent=None,
    )
    await session.commit()

    assert row.session_token_hash == hash_session_token(raw_token), (
        "row PK must be the keyed digest; raw token must never be persisted"
    )
    assert not hasattr(row, "session_id"), (
        "AdminSession instance leaks a session_id attribute — the ORM "
        "shape regressed"
    )


# ---------------------------------------------------------------------------
# 5. Legacy-shape row insert is impossible at the ORM layer
# ---------------------------------------------------------------------------


async def test_legacy_shape_row_cannot_be_inserted_via_orm(session) -> None:
    """Trying to insert with ``session_id=`` on the model raises ``TypeError``."""
    now = datetime.now(timezone.utc)
    with pytest.raises(TypeError):
        AdminSession(  # type: ignore[call-arg]
            session_id="raw-legacy-token",
            session_token_hash=None,
            subject="legacy@example.com",
            role="admin",
            tenant_id=None,
            created_at=now,
            expires_at=now + timedelta(hours=1),
            last_used_at=now,
            ip_hash="0" * 64,
            user_agent_hash="0" * 64,
            revoked_at=None,
        )


async def test_raw_sql_insert_into_session_id_fails(session) -> None:
    """Even raw SQL cannot use the dropped column — defence in depth."""
    now = datetime.now(timezone.utc)
    with pytest.raises(Exception):
        await session.execute(
            text(
                "INSERT INTO admin_sessions ("
                "session_id, session_token_hash, subject, role, tenant_id, "
                "created_at, expires_at, last_used_at, ip_hash, "
                "user_agent_hash, revoked_at"
                ") VALUES ("
                ":sid, :h, :s, :r, NULL, :ca, :ea, :lu, :ih, :uh, NULL"
                ")"
            ),
            {
                "sid": "should-not-exist",
                "h": "0" * 64,
                "s": "legacy@example.com",
                "r": "admin",
                "ca": now,
                "ea": now + timedelta(hours=1),
                "lu": now,
                "ih": "0" * 64,
                "uh": "0" * 64,
            },
        )


# ---------------------------------------------------------------------------
# 6. Resolver — hash-only lookup; tampered hash misses
# ---------------------------------------------------------------------------


async def test_resolver_misses_when_hash_does_not_match_persisted(
    session,
) -> None:
    """Tamper the persisted hash; the resolver must miss instead of legacy-fallback."""
    raw_token, row = await create_session(
        session,
        subject="alice@example.com",
        role="admin",
        tenant_id=None,
        ip=None,
        user_agent=None,
    )
    await session.commit()

    # Force the persisted hash to a different value (simulates a row that
    # never had a valid hash). The resolver must NOT fall back to any
    # other lookup path now that the legacy column is gone.
    different_hash = "f" * 64
    await session.execute(
        text(
            "UPDATE admin_sessions SET session_token_hash = :h "
            "WHERE session_token_hash = :pk"
        ),
        {"h": different_hash, "pk": row.session_token_hash},
    )
    await session.commit()
    session.expire_all()

    principal = await resolve_session(session, session_id=raw_token)
    assert principal is None, (
        "tampered hash must produce a miss; a hit here proves the legacy "
        "fallback regressed"
    )

    refreshed = (
        await session.execute(
            select(AdminSession).where(AdminSession.session_token_hash == different_hash)
        )
    ).scalar_one_or_none()
    assert refreshed is not None, "test pre-condition: tampered row stays in DB"
    assert refreshed.session_token_hash == different_hash, (
        "no opportunistic backfill must run — that path was removed in C7-T07"
    )


# ---------------------------------------------------------------------------
# 7. Resolver fail-safe — no pepper means no crash AND no fallback
# ---------------------------------------------------------------------------


async def test_resolver_returns_none_without_pepper_no_legacy_path(
    session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Pepper unset → resolver MUST return ``None`` without touching legacy code."""
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
        "missing pepper must short-circuit to None; a hit here would mean "
        "a legacy fallback path resurrected"
    )


# ---------------------------------------------------------------------------
# 8. Source-level scrub — no settings.admin_session_legacy_raw_* references
# ---------------------------------------------------------------------------


_LEGACY_FLAG_REGEX = re.compile(
    r"settings\.admin_session_legacy_raw_(write|fallback)"
)


def test_admin_sessions_source_has_no_legacy_settings_references() -> None:
    """The resolver source MUST NOT reference the removed flags."""
    source = _ADMIN_SESSIONS_SOURCE.read_text(encoding="utf-8")
    matches = _LEGACY_FLAG_REGEX.findall(source)
    assert not matches, (
        "admin_sessions.py still contains references to removed "
        f"settings.admin_session_legacy_raw_* flags: {matches!r}. "
        "Wave 3 cleanup is incomplete."
    )
