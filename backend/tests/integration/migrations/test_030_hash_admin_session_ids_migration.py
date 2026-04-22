r"""ISS-T20-003 hardening — ``030_hash_admin_session_ids`` migration tests.

Three-layer strategy mirroring ``test_028_admin_sessions_migration.py`` but
extended with a Layer A.5 that drives the migration end-to-end against an
in-memory SQLite engine. The 030 migration relies on ``op.batch_alter_table``
on SQLite, so a real upgrade/downgrade roundtrip is cheap, deterministic,
and Postgres-free — and it's the only way to verify the ``session_token_hash``
backfill behavior without booting a Postgres container.

A.   Dialect-free metadata checks — always run.
A.5. SQLite roundtrip — the heart of the suite (covers backfill,
     idempotence, and missing-pepper safety).
B.   Postgres roundtrip — gated by ``@pytest.mark.requires_postgres``.

Why test against SQLite at all
------------------------------
The legacy ``session_id`` column is the entire payload of the backfill
helper, and SQLite's ``ALTER TABLE`` quirks were the precise reason the
migration uses ``op.batch_alter_table`` for SQLite. Running the upgrade
on SQLite catches every dialect divergence the production Postgres path
would silently mask.

How to run the Postgres half locally (PowerShell)::

    docker run --rm -d --name argus-pg-t20-030 -p 55432:5432 `
        -e POSTGRES_PASSWORD=argus -e POSTGRES_DB=argus_test postgres:15
    $env:DATABASE_URL = "postgresql+asyncpg://postgres:argus@localhost:55432/argus_test"
    .\.venv\Scripts\python.exe -m pytest `
        backend/tests/integration/migrations/test_030_hash_admin_session_ids_migration.py -v
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import logging
import os
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

_BACKEND_ROOT = Path(__file__).resolve().parents[3]
_VERSIONS_DIR = _BACKEND_ROOT / "alembic" / "versions"
_REVISION = "030"
_DOWN_REVISION = "029"
_REVISION_028 = "028"
_SESSIONS_TABLE = "admin_sessions"
_HASH_COLUMN = "session_token_hash"
_HASH_INDEX = "ix_admin_sessions_token_hash"
_PEPPER_ENV = "ADMIN_SESSION_PEPPER"
_TEST_PEPPER = "test-030-migration-pepper-32chars-or-more-bytes"

# Gate for Layer B (real Postgres).
_PG_URL_RAW = os.environ.get("DATABASE_URL", "")
_HAS_POSTGRES_URL = _PG_URL_RAW.startswith(
    ("postgresql://", "postgresql+", "postgres://")
)

pytestmark_pg = pytest.mark.skipif(
    not _HAS_POSTGRES_URL,
    reason=(
        "DATABASE_URL is not a Postgres URL — admin_sessions hash-column "
        "checks need a real Postgres engine"
    ),
)


# ---------------------------------------------------------------------------
# Shared helpers.
# ---------------------------------------------------------------------------


def _load_revision_module(revision: str) -> Any:
    """Import a migration file as a standalone module (no chain run)."""
    matches = list(_VERSIONS_DIR.glob(f"{revision}_*.py"))
    assert matches, f"revision file for {revision} not found"
    spec = importlib.util.spec_from_file_location(
        f"_alembic_{revision}", matches[0]
    )
    assert spec and spec.loader, f"unable to load spec for {matches[0]}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _alembic_config(database_url: str) -> Config:
    cfg = Config(str(_BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


def _to_sync_url(url: str) -> str:
    """Translate the asyncpg URL used by ``alembic.env`` into a psycopg2 one."""
    for prefix in ("postgresql+asyncpg://", "postgres+asyncpg://"):
        if url.startswith(prefix):
            return "postgresql://" + url[len(prefix) :]
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://") :]
    return url


def _expected_hash(pepper: str, raw_token: str) -> str:
    """Independent HMAC re-implementation — drift-detector for the migration."""
    return hmac.new(
        pepper.encode("utf-8"),
        raw_token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _apply_revision_with_op_context(connection: sa.engine.Connection, revision: str) -> None:
    """Apply *revision*'s ``upgrade()`` using a fresh Alembic op context."""
    module = _load_revision_module(revision)
    ctx = MigrationContext.configure(connection)
    with Operations.context(ctx):
        module.upgrade()


def _downgrade_revision_with_op_context(
    connection: sa.engine.Connection, revision: str
) -> None:
    """Apply *revision*'s ``downgrade()`` using a fresh Alembic op context."""
    module = _load_revision_module(revision)
    ctx = MigrationContext.configure(connection)
    with Operations.context(ctx):
        module.downgrade()


def _seed_legacy_session_row(
    connection: sa.engine.Connection,
    *,
    raw_session_id: str,
    subject: str = "legacy@example.com",
    role: str = "admin",
    ttl_seconds: int = 12 * 3600,
) -> None:
    """Insert a row that mimics a pre-030 token (raw token in ``session_id``).

    Schema MUST be at revision 028 (no ``session_token_hash`` column yet)
    when this is called — that is the operational baseline we are
    migrating from.
    """
    now = datetime.now(timezone.utc)
    connection.execute(
        text(
            f"""
            INSERT INTO {_SESSIONS_TABLE} (
                session_id, subject, role,
                created_at, expires_at, last_used_at,
                ip_hash, user_agent_hash
            ) VALUES (
                :sid, :sub, :r,
                :ca, :ea, :lu,
                :ih, :uh
            )
            """
        ),
        {
            "sid": raw_session_id,
            "sub": subject,
            "r": role,
            "ca": now,
            "ea": now + timedelta(seconds=ttl_seconds),
            "lu": now,
            "ih": "0" * 64,
            "uh": "0" * 64,
        },
    )


@pytest.fixture()
def sqlite_engine() -> Iterator[Engine]:
    """In-memory sync SQLite engine with revision 028 applied.

    Yields the engine pre-loaded with the ``admin_users`` + ``admin_sessions``
    tables so each test starts at the canonical pre-030 baseline.
    """
    engine = sa.create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=sa.pool.StaticPool,
        future=True,
    )
    try:
        with engine.begin() as conn:
            _apply_revision_with_op_context(conn, _REVISION_028)
        yield engine
    finally:
        engine.dispose()


@pytest.fixture(autouse=True)
def _isolate_pepper_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure each test starts with no ambient ``ADMIN_SESSION_PEPPER``.

    The conftest at ``backend/tests/auth/conftest.py`` sets the env var
    via ``os.environ.setdefault`` to keep that suite deterministic. This
    one wants to *control* the env var from each test, so we wipe any
    inherited value up front.
    """
    monkeypatch.delenv(_PEPPER_ENV, raising=False)


# ---------------------------------------------------------------------------
# Layer A — dialect-free metadata checks.
# ---------------------------------------------------------------------------


def test_030_revision_metadata_pinned() -> None:
    module = _load_revision_module(_REVISION)
    assert module.revision == _REVISION, (
        f"030 migration must declare revision={_REVISION!r}, "
        f"got {module.revision!r}"
    )
    assert module.down_revision == _DOWN_REVISION, (
        f"030 migration must chain off {_DOWN_REVISION!r}, "
        f"got {module.down_revision!r}"
    )
    assert module.branch_labels is None, "030 must not introduce a branch label"
    assert module.depends_on is None, "030 must not depend on another revision"


def test_030_has_upgrade_and_downgrade_callables() -> None:
    module = _load_revision_module(_REVISION)
    assert callable(getattr(module, "upgrade", None)), (
        "030.upgrade missing or not callable"
    )
    assert callable(getattr(module, "downgrade", None)), (
        "030.downgrade missing or not callable"
    )


def test_030_orm_admin_session_carries_hash_column() -> None:
    """``AdminSession.session_token_hash`` must exist, be UNIQUE, and indexed."""
    from src.db.models import AdminSession

    table = cast(sa.Table, AdminSession.__table__)
    assert _HASH_COLUMN in table.columns, (
        f"AdminSession ORM missing {_HASH_COLUMN!r} column"
    )
    column = table.columns[_HASH_COLUMN]
    assert column.nullable is True, (
        f"{_HASH_COLUMN} must stay NULL-able during the 030 → 031 grace window"
    )
    assert column.unique is True, (
        f"{_HASH_COLUMN} must be UNIQUE — primary lookup column post-030"
    )


# ---------------------------------------------------------------------------
# Layer A.5 — SQLite roundtrip checks (the bulk of the coverage).
# ---------------------------------------------------------------------------


def test_upgrade_adds_hash_column_and_index(sqlite_engine: Engine) -> None:
    """After ``030.upgrade()`` the column + unique index must be present."""
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    insp = inspect(sqlite_engine)
    columns = {c["name"] for c in insp.get_columns(_SESSIONS_TABLE)}
    assert _HASH_COLUMN in columns, (
        f"030.upgrade must add {_HASH_COLUMN} to {_SESSIONS_TABLE}"
    )

    indexes = {ix["name"]: ix for ix in insp.get_indexes(_SESSIONS_TABLE)}
    assert _HASH_INDEX in indexes, (
        f"030.upgrade must create unique index {_HASH_INDEX!r}"
    )
    # SQLite inspector returns ``unique`` as int (0/1); Postgres returns bool.
    assert bool(indexes[_HASH_INDEX]["unique"]) is True, (
        f"{_HASH_INDEX} must be UNIQUE — replay defence relies on it"
    )
    assert indexes[_HASH_INDEX]["column_names"] == [_HASH_COLUMN], (
        f"{_HASH_INDEX} must cover ({_HASH_COLUMN},), got "
        f"{indexes[_HASH_INDEX]['column_names']}"
    )


def test_downgrade_drops_hash_column_and_index(sqlite_engine: Engine) -> None:
    """``030.downgrade()`` must remove the hash column AND its index cleanly."""
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    insp = inspect(sqlite_engine)
    assert _HASH_COLUMN in {
        c["name"] for c in insp.get_columns(_SESSIONS_TABLE)
    }

    with sqlite_engine.begin() as conn:
        _downgrade_revision_with_op_context(conn, _REVISION)

    insp = inspect(sqlite_engine)
    columns = {c["name"] for c in insp.get_columns(_SESSIONS_TABLE)}
    assert _HASH_COLUMN not in columns, (
        f"030.downgrade must drop {_HASH_COLUMN} from {_SESSIONS_TABLE}"
    )
    indexes = {ix["name"] for ix in insp.get_indexes(_SESSIONS_TABLE)}
    assert _HASH_INDEX not in indexes, (
        f"030.downgrade must drop {_HASH_INDEX!r}"
    )


def test_upgrade_backfills_when_pepper_set(
    sqlite_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Existing legacy rows must be backfilled with ``sha256(pepper||raw)``."""
    raw_token_a = "legacy-token-alpha-must-be-backfilled"
    raw_token_b = "legacy-token-beta-must-be-backfilled"
    with sqlite_engine.begin() as conn:
        _seed_legacy_session_row(
            conn, raw_session_id=raw_token_a, subject="alpha@example.com"
        )
        _seed_legacy_session_row(
            conn, raw_session_id=raw_token_b, subject="beta@example.com"
        )

    monkeypatch.setenv(_PEPPER_ENV, _TEST_PEPPER)
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    with sqlite_engine.connect() as conn:
        rows = conn.execute(
            text(
                f"""
                SELECT session_id, {_HASH_COLUMN}
                FROM {_SESSIONS_TABLE}
                ORDER BY session_id
                """
            )
        ).all()
    by_session_id = {r[0]: r[1] for r in rows}
    assert by_session_id[raw_token_a] == _expected_hash(
        _TEST_PEPPER, raw_token_a
    ), "alpha row must carry sha256(pepper + raw_token_a)"
    assert by_session_id[raw_token_b] == _expected_hash(
        _TEST_PEPPER, raw_token_b
    ), "beta row must carry sha256(pepper + raw_token_b)"


def test_upgrade_skips_backfill_when_pepper_missing(
    sqlite_engine: Engine, caplog: pytest.LogCaptureFixture
) -> None:
    """Missing pepper → backfill skipped + WARNING logged (no crash).

    Operational invariant: the migration must NEVER abort just because
    ``ADMIN_SESSION_PEPPER`` is unset. The cookie-mode fallback keeps
    admin access alive while ops sets the pepper and re-runs
    ``alembic stamp head``-and-friends.
    """
    raw_token = "legacy-token-without-pepper-stays-null-hash"
    with sqlite_engine.begin() as conn:
        _seed_legacy_session_row(conn, raw_session_id=raw_token)

    assert _PEPPER_ENV not in os.environ, (
        "test setup precondition: pepper must be unset"
    )

    with caplog.at_level(
        logging.WARNING, logger="alembic.030_hash_admin_session_ids"
    ):
        with sqlite_engine.begin() as conn:
            _apply_revision_with_op_context(conn, _REVISION)

    with sqlite_engine.connect() as conn:
        hash_value = conn.execute(
            text(
                f"SELECT {_HASH_COLUMN} FROM {_SESSIONS_TABLE} "
                "WHERE session_id = :sid"
            ),
            {"sid": raw_token},
        ).scalar_one()
    assert hash_value is None, (
        f"missing pepper must leave {_HASH_COLUMN} NULL for legacy rows"
    )

    matching = [
        r
        for r in caplog.records
        if r.name == "alembic.030_hash_admin_session_ids"
        and r.levelno == logging.WARNING
        and _PEPPER_ENV in r.getMessage()
    ]
    assert matching, (
        f"030.upgrade must emit a WARNING that mentions {_PEPPER_ENV} "
        "when the pepper is unset"
    )


def test_upgrade_idempotent_under_repeated_run(
    sqlite_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round-trip ``upgrade → downgrade → upgrade`` must yield identical hashes.

    This proves the migration is safe to re-run after a rollback (the
    canonical operational scenario for "what if we have to redeploy?").
    Also exercises that the index drop in downgrade is clean enough to
    let the re-create succeed.
    """
    raw_token = "legacy-token-idempotence-probe"
    with sqlite_engine.begin() as conn:
        _seed_legacy_session_row(conn, raw_session_id=raw_token)

    monkeypatch.setenv(_PEPPER_ENV, _TEST_PEPPER)
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    with sqlite_engine.connect() as conn:
        first_hash = conn.execute(
            text(
                f"SELECT {_HASH_COLUMN} FROM {_SESSIONS_TABLE} "
                "WHERE session_id = :sid"
            ),
            {"sid": raw_token},
        ).scalar_one()
        first_count = conn.execute(
            text(f"SELECT COUNT(*) FROM {_SESSIONS_TABLE}")
        ).scalar_one()
    assert first_hash == _expected_hash(_TEST_PEPPER, raw_token)
    assert first_count == 1

    with sqlite_engine.begin() as conn:
        _downgrade_revision_with_op_context(conn, _REVISION)
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    with sqlite_engine.connect() as conn:
        second_hash = conn.execute(
            text(
                f"SELECT {_HASH_COLUMN} FROM {_SESSIONS_TABLE} "
                "WHERE session_id = :sid"
            ),
            {"sid": raw_token},
        ).scalar_one()
        second_count = conn.execute(
            text(f"SELECT COUNT(*) FROM {_SESSIONS_TABLE}")
        ).scalar_one()
    assert second_hash == first_hash, (
        "second upgrade must produce the same hash — pepper-bound sha256 "
        "is deterministic"
    )
    assert second_count == first_count, (
        "second upgrade must NOT duplicate rows (downgrade preserves the "
        "session_id PK content, just drops the hash column)"
    )


def test_backfill_helper_is_idempotent_for_same_pepper(
    sqlite_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Calling ``_backfill_token_hash`` twice with the same pepper is a no-op.

    Belt-and-braces companion to the round-trip idempotence test —
    proves the function-level contract independent of the schema dance.
    """
    raw_token = "legacy-token-helper-idempotence-probe"
    with sqlite_engine.begin() as conn:
        _seed_legacy_session_row(conn, raw_session_id=raw_token)

    monkeypatch.setenv(_PEPPER_ENV, _TEST_PEPPER)
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    module = _load_revision_module(_REVISION)
    with sqlite_engine.begin() as conn:
        before = conn.execute(
            text(
                f"SELECT {_HASH_COLUMN} FROM {_SESSIONS_TABLE} "
                "WHERE session_id = :sid"
            ),
            {"sid": raw_token},
        ).scalar_one()
        module._backfill_token_hash(conn, pepper=_TEST_PEPPER)
        after = conn.execute(
            text(
                f"SELECT {_HASH_COLUMN} FROM {_SESSIONS_TABLE} "
                "WHERE session_id = :sid"
            ),
            {"sid": raw_token},
        ).scalar_one()
    assert before == after, (
        "second backfill with same pepper must not alter the hash"
    )
    assert before == _expected_hash(_TEST_PEPPER, raw_token)


# ---------------------------------------------------------------------------
# Layer B — Postgres roundtrip checks (gated).
# ---------------------------------------------------------------------------


@pytest.fixture()
def pg_url(monkeypatch: pytest.MonkeyPatch) -> str:
    """Return the configured Postgres URL and patch the cached settings."""
    if _PG_URL_RAW.startswith("postgresql://"):
        async_url = _PG_URL_RAW.replace(
            "postgresql://", "postgresql+asyncpg://", 1
        )
    elif _PG_URL_RAW.startswith("postgres://"):
        async_url = _PG_URL_RAW.replace(
            "postgres://", "postgresql+asyncpg://", 1
        )
    else:
        async_url = _PG_URL_RAW
    monkeypatch.setenv("DATABASE_URL", async_url)
    from src.core import config as _cfg

    monkeypatch.setattr(_cfg.settings, "database_url", async_url)
    return async_url


@pytest.fixture()
def migrated_engine(pg_url: str) -> Iterator[Engine]:
    """Drive ``upgrade head`` and yield a sync engine for introspection."""
    cfg = _alembic_config(pg_url)
    command.upgrade(cfg, "head")

    sync_url = _to_sync_url(pg_url)
    engine = sa.create_engine(sync_url, future=True)
    try:
        yield engine
    finally:
        engine.dispose()
        command.downgrade(cfg, "base")


@pytestmark_pg
@pytest.mark.requires_postgres
def test_030_pg_upgrade_creates_unique_index(migrated_engine: Engine) -> None:
    insp = inspect(migrated_engine)
    indexes = {ix["name"]: ix for ix in insp.get_indexes(_SESSIONS_TABLE)}
    assert _HASH_INDEX in indexes
    assert bool(indexes[_HASH_INDEX]["unique"]) is True


@pytestmark_pg
@pytest.mark.requires_postgres
def test_030_pg_downgrade_drops_index_idempotently(pg_url: str) -> None:
    """``upgrade -> downgrade -1 -> upgrade -> downgrade base`` all succeed."""
    cfg = _alembic_config(pg_url)
    command.upgrade(cfg, "head")

    sync_url = _to_sync_url(pg_url)
    engine = sa.create_engine(sync_url, future=True)
    try:
        insp = inspect(engine)
        indexes = {ix["name"] for ix in insp.get_indexes(_SESSIONS_TABLE)}
        assert _HASH_INDEX in indexes

        command.downgrade(cfg, "-1")
        engine.dispose()
        engine = sa.create_engine(sync_url, future=True)
        insp = inspect(engine)
        indexes = {ix["name"] for ix in insp.get_indexes(_SESSIONS_TABLE)}
        assert _HASH_INDEX not in indexes, (
            f"downgrade -1 from {_REVISION} must drop {_HASH_INDEX}"
        )

        command.upgrade(cfg, "head")
        engine.dispose()
        engine = sa.create_engine(sync_url, future=True)
        insp = inspect(engine)
        indexes = {ix["name"] for ix in insp.get_indexes(_SESSIONS_TABLE)}
        assert _HASH_INDEX in indexes
    finally:
        engine.dispose()
        command.downgrade(cfg, "base")
