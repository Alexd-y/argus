r"""C7-T07 / ISS-T20-003 Phase 2c — ``031_drop_legacy_admin_session_id`` tests.

Three-layer strategy mirroring ``test_028_*`` and ``test_030_*``:

A.   Dialect-free metadata + ORM-shape checks (always run, no DB needed).
A.5. SQLite roundtrip — exercises ``upgrade`` / ``downgrade`` on an in-memory
     engine. SQLite cannot ``ALTER TABLE`` PRIMARY KEY in place; the
     migration uses ``op.batch_alter_table`` to emit the copy-rebuild dance,
     so a real upgrade/downgrade roundtrip is the only honest way to verify
     the post-031 PK is exactly ``session_token_hash`` and the legacy
     ``session_id`` column is gone.
B.   Postgres roundtrip — gated by ``DATABASE_URL`` pointing at Postgres;
     verifies the dialect-aware ``DROP CONSTRAINT`` / ``ADD CONSTRAINT``
     path and the unique-index → PK rebuild.

Why the test fixture re-applies 030 manually
--------------------------------------------
We need a deterministic post-030, pre-031 schema (legacy ``session_id`` PK,
``session_token_hash`` UNIQUE NULLABLE) so the upgrade has something real
to drop. The fixture skips 029 (unrelated ``tenants`` schema), then runs
028 + 030. The 031 upgrade is then applied per-test so each scenario
(empty table, populated rows with hash, populated rows missing hash)
starts at the same baseline.

How to run the Postgres half locally (PowerShell)::

    docker run --rm -d --name argus-pg-c7-031 -p 55432:5432 `
        -e POSTGRES_PASSWORD=argus -e POSTGRES_DB=argus_test postgres:15
    $env:DATABASE_URL = "postgresql+asyncpg://postgres:argus@localhost:55432/argus_test"
    $env:ADMIN_SESSION_PEPPER = "test-pepper-iss-t20-003-not-for-prod-32chars-min"
    .\.venv\Scripts\python.exe -m pytest `
        backend/tests/integration/migrations/test_031_drop_legacy_admin_session_id_migration.py -v
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
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

_BACKEND_ROOT: Path = Path(__file__).resolve().parents[3]
_VERSIONS_DIR: Path = _BACKEND_ROOT / "alembic" / "versions"

_REVISION = "031"
_DOWN_REVISION = "030"
_REVISION_028 = "028"
_REVISION_030 = "030"

_SESSIONS_TABLE = "admin_sessions"
_LEGACY_COL = "session_id"
_HASH_COL = "session_token_hash"
_HASH_INDEX = "ix_admin_sessions_token_hash"

_TEST_PEPPER = "test-pepper-iss-t20-003-not-for-prod-32chars-min"

# Postgres-only gate.
_PG_URL_RAW = os.environ.get("DATABASE_URL", "")
_HAS_POSTGRES_URL = _PG_URL_RAW.startswith(
    ("postgresql://", "postgresql+", "postgres://")
)

pytestmark_pg = pytest.mark.skipif(
    not _HAS_POSTGRES_URL,
    reason=(
        "DATABASE_URL is not a Postgres URL — 031 dialect checks need a "
        "real Postgres engine"
    ),
)


# ---------------------------------------------------------------------------
# Shared helpers — keep the body of the tests focused on the invariant.
# ---------------------------------------------------------------------------


def _load_revision_module(revision: str) -> Any:
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
    for prefix in ("postgresql+asyncpg://", "postgres+asyncpg://"):
        if url.startswith(prefix):
            return "postgresql://" + url[len(prefix) :]
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://") :]
    return url


def _apply_revision_with_op_context(
    connection: sa.engine.Connection, revision: str
) -> None:
    module = _load_revision_module(revision)
    ctx = MigrationContext.configure(connection)
    with Operations.context(ctx):
        module.upgrade()


def _downgrade_revision_with_op_context(
    connection: sa.engine.Connection, revision: str
) -> None:
    module = _load_revision_module(revision)
    ctx = MigrationContext.configure(connection)
    with Operations.context(ctx):
        module.downgrade()


def _expected_hash(pepper: str, raw_token: str) -> str:
    """HMAC-SHA256(pepper, raw_token) hex — must match the migration helper."""
    return hmac.new(
        pepper.encode("utf-8"),
        raw_token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _seed_post_030_session(
    connection: sa.engine.Connection,
    *,
    raw_token: str,
    token_hash: str | None,
    subject: str = "alice@example.com",
    role: str = "admin",
    revoked: bool = False,
    ttl_seconds: int = 12 * 3600,
) -> None:
    """Insert a row with the post-030, pre-031 shape (legacy session_id PK)."""
    now = datetime.now(timezone.utc)
    connection.execute(
        text(
            f"""
            INSERT INTO {_SESSIONS_TABLE} (
                {_LEGACY_COL}, {_HASH_COL}, subject, role,
                tenant_id, created_at, expires_at, last_used_at,
                ip_hash, user_agent_hash, revoked_at
            ) VALUES (
                :sid, :h, :sub, :r,
                NULL, :ca, :ea, :lu,
                :ih, :uh, :rv
            )
            """
        ),
        {
            "sid": raw_token,
            "h": token_hash,
            "sub": subject,
            "r": role,
            "ca": now,
            "ea": now + timedelta(seconds=ttl_seconds),
            "lu": now,
            "ih": "0" * 64,
            "uh": "0" * 64,
            "rv": now if revoked else None,
        },
    )


@pytest.fixture()
def sqlite_engine() -> Iterator[Engine]:
    """In-memory sync SQLite engine with revisions 028 + 030 applied.

    Yields the engine pre-loaded with the post-030 admin schema so each
    test exercises the 031 upgrade against the canonical pre-031
    baseline. Skipping 029 mirrors the auth conftest — 029 only touches
    the unrelated ``tenants`` table.
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
            _apply_revision_with_op_context(conn, _REVISION_030)
        yield engine
    finally:
        engine.dispose()


@pytest.fixture(autouse=True)
def _set_pepper(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the pepper so the migration's straggler backfill is deterministic."""
    monkeypatch.setenv("ADMIN_SESSION_PEPPER", _TEST_PEPPER)


# ---------------------------------------------------------------------------
# Layer A — dialect-free metadata + module sanity.
# ---------------------------------------------------------------------------


def test_031_revision_metadata_pinned() -> None:
    """``revision='031'`` chains directly off ``030``."""
    module = _load_revision_module(_REVISION)
    assert module.revision == _REVISION, (
        f"031 migration must declare revision={_REVISION!r}, "
        f"got {module.revision!r}"
    )
    assert module.down_revision == _DOWN_REVISION, (
        f"031 migration must chain off {_DOWN_REVISION!r}; "
        f"got {module.down_revision!r}"
    )
    assert module.branch_labels is None, "031 must not introduce a branch label"
    assert module.depends_on is None, "031 must not depend on another revision"


def test_031_has_upgrade_and_downgrade_callables() -> None:
    module = _load_revision_module(_REVISION)
    assert callable(getattr(module, "upgrade", None)), (
        "031.upgrade missing or not callable"
    )
    assert callable(getattr(module, "downgrade", None)), (
        "031.downgrade missing or not callable"
    )


def test_032_chains_off_031() -> None:
    """The 032 MFA migration MUST be rebased onto 031 once C7-T07 lands."""
    module = _load_revision_module("032")
    assert module.down_revision == _REVISION, (
        f"032 must chain off 031 post-C7-T07; got {module.down_revision!r}"
    )


# ---------------------------------------------------------------------------
# Layer A.5 — SQLite roundtrip checks (the bulk of the coverage).
# ---------------------------------------------------------------------------


def test_upgrade_drops_legacy_session_id_column(sqlite_engine: Engine) -> None:
    """After ``031.upgrade()`` the legacy column is gone from the schema."""
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    insp = inspect(sqlite_engine)
    columns = {c["name"] for c in insp.get_columns(_SESSIONS_TABLE)}
    assert _LEGACY_COL not in columns, (
        f"031.upgrade must drop {_SESSIONS_TABLE}.{_LEGACY_COL!r}; "
        f"got {sorted(columns)!r}"
    )
    assert _HASH_COL in columns, (
        f"031.upgrade must keep {_HASH_COL!r}; got {sorted(columns)!r}"
    )


def test_upgrade_promotes_session_token_hash_to_pk(sqlite_engine: Engine) -> None:
    """After ``031.upgrade()`` the sole PK column is ``session_token_hash``."""
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    insp = inspect(sqlite_engine)
    pk = insp.get_pk_constraint(_SESSIONS_TABLE)
    pk_cols = set(pk.get("constrained_columns") or [])
    assert pk_cols == {_HASH_COL}, (
        f"post-031 PK must be exactly ({_HASH_COL!r},); got {pk_cols!r}"
    )

    columns = {c["name"]: c for c in insp.get_columns(_SESSIONS_TABLE)}
    assert columns[_HASH_COL]["nullable"] is False, (
        f"{_HASH_COL} must be NOT NULL post-031 (PK invariant); "
        f"got nullable={columns[_HASH_COL]['nullable']!r}"
    )


def test_upgrade_drops_redundant_unique_hash_index(sqlite_engine: Engine) -> None:
    """The 030 UNIQUE index on ``session_token_hash`` is folded into the PK."""
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    insp = inspect(sqlite_engine)
    index_names = {
        ix["name"] for ix in insp.get_indexes(_SESSIONS_TABLE) if ix.get("name")
    }
    assert _HASH_INDEX not in index_names, (
        f"031.upgrade must drop redundant UNIQUE index {_HASH_INDEX!r} "
        f"(PK already covers session_token_hash); got indexes: "
        f"{sorted(index_names)!r}"
    )


def test_upgrade_preserves_rows_with_hash_populated(sqlite_engine: Engine) -> None:
    """Rows with ``session_token_hash`` populated must survive the migration."""
    raw = "alpha-token-fully-backfilled-pre-031"
    digest = _expected_hash(_TEST_PEPPER, raw)
    with sqlite_engine.begin() as conn:
        _seed_post_030_session(
            conn,
            raw_token=raw,
            token_hash=digest,
            subject="alpha@example.com",
        )

    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    with sqlite_engine.connect() as conn:
        rows = conn.execute(
            text(f"SELECT subject, {_HASH_COL} FROM {_SESSIONS_TABLE}")
        ).all()
    assert len(rows) == 1
    assert rows[0][0] == "alpha@example.com"
    assert rows[0][1] == digest, (
        "session_token_hash must round-trip across the PK rebuild"
    )


def test_upgrade_backfills_straggler_rows_when_pepper_set(
    sqlite_engine: Engine,
) -> None:
    """A row with ``session_token_hash IS NULL`` gets re-hashed before PK promotion.

    Models the mixed-deploy state where 030 backfilled the bulk but a row
    landed during the grace window with ``ADMIN_SESSION_LEGACY_RAW_WRITE=true``
    + ``ADMIN_SESSION_PEPPER`` unset on the migration host. Once the
    pepper is configured, 031 must re-hash that row from its surviving
    ``session_id`` rather than dropping it.
    """
    raw = "straggler-token-needs-backfill-during-031"
    with sqlite_engine.begin() as conn:
        _seed_post_030_session(
            conn,
            raw_token=raw,
            token_hash=None,
            subject="straggler@example.com",
        )

    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    expected = _expected_hash(_TEST_PEPPER, raw)
    with sqlite_engine.connect() as conn:
        row = conn.execute(
            text(
                f"SELECT subject, {_HASH_COL} FROM {_SESSIONS_TABLE} "
                "WHERE subject = :s"
            ),
            {"s": "straggler@example.com"},
        ).one_or_none()
    assert row is not None, (
        "straggler row must survive — 031 backfill should hash from "
        "session_id before dropping the column"
    )
    assert row[1] == expected, (
        "031 straggler backfill must hash with the live pepper"
    )


def test_upgrade_purges_unreachable_rows_when_pepper_unset(
    sqlite_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rows that cannot be re-hashed (no pepper) must be deleted, not blocked.

    Without the pepper the migration cannot re-derive
    ``session_token_hash`` and the column must become NOT NULL PK; the
    only forward-only path is to delete the row. We also verify the
    non-stale, hash-bearing row survives so the purge is targeted.
    """
    monkeypatch.setenv("ADMIN_SESSION_PEPPER", "")

    surviving_raw = "hash-bearing-survivor"
    surviving_hash = "a" * 64  # synthetic — pepper-unset path doesn't re-hash
    with sqlite_engine.begin() as conn:
        _seed_post_030_session(
            conn,
            raw_token="orphan-without-hash",
            token_hash=None,
            subject="orphan@example.com",
        )
        _seed_post_030_session(
            conn,
            raw_token=surviving_raw,
            token_hash=surviving_hash,
            subject="survivor@example.com",
        )

    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    with sqlite_engine.connect() as conn:
        subjects = {
            row[0]
            for row in conn.execute(
                text(f"SELECT subject FROM {_SESSIONS_TABLE}")
            ).all()
        }
    assert "orphan@example.com" not in subjects, (
        "row without session_token_hash and no pepper to backfill must be "
        "purged so the PK promotion succeeds"
    )
    assert "survivor@example.com" in subjects, (
        "row with a real session_token_hash must survive the purge"
    )


def test_upgrade_is_idempotent_under_repeated_run(
    sqlite_engine: Engine,
) -> None:
    """Re-running ``031.upgrade`` is a clean no-op (defensive ``inspect`` checks)."""
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    insp = inspect(sqlite_engine)
    columns = {c["name"] for c in insp.get_columns(_SESSIONS_TABLE)}
    assert _LEGACY_COL not in columns
    assert _HASH_COL in columns
    pk = insp.get_pk_constraint(_SESSIONS_TABLE)
    assert set(pk.get("constrained_columns") or []) == {_HASH_COL}


def test_downgrade_restores_session_id_column_and_pk(sqlite_engine: Engine) -> None:
    """``031.downgrade()`` re-creates the legacy column + PK shape."""
    raw = "restore-roundtrip-token"
    digest = _expected_hash(_TEST_PEPPER, raw)
    with sqlite_engine.begin() as conn:
        _seed_post_030_session(conn, raw_token=raw, token_hash=digest)
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)
    with sqlite_engine.begin() as conn:
        _downgrade_revision_with_op_context(conn, _REVISION)

    insp = inspect(sqlite_engine)
    columns = {c["name"] for c in insp.get_columns(_SESSIONS_TABLE)}
    assert _LEGACY_COL in columns, (
        "downgrade must re-add session_id column"
    )
    assert _HASH_COL in columns, (
        "downgrade must keep session_token_hash (now nullable)"
    )

    pk = insp.get_pk_constraint(_SESSIONS_TABLE)
    pk_cols = set(pk.get("constrained_columns") or [])
    assert pk_cols == {_LEGACY_COL}, (
        f"downgrade must restore PK to ({_LEGACY_COL!r},); got {pk_cols!r}"
    )

    index_names = {
        ix["name"] for ix in insp.get_indexes(_SESSIONS_TABLE) if ix.get("name")
    }
    assert _HASH_INDEX in index_names, (
        f"downgrade must restore UNIQUE index {_HASH_INDEX!r}; "
        f"got indexes: {sorted(index_names)!r}"
    )


def test_upgrade_downgrade_roundtrip_is_clean(sqlite_engine: Engine) -> None:
    """``upgrade → downgrade → upgrade`` lands on the post-031 schema."""
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)
    with sqlite_engine.begin() as conn:
        _downgrade_revision_with_op_context(conn, _REVISION)
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    insp = inspect(sqlite_engine)
    columns = {c["name"] for c in insp.get_columns(_SESSIONS_TABLE)}
    assert _LEGACY_COL not in columns, (
        "round-trip must end with session_id dropped (post-031 invariant)"
    )
    pk = insp.get_pk_constraint(_SESSIONS_TABLE)
    assert set(pk.get("constrained_columns") or []) == {_HASH_COL}


def test_upgrade_aborts_when_post_030_schema_missing(
    sqlite_engine: Engine,
) -> None:
    """``031`` refuses to run on a pre-030 schema (operator gate).

    SQLite cannot ``DROP COLUMN`` while a referencing index survives
    (`no such column ... after drop column`), so the simulation drops the
    030 UNIQUE index first, then uses ``batch_alter_table`` to perform the
    copy-rebuild that removes ``session_token_hash``. The end-state matches
    a host that never ran 030 — exactly what the operator gate has to
    catch.
    """
    with sqlite_engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx) as ops:
            with ops.batch_alter_table(_SESSIONS_TABLE) as batch:
                batch.drop_index(_HASH_INDEX)
                batch.drop_column(_HASH_COL)

    with pytest.raises(RuntimeError, match="Apply migration 030 before 031"):
        with sqlite_engine.begin() as conn:
            _apply_revision_with_op_context(conn, _REVISION)


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
def test_031_pg_upgrade_drops_session_id_and_promotes_hash_pk(
    migrated_engine: Engine,
) -> None:
    """Postgres ``upgrade head`` lands the post-031 schema."""
    insp = inspect(migrated_engine)
    columns = {c["name"] for c in insp.get_columns(_SESSIONS_TABLE)}
    assert _LEGACY_COL not in columns, (
        f"Postgres upgrade head must drop {_LEGACY_COL}"
    )
    assert _HASH_COL in columns

    pk = insp.get_pk_constraint(_SESSIONS_TABLE)
    pk_cols = set(pk.get("constrained_columns") or [])
    assert pk_cols == {_HASH_COL}, (
        f"Postgres post-031 PK must be ({_HASH_COL!r},); got {pk_cols!r}"
    )


@pytestmark_pg
@pytest.mark.requires_postgres
def test_031_pg_downgrade_restores_legacy_pk(pg_url: str) -> None:
    """``upgrade head -> downgrade -1 -> upgrade head`` round-trip is clean."""
    cfg = _alembic_config(pg_url)
    command.upgrade(cfg, "head")

    sync_url = _to_sync_url(pg_url)
    engine = sa.create_engine(sync_url, future=True)
    try:
        # Walk the chain back to 030 and confirm the legacy shape returns.
        # Two ``-1`` hops because 032 sits on top of 031.
        command.downgrade(cfg, "-1")
        command.downgrade(cfg, "-1")

        engine.dispose()
        engine = sa.create_engine(sync_url, future=True)
        insp = inspect(engine)
        columns = {c["name"] for c in insp.get_columns(_SESSIONS_TABLE)}
        assert _LEGACY_COL in columns, (
            "Postgres downgrade -2 from head must restore session_id"
        )
        pk = insp.get_pk_constraint(_SESSIONS_TABLE)
        assert set(pk.get("constrained_columns") or []) == {_LEGACY_COL}

        # And forward again — the round-trip must end on the post-head schema.
        command.upgrade(cfg, "head")
        engine.dispose()
        engine = sa.create_engine(sync_url, future=True)
        insp = inspect(engine)
        columns = {c["name"] for c in insp.get_columns(_SESSIONS_TABLE)}
        assert _LEGACY_COL not in columns
    finally:
        engine.dispose()
        command.downgrade(cfg, "base")


# Silence unused-import warning when running on SQLite-only envs.
_ = cast
