r"""ISS-T20-003 Phase 1 — ``028_admin_sessions`` migration tests (B6-T08).

Two-layer strategy mirroring ``test_scan_schedules_migration.py``:

A. Dialect-free checks — always run, no DB required.
   * Revision metadata pinned (``revision="028"``, ``down_revision="027"``).
   * Both ``upgrade()`` and ``downgrade()`` callables exist.
   * The ``AdminUser`` and ``AdminSession`` ORM models match the spec
     column-by-column and declare the required indexes.

B. Postgres round-trip checks — gated by
   ``@pytest.mark.requires_postgres`` and skipped when ``DATABASE_URL`` is
   not a real Postgres URL.
   Layer B drives ``command.upgrade`` / ``command.downgrade`` and then
   validates:
     * columns / types / nullability via ``inspect``;
     * ``ix_admin_sessions_subject_revoked`` and
       ``ix_admin_sessions_expires_at`` are present;
     * **Row-Level Security is intentionally OFF** on both tables —
       documented rationale lives in the migration docstring;
     * ``upgrade -> downgrade -1 -> upgrade`` is byte-stable.

How to run the Postgres half locally (PowerShell)::

    docker run --rm -d --name argus-pg-t20 -p 55432:5432 `
        -e POSTGRES_PASSWORD=argus -e POSTGRES_DB=argus_test postgres:15
    $env:DATABASE_URL = "postgresql+asyncpg://postgres:argus@localhost:55432/argus_test"
    .\.venv\Scripts\python.exe -m pytest `
        backend/tests/integration/migrations/test_028_admin_sessions_migration.py -v
"""

from __future__ import annotations

import importlib.util
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

_BACKEND_ROOT = Path(__file__).resolve().parents[3]
_VERSIONS_DIR = _BACKEND_ROOT / "alembic" / "versions"
_REVISION = "028"
_DOWN_REVISION = "027"
_USERS_TABLE = "admin_users"
_SESSIONS_TABLE = "admin_sessions"
_INDEX_SUBJECT_REVOKED = "ix_admin_sessions_subject_revoked"
_INDEX_EXPIRES_AT = "ix_admin_sessions_expires_at"

# Expected column shape (name -> nullable) for ``admin_users``.
_EXPECTED_USERS_COLUMNS: dict[str, bool] = {
    "subject": False,
    "password_hash": False,
    "role": False,
    "tenant_id": True,
    "mfa_secret": True,
    "created_at": False,
    "disabled_at": True,
}

_EXPECTED_SESSIONS_COLUMNS: dict[str, bool] = {
    "session_id": False,
    "subject": False,
    "role": False,
    "tenant_id": True,
    "created_at": False,
    "expires_at": False,
    "last_used_at": False,
    "ip_hash": False,
    "user_agent_hash": False,
    "revoked_at": True,
}

_EXPECTED_SESSIONS_INDEXES = {_INDEX_SUBJECT_REVOKED, _INDEX_EXPIRES_AT}

# Gate for Layer B.
_PG_URL_RAW = os.environ.get("DATABASE_URL", "")
_HAS_POSTGRES_URL = _PG_URL_RAW.startswith(
    ("postgresql://", "postgresql+", "postgres://")
)

pytestmark_pg = pytest.mark.skipif(
    not _HAS_POSTGRES_URL,
    reason=(
        "DATABASE_URL is not a Postgres URL — admin_sessions schema checks "
        "need a real Postgres engine"
    ),
)


# ---------------------------------------------------------------------------
# Shared helpers.
# ---------------------------------------------------------------------------


def _load_revision_module() -> Any:
    """Import the 028 migration file as a standalone module (no chain run)."""
    matches = list(_VERSIONS_DIR.glob(f"{_REVISION}_*.py"))
    assert matches, f"revision file for {_REVISION} not found"
    spec = importlib.util.spec_from_file_location(
        f"_alembic_{_REVISION}", matches[0]
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


# ---------------------------------------------------------------------------
# Layer A — dialect-free checks.
# ---------------------------------------------------------------------------


def test_028_revision_metadata_pinned() -> None:
    module = _load_revision_module()
    assert module.revision == _REVISION, (
        f"028 migration must declare revision={_REVISION!r}, "
        f"got {module.revision!r}"
    )
    assert module.down_revision == _DOWN_REVISION, (
        f"028 migration must chain off {_DOWN_REVISION!r}, "
        f"got {module.down_revision!r}"
    )
    assert module.branch_labels is None, "028 must not introduce a branch label"
    assert module.depends_on is None, "028 must not depend on another revision"


def test_028_has_upgrade_and_downgrade_callables() -> None:
    module = _load_revision_module()
    assert callable(getattr(module, "upgrade", None)), (
        "028.upgrade missing or not callable"
    )
    assert callable(getattr(module, "downgrade", None)), (
        "028.downgrade missing or not callable"
    )


def test_028_orm_admin_users_matches_spec() -> None:
    """``AdminUser`` ORM must mirror the migration column-by-column."""
    from src.db.models import AdminUser

    assert AdminUser.__tablename__ == _USERS_TABLE
    table = cast(sa.Table, AdminUser.__table__)

    column_shapes = {c.name: c.nullable for c in table.columns}
    assert column_shapes == _EXPECTED_USERS_COLUMNS, (
        f"AdminUser column shape drifted from spec:\n"
        f"  expected: {_EXPECTED_USERS_COLUMNS}\n"
        f"  got:      {column_shapes}"
    )

    pk = {col.name for col in table.primary_key.columns}
    assert pk == {"subject"}, f"AdminUser PK must be (subject,), got {pk}"


def test_028_orm_admin_sessions_matches_spec() -> None:
    """``AdminSession`` ORM must mirror the migration column-by-column.

    Columns added in *later* migrations (e.g. ``session_token_hash`` in
    revision 030) are excluded from this assertion — each subsequent
    migration carries its own ``test_<rev>_orm_*_matches_spec`` test
    that pins its own contract. Without this scoping the 028 test would
    fail every time a new column lands on the table.
    """
    from src.db.models import AdminSession

    assert AdminSession.__tablename__ == _SESSIONS_TABLE
    table = cast(sa.Table, AdminSession.__table__)

    column_shapes = {
        c.name: c.nullable
        for c in table.columns
        if c.name in _EXPECTED_SESSIONS_COLUMNS
    }
    assert column_shapes == _EXPECTED_SESSIONS_COLUMNS, (
        f"AdminSession column shape drifted from spec:\n"
        f"  expected: {_EXPECTED_SESSIONS_COLUMNS}\n"
        f"  got:      {column_shapes}"
    )

    pk = {col.name for col in table.primary_key.columns}
    assert pk == {"session_id"}, (
        f"AdminSession PK must be (session_id,), got {pk}"
    )


def test_028_orm_admin_sessions_indexes_match_spec() -> None:
    from src.db.models import AdminSession

    table = cast(sa.Table, AdminSession.__table__)
    index_names = {ix.name for ix in table.indexes}
    missing = _EXPECTED_SESSIONS_INDEXES - index_names
    assert not missing, f"AdminSession missing ORM indexes: {missing}"

    by_name = {ix.name: tuple(c.name for c in ix.columns) for ix in table.indexes}
    assert by_name[_INDEX_SUBJECT_REVOKED] == ("subject", "revoked_at"), (
        f"{_INDEX_SUBJECT_REVOKED} must be (subject, revoked_at), "
        f"got {by_name[_INDEX_SUBJECT_REVOKED]}"
    )
    assert by_name[_INDEX_EXPIRES_AT] == ("expires_at",), (
        f"{_INDEX_EXPIRES_AT} must be (expires_at,), "
        f"got {by_name[_INDEX_EXPIRES_AT]}"
    )


def test_028_no_foreign_key_between_sessions_and_users() -> None:
    """Spec invariant: no FK so soft-deletes preserve forensic session rows."""
    from src.db.models import AdminSession

    table = cast(sa.Table, AdminSession.__table__)
    fk_targets = {
        (fk.column.table.name, fk.column.name) for fk in table.foreign_keys
    }
    assert ("admin_users", "subject") not in fk_targets, (
        "admin_sessions.subject MUST NOT FK admin_users.subject — see "
        "migration docstring (forensic preservation on soft-delete)"
    )


# ---------------------------------------------------------------------------
# Layer B — Postgres round-trip checks.
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
def test_028_upgrade_creates_admin_users_with_expected_columns(
    migrated_engine: Engine,
) -> None:
    insp = inspect(migrated_engine)
    assert insp.has_table(_USERS_TABLE), (
        f"{_USERS_TABLE} should exist after upgrade head"
    )

    columns = {c["name"]: c for c in insp.get_columns(_USERS_TABLE)}
    assert set(columns) == set(_EXPECTED_USERS_COLUMNS), (
        f"{_USERS_TABLE} columns differ from spec: "
        f"got={set(columns)} expected={set(_EXPECTED_USERS_COLUMNS)}"
    )
    for col_name, expected_nullable in _EXPECTED_USERS_COLUMNS.items():
        assert columns[col_name]["nullable"] is expected_nullable, (
            f"{_USERS_TABLE}.{col_name} nullable={columns[col_name]['nullable']!r} "
            f"but spec requires {expected_nullable!r}"
        )


@pytestmark_pg
@pytest.mark.requires_postgres
def test_028_upgrade_creates_admin_sessions_with_expected_columns(
    migrated_engine: Engine,
) -> None:
    insp = inspect(migrated_engine)
    assert insp.has_table(_SESSIONS_TABLE)

    columns = {c["name"]: c for c in insp.get_columns(_SESSIONS_TABLE)}
    assert set(columns) == set(_EXPECTED_SESSIONS_COLUMNS), (
        f"{_SESSIONS_TABLE} columns differ from spec: "
        f"got={set(columns)} expected={set(_EXPECTED_SESSIONS_COLUMNS)}"
    )
    for col_name, expected_nullable in _EXPECTED_SESSIONS_COLUMNS.items():
        assert columns[col_name]["nullable"] is expected_nullable, (
            f"{_SESSIONS_TABLE}.{col_name} "
            f"nullable={columns[col_name]['nullable']!r} "
            f"but spec requires {expected_nullable!r}"
        )


@pytestmark_pg
@pytest.mark.requires_postgres
def test_028_indexes_present(migrated_engine: Engine) -> None:
    insp = inspect(migrated_engine)
    index_names = {ix["name"] for ix in insp.get_indexes(_SESSIONS_TABLE)}
    missing = _EXPECTED_SESSIONS_INDEXES - index_names
    assert not missing, (
        f"{_SESSIONS_TABLE} missing indexes after upgrade head: {missing}"
    )


@pytestmark_pg
@pytest.mark.requires_postgres
def test_028_no_rls_enabled_on_admin_users(migrated_engine: Engine) -> None:
    """``admin_users`` is intentionally cross-tenant — RLS MUST stay OFF.

    Documented rationale lives in :mod:`alembic.versions.028_admin_sessions`
    docstring (super-admin role is itself cross-tenant).
    """
    with migrated_engine.connect() as conn:
        row = conn.execute(
            text(
                """
                SELECT relrowsecurity, relforcerowsecurity
                FROM pg_class
                WHERE relname = :table
                """
            ),
            {"table": _USERS_TABLE},
        ).one()
        assert not row.relrowsecurity, (
            f"{_USERS_TABLE} must NOT have RLS enabled (cross-tenant by design)"
        )
        assert not row.relforcerowsecurity, (
            f"{_USERS_TABLE} must NOT have FORCE RLS"
        )


@pytestmark_pg
@pytest.mark.requires_postgres
def test_028_no_rls_enabled_on_admin_sessions(migrated_engine: Engine) -> None:
    """``admin_sessions`` is cross-tenant by design — RLS MUST stay OFF."""
    with migrated_engine.connect() as conn:
        row = conn.execute(
            text(
                """
                SELECT relrowsecurity, relforcerowsecurity
                FROM pg_class
                WHERE relname = :table
                """
            ),
            {"table": _SESSIONS_TABLE},
        ).one()
        assert not row.relrowsecurity, (
            f"{_SESSIONS_TABLE} must NOT have RLS enabled (super-admin needs "
            "cross-tenant lookup)"
        )
        assert not row.relforcerowsecurity, (
            f"{_SESSIONS_TABLE} must NOT have FORCE RLS"
        )


@pytestmark_pg
@pytest.mark.requires_postgres
def test_028_no_policies_attached_to_admin_tables(migrated_engine: Engine) -> None:
    """No ``pg_policy`` rows should exist for the new admin tables."""
    with migrated_engine.connect() as conn:
        for table in (_USERS_TABLE, _SESSIONS_TABLE):
            policies = (
                conn.execute(
                    text(
                        "SELECT polname FROM pg_policy "
                        "WHERE polrelid = :table::regclass"
                    ),
                    {"table": table},
                )
                .scalars()
                .all()
            )
            assert policies == [], (
                f"{table} must not have RLS policies; got {policies!r}"
            )


@pytestmark_pg
@pytest.mark.requires_postgres
def test_028_downgrade_drops_tables_idempotently(pg_url: str) -> None:
    """``upgrade -> downgrade -1 -> upgrade -> downgrade base`` all succeed."""
    cfg = _alembic_config(pg_url)
    command.upgrade(cfg, "head")

    sync_url = _to_sync_url(pg_url)
    engine = sa.create_engine(sync_url, future=True)
    try:
        insp = inspect(engine)
        assert insp.has_table(_USERS_TABLE)
        assert insp.has_table(_SESSIONS_TABLE)

        command.downgrade(cfg, "-1")
        engine.dispose()
        engine = sa.create_engine(sync_url, future=True)
        insp = inspect(engine)
        assert not insp.has_table(_USERS_TABLE), (
            "downgrade -1 from 028 must drop admin_users"
        )
        assert not insp.has_table(_SESSIONS_TABLE), (
            "downgrade -1 from 028 must drop admin_sessions"
        )

        command.upgrade(cfg, "head")
        engine.dispose()
        engine = sa.create_engine(sync_url, future=True)
        insp = inspect(engine)
        assert insp.has_table(_USERS_TABLE)
        assert insp.has_table(_SESSIONS_TABLE)
    finally:
        engine.dispose()
        command.downgrade(cfg, "base")


@pytestmark_pg
@pytest.mark.requires_postgres
def test_028_basic_insert_select_roundtrip(migrated_engine: Engine) -> None:
    """Smoke-test the schema by inserting and reading back a session row."""
    with migrated_engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO admin_users (subject, password_hash, role)
                VALUES (:s, :h, :r)
                """
            ),
            {
                "s": "smoke@example.com",
                "h": "$2b$12$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN",
                "r": "admin",
            },
        )
        conn.execute(
            text(
                """
                INSERT INTO admin_sessions (
                    session_id, subject, role,
                    expires_at, ip_hash, user_agent_hash
                ) VALUES (
                    :sid, :sub, :r,
                    NOW() + INTERVAL '12 hours', :ih, :uh
                )
                """
            ),
            {
                "sid": "x" * 64,
                "sub": "smoke@example.com",
                "r": "admin",
                "ih": "0" * 64,
                "uh": "0" * 64,
            },
        )

    with migrated_engine.connect() as conn:
        users = conn.execute(text("SELECT COUNT(*) FROM admin_users")).scalar_one()
        sessions = conn.execute(
            text("SELECT COUNT(*) FROM admin_sessions")
        ).scalar_one()
        assert users == 1 and sessions == 1
