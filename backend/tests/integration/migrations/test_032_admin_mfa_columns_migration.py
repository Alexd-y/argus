r"""ARG-062 / Cycle 7 / C7-T01 — ``032_admin_mfa_columns`` migration tests.

Three-layer strategy mirroring ``test_028_admin_sessions_migration.py`` and
``test_030_hash_admin_session_ids_migration.py``:

A.   Dialect-free metadata + ORM-shape checks — always run, no DB required.
A.5. SQLite roundtrip — exercises ``upgrade`` / ``downgrade`` end-to-end on
     an in-memory engine. The 032 migration uses ``op.batch_alter_table``
     for SQLite (the dialect can't ``ALTER TABLE ADD COLUMN`` with a
     ``NOT NULL`` server default in a single statement on every version),
     so a real upgrade/downgrade roundtrip is the only way to verify the
     batch-recreate semantics without booting Postgres.
B.   Postgres roundtrip — gated by ``@pytest.mark.requires_postgres``;
     verifies the dialect-aware paths (``BYTEA``, ``TEXT[]``,
     ``TIMESTAMPTZ``, dropping the temp ``server_default``).

Why test against SQLite at all
------------------------------
The 032 migration is dialect-aware:

* Postgres → ``BYTEA`` / ``TEXT[]`` / ``BOOLEAN`` / ``TIMESTAMPTZ``;
* SQLite (test/dev only) → ``BLOB`` / ``JSON`` / ``BOOLEAN`` / ``DATETIME``.

The ORM model in :mod:`src.db.models` declares
``ARRAY(String).with_variant(JSON, "sqlite")`` for ``mfa_backup_codes_hash``,
so the SQLite tests *also* prove the ORM-side dialect variant lines up
with the migration-side one (a regression here would crash any SQLite
test that touches the column).

How to run the Postgres half locally (PowerShell)::

    docker run --rm -d --name argus-pg-c7-032 -p 55432:5432 `
        -e POSTGRES_PASSWORD=argus -e POSTGRES_DB=argus_test postgres:15
    $env:DATABASE_URL = "postgresql+asyncpg://postgres:argus@localhost:55432/argus_test"
    .\.venv\Scripts\python.exe -m pytest `
        backend/tests/integration/migrations/test_032_admin_mfa_columns_migration.py -v
"""

from __future__ import annotations

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

_REVISION = "032"
_DOWN_REVISION = "030"
_REVISION_028 = "028"
_REVISION_030 = "030"

_USERS_TABLE = "admin_users"
_SESSIONS_TABLE = "admin_sessions"

_COL_MFA_ENABLED = "mfa_enabled"
_COL_MFA_SECRET_ENCRYPTED = "mfa_secret_encrypted"
_COL_MFA_BACKUP_CODES_HASH = "mfa_backup_codes_hash"
_COL_MFA_PASSED_AT = "mfa_passed_at"

_NEW_USER_COLUMNS: frozenset[str] = frozenset(
    {_COL_MFA_ENABLED, _COL_MFA_SECRET_ENCRYPTED, _COL_MFA_BACKUP_CODES_HASH}
)

# Expected nullability for the columns 032 adds. Pinned literally so a
# silent flip (e.g. ``mfa_secret_encrypted`` becoming NOT NULL) fails this
# suite instead of breaking enrolment in production.
_EXPECTED_USER_MFA_COLUMN_NULLABILITY: dict[str, bool] = {
    _COL_MFA_ENABLED: False,
    _COL_MFA_SECRET_ENCRYPTED: True,
    _COL_MFA_BACKUP_CODES_HASH: True,
}
_EXPECTED_SESSION_MFA_COLUMN_NULLABILITY: dict[str, bool] = {
    _COL_MFA_PASSED_AT: True,
}

# Postgres-only gate (Layer B).
_PG_URL_RAW = os.environ.get("DATABASE_URL", "")
_HAS_POSTGRES_URL = _PG_URL_RAW.startswith(
    ("postgresql://", "postgresql+", "postgres://")
)

pytestmark_pg = pytest.mark.skipif(
    not _HAS_POSTGRES_URL,
    reason=(
        "DATABASE_URL is not a Postgres URL — admin MFA-column dialect "
        "checks need a real Postgres engine"
    ),
)


# ---------------------------------------------------------------------------
# Shared helpers — mirrors the 030 helpers verbatim so a future grep keeps
# all migration tests aligned.
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


def _apply_revision_with_op_context(
    connection: sa.engine.Connection, revision: str
) -> None:
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


def _seed_pre_032_admin_user(
    connection: sa.engine.Connection,
    *,
    subject: str,
    role: str = "admin",
) -> None:
    """Insert a row that mimics a pre-032 admin (no MFA columns yet).

    Schema MUST be at revision 028+030 (no MFA columns yet) when this is
    called — that is the operational baseline we are migrating from.
    """
    connection.execute(
        text(
            f"""
            INSERT INTO {_USERS_TABLE} (
                subject, password_hash, role, tenant_id,
                mfa_secret, created_at, disabled_at
            ) VALUES (
                :sub, :pwh, :r, NULL,
                NULL, :ca, NULL
            )
            """
        ),
        {
            "sub": subject,
            "pwh": "$2b$12$" + "x" * 53,  # bcrypt-shaped placeholder
            "r": role,
            "ca": datetime.now(timezone.utc),
        },
    )


def _seed_pre_032_admin_session(
    connection: sa.engine.Connection,
    *,
    session_id: str,
    subject: str,
    role: str = "admin",
    ttl_seconds: int = 12 * 3600,
) -> None:
    """Insert a row that mimics a pre-032 admin session (no mfa_passed_at)."""
    now = datetime.now(timezone.utc)
    connection.execute(
        text(
            f"""
            INSERT INTO {_SESSIONS_TABLE} (
                session_id, session_token_hash, subject, role,
                tenant_id, created_at, expires_at, last_used_at,
                ip_hash, user_agent_hash, revoked_at
            ) VALUES (
                :sid, NULL, :sub, :r,
                NULL, :ca, :ea, :lu,
                :ih, :uh, NULL
            )
            """
        ),
        {
            "sid": session_id,
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
    """In-memory sync SQLite engine with revisions 028 + 030 applied.

    Yields the engine pre-loaded with the post-030 admin schema (the
    canonical pre-032 baseline) so each test starts at a known shape.
    Skipping 029 is intentional — same rationale as
    ``backend/tests/auth/conftest.py``: 029 only touches an unrelated
    ``tenants`` column and is not required to load 030 or 032.
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


# ---------------------------------------------------------------------------
# Layer A — dialect-free metadata + ORM-shape checks.
# ---------------------------------------------------------------------------


def test_032_revision_metadata_pinned() -> None:
    """``revision='032'`` chains off ``030`` (031 lands later in C7-T07)."""
    module = _load_revision_module(_REVISION)
    assert module.revision == _REVISION, (
        f"032 migration must declare revision={_REVISION!r}, "
        f"got {module.revision!r}"
    )
    assert module.down_revision == _DOWN_REVISION, (
        f"032 migration must chain off {_DOWN_REVISION!r} until C7-T07 lands "
        "031 — got " + repr(module.down_revision)
    )
    assert module.branch_labels is None, "032 must not introduce a branch label"
    assert module.depends_on is None, "032 must not depend on another revision"


def test_032_has_upgrade_and_downgrade_callables() -> None:
    module = _load_revision_module(_REVISION)
    assert callable(getattr(module, "upgrade", None)), (
        "032.upgrade missing or not callable"
    )
    assert callable(getattr(module, "downgrade", None)), (
        "032.downgrade missing or not callable"
    )


def test_032_orm_admin_user_carries_mfa_columns() -> None:
    """Post-032 ORM ``AdminUser`` must declare the three MFA columns.

    Pinned shapes:
      * ``mfa_enabled``           — Boolean, NOT NULL, server default false
      * ``mfa_secret_encrypted``  — LargeBinary, nullable
      * ``mfa_backup_codes_hash`` — ``ARRAY(String).with_variant(JSON, "sqlite")``,
        nullable
    """
    from src.db.models import AdminUser

    table = cast(sa.Table, AdminUser.__table__)
    column_shapes = {c.name: c.nullable for c in table.columns}

    for col_name, expected_nullable in (
        _EXPECTED_USER_MFA_COLUMN_NULLABILITY.items()
    ):
        assert col_name in column_shapes, (
            f"AdminUser ORM is missing post-032 column {col_name!r}"
        )
        assert column_shapes[col_name] is expected_nullable, (
            f"AdminUser.{col_name} nullable={column_shapes[col_name]!r} "
            f"but post-032 spec requires {expected_nullable!r}"
        )

    enabled_col = table.columns[_COL_MFA_ENABLED]
    assert isinstance(enabled_col.type, sa.Boolean), (
        f"{_COL_MFA_ENABLED} must be Boolean, got {enabled_col.type!r}"
    )
    secret_col = table.columns[_COL_MFA_SECRET_ENCRYPTED]
    assert isinstance(secret_col.type, sa.LargeBinary), (
        f"{_COL_MFA_SECRET_ENCRYPTED} must be LargeBinary, "
        f"got {secret_col.type!r}"
    )


def test_032_orm_admin_session_carries_mfa_passed_at() -> None:
    """Post-032 ORM ``AdminSession`` must declare ``mfa_passed_at`` (TZ-aware)."""
    from src.db.models import AdminSession

    table = cast(sa.Table, AdminSession.__table__)
    assert _COL_MFA_PASSED_AT in table.columns, (
        f"AdminSession ORM is missing post-032 column {_COL_MFA_PASSED_AT!r}"
    )
    column = table.columns[_COL_MFA_PASSED_AT]
    assert column.nullable is True, (
        f"{_COL_MFA_PASSED_AT} must be NULL-able (NULL = MFA never satisfied)"
    )
    assert isinstance(column.type, sa.DateTime), (
        f"{_COL_MFA_PASSED_AT} must be DateTime, got {column.type!r}"
    )
    # The migration declares ``DateTime(timezone=True)``; the ORM must
    # mirror that or the AsyncSession will round-trip naive datetimes.
    assert getattr(column.type, "timezone", False) is True, (
        f"{_COL_MFA_PASSED_AT} must be TIMESTAMPTZ-equivalent "
        "(timezone=True)"
    )


# ---------------------------------------------------------------------------
# Layer A.5 — SQLite roundtrip checks (the bulk of the coverage).
# ---------------------------------------------------------------------------


def test_upgrade_adds_mfa_columns_to_admin_users(sqlite_engine: Engine) -> None:
    """After ``032.upgrade()`` ``admin_users`` carries the 3 new columns."""
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    insp = inspect(sqlite_engine)
    columns = {c["name"]: c for c in insp.get_columns(_USERS_TABLE)}
    missing = _NEW_USER_COLUMNS - set(columns)
    assert not missing, (
        f"032.upgrade must add {sorted(_NEW_USER_COLUMNS)!r} to "
        f"{_USERS_TABLE}; missing: {sorted(missing)!r}"
    )

    for col_name, expected_nullable in (
        _EXPECTED_USER_MFA_COLUMN_NULLABILITY.items()
    ):
        actual = columns[col_name]["nullable"]
        assert actual is expected_nullable, (
            f"{_USERS_TABLE}.{col_name} nullable={actual!r} but spec "
            f"requires {expected_nullable!r}"
        )


def test_upgrade_adds_mfa_passed_at_to_admin_sessions(
    sqlite_engine: Engine,
) -> None:
    """After ``032.upgrade()`` ``admin_sessions`` carries ``mfa_passed_at``."""
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    insp = inspect(sqlite_engine)
    columns = {c["name"]: c for c in insp.get_columns(_SESSIONS_TABLE)}
    assert _COL_MFA_PASSED_AT in columns, (
        f"032.upgrade must add {_COL_MFA_PASSED_AT!r} to {_SESSIONS_TABLE}"
    )
    assert columns[_COL_MFA_PASSED_AT]["nullable"] is True, (
        f"{_COL_MFA_PASSED_AT} must be NULL-able post-032"
    )


def test_existing_admin_users_survive_upgrade_with_mfa_disabled(
    sqlite_engine: Engine,
) -> None:
    """Pre-032 admin_users rows survive with ``mfa_enabled=False``, NULL secret."""
    with sqlite_engine.begin() as conn:
        _seed_pre_032_admin_user(conn, subject="alpha@example.com")
        _seed_pre_032_admin_user(conn, subject="beta@example.com", role="operator")
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    with sqlite_engine.connect() as conn:
        rows = conn.execute(
            text(
                f"""
                SELECT subject, role, {_COL_MFA_ENABLED},
                       {_COL_MFA_SECRET_ENCRYPTED}, {_COL_MFA_BACKUP_CODES_HASH}
                FROM {_USERS_TABLE}
                ORDER BY subject
                """
            )
        ).all()

    assert len(rows) == 2, (
        f"032.upgrade must preserve all pre-existing admin rows; got "
        f"{len(rows)} rows after upgrade"
    )
    by_subject = {r[0]: r for r in rows}
    for subject in ("alpha@example.com", "beta@example.com"):
        assert subject in by_subject, (
            f"row for {subject!r} disappeared during 032.upgrade"
        )
        row = by_subject[subject]
        # SQLite stores BOOLEAN as 0/1; treat both False and 0 as the
        # canonical "off" value.
        assert row[2] in (False, 0), (
            f"{subject}.{_COL_MFA_ENABLED} must default to False post-032; "
            f"got {row[2]!r}"
        )
        assert row[3] is None, (
            f"{subject}.{_COL_MFA_SECRET_ENCRYPTED} must default to NULL"
        )
        assert row[4] is None, (
            f"{subject}.{_COL_MFA_BACKUP_CODES_HASH} must default to NULL"
        )


def test_existing_admin_sessions_survive_upgrade_with_null_mfa_passed_at(
    sqlite_engine: Engine,
) -> None:
    """Pre-032 admin_sessions rows survive with ``mfa_passed_at IS NULL``."""
    with sqlite_engine.begin() as conn:
        _seed_pre_032_admin_session(
            conn,
            session_id="legacy-session-id-1",
            subject="alpha@example.com",
        )
        _seed_pre_032_admin_session(
            conn,
            session_id="legacy-session-id-2",
            subject="beta@example.com",
        )
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    with sqlite_engine.connect() as conn:
        rows = conn.execute(
            text(
                f"""
                SELECT session_id, subject, {_COL_MFA_PASSED_AT}
                FROM {_SESSIONS_TABLE}
                ORDER BY session_id
                """
            )
        ).all()

    assert len(rows) == 2, (
        f"032.upgrade must preserve all pre-existing admin_sessions rows; "
        f"got {len(rows)} rows after upgrade"
    )
    for row in rows:
        assert row[2] is None, (
            f"session {row[0]!r} must have {_COL_MFA_PASSED_AT}=NULL after "
            f"032.upgrade; got {row[2]!r}"
        )


def test_upgrade_is_idempotent_under_repeated_run(
    sqlite_engine: Engine,
) -> None:
    """Running ``upgrade`` twice is a no-op on the second invocation.

    Operational scenario: re-running ``alembic upgrade head`` after a
    partial deploy or a stamped-out-of-band fix-up. The migration uses
    ``sa.inspect`` to skip already-present columns, so a second pass
    must not raise even though ``add_column`` would normally fail on a
    duplicate column name.
    """
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)
    # Second upgrade — must be a clean no-op.
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    insp = inspect(sqlite_engine)
    user_cols = {c["name"] for c in insp.get_columns(_USERS_TABLE)}
    session_cols = {c["name"] for c in insp.get_columns(_SESSIONS_TABLE)}
    assert _NEW_USER_COLUMNS.issubset(user_cols), (
        f"after 2× upgrade {_USERS_TABLE} must still carry the MFA columns; "
        f"missing: {sorted(_NEW_USER_COLUMNS - user_cols)!r}"
    )
    assert _COL_MFA_PASSED_AT in session_cols, (
        f"after 2× upgrade {_SESSIONS_TABLE}.{_COL_MFA_PASSED_AT} must "
        "still exist"
    )


def test_downgrade_drops_mfa_columns_cleanly(sqlite_engine: Engine) -> None:
    """``032.downgrade()`` removes the 4 MFA columns; non-MFA rows survive."""
    with sqlite_engine.begin() as conn:
        _seed_pre_032_admin_user(conn, subject="gamma@example.com")
        _seed_pre_032_admin_session(
            conn,
            session_id="legacy-session-id-3",
            subject="gamma@example.com",
        )
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    # Mutate the row to populate the new MFA columns; the downgrade has
    # to discard this data without violating any constraint.
    with sqlite_engine.begin() as conn:
        conn.execute(
            text(
                f"""
                UPDATE {_USERS_TABLE}
                SET {_COL_MFA_ENABLED} = 1,
                    {_COL_MFA_SECRET_ENCRYPTED} = :ct,
                    {_COL_MFA_BACKUP_CODES_HASH} = :hashes
                WHERE subject = :sub
                """
            ),
            {
                "ct": b"\x80some-fernet-token-bytes-not-real",
                "hashes": '["$2b$12$" + "x" * 53]',
                "sub": "gamma@example.com",
            },
        )
        conn.execute(
            text(
                f"""
                UPDATE {_SESSIONS_TABLE}
                SET {_COL_MFA_PASSED_AT} = :ts
                WHERE session_id = :sid
                """
            ),
            {
                "ts": datetime.now(timezone.utc),
                "sid": "legacy-session-id-3",
            },
        )

    with sqlite_engine.begin() as conn:
        _downgrade_revision_with_op_context(conn, _REVISION)

    insp = inspect(sqlite_engine)
    user_cols = {c["name"] for c in insp.get_columns(_USERS_TABLE)}
    session_cols = {c["name"] for c in insp.get_columns(_SESSIONS_TABLE)}
    overlap = _NEW_USER_COLUMNS & user_cols
    assert not overlap, (
        f"032.downgrade must drop {sorted(_NEW_USER_COLUMNS)!r} from "
        f"{_USERS_TABLE}; still present: {sorted(overlap)!r}"
    )
    assert _COL_MFA_PASSED_AT not in session_cols, (
        f"032.downgrade must drop {_COL_MFA_PASSED_AT!r} from "
        f"{_SESSIONS_TABLE}; still present"
    )

    # Non-MFA rows must survive the downgrade — they carry forensic
    # value (audit trail) and operators expect them to be untouched.
    with sqlite_engine.connect() as conn:
        user_row = conn.execute(
            text(
                f"SELECT subject, role FROM {_USERS_TABLE} WHERE subject = :sub"
            ),
            {"sub": "gamma@example.com"},
        ).one()
        session_row = conn.execute(
            text(
                f"SELECT session_id, subject FROM {_SESSIONS_TABLE} "
                "WHERE session_id = :sid"
            ),
            {"sid": "legacy-session-id-3"},
        ).one()
    assert user_row.subject == "gamma@example.com"
    assert user_row.role == "admin"
    assert session_row.session_id == "legacy-session-id-3"
    assert session_row.subject == "gamma@example.com"


def test_upgrade_downgrade_roundtrip_is_clean(sqlite_engine: Engine) -> None:
    """``upgrade → downgrade → upgrade`` is byte-stable for the column shape.

    Belt-and-braces companion to the per-direction tests — proves the
    migration is safe to re-deploy after a rollback, the operational
    scenario for "redeploy after a hotfix to the previous revision".
    """
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)
    with sqlite_engine.begin() as conn:
        _downgrade_revision_with_op_context(conn, _REVISION)
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    insp = inspect(sqlite_engine)
    user_cols = {c["name"] for c in insp.get_columns(_USERS_TABLE)}
    session_cols = {c["name"] for c in insp.get_columns(_SESSIONS_TABLE)}
    assert _NEW_USER_COLUMNS.issubset(user_cols), (
        "round-trip must end with the MFA user columns present"
    )
    assert _COL_MFA_PASSED_AT in session_cols, (
        "round-trip must end with mfa_passed_at present"
    )


def test_sqlite_backup_codes_column_degrades_to_json(
    sqlite_engine: Engine,
) -> None:
    """SQLite cannot do ``ARRAY``; the migration must emit JSON instead.

    Documented in the worker's migration docstring (Dialect handling →
    SQLite uses ``JSON`` instead of ``ARRAY``). If this test fails,
    either the migration regressed (still emits ARRAY on SQLite — the
    table-create would error) or the inspector reports a different
    canonical type name than ``JSON``.
    """
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    insp = inspect(sqlite_engine)
    columns = {c["name"]: c for c in insp.get_columns(_USERS_TABLE)}
    backup_col = columns[_COL_MFA_BACKUP_CODES_HASH]

    # SQLAlchemy's reflector returns either a JSON instance or a string
    # type name; cover both shapes.
    type_repr = repr(backup_col["type"]).upper()
    assert "JSON" in type_repr or isinstance(backup_col["type"], sa.JSON), (
        f"{_COL_MFA_BACKUP_CODES_HASH} must degrade to JSON on SQLite; "
        f"got type={backup_col['type']!r}"
    )


def test_sqlite_secret_encrypted_column_is_blob_compatible(
    sqlite_engine: Engine,
) -> None:
    """``mfa_secret_encrypted`` must accept binary Fernet tokens on SQLite.

    Soft sanity-check that the dialect-aware ``LargeBinary`` resolves to
    ``BLOB`` on SQLite (so the DAO can persist Fernet ciphertext bytes
    without an implicit cast). A regression to ``TEXT`` would silently
    corrupt every Fernet token (utf-8 roundtrip ≠ identity for arbitrary
    bytes).
    """
    with sqlite_engine.begin() as conn:
        _apply_revision_with_op_context(conn, _REVISION)

    payload = b"\xff\x80\x00\x42-test-binary-token"
    with sqlite_engine.begin() as conn:
        _seed_pre_032_admin_user(conn, subject="binary-probe@example.com")
        conn.execute(
            text(
                f"""
                UPDATE {_USERS_TABLE}
                SET {_COL_MFA_SECRET_ENCRYPTED} = :ct
                WHERE subject = :sub
                """
            ),
            {"ct": payload, "sub": "binary-probe@example.com"},
        )

    with sqlite_engine.connect() as conn:
        roundtripped = conn.execute(
            text(
                f"SELECT {_COL_MFA_SECRET_ENCRYPTED} FROM {_USERS_TABLE} "
                "WHERE subject = :sub"
            ),
            {"sub": "binary-probe@example.com"},
        ).scalar_one()

    assert isinstance(roundtripped, (bytes, bytearray, memoryview)), (
        f"{_COL_MFA_SECRET_ENCRYPTED} must round-trip binary data; "
        f"got {type(roundtripped).__name__}"
    )
    assert bytes(roundtripped) == payload, (
        "binary payload corrupted by the BLOB round-trip — Fernet ciphertext "
        "would be unrecoverable"
    )


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
def test_032_pg_upgrade_creates_mfa_columns(migrated_engine: Engine) -> None:
    """Postgres ``upgrade head`` lands all 4 MFA columns with correct nullability."""
    insp = inspect(migrated_engine)
    user_cols = {c["name"]: c for c in insp.get_columns(_USERS_TABLE)}
    session_cols = {c["name"]: c for c in insp.get_columns(_SESSIONS_TABLE)}

    for col_name, expected_nullable in (
        _EXPECTED_USER_MFA_COLUMN_NULLABILITY.items()
    ):
        assert col_name in user_cols, (
            f"Postgres upgrade head must add {col_name!r} to {_USERS_TABLE}"
        )
        assert user_cols[col_name]["nullable"] is expected_nullable, (
            f"{_USERS_TABLE}.{col_name} nullable={user_cols[col_name]['nullable']!r} "
            f"but spec requires {expected_nullable!r}"
        )

    assert _COL_MFA_PASSED_AT in session_cols
    assert session_cols[_COL_MFA_PASSED_AT]["nullable"] is True


@pytestmark_pg
@pytest.mark.requires_postgres
def test_032_pg_downgrade_drops_mfa_columns(pg_url: str) -> None:
    """``upgrade head -> downgrade -1 -> upgrade head`` round-trip is clean."""
    cfg = _alembic_config(pg_url)
    command.upgrade(cfg, "head")

    sync_url = _to_sync_url(pg_url)
    engine = sa.create_engine(sync_url, future=True)
    try:
        insp = inspect(engine)
        user_cols = {c["name"] for c in insp.get_columns(_USERS_TABLE)}
        assert _NEW_USER_COLUMNS.issubset(user_cols)

        command.downgrade(cfg, "-1")
        engine.dispose()
        engine = sa.create_engine(sync_url, future=True)
        insp = inspect(engine)
        user_cols = {c["name"] for c in insp.get_columns(_USERS_TABLE)}
        session_cols = {c["name"] for c in insp.get_columns(_SESSIONS_TABLE)}
        assert _NEW_USER_COLUMNS.isdisjoint(user_cols), (
            f"downgrade -1 from 032 must drop the MFA columns from "
            f"{_USERS_TABLE}; still present: "
            f"{sorted(_NEW_USER_COLUMNS & user_cols)!r}"
        )
        assert _COL_MFA_PASSED_AT not in session_cols, (
            f"downgrade -1 from 032 must drop {_COL_MFA_PASSED_AT!r}"
        )

        command.upgrade(cfg, "head")
        engine.dispose()
        engine = sa.create_engine(sync_url, future=True)
        insp = inspect(engine)
        user_cols = {c["name"] for c in insp.get_columns(_USERS_TABLE)}
        assert _NEW_USER_COLUMNS.issubset(user_cols)
    finally:
        engine.dispose()
        command.downgrade(cfg, "base")
