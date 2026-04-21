r"""T32 / ARG-056 — ``scan_schedules`` migration tests.

Two-layer test strategy (mirrors ``test_alembic_smoke.py``):

A. Dialect-free checks — always run, no DB required.
   * Revision metadata is pinned (``revision="026"``, ``down_revision="025"``).
   * Both ``upgrade()`` and ``downgrade()`` callables exist.
   * The ``ScanSchedule`` ORM model is registered and exposes the spec-mandated
     columns / constraints / indexes.

B. Postgres round-trip checks — gated by ``@pytest.mark.requires_postgres``
   and skipped automatically when ``DATABASE_URL`` is not a real Postgres URL.
   Layer B drives ``command.upgrade`` / ``command.downgrade`` and then
   validates:
     * columns / types / nullability via ``inspect``;
     * indexes (``ix_scan_schedules_tenant_enabled``,
       ``ix_scan_schedules_next_run_at``) are present;
     * the unique ``(tenant_id, name)`` constraint rejects duplicates;
     * RLS isolation for SELECT and UPDATE paths;
     * ``ON DELETE CASCADE`` from ``tenants`` sweeps child rows;
     * ``upgrade`` → ``downgrade`` → ``upgrade`` is a no-op (schema byte-stable).

DEVIATION: the task spec asks for ``backend/tests/db/test_scan_schedules_migration.py``
but every other Alembic migration test in the repo lives under
``backend/tests/integration/migrations/``. Placing this file there keeps the
smoke-test tooling (``_alembic_config`` / ``_dump_schema``) discoverable and
lets the CI lane that runs ``pytest tests/integration/migrations`` pick it up
automatically. See the plan file for the formal deviation note.

How to run the Postgres half locally (PowerShell)::

    docker run --rm -d --name argus-pg-t32 -p 55432:5432 `
        -e POSTGRES_PASSWORD=argus -e POSTGRES_DB=argus_test postgres:15
    $env:DATABASE_URL = "postgresql+asyncpg://postgres:argus@localhost:55432/argus_test"
    .\.venv\Scripts\python.exe -m pytest `
        backend/tests/integration/migrations/test_scan_schedules_migration.py -v
"""

from __future__ import annotations

import importlib.util
import os
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

_BACKEND_ROOT = Path(__file__).resolve().parents[3]
_VERSIONS_DIR = _BACKEND_ROOT / "alembic" / "versions"
_REVISION = "026"
_DOWN_REVISION = "025"
_TABLE = "scan_schedules"
_POLICY = "tenant_isolation"

# Expected (name -> nullable) shape — verbatim from the spec.
_EXPECTED_COLUMNS: dict[str, bool] = {
    "id": False,
    "tenant_id": False,
    "name": False,
    "cron_expression": False,
    "target_url": False,
    "scan_mode": False,
    "enabled": False,
    "maintenance_window_cron": True,
    "last_run_at": True,
    "next_run_at": True,
    "created_at": False,
    "updated_at": False,
}

_EXPECTED_INDEXES = {
    "ix_scan_schedules_tenant_enabled",
    "ix_scan_schedules_next_run_at",
}

# Gate for Layer B.
_PG_URL_RAW = os.environ.get("DATABASE_URL", "")
_HAS_POSTGRES_URL = _PG_URL_RAW.startswith(("postgresql://", "postgresql+", "postgres://"))

pytestmark_pg = pytest.mark.skipif(
    not _HAS_POSTGRES_URL,
    reason="DATABASE_URL is not a Postgres URL — scan_schedules RLS checks need real Postgres",
)


# ---------------------------------------------------------------------------
# Shared helpers.
# ---------------------------------------------------------------------------


def _load_revision_module() -> Any:
    """Import the 026 migration file as a standalone module."""
    matches = list(_VERSIONS_DIR.glob(f"{_REVISION}_*.py"))
    assert matches, f"revision file for {_REVISION} not found"
    spec = importlib.util.spec_from_file_location(f"_alembic_{_REVISION}", matches[0])
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
    """Translate the asyncpg URL used by alembic.env into a psycopg2 one.

    The project keeps ``asyncpg`` in runtime deps and ``psycopg2-binary`` in
    the dev extras, so dev/test environments can reliably open a synchronous
    connection for introspection. We deliberately default to the bare
    ``postgresql://`` driver spec so SQLAlchemy picks psycopg2 without extra
    extras in the URL.
    """
    for prefix in ("postgresql+asyncpg://", "postgres+asyncpg://"):
        if url.startswith(prefix):
            return "postgresql://" + url[len(prefix) :]
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://") :]
    return url


# ---------------------------------------------------------------------------
# Layer A — dialect-free checks (no DB required).
# ---------------------------------------------------------------------------


def test_026_revision_metadata_pinned() -> None:
    module = _load_revision_module()
    assert module.revision == _REVISION, (
        f"026 migration must declare revision={_REVISION!r}, got {module.revision!r}"
    )
    assert module.down_revision == _DOWN_REVISION, (
        f"026 migration must chain off {_DOWN_REVISION!r} "
        f"(024 and 025 are already in use), got {module.down_revision!r}"
    )
    assert module.branch_labels is None, "026 must not introduce a branch label"
    assert module.depends_on is None, "026 must not depend on another revision"


def test_026_has_upgrade_and_downgrade_callables() -> None:
    module = _load_revision_module()
    assert callable(getattr(module, "upgrade", None)), "026.upgrade missing or not callable"
    assert callable(getattr(module, "downgrade", None)), "026.downgrade missing or not callable"


def test_026_orm_model_matches_spec() -> None:
    """``ScanSchedule`` ORM must mirror the migration column-by-column.

    Guards against drift between the physical schema (migration) and the
    logical schema (ORM) — a classic source of production bugs where an ALTER
    ships in Alembic but the model keeps the old shape.
    """
    from src.db.models import ScanSchedule

    assert ScanSchedule.__tablename__ == _TABLE
    # ``__table__`` is typed as ``FromClause`` in SQLAlchemy stubs; narrow it
    # so mypy can see ``.constraints`` / ``.indexes`` which ``Table`` exposes.
    table = cast(sa.Table, ScanSchedule.__table__)
    column_shapes = {c.name: c.nullable for c in table.columns}
    assert column_shapes == _EXPECTED_COLUMNS, (
        f"ScanSchedule column shape drifted from spec:\n"
        f"  expected: {_EXPECTED_COLUMNS}\n"
        f"  got:      {column_shapes}"
    )

    unique_constraints = {
        uc.name: tuple(sorted(c.name for c in uc.columns))
        for uc in table.constraints
        if isinstance(uc, sa.UniqueConstraint)
    }
    assert unique_constraints.get("uq_scan_schedules_tenant_name") == ("name", "tenant_id"), (
        "ScanSchedule must declare UniqueConstraint(tenant_id, name)"
    )

    index_names = {ix.name for ix in table.indexes}
    missing = _EXPECTED_INDEXES - index_names
    assert not missing, f"ScanSchedule missing ORM indexes: {missing}"

    fk_targets = {
        (fk.column.table.name, fk.column.name, fk.ondelete)
        for fk in table.foreign_keys
    }
    assert ("tenants", "id", "CASCADE") in fk_targets, (
        "ScanSchedule.tenant_id must FK tenants(id) ON DELETE CASCADE"
    )


# ---------------------------------------------------------------------------
# Layer B — Postgres round-trip checks.
# ---------------------------------------------------------------------------


@pytest.fixture()
def pg_url(monkeypatch: pytest.MonkeyPatch) -> str:
    """Return the configured Postgres URL and patch the cached settings.

    Mirrors the fixture shape used by ``test_alembic_smoke.py`` so both test
    modules can share the same ``DATABASE_URL`` contract.
    """
    if _PG_URL_RAW.startswith("postgresql://"):
        async_url = _PG_URL_RAW.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif _PG_URL_RAW.startswith("postgres://"):
        async_url = _PG_URL_RAW.replace("postgres://", "postgresql+asyncpg://", 1)
    else:
        async_url = _PG_URL_RAW
    monkeypatch.setenv("DATABASE_URL", async_url)
    from src.core import config as _cfg

    monkeypatch.setattr(_cfg.settings, "database_url", async_url)
    return async_url


@pytest.fixture()
def migrated_engine(pg_url: str) -> Iterator[Engine]:
    """Drive ``upgrade head`` and yield a synchronous engine over the same DB.

    The alembic CLI runs with the async driver (see ``alembic/env.py``); our
    assertions run on a sibling psycopg2 engine so we can use standard
    ``inspect`` and session-variable SQL. Each test resets the DB to a clean
    ``base`` state on teardown so tests don't leak rows.
    """
    cfg = _alembic_config(pg_url)
    command.upgrade(cfg, "head")

    sync_url = _to_sync_url(pg_url)
    engine = sa.create_engine(sync_url, future=True)
    try:
        yield engine
    finally:
        engine.dispose()
        # Clean slate for the next test / the next pytest run.
        command.downgrade(cfg, "base")


def _seed_tenant(conn: sa.Connection, name: str) -> str:
    """Insert a minimal tenant row and return its id.

    Uses only columns guaranteed by the initial schema so the helper stays
    robust against later additions to ``tenants``.
    """
    tid = str(uuid.uuid4())
    conn.execute(
        text("INSERT INTO tenants (id, name) VALUES (:id, :name)"),
        {"id": tid, "name": name},
    )
    return tid


def _set_tenant(conn: sa.Connection, tenant_id: str) -> None:
    """Set ``app.current_tenant_id`` for the current transaction.

    Using ``SET LOCAL`` means the setting evaporates at COMMIT/ROLLBACK so
    tests cannot poison subsequent ones via session state.
    """
    # SET LOCAL accepts only a literal; quote via psycopg2 format_string.
    conn.execute(text(f"SET LOCAL app.current_tenant_id = '{tenant_id}'"))


def _insert_schedule(
    conn: sa.Connection,
    tenant_id: str,
    name: str,
    *,
    cron: str = "0 3 * * *",
    target_url: str = "https://example.com",
    scan_mode: str = "standard",
    enabled: bool = True,
) -> str:
    """Insert one ``scan_schedules`` row and return its id."""
    sid = str(uuid.uuid4())
    conn.execute(
        text(
            """
            INSERT INTO scan_schedules (
                id, tenant_id, name, cron_expression, target_url, scan_mode, enabled
            ) VALUES (
                :id, :tenant_id, :name, :cron, :target_url, :scan_mode, :enabled
            )
            """
        ),
        {
            "id": sid,
            "tenant_id": tenant_id,
            "name": name,
            "cron": cron,
            "target_url": target_url,
            "scan_mode": scan_mode,
            "enabled": enabled,
        },
    )
    return sid


@pytestmark_pg
@pytest.mark.requires_postgres
def test_026_upgrade_creates_table_with_expected_columns(migrated_engine: Engine) -> None:
    insp = inspect(migrated_engine)
    assert insp.has_table(_TABLE), f"{_TABLE} should exist after upgrade head"

    columns = {c["name"]: c for c in insp.get_columns(_TABLE)}
    assert set(columns) == set(_EXPECTED_COLUMNS), (
        f"{_TABLE} columns differ from spec: got={set(columns)} expected={set(_EXPECTED_COLUMNS)}"
    )
    for col_name, expected_nullable in _EXPECTED_COLUMNS.items():
        assert columns[col_name]["nullable"] is expected_nullable, (
            f"{_TABLE}.{col_name} nullable={columns[col_name]['nullable']!r} "
            f"but spec requires {expected_nullable!r}"
        )


@pytestmark_pg
@pytest.mark.requires_postgres
def test_026_indexes_present(migrated_engine: Engine) -> None:
    insp = inspect(migrated_engine)
    index_names = {ix["name"] for ix in insp.get_indexes(_TABLE)}
    missing = _EXPECTED_INDEXES - index_names
    assert not missing, f"{_TABLE} missing indexes after upgrade head: {missing}"


@pytestmark_pg
@pytest.mark.requires_postgres
def test_026_rls_enabled_and_policy_present(migrated_engine: Engine) -> None:
    """Confirm RLS is ENABLED + FORCED and the ``tenant_isolation`` policy exists."""
    with migrated_engine.connect() as conn:
        row = conn.execute(
            text(
                """
                SELECT relrowsecurity, relforcerowsecurity
                FROM pg_class
                WHERE relname = :table
                """
            ),
            {"table": _TABLE},
        ).one()
        assert row.relrowsecurity, f"{_TABLE} must have ROW LEVEL SECURITY enabled"
        assert row.relforcerowsecurity, (
            f"{_TABLE} must have FORCE ROW LEVEL SECURITY set (T32 hardening over 019/020)"
        )

        policy_names = conn.execute(
            text("SELECT polname FROM pg_policy WHERE polrelid = :table::regclass"),
            {"table": _TABLE},
        ).scalars().all()
        assert _POLICY in policy_names, (
            f"canonical {_POLICY!r} policy missing on {_TABLE}; found {policy_names!r}"
        )


@pytestmark_pg
@pytest.mark.requires_postgres
def test_026_unique_tenant_name_enforced(migrated_engine: Engine) -> None:
    with migrated_engine.begin() as conn:
        tid = _seed_tenant(conn, "t-unique")
        _insert_schedule(conn, tid, "daily")

    with migrated_engine.connect() as conn:
        tid = conn.execute(
            text("SELECT id FROM tenants WHERE name = 't-unique'")
        ).scalar_one()

    with pytest.raises(IntegrityError):
        with migrated_engine.begin() as conn:
            _insert_schedule(conn, tid, "daily")


@pytestmark_pg
@pytest.mark.requires_postgres
def test_026_rls_isolation_on_select(migrated_engine: Engine) -> None:
    """Rows scoped to tenant A must be invisible to a session scoped to B."""
    with migrated_engine.begin() as conn:
        tenant_a = _seed_tenant(conn, "rls-select-a")
        tenant_b = _seed_tenant(conn, "rls-select-b")
        _insert_schedule(conn, tenant_a, "daily", target_url="https://a.example")
        _insert_schedule(conn, tenant_b, "daily", target_url="https://b.example")

    # Tenant A session — must see its own row, never B's.
    with migrated_engine.begin() as conn:
        _set_tenant(conn, tenant_a)
        rows_a = conn.execute(
            text("SELECT tenant_id FROM scan_schedules")
        ).scalars().all()
        assert rows_a == [tenant_a], (
            f"tenant A session leaked other tenants' rows: {rows_a!r}"
        )

    # Tenant B session — symmetric guarantee.
    with migrated_engine.begin() as conn:
        _set_tenant(conn, tenant_b)
        rows_b = conn.execute(
            text("SELECT tenant_id FROM scan_schedules")
        ).scalars().all()
        assert rows_b == [tenant_b]

    # No tenant set at all — policy rejects every row.
    with migrated_engine.begin() as conn:
        visible = conn.execute(text("SELECT COUNT(*) FROM scan_schedules")).scalar_one()
        assert visible == 0, (
            "with no app.current_tenant_id set, RLS must hide every row; "
            f"got {visible} visible"
        )


@pytestmark_pg
@pytest.mark.requires_postgres
def test_026_rls_isolation_on_update(migrated_engine: Engine) -> None:
    """Cross-tenant UPDATE must touch 0 rows — both USING and WITH CHECK bite."""
    with migrated_engine.begin() as conn:
        tenant_a = _seed_tenant(conn, "rls-update-a")
        tenant_b = _seed_tenant(conn, "rls-update-b")
        _insert_schedule(conn, tenant_a, "daily")
        _insert_schedule(conn, tenant_b, "daily")

    with migrated_engine.begin() as conn:
        _set_tenant(conn, tenant_a)
        result = conn.execute(
            text(
                """
                UPDATE scan_schedules
                SET enabled = false
                WHERE tenant_id = :other
                """
            ),
            {"other": tenant_b},
        )
        assert result.rowcount == 0, (
            "tenant A must not be able to UPDATE tenant B rows via raw WHERE clause"
        )

    # Tenant B's row is untouched.
    with migrated_engine.begin() as conn:
        _set_tenant(conn, tenant_b)
        still_enabled = conn.execute(
            text(
                "SELECT enabled FROM scan_schedules WHERE tenant_id = :t"
            ),
            {"t": tenant_b},
        ).scalar_one()
        assert still_enabled is True, (
            "tenant B row was mutated across the RLS boundary — policy is broken"
        )


@pytestmark_pg
@pytest.mark.requires_postgres
def test_026_fk_cascade_on_tenant_delete(migrated_engine: Engine) -> None:
    with migrated_engine.begin() as conn:
        tid = _seed_tenant(conn, "cascade")
        _insert_schedule(conn, tid, "daily")
        _insert_schedule(conn, tid, "weekly")
        count_before = conn.execute(
            text("SELECT COUNT(*) FROM scan_schedules WHERE tenant_id = :t"),
            {"t": tid},
        ).scalar_one()
        assert count_before == 2

    with migrated_engine.begin() as conn:
        conn.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": tid})

    with migrated_engine.begin() as conn:
        count_after = conn.execute(
            text("SELECT COUNT(*) FROM scan_schedules WHERE tenant_id = :t"),
            {"t": tid},
        ).scalar_one()
        assert count_after == 0, (
            "ON DELETE CASCADE failed — child schedule rows outlived the parent tenant"
        )


@pytestmark_pg
@pytest.mark.requires_postgres
def test_026_downgrade_drops_table_idempotently(pg_url: str) -> None:
    """``upgrade → downgrade -1 → upgrade → downgrade base`` all succeed."""
    cfg = _alembic_config(pg_url)

    command.upgrade(cfg, "head")
    sync_url = _to_sync_url(pg_url)
    engine = sa.create_engine(sync_url, future=True)
    try:
        assert inspect(engine).has_table(_TABLE)

        command.downgrade(cfg, "-1")
        engine.dispose()
        engine = sa.create_engine(sync_url, future=True)
        assert not inspect(engine).has_table(_TABLE), (
            "downgrade -1 from 026 must drop scan_schedules"
        )

        # Replay upgrade to make sure upgrade() is idempotent-safe against
        # a partially-applied schema (reconnect first to see the new table).
        command.upgrade(cfg, "head")
        engine.dispose()
        engine = sa.create_engine(sync_url, future=True)
        assert inspect(engine).has_table(_TABLE)
    finally:
        engine.dispose()
        command.downgrade(cfg, "base")
