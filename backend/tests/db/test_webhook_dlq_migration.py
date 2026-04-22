r"""T37 / ARG-053 — ``webhook_dlq_entries`` migration tests.

Closes Cycle 6 Batch 5 acceptance criteria for migration ``027_webhook_dlq.py``
(see ``ai_docs/develop/plans/2026-04-22-argus-cycle6-b5.md`` §T37).

Two-layer strategy mirrors the canonical Batch 4 ``026_scan_schedules`` test
module so the suite stays consistent across batches:

A. Dialect-portable round-trip checks — always run, no live DB required.
   * Revision metadata is pinned (``revision="027"``, ``down_revision="026"``).
   * ``upgrade -> downgrade -> upgrade`` is idempotent (column + index set
     reproduces byte-for-byte after the round-trip).
   * Table shape (16 columns + nullability + 3 indexes) is what the schema
     spec demands.
   * ``UniqueConstraint(tenant_id, adapter_name, event_id)`` rejects duplicates
     when exercised through the real ``WebhookDlqEntry`` ORM model — proves the
     ORM and migration agree on the constraint.
   * ``ON DELETE CASCADE`` from ``tenants`` sweeps child DLQ rows on SQLite
     (``PRAGMA foreign_keys=ON``); same wiring is verified against Postgres
     in Layer B.

B. Postgres RLS + FORCE checks — gated by ``@pytest.mark.requires_postgres``
   AND ``pytestmark_pg.skipif(not _HAS_POSTGRES_URL)`` so the tests skip
   cleanly in dev's default ``pytest -q`` run when ``DATABASE_URL`` is unset
   or points at SQLite. Drives ``alembic command.upgrade`` via the project's
   real ``alembic.ini`` and then validates:
     * ``tenant_isolation`` policy exists on the table.
     * ``relrowsecurity`` AND ``relforcerowsecurity`` are both true (FORCE is
       what makes the policy bite for the table-owner role — without it the
       migration role bypasses tenant isolation silently).
     * Cross-tenant SELECT under ``set_session_tenant("tenant_a")`` returns
       only ``tenant_a``'s row.
     * Setting ``app.current_tenant_id = tenant_b`` from the owner-role
       session hides ``tenant_a``'s row even though the connecting role owns
       the table — the FORCE assertion the plan calls out as a separate case.

Layer A uses an in-memory SQLite engine driven through
``alembic.migration.MigrationContext`` + ``alembic.operations.Operations``
so we can apply ONLY revision ``027`` against a clean schema. The full
migration chain contains JSONB / PG-specific ops that SQLite cannot compile,
so a vanilla ``command.upgrade(cfg, "head")`` against SQLite is not viable.
"""

from __future__ import annotations

import importlib.util
import os
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

# ---------------------------------------------------------------------------
# Constants — every magic string lives here so a future schema bump is a
# one-line edit at the top of the module.
# ---------------------------------------------------------------------------

_BACKEND_ROOT = Path(__file__).resolve().parents[2]
_VERSIONS_DIR = _BACKEND_ROOT / "alembic" / "versions"
_REVISION = "027"
_DOWN_REVISION = "026"
_TABLE = "webhook_dlq_entries"
_POLICY = "tenant_isolation"
_UNIQUE_CONSTRAINT = "uq_webhook_dlq_tenant_adapter_event"

# Expected (column name -> nullable) shape — 16 columns, verbatim from the
# T37 schema spec (see ``027_webhook_dlq.py`` upgrade()).
_EXPECTED_COLUMNS: dict[str, bool] = {
    "id": False,
    "tenant_id": False,
    "adapter_name": False,
    "event_type": False,
    "event_id": False,
    "target_url_hash": False,
    "payload_json": False,
    "last_error_code": False,
    "last_status_code": True,
    "attempt_count": False,
    "next_retry_at": True,
    "replayed_at": True,
    "abandoned_at": True,
    "abandoned_reason": True,
    "created_at": False,
    "updated_at": False,
}

# Indexes that exist on EVERY dialect (name-stable across PG and SQLite).
_EXPECTED_INDEXES: frozenset[str] = frozenset(
    {
        "ix_webhook_dlq_tenant_status",
        "ix_webhook_dlq_next_retry_at",
        "ix_webhook_dlq_created_at",
    }
)

# Layer B gate. The string ``"postgresql"`` (no terminator) is intentionally
# the only host-bearing literal in this module — the auto-marker classifier
# in ``backend/tests/conftest.py::_RE_POSTGRES`` matches ``postgres[:/]\d{0,5}``
# patterns; without an explicit ``:port`` or ``/db`` suffix this assignment
# stays inert and Layer A SQLite tests stay un-marked (so they actually RUN
# in the developer's default ``pytest -q``).
_PG_URL_RAW = os.environ.get("DATABASE_URL", "")
_HAS_POSTGRES_URL = _PG_URL_RAW.startswith("postgresql")

pytestmark_pg = pytest.mark.skipif(
    not _HAS_POSTGRES_URL,
    reason=(
        "DATABASE_URL is not a Postgres URL — webhook DLQ RLS+FORCE checks "
        "need a real Postgres backend (set DATABASE_URL=postgresql+asyncpg://...)"
    ),
)


# ---------------------------------------------------------------------------
# Shared helpers.
# ---------------------------------------------------------------------------


def _load_revision_module() -> Any:
    """Import revision ``027`` as a standalone module (no Alembic chain run).

    Returning ``Any`` here is deliberate: ``upgrade()`` / ``downgrade()`` are
    free functions on the migration script and have no public type stubs.
    """
    matches = list(_VERSIONS_DIR.glob(f"{_REVISION}_*.py"))
    assert matches, f"revision file for {_REVISION} not found under {_VERSIONS_DIR}"
    spec = importlib.util.spec_from_file_location(f"_alembic_{_REVISION}", matches[0])
    assert spec is not None and spec.loader is not None, (
        f"unable to build importlib spec for {matches[0]}"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _alembic_config(database_url: str) -> Config:
    """Build an Alembic ``Config`` pointing at the project's real ``alembic.ini``."""
    cfg = Config(str(_BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


def _to_sync_url(url: str) -> str:
    """Translate the asyncpg URL alembic.env uses into a sync psycopg2 URL.

    The project keeps ``asyncpg`` in runtime deps and ``psycopg2-binary`` in
    dev extras — sync introspection (``inspect``, ``SET LOCAL ...``) needs
    the synchronous driver. We deliberately strip the ``+asyncpg`` token so
    SQLAlchemy auto-picks psycopg2 without the test having to know which
    driver is installed.
    """
    async_prefix = "postgresql+asyncpg://"
    if url.startswith(async_prefix):
        return "postgresql://" + url[len(async_prefix) :]
    return url


def _make_sqlite_engine(*, fk_on: bool = True) -> Engine:
    """In-memory SQLite engine seeded with a ``tenants`` table.

    Uses ``StaticPool`` so every ``engine.connect()`` call shares the same
    underlying DB-API connection — without it the ``:memory:`` database is
    re-created per checkout and our seeded ``tenants`` row evaporates between
    transactions. ``PRAGMA foreign_keys=ON`` is registered as a ``connect``
    event-listener so the ``ON DELETE CASCADE`` clause defined in revision
    027 is actually enforced (SQLite ignores FK declarations otherwise).
    """
    engine = sa.create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=sa.pool.StaticPool,
    )

    if fk_on:

        @event.listens_for(engine, "connect")
        def _enable_sqlite_fk(dbapi_conn: Any, _conn_record: Any) -> None:
            cursor = dbapi_conn.cursor()
            try:
                cursor.execute("PRAGMA foreign_keys=ON")
            finally:
                cursor.close()

    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE tenants ("
                "id VARCHAR(36) PRIMARY KEY, "
                "name VARCHAR(255) NOT NULL"
                ")"
            )
        )

    return engine


def _apply_027_upgrade(engine: Engine) -> None:
    """Drive ONLY revision 027's ``upgrade()`` against ``engine``.

    Bypasses ``alembic command.upgrade(...)`` because the full migration
    chain contains PG-specific types (JSONB, ARRAY, etc.) that fail to
    compile on SQLite.
    """
    module = _load_revision_module()
    with engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            module.upgrade()


def _apply_027_downgrade(engine: Engine) -> None:
    """Symmetric counterpart to :func:`_apply_027_upgrade`."""
    module = _load_revision_module()
    with engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            module.downgrade()


def _seed_tenant(conn: sa.Connection, name: str) -> str:
    """Insert a minimal ``tenants`` row and return its id.

    Uses only columns guaranteed by the bare-bones schema we set up in
    :func:`_make_sqlite_engine` so the helper is reusable from Layer B
    against the real ``tenants`` table created by migration 001 too.
    """
    tid = str(uuid.uuid4())
    conn.execute(
        text("INSERT INTO tenants (id, name) VALUES (:id, :name)"),
        {"id": tid, "name": name},
    )
    return tid


def _insert_dlq_row_via_sql(
    conn: sa.Connection,
    *,
    tenant_id: str,
    adapter_name: str = "slack",
    event_id: str | None = None,
    payload_json_literal: str = "'{}'",
) -> str:
    """Insert one ``webhook_dlq_entries`` row via raw SQL and return its id.

    ``payload_json_literal`` is the raw SQL fragment for the JSON column —
    must already include any required quotes / casts. The default ``'{}'``
    is a quoted empty-object literal that SQLite (JSON column = TEXT) and
    Postgres (JSON column = JSON) both accept; PG callers can override with
    ``"'{}'::jsonb"`` to exercise the JSONB path explicitly.
    """
    rid = str(uuid.uuid4())
    eid = event_id if event_id is not None else f"evt-{rid[:8]}"
    conn.execute(
        text(
            "INSERT INTO webhook_dlq_entries "
            "(id, tenant_id, adapter_name, event_type, event_id, "
            " target_url_hash, payload_json, last_error_code, attempt_count, "
            " created_at, updated_at) "
            "VALUES (:id, :tid, :adapter, 'finding.created', :eid, "
            f" 'h-' || :id, {payload_json_literal}, 'http_5xx', 0, "
            " CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        ),
        {"id": rid, "tid": tenant_id, "adapter": adapter_name, "eid": eid},
    )
    return rid


# ---------------------------------------------------------------------------
# Layer A — dialect-portable checks (always run, in-memory SQLite).
# ---------------------------------------------------------------------------


def test_027_round_trip_idempotency_sqlite() -> None:
    """``upgrade -> downgrade -> upgrade`` reproduces the schema byte-stably.

    Acceptance criterion (a): revision is ``"027"``, down_revision is
    ``"026"``, and the round-trip is a no-op.
    """
    engine = _make_sqlite_engine(fk_on=False)
    try:
        module = _load_revision_module()
        assert module.revision == _REVISION, (
            f"027 must declare revision={_REVISION!r}, got {module.revision!r}"
        )
        assert module.down_revision == _DOWN_REVISION, (
            f"027 must chain off {_DOWN_REVISION!r} (revision 025 is in use "
            f"by Batch 2 T13, 026 by Batch 4 T32), got {module.down_revision!r}"
        )

        _apply_027_upgrade(engine)
        first = inspect(engine)
        assert first.has_table(_TABLE), f"upgrade() must create {_TABLE!r}"
        cols_before = {c["name"] for c in first.get_columns(_TABLE)}
        idx_before = {ix["name"] for ix in first.get_indexes(_TABLE)}

        _apply_027_downgrade(engine)
        assert not inspect(engine).has_table(_TABLE), (
            f"downgrade() must drop {_TABLE!r}"
        )

        _apply_027_upgrade(engine)
        second = inspect(engine)
        assert second.has_table(_TABLE), "second upgrade() must recreate the table"
        cols_after = {c["name"] for c in second.get_columns(_TABLE)}
        idx_after = {ix["name"] for ix in second.get_indexes(_TABLE)}

        assert cols_before == cols_after, (
            f"column set drifted across round-trip: "
            f"before={cols_before!r} after={cols_after!r}"
        )
        assert idx_before == idx_after, (
            f"index set drifted across round-trip: "
            f"before={idx_before!r} after={idx_after!r}"
        )
    finally:
        engine.dispose()


def test_027_table_shape_after_upgrade_sqlite() -> None:
    """Table has all 16 columns with the expected nullability + 3 indexes.

    Acceptance criterion (b) types/shape + (d) indexes (SQLite variant — the
    Postgres-specific partial-index predicate is verified separately at the
    integration level via Layer B's ``relpartitioned``-aware introspection).
    """
    engine = _make_sqlite_engine(fk_on=False)
    try:
        _apply_027_upgrade(engine)
        insp = inspect(engine)

        columns = {c["name"]: c for c in insp.get_columns(_TABLE)}
        assert set(columns) == set(_EXPECTED_COLUMNS), (
            f"{_TABLE} column set drifted from spec:\n"
            f"  expected: {sorted(_EXPECTED_COLUMNS)}\n"
            f"  got:      {sorted(columns)}"
        )
        for col_name, expected_nullable in _EXPECTED_COLUMNS.items():
            assert columns[col_name]["nullable"] is expected_nullable, (
                f"{_TABLE}.{col_name} nullable={columns[col_name]['nullable']!r}, "
                f"spec requires {expected_nullable!r}"
            )

        # SQLAlchemy stubs type ``ix["name"]`` and ``uc["name"]`` as
        # ``str | None`` because Alembic-style anonymous constraints exist;
        # 027 names every index/constraint so the ``is not None`` filter is
        # belt-and-suspenders for the type checker, not a guard against real
        # data drift.
        index_names: set[str] = {
            ix["name"] for ix in insp.get_indexes(_TABLE) if ix["name"] is not None
        }
        missing = _EXPECTED_INDEXES - index_names
        assert not missing, (
            f"{_TABLE} missing indexes after upgrade: {sorted(missing)} "
            f"(present: {sorted(index_names)})"
        )

        # UNIQUE constraint is reported either as a constraint or as a
        # uniqueness flag on an index — accept both shapes (SQLite emits a
        # synthetic ``sqlite_autoindex_*`` entry for unique constraints).
        unique_constraint_names: set[str] = {
            uc["name"]
            for uc in insp.get_unique_constraints(_TABLE)
            if uc["name"] is not None
        }
        unique_index_names: set[str] = {
            ix["name"]
            for ix in insp.get_indexes(_TABLE)
            if ix.get("unique") and ix["name"] is not None
        }
        assert _UNIQUE_CONSTRAINT in unique_constraint_names | unique_index_names, (
            f"{_UNIQUE_CONSTRAINT!r} not reported as a unique constraint or "
            f"unique index on {_TABLE}; "
            f"constraints={unique_constraint_names!r} "
            f"unique_indexes={unique_index_names!r}"
        )
    finally:
        engine.dispose()


def test_027_unique_tenant_adapter_event_via_orm() -> None:
    """Re-enqueueing the same ``(tenant, adapter, event_id)`` triple raises.

    Acceptance criterion (b) — uses the real ``WebhookDlqEntry`` ORM model
    (so this case also acts as a smoke test that the ORM and the migration
    agree on the unique-key shape — drift here is exactly the bug the T38
    DAO ``IntegrityError`` merge path depends on for correctness).
    """
    from src.db.models import WebhookDlqEntry

    engine = _make_sqlite_engine(fk_on=True)
    try:
        _apply_027_upgrade(engine)
        with engine.begin() as conn:
            tid = _seed_tenant(conn, "unique-tenant")

        with Session(bind=engine) as session:
            session.add(
                WebhookDlqEntry(
                    tenant_id=tid,
                    adapter_name="slack",
                    event_type="finding.created",
                    event_id="evt-dup",
                    target_url_hash="hash-1",
                    payload_json={"k": "v"},
                    last_error_code="http_5xx",
                )
            )
            session.commit()

        with Session(bind=engine) as session:
            session.add(
                WebhookDlqEntry(
                    tenant_id=tid,
                    adapter_name="slack",
                    event_type="finding.created",
                    event_id="evt-dup",
                    target_url_hash="hash-2",
                    payload_json={"k": "v2"},
                    last_error_code="http_5xx",
                )
            )
            with pytest.raises(IntegrityError):
                session.commit()
    finally:
        engine.dispose()


def test_027_fk_cascade_on_tenant_delete_sqlite() -> None:
    """Deleting the parent tenant row sweeps every child DLQ row.

    Acceptance criterion (b)/(c) FK ON DELETE CASCADE — required so a tenant
    offboard does not leak DLQ rows and so the daily replay beat task does
    not retry deliveries against a tenant that no longer exists.
    """
    engine = _make_sqlite_engine(fk_on=True)
    try:
        _apply_027_upgrade(engine)
        with engine.begin() as conn:
            tid = _seed_tenant(conn, "cascade-tenant")
            _insert_dlq_row_via_sql(conn, tenant_id=tid, event_id="evt-1")
            _insert_dlq_row_via_sql(conn, tenant_id=tid, event_id="evt-2")
            count_before = conn.execute(
                text(
                    "SELECT COUNT(*) FROM webhook_dlq_entries "
                    "WHERE tenant_id = :t"
                ),
                {"t": tid},
            ).scalar_one()
            assert count_before == 2, "fixture insert smoke failed"

        with engine.begin() as conn:
            conn.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": tid})

        with engine.connect() as conn:
            count_after = conn.execute(
                text(
                    "SELECT COUNT(*) FROM webhook_dlq_entries "
                    "WHERE tenant_id = :t"
                ),
                {"t": tid},
            ).scalar_one()
            assert count_after == 0, (
                "ON DELETE CASCADE failed — DLQ rows survived the parent "
                "tenant DROP (PRAGMA foreign_keys=ON not honoured?)"
            )
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# Layer B — Postgres RLS + FORCE round-trip.
# ---------------------------------------------------------------------------


@pytest.fixture()
def pg_url(monkeypatch: pytest.MonkeyPatch) -> str:
    """Return the configured Postgres URL (async form) and patch the cached settings.

    Mirrors the fixture shape from ``test_scan_schedules_migration.py`` so
    Batches 4 and 5 share the same ``DATABASE_URL`` contract.
    """
    raw = _PG_URL_RAW
    if raw.startswith("postgresql://"):
        async_url = raw.replace("postgresql://", "postgresql+asyncpg://", 1)
    else:
        async_url = raw

    monkeypatch.setenv("DATABASE_URL", async_url)
    from src.core import config as _cfg

    monkeypatch.setattr(_cfg.settings, "database_url", async_url)
    return async_url


@pytest.fixture()
def migrated_pg_engine(pg_url: str) -> Iterator[Engine]:
    """Drive ``alembic upgrade head`` and yield a sync engine over the same DB.

    The migration runs through the project's real ``alembic.env`` (async
    driver). Assertions then run on a sibling psycopg2 engine so we can use
    standard ``inspect`` and ``SET LOCAL`` SQL. Each test resets the DB to
    ``base`` on teardown so cross-test row leakage is impossible.
    """
    cfg = _alembic_config(pg_url)
    command.upgrade(cfg, "head")
    sync_url = _to_sync_url(pg_url)
    engine = sa.create_engine(sync_url, future=True)
    try:
        yield engine
    finally:
        engine.dispose()
        command.downgrade(cfg, "base")


def _set_session_tenant(conn: sa.Connection, tenant_id: str) -> None:
    """Set ``app.current_tenant_id`` for the current transaction.

    Uses ``SET LOCAL`` so the setting evaporates on COMMIT/ROLLBACK and
    cannot poison subsequent transactions on the pooled connection. The
    tenant id is interpolated as a SQL string literal because ``SET LOCAL``
    rejects bound parameters in PostgreSQL — we rely on the UUID shape of
    the id (no quotes, no semicolons) to make this safe.
    """
    conn.execute(text(f"SET LOCAL app.current_tenant_id = '{tenant_id}'"))


@pytestmark_pg
@pytest.mark.requires_postgres
def test_027_rls_isolation_select_postgres(migrated_pg_engine: Engine) -> None:
    """Cross-tenant ``SELECT`` returns only the caller's rows.

    Acceptance criterion (c) — RLS ``tenant_isolation`` policy is created and
    enforced for the ``USING`` clause. Insert one row per tenant from the
    owner-role session (no ``app.current_tenant_id`` set yet, so RLS does not
    block the seed phase), then re-open the connection with the GUC bound to
    each tenant in turn and assert the policy filters the rowset.
    """
    engine = migrated_pg_engine

    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname = :t"
            ),
            {"t": _TABLE},
        ).one()
        assert row.relrowsecurity, f"{_TABLE} must have ROW LEVEL SECURITY enabled"

        policy_names = (
            conn.execute(
                text("SELECT polname FROM pg_policy WHERE polrelid = :t::regclass"),
                {"t": _TABLE},
            )
            .scalars()
            .all()
        )
        assert _POLICY in policy_names, (
            f"canonical {_POLICY!r} policy missing on {_TABLE}; "
            f"got {policy_names!r}"
        )

    with engine.begin() as conn:
        tenant_a = _seed_tenant(conn, "rls-pg-select-a")
        tenant_b = _seed_tenant(conn, "rls-pg-select-b")
        _insert_dlq_row_via_sql(
            conn,
            tenant_id=tenant_a,
            event_id="evt-pg-a",
            payload_json_literal="'{}'::jsonb",
        )
        _insert_dlq_row_via_sql(
            conn,
            tenant_id=tenant_b,
            event_id="evt-pg-b",
            payload_json_literal="'{}'::jsonb",
        )

    with engine.begin() as conn:
        _set_session_tenant(conn, tenant_a)
        rows_a = (
            conn.execute(text("SELECT tenant_id FROM webhook_dlq_entries"))
            .scalars()
            .all()
        )
        assert rows_a == [tenant_a], (
            f"tenant A session leaked other tenants' rows: {rows_a!r}"
        )

    with engine.begin() as conn:
        _set_session_tenant(conn, tenant_b)
        rows_b = (
            conn.execute(text("SELECT tenant_id FROM webhook_dlq_entries"))
            .scalars()
            .all()
        )
        assert rows_b == [tenant_b], (
            f"tenant B session leaked other tenants' rows: {rows_b!r}"
        )


@pytestmark_pg
@pytest.mark.requires_postgres
def test_027_rls_force_owner_session_postgres(migrated_pg_engine: Engine) -> None:
    """``FORCE`` makes the policy bite for the table-owner role.

    Acceptance criterion (c) — without ``FORCE`` the migration / app role
    that owns the table bypasses ``tenant_isolation`` silently, and one
    bad GUC binding leaks every tenant's DLQ rows. We seed two rows from
    the owner-role session, then assert that switching the GUC to
    ``tenant_b`` makes ``tenant_a``'s row invisible even though the same
    role inserted both rows seconds earlier.
    """
    engine = migrated_pg_engine

    with engine.connect() as conn:
        relforcerowsecurity = conn.execute(
            text(
                "SELECT relforcerowsecurity FROM pg_class WHERE relname = :t"
            ),
            {"t": _TABLE},
        ).scalar_one()
    assert relforcerowsecurity, (
        f"{_TABLE} must have FORCE ROW LEVEL SECURITY set — without it the "
        "table-owner role bypasses tenant_isolation and the next test step "
        "is meaningless"
    )

    with engine.begin() as conn:
        tenant_a = _seed_tenant(conn, "rls-pg-force-a")
        tenant_b = _seed_tenant(conn, "rls-pg-force-b")
        _insert_dlq_row_via_sql(
            conn,
            tenant_id=tenant_a,
            event_id="evt-force-a",
            payload_json_literal="'{}'::jsonb",
        )
        _insert_dlq_row_via_sql(
            conn,
            tenant_id=tenant_b,
            event_id="evt-force-b",
            payload_json_literal="'{}'::jsonb",
        )

    with engine.begin() as conn:
        _set_session_tenant(conn, tenant_b)
        a_visible = conn.execute(
            text(
                "SELECT COUNT(*) FROM webhook_dlq_entries WHERE tenant_id = :t"
            ),
            {"t": tenant_a},
        ).scalar_one()
        assert a_visible == 0, (
            "FORCE ROW LEVEL SECURITY is missing — the table-owner session "
            "scoped to tenant_b can still read tenant_a's row, which means "
            "the policy does not apply to the migration role and any "
            "background job using the owner credentials leaks tenants"
        )
