r"""Cycle 6 / Batch 6 / B6-T02 — ``029_tenant_pdf_archival_format`` migration tests.

Two-layer strategy mirroring ``test_028_admin_sessions_migration.py``:

A. Dialect-free checks — always run, no DB required.
   * Revision metadata pinned (``revision="029"``, ``down_revision="028"``).
   * Both ``upgrade()`` and ``downgrade()`` callables exist.
   * The ``Tenant`` ORM declares the new ``pdf_archival_format`` column with
     ``nullable=False`` and a ``CheckConstraint`` enforcing the closed
     taxonomy.

B. Postgres round-trip checks — gated by
   ``@pytest.mark.requires_postgres`` and skipped when ``DATABASE_URL`` is
   not a real Postgres URL.
   Layer B drives ``command.upgrade`` / ``command.downgrade`` and then
   validates:
     * the column exists with the expected type / nullability;
     * the ``CHECK`` constraint rejects out-of-taxonomy literals;
     * an existing row pre-dating the migration is back-filled to
       ``"standard"`` by the column default;
     * ``upgrade -> downgrade -1 -> upgrade`` is byte-stable.

How to run the Postgres half locally (PowerShell)::

    docker run --rm -d --name argus-pg-t48 -p 55432:5432 `
        -e POSTGRES_PASSWORD=argus -e POSTGRES_DB=argus_test postgres:15
    $env:DATABASE_URL = "postgresql+asyncpg://postgres:argus@localhost:55432/argus_test"
    .\.venv\Scripts\python.exe -m pytest `
        backend/tests/integration/migrations/test_029_pdf_archival_format_migration.py -v
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
from sqlalchemy.exc import IntegrityError

_BACKEND_ROOT = Path(__file__).resolve().parents[3]
_VERSIONS_DIR = _BACKEND_ROOT / "alembic" / "versions"
_REVISION = "029"
_DOWN_REVISION = "028"
_TENANTS_TABLE = "tenants"
_COLUMN_NAME = "pdf_archival_format"
_CHECK_NAME = "ck_tenants_pdf_archival_format"
_DEFAULT_VALUE = "standard"
_ALLOWED_VALUES = ("standard", "pdfa-2u")

# Gate for Layer B.
_PG_URL_RAW = os.environ.get("DATABASE_URL", "")
_HAS_POSTGRES_URL = _PG_URL_RAW.startswith(
    ("postgresql://", "postgresql+", "postgres://")
)

pytestmark_pg = pytest.mark.skipif(
    not _HAS_POSTGRES_URL,
    reason=(
        "DATABASE_URL is not a Postgres URL — pdf_archival_format schema "
        "checks need a real Postgres engine"
    ),
)


# ---------------------------------------------------------------------------
# Shared helpers.
# ---------------------------------------------------------------------------


def _load_revision_module() -> Any:
    """Import the 029 migration file as a standalone module (no chain run)."""
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


def test_029_revision_metadata_pinned() -> None:
    module = _load_revision_module()
    assert module.revision == _REVISION, (
        f"029 migration must declare revision={_REVISION!r}, "
        f"got {module.revision!r}"
    )
    assert module.down_revision == _DOWN_REVISION, (
        f"029 migration must chain off {_DOWN_REVISION!r}, "
        f"got {module.down_revision!r}"
    )
    assert module.branch_labels is None, "029 must not introduce a branch label"
    assert module.depends_on is None, "029 must not depend on another revision"


def test_029_has_upgrade_and_downgrade_callables() -> None:
    module = _load_revision_module()
    assert callable(getattr(module, "upgrade", None)), (
        "029.upgrade missing or not callable"
    )
    assert callable(getattr(module, "downgrade", None)), (
        "029.downgrade missing or not callable"
    )


def test_029_module_exports_taxonomy_constants() -> None:
    """The migration module must declare the closed taxonomy + default value."""
    module = _load_revision_module()
    assert getattr(module, "ALLOWED_VALUES", None) == _ALLOWED_VALUES, (
        "ALLOWED_VALUES drifted from the spec — keep it in lock-step with "
        "src.db.models.PDF_ARCHIVAL_FORMAT_VALUES"
    )
    assert getattr(module, "DEFAULT_VALUE", None) == _DEFAULT_VALUE, (
        f"DEFAULT_VALUE must be {_DEFAULT_VALUE!r}"
    )
    assert getattr(module, "CHECK_NAME", None) == _CHECK_NAME, (
        f"CHECK_NAME must be {_CHECK_NAME!r} (used by API audit + ORM)"
    )


def test_029_orm_tenant_has_pdf_archival_format_column() -> None:
    """``Tenant.pdf_archival_format`` must mirror the migration."""
    from src.db.models import (
        PDF_ARCHIVAL_FORMAT_DEFAULT,
        PDF_ARCHIVAL_FORMAT_VALUES,
        Tenant,
    )

    table = cast(sa.Table, Tenant.__table__)
    assert _COLUMN_NAME in table.columns, (
        f"Tenant ORM missing {_COLUMN_NAME!r} column"
    )
    column = table.columns[_COLUMN_NAME]
    assert column.nullable is False, (
        f"{_COLUMN_NAME} must be NOT NULL"
    )
    assert column.server_default is not None, (
        f"{_COLUMN_NAME} must declare a server_default for back-fill safety"
    )
    server_default_arg = getattr(column.server_default, "arg", None)
    server_default_str = (
        str(server_default_arg)
        if server_default_arg is not None
        else str(column.server_default)
    )
    assert PDF_ARCHIVAL_FORMAT_DEFAULT in server_default_str, (
        f"{_COLUMN_NAME}.server_default must literal-match "
        f"PDF_ARCHIVAL_FORMAT_DEFAULT={PDF_ARCHIVAL_FORMAT_DEFAULT!r}"
    )
    assert PDF_ARCHIVAL_FORMAT_VALUES == _ALLOWED_VALUES, (
        "models.PDF_ARCHIVAL_FORMAT_VALUES drifted from the migration "
        "ALLOWED_VALUES — keep both in lock-step"
    )


def test_029_orm_tenant_check_constraint_present() -> None:
    """``Tenant`` must declare a CHECK constraint mirroring the closed taxonomy."""
    from src.db.models import Tenant

    table = cast(sa.Table, Tenant.__table__)
    check_constraints = [
        c
        for c in table.constraints
        if isinstance(c, sa.CheckConstraint) and c.name == _CHECK_NAME
    ]
    assert check_constraints, (
        f"Tenant ORM missing CHECK constraint {_CHECK_NAME!r}"
    )
    sql = str(check_constraints[0].sqltext)
    for value in _ALLOWED_VALUES:
        assert value in sql, (
            f"CHECK constraint {_CHECK_NAME!r} must enforce {value!r} "
            f"(got: {sql!r})"
        )


def test_029_orm_validates_rejects_unknown_format() -> None:
    """SQLAlchemy ``@validates`` must raise on out-of-taxonomy assignment."""
    from src.db.models import Tenant

    tenant = Tenant(name="probe")
    with pytest.raises(ValueError):
        tenant.pdf_archival_format = "pdfa-3u"  # type: ignore[assignment]


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
def test_029_upgrade_adds_column_with_default(migrated_engine: Engine) -> None:
    insp = inspect(migrated_engine)
    columns = {c["name"]: c for c in insp.get_columns(_TENANTS_TABLE)}
    assert _COLUMN_NAME in columns, (
        f"{_TENANTS_TABLE} should expose {_COLUMN_NAME} after upgrade head"
    )
    column = columns[_COLUMN_NAME]
    assert column["nullable"] is False, (
        f"{_COLUMN_NAME} must be NOT NULL after upgrade head"
    )
    server_default = column.get("default")
    assert server_default is not None and "standard" in str(server_default), (
        f"{_COLUMN_NAME} must default to 'standard' "
        f"(got server_default={server_default!r})"
    )


@pytestmark_pg
@pytest.mark.requires_postgres
def test_029_check_constraint_rejects_unknown_value(migrated_engine: Engine) -> None:
    """The CHECK constraint must reject literals outside the taxonomy."""
    with migrated_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO tenants (id, name, pdf_archival_format) "
                "VALUES (:id, :name, :fmt)"
            ),
            {
                "id": "00000000-0000-4000-8000-000000000001",
                "name": "probe-valid",
                "fmt": "pdfa-2u",
            },
        )

    with migrated_engine.begin() as conn, pytest.raises(IntegrityError):
        conn.execute(
            text(
                "INSERT INTO tenants (id, name, pdf_archival_format) "
                "VALUES (:id, :name, :fmt)"
            ),
            {
                "id": "00000000-0000-4000-8000-000000000002",
                "name": "probe-invalid",
                "fmt": "pdfa-3u",  # not in the closed taxonomy
            },
        )


@pytestmark_pg
@pytest.mark.requires_postgres
def test_029_existing_rows_backfilled_to_standard(pg_url: str) -> None:
    """Pre-existing tenant rows must get the default ``"standard"`` value."""
    cfg = _alembic_config(pg_url)
    command.downgrade(cfg, _DOWN_REVISION)

    sync_url = _to_sync_url(pg_url)
    engine = sa.create_engine(sync_url, future=True)
    try:
        # Seed a tenant row at revision 028 (no pdf_archival_format column yet).
        with engine.begin() as conn:
            conn.execute(
                text("INSERT INTO tenants (id, name) VALUES (:id, :name)"),
                {
                    "id": "00000000-0000-4000-8000-000000000003",
                    "name": "legacy-tenant",
                },
            )

        command.upgrade(cfg, _REVISION)

        engine.dispose()
        engine = sa.create_engine(sync_url, future=True)
        with engine.connect() as conn:
            value = conn.execute(
                text(
                    "SELECT pdf_archival_format FROM tenants "
                    "WHERE id = :id"
                ),
                {"id": "00000000-0000-4000-8000-000000000003"},
            ).scalar_one()
        assert value == _DEFAULT_VALUE, (
            f"Legacy tenant row must be back-filled to {_DEFAULT_VALUE!r}, "
            f"got {value!r}"
        )
    finally:
        engine.dispose()
        command.downgrade(cfg, "base")


@pytestmark_pg
@pytest.mark.requires_postgres
def test_029_downgrade_drops_column_idempotently(pg_url: str) -> None:
    """``upgrade -> downgrade -1 -> upgrade -> downgrade base`` all succeed."""
    cfg = _alembic_config(pg_url)
    command.upgrade(cfg, "head")

    sync_url = _to_sync_url(pg_url)
    engine = sa.create_engine(sync_url, future=True)
    try:
        insp = inspect(engine)
        columns = {c["name"] for c in insp.get_columns(_TENANTS_TABLE)}
        assert _COLUMN_NAME in columns

        command.downgrade(cfg, "-1")
        engine.dispose()
        engine = sa.create_engine(sync_url, future=True)
        insp = inspect(engine)
        columns = {c["name"] for c in insp.get_columns(_TENANTS_TABLE)}
        assert _COLUMN_NAME not in columns, (
            f"downgrade -1 from {_REVISION} must drop {_COLUMN_NAME}"
        )

        command.upgrade(cfg, "head")
        engine.dispose()
        engine = sa.create_engine(sync_url, future=True)
        insp = inspect(engine)
        columns = {c["name"] for c in insp.get_columns(_TENANTS_TABLE)}
        assert _COLUMN_NAME in columns
    finally:
        engine.dispose()
        command.downgrade(cfg, "base")
