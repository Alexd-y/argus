"""069 — scans.error_message: revision chain + SQLite schema smoke.

Layer A only (in-memory SQLite), mirrors ``test_059_scan_profile_migration.py``.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine
from src.db.models import Scan

_BACKEND_ROOT = Path(__file__).resolve().parents[2]
_VERSIONS_DIR = _BACKEND_ROOT / "alembic" / "versions"
_REVISION = "069"
_DOWN_REVISION = "068"
_REVISION_FILE = _VERSIONS_DIR / "069_scan_error_message.py"

_NEW_COLUMN = "error_message"


def _load_revision_module() -> Any:
    assert _REVISION_FILE.is_file(), f"revision file not found: {_REVISION_FILE}"
    spec = importlib.util.spec_from_file_location(f"_alembic_{_REVISION}", _REVISION_FILE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _make_sqlite_engine() -> Engine:
    engine = sa.create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=sa.pool.StaticPool,
    )
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE tenants (id VARCHAR(36) PRIMARY KEY, name VARCHAR(255))"))
        conn.execute(
            text(
                "CREATE TABLE scans ("
                "id VARCHAR(36) PRIMARY KEY, "
                "tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id), "
                "status VARCHAR(50)"
                ")"
            )
        )
    return engine


def _apply_upgrade(engine: Engine) -> None:
    module = _load_revision_module()
    with engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            module.upgrade()


def _apply_downgrade(engine: Engine) -> None:
    module = _load_revision_module()
    with engine.begin() as conn:
        ctx = MigrationContext.configure(conn)
        with Operations.context(ctx):
            module.downgrade()


def test_069_revision_chains_off_068() -> None:
    module = _load_revision_module()
    assert module.revision == _REVISION
    assert module.down_revision == _DOWN_REVISION


def test_069_upgrade_adds_nullable_error_message_sqlite() -> None:
    engine = _make_sqlite_engine()
    try:
        _apply_upgrade(engine)
        insp = inspect(engine)
        cols = {c["name"]: c for c in insp.get_columns("scans")}
        assert _NEW_COLUMN in cols, "scans.error_message missing after upgrade"
        assert cols[_NEW_COLUMN]["nullable"] is True, "error_message must be nullable (additive)"
    finally:
        engine.dispose()


def test_069_upgrade_is_idempotent_sqlite() -> None:
    engine = _make_sqlite_engine()
    try:
        _apply_upgrade(engine)
        # Guarded upgrade must be a no-op the second time (no duplicate-column error).
        _apply_upgrade(engine)
        insp = inspect(engine)
        cols = {c["name"] for c in insp.get_columns("scans")}
        assert _NEW_COLUMN in cols
    finally:
        engine.dispose()


def test_069_round_trip_upgrade_downgrade_sqlite() -> None:
    engine = _make_sqlite_engine()
    try:
        _apply_upgrade(engine)
        _apply_downgrade(engine)
        insp = inspect(engine)
        cols = {c["name"] for c in insp.get_columns("scans")}
        assert _NEW_COLUMN not in cols, "downgrade() left error_message behind"
    finally:
        engine.dispose()


def test_orm_model_has_error_message_column() -> None:
    scan_cols = set(Scan.__table__.c.keys())
    assert _NEW_COLUMN in scan_cols
    assert Scan.__table__.c[_NEW_COLUMN].nullable is True
