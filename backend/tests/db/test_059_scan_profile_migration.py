"""059 — scan_profile resolver columns: revision chain + SQLite schema smoke.

Layer A only (in-memory SQLite), mirrors ``test_058_quick_mode_migration.py``.
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
_REVISION = "059"
_DOWN_REVISION = "058"
_REVISION_FILE = _VERSIONS_DIR / "059_scan_profile_resolver.py"

_NEW_COLUMNS: tuple[str, ...] = (
    "scan_profile",
    "resolved_scan_mode",
    "nuclei_profile",
    "engagement_id",
    "lab_lease_id",
    "profile_version",
    "report_snapshot_version",
)


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
                "scan_mode VARCHAR(20), "
                "execution_mode VARCHAR(32)"
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


def test_059_revision_chains_off_058() -> None:
    module = _load_revision_module()
    assert module.revision == _REVISION
    assert module.down_revision == _DOWN_REVISION


def test_059_upgrade_adds_scan_profile_columns_sqlite() -> None:
    engine = _make_sqlite_engine()
    try:
        _apply_upgrade(engine)
        insp = inspect(engine)
        scan_cols = {c["name"] for c in insp.get_columns("scans")}
        missing = set(_NEW_COLUMNS) - scan_cols
        assert not missing, f"scans missing columns after upgrade: {sorted(missing)}"
        for col in insp.get_columns("scans"):
            if col["name"] in _NEW_COLUMNS:
                assert col["nullable"] is True, f"{col['name']} must be nullable (additive)"
        indexes = {ix["name"] for ix in insp.get_indexes("scans") if ix["name"]}
        assert "ix_scans_tenant_scan_profile" in indexes
    finally:
        engine.dispose()


def test_059_round_trip_upgrade_downgrade_sqlite() -> None:
    engine = _make_sqlite_engine()
    try:
        _apply_upgrade(engine)
        _apply_downgrade(engine)
        insp = inspect(engine)
        scan_cols = {c["name"] for c in insp.get_columns("scans")}
        leftover = set(_NEW_COLUMNS) & scan_cols
        assert not leftover, f"downgrade() left columns: {sorted(leftover)}"
    finally:
        engine.dispose()


def test_orm_model_has_scan_profile_columns() -> None:
    scan_cols = set(Scan.__table__.c.keys())
    assert set(_NEW_COLUMNS) <= scan_cols
    for col in _NEW_COLUMNS:
        assert Scan.__table__.c[col].nullable is True
