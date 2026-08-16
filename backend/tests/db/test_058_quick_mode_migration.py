"""QUICK-001 — Alembic 058 Quick mode revision chain + SQLite schema smoke.

Layer A only (in-memory SQLite). No live Postgres URL literals — the
auto-marker classifier in ``tests/conftest.py`` would otherwise skip this
module in the default ``pytest -q`` run. Follows the dialect-portable
pattern from ``test_webhook_dlq_migration.py``.
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
from src.quick.models import (
    QuickBudgetLeaseRow,
    QuickScanConfigRow,
    QuickScanPlanRow,
    QuickTaskRow,
)

_BACKEND_ROOT = Path(__file__).resolve().parents[2]
_VERSIONS_DIR = _BACKEND_ROOT / "alembic" / "versions"
_REVISION = "058"
_DOWN_REVISION = "057"
_REVISION_FILE = _VERSIONS_DIR / "058_quick_mode.py"

_QUICK_TABLES: tuple[str, ...] = (
    "quick_scan_configs",
    "quick_scan_plans",
    "quick_tasks",
    "quick_budget_leases",
)

_SCAN_COLUMNS: tuple[str, ...] = ("execution_mode", "deadline_at", "quick_profile")

_EXPECTED_INDEXES: dict[str, frozenset[str]] = {
    "scans": frozenset({"ix_scans_tenant_execution_mode"}),
    "quick_scan_configs": frozenset(
        {"ix_quick_scan_configs_tenant_scan", "ix_quick_scan_configs_deadline"}
    ),
    "quick_scan_plans": frozenset({"ix_quick_scan_plans_tenant_scan"}),
    "quick_tasks": frozenset(
        {"ix_quick_tasks_tenant_scan", "ix_quick_tasks_plan_status"}
    ),
    "quick_budget_leases": frozenset(
        {
            "ix_quick_budget_leases_tenant_scan",
            "ix_quick_budget_leases_status_expires",
        }
    ),
}


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
        conn.execute(
            text(
                "CREATE TABLE tenants ("
                "id VARCHAR(36) PRIMARY KEY, "
                "name VARCHAR(255) NOT NULL"
                ")"
            )
        )
        conn.execute(
            text(
                "CREATE TABLE scans ("
                "id VARCHAR(36) PRIMARY KEY, "
                "tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id)"
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


def test_058_revision_chains_off_057() -> None:
    module = _load_revision_module()
    assert module.revision == _REVISION
    assert module.down_revision == _DOWN_REVISION
    assert callable(module.upgrade)
    assert callable(module.downgrade)


def test_058_upgrade_creates_quick_tables_and_scan_columns_sqlite() -> None:
    engine = _make_sqlite_engine()
    try:
        _apply_upgrade(engine)
        insp = inspect(engine)
        for table in _QUICK_TABLES:
            assert insp.has_table(table), f"upgrade() must create {table!r}"

        scan_cols = {c["name"] for c in insp.get_columns("scans")}
        missing = set(_SCAN_COLUMNS) - scan_cols
        assert not missing, f"scans missing columns after upgrade: {sorted(missing)}"

        execution_mode = next(
            c for c in insp.get_columns("scans") if c["name"] == "execution_mode"
        )
        assert execution_mode["nullable"] is False

        for table, expected in _EXPECTED_INDEXES.items():
            present = {
                ix["name"] for ix in insp.get_indexes(table) if ix["name"] is not None
            }
            absent = expected - present
            assert not absent, f"{table} missing indexes: {sorted(absent)}"
    finally:
        engine.dispose()


def test_058_round_trip_upgrade_downgrade_sqlite() -> None:
    engine = _make_sqlite_engine()
    try:
        _apply_upgrade(engine)
        _apply_downgrade(engine)
        insp = inspect(engine)
        for table in _QUICK_TABLES:
            assert not insp.has_table(table), f"downgrade() must drop {table!r}"

        scan_cols = {c["name"] for c in insp.get_columns("scans")}
        leftover = set(_SCAN_COLUMNS) & scan_cols
        assert not leftover, f"downgrade() left scan columns: {sorted(leftover)}"

        _apply_upgrade(engine)
        second = inspect(engine)
        for table in _QUICK_TABLES:
            assert second.has_table(table)
        scan_cols_again = {c["name"] for c in second.get_columns("scans")}
        assert set(_SCAN_COLUMNS) <= scan_cols_again
    finally:
        engine.dispose()


def test_orm_models_match_058_table_names() -> None:
    assert QuickScanConfigRow.__tablename__ == "quick_scan_configs"
    assert QuickScanPlanRow.__tablename__ == "quick_scan_plans"
    assert QuickTaskRow.__tablename__ == "quick_tasks"
    assert QuickBudgetLeaseRow.__tablename__ == "quick_budget_leases"
    scan_cols = set(Scan.__table__.c.keys())
    assert {"execution_mode", "deadline_at", "quick_profile"} <= scan_cols
    assert Scan.__table__.c["execution_mode"].nullable is False
