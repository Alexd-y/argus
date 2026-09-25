"""Phase 1 — dialect-free checks for the Cairn data model and migration 066.

These run without a database. They guard three things:
  * every Cairn table is registered in ``Base.metadata`` (so Alembic autogenerate
    and RLS wiring can see them);
  * every Cairn table carries ``tenant_id`` (RLS eligibility, hard rule #2);
  * migration ``066`` chains from ``065`` and defines both ``upgrade`` and
    ``downgrade``, and its RLS table list matches the model set exactly.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import src.cairn.models as cairn_models
from src.db.models import Base

_VERSIONS_DIR = Path(__file__).resolve().parents[3] / "alembic" / "versions"

EXPECTED_TABLES: set[str] = {
    "cairn_projects",
    "cairn_facts",
    "cairn_intents",
    "cairn_intent_sources",
    "cairn_hints",
    "cairn_settings",
    "cairn_scoped_counters",
    "cairn_tenant_counters",
    "cairn_task_runs",
    "cairn_worker_backoff",
}


def test_all_cairn_tables_registered() -> None:
    registered = set(Base.metadata.tables.keys())
    missing = EXPECTED_TABLES - registered
    assert not missing, f"Cairn tables missing from metadata: {missing}"


def test_every_cairn_table_has_tenant_id() -> None:
    for name in EXPECTED_TABLES:
        table = Base.metadata.tables[name]
        assert "tenant_id" in table.columns, f"{name} is missing tenant_id (RLS rule #2)"


def test_uuid_pk_columns_are_string36() -> None:
    # Rule #3: UUID PKs are String(36), never a dialect UUID type.
    for name in (
        "cairn_projects",
        "cairn_facts",
        "cairn_intents",
        "cairn_hints",
        "cairn_task_runs",
    ):
        pk_cols = list(Base.metadata.tables[name].primary_key.columns)
        assert pk_cols, f"{name} has no primary key"
        id_col = Base.metadata.tables[name].columns["id"]
        assert id_col.type.length == 36, f"{name}.id must be String(36)"


def _load_revision_066() -> object:
    matches = list(_VERSIONS_DIR.glob("066_*.py"))
    assert matches, "revision file for 066 not found"
    spec = importlib.util.spec_from_file_location("_alembic_066", matches[0])
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def test_migration_066_chains_from_065() -> None:
    module = _load_revision_066()
    assert module.revision == "066"
    assert module.down_revision == "065"
    assert callable(getattr(module, "upgrade", None))
    assert callable(getattr(module, "downgrade", None))


def test_migration_066_rls_covers_every_table() -> None:
    module = _load_revision_066()
    rls_tables = set(module._RLS_TABLES)
    assert (
        rls_tables == EXPECTED_TABLES
    ), "migration 066 RLS table list must match the model set exactly"
    # Drop order must be the reverse-dependency permutation of the same set.
    assert set(module._DROP_ORDER) == EXPECTED_TABLES


def test_closed_vocabularies_present() -> None:
    assert cairn_models.PROJECT_STATUSES == ("active", "stopped", "completed")
    assert set(cairn_models.COUNTER_KINDS) == {"fact", "intent", "hint"}
    assert set(cairn_models.BACKOFF_KINDS) == {"unhealthy", "rejected"}
