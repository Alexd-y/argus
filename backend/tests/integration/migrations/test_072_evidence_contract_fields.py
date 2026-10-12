"""072 — offline chain + SQLite round-trip for the evidence-contract fields.

Dialect-free checks (no live Postgres required):

* ``072`` chains onto ``071``.
* ``upgrade`` / ``downgrade`` are defined and callable.
* ``_COLUMNS`` targets exactly the fourteen R-7.1 fields.
* A real upgrade -> (idempotent re-upgrade) -> downgrade round-trip against an
  in-memory SQLite ``evidence`` table adds every column nullable and then drops
  them cleanly, restoring the original shape.

The Postgres round-trip is covered by the ``requires_postgres`` alembic smoke
test; this file stays offline.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

_BACKEND_ROOT = Path(__file__).resolve().parents[3]
_VERSIONS_DIR = _BACKEND_ROOT / "alembic" / "versions"

_EXPECTED_COLUMNS = {
    "kind",
    "checksum_algorithm",
    "checksum_value",
    "size_bytes",
    "tool_run_id",
    "tool_name",
    "tool_version",
    "started_at",
    "finished_at",
    "is_negative_control",
    "paired_evidence_id",
    "repro_attempt",
    "redaction_applied",
    "ledger_state",
}

_BASE_COLUMNS = {"id", "tenant_id", "scan_id", "finding_id", "object_key"}


def _load_revision_module(rev: str) -> Any:
    matches = list(_VERSIONS_DIR.glob(f"{rev}_*.py"))
    assert matches, f"revision file for {rev} not found"
    spec = importlib.util.spec_from_file_location(f"_alembic_{rev}", matches[0])
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_072_chains_onto_071() -> None:
    module = _load_revision_module("072")
    assert module.revision == "072"
    assert module.down_revision == "071"


def test_072_defines_upgrade_and_downgrade() -> None:
    module = _load_revision_module("072")
    assert callable(getattr(module, "upgrade", None))
    assert callable(getattr(module, "downgrade", None))


def test_072_targets_the_fourteen_contract_columns() -> None:
    module = _load_revision_module("072")
    names = {name for name, _type in module._COLUMNS}
    assert names == _EXPECTED_COLUMNS


def test_072_sqlite_roundtrip_adds_then_drops_all_columns() -> None:
    module = _load_revision_module("072")
    engine = sa.create_engine("sqlite://")
    try:
        with engine.begin() as conn:
            conn.execute(
                sa.text(
                    "CREATE TABLE evidence ("
                    "id TEXT PRIMARY KEY, tenant_id TEXT, scan_id TEXT, "
                    "finding_id TEXT, object_key TEXT)"
                )
            )
            ops = Operations(MigrationContext.configure(conn))
            module.op = ops  # bind the migration's `op` proxy to this connection

            module.upgrade()
            cols = {c["name"] for c in sa.inspect(conn).get_columns("evidence")}
            assert cols >= _EXPECTED_COLUMNS
            # Every new column is nullable (additive, existing rows stay valid).
            by_name = {c["name"]: c for c in sa.inspect(conn).get_columns("evidence")}
            assert all(by_name[name]["nullable"] for name in _EXPECTED_COLUMNS)

            module.upgrade()  # idempotent: guards make a second run a no-op

            module.downgrade()
            after = {c["name"] for c in sa.inspect(conn).get_columns("evidence")}
            assert after == _BASE_COLUMNS
    finally:
        engine.dispose()
