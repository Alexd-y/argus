"""063 — offline chain + structure checks for severity assessments migration.

Dialect-free checks (no DB required):

* ``063`` chains onto ``062``.
* ``upgrade`` / ``downgrade`` are defined and callable.
* The four additive finding columns are targeted.
* ``_json_type`` picks ``JSONB`` on Postgres and portable ``JSON`` on SQLite.

The live upgrade/downgrade round-trip against Postgres is covered by the
``requires_postgres`` alembic smoke test; this file stays offline.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import sqlalchemy as sa

_BACKEND_ROOT = Path(__file__).resolve().parents[3]
_VERSIONS_DIR = _BACKEND_ROOT / "alembic" / "versions"


def _load_revision_module(rev: str) -> Any:
    matches = list(_VERSIONS_DIR.glob(f"{rev}_*.py"))
    assert matches, f"revision file for {rev} not found"
    spec = importlib.util.spec_from_file_location(f"_alembic_{rev}", matches[0])
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_063_chains_onto_062() -> None:
    module = _load_revision_module("063")
    assert module.revision == "063"
    assert module.down_revision == "062"


def test_063_defines_upgrade_and_downgrade() -> None:
    module = _load_revision_module("063")
    assert callable(getattr(module, "upgrade", None))
    assert callable(getattr(module, "downgrade", None))


def test_063_targets_four_finding_columns() -> None:
    module = _load_revision_module("063")
    names = {name for name, _type in module._FINDING_COLUMNS}
    assert names == {"record_kind", "validation", "lifecycle", "remediation_priority"}


def test_063_json_type_selects_dialect() -> None:
    module = _load_revision_module("063")

    for dialect, expected in (("postgresql", sa.dialects.postgresql.JSONB), ("sqlite", sa.JSON)):
        bind = MagicMock()
        bind.dialect.name = dialect
        with patch.object(module.op, "get_bind", return_value=bind):
            assert isinstance(module._json_type(), expected)
