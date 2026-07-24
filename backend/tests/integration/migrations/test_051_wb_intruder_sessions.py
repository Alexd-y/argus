"""051 — offline chain + structure checks for Intruder/Sessions migration.

Dialect-free checks (no DB required):

* ``051`` chains onto ``050`` and is the single Alembic head.
* ``upgrade``/``downgrade`` are defined and callable.
* The migration targets exactly the four new tables and applies RLS to all of
  them.
* ``_json_type`` picks ``JSONB`` on Postgres and portable ``JSON`` elsewhere
  (so the SQLite smoke path round-trips cleanly).

The live upgrade/downgrade round-trip against Postgres is covered by
``test_alembic_smoke`` (``requires_postgres``); this file stays offline.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import sqlalchemy as sa
from alembic.config import Config
from alembic.script import ScriptDirectory

_BACKEND_ROOT = Path(__file__).resolve().parents[3]
_VERSIONS_DIR = _BACKEND_ROOT / "alembic" / "versions"

_EXPECTED_TABLES = {
    "wb_session_macros",
    "wb_session_principals",
    "wb_intruder_attacks",
    "wb_intruder_requests",
}


def _load_revision_module(rev: str) -> Any:
    matches = list(_VERSIONS_DIR.glob(f"{rev}_*.py"))
    assert matches, f"revision file for {rev} not found"
    spec = importlib.util.spec_from_file_location(f"_alembic_{rev}", matches[0])
    assert spec and spec.loader, f"unable to load spec for {matches[0]}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _alembic_config() -> Config:
    cfg = Config(str(_BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", "sqlite+aiosqlite:///:memory:")
    return cfg


def test_051_chains_onto_050() -> None:
    module = _load_revision_module("051")
    assert module.revision == "051"
    assert module.down_revision == "050"


def test_051_defines_upgrade_and_downgrade() -> None:
    module = _load_revision_module("051")
    assert callable(getattr(module, "upgrade", None))
    assert callable(getattr(module, "downgrade", None))


def test_051_is_single_head() -> None:
    # 052 (SEC-002 FORCE RLS) now sits on top of 051; assert the chain still has a
    # single head and that 051 -> 052 is the tip edge.
    script = ScriptDirectory.from_config(_alembic_config())
    heads = script.get_heads()
    assert heads == ["052"], f"expected 052 as single head, got {heads}"
    module_052 = _load_revision_module("052")
    assert module_052.down_revision == "051"


def test_051_targets_expected_tables() -> None:
    module = _load_revision_module("051")
    targeted = {module._MACROS, module._PRINCIPALS, module._ATTACKS, module._REQUESTS}
    assert targeted == _EXPECTED_TABLES


def test_051_applies_rls_to_all_new_tables() -> None:
    module = _load_revision_module("051")
    assert set(module._RLS_TABLES) == _EXPECTED_TABLES


def test_051_json_type_selects_dialect() -> None:
    module = _load_revision_module("051")
    assert module._json_type(True) is sa.dialects.postgresql.JSONB
    assert module._json_type(False) is sa.JSON
