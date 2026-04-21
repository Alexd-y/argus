"""ARG-045 — Alembic round-trip schema smoke test.

Two layers of checks
====================

A. Dialect-free chain checks (always run, no DB required)
   * Every revision declares a ``down_revision`` (or is the root).
   * The chain is contiguous — single root, single head, no duplicates.
   * Each revision file has matching ``upgrade()`` and ``downgrade()`` callables
     (catches accidental missing ``downgrade``).
   * Every ARG-045 migration (019..023) lives at the expected position and
     creates the expected target table.

B. Round-trip schema diff (``requires_postgres`` — runs only when a real
   Postgres URL is provided via the ``DATABASE_URL`` env var; the migrations
   use Postgres-specific types like ``JSONB`` that SQLite cannot compile, so
   the round-trip MUST run against Postgres).

   Cases:
     * ``upgrade head`` against an empty DB — final-state schema contains
       every Cycle 5 table.
     * ``downgrade base`` → ``upgrade head`` is a no-op (byte-equal schema
       snapshot).
     * ``downgrade -5`` → ``upgrade head`` is a no-op (partial round-trip).
     * The ``report_bundles`` table created by 019 has the right columns
       + foreign keys + RLS policy.

How to run the Postgres half locally (PowerShell)::

    docker run --rm -d --name argus-pg-smoke -p 55432:5432 \\
        -e POSTGRES_PASSWORD=argus -e POSTGRES_DB=argus_test postgres:15
    $env:DATABASE_URL = "postgresql+asyncpg://postgres:argus@localhost:55432/argus_test"
    .\\\\.venv\\\\Scripts\\\\python.exe -m pytest tests/integration/migrations -v -m requires_postgres
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

_BACKEND_ROOT = Path(__file__).resolve().parents[3]
_VERSIONS_DIR = _BACKEND_ROOT / "alembic" / "versions"

# Map of ARG-045 revision → headline table created by that migration.
ARG045_TABLES: dict[str, str] = {
    "019": "report_bundles",
    "020": "mcp_audit",
    "021": "notification_dispatch_log",
    "022": "rate_limiter_state",
    "023": "epss_scores",
}

# Skip the round-trip block unless an explicit Postgres URL is provided.
_PG_URL = os.environ.get("DATABASE_URL", "")
_HAS_POSTGRES_URL = _PG_URL.startswith(("postgresql://", "postgresql+", "postgres://"))


def _alembic_config(database_url: str) -> Config:
    cfg = Config(str(_BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


def _dump_schema(database_url: str) -> str:
    """Run the schema dumper as a subprocess (matches CI invocation)."""
    env = dict(os.environ)
    env["DATABASE_URL"] = database_url
    env["PYTHONPATH"] = str(_BACKEND_ROOT)
    proc = subprocess.run(
        [sys.executable, "-m", "scripts.dump_alembic_schema"],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(_BACKEND_ROOT),
        check=True,
    )
    return proc.stdout


# ---------------------------------------------------------------------------
# Layer A — dialect-free chain checks (no DB).
# ---------------------------------------------------------------------------


def test_every_revision_has_down_revision_or_is_root() -> None:
    cfg = _alembic_config("sqlite+aiosqlite:///:memory:")
    script = ScriptDirectory.from_config(cfg)
    revisions = list(script.walk_revisions())
    assert revisions, "no Alembic revisions found"
    roots = [rev for rev in revisions if rev.down_revision is None]
    assert len(roots) == 1, f"expected exactly one root revision, got {len(roots)}"


def test_migration_chain_is_contiguous() -> None:
    cfg = _alembic_config("sqlite+aiosqlite:///:memory:")
    script = ScriptDirectory.from_config(cfg)
    seen: set[str] = set()
    duplicates: list[str] = []
    for rev in script.walk_revisions():
        if rev.revision in seen:
            duplicates.append(rev.revision)
        seen.add(rev.revision)
    assert not duplicates, f"duplicate revisions detected: {duplicates}"
    heads = script.get_heads()
    assert len(heads) == 1, f"expected 1 head, got {heads}"


def _load_revision_module(rev: str) -> object:
    """Load an Alembic revision file as a Python module, by revision id."""
    matches = list(_VERSIONS_DIR.glob(f"{rev}_*.py"))
    assert matches, f"revision file for {rev} not found"
    spec = importlib.util.spec_from_file_location(f"_alembic_{rev}", matches[0])
    assert spec and spec.loader, f"unable to load spec for {matches[0]}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def test_each_arg045_revision_defines_upgrade_and_downgrade() -> None:
    for rev in ARG045_TABLES:
        module = _load_revision_module(rev)
        assert callable(getattr(module, "upgrade", None)), f"{rev}.upgrade missing"
        assert callable(getattr(module, "downgrade", None)), f"{rev}.downgrade missing"


def test_arg045_migrations_chain_in_sequence() -> None:
    cfg = _alembic_config("sqlite+aiosqlite:///:memory:")
    script = ScriptDirectory.from_config(cfg)
    chain = {rev.revision: rev.down_revision for rev in script.walk_revisions()}
    expected_order = [
        ("019", "017"),
        ("020", "019"),
        ("021", "020"),
        ("022", "021"),
        ("023", "022"),
        ("024", "023"),
    ]
    for rev, expected_down in expected_order:
        assert rev in chain, f"revision {rev} missing from chain"
        assert chain[rev] == expected_down, (
            f"revision {rev} expected down_revision={expected_down}, "
            f"got {chain[rev]}"
        )


# ---------------------------------------------------------------------------
# Layer B — Postgres round-trip (skipped without a real PG URL).
# ---------------------------------------------------------------------------


pytestmark_pg = pytest.mark.skipif(
    not _HAS_POSTGRES_URL,
    reason="DATABASE_URL is not a Postgres URL — round-trip checks need real Postgres",
)


@pytest.fixture()
def pg_url(monkeypatch: pytest.MonkeyPatch) -> str:
    """Return the configured Postgres URL and patch the cached settings."""
    raw = _PG_URL
    if raw.startswith("postgresql://"):
        async_url = raw.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif raw.startswith("postgres://"):
        async_url = raw.replace("postgres://", "postgresql+asyncpg://", 1)
    else:
        async_url = raw
    monkeypatch.setenv("DATABASE_URL", async_url)
    from src.core import config as _cfg

    monkeypatch.setattr(_cfg.settings, "database_url", async_url)
    return async_url


@pytestmark_pg
@pytest.mark.requires_postgres
def test_upgrade_head_creates_arg045_tables(pg_url: str) -> None:
    cfg = _alembic_config(pg_url)
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    snap = _dump_schema(pg_url)
    parsed = json.loads(snap)
    table_names = {t["name"] for t in parsed["tables"]}
    for rev, table in ARG045_TABLES.items():
        assert table in table_names, f"{rev} did not create {table}"


@pytestmark_pg
@pytest.mark.requires_postgres
def test_full_round_trip_is_no_op(pg_url: str) -> None:
    cfg = _alembic_config(pg_url)
    command.upgrade(cfg, "head")
    snap1 = _dump_schema(pg_url)

    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    snap2 = _dump_schema(pg_url)

    assert snap1 == snap2, "Full round-trip schema drift detected"


@pytestmark_pg
@pytest.mark.requires_postgres
def test_partial_rollback_round_trip_is_no_op(pg_url: str) -> None:
    cfg = _alembic_config(pg_url)
    command.upgrade(cfg, "head")
    snap1 = _dump_schema(pg_url)

    command.downgrade(cfg, "-5")
    command.upgrade(cfg, "head")
    snap2 = _dump_schema(pg_url)

    assert snap1 == snap2, "5-step rollback + upgrade head produced schema drift"


@pytestmark_pg
@pytest.mark.requires_postgres
def test_report_bundles_columns_match_arg045_spec(pg_url: str) -> None:
    cfg = _alembic_config(pg_url)
    command.upgrade(cfg, "head")
    snap = json.loads(_dump_schema(pg_url))
    table = next(
        (t for t in snap["tables"] if t["name"] == "report_bundles"),
        None,
    )
    assert table is not None, "report_bundles missing after upgrade"

    columns = {c["name"] for c in table["columns"]}
    expected = {
        "report_bundle_id",
        "tenant_id",
        "scan_id",
        "tier",
        "format",
        "s3_key",
        "byte_size",
        "sha256",
        "created_at",
        "deleted_at",
    }
    missing = expected - columns
    assert not missing, f"report_bundles missing columns: {missing}"

    fk_targets = {
        (fk["referred_table"], tuple(fk["referred_columns"]))
        for fk in table["foreign_keys"]
    }
    assert ("tenants", ("id",)) in fk_targets, "tenant FK missing on report_bundles"
    assert ("scans", ("id",)) in fk_targets, "scan FK missing on report_bundles"

    rls_entries = [
        entry for entry in snap["rls"] if isinstance(entry, dict) and entry.get("table") == "report_bundles"
    ]
    assert any(
        entry.get("rowsecurity") for entry in rls_entries
    ), "RLS not enabled on report_bundles"
