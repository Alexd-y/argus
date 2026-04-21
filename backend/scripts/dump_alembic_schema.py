"""Dump the live Postgres / SQLite schema as a deterministic byte stream.

Used by:

* ``infra/scripts/migrate_smoke.sh`` and its PowerShell sibling.
* ``backend/tests/integration/migrations/test_alembic_smoke.py``.

The output is a sorted, schema-only canonicalised representation of every
table that Alembic touches — the exact shape doesn't matter, only that it
is **byte-identical** between two ``alembic upgrade head`` rounds. A diff
of zero proves the migration chain is round-trip safe.

Why a custom dumper instead of ``pg_dump``?

* Works against SQLite (used by the unit suite) AND Postgres (used by CI
  Postgres service container) without depending on dialect-specific
  binaries.
* Strips noise (comments, default sequence names, reproducible-only
  fields) so the diff doesn't false-trigger on irrelevant churn.
* Renders RLS policies and row-security state — the regular SQLAlchemy
  ``MetaData`` reflection does NOT capture these by default.

Usage:
    DATABASE_URL=... python -m scripts.dump_alembic_schema
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from sqlalchemy import MetaData, create_engine, inspect, text
from sqlalchemy.engine import Engine

DEFAULT_URL = "sqlite:///:memory:"


_ASYNC_TO_SYNC_DRIVERS = {
    "postgresql+asyncpg": "postgresql+psycopg2",
    "postgresql+aiopg": "postgresql+psycopg2",
    "sqlite+aiosqlite": "sqlite",
    "mysql+aiomysql": "mysql+pymysql",
    "mysql+asyncmy": "mysql+pymysql",
}


def _to_sync_url(url: str) -> str:
    """Coerce an async SQLAlchemy URL into its sync equivalent.

    The dumper uses the sync ``create_engine`` (Inspector + reflection on
    SQLAlchemy 2.x is sync-only), so we transparently translate any async
    driver prefix to the matching sync DBAPI before connecting. This lets
    callers pass the same ``DATABASE_URL`` they use for Alembic without
    having to maintain two separate env vars.
    """
    for async_prefix, sync_prefix in _ASYNC_TO_SYNC_DRIVERS.items():
        if url.startswith(async_prefix):
            return sync_prefix + url[len(async_prefix):]
    return url


def _connect() -> Engine:
    url = _to_sync_url(os.environ.get("DATABASE_URL", DEFAULT_URL))
    return create_engine(url, future=True)


def _serialise_table(inspector: Any, name: str) -> dict[str, Any]:
    columns = []
    for col in inspector.get_columns(name):
        columns.append(
            {
                "name": col["name"],
                "type": str(col["type"]),
                "nullable": bool(col.get("nullable", True)),
                "default": str(col.get("default")) if col.get("default") is not None else None,
            }
        )

    pks = inspector.get_pk_constraint(name).get("constrained_columns") or []
    fks = []
    for fk in inspector.get_foreign_keys(name):
        fks.append(
            {
                "name": fk.get("name"),
                "constrained_columns": fk.get("constrained_columns") or [],
                "referred_table": fk.get("referred_table"),
                "referred_columns": fk.get("referred_columns") or [],
                "options": {
                    k: v
                    for k, v in (fk.get("options") or {}).items()
                    if k in {"ondelete", "onupdate"}
                },
            }
        )

    indexes = []
    for ix in inspector.get_indexes(name):
        indexes.append(
            {
                "name": ix.get("name"),
                "column_names": ix.get("column_names") or [],
                "unique": bool(ix.get("unique")),
            }
        )

    checks = []
    try:
        for ck in inspector.get_check_constraints(name):
            checks.append(
                {
                    "name": ck.get("name"),
                    "sqltext": ck.get("sqltext"),
                }
            )
    except NotImplementedError:
        pass

    uniques = []
    try:
        for uq in inspector.get_unique_constraints(name):
            uniques.append(
                {
                    "name": uq.get("name"),
                    "column_names": uq.get("column_names") or [],
                }
            )
    except NotImplementedError:
        pass

    return {
        "name": name,
        "columns": sorted(columns, key=lambda c: c["name"]),
        "primary_key": sorted(pks),
        "foreign_keys": sorted(fks, key=lambda f: (f.get("name") or "", tuple(f["constrained_columns"]))),
        "indexes": sorted(indexes, key=lambda i: i["name"] or ""),
        "check_constraints": sorted(checks, key=lambda c: c.get("name") or ""),
        "unique_constraints": sorted(uniques, key=lambda u: u.get("name") or ""),
    }


def _serialise_postgres_rls(engine: Engine) -> list[dict[str, Any]]:
    """Capture RLS state for every Postgres table — SQLAlchemy doesn't."""
    if engine.dialect.name != "postgresql":
        return []
    out: list[dict[str, Any]] = []
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT schemaname, tablename, rowsecurity, forcerowsecurity
                FROM pg_tables
                WHERE schemaname = 'public'
                ORDER BY tablename
                """
            )
        ).all()
        for r in rows:
            out.append(
                {
                    "table": r.tablename,
                    "rowsecurity": bool(r.rowsecurity),
                    "forcerowsecurity": bool(r.forcerowsecurity),
                }
            )
        policies = conn.execute(
            text(
                """
                SELECT schemaname, tablename, policyname, cmd, qual, with_check
                FROM pg_policies
                WHERE schemaname = 'public'
                ORDER BY tablename, policyname
                """
            )
        ).all()
        out.append(
            {
                "policies": [
                    {
                        "table": p.tablename,
                        "name": p.policyname,
                        "command": p.cmd,
                        "using": p.qual,
                        "with_check": p.with_check,
                    }
                    for p in policies
                ]
            }
        )
    return out


def main() -> int:
    engine = _connect()
    metadata = MetaData()
    metadata.reflect(bind=engine)
    inspector = inspect(engine)

    payload: dict[str, Any] = {
        "dialect": engine.dialect.name,
        "tables": [
            _serialise_table(inspector, name)
            for name in sorted(inspector.get_table_names())
            # Drop Alembic's own bookkeeping (revision differs between rounds).
            if name != "alembic_version"
        ],
        "rls": _serialise_postgres_rls(engine),
    }
    json.dump(payload, sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
