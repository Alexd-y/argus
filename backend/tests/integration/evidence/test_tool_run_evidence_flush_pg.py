"""Wave 2 / stage 3 — flush_tool_runs writes finding-less evidence rows (Postgres).

Exercises the real DB path on a live Postgres: a buffered tool run + its raw
RAW_OUTPUT evidence are flushed through ``flush_tool_runs`` and land in the
``evidence`` table with a non-empty checksum, a NULL ``finding_id``, and a
``tool_run_id`` linking the producing run (R-5.3.1 / R-5.3.2 / criterion 4).

Runs only against a real Postgres URL (``DATABASE_URL``); SQLite has no RLS and
cannot exercise the finding-less insert under tenant isolation. Set e.g.
``DATABASE_URL=postgresql+asyncpg://argus:change-me@127.0.0.1:15432/argus_test``.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from src.db.session import set_session_tenant
from src.tools import executor

pytestmark = pytest.mark.requires_postgres

_RAW = os.environ.get("DATABASE_URL", "")
_HAS_PG = _RAW.startswith(("postgresql://", "postgresql+", "postgres://"))
pytestmark_pg = pytest.mark.skipif(not _HAS_PG, reason="DATABASE_URL is not a Postgres URL")

_BACKEND_ROOT = Path(__file__).resolve().parents[3]


def _async_url(url: str) -> str:
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url


def _sync_url(url: str) -> str:
    for prefix in ("postgresql+asyncpg://", "postgres+asyncpg://"):
        if url.startswith(prefix):
            return "postgresql://" + url[len(prefix) :]
    return url


@pytest.fixture(scope="module", autouse=True)
def _migrated() -> None:
    if not _HAS_PG:
        return
    cfg = Config(str(_BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", _async_url(_RAW))
    command.upgrade(cfg, "head")  # idempotent; no downgrade (DB is disposable)


@pytestmark_pg
async def test_flush_writes_tool_run_evidence_with_checksum() -> None:
    async_url = _async_url(_RAW)
    tenant_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())
    tool_run_id = uuid.uuid4()
    now = datetime.now(tz=UTC)

    # Seed the tenant via a short-lived sync engine (tenants has no RLS).
    sync_engine = sa.create_engine(_sync_url(_RAW), future=True)
    try:
        with sync_engine.begin() as conn:
            conn.execute(
                text("INSERT INTO tenants (id, name) VALUES (:id, :name)"),
                {"id": tenant_id, "name": "w2-evidence-test"},
            )
    finally:
        sync_engine.dispose()

    engine = create_async_engine(async_url, future=True)
    try:
        maker = async_sessionmaker(engine, expire_on_commit=False)
        async with maker() as session:
            await set_session_tenant(session, tenant_id)
            await session.execute(
                text(
                    "INSERT INTO scans (id, tenant_id, target_url) "
                    "VALUES (:id, :t, :u)"
                ),
                {"id": scan_id, "t": tenant_id, "u": "http://target.example"},
            )

            # Buffer a tool run (with a pre-assigned id) + its raw-output evidence.
            executor._schedule_tool_run_record(
                tenant_id,
                scan_id,
                "nmap",
                {"success": True, "stdout": "scan report", "stderr": ""},
                now,
                now,
                "nmap -sV x",
                tool_run_id=tool_run_id,
                evidence_saved=True,
                output_object_key=f"{tenant_id}/{scan_id}/evidence/raw_output-abc.bin",
            )
            with executor._PENDING_EVIDENCE_LOCK:
                executor._PENDING_EVIDENCE.setdefault(scan_id, []).append(
                    {
                        "id": str(uuid.uuid4()),
                        "tenant_id": tenant_id,
                        "scan_id": scan_id,
                        "finding_id": None,
                        "tool_run_id": str(tool_run_id),
                        "object_key": f"{tenant_id}/{scan_id}/evidence/raw_output-abc.bin",
                        "kind": "raw_output",
                        "checksum_algorithm": "sha256",
                        "checksum_value": "a" * 64,
                        "size_bytes": 11,
                        "content_type": "text/plain",
                        "tool_name": "nmap",
                        "started_at": now,
                        "finished_at": now,
                        "redaction_applied": False,
                        "description": "stdout of nmap",
                    }
                )

            flushed = await executor.flush_tool_runs(session, tenant_id, scan_id)
            assert flushed == 1
            await session.flush()

            rows = (
                await session.execute(
                    text(
                        "SELECT finding_id, tool_run_id, checksum_value, kind "
                        "FROM evidence WHERE scan_id = :s"
                    ),
                    {"s": scan_id},
                )
            ).all()
            assert len(rows) == 1
            finding_id, tr_id, checksum, kind = rows[0]
            assert finding_id is None  # finding-less tool-run evidence
            assert str(tr_id) == str(tool_run_id)
            assert checksum == "a" * 64 and len(checksum) == 64
            assert kind == "raw_output"

            # Don't persist test rows in the shared disposable DB.
            await session.rollback()
    finally:
        # Drop buffers + the seeded tenant (rollback already undid scan/evidence).
        executor.drain_pending_tool_runs(scan_id)
        executor.drain_pending_evidence(scan_id)
        cleanup = sa.create_engine(_sync_url(_RAW), future=True)
        try:
            with cleanup.begin() as conn:
                conn.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        finally:
            cleanup.dispose()
        await engine.dispose()
