"""Wave 2 / stage 6 — persistent, tamper-evident, race-free audit chain (Postgres).

Exercises DatabaseAuditSink against a live Postgres:

* the chain survives a "process restart" (a fresh sink instance replays it);
* editing a stored row in-band (triggers bypassed) is caught as AuditChainError;
* concurrent writers (separate AuditLogger instances = separate in-process
  locks, sharing the sink) never fork the chain — the Postgres advisory lock +
  re-chain in ``append`` serialise them.

Set DATABASE_URL to a *disposable* Postgres (e.g. argus_test); never the app DB.
"""

from __future__ import annotations

import os
import threading
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from src.policy.audit import AuditChainError, AuditEventType, AuditLogger
from src.policy.audit_db import DatabaseAuditSink, _sync_url

pytestmark = pytest.mark.requires_postgres

_RAW = os.environ.get("DATABASE_URL", "")
_HAS_PG = _RAW.startswith(("postgresql://", "postgresql+", "postgres://"))
pytestmark_pg = pytest.mark.skipif(not _HAS_PG, reason="DATABASE_URL is not a Postgres URL")

_BACKEND_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module", autouse=True)
def _migrated() -> None:
    if not _HAS_PG:
        return
    cfg = Config(str(_BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", _RAW)
    command.upgrade(cfg, "head")


@pytest.fixture()
def pg_engine() -> sa.engine.Engine:
    return sa.create_engine(_sync_url(_RAW), future=True)


@pytest.fixture()
def tenant_id(pg_engine: sa.engine.Engine) -> str:
    tid = str(uuid.uuid4())
    with pg_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO tenants (id, name) VALUES (:id, :n)"),
            {"id": tid, "n": "w2-audit-test"},
        )
    yield tid
    with pg_engine.begin() as conn:
        # audit_logs is append-only (trigger blocks DELETE); bypass it for the
        # disposable test DB cleanup only.
        conn.execute(text("SET LOCAL session_replication_role = replica"))
        conn.execute(text("DELETE FROM audit_logs WHERE tenant_id = :t"), {"t": tid})
        conn.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": tid})


@pytestmark_pg
def test_chain_survives_restart(pg_engine: sa.engine.Engine, tenant_id: str) -> None:
    tid = uuid.UUID(tenant_id)
    logger = AuditLogger(DatabaseAuditSink(pg_engine))
    for i in range(3):
        logger.emit(
            event_type=AuditEventType.EVIDENCE_PERSISTED,
            tenant_id=tid,
            decision_allowed=True,
            payload={"i": i},
        )
    # A brand-new sink instance (simulating a fresh process) replays the chain.
    fresh = AuditLogger(DatabaseAuditSink(pg_engine))
    assert fresh.verify_chain(tenant_id=tid) == 3


@pytestmark_pg
def test_tamper_is_detected(pg_engine: sa.engine.Engine, tenant_id: str) -> None:
    tid = uuid.UUID(tenant_id)
    logger = AuditLogger(DatabaseAuditSink(pg_engine))
    for i in range(3):
        logger.emit(
            event_type=AuditEventType.EVIDENCE_PERSISTED,
            tenant_id=tid,
            decision_allowed=True,
            payload={"i": i},
        )
    # Edit a stored row in-band, bypassing the append-only triggers.
    with pg_engine.begin() as conn:
        conn.execute(text(f"SET LOCAL app.current_tenant_id = '{tenant_id}'"))
        conn.execute(text("SET LOCAL session_replication_role = replica"))
        conn.execute(
            text(
                "UPDATE audit_logs SET details = jsonb_set(details, '{decision_allowed}', 'false') "
                "WHERE tenant_id = :t AND (details->>'decision_allowed') = 'true' "
                "AND ctid = (SELECT ctid FROM audit_logs WHERE tenant_id = :t "
                "ORDER BY created_at ASC LIMIT 1)"
            ),
            {"t": tenant_id},
        )
    with pytest.raises(AuditChainError):
        AuditLogger(DatabaseAuditSink(pg_engine)).verify_chain(tenant_id=tid)


@pytestmark_pg
def test_concurrent_writers_do_not_fork(pg_engine: sa.engine.Engine, tenant_id: str) -> None:
    tid = uuid.UUID(tenant_id)
    sink = DatabaseAuditSink(pg_engine)
    threads_n, per_thread = 4, 5
    errors: list[Exception] = []

    def worker() -> None:
        # Separate AuditLogger per thread = separate in-process lock, so the
        # only cross-writer serialisation is the DB advisory lock in append.
        local_logger = AuditLogger(sink)
        try:
            for i in range(per_thread):
                local_logger.emit(
                    event_type=AuditEventType.EVIDENCE_PERSISTED,
                    tenant_id=tid,
                    decision_allowed=True,
                    payload={"i": i},
                )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    workers = [threading.Thread(target=worker) for _ in range(threads_n)]
    for t in workers:
        t.start()
    for t in workers:
        t.join()

    assert not errors, errors
    # A forked chain would make verify_chain raise; a clean linear chain of all
    # events proves the advisory lock + re-chain serialised the writers.
    verified = AuditLogger(sink).verify_chain(tenant_id=tid)
    assert verified == threads_n * per_thread
