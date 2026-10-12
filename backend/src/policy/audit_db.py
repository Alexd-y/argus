"""Persistent :class:`AuditSink` backed by the append-only ``audit_logs`` table.

Wave 2 (R-5.6.1). The in-memory sink loses the hash chain on process restart and
cannot serialise writers across the backend + four Celery worker processes — so
a shared, persistent sink is required for a tamper-evident audit trail.

Design
------
* **Sync engine.** The :class:`AuditSink` protocol is synchronous and audit
  writes are small and best-effort, so this uses a short-lived sync (psycopg2)
  engine rather than the async app session.
* **Cross-process serialisation.** The real fork guard is a Postgres
  transaction-scoped advisory lock keyed by tenant, held across *read latest
  hash → insert*. :func:`AuditLogger`'s per-tenant ``threading.Lock`` only
  guards one process; the advisory lock closes the gap between backend and the
  worker processes. ``append`` also re-reads the true latest hash under the lock
  and re-chains the event if a concurrent writer moved the head, so two emitters
  can never produce two rows with the same ``prev_event_hash``.
* **Row shape.** Each :class:`AuditEvent` maps onto one ``audit_logs`` row;
  the chain markers ``_event_hash`` / ``_prev_event_hash`` (the convention
  :func:`src.policy.audit.verify_audit_log_chain` already reads) plus the event
  fields live in ``details`` so :meth:`iter_events` can faithfully rebuild the
  event — any post-hoc edit flips the recomputed hash and raises
  :class:`AuditChainError`.
* **RLS.** ``audit_logs`` is tenant-scoped with FORCE RLS, so every transaction
  sets ``app.current_tenant_id`` before touching the table.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from datetime import datetime
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy import text

from src.policy.audit import (
    GENESIS_HASH,
    AuditEvent,
    AuditEventType,
    AuditLogger,
    InMemoryAuditSink,
)

_logger = logging.getLogger(__name__)


def _sync_url(database_url: str) -> str:
    """Translate an async SQLAlchemy URL into a sync (psycopg2) one."""
    return database_url.replace("+asyncpg", "").replace("postgres+psycopg", "postgresql")


class DatabaseAuditSink:
    """Append-only, hash-chained audit sink persisted in ``audit_logs``."""

    def __init__(self, engine: sa.engine.Engine) -> None:
        self._engine = engine

    @staticmethod
    def _tenant_literal(tenant_id: UUID) -> str:
        # SET LOCAL rejects bound params; tenant_id is a validated UUID.
        return str(tenant_id).replace("'", "''")

    def append(self, event: AuditEvent) -> None:
        with self._engine.begin() as conn:
            conn.execute(
                text(f"SET LOCAL app.current_tenant_id = '{self._tenant_literal(event.tenant_id)}'")
            )
            # Serialise all writers for this tenant across processes.
            conn.execute(
                text("SELECT pg_advisory_xact_lock(hashtext(:t))"), {"t": str(event.tenant_id)}
            )

            # Idempotent on duplicate event_id.
            exists = conn.execute(
                text("SELECT 1 FROM audit_logs WHERE id = :id"), {"id": str(event.event_id)}
            ).first()
            if exists:
                return

            actual_prev = self._latest_hash_conn(conn, event.tenant_id)
            if actual_prev != event.prev_event_hash:
                # A concurrent writer moved the head — re-chain onto the real tip.
                event = AuditEvent(
                    event_id=event.event_id,
                    event_type=event.event_type,
                    occurred_at=event.occurred_at,
                    tenant_id=event.tenant_id,
                    scan_id=event.scan_id,
                    actor_id=event.actor_id,
                    decision_allowed=event.decision_allowed,
                    failure_summary=event.failure_summary,
                    prev_event_hash=actual_prev,
                    event_hash="",
                    payload=event.payload,
                )

            details = {
                "_event_hash": event.event_hash,
                "_prev_event_hash": event.prev_event_hash,
                "event_type": event.event_type.value,
                "occurred_at": event.occurred_at.isoformat(),
                "scan_id": str(event.scan_id) if event.scan_id is not None else None,
                "actor_id": str(event.actor_id) if event.actor_id is not None else None,
                "decision_allowed": bool(event.decision_allowed),
                "failure_summary": event.failure_summary,
                "payload": event.payload,
            }
            conn.execute(
                text(
                    "INSERT INTO audit_logs (id, tenant_id, user_id, action, details, created_at) "
                    "VALUES (:id, :tenant_id, :user_id, :action, CAST(:details AS JSONB), :created_at)"
                ),
                {
                    "id": str(event.event_id),
                    "tenant_id": str(event.tenant_id),
                    "user_id": str(event.actor_id) if event.actor_id is not None else None,
                    "action": event.event_type.value,
                    "details": json.dumps(details),
                    "created_at": event.occurred_at,
                },
            )

    def latest_hash(self, *, tenant_id: UUID) -> str:
        with self._engine.begin() as conn:
            conn.execute(
                text(f"SET LOCAL app.current_tenant_id = '{self._tenant_literal(tenant_id)}'")
            )
            return self._latest_hash_conn(conn, tenant_id)

    def _latest_hash_conn(self, conn: sa.engine.Connection, tenant_id: UUID) -> str:
        row = conn.execute(
            text(
                "SELECT details->>'_event_hash' AS h FROM audit_logs "
                "WHERE tenant_id = :t AND details ? '_event_hash' "
                "ORDER BY created_at DESC, id DESC LIMIT 1"
            ),
            {"t": str(tenant_id)},
        ).first()
        if row is None or row.h is None:
            return GENESIS_HASH
        return str(row.h)

    def iter_events(self, *, tenant_id: UUID) -> Iterable[AuditEvent]:
        with self._engine.begin() as conn:
            conn.execute(
                text(f"SET LOCAL app.current_tenant_id = '{self._tenant_literal(tenant_id)}'")
            )
            rows = conn.execute(
                text(
                    "SELECT id, details FROM audit_logs "
                    "WHERE tenant_id = :t AND details ? '_event_hash' "
                    "ORDER BY created_at ASC, id ASC"
                ),
                {"t": str(tenant_id)},
            ).all()
        events: list[AuditEvent] = []
        for row in rows:
            d = row.details if isinstance(row.details, dict) else json.loads(row.details)
            # Reconstruction re-validates the stored hash — a tampered row flips
            # the recomputed hash and raises AuditChainError here.
            events.append(
                AuditEvent(
                    event_id=UUID(str(row.id)),
                    event_type=AuditEventType(d["event_type"]),
                    occurred_at=datetime.fromisoformat(d["occurred_at"]),
                    tenant_id=tenant_id,
                    scan_id=UUID(d["scan_id"]) if d.get("scan_id") else None,
                    actor_id=UUID(d["actor_id"]) if d.get("actor_id") else None,
                    decision_allowed=bool(d["decision_allowed"]),
                    failure_summary=d.get("failure_summary"),
                    prev_event_hash=d["_prev_event_hash"],
                    event_hash=d["_event_hash"],
                    payload=d.get("payload") or {},
                )
            )
        return events


def build_production_audit_logger() -> AuditLogger:
    """Return an :class:`AuditLogger` on the persistent sink when a Postgres URL
    is configured, else the in-process sink (dev / SQLite / tests)."""
    from src.core.config import settings

    url = settings.database_url or ""
    if url.startswith(("postgresql://", "postgresql+", "postgres://")):
        engine = sa.create_engine(_sync_url(url), future=True, pool_pre_ping=True)
        return AuditLogger(DatabaseAuditSink(engine))
    return AuditLogger(InMemoryAuditSink())


__all__ = ["DatabaseAuditSink", "build_production_audit_logger"]
