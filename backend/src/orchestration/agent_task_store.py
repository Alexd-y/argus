"""Durable agent-task store with claim/lease/fencing + outbox (§6).

Separates the logical task (durable row) from attempts (fencing token bumped on
each claim). Provides:

* atomic **claim** across workers (Postgres ``FOR UPDATE SKIP LOCKED``);
* **lease + heartbeat** with a bounded owner window;
* a **fencing token** so a stale worker whose lease expired cannot overwrite a
  newer attempt's result;
* bounded **retries** with retryable/non-retryable classification and preserved
  failure history (``attempts`` + ``last_error``);
* a **transactional outbox** — the task row and its dispatch intent are written
  in the same transaction, so "saved to DB but not sent to Celery" is
  reconcilable by a relay that reads undispatched rows.

Two backends implement ``AgentTaskStore``: ``InMemoryAgentTaskStore`` (offline
logic tests) and ``PostgresAgentTaskStore`` (production atomicity). The Celery
payload carries only the ``task_id`` + minimal metadata — never evidence or
credentials.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    insert,
    select,
    update,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.orchestration.agent_contracts import AgentTaskSpec, AgentTaskState, utcnow

task_metadata = MetaData()

agent_task = Table(
    "agent_task",
    task_metadata,
    Column("task_id", String(36), primary_key=True),
    Column("tenant_id", String(36), nullable=False),
    Column("scan_id", String(36), nullable=False),
    Column("phase", String(64), nullable=False),
    Column("agent_role", String(64), nullable=False),
    Column("idempotency_key", String(64), nullable=False, unique=True),
    Column("state", String(16), nullable=False),
    Column("attempts", Integer, nullable=False, server_default="0"),
    Column("max_attempts", Integer, nullable=False, server_default="3"),
    Column("fencing_token", BigInteger, nullable=False, server_default="0"),
    Column("worker_id", String(64), nullable=False, server_default=""),
    Column("lease_expires_at", DateTime(timezone=True), nullable=True),
    Column("payload", Text, nullable=False, server_default="{}"),
    Column("result_ref", Text, nullable=True),
    Column("last_error", Text, nullable=False, server_default=""),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

agent_task_outbox = Table(
    "agent_task_outbox",
    task_metadata,
    Column("id", String(32), primary_key=True),
    Column("task_id", String(36), nullable=False),
    Column("dispatched", Boolean, nullable=False, server_default="false"),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

_CLAIMABLE = (AgentTaskState.QUEUED.value, AgentTaskState.RETRY_WAIT.value)


@dataclass
class ClaimedTask:
    task_id: str
    tenant_id: str
    scan_id: str
    phase: str
    agent_role: str
    attempts: int
    fencing_token: int
    payload: dict


async def create_task_tables(engine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(task_metadata.create_all)


class InMemoryAgentTaskStore:
    """Process-local store for offline logic tests (lock models a transaction)."""

    def __init__(self) -> None:
        self._rows: dict[str, dict] = {}
        self._outbox: dict[str, dict] = {}
        self._by_idem: dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def enqueue(self, spec: AgentTaskSpec, payload: dict | None = None) -> str:
        async with self._lock:
            if spec.idempotency_key and spec.idempotency_key in self._by_idem:
                return self._by_idem[spec.idempotency_key]
            now = utcnow()
            self._rows[spec.task_id] = {
                "task_id": spec.task_id,
                "tenant_id": spec.tenant_id,
                "scan_id": spec.scan_id,
                "phase": spec.phase,
                "agent_role": spec.agent_role,
                "idempotency_key": spec.idempotency_key or spec.task_id,
                "state": AgentTaskState.QUEUED.value,
                "attempts": 0,
                "max_attempts": 3,
                "fencing_token": 0,
                "worker_id": "",
                "lease_expires_at": None,
                "payload": payload or {},
                "result_ref": None,
                "last_error": "",
                "created_at": now,
                "updated_at": now,
            }
            self._by_idem[spec.idempotency_key or spec.task_id] = spec.task_id
            self._outbox[uuid.uuid4().hex] = {
                "task_id": spec.task_id, "dispatched": False, "created_at": now
            }
            return spec.task_id

    async def claim(
        self, worker_id: str, phases: list[str] | None = None, lease_seconds: int = 180
    ) -> ClaimedTask | None:
        now = utcnow()
        async with self._lock:
            for row in sorted(self._rows.values(), key=lambda r: r["created_at"]):
                if row["state"] not in _CLAIMABLE:
                    continue
                if phases and row["phase"] not in phases:
                    continue
                lease = row["lease_expires_at"]
                if row["state"] == AgentTaskState.RUNNING.value and lease and lease > now:
                    continue
                row["state"] = AgentTaskState.RUNNING.value
                row["worker_id"] = worker_id
                row["fencing_token"] += 1
                row["attempts"] += 1
                row["lease_expires_at"] = now + timedelta(seconds=lease_seconds)
                row["updated_at"] = now
                return _to_claimed(row)
            return None

    async def heartbeat(
        self, task_id: str, worker_id: str, fencing_token: int, lease_seconds: int = 180
    ) -> bool:
        async with self._lock:
            row = self._rows.get(task_id)
            if (
                row is None
                or row["state"] != AgentTaskState.RUNNING.value
                or row["worker_id"] != worker_id
                or row["fencing_token"] != fencing_token
            ):
                return False
            row["lease_expires_at"] = utcnow() + timedelta(seconds=lease_seconds)
            return True

    async def complete(
        self, task_id: str, fencing_token: int, state: AgentTaskState, result_ref: str = ""
    ) -> bool:
        async with self._lock:
            row = self._rows.get(task_id)
            # Fencing: a stale worker (older token) can never overwrite.
            if row is None or row["fencing_token"] != fencing_token:
                return False
            row["state"] = state.value
            row["result_ref"] = result_ref
            row["lease_expires_at"] = None
            row["updated_at"] = utcnow()
            return True

    async def retry_or_fail(
        self, task_id: str, fencing_token: int, retryable: bool, error: str = ""
    ) -> str:
        async with self._lock:
            row = self._rows.get(task_id)
            if row is None or row["fencing_token"] != fencing_token:
                return ""
            row["last_error"] = error
            row["updated_at"] = utcnow()
            if retryable and row["attempts"] < row["max_attempts"]:
                row["state"] = AgentTaskState.RETRY_WAIT.value
                row["lease_expires_at"] = None
                self._outbox[uuid.uuid4().hex] = {
                    "task_id": task_id, "dispatched": False, "created_at": utcnow()
                }
            else:
                row["state"] = AgentTaskState.FAILED.value
            return row["state"]

    async def reclaim_expired(self) -> int:
        now = utcnow()
        count = 0
        async with self._lock:
            for row in self._rows.values():
                if (
                    row["state"] == AgentTaskState.RUNNING.value
                    and row["lease_expires_at"]
                    and row["lease_expires_at"] <= now
                ):
                    row["state"] = AgentTaskState.RETRY_WAIT.value
                    row["lease_expires_at"] = None
                    row["updated_at"] = now
                    count += 1
        return count

    async def fetch_outbox(self, limit: int = 100) -> list[tuple[str, str]]:
        async with self._lock:
            return [
                (oid, o["task_id"])
                for oid, o in self._outbox.items()
                if not o["dispatched"]
            ][:limit]

    async def mark_dispatched(self, outbox_id: str) -> None:
        async with self._lock:
            if outbox_id in self._outbox:
                self._outbox[outbox_id]["dispatched"] = True

    async def get(self, task_id: str) -> dict | None:
        async with self._lock:
            row = self._rows.get(task_id)
            return dict(row) if row else None


class PostgresAgentTaskStore:
    """Production store — atomic claim via ``FOR UPDATE SKIP LOCKED``."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sf = session_factory

    async def enqueue(self, spec: AgentTaskSpec, payload: dict | None = None) -> str:
        now = utcnow()
        async with self._sf() as session, session.begin():
            ins = pg_insert(agent_task).values(
                task_id=spec.task_id,
                tenant_id=spec.tenant_id,
                scan_id=spec.scan_id,
                phase=spec.phase,
                agent_role=spec.agent_role,
                idempotency_key=spec.idempotency_key or spec.task_id,
                state=AgentTaskState.QUEUED.value,
                attempts=0,
                max_attempts=3,
                fencing_token=0,
                payload=json.dumps(payload or {}),
                created_at=now,
                updated_at=now,
            ).on_conflict_do_nothing(index_elements=["idempotency_key"])
            await session.execute(ins)
            existing = (
                await session.execute(
                    select(agent_task.c.task_id).where(
                        agent_task.c.idempotency_key == (spec.idempotency_key or spec.task_id)
                    )
                )
            ).scalar_one()
            # Transactional outbox in the SAME transaction as the task row.
            await session.execute(
                insert(agent_task_outbox).values(
                    id=uuid.uuid4().hex, task_id=existing, dispatched=False, created_at=now
                )
            )
            return existing

    async def claim(
        self, worker_id: str, phases: list[str] | None = None, lease_seconds: int = 180
    ) -> ClaimedTask | None:
        now = utcnow()
        async with self._sf() as session, session.begin():
            q = (
                select(agent_task)
                .where(agent_task.c.state.in_(_CLAIMABLE))
                .order_by(agent_task.c.created_at)
                .limit(1)
                .with_for_update(skip_locked=True)
            )
            if phases:
                q = q.where(agent_task.c.phase.in_(phases))
            row = (await session.execute(q)).mappings().first()
            if row is None:
                return None
            new_token = row["fencing_token"] + 1
            await session.execute(
                update(agent_task)
                .where(agent_task.c.task_id == row["task_id"])
                .values(
                    state=AgentTaskState.RUNNING.value,
                    worker_id=worker_id,
                    fencing_token=new_token,
                    attempts=row["attempts"] + 1,
                    lease_expires_at=now + timedelta(seconds=lease_seconds),
                    updated_at=now,
                )
            )
            payload = json.loads(row["payload"] or "{}")
            return ClaimedTask(
                task_id=row["task_id"],
                tenant_id=row["tenant_id"],
                scan_id=row["scan_id"],
                phase=row["phase"],
                agent_role=row["agent_role"],
                attempts=row["attempts"] + 1,
                fencing_token=new_token,
                payload=payload,
            )

    async def heartbeat(
        self, task_id: str, worker_id: str, fencing_token: int, lease_seconds: int = 180
    ) -> bool:
        now = utcnow()
        async with self._sf() as session, session.begin():
            result = await session.execute(
                update(agent_task)
                .where(agent_task.c.task_id == task_id)
                .where(agent_task.c.worker_id == worker_id)
                .where(agent_task.c.fencing_token == fencing_token)
                .where(agent_task.c.state == AgentTaskState.RUNNING.value)
                .values(lease_expires_at=now + timedelta(seconds=lease_seconds))
            )
            return result.rowcount == 1

    async def complete(
        self, task_id: str, fencing_token: int, state: AgentTaskState, result_ref: str = ""
    ) -> bool:
        async with self._sf() as session, session.begin():
            result = await session.execute(
                update(agent_task)
                .where(agent_task.c.task_id == task_id)
                .where(agent_task.c.fencing_token == fencing_token)
                .values(
                    state=state.value,
                    result_ref=result_ref,
                    lease_expires_at=None,
                    updated_at=utcnow(),
                )
            )
            return result.rowcount == 1

    async def retry_or_fail(
        self, task_id: str, fencing_token: int, retryable: bool, error: str = ""
    ) -> str:
        async with self._sf() as session, session.begin():
            row = (
                await session.execute(
                    select(agent_task)
                    .where(agent_task.c.task_id == task_id)
                    .with_for_update()
                )
            ).mappings().first()
            if row is None or row["fencing_token"] != fencing_token:
                return ""
            if retryable and row["attempts"] < row["max_attempts"]:
                new_state = AgentTaskState.RETRY_WAIT.value
                await session.execute(
                    insert(agent_task_outbox).values(
                        id=uuid.uuid4().hex, task_id=task_id, dispatched=False,
                        created_at=utcnow(),
                    )
                )
            else:
                new_state = AgentTaskState.FAILED.value
            await session.execute(
                update(agent_task)
                .where(agent_task.c.task_id == task_id)
                .values(
                    state=new_state, last_error=error, lease_expires_at=None,
                    updated_at=utcnow(),
                )
            )
            return new_state

    async def reclaim_expired(self) -> int:
        now = utcnow()
        async with self._sf() as session, session.begin():
            result = await session.execute(
                update(agent_task)
                .where(agent_task.c.state == AgentTaskState.RUNNING.value)
                .where(agent_task.c.lease_expires_at.is_not(None))
                .where(agent_task.c.lease_expires_at < now)
                .values(
                    state=AgentTaskState.RETRY_WAIT.value,
                    lease_expires_at=None,
                    updated_at=now,
                )
            )
            return result.rowcount

    async def fetch_outbox(self, limit: int = 100) -> list[tuple[str, str]]:
        async with self._sf() as session, session.begin():
            rows = (
                await session.execute(
                    select(agent_task_outbox.c.id, agent_task_outbox.c.task_id)
                    .where(agent_task_outbox.c.dispatched.is_(False))
                    .order_by(agent_task_outbox.c.created_at)
                    .limit(limit)
                )
            ).all()
            return [(r[0], r[1]) for r in rows]

    async def mark_dispatched(self, outbox_id: str) -> None:
        async with self._sf() as session, session.begin():
            await session.execute(
                update(agent_task_outbox)
                .where(agent_task_outbox.c.id == outbox_id)
                .values(dispatched=True)
            )

    async def get(self, task_id: str) -> dict | None:
        async with self._sf() as session, session.begin():
            row = (
                await session.execute(
                    select(agent_task).where(agent_task.c.task_id == task_id)
                )
            ).mappings().first()
            return dict(row) if row else None


def _to_claimed(row: dict) -> ClaimedTask:
    return ClaimedTask(
        task_id=row["task_id"],
        tenant_id=row["tenant_id"],
        scan_id=row["scan_id"],
        phase=row["phase"],
        agent_role=row["agent_role"],
        attempts=row["attempts"],
        fencing_token=row["fencing_token"],
        payload=row["payload"] if isinstance(row["payload"], dict) else {},
    )


__all__ = [
    "ClaimedTask",
    "InMemoryAgentTaskStore",
    "PostgresAgentTaskStore",
    "agent_task",
    "agent_task_outbox",
    "create_task_tables",
    "task_metadata",
]
