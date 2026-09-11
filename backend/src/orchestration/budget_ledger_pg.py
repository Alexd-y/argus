"""Postgres-backed authoritative budget store (platform-hardening A, §7).

Implements the ``BudgetStore`` protocol from :mod:`budget_ledger` with
cross-process atomicity delegated to Postgres row locks
(``SELECT … FOR UPDATE``). Idempotent settlement is guaranteed by a unique
``agent_budget_usage_event`` row keyed on ``reservation_id`` — a repeated settle
can never book usage twice, even across workers.

Schema lives in a dedicated ``MetaData`` (``budget_metadata``) so it does not
couple to the app ``Base``; the Alembic migration ``064_agent_budget`` creates
the identical tables for production (with tenant indexing).
"""

from __future__ import annotations

import json
import uuid
from datetime import timedelta

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    Float,
    MetaData,
    String,
    Table,
    insert,
    select,
    update,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from src.orchestration.agent_contracts import AgentUsage, utcnow
from src.orchestration.budget_ledger import (
    BudgetScope,
    BudgetSnapshot,
    Reservation,
    ReservationState,
)

budget_metadata = MetaData()

agent_budget_scope = Table(
    "agent_budget_scope",
    budget_metadata,
    Column("key", String(128), primary_key=True),
    Column("limit_tokens", Float, nullable=True),
    Column("limit_cost", Float, nullable=True),
    Column("reserved_tokens", BigInteger, nullable=False, server_default="0"),
    Column("reserved_cost", Float, nullable=False, server_default="0"),
    Column("used_tokens", BigInteger, nullable=False, server_default="0"),
    Column("used_cost", Float, nullable=False, server_default="0"),
)

agent_budget_reservation = Table(
    "agent_budget_reservation",
    budget_metadata,
    Column("reservation_id", String(32), primary_key=True),
    Column("scope_keys", String, nullable=False),  # JSON list
    Column("tokens", BigInteger, nullable=False, server_default="0"),
    Column("cost_usd", Float, nullable=False, server_default="0"),
    Column("state", String(16), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=True),
)

agent_budget_usage_event = Table(
    "agent_budget_usage_event",
    budget_metadata,
    # PK on reservation_id => at most one settled usage event per reservation.
    Column("reservation_id", String(32), primary_key=True),
    Column("tokens", BigInteger, nullable=False, server_default="0"),
    Column("cost_usd", Float, nullable=False, server_default="0"),
    Column("estimated", Boolean, nullable=False, server_default="false"),
    Column("created_at", DateTime(timezone=True), nullable=False),
)

_INF = float("inf")


async def create_budget_tables(engine) -> None:
    """Create the budget tables (tests / dev). Production uses Alembic."""
    async with engine.begin() as conn:
        await conn.run_sync(budget_metadata.create_all)


def _limit(value: float | None) -> float:
    return _INF if value is None else value


class PostgresBudgetStore:
    """``BudgetStore`` backed by Postgres row-level locks."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._sf = session_factory

    async def _ensure_scope_rows(self, session: AsyncSession, keys: list[str]) -> None:
        for key in keys:
            stmt = pg_insert(agent_budget_scope).values(key=key)
            stmt = stmt.on_conflict_do_nothing(index_elements=["key"])
            await session.execute(stmt)

    async def set_limits(
        self, key: str, *, max_tokens: float | None = None, max_cost_usd: float | None = None
    ) -> None:
        async with self._sf() as session, session.begin():
            values = {"key": key}
            set_ = {}
            if max_tokens is not None:
                values["limit_tokens"] = max_tokens
                set_["limit_tokens"] = max_tokens
            if max_cost_usd is not None:
                values["limit_cost"] = max_cost_usd
                set_["limit_cost"] = max_cost_usd
            stmt = pg_insert(agent_budget_scope).values(**values)
            if set_:
                stmt = stmt.on_conflict_do_update(index_elements=["key"], set_=set_)
            else:
                stmt = stmt.on_conflict_do_nothing(index_elements=["key"])
            await session.execute(stmt)

    async def try_reserve(
        self, scope: BudgetScope, tokens: int, cost_usd: float, lease_seconds: int
    ) -> Reservation | None:
        keys = scope.keys()
        if not keys:
            keys = ["global"]
        async with self._sf() as session, session.begin():
            await self._ensure_scope_rows(session, keys)
            # Lock all involved scope rows in a stable order to avoid deadlocks.
            rows = (
                await session.execute(
                    select(agent_budget_scope)
                    .where(agent_budget_scope.c.key.in_(keys))
                    .order_by(agent_budget_scope.c.key)
                    .with_for_update()
                )
            ).mappings().all()

            for row in rows:
                lim_t = _limit(row["limit_tokens"])
                if row["reserved_tokens"] + row["used_tokens"] + tokens > lim_t:
                    return None
                lim_c = _limit(row["limit_cost"])
                if row["reserved_cost"] + row["used_cost"] + cost_usd > lim_c:
                    return None

            for key in keys:
                await session.execute(
                    update(agent_budget_scope)
                    .where(agent_budget_scope.c.key == key)
                    .values(
                        reserved_tokens=agent_budget_scope.c.reserved_tokens + tokens,
                        reserved_cost=agent_budget_scope.c.reserved_cost + cost_usd,
                    )
                )

            res = Reservation(
                reservation_id=_new_id(),
                scope_keys=keys,
                tokens=tokens,
                cost_usd=cost_usd,
                expires_at=_expiry(lease_seconds),
            )
            await session.execute(
                insert(agent_budget_reservation).values(
                    reservation_id=res.reservation_id,
                    scope_keys=json.dumps(keys),
                    tokens=tokens,
                    cost_usd=cost_usd,
                    state=ReservationState.RESERVED.value,
                    created_at=res.created_at,
                    expires_at=res.expires_at,
                )
            )
            return res

    async def settle(self, reservation_id: str, usage: AgentUsage) -> bool:
        actual_tokens = max(0, usage.total_tokens)
        actual_cost = float(usage.cost_usd or 0.0)
        async with self._sf() as session, session.begin():
            res = (
                await session.execute(
                    select(agent_budget_reservation)
                    .where(agent_budget_reservation.c.reservation_id == reservation_id)
                    .with_for_update()
                )
            ).mappings().first()
            if res is None or res["state"] not in (
                ReservationState.RESERVED.value,
                ReservationState.UNCERTAIN.value,
            ):
                return False

            # Idempotent booking: unique usage-event row. If it already exists,
            # someone else already settled — do not double-charge.
            ins = pg_insert(agent_budget_usage_event).values(
                reservation_id=reservation_id,
                tokens=actual_tokens,
                cost_usd=actual_cost,
                estimated=usage.estimated,
                created_at=utcnow(),
            ).on_conflict_do_nothing(index_elements=["reservation_id"])
            result = await session.execute(ins)
            if result.rowcount == 0:
                return False

            keys = json.loads(res["scope_keys"])
            for key in keys:
                srow = (
                    await session.execute(
                        select(agent_budget_scope)
                        .where(agent_budget_scope.c.key == key)
                        .with_for_update()
                    )
                ).mappings().first()
                if srow is None:
                    continue
                new_reserved_t = max(0, srow["reserved_tokens"] - res["tokens"])
                new_reserved_c = max(0.0, srow["reserved_cost"] - res["cost_usd"])
                await session.execute(
                    update(agent_budget_scope)
                    .where(agent_budget_scope.c.key == key)
                    .values(
                        reserved_tokens=new_reserved_t,
                        reserved_cost=new_reserved_c,
                        used_tokens=srow["used_tokens"] + actual_tokens,
                        used_cost=srow["used_cost"] + actual_cost,
                    )
                )
            await session.execute(
                update(agent_budget_reservation)
                .where(agent_budget_reservation.c.reservation_id == reservation_id)
                .values(state=ReservationState.SETTLED.value)
            )
            return True

    async def release(self, reservation_id: str) -> bool:
        async with self._sf() as session, session.begin():
            res = (
                await session.execute(
                    select(agent_budget_reservation)
                    .where(agent_budget_reservation.c.reservation_id == reservation_id)
                    .with_for_update()
                )
            ).mappings().first()
            if res is None or res["state"] != ReservationState.RESERVED.value:
                return False
            await self._unreserve(session, json.loads(res["scope_keys"]), res)
            await session.execute(
                update(agent_budget_reservation)
                .where(agent_budget_reservation.c.reservation_id == reservation_id)
                .values(state=ReservationState.RELEASED.value)
            )
            return True

    async def mark_uncertain(self, reservation_id: str) -> bool:
        async with self._sf() as session, session.begin():
            res = (
                await session.execute(
                    select(agent_budget_reservation)
                    .where(agent_budget_reservation.c.reservation_id == reservation_id)
                    .with_for_update()
                )
            ).mappings().first()
            if res is None or res["state"] != ReservationState.RESERVED.value:
                return False
            await session.execute(
                update(agent_budget_reservation)
                .where(agent_budget_reservation.c.reservation_id == reservation_id)
                .values(state=ReservationState.UNCERTAIN.value)
            )
            return True

    async def book_usage(self, scope: BudgetScope, usage: AgentUsage) -> None:
        keys = scope.keys() or ["global"]
        tokens = max(0, usage.total_tokens)
        cost = float(usage.cost_usd or 0.0)
        async with self._sf() as session, session.begin():
            await self._ensure_scope_rows(session, keys)
            for key in keys:
                await session.execute(
                    update(agent_budget_scope)
                    .where(agent_budget_scope.c.key == key)
                    .values(
                        used_tokens=agent_budget_scope.c.used_tokens + tokens,
                        used_cost=agent_budget_scope.c.used_cost + cost,
                    )
                )

    async def reconcile_stale(self, ttl_seconds: int) -> list[Reservation]:
        cutoff = _expiry(-ttl_seconds)
        recovered: list[Reservation] = []
        async with self._sf() as session, session.begin():
            rows = (
                await session.execute(
                    select(agent_budget_reservation)
                    .where(agent_budget_reservation.c.expires_at.is_not(None))
                    .where(agent_budget_reservation.c.expires_at < cutoff)
                    .where(
                        agent_budget_reservation.c.state.in_(
                            [ReservationState.RESERVED.value, ReservationState.UNCERTAIN.value]
                        )
                    )
                    .with_for_update()
                )
            ).mappings().all()
            for res in rows:
                rec = Reservation(
                    reservation_id=res["reservation_id"],
                    scope_keys=json.loads(res["scope_keys"]),
                    tokens=res["tokens"],
                    cost_usd=res["cost_usd"],
                    state=ReservationState(res["state"]),
                    created_at=res["created_at"],
                    expires_at=res["expires_at"],
                )
                if res["state"] == ReservationState.RESERVED.value:
                    await self._unreserve(session, rec.scope_keys, res)
                    await session.execute(
                        update(agent_budget_reservation)
                        .where(
                            agent_budget_reservation.c.reservation_id == res["reservation_id"]
                        )
                        .values(state=ReservationState.RELEASED.value)
                    )
                    rec.state = ReservationState.RELEASED
                recovered.append(rec)
        return recovered

    async def snapshot(self, key: str) -> BudgetSnapshot:
        async with self._sf() as session, session.begin():
            row = (
                await session.execute(
                    select(agent_budget_scope).where(agent_budget_scope.c.key == key)
                )
            ).mappings().first()
            if row is None:
                return BudgetSnapshot(key, _INF, _INF, 0, 0.0, 0, 0.0)
            return BudgetSnapshot(
                key=key,
                limit_tokens=_limit(row["limit_tokens"]),
                limit_cost=_limit(row["limit_cost"]),
                reserved_tokens=row["reserved_tokens"],
                reserved_cost=row["reserved_cost"],
                used_tokens=row["used_tokens"],
                used_cost=row["used_cost"],
            )

    async def _unreserve(self, session: AsyncSession, keys: list[str], res) -> None:
        for key in keys:
            srow = (
                await session.execute(
                    select(agent_budget_scope)
                    .where(agent_budget_scope.c.key == key)
                    .with_for_update()
                )
            ).mappings().first()
            if srow is None:
                continue
            await session.execute(
                update(agent_budget_scope)
                .where(agent_budget_scope.c.key == key)
                .values(
                    reserved_tokens=max(0, srow["reserved_tokens"] - res["tokens"]),
                    reserved_cost=max(0.0, srow["reserved_cost"] - res["cost_usd"]),
                )
            )


def _new_id() -> str:
    return uuid.uuid4().hex


def _expiry(lease_seconds: int):
    return utcnow() + timedelta(seconds=lease_seconds)


__all__ = [
    "PostgresBudgetStore",
    "agent_budget_reservation",
    "agent_budget_scope",
    "agent_budget_usage_event",
    "budget_metadata",
    "create_budget_tables",
]
