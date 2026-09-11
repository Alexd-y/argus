"""Authoritative budget ledger (platform-hardening A, §7).

Single source of truth for agent/LLM budgeting with an explicit
``reserve → execute → settle | release`` discipline:

* **reserve** — atomically check *all* applicable scope limits (tenant / scan /
  task) and hold budget. All-or-nothing.
* **settle** — book *actual* usage (idempotent: a repeated settle never charges
  twice); the held reservation is converted to used.
* **release** — only when the operation definitely never started (no charge).
* **mark_uncertain** — the operation may have hit the provider but usage is
  unknown; the reservation is NOT freed as if it were free — it is held for
  reconciliation.

Separation of concerns (per §7):
* limits vs reservations vs actual usage vs (observability metrics — external).

The ``BudgetStore`` protocol isolates the atomic backend. ``InMemoryBudgetStore``
(offline, ``asyncio.Lock``-guarded to model a DB transaction) is provided and
fully tested here. The production store (atomic via Postgres ``SELECT … FOR
UPDATE`` / conditional ``UPDATE``, durable usage events keyed by idempotency)
must implement this same protocol; it is the next infra-gated step and is NOT
shipped half-done. When no store is available, new paid calls are DENIED — there
is no unlimited local fallback.
"""

from __future__ import annotations

import asyncio
import math
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol, runtime_checkable

from src.orchestration.agent_contracts import AgentUsage, utcnow

DEFAULT_LEASE_SECONDS = 300


class ReservationState(StrEnum):
    RESERVED = "reserved"
    SETTLED = "settled"
    RELEASED = "released"
    UNCERTAIN = "uncertain"


class BudgetError(Exception):
    """Base class for budget errors."""


class BudgetUnavailableError(BudgetError):
    """The authoritative budget store is unavailable — deny new paid calls."""


class BudgetDeniedError(BudgetError):
    """The reservation would exceed a configured limit."""


@dataclass(frozen=True)
class BudgetScope:
    """Which limits a reservation is charged against."""

    tenant_id: str = ""
    scan_id: str = ""
    task_id: str = ""

    def keys(self) -> list[str]:
        out: list[str] = []
        if self.tenant_id:
            out.append(f"tenant:{self.tenant_id}")
        if self.scan_id:
            out.append(f"scan:{self.scan_id}")
        if self.task_id:
            out.append(f"task:{self.task_id}")
        return out


@dataclass
class Reservation:
    reservation_id: str
    scope_keys: list[str]
    tokens: int
    cost_usd: float
    state: ReservationState = ReservationState.RESERVED
    created_at: datetime = field(default_factory=utcnow)
    expires_at: datetime | None = None


@dataclass
class BudgetSnapshot:
    key: str
    limit_tokens: float
    limit_cost: float
    reserved_tokens: int
    reserved_cost: float
    used_tokens: int
    used_cost: float

    @property
    def available_tokens(self) -> float:
        return max(0.0, self.limit_tokens - self.reserved_tokens - self.used_tokens)

    @property
    def available_cost(self) -> float:
        return max(0.0, self.limit_cost - self.reserved_cost - self.used_cost)


@dataclass
class _Counter:
    limit_tokens: float = math.inf
    limit_cost: float = math.inf
    reserved_tokens: int = 0
    reserved_cost: float = 0.0
    used_tokens: int = 0
    used_cost: float = 0.0


@runtime_checkable
class BudgetStore(Protocol):
    async def set_limits(
        self, key: str, *, max_tokens: float | None = None, max_cost_usd: float | None = None
    ) -> None: ...

    async def try_reserve(
        self, scope: BudgetScope, tokens: int, cost_usd: float, lease_seconds: int
    ) -> Reservation | None: ...

    async def settle(self, reservation_id: str, usage: AgentUsage) -> bool: ...

    async def release(self, reservation_id: str) -> bool: ...

    async def mark_uncertain(self, reservation_id: str) -> bool: ...

    async def book_usage(self, scope: BudgetScope, usage: AgentUsage) -> None: ...

    async def reconcile_stale(self, ttl_seconds: int) -> list[Reservation]: ...

    async def snapshot(self, key: str) -> BudgetSnapshot: ...


class InMemoryBudgetStore:
    """Process-local store guarded by a lock (models a DB transaction).

    Suitable for offline tests and single-process use. Cross-worker atomicity in
    production is delegated to a DB-backed implementation of ``BudgetStore``.
    """

    def __init__(self) -> None:
        self._counters: dict[str, _Counter] = {}
        self._reservations: dict[str, Reservation] = {}
        self._lock = asyncio.Lock()

    def _counter(self, key: str) -> _Counter:
        c = self._counters.get(key)
        if c is None:
            c = _Counter()
            self._counters[key] = c
        return c

    async def set_limits(
        self, key: str, *, max_tokens: float | None = None, max_cost_usd: float | None = None
    ) -> None:
        async with self._lock:
            c = self._counter(key)
            if max_tokens is not None:
                c.limit_tokens = max_tokens
            if max_cost_usd is not None:
                c.limit_cost = max_cost_usd

    async def try_reserve(
        self, scope: BudgetScope, tokens: int, cost_usd: float, lease_seconds: int
    ) -> Reservation | None:
        keys = scope.keys()
        async with self._lock:
            # All-or-nothing: every constrained scope level must fit.
            for key in keys:
                c = self._counter(key)
                if c.reserved_tokens + c.used_tokens + tokens > c.limit_tokens:
                    return None
                if c.reserved_cost + c.used_cost + cost_usd > c.limit_cost:
                    return None
            for key in keys:
                c = self._counter(key)
                c.reserved_tokens += tokens
                c.reserved_cost += cost_usd
            res = Reservation(
                reservation_id=uuid.uuid4().hex,
                scope_keys=keys,
                tokens=tokens,
                cost_usd=cost_usd,
                expires_at=utcnow() + timedelta(seconds=lease_seconds),
            )
            self._reservations[res.reservation_id] = res
            return res

    async def settle(self, reservation_id: str, usage: AgentUsage) -> bool:
        async with self._lock:
            res = self._reservations.get(reservation_id)
            if res is None:
                return False
            # Idempotent: a reservation is settled/released exactly once.
            if res.state != ReservationState.RESERVED and res.state != ReservationState.UNCERTAIN:
                return False
            actual_tokens = max(0, usage.total_tokens)
            actual_cost = float(usage.cost_usd or 0.0)
            for key in res.scope_keys:
                c = self._counter(key)
                c.reserved_tokens = max(0, c.reserved_tokens - res.tokens)
                c.reserved_cost = max(0.0, c.reserved_cost - res.cost_usd)
                c.used_tokens += actual_tokens
                c.used_cost += actual_cost
            res.state = ReservationState.SETTLED
            return True

    async def release(self, reservation_id: str) -> bool:
        async with self._lock:
            res = self._reservations.get(reservation_id)
            if res is None or res.state != ReservationState.RESERVED:
                return False
            for key in res.scope_keys:
                c = self._counter(key)
                c.reserved_tokens = max(0, c.reserved_tokens - res.tokens)
                c.reserved_cost = max(0.0, c.reserved_cost - res.cost_usd)
            res.state = ReservationState.RELEASED
            return True

    async def mark_uncertain(self, reservation_id: str) -> bool:
        async with self._lock:
            res = self._reservations.get(reservation_id)
            if res is None or res.state != ReservationState.RESERVED:
                return False
            res.state = ReservationState.UNCERTAIN
            return True

    async def book_usage(self, scope: BudgetScope, usage: AgentUsage) -> None:
        """Book actual usage with no prior reservation (post-hoc accounting)."""
        keys = scope.keys() or ["global"]
        tokens = max(0, usage.total_tokens)
        cost = float(usage.cost_usd or 0.0)
        async with self._lock:
            for key in keys:
                c = self._counter(key)
                c.used_tokens += tokens
                c.used_cost += cost

    async def reconcile_stale(self, ttl_seconds: int) -> list[Reservation]:
        """Recover hung RESERVED holds; surface UNCERTAIN ones for follow-up.

        A RESERVED reservation past its lease with no settle is treated as never
        having charged and is released (bounded recovery). UNCERTAIN reservations
        are returned but NOT auto-freed — usage may have been incurred and must
        be reconciled against provider metadata.
        """
        now = utcnow()
        recovered: list[Reservation] = []
        async with self._lock:
            for res in list(self._reservations.values()):
                if res.expires_at is None or (now - res.expires_at).total_seconds() < ttl_seconds:
                    continue
                if res.state == ReservationState.RESERVED:
                    for key in res.scope_keys:
                        c = self._counter(key)
                        c.reserved_tokens = max(0, c.reserved_tokens - res.tokens)
                        c.reserved_cost = max(0.0, c.reserved_cost - res.cost_usd)
                    res.state = ReservationState.RELEASED
                    recovered.append(res)
                elif res.state == ReservationState.UNCERTAIN:
                    recovered.append(res)
        return recovered

    async def snapshot(self, key: str) -> BudgetSnapshot:
        async with self._lock:
            c = self._counter(key)
            return BudgetSnapshot(
                key=key,
                limit_tokens=c.limit_tokens,
                limit_cost=c.limit_cost,
                reserved_tokens=c.reserved_tokens,
                reserved_cost=c.reserved_cost,
                used_tokens=c.used_tokens,
                used_cost=c.used_cost,
            )


class BudgetLedger:
    """High-level budget API over a ``BudgetStore``.

    With ``store=None`` every reservation raises ``BudgetUnavailableError`` —
    callers MUST NOT fall back to unlimited execution.
    """

    def __init__(self, store: BudgetStore | None) -> None:
        self._store = store

    @property
    def available(self) -> bool:
        return self._store is not None

    async def reserve(
        self,
        scope: BudgetScope,
        tokens: int,
        est_cost_usd: float = 0.0,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
    ) -> Reservation:
        if self._store is None:
            raise BudgetUnavailableError("budget store unavailable — denying paid call")
        res = await self._store.try_reserve(scope, tokens, est_cost_usd, lease_seconds)
        if res is None:
            raise BudgetDeniedError(
                f"budget denied for {scope.keys()} (tokens={tokens}, est_cost={est_cost_usd})"
            )
        return res

    async def settle(self, reservation: Reservation, usage: AgentUsage) -> bool:
        if self._store is None:
            raise BudgetUnavailableError("budget store unavailable")
        return await self._store.settle(reservation.reservation_id, usage)

    async def release(self, reservation: Reservation) -> bool:
        if self._store is None:
            raise BudgetUnavailableError("budget store unavailable")
        return await self._store.release(reservation.reservation_id)

    async def mark_uncertain(self, reservation: Reservation) -> bool:
        if self._store is None:
            raise BudgetUnavailableError("budget store unavailable")
        return await self._store.mark_uncertain(reservation.reservation_id)

    async def record_usage(self, scope: BudgetScope, usage: AgentUsage) -> None:
        """Book actual usage post-hoc (no reservation) into the durable ledger."""
        if self._store is None:
            raise BudgetUnavailableError("budget store unavailable")
        await self._store.book_usage(scope, usage)

    async def reconcile_stale(self, ttl_seconds: int = DEFAULT_LEASE_SECONDS) -> list[Reservation]:
        if self._store is None:
            raise BudgetUnavailableError("budget store unavailable")
        return await self._store.reconcile_stale(ttl_seconds)

    async def snapshot(self, key: str) -> BudgetSnapshot:
        if self._store is None:
            raise BudgetUnavailableError("budget store unavailable")
        return await self._store.snapshot(key)

    @asynccontextmanager
    async def budgeted(
        self,
        scope: BudgetScope,
        tokens: int,
        est_cost_usd: float = 0.0,
        lease_seconds: int = DEFAULT_LEASE_SECONDS,
    ):
        """`reserve → execute → settle | release | mark_uncertain` in one block.

        Usage:

            async with ledger.budgeted(scope, est_tokens, est_cost) as run:
                run.mark_started()          # right before the provider call
                result = await call_llm(...)
                run.record_usage(usage)     # from provider metadata

        On exit:
        * usage recorded  → settle (actual);
        * started, no usage (ambiguous — provider may have run) → mark_uncertain
          (the reservation is NOT freed as if it were free);
        * never started   → release (no charge).
        """
        res = await self.reserve(scope, tokens, est_cost_usd, lease_seconds)
        handle = BudgetedReservation(res)
        try:
            yield handle
        finally:
            if handle.usage is not None:
                await self.settle(res, handle.usage)
            elif handle.started:
                await self.mark_uncertain(res)
            else:
                await self.release(res)


class BudgetedReservation:
    """Handle yielded by :meth:`BudgetLedger.budgeted`."""

    def __init__(self, reservation: Reservation) -> None:
        self.reservation = reservation
        self.started = False
        self.usage: AgentUsage | None = None

    def mark_started(self) -> None:
        self.started = True

    def record_usage(self, usage: AgentUsage) -> None:
        self.started = True
        self.usage = usage


__all__ = [
    "BudgetDeniedError",
    "BudgetError",
    "BudgetLedger",
    "BudgetScope",
    "BudgetSnapshot",
    "BudgetStore",
    "BudgetUnavailableError",
    "BudgetedReservation",
    "InMemoryBudgetStore",
    "Reservation",
    "ReservationState",
]
