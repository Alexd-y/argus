"""Quick wall-clock / request / concurrency budget manager.

Wall-clock deadline **wins** over USD :class:`~src.orchestration.cost_aware_reasoning.CostTracker`.
This module does not import or call ``BudgetEnforcer`` / ``CostTracker``. When both
signals exist (QUICK-004), stop on ``deadline_at`` first; do not mix the two ledgers.

``deadline_at`` is computed from the caller-supplied ``started_at`` (scan
``created_at`` / DB origin), not from the worker's local clock. The injectable
:class:`~src.quick.clock.Clock` is used only for lease expiry and token-bucket
refill so unit tests never sleep.

Discovery leases cannot consume the verification/report reserve. An expired
lease must not start; callers map :class:`LeaseExpiredError.task_status` to
``timed_out``.
"""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from src.quick.clock import Clock, SystemClock, as_utc
from src.quick.profiles import (
    DeploymentQuickClamps,
    QuickProfileCatalog,
    QuickProfileDefaults,
    TenantQuickLimits,
    clamp_int,
    default_clamps,
    load_quick_profiles,
)
from src.quick.schemas import (
    QuickBudget,
    QuickBudgetKind,
    QuickScanConfig,
    QuickTaskStatus,
)

logger = logging.getLogger(__name__)

_TIME_KINDS = frozenset(
    {
        QuickBudgetKind.WALL_CLOCK,
        QuickBudgetKind.DISCOVERY,
        QuickBudgetKind.FINGERPRINT,
        QuickBudgetKind.VERIFICATION,
        QuickBudgetKind.AI,
        QuickBudgetKind.REPORT,
    }
)


class LeaseStatus(StrEnum):
    ACTIVE = "active"
    EXHAUSTED = "exhausted"
    RELEASED = "released"
    EXPIRED = "expired"


class QuickBudgetError(ValueError):
    """Domain error for budget/lease operations. ``code`` is API-stable."""

    code = "quick_budget_error"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        self.code = code or type(self).code
        super().__init__(message)


class LeaseExpiredError(QuickBudgetError):
    """Lease past ``expires_at`` or scan past ``deadline_at``. Task must not start."""

    code = "lease_expired"
    task_status = QuickTaskStatus.TIMED_OUT

    def __init__(self, message: str = "lease_expired") -> None:
        super().__init__(message, code="lease_expired")


class DiscoveryReserveProtectedError(QuickBudgetError):
    """Discovery attempted to consume verification/report reserve."""

    code = "discovery_reserve_protected"

    def __init__(self, message: str = "discovery_reserve_protected") -> None:
        super().__init__(message, code="discovery_reserve_protected")


class BudgetExhaustedError(QuickBudgetError):
    code = "budget_exhausted"

    def __init__(self, message: str = "budget_exhausted") -> None:
        super().__init__(message, code="budget_exhausted")


class ConcurrencyLimitError(QuickBudgetError):
    code = "concurrency_limit"

    def __init__(self, message: str = "concurrency_limit") -> None:
        super().__init__(message, code="concurrency_limit")


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class BudgetLease(_Frozen):
    lease_id: StrictStr = Field(min_length=1, max_length=36)
    tenant_id: StrictStr = Field(min_length=1, max_length=36)
    scan_id: StrictStr = Field(min_length=1, max_length=36)
    task_id: StrictStr | None = Field(default=None, max_length=36)
    kind: QuickBudgetKind
    granted: StrictInt = Field(ge=0)
    consumed: StrictInt = Field(ge=0)
    expires_at: datetime
    status: LeaseStatus = LeaseStatus.ACTIVE
    host_key: StrictStr | None = Field(default=None, max_length=256)


class QuickBudgetSnapshot(_Frozen):
    scan_id: StrictStr
    tenant_id: StrictStr
    started_at: datetime
    deadline_at: datetime
    budget: QuickBudget


@dataclass
class _TokenBucket:
    capacity: int
    tokens: float
    refill_per_second: float
    last_refill: datetime

    def refill(self, now: datetime) -> None:
        instant = as_utc(now)
        elapsed = (instant - self.last_refill).total_seconds()
        if elapsed <= 0:
            return
        self.tokens = min(float(self.capacity), self.tokens + elapsed * self.refill_per_second)
        self.last_refill = instant

    def try_consume(self, amount: int, now: datetime) -> bool:
        self.refill(now)
        if amount <= 0:
            return True
        if self.tokens + 1e-9 < float(amount):
            return False
        self.tokens -= float(amount)
        return True

    def return_tokens(self, amount: int) -> None:
        if amount <= 0:
            return
        self.tokens = min(float(self.capacity), self.tokens + float(amount))


@dataclass
class _ScanBudgetState:
    tenant_id: str
    scan_id: str
    started_at: datetime
    deadline_at: datetime
    budget: QuickBudget
    remaining: dict[QuickBudgetKind, int]
    consumed: dict[QuickBudgetKind, int]
    leases: dict[str, BudgetLease] = field(default_factory=dict)
    host_buckets: dict[str, _TokenBucket] = field(default_factory=dict)
    scan_concurrency: int = 0
    tenant_concurrency_cap: int = 10


def reserve_seconds(wall_clock: int, percent: int) -> int:
    """Round-half-up integer seconds reserved for validation+report."""
    if wall_clock <= 0 or percent <= 0:
        return 0
    return min(wall_clock, (wall_clock * percent + 50) // 100)


def stage_budget_sum(budget: QuickBudget) -> int:
    return (
        budget.discovery_budget_seconds
        + budget.fingerprint_budget_seconds
        + budget.verification_budget_seconds
        + budget.ai_budget_seconds
        + budget.report_budget_seconds
    )


def assert_reserve_invariant(budget: QuickBudget) -> None:
    reserved = reserve_seconds(
        budget.wall_clock_budget_seconds,
        budget.reserve_for_validation_percent,
    )
    delta = abs(stage_budget_sum(budget) + reserved - budget.wall_clock_budget_seconds)
    if delta > 1:
        raise QuickBudgetError("reserve_invariant_violated", code="reserve_invariant_violated")


def split_int_by_weights(total: int, weights: dict[str, int]) -> dict[str, int]:
    keys = tuple(weights.keys())
    if total <= 0:
        return {key: 0 for key in keys}
    weight_sum = sum(weights.values())
    if weight_sum <= 0:
        raise QuickBudgetError("invalid_work_split_weights", code="invalid_work_split_weights")
    allocated = {key: (total * weights[key]) // weight_sum for key in keys}
    remainder = total - sum(allocated.values())
    allocated[keys[0]] += remainder
    return allocated


def compute_deadline_at(started_at: datetime, wall_clock_seconds: int) -> datetime:
    """``deadline_at = started_at + wall_clock``. Uses DB origin, not worker clock."""
    origin = as_utc(started_at)
    return origin + timedelta(seconds=max(0, int(wall_clock_seconds)))


def normalize_host_key(host_key: str) -> str:
    """Hostname-only key. Strips userinfo/credentials; never returns secrets."""
    raw = (host_key or "").strip()
    if not raw:
        return "unknown-host"
    candidate = raw
    if "://" in candidate:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").strip().lower()
        if host:
            return host[:256]
        candidate = parsed.netloc or candidate
    if "@" in candidate:
        candidate = candidate.rsplit("@", 1)[-1]
    host = candidate.split("/")[0].split(":")[0].strip().lower()
    return (host or "unknown-host")[:256]


def build_quick_budget(
    config: QuickScanConfig,
    defaults: QuickProfileDefaults,
    *,
    concurrency_cap: int,
) -> QuickBudget:
    """Split wall-clock into stage budgets. Sum(stages) + reserve = wall_clock (±1s)."""
    wall = config.wall_clock_budget_seconds
    reserved = reserve_seconds(wall, config.reserve_for_validation_percent)
    work = max(0, wall - reserved)
    ai = min(max(0, config.ai_budget_seconds), work)
    rest = max(0, work - ai)
    weights = {
        "discovery": defaults.work_split_weights.discovery,
        "fingerprint": defaults.work_split_weights.fingerprint,
        "verification": defaults.work_split_weights.verification,
        "report": defaults.work_split_weights.report,
    }
    parts = split_int_by_weights(rest, weights)
    concurrency = clamp_int(min(defaults.concurrency_budget, concurrency_cap), lo=1, hi=256)
    budget = QuickBudget(
        wall_clock_budget_seconds=wall,
        discovery_budget_seconds=parts["discovery"],
        fingerprint_budget_seconds=parts["fingerprint"],
        verification_budget_seconds=parts["verification"],
        ai_budget_seconds=ai,
        report_budget_seconds=parts["report"],
        request_budget=max(0, defaults.request_budget),
        per_host_budget=max(0, defaults.per_host_budget),
        concurrency_budget=concurrency,
        reserve_for_validation_percent=config.reserve_for_validation_percent,
    )
    assert_reserve_invariant(budget)
    return budget


def _new_remaining(budget: QuickBudget) -> dict[QuickBudgetKind, int]:
    return {
        QuickBudgetKind.WALL_CLOCK: budget.wall_clock_budget_seconds,
        QuickBudgetKind.DISCOVERY: budget.discovery_budget_seconds,
        QuickBudgetKind.FINGERPRINT: budget.fingerprint_budget_seconds,
        QuickBudgetKind.VERIFICATION: budget.verification_budget_seconds,
        QuickBudgetKind.AI: budget.ai_budget_seconds,
        QuickBudgetKind.REPORT: budget.report_budget_seconds,
        QuickBudgetKind.REQUEST: budget.request_budget,
        QuickBudgetKind.PER_HOST: budget.per_host_budget,
        QuickBudgetKind.CONCURRENCY: budget.concurrency_budget,
    }


def _zero_consumed() -> dict[QuickBudgetKind, int]:
    return {kind: 0 for kind in QuickBudgetKind}


class QuickBudgetManager:
    """In-memory leases for a process. Persistence is wired in later QUICK tasks."""

    def __init__(
        self,
        clock: Clock | None = None,
        catalog: QuickProfileCatalog | None = None,
        clamps: DeploymentQuickClamps | None = None,
    ) -> None:
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._catalog = catalog if catalog is not None else load_quick_profiles()
        self._clamps = clamps if clamps is not None else default_clamps()
        self._lock = threading.Lock()
        self._scans: dict[str, _ScanBudgetState] = {}
        self._lease_index: dict[str, str] = {}
        self._tenant_concurrency: dict[str, int] = {}

    def build_budget(
        self,
        config: QuickScanConfig,
        tenant_limits: TenantQuickLimits | None = None,
    ) -> QuickBudget:
        defaults = self._catalog.get(config.profile)
        concurrency_cap = self._clamps.max_concurrency
        if tenant_limits is not None and tenant_limits.max_concurrency is not None:
            concurrency_cap = min(concurrency_cap, tenant_limits.max_concurrency)
        return build_quick_budget(config, defaults, concurrency_cap=concurrency_cap)

    def compute_deadline(self, started_at: datetime, wall_clock_seconds: int) -> datetime:
        return compute_deadline_at(started_at, wall_clock_seconds)

    def open_scan(
        self,
        *,
        tenant_id: str,
        scan_id: str,
        config: QuickScanConfig,
        started_at: datetime,
        tenant_limits: TenantQuickLimits | None = None,
    ) -> QuickBudgetSnapshot:
        """Create stage pools, wall-clock lease, and per-scan concurrency cap.

        ``started_at`` must be the scan/DB origin, not ``clock.now()``.
        """
        origin = as_utc(started_at)
        budget = self.build_budget(config, tenant_limits)
        deadline = compute_deadline_at(origin, budget.wall_clock_budget_seconds)
        tenant_cap = self._clamps.max_concurrency
        if tenant_limits is not None and tenant_limits.max_concurrency is not None:
            tenant_cap = min(tenant_cap, tenant_limits.max_concurrency)
        with self._lock:
            if scan_id in self._scans:
                raise QuickBudgetError("scan_budget_already_open", code="scan_budget_already_open")
            state = _ScanBudgetState(
                tenant_id=tenant_id,
                scan_id=scan_id,
                started_at=origin,
                deadline_at=deadline,
                budget=budget,
                remaining=_new_remaining(budget),
                consumed=_zero_consumed(),
                tenant_concurrency_cap=max(1, tenant_cap),
            )
            wall_lease = self._make_lease(
                state=state,
                kind=QuickBudgetKind.WALL_CLOCK,
                amount=budget.wall_clock_budget_seconds,
                task_id=None,
                host_key=None,
                now=origin,
            )
            state.remaining[QuickBudgetKind.WALL_CLOCK] = 0
            state.leases[wall_lease.lease_id] = wall_lease
            self._lease_index[wall_lease.lease_id] = scan_id
            self._scans[scan_id] = state
        logger.info(
            "quick_budget_opened",
            extra={
                "tenant_id": tenant_id,
                "scan_id": scan_id,
                "profile": config.profile.value,
                "wall_clock_budget_seconds": budget.wall_clock_budget_seconds,
                "deadline_at": deadline.isoformat(),
            },
        )
        return QuickBudgetSnapshot(
            scan_id=scan_id,
            tenant_id=tenant_id,
            started_at=origin,
            deadline_at=deadline,
            budget=budget,
        )

    def deadline_reached(self, scan_id: str) -> bool:
        """True when wall-clock deadline has passed. Fail-closed if scan unknown."""
        with self._lock:
            state = self._scans.get(scan_id)
            if state is None:
                return True
            return as_utc(self._clock.now()) >= state.deadline_at

    def is_open(self, scan_id: str) -> bool:
        with self._lock:
            return scan_id in self._scans

    def should_stop_discovery(self, scan_id: str) -> bool:
        """QUICK-004 helper: stop scheduling discovery; keep verification+report reserve."""
        with self._lock:
            state = self._scans.get(scan_id)
            if state is None:
                return True
            now = as_utc(self._clock.now())
            if now >= state.deadline_at:
                return True
            return self._discovery_allowance(state, now) <= 0

    def remaining(self, scan_id: str, kind: QuickBudgetKind) -> int:
        with self._lock:
            state = self._require_scan(scan_id)
            return int(state.remaining[kind])

    def get_lease(self, lease_id: str) -> BudgetLease:
        with self._lock:
            return self._require_lease(lease_id)

    def acquire_lease(
        self,
        *,
        scan_id: str,
        kind: QuickBudgetKind,
        amount: int,
        task_id: str | None = None,
        host_key: str | None = None,
    ) -> BudgetLease:
        """Reserve budget. Task must call :meth:`assert_startable` before running."""
        if amount < 0:
            raise QuickBudgetError("lease_amount_negative", code="lease_amount_negative")
        with self._lock:
            state = self._require_scan(scan_id)
            now = as_utc(self._clock.now())
            self._expire_stale(state, now)
            if now >= state.deadline_at:
                raise LeaseExpiredError("lease_expired")
            granted = self._reserve_kind(state, kind, amount, now, host_key)
            lease = self._make_lease(
                state=state,
                kind=kind,
                amount=granted,
                task_id=task_id,
                host_key=normalize_host_key(host_key) if host_key else None,
                now=now,
            )
            state.leases[lease.lease_id] = lease
            self._lease_index[lease.lease_id] = scan_id
            logger.info(
                "quick_budget_lease_acquired",
                extra={
                    "tenant_id": state.tenant_id,
                    "scan_id": scan_id,
                    "lease_id": lease.lease_id,
                    "kind": kind.value,
                    "granted": granted,
                },
            )
            return lease

    def assert_startable(self, lease_id: str) -> BudgetLease:
        """Raise :class:`LeaseExpiredError` (task status ``timed_out``) if the lease cannot start."""
        with self._lock:
            lease = self._require_lease(lease_id)
            state = self._require_scan(lease.scan_id)
            now = as_utc(self._clock.now())
            if now >= state.deadline_at or now >= as_utc(lease.expires_at):
                self._mark_expired(state, lease)
                raise LeaseExpiredError("lease_expired")
            if lease.status is LeaseStatus.EXPIRED:
                raise LeaseExpiredError("lease_expired")
            if lease.status is not LeaseStatus.ACTIVE:
                raise QuickBudgetError(
                    f"lease_not_startable:{lease.status.value}",
                    code="lease_not_startable",
                )
            return lease

    def consume(self, lease_id: str, amount: int | None = None) -> BudgetLease:
        """Record actual use. ``amount=None`` consumes the remaining granted units."""
        with self._lock:
            lease = self._require_lease(lease_id)
            state = self._require_scan(lease.scan_id)
            now = as_utc(self._clock.now())
            if lease.status is LeaseStatus.EXPIRED or now >= as_utc(lease.expires_at):
                self._mark_expired(state, lease)
                raise LeaseExpiredError("lease_expired")
            if lease.status is not LeaseStatus.ACTIVE:
                raise QuickBudgetError(
                    f"lease_not_active:{lease.status.value}",
                    code="lease_not_active",
                )
            unused = lease.granted - lease.consumed
            take = unused if amount is None else amount
            if take < 0 or take > unused:
                raise QuickBudgetError("lease_consume_invalid", code="lease_consume_invalid")
            new_consumed = lease.consumed + take
            new_status = LeaseStatus.EXHAUSTED if new_consumed >= lease.granted else LeaseStatus.ACTIVE
            updated = lease.model_copy(update={"consumed": new_consumed, "status": new_status})
            state.consumed[lease.kind] = state.consumed.get(lease.kind, 0) + take
            self._store_lease(state, updated)
            return updated

    def release(self, lease_id: str) -> BudgetLease:
        """Return unused units on cancel/skip. Concurrency slots and host tokens are freed."""
        with self._lock:
            lease = self._require_lease(lease_id)
            state = self._require_scan(lease.scan_id)
            if lease.status in {LeaseStatus.RELEASED, LeaseStatus.EXPIRED}:
                return lease
            unused = max(0, lease.granted - lease.consumed)
            self._free_held_resources(state, lease)
            updated = lease.model_copy(update={"status": LeaseStatus.RELEASED})
            self._store_lease(state, updated)
            logger.info(
                "quick_budget_lease_released",
                extra={
                    "tenant_id": state.tenant_id,
                    "scan_id": state.scan_id,
                    "lease_id": lease.lease_id,
                    "kind": lease.kind.value,
                    "unused": unused,
                },
            )
            return updated

    def _reserve_kind(
        self,
        state: _ScanBudgetState,
        kind: QuickBudgetKind,
        amount: int,
        now: datetime,
        host_key: str | None,
    ) -> int:
        if kind is QuickBudgetKind.WALL_CLOCK:
            raise QuickBudgetError("wall_clock_lease_already_open", code="wall_clock_lease_already_open")
        if kind is QuickBudgetKind.DISCOVERY:
            if amount > state.remaining[QuickBudgetKind.DISCOVERY]:
                raise BudgetExhaustedError("budget_exhausted")
            if amount > self._discovery_wall_allowance(state, now):
                raise DiscoveryReserveProtectedError("discovery_reserve_protected")
        if kind is QuickBudgetKind.CONCURRENCY:
            self._acquire_concurrency(state, amount)
            state.remaining[kind] = max(0, state.remaining[kind] - amount)
            return amount
        if kind is QuickBudgetKind.PER_HOST:
            key = normalize_host_key(host_key or "")
            bucket = self._host_bucket(state, key, now)
            if not bucket.try_consume(amount, now):
                raise BudgetExhaustedError("per_host_budget_exhausted")
            return amount
        available = state.remaining.get(kind, 0)
        if amount > available:
            raise BudgetExhaustedError("budget_exhausted")
        state.remaining[kind] = available - amount
        return amount

    def _discovery_wall_allowance(self, state: _ScanBudgetState, now: datetime) -> int:
        elapsed = max(0, int((as_utc(now) - state.started_at).total_seconds()))
        wall_left = max(0, state.budget.wall_clock_budget_seconds - elapsed)
        reserved = reserve_seconds(
            state.budget.wall_clock_budget_seconds,
            state.budget.reserve_for_validation_percent,
        )
        protected = min(wall_left, reserved)
        return max(0, wall_left - protected)

    def _discovery_allowance(self, state: _ScanBudgetState, now: datetime) -> int:
        return min(
            state.remaining[QuickBudgetKind.DISCOVERY],
            self._discovery_wall_allowance(state, now),
        )

    def _acquire_concurrency(self, state: _ScanBudgetState, slots: int) -> None:
        if slots <= 0:
            raise QuickBudgetError("lease_amount_negative", code="lease_amount_negative")
        if state.scan_concurrency + slots > state.budget.concurrency_budget:
            raise ConcurrencyLimitError("scan_concurrency_exhausted")
        tenant_used = self._tenant_concurrency.get(state.tenant_id, 0)
        if tenant_used + slots > state.tenant_concurrency_cap:
            raise ConcurrencyLimitError("tenant_concurrency_exhausted")
        state.scan_concurrency += slots
        self._tenant_concurrency[state.tenant_id] = tenant_used + slots

    def _release_concurrency(self, state: _ScanBudgetState, slots: int) -> None:
        if slots <= 0:
            return
        state.scan_concurrency = max(0, state.scan_concurrency - slots)
        used = self._tenant_concurrency.get(state.tenant_id, 0)
        self._tenant_concurrency[state.tenant_id] = max(0, used - slots)

    def _host_bucket(self, state: _ScanBudgetState, host_key: str, now: datetime) -> _TokenBucket:
        existing = state.host_buckets.get(host_key)
        if existing is not None:
            return existing
        capacity = max(0, state.budget.per_host_budget)
        wall = max(1, state.budget.wall_clock_budget_seconds)
        bucket = _TokenBucket(
            capacity=capacity,
            tokens=float(capacity),
            refill_per_second=float(capacity) / float(wall),
            last_refill=as_utc(now),
        )
        state.host_buckets[host_key] = bucket
        return bucket

    def _make_lease(
        self,
        *,
        state: _ScanBudgetState,
        kind: QuickBudgetKind,
        amount: int,
        task_id: str | None,
        host_key: str | None,
        now: datetime,
    ) -> BudgetLease:
        if kind in _TIME_KINDS:
            ttl = max(1, amount) if amount > 0 else 1
            expires = min(now + timedelta(seconds=ttl), state.deadline_at)
        else:
            expires = state.deadline_at
        return BudgetLease(
            lease_id=str(uuid.uuid4()),
            tenant_id=state.tenant_id,
            scan_id=state.scan_id,
            task_id=task_id,
            kind=kind,
            granted=amount,
            consumed=0,
            expires_at=expires,
            status=LeaseStatus.ACTIVE,
            host_key=host_key,
        )

    def _expire_stale(self, state: _ScanBudgetState, now: datetime) -> None:
        for lease in tuple(state.leases.values()):
            if lease.status is not LeaseStatus.ACTIVE:
                continue
            if now >= as_utc(lease.expires_at) or now >= state.deadline_at:
                self._mark_expired(state, lease)

    def _mark_expired(self, state: _ScanBudgetState, lease: BudgetLease) -> None:
        if lease.status is LeaseStatus.EXPIRED:
            return
        self._free_held_resources(state, lease)
        self._store_lease(state, lease.model_copy(update={"status": LeaseStatus.EXPIRED}))

    def _free_held_resources(self, state: _ScanBudgetState, lease: BudgetLease) -> None:
        """Return unused quota / slots / host tokens for an open lease."""
        if lease.status in {LeaseStatus.RELEASED, LeaseStatus.EXPIRED}:
            return
        if lease.kind is QuickBudgetKind.CONCURRENCY:
            self._release_concurrency(state, lease.granted)
            state.remaining[lease.kind] = state.remaining.get(lease.kind, 0) + lease.granted
            return
        unused = max(0, lease.granted - lease.consumed)
        if unused and lease.kind is not QuickBudgetKind.WALL_CLOCK:
            state.remaining[lease.kind] = state.remaining.get(lease.kind, 0) + unused
        if lease.kind is QuickBudgetKind.PER_HOST and lease.host_key:
            bucket = state.host_buckets.get(lease.host_key)
            if bucket is not None:
                bucket.return_tokens(unused)

    def _store_lease(self, state: _ScanBudgetState, lease: BudgetLease) -> None:
        state.leases[lease.lease_id] = lease
        self._lease_index[lease.lease_id] = state.scan_id

    def _require_scan(self, scan_id: str) -> _ScanBudgetState:
        state = self._scans.get(scan_id)
        if state is None:
            raise QuickBudgetError("unknown_quick_scan_budget", code="unknown_quick_scan_budget")
        return state

    def _require_lease(self, lease_id: str) -> BudgetLease:
        scan_id = self._lease_index.get(lease_id)
        if scan_id is None:
            raise QuickBudgetError("unknown_quick_lease", code="unknown_quick_lease")
        state = self._require_scan(scan_id)
        lease = state.leases.get(lease_id)
        if lease is None:
            raise QuickBudgetError("unknown_quick_lease", code="unknown_quick_lease")
        return lease


__all__ = [
    "BudgetExhaustedError",
    "BudgetLease",
    "ConcurrencyLimitError",
    "DiscoveryReserveProtectedError",
    "LeaseExpiredError",
    "LeaseStatus",
    "QuickBudgetError",
    "QuickBudgetManager",
    "QuickBudgetSnapshot",
    "assert_reserve_invariant",
    "build_quick_budget",
    "compute_deadline_at",
    "normalize_host_key",
    "reserve_seconds",
    "split_int_by_weights",
    "stage_budget_sum",
]
