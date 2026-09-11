"""Pool concurrency leases wired to settings (platform-hardening A, §8).

Central helper that call sites use to acquire a bounded slot in a shared pool
(LLM provider/model, tenant, scan, browser, tool, target host). Capacities come
from ``settings.lease_*``; the whole mechanism is opt-in via
``settings.lease_enabled`` and a reachable Redis. When disabled or Redis is
unavailable the context manager yields ``None`` (no distributed enforcement) —
local ``asyncio.Semaphore`` guards may still apply at the call site as an extra
layer (§8: local semaphores are additional defence, not the shared limit).

Example call-site wiring (LLM provider):

    from src.orchestration.pool_leases import pool_slot
    with pool_slot("provider", model_provider):
        text = call_provider(...)

A ``LeaseContendedError`` is raised only after the bounded backoff deadline —
callers should treat it as "defer/reschedule", not "fail the scan".
"""

from __future__ import annotations

from contextlib import contextmanager

from src.core.config import settings
from src.core.redis_client import get_redis
from src.orchestration.distributed_lease import DistributedLease, LeaseContendedError
from src.orchestration.observability import LEASE_EVENTS, metric_labels

_CAPACITY_ATTR = {
    "provider": "lease_provider_capacity",
    "tenant": "lease_tenant_capacity",
    "scan": "lease_scan_capacity",
    "browser": "lease_browser_capacity",
    "tool": "lease_tool_capacity",
    "host": "lease_host_capacity",
}


def pool_capacity(pool_type: str) -> int:
    """Configured capacity for a pool type; 0/absent => unbounded (no lease)."""
    attr = _CAPACITY_ATTR.get(pool_type)
    if attr is None:
        return 0
    return int(getattr(settings, attr, 0) or 0)


def get_pool_lease() -> DistributedLease | None:
    """Build a DistributedLease from the shared Redis client, or None."""
    if not settings.lease_enabled:
        return None
    client = get_redis()
    if client is None:
        return None
    return DistributedLease(client)


@contextmanager
def pool_slot(pool_type: str, resource_key: str, *, max_wait_seconds: float = 30.0):
    """Hold one slot in ``{pool_type}:{resource_key}``.

    Yields the ``LeaseHandle`` (or ``None`` when leasing is disabled/unavailable
    or the pool is unbounded). Releases owner-only on exit.
    """
    lease = get_pool_lease()
    capacity = pool_capacity(pool_type)
    if lease is None or capacity <= 0:
        yield None
        return

    pool_name = f"{pool_type}:{resource_key}"
    handle = lease.acquire_slot_blocking(
        pool_name,
        capacity,
        ttl_seconds=settings.lease_ttl_seconds,
        max_wait_seconds=max_wait_seconds,
    )
    if handle is None:
        LEASE_EVENTS.labels(**metric_labels(pool=pool_type, outcome="contended")).inc()
        raise LeaseContendedError(f"pool exhausted: {pool_name} (capacity={capacity})")

    LEASE_EVENTS.labels(**metric_labels(pool=pool_type, outcome="acquired")).inc()
    try:
        yield handle
    finally:
        lease.release(handle)
        LEASE_EVENTS.labels(**metric_labels(pool=pool_type, outcome="released")).inc()


__all__ = ["get_pool_lease", "pool_capacity", "pool_slot"]
