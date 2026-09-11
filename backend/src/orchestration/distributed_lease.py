"""Distributed concurrency leases (platform-hardening A, §8).

Reuses the Redis ``SET NX EX`` + random-token primitive already used by
``celery/tasks/intel_refresh.py`` and generalises it into bounded-capacity
*slot* leases for shared pools: LLM provider/model, tenant, scan, browser, tool,
target/host, and heavy-operation classes.

Guarantees:
* bounded TTL — a crashed holder's slot auto-frees when the lease expires;
* renewal — a live operation extends its own lease (``PEXPIRE`` via CAS);
* owner-only release — a holder can only free *its own* slot (token CAS), never
  someone else's;
* bounded backoff on exhaustion — callers wait with capped exponential backoff
  and honour a deadline instead of busy-looping or blocking forever.

This is a *concurrency* limiter (max simultaneous holders). It is deliberately
NOT a requests-per-second or tokens-per-minute rate limiter — those are separate
concerns and must not be conflated (§8).
"""

from __future__ import annotations

import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

# Owner-only atomic release: delete the key only if the token still matches.
_RELEASE_LUA = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('del', KEYS[1]) else return 0 end"
)
# Owner-only atomic renew: extend TTL only if the token still matches.
_RENEW_LUA = (
    "if redis.call('get', KEYS[1]) == ARGV[1] then "
    "return redis.call('pexpire', KEYS[1], ARGV[2]) else return 0 end"
)

DEFAULT_TTL_SECONDS = 120


class LeaseUnavailableError(RuntimeError):
    """Raised when no Redis client is available — deny rather than run unbounded."""


@dataclass
class LeaseHandle:
    resource: str
    token: str
    ttl_seconds: int
    key: str
    slot: int | None = None


class DistributedLease:
    """Redis-backed concurrency leases.

    ``redis_client`` is the sync client from ``src.core.redis_client.get_redis``
    (``decode_responses=True``). When ``None`` every acquire raises
    ``LeaseUnavailableError`` — callers must not fall back to unbounded local
    concurrency.
    """

    def __init__(self, redis_client: Any | None, namespace: str = "argus:lease") -> None:
        self._redis = redis_client
        self._ns = namespace

    def _key(self, resource: str) -> str:
        return f"{self._ns}:{resource}"

    def acquire(
        self, resource: str, ttl_seconds: int = DEFAULT_TTL_SECONDS, token: str | None = None
    ) -> LeaseHandle | None:
        """Try once to acquire a single named lease. Returns None if held."""
        if self._redis is None:
            raise LeaseUnavailableError("redis unavailable — cannot lease concurrency slot")
        tok = token or uuid.uuid4().hex
        key = self._key(resource)
        ok = self._redis.set(key, tok, nx=True, ex=ttl_seconds)
        if not ok:
            return None
        return LeaseHandle(resource=resource, token=tok, ttl_seconds=ttl_seconds, key=key)

    def acquire_slot(
        self, pool: str, capacity: int, ttl_seconds: int = DEFAULT_TTL_SECONDS
    ) -> LeaseHandle | None:
        """Acquire one of ``capacity`` slots for ``pool``. None if all taken."""
        if capacity <= 0:
            return None
        for i in range(capacity):
            handle = self.acquire(f"{pool}:{i}", ttl_seconds)
            if handle is not None:
                handle.slot = i
                return handle
        return None

    def acquire_slot_blocking(
        self,
        pool: str,
        capacity: int,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        *,
        max_wait_seconds: float = 30.0,
        base_backoff: float = 0.05,
        max_backoff: float = 2.0,
        sleep: Any = time.sleep,
    ) -> LeaseHandle | None:
        """Acquire a slot with bounded exponential backoff, honouring a deadline.

        Returns None when ``max_wait_seconds`` elapses without a free slot — the
        caller should then defer/reschedule the task rather than spin.
        """
        deadline = time.monotonic() + max_wait_seconds
        backoff = base_backoff
        while True:
            handle = self.acquire_slot(pool, capacity, ttl_seconds)
            if handle is not None:
                return handle
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sleep(min(backoff, max_backoff, remaining))
            backoff = min(backoff * 2, max_backoff)

    def renew(self, handle: LeaseHandle, ttl_seconds: int | None = None) -> bool:
        """Extend the lease TTL — only if we still own it (token CAS)."""
        if self._redis is None:
            raise LeaseUnavailableError("redis unavailable")
        ttl = ttl_seconds or handle.ttl_seconds
        result = self._redis.eval(_RENEW_LUA, 1, handle.key, handle.token, int(ttl * 1000))
        return bool(result)

    def release(self, handle: LeaseHandle) -> bool:
        """Release the lease — only if we still own it (never frees another's)."""
        if self._redis is None:
            raise LeaseUnavailableError("redis unavailable")
        result = self._redis.eval(_RELEASE_LUA, 1, handle.key, handle.token)
        return bool(result)

    @contextmanager
    def hold(self, resource: str, ttl_seconds: int = DEFAULT_TTL_SECONDS):
        """Context manager holding a single lease; releases owner-only on exit."""
        handle = self.acquire(resource, ttl_seconds)
        if handle is None:
            raise LeaseContendedError(f"lease busy: {resource}")
        try:
            yield handle
        finally:
            self.release(handle)

    @contextmanager
    def hold_slot(
        self,
        pool: str,
        capacity: int,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        *,
        max_wait_seconds: float = 30.0,
    ):
        """Context manager holding one pool slot (blocking acquire)."""
        handle = self.acquire_slot_blocking(
            pool, capacity, ttl_seconds, max_wait_seconds=max_wait_seconds
        )
        if handle is None:
            raise LeaseContendedError(f"pool exhausted: {pool} (capacity={capacity})")
        try:
            yield handle
        finally:
            self.release(handle)


class LeaseContendedError(RuntimeError):
    """Raised when a lease/pool slot could not be acquired within the deadline."""


__all__ = [
    "DEFAULT_TTL_SECONDS",
    "DistributedLease",
    "LeaseContendedError",
    "LeaseHandle",
    "LeaseUnavailableError",
]
