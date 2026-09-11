"""Offline tests for distributed concurrency leases (§8).

Uses an in-process fake Redis with a test-controlled clock — no real Redis.
Real-Redis behaviour is covered separately under requires_redis.
"""

from __future__ import annotations

import pytest
from src.orchestration.distributed_lease import (
    DistributedLease,
    LeaseContendedError,
    LeaseHandle,
    LeaseUnavailableError,
)


class FakeRedis:
    """Minimal Redis double: SET NX EX/PX, GET, and the two lease Lua scripts."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[str, float | None]] = {}
        self.now = 0.0

    def _expired(self, key: str) -> bool:
        v = self._store.get(key)
        if v is None:
            return True
        _, exp = v
        if exp is not None and self.now >= exp:
            del self._store[key]
            return True
        return False

    def set(self, key, value, nx=False, ex=None, px=None):
        if nx and not self._expired(key) and key in self._store:
            return None
        exp = None
        if ex is not None:
            exp = self.now + ex
        elif px is not None:
            exp = self.now + px / 1000.0
        self._store[key] = (value, exp)
        return True

    def get(self, key):
        if self._expired(key):
            return None
        return self._store[key][0]

    def eval(self, script, numkeys, *args):
        keys = args[:numkeys]
        argv = args[numkeys:]
        key = keys[0]
        owned = (not self._expired(key)) and self._store.get(key, (None, None))[0] == argv[0]
        if "pexpire" in script:  # renew
            if owned:
                val, _ = self._store[key]
                self._store[key] = (val, self.now + int(argv[1]) / 1000.0)
                return 1
            return 0
        # release (del)
        if owned:
            del self._store[key]
            return 1
        return 0


def test_acquire_and_contention():
    lease = DistributedLease(FakeRedis())
    h = lease.acquire("provider:openai", ttl_seconds=10)
    assert h is not None
    # Same resource already held -> None.
    assert lease.acquire("provider:openai", ttl_seconds=10) is None


def test_slot_pool_exhaustion():
    lease = DistributedLease(FakeRedis())
    h0 = lease.acquire_slot("browser", capacity=2, ttl_seconds=10)
    h1 = lease.acquire_slot("browser", capacity=2, ttl_seconds=10)
    h2 = lease.acquire_slot("browser", capacity=2, ttl_seconds=10)
    assert {h0.slot, h1.slot} == {0, 1}
    assert h2 is None  # both slots taken


def test_release_is_owner_only():
    fake = FakeRedis()
    lease = DistributedLease(fake)
    h = lease.acquire("scan:s1", ttl_seconds=10)
    # A different owner (wrong token) must not be able to free the lease.
    impostor = LeaseHandle(resource="scan:s1", token="not-the-token", ttl_seconds=10, key=h.key)
    assert lease.release(impostor) is False
    assert lease.acquire("scan:s1", ttl_seconds=10) is None  # still held
    # The real owner frees it.
    assert lease.release(h) is True
    assert lease.acquire("scan:s1", ttl_seconds=10) is not None


def test_ttl_expiry_frees_slot_on_crash():
    fake = FakeRedis()
    lease = DistributedLease(fake)
    h = lease.acquire("host:1.2.3.4", ttl_seconds=10)
    assert h is not None
    # Holder "crashes" without releasing; time passes beyond the TTL.
    fake.now = 11.0
    # The lease auto-expired, so a new holder can acquire it.
    assert lease.acquire("host:1.2.3.4", ttl_seconds=10) is not None


def test_renew_extends_live_lease():
    fake = FakeRedis()
    lease = DistributedLease(fake)
    h = lease.acquire("tenant:t1", ttl_seconds=10)  # expires at 10
    fake.now = 5.0
    assert lease.renew(h, ttl_seconds=10) is True  # now expires at 15
    fake.now = 12.0
    # Still held thanks to renewal (would have expired at 10 otherwise).
    assert lease.acquire("tenant:t1", ttl_seconds=10) is None


def test_renew_owner_only():
    fake = FakeRedis()
    lease = DistributedLease(fake)
    h = lease.acquire("tenant:t1", ttl_seconds=10)
    impostor = LeaseHandle(resource="tenant:t1", token="wrong", ttl_seconds=10, key=h.key)
    assert lease.renew(impostor) is False


def test_blocking_acquire_returns_none_on_deadline():
    lease = DistributedLease(FakeRedis())
    lease.acquire_slot("tool", capacity=1, ttl_seconds=10)  # fill the only slot
    # Deadline 0 -> one attempt, then give up (no busy loop, no infinite wait).
    got = lease.acquire_slot_blocking(
        "tool", capacity=1, ttl_seconds=10, max_wait_seconds=0.0, sleep=lambda _s: None
    )
    assert got is None


def test_no_redis_denies():
    lease = DistributedLease(None)
    with pytest.raises(LeaseUnavailableError):
        lease.acquire("x")


def test_hold_context_manager_releases():
    fake = FakeRedis()
    lease = DistributedLease(fake)
    with lease.hold("scan:s2", ttl_seconds=10) as h:
        assert h is not None
        assert lease.acquire("scan:s2", ttl_seconds=10) is None  # held inside
    # Released on exit.
    assert lease.acquire("scan:s2", ttl_seconds=10) is not None


def test_hold_raises_when_contended():
    fake = FakeRedis()
    lease = DistributedLease(fake)
    lease.acquire("scan:s3", ttl_seconds=10)
    with pytest.raises(LeaseContendedError), lease.hold("scan:s3", ttl_seconds=10):
        pass


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
