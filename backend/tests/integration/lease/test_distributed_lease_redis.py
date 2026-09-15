"""Real-Redis tests for distributed leases (§8).

Marked ``requires_redis`` — needs a live Redis. Run, e.g.:

    $env:ARGUS_TEST_REDIS_URL = "redis://localhost:63790/0"
    pytest tests/integration/lease/test_distributed_lease_redis.py -m requires_redis -p no:cacheprovider

Exercises the real ``SET NX EX`` + Lua CAS release/renew against a running Redis.
"""

from __future__ import annotations

import os
import uuid

import pytest
from src.orchestration.distributed_lease import DistributedLease, LeaseHandle

pytestmark = pytest.mark.requires_redis

_URL = os.environ.get("ARGUS_TEST_REDIS_URL")


def _client():
    import redis

    return redis.from_url(_URL, decode_responses=True, socket_connect_timeout=5)


@pytest.fixture(scope="module", autouse=True)
def _require_url():
    if not _URL:
        pytest.skip("ARGUS_TEST_REDIS_URL not set — live Redis required")


def test_real_acquire_contention_and_owner_only_release():
    lease = DistributedLease(_client(), namespace=f"argus:test:{uuid.uuid4().hex[:8]}")
    res = f"provider:{uuid.uuid4().hex[:8]}"
    h = lease.acquire(res, ttl_seconds=30)
    assert h is not None
    assert lease.acquire(res, ttl_seconds=30) is None  # contended

    impostor = LeaseHandle(resource=res, token="wrong", ttl_seconds=30, key=h.key)
    assert lease.release(impostor) is False  # cannot free another's lease
    assert lease.acquire(res, ttl_seconds=30) is None  # still held

    assert lease.release(h) is True
    h2 = lease.acquire(res, ttl_seconds=30)
    assert h2 is not None
    lease.release(h2)


def test_real_slot_pool_and_renew():
    lease = DistributedLease(_client(), namespace=f"argus:test:{uuid.uuid4().hex[:8]}")
    pool = f"browser:{uuid.uuid4().hex[:8]}"
    h0 = lease.acquire_slot(pool, capacity=2, ttl_seconds=30)
    h1 = lease.acquire_slot(pool, capacity=2, ttl_seconds=30)
    h2 = lease.acquire_slot(pool, capacity=2, ttl_seconds=30)
    assert h0 is not None and h1 is not None
    assert h2 is None  # exhausted

    assert lease.renew(h0, ttl_seconds=60) is True
    lease.release(h0)
    lease.release(h1)
    # A slot is free again after release.
    h3 = lease.acquire_slot(pool, capacity=2, ttl_seconds=30)
    assert h3 is not None
    lease.release(h3)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v", "-m", "requires_redis"]))
