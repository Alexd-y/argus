"""Real-Redis serialisation test for ``apool_slot`` (§8.1).

Marked ``requires_redis`` — needs a live Redis. Run, e.g.:

    $env:ARGUS_TEST_REDIS_URL = "redis://localhost:63790/0"
    pytest tests/integration/lease/test_pool_slot_serialization_redis.py -m requires_redis -p no:cacheprovider

Asserts that with ``capacity=1`` two concurrent acquirers of the same key
serialise: while the first holds the slot the second defers (contended), and it
acquires only after the first releases.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import pytest
from src.core.config import settings
from src.orchestration import pool_leases
from src.orchestration.distributed_lease import LeaseContendedError
from src.orchestration.pool_leases import apool_slot

pytestmark = pytest.mark.requires_redis

_URL = os.environ.get("ARGUS_TEST_REDIS_URL")


@pytest.fixture(scope="module", autouse=True)
def _require_url():
    if not _URL:
        pytest.skip("ARGUS_TEST_REDIS_URL not set — live Redis required")


@pytest.fixture
def _real_redis(monkeypatch):
    import redis

    client = redis.from_url(_URL, decode_responses=True, socket_connect_timeout=5)
    monkeypatch.setattr(settings, "lease_enabled", True)
    monkeypatch.setattr(settings, "lease_ttl_seconds", 30)
    monkeypatch.setattr(settings, "lease_host_capacity", 1)
    monkeypatch.setattr(pool_leases, "get_redis", lambda: client)
    return client


async def test_capacity_one_two_concurrent_acquirers_serialise(_real_redis):
    key = f"itest-{uuid.uuid4().hex[:10]}"
    second_started = asyncio.Event()
    order: list[str] = []

    async def _first():
        async with apool_slot("host", key, max_wait_seconds=5.0):
            order.append("first_acquired")
            # Hold until the second acquirer has proven it must wait.
            await asyncio.wait_for(second_started.wait(), timeout=5.0)
            await asyncio.sleep(0.2)
        order.append("first_released")

    async def _second():
        second_started.set()
        # While the first holds the only slot, an immediate attempt defers.
        with pytest.raises(LeaseContendedError):
            async with apool_slot("host", key, max_wait_seconds=0.0):
                pass
        order.append("second_contended")

    await asyncio.gather(_first(), _second())

    assert "first_acquired" in order
    assert "second_contended" in order
    # After the first releases, the slot is acquirable again.
    async with apool_slot("host", key, max_wait_seconds=2.0) as handle:
        assert handle is not None


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v", "-m", "requires_redis"]))
