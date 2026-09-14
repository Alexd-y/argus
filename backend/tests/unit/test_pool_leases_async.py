"""Offline tests for the async pool-slot helper ``apool_slot`` (§8.1).

Uses an in-process fake Redis and monkeypatched settings — no real Redis. The
real-Redis serialisation behaviour is covered under ``requires_redis`` in
``tests/integration/lease/test_pool_slot_serialization_redis.py``.
"""

from __future__ import annotations

import pytest
from src.core.config import settings
from src.orchestration import pool_leases
from src.orchestration.distributed_lease import LeaseContendedError
from src.orchestration.pool_leases import apool_slot


class FakeRedis:
    """Minimal Redis double: SET NX EX, GET, and the owner-only release Lua."""

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    def set(self, key, value, nx=False, ex=None, px=None):
        if nx and key in self._store:
            return None
        self._store[key] = value
        return True

    def get(self, key):
        return self._store.get(key)

    def eval(self, script, numkeys, *args):
        key = args[0]
        token = args[numkeys]
        owned = self._store.get(key) == token
        if "pexpire" in script:  # renew
            return 1 if owned else 0
        if owned:  # release
            del self._store[key]
            return 1
        return 0


@pytest.fixture
def _lease_enabled(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(settings, "lease_enabled", True)
    monkeypatch.setattr(settings, "lease_ttl_seconds", 30)
    monkeypatch.setattr(settings, "lease_tool_capacity", 1)
    monkeypatch.setattr(pool_leases, "get_redis", lambda: fake)
    return fake


async def test_apool_slot_noop_when_disabled(monkeypatch):
    monkeypatch.setattr(settings, "lease_enabled", False)
    async with apool_slot("tool", "t1") as handle:
        assert handle is None


async def test_apool_slot_noop_when_capacity_zero(monkeypatch):
    monkeypatch.setattr(settings, "lease_enabled", True)
    monkeypatch.setattr(settings, "lease_tool_capacity", 0)
    monkeypatch.setattr(pool_leases, "get_redis", lambda: FakeRedis())
    async with apool_slot("tool", "t1") as handle:
        assert handle is None


async def test_apool_slot_acquires_serialises_and_releases(_lease_enabled):
    async with apool_slot("tool", "t1", max_wait_seconds=0.0) as first:
        assert first is not None
        # The single slot is now taken; a second acquirer defers → contended.
        with pytest.raises(LeaseContendedError):
            async with apool_slot("tool", "t1", max_wait_seconds=0.0):
                pass
    # Released on exit — the slot is free again.
    async with apool_slot("tool", "t1", max_wait_seconds=0.0) as third:
        assert third is not None


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
