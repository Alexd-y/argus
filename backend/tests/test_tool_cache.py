"""Unit tests for tool_result cache (Redis via unittest.mock; no real Redis)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from src.cache import tool_cache as tc


@pytest.fixture(autouse=True)
def reset_tool_cache_singleton() -> None:
    prev = tc._singleton
    tc._singleton = None
    yield
    tc._singleton = prev


def _cache_with_redis(mock_redis: MagicMock | None) -> tc.ToolResultCache:
    cache = tc.ToolResultCache.__new__(tc.ToolResultCache)
    cache._redis = mock_redis
    return cache


def test_ttl_for_tool_unknown_uses_default() -> None:
    assert tc.ttl_for_tool("nonexistent_tool_name") == tc._DEFAULT_TTL_SEC


def test_ttl_for_tool_none_uses_default() -> None:
    assert tc.ttl_for_tool(None) == tc._DEFAULT_TTL_SEC


def test_ttl_for_tool_nmap() -> None:
    assert tc.ttl_for_tool("nmap") == 3600


def test_cache_key_stable_for_same_inputs() -> None:
    k1 = tc.cache_key_for_execute("  ls -la  ", True, 30)
    k2 = tc.cache_key_for_execute("ls -la", True, 30)
    assert k1 == k2
    assert k1.startswith("argus:sandbox:exec:")


def test_cache_key_differs_when_inputs_differ() -> None:
    assert tc.cache_key_for_execute("ls", True, 30) != tc.cache_key_for_execute("ls", False, 30)


def test_get_miss_returns_none() -> None:
    r = MagicMock()
    r.get.return_value = None
    c = _cache_with_redis(r)
    assert c.get("anykey") is None
    r.get.assert_called_once_with("anykey")


def test_get_hit_returns_dict() -> None:
    r = MagicMock()
    r.get.return_value = json.dumps({"ok": True, "exit_code": 0})
    c = _cache_with_redis(r)
    assert c.get("k") == {"ok": True, "exit_code": 0}


def test_get_non_dict_json_returns_none() -> None:
    r = MagicMock()
    r.get.return_value = json.dumps([1, 2, 3])
    c = _cache_with_redis(r)
    assert c.get("k") is None


def test_get_redis_failure_degrades_to_none() -> None:
    r = MagicMock()
    r.get.side_effect = ConnectionError("redis down")
    c = _cache_with_redis(r)
    assert c.get("k") is None


def test_get_without_redis_degrades_to_none() -> None:
    c = _cache_with_redis(None)
    assert c.get("k") is None


def test_set_without_redis_is_noop() -> None:
    c = _cache_with_redis(None)
    c.set("k", {"a": 1}, 300)


def test_set_ttl_zero_skips_setex() -> None:
    r = MagicMock()
    c = _cache_with_redis(r)
    c.set("k", {"a": 1}, 0)
    r.setex.assert_not_called()


def test_set_happy_path_calls_setex() -> None:
    r = MagicMock()
    c = _cache_with_redis(r)
    c.set("mykey", {"out": "data"}, 90)
    r.setex.assert_called_once()
    call_kw = r.setex.call_args[0]
    assert call_kw[0] == "mykey"
    assert call_kw[1] == 90
    assert json.loads(call_kw[2]) == {"out": "data"}


def test_set_redis_failure_degrades_no_raise() -> None:
    r = MagicMock()
    r.setex.side_effect = ConnectionError("write failed")
    c = _cache_with_redis(r)
    c.set("k", {"a": 1}, 60)


def test_init_from_url_failure_degrades() -> None:
    with patch("redis.Redis.from_url", side_effect=ConnectionError("unreachable")):
        cache = tc.ToolResultCache()
    assert cache._redis is None
    assert cache.enabled is False


def test_init_ping_failure_degrades() -> None:
    mock_r = MagicMock()
    mock_r.ping.side_effect = OSError("timeout")
    with patch("redis.Redis.from_url", return_value=mock_r):
        cache = tc.ToolResultCache()
    assert cache._redis is None
    assert cache.enabled is False


def test_init_success_sets_redis() -> None:
    mock_r = MagicMock()
    mock_r.ping.return_value = True
    with patch("redis.Redis.from_url", return_value=mock_r):
        cache = tc.ToolResultCache()
    assert cache._redis is mock_r
    assert cache.enabled is True


def test_get_tool_cache_singleton() -> None:
    mock_r = MagicMock()
    mock_r.ping.return_value = True
    with patch("redis.Redis.from_url", return_value=mock_r):
        a = tc.get_tool_cache()
        b = tc.get_tool_cache()
    assert a is b
