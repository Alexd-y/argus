"""FastAPI cache admin router — auth and mocked Redis / KB (no real Redis admin)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from starlette.testclient import TestClient

from src.core.config import settings


def _mock_redis_for_stats_and_health() -> MagicMock:
    r = MagicMock()
    r.ping.return_value = True

    def _info(section: str) -> dict:
        return {
            "memory": {
                "used_memory": 2048,
                "used_memory_human": "2.00K",
                "maxmemory_human": "0B",
                "maxmemory_policy": "noeviction",
            },
            "stats": {"keyspace_hits": 4, "keyspace_misses": 1},
            "server": {"uptime_in_seconds": 120, "redis_version": "7.2.0"},
        }[section]

    r.info.side_effect = _info
    r.scan_iter.return_value = iter([])
    r.ttl.return_value = -1
    return r


class TestCacheRouterAdminAuth:
    def test_health_401_without_admin_key_when_configured(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", "secret-admin-key"):
            response = client.get("/api/v1/cache/health")
        assert response.status_code == 401
        assert response.json().get("detail") == "Admin access required"

    def test_health_401_wrong_admin_key(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", "secret-admin-key"):
            response = client.get(
                "/api/v1/cache/health",
                headers={"X-Admin-Key": "wrong"},
            )
        assert response.status_code == 401

    def test_stats_401_without_header(self, client: TestClient) -> None:
        with patch.object(settings, "admin_api_key", "k"):
            response = client.get("/api/v1/cache/stats")
        assert response.status_code == 401


class TestCacheRouterWithMocks:
    def test_health_ok_with_admin_key_and_mock_redis(self, client: TestClient) -> None:
        mock_r = _mock_redis_for_stats_and_health()
        with patch.object(settings, "admin_api_key", "secret-admin-key"):
            with patch("src.api.routers.cache.get_redis", return_value=mock_r):
                response = client.get(
                    "/api/v1/cache/health",
                    headers={"X-Admin-Key": "secret-admin-key"},
                )
        assert response.status_code == 200
        body = response.json()
        assert body["connected"] is True
        assert "latency_ms" in body
        assert body["version"] == "7.2.0"
        mock_r.ping.assert_called()

    def test_stats_ok_with_admin_key_and_mock_redis(self, client: TestClient) -> None:
        mock_r = _mock_redis_for_stats_and_health()
        with patch.object(settings, "admin_api_key", "secret-admin-key"):
            with patch("src.api.routers.cache.get_redis", return_value=mock_r):
                response = client.get(
                    "/api/v1/cache/stats",
                    headers={"X-Admin-Key": "secret-admin-key"},
                )
        assert response.status_code == 200
        data = response.json()
        assert data["connected"] is True
        assert data["hits"] == 4
        assert data["misses"] == 1
        assert data["total_keys"] == 0
        assert "tool_breakdown" in data
        assert abs(data["hit_rate"] - 4 / 5) < 1e-5

    def test_warm_ok_mocks_knowledge_base(self, client: TestClient) -> None:
        mock_kb = MagicMock()
        mock_kb.stats.return_value = {"key_count": 7}
        with patch.object(settings, "admin_api_key", "secret-admin-key"):
            with patch(
                "src.api.routers.cache.get_knowledge_base",
                return_value=mock_kb,
            ):
                response = client.post(
                    "/api/v1/cache/warm",
                    headers={"X-Admin-Key": "secret-admin-key"},
                )
        assert response.status_code == 200
        payload = response.json()
        assert payload["warmed_keys"] == 7
        assert payload["source"] == "scan_knowledge_base"
        assert "duration_ms" in payload
        mock_kb.warm_cache.assert_called_once()
