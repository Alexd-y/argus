"""Health endpoint tests for ARGUS-002 (Phase 1: Project Structure & Infra).

Проверяет GET /api/v1/health — unit test через TestClient (без поднятия сервера).
"""

import sys
from pathlib import Path

import pytest

ARGUS_ROOT = Path(__file__).resolve().parent.parent

# Add backend to path for import (backend or Backend)
_backend_candidates = ["backend", "Backend"]
_backend_dir = next((ARGUS_ROOT / n for n in _backend_candidates if (ARGUS_ROOT / n).exists()), None)
if _backend_dir is not None:
    sys.path.insert(0, str(_backend_dir))


@pytest.fixture(scope="module")
def app():
    """FastAPI app из backend."""
    from main import app as _app
    return _app


@pytest.fixture
def client(app):
    """TestClient для FastAPI app."""
    from fastapi.testclient import TestClient
    return TestClient(app)


class TestHealthEndpoint:
    """Проверка health endpoint."""

    def test_health_returns_200(self, client) -> None:
        """GET /api/v1/health возвращает 200."""
        response = client.get("/api/v1/health")
        assert response.status_code == 200

    def test_health_returns_json(self, client) -> None:
        """Health endpoint возвращает JSON."""
        response = client.get("/api/v1/health")
        assert response.headers.get("content-type", "").startswith("application/json")

    def test_health_response_structure(self, client) -> None:
        """Ответ содержит status и version."""
        response = client.get("/api/v1/health")
        data = response.json()
        assert "status" in data
        assert "version" in data
        assert data["status"] == "ok"
        assert data["version"] == "0.1.0"
