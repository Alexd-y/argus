"""Auth tests for ARGUS-003 (Phase 2: Core Backend).

POST /auth/login, protected route /auth/me with/without token.
"""

import pytest
from starlette.testclient import TestClient


def _patch_login_db_no_user(monkeypatch: pytest.MonkeyPatch) -> None:
    """Avoid real PostgreSQL when login queries users (dev bypass / 401 paths)."""

    class _Sess:
        async def execute(self, *_args, **_kwargs):
            class _R:
                def scalar_one_or_none(self):
                    return None

            return _R()

    class _CM:
        async def __aenter__(self):
            return _Sess()

        async def __aexit__(self, *_args):
            return None

    monkeypatch.setattr("src.api.routers.auth.async_session_factory", lambda: _CM())


class TestLoginEndpoint:
    """POST /api/v1/auth/login."""

    def test_login_returns_503_when_jwt_not_configured(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Login returns 503 when JWT_SECRET is not set."""
        monkeypatch.setattr("src.core.config.settings.jwt_secret", "")
        # Need fresh app/client after config change — re-import
        from main import app
        from starlette.testclient import TestClient
        test_client = TestClient(app)
        response = test_client.post(
            "/api/v1/auth/login",
            json={"mail": "user@example.com", "password": "secret"},
        )
        assert response.status_code == 503
        assert "JWT_SECRET" in response.json().get("detail", "")

    def test_login_returns_200_and_token_when_configured(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Login returns 200 and access_token when JWT_SECRET is set (DEBUG dev bypass)."""
        monkeypatch.setattr(
            "src.core.config.settings.jwt_secret",
            "test-secret-key-min-32-chars-long-for-hs256",
        )
        monkeypatch.setattr("src.core.config.settings.debug", True)
        monkeypatch.setattr("src.core.config.settings.dev_login_bypass_enabled", True)
        _patch_login_db_no_user(monkeypatch)
        from main import app
        from starlette.testclient import TestClient
        test_client = TestClient(app)
        response = test_client.post(
            "/api/v1/auth/login",
            json={"mail": "user@example.com", "password": "any"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data.get("dev_mode") is True

    def test_login_missing_mail_returns_422(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Login without mail returns 422."""
        monkeypatch.setattr(
            "src.core.config.settings.jwt_secret",
            "test-secret-key-min-32-chars-long-for-hs256",
        )
        from main import app
        from starlette.testclient import TestClient
        test_client = TestClient(app)
        response = test_client.post(
            "/api/v1/auth/login",
            json={"password": "secret"},
        )
        assert response.status_code == 422

    def test_login_missing_password_returns_422(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Login without password returns 422."""
        monkeypatch.setattr(
            "src.core.config.settings.jwt_secret",
            "test-secret-key-min-32-chars-long-for-hs256",
        )
        from main import app
        from starlette.testclient import TestClient
        test_client = TestClient(app)
        response = test_client.post(
            "/api/v1/auth/login",
            json={"mail": "user@example.com"},
        )
        assert response.status_code == 422


@pytest.mark.no_auth_override
class TestProtectedRoute:
    """GET /api/v1/auth/me — requires auth."""

    def test_me_returns_401_without_token(self, client: TestClient) -> None:
        """GET /auth/me without token returns 401."""
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 401
        assert "Authentication required" in response.json().get("detail", "")

    def test_me_returns_401_with_invalid_token(self, client: TestClient) -> None:
        """GET /auth/me with invalid token returns 401."""
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid-token"},
        )
        assert response.status_code == 401

    def test_me_returns_200_with_valid_token(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GET /auth/me with valid JWT returns user info."""
        monkeypatch.setattr(
            "src.core.config.settings.jwt_secret",
            "test-secret-key-min-32-chars-long-for-hs256",
        )
        monkeypatch.setattr("src.core.config.settings.debug", True)
        monkeypatch.setattr("src.core.config.settings.dev_login_bypass_enabled", True)
        _patch_login_db_no_user(monkeypatch)
        from main import app
        from starlette.testclient import TestClient
        test_client = TestClient(app)
        login_resp = test_client.post(
            "/api/v1/auth/login",
            json={"mail": "u@x.com", "password": "p"},
        )
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]
        me_resp = test_client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert me_resp.status_code == 200
        data = me_resp.json()
        assert data["user_id"] == "dev-user"
        assert "tenant_id" in data
        assert "is_api_key" in data
        assert data["is_api_key"] is False

    def test_me_returns_200_with_api_key(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GET /auth/me with valid X-API-Key returns user info."""
        monkeypatch.setattr(
            "src.core.config.settings.jwt_secret",
            "test-secret-key-min-32-chars-long-for-hs256",
        )
        monkeypatch.setattr("src.core.config.settings.api_keys", ["test-argus-api-key-one"])
        from main import app
        from starlette.testclient import TestClient
        test_client = TestClient(app)
        response = test_client.get(
            "/api/v1/auth/me",
            headers={"X-API-Key": "test-argus-api-key-one"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_api_key"] is True
        assert data["user_id"] == "api-key"
