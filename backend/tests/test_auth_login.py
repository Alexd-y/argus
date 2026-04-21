"""Block 9 — auth login and admin hardening (no network)."""

from unittest.mock import MagicMock

import pytest
from starlette.testclient import TestClient


def _patch_login_db_no_user(monkeypatch: pytest.MonkeyPatch) -> None:
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


def _patch_login_db_with_user(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    user = MagicMock()
    user.id = "user-uuid-1"
    user.tenant_id = "tenant-1"
    user.email = "real@example.com"
    user.is_active = True
    user.password_hash = "$2b$12$dummyhash"

    class _Sess:
        async def execute(self, *_args, **_kwargs):
            class _R:
                def scalar_one_or_none(self):
                    return user

            return _R()

    class _CM:
        async def __aenter__(self):
            return _Sess()

        async def __aexit__(self, *_args):
            return None

    monkeypatch.setattr("src.api.routers.auth.async_session_factory", lambda: _CM())
    return user


class TestAuthLoginBlock9:
    def test_jwt_secret_missing_returns_503(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("src.core.config.settings.jwt_secret", "")
        from main import app

        tc = TestClient(app)
        r = tc.post(
            "/api/v1/auth/login",
            json={"mail": "any@example.com", "password": "x"},
        )
        assert r.status_code == 503
        assert "JWT_SECRET" in (r.json().get("detail") or "")

    def test_dev_debug_login_when_no_db_user(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret = "test-secret-key-min-32-chars-long-for-hs256"
        monkeypatch.setattr("src.core.config.settings.jwt_secret", secret)
        monkeypatch.setattr("src.core.config.settings.debug", True)
        monkeypatch.setattr("src.core.config.settings.dev_login_bypass_enabled", True)
        _patch_login_db_no_user(monkeypatch)
        from main import app

        tc = TestClient(app)
        r = tc.post(
            "/api/v1/auth/login",
            json={"mail": "dev@local", "password": "anything"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body.get("status") == "success"
        assert body.get("dev_mode") is True
        assert body.get("access_token")

    def test_wrong_password_returns_401_when_debug_off(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret = "test-secret-key-min-32-chars-long-for-hs256"
        monkeypatch.setattr("src.core.config.settings.jwt_secret", secret)
        monkeypatch.setattr("src.core.config.settings.debug", False)
        _patch_login_db_with_user(monkeypatch)
        monkeypatch.setattr("src.api.routers.auth._pwd_context.verify", lambda *_a, **_k: False)
        from main import app

        tc = TestClient(app)
        r = tc.post(
            "/api/v1/auth/login",
            json={"mail": "real@example.com", "password": "wrong-password"},
        )
        assert r.status_code == 401
        assert (r.json().get("detail") or "").lower().find("invalid") >= 0

    def test_require_admin_503_without_key_in_prod_mode(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("src.core.config.settings.admin_api_key", "")
        monkeypatch.setattr("src.core.config.settings.debug", False)
        r = client.get("/api/v1/cache/stats")
        assert r.status_code == 503
