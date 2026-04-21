"""Tests for admin default-deny and metrics auth (H-8, H-9)."""

from __future__ import annotations

import pytest


class TestAdminDefaultDeny:
    """H-8: Admin router returns 503 when ADMIN_API_KEY is not set."""

    def test_admin_requires_api_key_config(self) -> None:
        """Settings without admin_api_key should have None."""
        from src.core.config import Settings

        s = Settings(_env_file=None, jwt_secret="test", debug=True)
        assert s.admin_api_key is None

    def test_admin_api_key_stored_as_secret(self) -> None:
        """admin_api_key should be SecretStr type."""
        from src.core.config import Settings

        s = Settings(
            _env_file=None, jwt_secret="test", admin_api_key="my-secret",
            database_url="postgresql+asyncpg://test:test@localhost/test",
            minio_secret_key="test-secret",
        )
        assert s.admin_api_key is not None
        assert s.admin_api_key.get_secret_value() == "my-secret"

    def test_admin_api_key_not_leaked_via_str(self) -> None:
        """SecretStr repr/str must not expose the value."""
        from src.core.config import Settings

        s = Settings(
            _env_file=None, jwt_secret="test", admin_api_key="super-secret-key",
            database_url="postgresql+asyncpg://test:test@localhost/test",
            minio_secret_key="test-secret",
        )
        assert "super-secret-key" not in str(s.admin_api_key)
        assert "super-secret-key" not in repr(s.admin_api_key)

    def test_require_admin_raises_503_when_no_key(self) -> None:
        """require_admin dependency must raise 503 when ADMIN_API_KEY is unset."""
        from pathlib import Path

        admin_src = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "api"
            / "routers"
            / "admin.py"
        )
        text = admin_src.read_text(encoding="utf-8")
        assert "503" in text or "HTTP_503_SERVICE_UNAVAILABLE" in text
        assert "Admin API disabled" in text


class TestMetricsAuth:
    """H-9: /metrics requires bearer token."""

    def test_metrics_token_default_none(self) -> None:
        from src.core.config import Settings

        s = Settings(_env_file=None, jwt_secret="test", debug=True)
        assert s.metrics_token is None

    def test_metrics_token_configurable(self) -> None:
        from src.core.config import Settings

        s = Settings(
            _env_file=None, jwt_secret="test", metrics_token="prom-token-123",
            database_url="postgresql+asyncpg://test:test@localhost/test",
            minio_secret_key="test-secret",
        )
        assert s.metrics_token == "prom-token-123"

    def test_metrics_token_in_env_example(self) -> None:
        """METRICS_TOKEN should be documented in .env.example."""
        from pathlib import Path

        env = (
            Path(__file__).resolve().parent.parent.parent
            / "infra"
            / ".env.example"
        )
        text = env.read_text(encoding="utf-8")
        assert "METRICS_TOKEN" in text
