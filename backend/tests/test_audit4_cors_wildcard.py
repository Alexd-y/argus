"""M-19: CORS wildcard rejected in production."""

from __future__ import annotations

import pytest


class TestCorsWildcardRejection:
    """Settings with cors_origins='*' and debug=False must raise ValueError."""

    def test_cors_wildcard_rejected_in_prod(self) -> None:
        from src.core.config import Settings

        with pytest.raises(ValueError, match="(?i)cors.*wildcard|wildcard.*not allowed"):
            Settings(
                _env_file=None,
                cors_origins="*",
                debug=False,
                jwt_secret="test-secret-32chars-for-validation",
                database_url="postgresql+asyncpg://test:test@localhost/test",
                minio_secret_key="test-secret",
            )

    def test_cors_wildcard_allowed_in_debug(self) -> None:
        from src.core.config import Settings

        s = Settings(
            _env_file=None,
            cors_origins="*",
            debug=True,
            jwt_secret="test",
        )
        assert s.cors_origins == "*"

    def test_explicit_origin_allowed_in_prod(self) -> None:
        from src.core.config import Settings

        s = Settings(
            _env_file=None,
            cors_origins="https://app.example.com",
            debug=False,
            jwt_secret="test-secret-32chars-for-validation",
            database_url="postgresql+asyncpg://test:test@localhost/test",
            minio_secret_key="test-secret",
        )
        assert s.cors_origins == "https://app.example.com"
