"""FIX-002: Config defaults (CORS, passwords) and .env.example has no real keys."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from pydantic import ValidationError


ARGUS_ROOT = Path(__file__).resolve().parent.parent.parent
ENV_EXAMPLE_PATH = ARGUS_ROOT / "infra" / ".env.example"

REAL_KEY_PATTERNS = re.compile(
    r"(?:"
    r"sk-or-v1-[a-zA-Z0-9]"
    r"|sk-proj-[a-zA-Z0-9]"
    r"|sk-[a-zA-Z0-9]{20,}"
    r"|pplx-[a-zA-Z0-9]"
    r"|AIzaSy[a-zA-Z0-9]"
    r"|ghp_[a-zA-Z0-9]{36}"
    r"|gho_[a-zA-Z0-9]{36}"
    r")"
)


class TestConfigCorsDefault:
    """CORS_ORIGINS default must not be wildcard '*'."""

    def test_cors_default_is_not_wildcard(self) -> None:
        from src.core.config import Settings

        s = Settings(
            _env_file=None,
            cors_origins="http://localhost:3000",
            jwt_secret="test-secret",
            database_url="postgresql+asyncpg://test:test@localhost/test",
            minio_secret_key="test-secret",
        )
        assert s.cors_origins != "*"

    def test_settings_default_cors_value(self) -> None:
        from src.core.config import Settings

        s = Settings(
            _env_file=None,
            jwt_secret="test-secret",
            database_url="postgresql+asyncpg://test:test@localhost/test",
            minio_secret_key="test-secret",
        )
        assert s.cors_origins.strip() != "*"


class TestConfigDatabaseDefault:
    """Empty database_url / minio_secret_key must raise in production."""

    def test_empty_database_url_raises_in_prod(self) -> None:
        from src.core.config import Settings

        with pytest.raises(ValidationError, match="DATABASE_URL"):
            Settings(
                _env_file=None,
                jwt_secret="test-secret",
                database_url="",
                minio_secret_key="test-secret",
                debug=False,
            )

    def test_empty_minio_secret_raises_in_prod(self) -> None:
        from src.core.config import Settings

        with pytest.raises(ValidationError, match="MINIO_SECRET_KEY"):
            Settings(
                _env_file=None,
                jwt_secret="test-secret",
                database_url="postgresql+asyncpg://test:test@localhost/test",
                minio_secret_key="",
                debug=False,
            )


class TestEnvExampleNoRealKeys:
    """.env.example must not contain real API key patterns."""

    @pytest.fixture(scope="class")
    def env_content(self) -> str:
        if not ENV_EXAMPLE_PATH.exists():
            pytest.skip(f".env.example not found at {ENV_EXAMPLE_PATH}")
        return ENV_EXAMPLE_PATH.read_text(encoding="utf-8")

    def test_no_openai_real_key(self, env_content: str) -> None:
        for line in env_content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if "OPENAI_API_KEY" in stripped and "=" in stripped:
                value = stripped.split("=", 1)[1].strip()
                assert not value.startswith("sk-"), (
                    f"Real OpenAI key detected in .env.example: {value[:12]}..."
                )

    def test_no_real_key_patterns(self, env_content: str) -> None:
        for i, line in enumerate(env_content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            match = REAL_KEY_PATTERNS.search(stripped)
            assert match is None, (
                f"Line {i} in .env.example contains real key pattern: {match.group()[:20]}..."
            )

    def test_passwords_are_placeholders(self, env_content: str) -> None:
        for line in env_content.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if "POSTGRES_PASSWORD=" in stripped:
                value = stripped.split("=", 1)[1].strip()
                assert "change-me" in value.lower() or value == "", (
                    "POSTGRES_PASSWORD must be a placeholder"
                )
