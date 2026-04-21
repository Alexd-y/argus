"""H-4: Compose uses required env vars for secrets."""

from __future__ import annotations

from pathlib import Path

COMPOSE_FILE = Path(__file__).resolve().parents[2] / "infra" / "docker-compose.yml"


class TestComposeSecrets:
    """Docker compose must require secrets via :? syntax (no fallbacks)."""

    def test_compose_file_exists(self) -> None:
        assert COMPOSE_FILE.exists(), f"docker-compose.yml not found at {COMPOSE_FILE}"

    def test_compose_requires_postgres_password(self) -> None:
        content = COMPOSE_FILE.read_text(encoding="utf-8")
        assert "${POSTGRES_PASSWORD:?" in content, "POSTGRES_PASSWORD must be required"
        assert "${POSTGRES_PASSWORD:-argus}" not in content, "POSTGRES_PASSWORD must not have fallback"

    def test_compose_requires_minio_secret(self) -> None:
        content = COMPOSE_FILE.read_text(encoding="utf-8")
        assert "${MINIO_SECRET_KEY:?" in content, "MINIO_SECRET_KEY must be required"
        assert "${MINIO_SECRET_KEY:-argussecret}" not in content, "MINIO_SECRET_KEY must not have fallback"

    def test_compose_requires_jwt_secret(self) -> None:
        content = COMPOSE_FILE.read_text(encoding="utf-8")
        assert "${JWT_SECRET:?" in content, "JWT_SECRET must be required"
        assert "dev-secret-change-in-prod" not in content, "JWT_SECRET must not use dev fallback"
