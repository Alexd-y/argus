"""Docker tests for ARGUS-002 (Phase 1: Project Structure & Infra).

Проверяет валидность docker-compose конфигурации через YAML parse.
"""

from pathlib import Path

import pytest
import yaml

ARGUS_ROOT = Path(__file__).resolve().parent.parent
DOCKER_COMPOSE_PATH = ARGUS_ROOT / "infra" / "docker-compose.yml"

# Required services from Phase 1
REQUIRED_SERVICES = ["postgres", "minio", "redis", "backend", "sandbox"]

# Required volumes
REQUIRED_VOLUMES = ["argus_postgres_data", "argus_minio_data", "argus_redis_data"]


@pytest.fixture(scope="module")
def compose_config() -> dict:
    """Загружает и парсит docker-compose.yml."""
    content = DOCKER_COMPOSE_PATH.read_text(encoding="utf-8")
    return yaml.safe_load(content)


class TestDockerComposeFile:
    """Базовые проверки docker-compose.yml."""

    def test_file_exists(self) -> None:
        """docker-compose.yml должен существовать."""
        assert DOCKER_COMPOSE_PATH.exists()
        assert DOCKER_COMPOSE_PATH.is_file()

    def test_yaml_parseable(self) -> None:
        """docker-compose.yml должен быть валидным YAML."""
        content = DOCKER_COMPOSE_PATH.read_text(encoding="utf-8")
        config = yaml.safe_load(content)
        assert config is not None
        assert isinstance(config, dict)

    def test_has_services_section(self, compose_config: dict) -> None:
        """Должна быть секция services."""
        assert "services" in compose_config
        assert isinstance(compose_config["services"], dict)

    def test_has_volumes_section(self, compose_config: dict) -> None:
        """Должна быть секция volumes."""
        assert "volumes" in compose_config
        assert isinstance(compose_config["volumes"], dict)


class TestDockerComposeServices:
    """Проверка обязательных сервисов."""

    @pytest.mark.parametrize("service", REQUIRED_SERVICES)
    def test_service_defined(self, compose_config: dict, service: str) -> None:
        """Каждый обязательный сервис Phase 1 должен быть определён."""
        services = compose_config.get("services", {})
        assert service in services, f"Service '{service}' must be defined in docker-compose.yml"

    def test_backend_has_build_context(self, compose_config: dict) -> None:
        """Backend сервис должен иметь build context."""
        backend = compose_config.get("services", {}).get("backend", {})
        assert "build" in backend
        assert "context" in backend["build"]
        assert backend["build"]["context"] == "../backend"

    def test_postgres_has_healthcheck(self, compose_config: dict) -> None:
        """Postgres должен иметь healthcheck."""
        postgres = compose_config.get("services", {}).get("postgres", {})
        assert "healthcheck" in postgres

    def test_redis_has_healthcheck(self, compose_config: dict) -> None:
        """Redis должен иметь healthcheck."""
        redis = compose_config.get("services", {}).get("redis", {})
        assert "healthcheck" in redis


class TestDockerComposeVolumes:
    """Проверка volumes."""

    @pytest.mark.parametrize("volume", REQUIRED_VOLUMES)
    def test_volume_defined(self, compose_config: dict, volume: str) -> None:
        """Каждый обязательный volume должен быть определён."""
        volumes = compose_config.get("volumes", {})
        assert volume in volumes, f"Volume '{volume}' must be defined"
