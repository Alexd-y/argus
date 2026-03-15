"""LLM-001: Verify docker-compose.yml contains all required LLM env vars.

Ensures backend and celery-worker services have DEEPSEEK_API_KEY, GOOGLE_API_KEY,
KIMI_API_KEY, PERPLEXITY_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY.
"""

from pathlib import Path

import pytest
import yaml

# ARGUS root: backend/tests/ -> parent=backend, parent.parent=ARGUS
ARGUS_ROOT = Path(__file__).resolve().parent.parent.parent
DOCKER_COMPOSE_PATH = ARGUS_ROOT / "infra" / "docker-compose.yml"

REQUIRED_LLM_ENV_VARS = [
    "OPENAI_API_KEY",
    "DEEPSEEK_API_KEY",
    "OPENROUTER_API_KEY",
    "GOOGLE_API_KEY",
    "KIMI_API_KEY",
    "PERPLEXITY_API_KEY",
]

SERVICES_WITH_LLM = ["backend", "celery-worker"]


@pytest.fixture(scope="module")
def compose_config() -> dict:
    """Load and parse docker-compose.yml."""
    content = DOCKER_COMPOSE_PATH.read_text(encoding="utf-8")
    return yaml.safe_load(content)


class TestLLM001DockerComposeLLMKeys:
    """LLM-001: All LLM keys present in docker-compose for backend and celery-worker."""

    def test_docker_compose_exists(self) -> None:
        """docker-compose.yml exists at infra/docker-compose.yml."""
        assert DOCKER_COMPOSE_PATH.exists(), f"Not found: {DOCKER_COMPOSE_PATH}"
        assert DOCKER_COMPOSE_PATH.is_file()

    def test_docker_compose_valid_yaml(self, compose_config: dict) -> None:
        """docker-compose.yml is valid YAML."""
        assert compose_config is not None
        assert isinstance(compose_config, dict)
        assert "services" in compose_config

    @pytest.mark.parametrize("service", SERVICES_WITH_LLM)
    def test_service_has_environment_section(
        self, compose_config: dict, service: str
    ) -> None:
        """Backend and celery-worker have environment section."""
        services = compose_config.get("services", {})
        assert service in services, f"Service '{service}' must be defined"
        env = services[service].get("environment")
        assert env is not None, f"Service '{service}' must have 'environment'"
        assert isinstance(env, dict), f"Service '{service}' environment must be dict"

    @pytest.mark.parametrize("service", SERVICES_WITH_LLM)
    @pytest.mark.parametrize("key", REQUIRED_LLM_ENV_VARS)
    def test_service_has_llm_env_var(
        self, compose_config: dict, service: str, key: str
    ) -> None:
        """Each LLM env var is present in backend and celery-worker."""
        services = compose_config.get("services", {})
        env = services.get(service, {}).get("environment", {})
        assert key in env, (
            f"LLM-001: '{key}' must be in {service}.environment "
            f"(docker-compose.yml)"
        )
