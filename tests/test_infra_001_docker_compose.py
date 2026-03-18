"""INFRA-001: Validate docker-compose.yml for ARGUS infrastructure.

Validates:
- docker-compose.yml syntax (YAML parse + optional docker compose config)
- All required services: postgres, redis, minio, backend, worker, nginx
- Networks: frontend, backend, data
- Volumes: postgres_data, redis_data, minio_data
"""

import subprocess
from pathlib import Path

import pytest
import yaml

ARGUS_ROOT = Path(__file__).resolve().parent.parent
DOCKER_COMPOSE_PATH = ARGUS_ROOT / "infra" / "docker-compose.yml"

REQUIRED_SERVICES = ["postgres", "redis", "minio", "backend", "worker", "nginx"]
REQUIRED_NETWORKS = ["frontend", "backend", "data"]
REQUIRED_VOLUMES = ["postgres_data", "redis_data", "minio_data"]


@pytest.fixture(scope="module")
def compose_config() -> dict:
    """Load and parse docker-compose.yml."""
    content = DOCKER_COMPOSE_PATH.read_text(encoding="utf-8")
    return yaml.safe_load(content)


class TestInfra001DockerComposeSyntax:
    """INFRA-001: docker-compose.yml syntax validation."""

    def test_docker_compose_exists(self) -> None:
        """docker-compose.yml exists at infra/docker-compose.yml."""
        assert DOCKER_COMPOSE_PATH.exists(), f"Not found: {DOCKER_COMPOSE_PATH}"
        assert DOCKER_COMPOSE_PATH.is_file()

    def test_docker_compose_valid_yaml(self, compose_config: dict) -> None:
        """docker-compose.yml is valid YAML and has required top-level keys."""
        assert compose_config is not None
        assert isinstance(compose_config, dict)
        assert "services" in compose_config
        assert isinstance(compose_config["services"], dict)

    def test_docker_compose_config_valid(self) -> None:
        """docker compose config validates syntax (skips if Docker unavailable)."""
        infra_dir = ARGUS_ROOT / "infra"
        env_path = infra_dir / ".env"
        env_example = infra_dir / ".env.example"
        if not env_path.exists() and env_example.exists():
            env_path.write_text(env_example.read_text(encoding="utf-8"), encoding="utf-8")
        try:
            result = subprocess.run(
                ["docker", "compose", "-f", "docker-compose.yml", "config"],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(infra_dir),
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pytest.skip("Docker not available or timed out")
        assert result.returncode == 0, (
            f"docker compose config failed: {result.stderr}"
        )


class TestInfra001DockerComposeServices:
    """INFRA-001: All required services are defined."""

    @pytest.mark.parametrize("service", REQUIRED_SERVICES)
    def test_service_defined(self, compose_config: dict, service: str) -> None:
        """Each required service must be defined in docker-compose.yml."""
        services = compose_config.get("services", {})
        assert service in services, (
            f"INFRA-001: Service '{service}' must be defined in docker-compose.yml"
        )

    def test_backend_has_build_context(self, compose_config: dict) -> None:
        """Backend service must have build context pointing to ../backend."""
        backend = compose_config.get("services", {}).get("backend", {})
        assert "build" in backend, "backend must have build section"
        assert "context" in backend["build"]
        assert backend["build"]["context"] == "../backend"

    def test_worker_has_build_context(self, compose_config: dict) -> None:
        """Worker service must have build section (context: . or ../backend, inherits from backend)."""
        worker = compose_config.get("services", {}).get("worker", {})
        assert "build" in worker, "worker must have build section"
        assert "context" in worker["build"]
        # Worker may use context: . (infra) with Dockerfile FROM argus-backend, or context: ../backend
        ctx = worker["build"]["context"]
        assert ctx in (".", "../backend"), f"worker build context must be . or ../backend, got {ctx}"

    @pytest.mark.parametrize("service", ["postgres", "redis", "minio", "backend", "worker", "nginx"])
    def test_service_has_healthcheck(self, compose_config: dict, service: str) -> None:
        """Each service must have healthcheck defined."""
        services = compose_config.get("services", {})
        svc = services.get(service, {})
        assert "healthcheck" in svc, (
            f"INFRA-001: Service '{service}' must have healthcheck"
        )
        hc = svc["healthcheck"]
        assert "test" in hc, f"Service '{service}' healthcheck must have 'test'"


class TestInfra001DockerComposeNetworks:
    """INFRA-001: Required networks are defined."""

    def test_networks_section_exists(self, compose_config: dict) -> None:
        """docker-compose must have networks section."""
        assert "networks" in compose_config
        assert isinstance(compose_config["networks"], dict)

    @pytest.mark.parametrize("network", REQUIRED_NETWORKS)
    def test_network_defined(self, compose_config: dict, network: str) -> None:
        """Each required network must be defined."""
        networks = compose_config.get("networks", {})
        assert network in networks, (
            f"INFRA-001: Network '{network}' must be defined in docker-compose.yml"
        )

    def test_data_services_not_on_frontend_network(self, compose_config: dict) -> None:
        """Data services (postgres, redis, minio) must NOT be on frontend network."""
        services = compose_config.get("services", {})
        data_services = ["postgres", "redis", "minio"]
        frontend_network = "frontend"
        for svc_name in data_services:
            svc = services.get(svc_name, {})
            networks = svc.get("networks", [])
            assert frontend_network not in networks, (
                f"INFRA-001: Data service '{svc_name}' must NOT be on '{frontend_network}' "
                "network (security: isolate data layer from frontend)"
            )

    def test_data_ports_not_exposed_in_main_compose(self, compose_config: dict) -> None:
        """Postgres, redis, minio must have no ports in main compose (security: data services not exposed in production)."""
        services = compose_config.get("services", {})
        data_services = ["postgres", "redis", "minio"]
        for svc_name in data_services:
            svc = services.get(svc_name, {})
            ports = svc.get("ports")
            assert not ports, (
                f"INFRA-001: Data service '{svc_name}' must NOT expose ports in main compose "
                "(security: data services not exposed in production; use docker-compose.dev.yml for dev)"
            )


class TestInfra001DockerComposeVolumes:
    """INFRA-001: Required volumes are defined."""

    def test_volumes_section_exists(self, compose_config: dict) -> None:
        """docker-compose must have volumes section."""
        assert "volumes" in compose_config
        assert isinstance(compose_config["volumes"], dict)

    @pytest.mark.parametrize("volume", REQUIRED_VOLUMES)
    def test_volume_defined(self, compose_config: dict, volume: str) -> None:
        """Each required volume must be defined."""
        volumes = compose_config.get("volumes", {})
        assert volume in volumes, (
            f"INFRA-001: Volume '{volume}' must be defined in docker-compose.yml"
        )
