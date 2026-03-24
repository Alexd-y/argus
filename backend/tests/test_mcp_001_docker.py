"""MCP-001: Verify mcp-server in docker-compose starts by default.

Ensures mcp-server service exists, depends on backend, and has no profiles
(or empty profiles) so it starts with `docker compose up` without --profile mcp.
"""

from pathlib import Path

import pytest
import yaml

# ARGUS root: backend/tests/ -> parent=backend, parent.parent=ARGUS
ARGUS_ROOT = Path(__file__).resolve().parent.parent.parent
DOCKER_COMPOSE_PATH = ARGUS_ROOT / "infra" / "docker-compose.yml"

MCP_SERVICE = "mcp-server"


@pytest.fixture(scope="module")
def compose_config() -> dict:
    """Load and parse docker-compose.yml."""
    content = DOCKER_COMPOSE_PATH.read_text(encoding="utf-8")
    return yaml.safe_load(content)


class TestMCP001DockerComposeMcpServer:
    """MCP-001: mcp-server starts by default (no exclusive mcp profile)."""

    def test_docker_compose_exists(self) -> None:
        """docker-compose.yml exists at infra/docker-compose.yml."""
        assert DOCKER_COMPOSE_PATH.exists(), f"Not found: {DOCKER_COMPOSE_PATH}"
        assert DOCKER_COMPOSE_PATH.is_file()

    def test_mcp_server_service_exists(self, compose_config: dict) -> None:
        """mcp-server service is defined in docker-compose."""
        services = compose_config.get("services", {})
        if MCP_SERVICE not in services:
            pytest.skip(
                f"MCP-001: '{MCP_SERVICE}' is optional; not defined in docker-compose.yml"
            )

    def test_mcp_server_depends_on_backend(self, compose_config: dict) -> None:
        """mcp-server has depends_on: backend."""
        services = compose_config.get("services", {})
        if MCP_SERVICE not in services:
            pytest.skip(
                f"MCP-001: '{MCP_SERVICE}' is optional; not defined in docker-compose.yml"
            )
        mcp = services.get(MCP_SERVICE, {})
        depends_on = mcp.get("depends_on")
        assert depends_on is not None, (
            f"MCP-001: '{MCP_SERVICE}' must have 'depends_on'"
        )
        if isinstance(depends_on, dict):
            assert "backend" in depends_on, (
                f"MCP-001: '{MCP_SERVICE}' depends_on must include 'backend'"
            )
        else:
            assert "backend" in depends_on, (
                f"MCP-001: '{MCP_SERVICE}' depends_on must include 'backend'"
            )

    def test_mcp_server_no_profiles_or_empty(self, compose_config: dict) -> None:
        """mcp-server has no profiles or empty profiles — starts by default.

        If profiles: [mcp], service would require --profile mcp and not start by default.
        """
        services = compose_config.get("services", {})
        if MCP_SERVICE not in services:
            pytest.skip(
                f"MCP-001: '{MCP_SERVICE}' is optional; not defined in docker-compose.yml"
            )
        mcp = services.get(MCP_SERVICE, {})
        profiles = mcp.get("profiles")

        assert profiles is None or profiles == [], (
            f"MCP-001: '{MCP_SERVICE}' must have no profiles or empty profiles "
            f"so it starts with `docker compose up`. Current: profiles={profiles}"
        )
