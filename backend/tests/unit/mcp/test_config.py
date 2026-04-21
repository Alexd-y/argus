"""Unit tests for the MCP-specific knobs on :class:`Settings`.

The MCP server reads its transport / auth / config-path defaults from
``backend/src/core/config.py`` (Pydantic Settings). The following tests
guard the contract: defaults stay sane, env vars override correctly, and
the port validator refuses out-of-range values.
"""

from __future__ import annotations

import pytest

from src.core.config import Settings


class TestDefaults:
    def test_transport_defaults_to_stdio(self) -> None:
        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.mcp_transport == "stdio"

    def test_http_host_defaults_loopback(self) -> None:
        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.mcp_http_host == "127.0.0.1"

    def test_http_port_default(self) -> None:
        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.mcp_http_port == 8765

    def test_server_name_default(self) -> None:
        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.mcp_server_name == "argus"

    def test_log_level_default(self) -> None:
        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.mcp_log_level == "INFO"

    def test_auth_token_default_none(self) -> None:
        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.mcp_auth_token is None

    def test_stdio_actor_default(self) -> None:
        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.mcp_stdio_actor_id == "local-stdio"

    def test_config_path_defaults(self) -> None:
        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.mcp_config_path.endswith("server.yaml")
        assert s.mcp_config_signatures_path.endswith("SIGNATURES")
        assert s.mcp_config_keys_dir.endswith("_keys")


class TestPortValidation:
    @pytest.mark.parametrize("port", [0, -1, 65_536, 100_000])
    def test_invalid_port_rejected(self, port: int) -> None:
        with pytest.raises(Exception):
            Settings(_env_file=None, mcp_http_port=port)  # type: ignore[call-arg]

    @pytest.mark.parametrize("port", [1, 80, 8080, 65_535])
    def test_valid_port_accepted(self, port: int) -> None:
        s = Settings(_env_file=None, mcp_http_port=port)  # type: ignore[call-arg]
        assert s.mcp_http_port == port


class TestEnvOverrides:
    def test_env_overrides_transport(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MCP_TRANSPORT", "streamable-http")
        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.mcp_transport == "streamable-http"

    def test_env_overrides_auth_token(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MCP_AUTH_TOKEN", "deadbeef" * 4)
        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.mcp_auth_token == "deadbeef" * 4

    def test_env_overrides_log_level(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MCP_LOG_LEVEL", "WARNING")
        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.mcp_log_level == "WARNING"

    def test_env_overrides_stdio_tenant(self, monkeypatch: pytest.MonkeyPatch) -> None:
        custom_tenant = "00000000-0000-0000-0000-00000000abcd"
        monkeypatch.setenv("MCP_STDIO_TENANT_ID", custom_tenant)
        s = Settings(_env_file=None)  # type: ignore[call-arg]
        assert s.mcp_stdio_tenant_id == custom_tenant
