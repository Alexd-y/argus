"""Tests for infrastructure changes (M-9, M-10, M-12, M-13, M-14, L-3, L-4, L-8)."""

from __future__ import annotations

import re
from pathlib import Path

ARGUS_ROOT = Path(__file__).resolve().parent.parent.parent


class TestMcpEntrypoint:
    """M-9: Only argus_mcp.py should be the MCP entrypoint."""

    def test_no_mcp_main_py(self) -> None:
        main = ARGUS_ROOT / "mcp-server" / "main.py"
        assert not main.exists(), "mcp-server/main.py should be deleted"

    def test_argus_mcp_py_exists(self) -> None:
        mcp = ARGUS_ROOT / "mcp-server" / "argus_mcp.py"
        assert mcp.exists(), "mcp-server/argus_mcp.py missing"


class TestKaliRegistryDocstring:
    """M-10: Kali registry should not claim 150+ tools."""

    def test_no_150_plus_claim(self) -> None:
        registry = ARGUS_ROOT / "mcp-server" / "tools" / "kali_registry.py"
        assert registry.exists(), "kali_registry.py must exist in the project"
        text = registry.read_text(encoding="utf-8")
        assert "150+" not in text


class TestWorkerHealthcheck:
    """M-12: Worker should depend on service_healthy."""

    def test_worker_depends_on_healthy(self) -> None:
        compose = ARGUS_ROOT / "infra" / "docker-compose.yml"
        text = compose.read_text(encoding="utf-8")
        assert "service_healthy" in text

    def test_no_service_started_for_critical_deps(self) -> None:
        """Backend and worker should use service_healthy, not service_started."""
        compose = ARGUS_ROOT / "infra" / "docker-compose.yml"
        text = compose.read_text(encoding="utf-8")
        assert "service_started" not in text, (
            "service_started found — all deps should use service_healthy"
        )


class TestMcpPort:
    """M-13: MCP default port should be 8765."""

    def test_mcp_default_port(self) -> None:
        mcp = ARGUS_ROOT / "mcp-server" / "argus_mcp.py"
        text = mcp.read_text(encoding="utf-8")
        assert "8765" in text

    def test_mcp_port_in_env_example(self) -> None:
        env = ARGUS_ROOT / "infra" / ".env.example"
        text = env.read_text(encoding="utf-8")
        assert "ARGUS_MCP_PORT" in text
        assert "8765" in text


class TestCorsSettingsField:
    """M-14: cors_include_dev_origins should be a Settings field."""

    def test_cors_dev_origins_in_settings(self) -> None:
        from src.core.config import Settings

        assert "cors_include_dev_origins" in Settings.model_fields


class TestDeprecatedSteps:
    """L-3: STUB_STEPS renamed to DEPRECATED_STEPS."""

    def test_deprecated_steps_exists(self) -> None:
        registry = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "recon"
            / "step_registry.py"
        )
        text = registry.read_text(encoding="utf-8")
        assert "DEPRECATED_STEPS" in text


class TestNoVercelUrls:
    """L-4: No real Vercel URLs in .env.example."""

    def test_no_vercel_urls(self) -> None:
        env = ARGUS_ROOT / "infra" / ".env.example"
        text = env.read_text(encoding="utf-8")
        assert "vercel.app" not in text.lower()


class TestNoRussianInEnvExample:
    """L-8: No Russian comments in .env.example."""

    def test_no_cyrillic(self) -> None:
        env = ARGUS_ROOT / "infra" / ".env.example"
        text = env.read_text(encoding="utf-8")
        cyrillic = re.findall(r"[а-яА-ЯёЁ]+", text)
        assert cyrillic == [], f"Found Cyrillic: {cyrillic[:5]}"
