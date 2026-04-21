"""H-8: Aggressive VA defaults are disabled in .env.example."""

from __future__ import annotations

from pathlib import Path

ENV_EXAMPLE = Path(__file__).resolve().parents[2] / "infra" / ".env.example"


class TestEnvExampleDefaults:
    """Dangerous scanning tools must be disabled by default in .env.example."""

    def test_env_example_exists(self) -> None:
        assert ENV_EXAMPLE.exists(), f".env.example not found at {ENV_EXAMPLE}"

    def test_sqlmap_disabled_by_default(self) -> None:
        content = ENV_EXAMPLE.read_text(encoding="utf-8")
        assert "SQLMAP_VA_ENABLED=false" in content, (
            "SQLMAP_VA_ENABLED must be explicitly set to false in .env.example"
        )

    def test_va_exploit_aggressive_disabled(self) -> None:
        content = ENV_EXAMPLE.read_text(encoding="utf-8")
        assert "VA_EXPLOIT_AGGRESSIVE_ENABLED=false" in content, (
            "VA_EXPLOIT_AGGRESSIVE_ENABLED must be explicitly set to false in .env.example"
        )
