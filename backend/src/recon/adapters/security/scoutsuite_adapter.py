"""ScoutSuite adapter — multi-cloud security (stub)."""

from typing import Any

from src.recon.adapters.security.base import SecurityToolAdapter


class ScoutSuiteAdapter(SecurityToolAdapter):
    """Stub adapter for ScoutSuite — multi-cloud security assessment."""

    @property
    def name(self) -> str:
        return "scoutsuite"

    @property
    def command_name(self) -> str:
        return "scout"

    @property
    def supported_stages(self) -> list[int]:
        return [12]

    async def build_command(self, target: str, config: dict[str, Any]) -> list[str]:
        return ["scout", "aws"]

    async def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []

    async def normalize(
        self, raw_results: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        return []
