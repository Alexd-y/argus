"""Terrascan adapter — IaC security (stub)."""

from typing import Any

from src.recon.adapters.security.base import SecurityToolAdapter


class TerrascanAdapter(SecurityToolAdapter):
    """Stub adapter for Terrascan — IaC security scanning."""

    @property
    def name(self) -> str:
        return "terrascan"

    @property
    def command_name(self) -> str:
        return "terrascan"

    @property
    def supported_stages(self) -> list[int]:
        return [12]

    async def build_command(self, target: str, config: dict[str, Any]) -> list[str]:
        return ["terrascan", "scan", "-d", target or ".", "-o", "json"]

    async def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []

    async def normalize(
        self, raw_results: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        return []
