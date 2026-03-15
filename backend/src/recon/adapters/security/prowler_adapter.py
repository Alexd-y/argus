"""Prowler adapter — AWS security (stub)."""

from typing import Any

from src.recon.adapters.security.base import SecurityToolAdapter


class ProwlerAdapter(SecurityToolAdapter):
    """Stub adapter for Prowler — AWS security assessment."""

    @property
    def name(self) -> str:
        return "prowler"

    @property
    def command_name(self) -> str:
        return "prowler"

    @property
    def supported_stages(self) -> list[int]:
        return [12]

    async def build_command(self, target: str, config: dict[str, Any]) -> list[str]:
        return ["prowler", "aws", "--output-format", "json"]

    async def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []

    async def normalize(
        self, raw_results: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        return []
