"""TruffleHog adapter — secrets in repos (stub). Run in sandbox when config allows."""

from typing import Any

from src.recon.adapters.security.base import SecurityToolAdapter


class TruffleHogAdapter(SecurityToolAdapter):
    """Stub adapter for TruffleHog — secrets in repos."""

    @property
    def name(self) -> str:
        return "trufflehog"

    @property
    def command_name(self) -> str:
        return "trufflehog"

    @property
    def supported_stages(self) -> list[int]:
        return [10]

    async def build_command(self, target: str, config: dict[str, Any]) -> list[str]:
        return ["trufflehog", "filesystem", target, "--json"]

    async def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []

    async def normalize(
        self, raw_results: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        return []
