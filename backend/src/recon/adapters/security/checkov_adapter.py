"""Checkov adapter — IaC security (Terraform, etc.) (stub)."""

from typing import Any

from src.recon.adapters.security.base import SecurityToolAdapter


class CheckovAdapter(SecurityToolAdapter):
    """Stub adapter for Checkov — IaC security scanning."""

    @property
    def name(self) -> str:
        return "checkov"

    @property
    def command_name(self) -> str:
        return "checkov"

    @property
    def supported_stages(self) -> list[int]:
        return [12]

    async def build_command(self, target: str, config: dict[str, Any]) -> list[str]:
        return ["checkov", "-d", target or ".", "--output", "json"]

    async def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        return []

    async def normalize(
        self, raw_results: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        return []
