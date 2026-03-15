"""Subfinder adapter — passive subdomain enumeration."""

import json
import logging
from typing import Any

from src.recon.adapters.base import ToolAdapter
from src.recon.schemas.base import FindingType

logger = logging.getLogger(__name__)


class SubfinderAdapter(ToolAdapter):
    """Adapter for subfinder tool output parsing and normalization."""

    @property
    def name(self) -> str:
        return "subfinder"

    @property
    def supported_stages(self) -> list[int]:
        return [2]  # SUBDOMAIN_ENUM

    async def build_command(self, target: str, config: dict[str, Any]) -> list[str]:
        cmd = ["subfinder", "-d", target, "-silent"]
        if config.get("json_output", True):
            cmd.append("-json")
        if config.get("timeout"):
            cmd.extend(["-timeout", str(config["timeout"])])
        if config.get("max_time"):
            cmd.extend(["-max-time", str(config["max_time"])])
        return cmd

    async def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse subfinder output — supports both plain text and JSON lines."""
        results: list[dict[str, Any]] = []
        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append({
                    "subdomain": data.get("host", line),
                    "source": data.get("source", "subfinder"),
                    "ip": data.get("ip", ""),
                })
            except json.JSONDecodeError:
                if "." in line and not line.startswith("#"):
                    results.append({
                        "subdomain": line.lower().rstrip("."),
                        "source": "subfinder",
                        "ip": "",
                    })
        return results

    async def normalize(
        self, raw_results: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Normalize to canonical SubdomainFinding format."""
        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in raw_results:
            sub = item.get("subdomain", "").lower().strip().rstrip(".")
            if not sub or sub in seen:
                continue
            seen.add(sub)
            findings.append({
                "finding_type": FindingType.SUBDOMAIN,
                "value": sub,
                "data": {
                    "subdomain": sub,
                    "source": item.get("source", "subfinder"),
                    "is_wildcard": sub.startswith("*."),
                    "parent_domain": (
                        ".".join(sub.split(".")[-2:]) if "." in sub else sub
                    ),
                },
                "source_tool": "subfinder",
                "confidence": 0.8,
            })
        return findings
