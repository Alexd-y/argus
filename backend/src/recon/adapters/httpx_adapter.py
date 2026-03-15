"""Httpx adapter — HTTP probing and fingerprinting."""

import json
import logging
from typing import Any

from src.recon.adapters.base import ToolAdapter
from src.recon.schemas.base import FindingType

logger = logging.getLogger(__name__)


class HttpxAdapter(ToolAdapter):
    """Adapter for httpx tool output parsing and normalization."""

    @property
    def name(self) -> str:
        return "httpx"

    @property
    def supported_stages(self) -> list[int]:
        return [4, 6]  # LIVE_HOSTS, FINGERPRINTING

    async def build_command(self, target: str, config: dict[str, Any]) -> list[str]:
        cmd = [
            "httpx",
            "-l", target,
            "-json",
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect",
            "-server",
            "-content-type",
            "-content-length",
            "-follow-redirects",
        ]
        if config.get("timeout"):
            cmd.extend(["-timeout", str(config["timeout"])])
        if config.get("rate_limit"):
            cmd.extend(["-rate-limit", str(config["rate_limit"])])
        if config.get("threads"):
            cmd.extend(["-threads", str(config["threads"])])
        return cmd

    async def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse httpx JSON lines output."""
        results: list[dict[str, Any]] = []
        for line in raw_output.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append(data)
            except json.JSONDecodeError:
                continue
        return results

    async def normalize(
        self, raw_results: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Normalize httpx output to multiple finding types."""
        findings: list[dict[str, Any]] = []

        for item in raw_results:
            url = item.get("url", item.get("input", ""))
            host = item.get("host", "")
            ip = (
                item.get("a", [""])[0]
                if isinstance(item.get("a"), list)
                else item.get("host", "")
            )
            status = item.get("status_code") or item.get("status-code")
            title = item.get("title", "")
            server = item.get("webserver") or item.get("server", "")
            tech = item.get("tech") or item.get("technologies", [])
            content_type = item.get("content_type") or item.get("content-type", "")
            content_length = item.get("content_length") or item.get("content-length")

            if url:
                findings.append({
                    "finding_type": FindingType.URL,
                    "value": url,
                    "data": {
                        "url": url,
                        "method": "GET",
                        "status_code": status,
                        "content_type": content_type,
                        "content_length": content_length,
                        "title": title,
                        "redirect_location": item.get("final_url", ""),
                        "source": "httpx",
                    },
                    "source_tool": "httpx",
                    "confidence": 1.0,
                })

            if isinstance(tech, list):
                for t in tech:
                    if isinstance(t, str) and t:
                        findings.append({
                            "finding_type": FindingType.TECHNOLOGY,
                            "value": f"{host}:{t}",
                            "data": {
                                "url": url,
                                "name": t,
                                "version": None,
                                "category": None,
                                "confidence": 0.8,
                                "evidence": f"Detected by httpx on {host}",
                            },
                            "source_tool": "httpx",
                            "confidence": 0.8,
                        })

            if server:
                findings.append({
                    "finding_type": FindingType.TECHNOLOGY,
                    "value": f"{host}:server:{server}",
                    "data": {
                        "url": url,
                        "name": server,
                        "version": None,
                        "category": "server",
                        "confidence": 0.9,
                        "evidence": "Server header",
                    },
                    "source_tool": "httpx",
                    "confidence": 0.9,
                })

        return findings
