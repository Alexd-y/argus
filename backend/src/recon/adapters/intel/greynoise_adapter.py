"""GreyNoise intel adapter — IP classification via GREYNOISE_API_KEY."""

from __future__ import annotations

import os
import socket
from typing import Any

import httpx

from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType

GN_BASE = "https://api.greynoise.io/v3/community"


class GreyNoiseIntelAdapter(IntelAdapter):
    """GreyNoise adapter — noise / RIOT context for the domain's resolved IP."""

    @property
    def name(self) -> str:
        return "greynoise"

    @property
    def env_key(self) -> str | None:
        return "GREYNOISE_API_KEY"

    async def fetch(self, domain: str) -> dict[str, Any]:
        if not self.is_available():
            return {
                "source": self.name,
                "findings": [],
                "skipped": True,
                "error": None,
                "raw": None,
            }

        try:
            ip = socket.gethostbyname(domain)
        except (socket.gaierror, OSError):
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": f"Cannot resolve {domain}",
                "raw": None,
            }

        key = (os.environ.get("GREYNOISE_API_KEY") or "").strip()
        headers = {"key": key, "Accept": "application/json"}

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(f"{GN_BASE}/{ip}", headers=headers)
                if resp.status_code != 200:
                    return {
                        "source": self.name,
                        "findings": [],
                        "skipped": False,
                        "error": f"HTTP {resp.status_code}",
                        "raw": None,
                    }
                data = resp.json()
        except Exception as e:
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": f"GreyNoise failed: {type(e).__name__}",
                "raw": None,
            }

        if not isinstance(data, dict):
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": "invalid_response",
                "raw": None,
            }

        noise = bool(data.get("noise", False))
        riot = bool(data.get("riot", False))
        classification = str(data.get("classification", "unknown"))
        findings: list[dict[str, Any]] = [
            _finding(
                FindingType.OSINT_ENTRY,
                f"greynoise:{ip}",
                {
                    "ip": ip,
                    "domain": domain,
                    "noise": noise,
                    "riot": riot,
                    "classification": classification,
                    "name": data.get("name", ""),
                    "source": self.name,
                },
                self.name,
                0.85,
            )
        ]

        return {
            "source": self.name,
            "findings": findings,
            "skipped": False,
            "error": None,
            "raw": data,
        }
