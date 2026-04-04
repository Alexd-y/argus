"""AbuseIPDB intel adapter — IP abuse scoring via ABUSEIPDB_API_KEY."""

from __future__ import annotations

import os
import socket
from typing import Any

import httpx

from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2/check"


class AbuseIpDbIntelAdapter(IntelAdapter):
    """AbuseIPDB adapter for the domain's resolved IPv4 address."""

    @property
    def name(self) -> str:
        return "abuseipdb"

    @property
    def env_key(self) -> str | None:
        return "ABUSEIPDB_API_KEY"

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

        key = (os.environ.get("ABUSEIPDB_API_KEY") or "").strip()
        headers = {"Key": key, "Accept": "application/json"}

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    ABUSEIPDB_BASE,
                    params={"ipAddress": ip, "maxAgeInDays": "90"},
                    headers=headers,
                )
                if resp.status_code != 200:
                    return {
                        "source": self.name,
                        "findings": [],
                        "skipped": False,
                        "error": f"HTTP {resp.status_code}",
                        "raw": None,
                    }
                body = resp.json()
        except Exception as e:
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": f"AbuseIPDB failed: {type(e).__name__}",
                "raw": None,
            }

        if not isinstance(body, dict):
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": "invalid_response",
                "raw": None,
            }

        row = body.get("data") or {}
        if not isinstance(row, dict):
            row = {}

        abuse_score = int(row.get("abuseConfidenceScore", 0) or 0)
        total_reports = int(row.get("totalReports", 0) or 0)
        findings: list[dict[str, Any]] = [
            _finding(
                FindingType.OSINT_ENTRY,
                f"abuseipdb:{ip}",
                {
                    "ip": ip,
                    "domain": domain,
                    "abuse_score": abuse_score,
                    "total_reports": total_reports,
                    "isp": row.get("isp", ""),
                    "country": row.get("countryCode", ""),
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
            "raw": {"abuse_score": abuse_score, "total_reports": total_reports},
        }
