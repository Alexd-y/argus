"""OTX (AlienVault Open Threat Exchange) intel adapter — requires OTX_API_KEY."""

from __future__ import annotations

import os
from typing import Any

import httpx

from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType

OTX_BASE = "https://otx.alienvault.com/api/v1"


class OtxIntelAdapter(IntelAdapter):
    """OTX adapter for domain threat context and passive DNS hostnames."""

    @property
    def name(self) -> str:
        return "otx"

    @property
    def env_key(self) -> str | None:
        return "OTX_API_KEY"

    async def fetch(self, domain: str) -> dict[str, Any]:
        if not self.is_available():
            return {
                "source": self.name,
                "findings": [],
                "skipped": True,
                "error": None,
                "raw": None,
            }

        key = (os.environ.get("OTX_API_KEY") or "").strip()
        headers = {"X-OTX-API-KEY": key, "Accept": "application/json"}
        findings: list[dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(
                    f"{OTX_BASE}/indicators/domain/{domain}/general",
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
                data = resp.json()
                if not isinstance(data, dict):
                    return {
                        "source": self.name,
                        "findings": [],
                        "skipped": False,
                        "error": "invalid_response",
                        "raw": None,
                    }

                pulse_info = data.get("pulse_info") or {}
                pulse_count = int(pulse_info.get("count", 0) or 0)
                if pulse_count > 0:
                    findings.append(
                        _finding(
                            FindingType.OSINT_ENTRY,
                            f"otx_pulses:{domain}",
                            {"domain": domain, "pulse_count": pulse_count, "source": self.name},
                            self.name,
                            0.8,
                        )
                    )

                pdns_resp = await client.get(
                    f"{OTX_BASE}/indicators/domain/{domain}/passive_dns",
                    headers=headers,
                )
                if pdns_resp.status_code == 200:
                    pdns = pdns_resp.json()
                    if isinstance(pdns, dict):
                        seen: set[str] = set()
                        entries = pdns.get("passive_dns") or []
                        if isinstance(entries, list):
                            for entry in entries[:100]:
                                if not isinstance(entry, dict):
                                    continue
                                hostname = (entry.get("hostname") or "").lower().rstrip(".")
                                if (
                                    hostname
                                    and "." in hostname
                                    and hostname not in seen
                                    and domain in hostname
                                ):
                                    seen.add(hostname)
                                    findings.append(
                                        _finding(
                                            FindingType.SUBDOMAIN,
                                            hostname,
                                            {
                                                "source": self.name,
                                                "parent_domain": domain,
                                                "address": entry.get("address", ""),
                                            },
                                            self.name,
                                            0.75,
                                        )
                                    )

                return {
                    "source": self.name,
                    "findings": findings,
                    "skipped": False,
                    "error": None,
                    "raw": {"pulse_count": pulse_count},
                }
        except Exception as e:
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": f"OTX query failed: {type(e).__name__}",
                "raw": None,
            }
