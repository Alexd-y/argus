"""urlscan.io intel adapter — public search; URLSCAN_API_KEY improves rate limits."""

from __future__ import annotations

import os
from typing import Any

import httpx

from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType

URLSCAN_BASE = "https://urlscan.io/api/v1"


class UrlScanIntelAdapter(IntelAdapter):
    """urlscan.io search for URLs and IPs related to the domain."""

    @property
    def name(self) -> str:
        return "urlscan"

    @property
    def env_key(self) -> str | None:
        return None

    async def fetch(self, domain: str) -> dict[str, Any]:
        key = (os.environ.get("URLSCAN_API_KEY") or "").strip()
        headers: dict[str, str] = {"Accept": "application/json"}
        if key:
            headers["API-Key"] = key

        findings: list[dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(
                    f"{URLSCAN_BASE}/search/",
                    params={"q": f"domain:{domain}", "size": 10},
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
        except Exception as e:
            return {
                "source": self.name,
                "findings": [],
                "skipped": False,
                "error": f"urlscan failed: {type(e).__name__}",
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

        results = data.get("results") or []
        if not isinstance(results, list):
            results = []

        seen_urls: set[str] = set()
        for r in results[:10]:
            if not isinstance(r, dict):
                continue
            page = r.get("page") or {}
            if not isinstance(page, dict):
                page = {}
            url = page.get("url") or ""
            server = page.get("server") or ""
            ip = page.get("ip") or ""

            if url and url not in seen_urls:
                seen_urls.add(url)
                findings.append(
                    _finding(
                        FindingType.URL,
                        url,
                        {"domain": domain, "server": server, "ip": ip, "source": self.name},
                        self.name,
                        0.75,
                    )
                )
            if ip:
                findings.append(
                    _finding(
                        FindingType.IP_ADDRESS,
                        str(ip),
                        {"domain": domain, "source": self.name},
                        self.name,
                        0.7,
                    )
                )

        return {
            "source": self.name,
            "findings": findings,
            "skipped": False,
            "error": None,
            "raw": {"results_count": len(results)},
        }
