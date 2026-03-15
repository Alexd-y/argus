"""urlscan.io intel adapter — URLSCAN_API_KEY optional (higher rate limit)."""

from typing import Any

from src.recon.adapters.intel.base import IntelAdapter


class UrlScanIntelAdapter(IntelAdapter):
    """urlscan.io API adapter. Stub — skips when no key (optional for public)."""

    @property
    def name(self) -> str:
        return "urlscan"

    @property
    def env_key(self) -> str | None:
        return "URLSCAN_API_KEY"

    async def fetch(self, domain: str) -> dict[str, Any]:
        if not self.is_available():
            return {
                "source": self.name,
                "findings": [],
                "skipped": True,
                "error": None,
                "raw": None,
            }
        return {
            "source": self.name,
            "findings": [],
            "skipped": False,
            "error": "Stub — not implemented",
            "raw": None,
        }
