"""AbuseIPDB intel adapter — requires ABUSEIPDB_API_KEY."""

from typing import Any

from src.recon.adapters.intel.base import IntelAdapter


class AbuseIpDbIntelAdapter(IntelAdapter):
    """AbuseIPDB API adapter. Stub — skips when no key."""

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
        return {
            "source": self.name,
            "findings": [],
            "skipped": False,
            "error": "Stub — not implemented",
            "raw": None,
        }
