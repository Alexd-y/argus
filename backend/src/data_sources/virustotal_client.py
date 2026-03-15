"""VirusTotal API client — stub. Uses VIRUSTOTAL_API_KEY when present."""

from typing import Any

import httpx

from src.data_sources.base import DataSourceClient


class VirusTotalClient(DataSourceClient):
    """Minimal VirusTotal API client. Stub implementation."""

    def __init__(self) -> None:
        super().__init__("VIRUSTOTAL_API_KEY")
        self._base_url = "https://www.virustotal.com/api/v3"

    async def query(self, **kwargs: Any) -> dict[str, Any]:
        """Query VirusTotal. Returns empty dict if not configured."""
        if not self.is_available():
            return {}

        key = self._get_key()
        if not key:
            return {}

        # Stub: minimal GET for domain/URL report
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self._base_url}/domains/{kwargs.get('domain', 'example.com')}",
                    headers={"x-apikey": key},
                )
                resp.raise_for_status()
                return resp.json()
        except Exception:
            return {}
