"""SecurityTrails API client — stub. Uses SECURITYTRAILS_API_KEY when present."""

from typing import Any

import httpx

from src.data_sources.base import DataSourceClient


class SecurityTrailsClient(DataSourceClient):
    """Minimal SecurityTrails API client. Stub implementation."""

    def __init__(self) -> None:
        super().__init__("SECURITYTRAILS_API_KEY")
        self._base_url = "https://api.securitytrails.com/v1"

    async def query(self, **kwargs: Any) -> dict[str, Any]:
        """Query SecurityTrails. Returns empty dict if not configured."""
        if not self.is_available():
            return {}

        key = self._get_key()
        if not key:
            return {}

        # Stub: domain info
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                domain = kwargs.get("domain", "example.com")
                resp = await client.get(
                    f"{self._base_url}/domain/{domain}",
                    headers={"APIKEY": key},
                )
                resp.raise_for_status()
                return resp.json()
        except Exception:
            return {}
