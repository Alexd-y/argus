"""Censys API client — stub. Uses CENSYS_API_KEY when present."""

from typing import Any

import httpx

from src.data_sources.base import DataSourceClient


class CensysClient(DataSourceClient):
    """Minimal Censys API client. Stub implementation."""

    def __init__(self) -> None:
        super().__init__("CENSYS_API_KEY")
        self._base_url = "https://search.censys.io/api/v2"

    async def query(self, **kwargs: Any) -> dict[str, Any]:
        """Query Censys. Returns empty dict if not configured."""
        if not self.is_available():
            return {}

        key = self._get_key()
        if not key:
            return {}

        # Stub: minimal GET to hosts endpoint
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    f"{self._base_url}/hosts",
                    params=kwargs.get("params", {}),
                    auth=(key, ""),
                )
                resp.raise_for_status()
                return resp.json()
        except Exception:
            return {}
