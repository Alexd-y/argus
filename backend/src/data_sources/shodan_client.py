"""Shodan API client — activate by SHODAN_API_KEY."""

from typing import Any

import httpx

from src.data_sources.base import DataSourceClient


class ShodanClient(DataSourceClient):
    """Shodan API client for host/domain intelligence."""

    def __init__(self) -> None:
        super().__init__("SHODAN_API_KEY")
        self._base_url = "https://api.shodan.io"

    async def query(self, **kwargs: Any) -> dict[str, Any]:
        """Query Shodan. Returns empty dict if not configured or on error."""
        if not self.is_available():
            return {}

        key = self._get_key()
        if not key:
            return {}

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                endpoint = kwargs.get("endpoint", "shodan/host/search")
                params = dict(kwargs.get("params", {}))
                params["key"] = key
                resp = await client.get(
                    f"{self._base_url}/{endpoint}",
                    params=params,
                )
                resp.raise_for_status()
                return resp.json()
        except Exception:
            return {}
