"""Have I Been Pwned API client — stub. Uses HIBP_API_KEY when present."""

from typing import Any
from urllib.parse import quote

import httpx

from src.data_sources.base import DataSourceClient


class HIBPClient(DataSourceClient):
    """Minimal HIBP API client. Stub implementation."""

    def __init__(self) -> None:
        super().__init__("HIBP_API_KEY")
        self._base_url = "https://haveibeenpwned.com/api/v3"

    async def query(self, **kwargs: Any) -> dict[str, Any]:
        """Query HIBP. Returns empty dict if not configured."""
        if not self.is_available():
            return {}

        key = self._get_key()
        if not key:
            return {}

        # Stub: breach check for account
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                account = quote(kwargs.get("account", "test@example.com"), safe="")
                resp = await client.get(
                    f"{self._base_url}/breachedaccount/{account}",
                    headers={"hibp-api-key": key},
                )
                resp.raise_for_status()
                return {"breaches": resp.json()}
        except Exception:
            return {}
