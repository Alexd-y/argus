"""NVD (National Vulnerability Database) client — public API, no key required."""

from typing import Any

import httpx


class NVDClient:
    """Minimal NVD API client. Public, no API key."""

    _base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def query(self, **kwargs: Any) -> dict[str, Any]:
        """Query NVD for CVEs. Returns empty dict on error."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(
                    self._base_url,
                    params=kwargs.get("params", {"resultsPerPage": 5}),
                )
                resp.raise_for_status()
                return resp.json()
        except Exception:
            return {}
