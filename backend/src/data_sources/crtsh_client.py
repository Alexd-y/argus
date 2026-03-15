"""crt.sh client — public API, no key required."""

from typing import Any

import httpx


class CrtShClient:
    """crt.sh certificate transparency client. Public, no API key."""

    _base_url = "https://crt.sh"

    def is_available(self) -> bool:
        """Always available (public API)."""
        return True

    async def query(self, **kwargs: Any) -> dict[str, Any]:
        """Query crt.sh for certificates by domain. Returns empty dict on error."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                params = dict(kwargs.get("params", {}))
                params.setdefault("output", "json")
                resp = await client.get(
                    self._base_url,
                    params=params,
                )
                resp.raise_for_status()
                data = resp.json()
                return {"results": data} if isinstance(data, list) else {"data": data}
        except Exception:
            return {}
