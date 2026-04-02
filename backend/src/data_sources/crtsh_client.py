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
        params_in = dict(kwargs.get("params", {}))
        timeout_sec = float(kwargs.get("timeout_sec", 30.0))
        try:
            async with httpx.AsyncClient(timeout=max(5.0, timeout_sec)) as client:
                params = dict(params_in)
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
