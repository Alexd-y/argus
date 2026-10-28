"""LeakCheck breach-lookup client (gated by ``LEAKCHECK_API_KEY``).

Commercial source — skipped unless licensed. We never store/print plaintext
passwords; the collector keeps only a presence flag + source name.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

import httpx

from src.data_sources.base import DataSourceClient

logger = logging.getLogger(__name__)

_SOURCE = "leakcheck"
_DEFAULT_TIMEOUT = 30.0


class LeakCheckClient(DataSourceClient):
    def __init__(self) -> None:
        super().__init__("LEAKCHECK_API_KEY")
        self._base_url = "https://leakcheck.io/api/v2"

    async def query(self, **kwargs: Any) -> dict[str, Any]:
        if not self.is_available():
            return {"available": False, "source": _SOURCE}
        key = self._get_key()
        if not key:
            return {"available": False, "source": _SOURCE}
        term = str(kwargs.get("email") or kwargs.get("query") or "").strip()
        if not term:
            return {"source": _SOURCE, "available": True, "error": "missing_query"}
        query_type = str(kwargs.get("query_type") or "email").strip().lower()
        url = f"{self._base_url}/query/{quote(term, safe='')}?type={quote(query_type, safe='')}"
        try:
            async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
                resp = await client.get(
                    url,
                    headers={"X-API-Key": key, "User-Agent": "ARGUS-DWM/1.0"},
                )
                return _finish_response(resp)
        except httpx.TimeoutException:
            logger.warning("leakcheck_query_timeout", extra={"source": _SOURCE})
            return {"source": _SOURCE, "available": True, "error": "timeout"}
        except httpx.HTTPStatusError as e:
            return _http_error(e.response)
        except Exception:
            logger.exception("leakcheck_query_failed", extra={"source": _SOURCE})
            return {}


def _finish_response(resp: httpx.Response) -> dict[str, Any]:
    if resp.status_code == 429:
        return {"source": _SOURCE, "available": True, "rate_limited": True, "status_code": 429}
    if resp.status_code == 404:
        return {"source": _SOURCE, "available": True, "data": [], "not_breached": True}
    resp.raise_for_status()
    return {"source": _SOURCE, "available": True, "data": resp.json()}


def _http_error(resp: httpx.Response) -> dict[str, Any]:
    if resp.status_code == 429:
        return {"source": _SOURCE, "available": True, "rate_limited": True, "status_code": 429}
    return {}
