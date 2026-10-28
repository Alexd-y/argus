"""DeHashed breach-search client (gated by ``DEHASHED_API_KEY``).

Commercial source — skipped entirely unless licensed. DeHashed uses HTTP Basic
auth with an account email (``DEHASHED_USERNAME``) + API key. We never store or
print plaintext passwords; the collector downstream keeps only a presence flag.
"""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import quote

import httpx

from src.data_sources.base import DataSourceClient

logger = logging.getLogger(__name__)

_SOURCE = "dehashed"
_DEFAULT_TIMEOUT = 30.0


class DehashedClient(DataSourceClient):
    def __init__(self) -> None:
        super().__init__("DEHASHED_API_KEY")
        self._base_url = "https://api.dehashed.com"

    async def query(self, **kwargs: Any) -> dict[str, Any]:
        if not self.is_available():
            return {"available": False, "source": _SOURCE}
        key = self._get_key()
        username = (os.environ.get("DEHASHED_USERNAME") or "").strip()
        if not key or not username:
            return {"available": False, "source": _SOURCE}
        term = str(kwargs.get("email") or kwargs.get("query") or "").strip()
        if not term:
            return {"source": _SOURCE, "available": True, "error": "missing_query"}
        url = f"{self._base_url}/search?query={quote(term, safe='')}"
        try:
            async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
                resp = await client.get(
                    url,
                    headers={"Accept": "application/json", "User-Agent": "ARGUS-DWM/1.0"},
                    auth=(username, key),
                )
                return _finish_response(resp)
        except httpx.TimeoutException:
            logger.warning("dehashed_query_timeout", extra={"source": _SOURCE})
            return {"source": _SOURCE, "available": True, "error": "timeout"}
        except httpx.HTTPStatusError as e:
            return _http_error(e.response)
        except Exception:
            logger.exception("dehashed_query_failed", extra={"source": _SOURCE})
            return {}


def _finish_response(resp: httpx.Response) -> dict[str, Any]:
    if resp.status_code == 429:
        return {"source": _SOURCE, "available": True, "rate_limited": True, "status_code": 429}
    resp.raise_for_status()
    return {"source": _SOURCE, "available": True, "data": resp.json()}


def _http_error(resp: httpx.Response) -> dict[str, Any]:
    if resp.status_code == 429:
        return {"source": _SOURCE, "available": True, "rate_limited": True, "status_code": 429}
    return {}
