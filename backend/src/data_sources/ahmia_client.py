"""Ahmia clearnet index of .onion services (gated by ``AHMIA_BASE_URL``).

Ahmia is a search engine that indexes Tor hidden services from the clearnet and
honours a blocklist. We only query its clearnet search endpoint for mentions of
an authorized target — no direct Tor fetch happens here. Gated: skipped entirely
unless ``AHMIA_BASE_URL`` is configured.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

import httpx

from src.data_sources.base import DataSourceClient

logger = logging.getLogger(__name__)

_SOURCE = "ahmia"
_DEFAULT_TIMEOUT = 30.0


class AhmiaClient(DataSourceClient):
    def __init__(self) -> None:
        super().__init__("AHMIA_BASE_URL")
        import os

        self._base_url = (
            (os.environ.get("AHMIA_BASE_URL") or "https://ahmia.fi").strip().rstrip("/")
        )

    async def query(self, **kwargs: Any) -> dict[str, Any]:
        if not self.is_available():
            return {"available": False, "source": _SOURCE}
        keyword = str(kwargs.get("keyword") or kwargs.get("q") or "").strip()
        if not keyword:
            return {"source": _SOURCE, "available": True, "error": "missing_keyword"}
        url = f"{self._base_url}/search/?q={quote(keyword, safe='')}"
        try:
            async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
                resp = await client.get(url, headers={"User-Agent": "ARGUS-DWM/1.0"})
                return _finish_response(resp)
        except httpx.TimeoutException:
            logger.warning("ahmia_query_timeout", extra={"source": _SOURCE})
            return {"source": _SOURCE, "available": True, "error": "timeout"}
        except httpx.HTTPStatusError as e:
            return _http_error(e.response)
        except Exception:
            logger.exception("ahmia_query_failed", extra={"source": _SOURCE})
            return {}


def _finish_response(resp: httpx.Response) -> dict[str, Any]:
    if resp.status_code == 429:
        return {"source": _SOURCE, "available": True, "rate_limited": True, "status_code": 429}
    resp.raise_for_status()
    # Ahmia returns HTML for /search/; expose raw text so the collector can parse links.
    return {"source": _SOURCE, "available": True, "data": {"body": resp.text}}


def _http_error(resp: httpx.Response) -> dict[str, Any]:
    if resp.status_code == 429:
        return {"source": _SOURCE, "available": True, "rate_limited": True, "status_code": 429}
    return {}
