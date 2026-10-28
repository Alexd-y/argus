"""Psbdmp paste-dump index client (gated by ``PSBDMP_API_KEY``).

Psbdmp indexes public paste dumps. It is largely keyless, but we gate on an
opt-in ``PSBDMP_API_KEY`` so the source stays OFF by default (off-by-default
invariant); operators set any non-empty value to enable it.
"""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import quote

import httpx

from src.data_sources.base import DataSourceClient

logger = logging.getLogger(__name__)

_SOURCE = "psbdmp"
_DEFAULT_TIMEOUT = 30.0


class PsbdmpClient(DataSourceClient):
    def __init__(self) -> None:
        super().__init__("PSBDMP_API_KEY")
        self._base_url = (
            (os.environ.get("PSBDMP_BASE_URL") or "https://psbdmp.ws/api/v3").strip().rstrip("/")
        )

    async def query(self, **kwargs: Any) -> dict[str, Any]:
        if not self.is_available():
            return {"available": False, "source": _SOURCE}
        term = str(kwargs.get("domain") or kwargs.get("query") or kwargs.get("email") or "").strip()
        if not term:
            return {"source": _SOURCE, "available": True, "error": "missing_query"}
        url = f"{self._base_url}/search/{quote(term, safe='')}"
        try:
            async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
                resp = await client.get(url, headers={"User-Agent": "ARGUS-DWM/1.0"})
                return _finish_response(resp)
        except httpx.TimeoutException:
            logger.warning("psbdmp_query_timeout", extra={"source": _SOURCE})
            return {"source": _SOURCE, "available": True, "error": "timeout"}
        except httpx.HTTPStatusError as e:
            return _http_error(e.response)
        except Exception:
            logger.exception("psbdmp_query_failed", extra={"source": _SOURCE})
            return {}


def _finish_response(resp: httpx.Response) -> dict[str, Any]:
    if resp.status_code == 429:
        return {"source": _SOURCE, "available": True, "rate_limited": True, "status_code": 429}
    if resp.status_code == 404:
        return {"source": _SOURCE, "available": True, "data": []}
    resp.raise_for_status()
    return {"source": _SOURCE, "available": True, "data": resp.json()}


def _http_error(resp: httpx.Response) -> dict[str, Any]:
    if resp.status_code == 429:
        return {"source": _SOURCE, "available": True, "rate_limited": True, "status_code": 429}
    return {}
