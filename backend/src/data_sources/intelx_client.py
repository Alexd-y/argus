"""Intelligence X (intelx.io) search client — gated by ``INTELX_API_KEY``.

Free tier: set ``INTELX_API_KEY`` to a key from https://free.intelx.io/ and leave
``INTELX_BASE_URL`` at its default (the free endpoint). IntelX uses a two-step
search: POST /intelligent/search returns a search id, then
GET /intelligent/search/result?id=... returns the matched records (bucket names,
system ids, dates — NO plaintext credentials). We keep only those non-sensitive
descriptors downstream. Skipped entirely when the key is unset.
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from src.data_sources.base import DataSourceClient

logger = logging.getLogger(__name__)

_SOURCE = "intelx"
_DEFAULT_BASE = "https://free.intelx.io"
_TIMEOUT = 30.0


class IntelXClient(DataSourceClient):
    def __init__(self) -> None:
        super().__init__("INTELX_API_KEY")
        base = (os.environ.get("INTELX_BASE_URL") or _DEFAULT_BASE).strip().rstrip("/")
        self._base_url = base or _DEFAULT_BASE

    async def query(self, **kwargs: Any) -> dict[str, Any]:
        if not self.is_available():
            return {"available": False, "source": _SOURCE}
        key = self._get_key()
        term = str(kwargs.get("term") or kwargs.get("email") or kwargs.get("query") or "").strip()
        if not key or not term:
            return {"source": _SOURCE, "available": True, "error": "missing_query"}
        headers = {
            "x-key": key,
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "ARGUS-DWM/1.0",
        }
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                started = await client.post(
                    f"{self._base_url}/intelligent/search",
                    headers=headers,
                    json={
                        "term": term,
                        "maxresults": int(kwargs.get("maxresults", 10)),
                        "media": 0,
                        "sort": 2,
                        "terminate": [],
                    },
                )
                if started.status_code == 429:
                    return {"source": _SOURCE, "available": True, "rate_limited": True}
                started.raise_for_status()
                sid = str((started.json() or {}).get("id") or "").strip()
                if not sid:
                    return {"source": _SOURCE, "available": True, "data": {"records": []}}
                result = await client.get(
                    f"{self._base_url}/intelligent/search/result",
                    headers=headers,
                    params={"id": sid, "limit": int(kwargs.get("maxresults", 10)), "statistics": 0},
                )
                if result.status_code == 429:
                    return {"source": _SOURCE, "available": True, "rate_limited": True}
                result.raise_for_status()
                return {"source": _SOURCE, "available": True, "data": result.json()}
        except httpx.TimeoutException:
            logger.warning("intelx_query_timeout", extra={"source": _SOURCE})
            return {"source": _SOURCE, "available": True, "error": "timeout"}
        except httpx.HTTPStatusError as e:
            if e.response is not None and e.response.status_code == 429:
                return {"source": _SOURCE, "available": True, "rate_limited": True}
            logger.warning("intelx_query_http_error", extra={"source": _SOURCE})
            return {}
        except Exception:
            logger.exception("intelx_query_failed", extra={"source": _SOURCE})
            return {}
