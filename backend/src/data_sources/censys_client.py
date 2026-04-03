"""Censys API v2 — host search, view, certificates."""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

from src.data_sources.base import DataSourceClient

logger = logging.getLogger(__name__)

_SOURCE = "censys"
_DEFAULT_TIMEOUT = 30.0


class CensysClient(DataSourceClient):
    """Censys Search API v2 with HTTP Basic (API ID + secret)."""

    def __init__(self) -> None:
        super().__init__("CENSYS_API_KEY")
        self._base_url = "https://search.censys.io/api/v2"

    def is_available(self) -> bool:
        key = (os.environ.get("CENSYS_API_KEY") or "").strip()
        secret = (os.environ.get("CENSYS_API_SECRET") or "").strip()
        return bool(key and secret)

    def _credentials(self) -> tuple[str, str] | None:
        key = (os.environ.get("CENSYS_API_KEY") or "").strip()
        secret = (os.environ.get("CENSYS_API_SECRET") or "").strip()
        if not key or not secret:
            return None
        return key, secret

    async def query(self, **kwargs: Any) -> dict[str, Any]:
        """Query Censys v2.

        kwargs:
            query_type / type: ``hosts`` | ``search`` | ``certificates``
            q / query: search string (search, certificates)
            ip: host IP for ``hosts`` view
            per_page, cursor: optional pagination for search endpoints
        """
        if not self.is_available():
            return {"available": False, "source": _SOURCE}

        auth_pair = self._credentials()
        if not auth_pair:
            return {"available": False, "source": _SOURCE}

        query_type = (kwargs.get("query_type") or kwargs.get("type") or "search").strip().lower()
        q = (kwargs.get("q") or kwargs.get("query") or "").strip()
        per_page = kwargs.get("per_page")
        cursor = kwargs.get("cursor")

        try:
            async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
                if query_type == "hosts":
                    ip = (kwargs.get("ip") or kwargs.get("host") or "").strip()
                    if not ip:
                        return {
                            "source": _SOURCE,
                            "available": True,
                            "error": "missing_ip",
                        }
                    url = f"{self._base_url}/hosts/{ip}"
                    resp = await client.get(url, auth=auth_pair)
                    return await _finish_censys_response(resp)

                if query_type == "certificates":
                    url = f"{self._base_url}/certificates/search"
                    body: dict[str, Any] = {"q": q or "*"}
                    if per_page is not None:
                        body["per_page"] = per_page
                    if cursor:
                        body["cursor"] = cursor
                    resp = await client.post(url, auth=auth_pair, json=body)
                    return await _finish_censys_response(resp)

                # search — host index search
                url = f"{self._base_url}/hosts/search"
                body = {"q": q or "*"}
                if per_page is not None:
                    body["per_page"] = per_page
                if cursor:
                    body["cursor"] = cursor
                resp = await client.post(url, auth=auth_pair, json=body)
                return await _finish_censys_response(resp)
        except httpx.TimeoutException:
            logger.warning(
                "censys_query_timeout",
                extra={"source": _SOURCE},
            )
            return {"source": _SOURCE, "available": True, "error": "timeout"}
        except httpx.HTTPStatusError as e:
            return _censys_http_error(e.response)
        except Exception:
            logger.exception(
                "censys_query_failed",
                extra={"source": _SOURCE},
            )
            return {}


async def _finish_censys_response(resp: httpx.Response) -> dict[str, Any]:
    if resp.status_code == 429:
        return {
            "source": _SOURCE,
            "available": True,
            "rate_limited": True,
            "status_code": 429,
        }
    resp.raise_for_status()
    return {"source": _SOURCE, "available": True, "data": resp.json()}


def _censys_http_error(resp: httpx.Response) -> dict[str, Any]:
    if resp.status_code == 429:
        return {
            "source": _SOURCE,
            "available": True,
            "rate_limited": True,
            "status_code": 429,
        }
    return {}
