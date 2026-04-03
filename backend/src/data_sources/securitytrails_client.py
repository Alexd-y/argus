"""SecurityTrails API v1 — domain info, subdomains, DNS history."""

from __future__ import annotations

import logging
from typing import Any

import httpx

from src.data_sources.base import DataSourceClient

logger = logging.getLogger(__name__)

_SOURCE = "securitytrails"
_DEFAULT_TIMEOUT = 30.0


class SecurityTrailsClient(DataSourceClient):
    """SecurityTrails REST API v1 (``APIKEY`` header)."""

    def __init__(self) -> None:
        super().__init__("SECURITYTRAILS_API_KEY")
        self._base_url = "https://api.securitytrails.com/v1"

    async def query(self, **kwargs: Any) -> dict[str, Any]:
        """Query SecurityTrails.

        kwargs:
            query_type / type: ``domain`` | ``subdomains`` | ``dns_history`` | ``whois``
            domain: hostname (required)
            record_type: for ``dns_history`` (default ``a``)
        """
        if not self.is_available():
            return {"available": False, "source": _SOURCE}

        key = self._get_key()
        if not key:
            return {"available": False, "source": _SOURCE}

        domain = (kwargs.get("domain") or "").strip().lower()
        if not domain:
            return {"source": _SOURCE, "available": True, "error": "missing_domain"}

        query_type = (kwargs.get("query_type") or kwargs.get("type") or "domain").strip().lower()
        headers = {"APIKEY": key}

        try:
            async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
                if query_type == "subdomains":
                    url = f"{self._base_url}/domain/{domain}/subdomains"
                    resp = await client.get(url, headers=headers)
                    return _finish_response(resp)

                if query_type == "dns_history":
                    record = (kwargs.get("record_type") or kwargs.get("dns_type") or "a").strip().lower()
                    url = f"{self._base_url}/history/{domain}/dns/{record}"
                    resp = await client.get(url, headers=headers)
                    return _finish_response(resp)

                if query_type == "whois":
                    url = f"{self._base_url}/domain/{domain}/whois"
                    resp = await client.get(url, headers=headers)
                    return _finish_response(resp)

                url = f"{self._base_url}/domain/{domain}"
                resp = await client.get(url, headers=headers)
                return _finish_response(resp)
        except httpx.TimeoutException:
            logger.warning("securitytrails_query_timeout", extra={"source": _SOURCE})
            return {"source": _SOURCE, "available": True, "error": "timeout"}
        except httpx.HTTPStatusError as e:
            return _http_error(e.response)
        except Exception:
            logger.exception("securitytrails_query_failed", extra={"source": _SOURCE})
            return {}


def _finish_response(resp: httpx.Response) -> dict[str, Any]:
    if resp.status_code == 429:
        return {
            "source": _SOURCE,
            "available": True,
            "rate_limited": True,
            "status_code": 429,
        }
    resp.raise_for_status()
    return {"source": _SOURCE, "available": True, "data": resp.json()}


def _http_error(resp: httpx.Response) -> dict[str, Any]:
    if resp.status_code == 429:
        return {
            "source": _SOURCE,
            "available": True,
            "rate_limited": True,
            "status_code": 429,
        }
    return {}
