"""Have I Been Pwned API v3 — breach data, paste data."""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import quote

import httpx

from src.data_sources.base import DataSourceClient

logger = logging.getLogger(__name__)

_SOURCE = "hibp"
_DEFAULT_TIMEOUT = 30.0
_HIBP_USER_AGENT = "ARGUS-Backend/1.0 (security-research; contact: security@local)"


class HIBPClient(DataSourceClient):
    """HIBP API v3 (``hibp-api-key`` + descriptive User-Agent)."""

    def __init__(self) -> None:
        super().__init__("HIBP_API_KEY")
        self._base_url = "https://haveibeenpwned.com/api/v3"

    def _headers(self, key: str) -> dict[str, str]:
        return {
            "hibp-api-key": key,
            "User-Agent": _HIBP_USER_AGENT,
        }

    async def query(self, **kwargs: Any) -> dict[str, Any]:
        """Query HIBP v3.

        kwargs:
            query_type / type: ``breachedaccount`` | ``breaches`` | ``pasteaccount``
            account: email or username for breached/paste lookups
        """
        if not self.is_available():
            return {"available": False, "source": _SOURCE}

        key = self._get_key()
        if not key:
            return {"available": False, "source": _SOURCE}

        query_type = (
            kwargs.get("query_type") or kwargs.get("type") or "breachedaccount"
        ).strip().lower()
        headers = self._headers(key)

        try:
            async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
                if query_type == "breaches":
                    url = f"{self._base_url}/breaches"
                    resp = await client.get(url, headers=headers)
                    return _finish_hibp_response(resp, empty_404=False, not_breached_flag=False)

                if query_type == "pasteaccount":
                    account = (kwargs.get("account") or "").strip()
                    if not account:
                        return {"source": _SOURCE, "available": True, "error": "missing_account"}
                    enc = quote(account, safe="")
                    url = f"{self._base_url}/pasteaccount/{enc}"
                    resp = await client.get(url, headers=headers)
                    return _finish_hibp_response(resp, empty_404=True, not_breached_flag=False)

                # breachedaccount
                account = (kwargs.get("account") or "").strip()
                if not account:
                    return {"source": _SOURCE, "available": True, "error": "missing_account"}
                enc = quote(account, safe="")
                url = f"{self._base_url}/breachedaccount/{enc}"
                resp = await client.get(url, headers=headers)
                return _finish_hibp_response(resp, empty_404=True, not_breached_flag=True)
        except httpx.TimeoutException:
            logger.warning("hibp_query_timeout", extra={"source": _SOURCE})
            return {"source": _SOURCE, "available": True, "error": "timeout"}
        except httpx.HTTPStatusError as e:
            return _hibp_http_error(e.response)
        except Exception:
            logger.exception("hibp_query_failed", extra={"source": _SOURCE})
            return {}


def _finish_hibp_response(
    resp: httpx.Response,
    *,
    empty_404: bool,
    not_breached_flag: bool = False,
) -> dict[str, Any]:
    if resp.status_code == 429:
        return {
            "source": _SOURCE,
            "available": True,
            "rate_limited": True,
            "status_code": 429,
        }
    if resp.status_code == 404 and empty_404:
        out: dict[str, Any] = {
            "source": _SOURCE,
            "available": True,
            "data": [],
        }
        if not_breached_flag:
            out["not_breached"] = True
        return out
    resp.raise_for_status()
    return {"source": _SOURCE, "available": True, "data": resp.json()}


def _hibp_http_error(resp: httpx.Response) -> dict[str, Any]:
    if resp.status_code == 429:
        return {
            "source": _SOURCE,
            "available": True,
            "rate_limited": True,
            "status_code": 429,
        }
    return {}
