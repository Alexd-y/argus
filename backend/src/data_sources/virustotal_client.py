"""VirusTotal API v3 — domain, URL, IP analysis."""

from __future__ import annotations

import base64
import logging
from typing import Any

import httpx

from src.data_sources.base import DataSourceClient

logger = logging.getLogger(__name__)

_SOURCE = "virustotal"
_DEFAULT_TIMEOUT = 30.0


def _vt_url_id(url: str) -> str:
    padded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
    return padded.rstrip("=")


class VirusTotalClient(DataSourceClient):
    """VirusTotal API v3 (``x-apikey`` header)."""

    def __init__(self) -> None:
        super().__init__("VIRUSTOTAL_API_KEY")
        self._base_url = "https://www.virustotal.com/api/v3"

    async def query(self, **kwargs: Any) -> dict[str, Any]:
        """Query VirusTotal v3.

        kwargs:
            query_type / type: ``domain`` | ``ip`` | ``url``
            domain, ip: identifier string
            url: full URL for ``url`` analysis (converted to VT URL id)
        """
        if not self.is_available():
            return {"available": False, "source": _SOURCE}

        key = self._get_key()
        if not key:
            return {"available": False, "source": _SOURCE}

        headers = {"x-apikey": key}
        query_type = (kwargs.get("query_type") or kwargs.get("type") or "domain").strip().lower()

        try:
            async with httpx.AsyncClient(timeout=_DEFAULT_TIMEOUT) as client:
                if query_type == "ip":
                    ip = (kwargs.get("ip") or "").strip()
                    if not ip:
                        return {"source": _SOURCE, "available": True, "error": "missing_ip"}
                    url = f"{self._base_url}/ip_addresses/{ip}"
                    resp = await client.get(url, headers=headers)
                    return _finish_response(resp)

                if query_type == "url":
                    raw_url = (kwargs.get("url") or "").strip()
                    if not raw_url:
                        return {"source": _SOURCE, "available": True, "error": "missing_url"}
                    uid = kwargs.get("url_id") or _vt_url_id(raw_url)
                    url = f"{self._base_url}/urls/{uid}"
                    resp = await client.get(url, headers=headers)
                    return _finish_response(resp)

                domain = (kwargs.get("domain") or "").strip().lower()
                if not domain:
                    return {"source": _SOURCE, "available": True, "error": "missing_domain"}
                url = f"{self._base_url}/domains/{domain}"
                resp = await client.get(url, headers=headers)
                return _finish_response(resp)
        except httpx.TimeoutException:
            logger.warning("virustotal_query_timeout", extra={"source": _SOURCE})
            return {"source": _SOURCE, "available": True, "error": "timeout"}
        except httpx.HTTPStatusError as e:
            return _http_error(e.response)
        except Exception:
            logger.exception("virustotal_query_failed", extra={"source": _SOURCE})
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
