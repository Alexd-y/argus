"""Free, keyless OSINT clients for Dark Web Monitoring (§6).

Three public, no-key sources that surface *infrastructure exposure* for an
authorized domain:

* :class:`CrtShClient`            — crt.sh Certificate Transparency search.
* :class:`CertSpotterClient`      — SSLMate certspotter CT issuances.
* :class:`ShodanInternetDbClient` — Shodan InternetDB (open ports + CVEs per IP).

All three are keyless and free; certspotter honours an optional
``CERTSPOTTER_API_TOKEN`` for higher rate limits. Each is gated by a settings
flag (not a key) so an operator can cut that source's egress without disabling
DWM. Like every DWM client they NEVER raise — a failure/timeout degrades to a
structured empty result; the collector turns that into ``[]``.
"""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import quote

import httpx

from src.core.config import settings

logger = logging.getLogger(__name__)

_TIMEOUT = 30.0
_UA = "ARGUS-DWM/1.0 (authorized security assessment)"
_MAX_BYTES = 4 * 1024 * 1024  # defensive cap on response size


def _dwm_on() -> bool:
    """Keyless DWM sources respect the global kill-switch: with DWM off there is no
    'key' to be absent, so the global flag is what makes an unconfigured deployment
    inert (mirrors the keyed collectors' no-key => disabled invariant)."""
    return bool(getattr(settings, "dark_web_monitoring_enabled", False))


def _too_large(resp: httpx.Response) -> bool:
    try:
        return len(resp.content) > _MAX_BYTES
    except Exception:  # noqa: BLE001
        return False


class CrtShClient:
    """crt.sh CT-log search (``?q=%.<domain>&output=json``). Keyless."""

    source = "crtsh"

    def __init__(self) -> None:
        self._base = (os.environ.get("CRTSH_BASE_URL") or "https://crt.sh").strip().rstrip("/")

    def is_available(self) -> bool:
        return _dwm_on() and bool(getattr(settings, "dwm_ct_logs_enabled", True))

    async def query(self, *, domain: str) -> dict[str, Any]:
        domain = (domain or "").strip().lower().lstrip(".")
        if not domain:
            return {"source": self.source, "available": True, "data": []}
        url = f"{self._base}/?q={quote('%.' + domain, safe='')}&output=json"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
                resp = await client.get(
                    url, headers={"User-Agent": _UA, "Accept": "application/json"}
                )
                if resp.status_code == 429:
                    return {"source": self.source, "available": True, "rate_limited": True}
                resp.raise_for_status()
                if _too_large(resp):
                    return {"source": self.source, "available": True, "data": []}
                data = resp.json()
                return {
                    "source": self.source,
                    "available": True,
                    "data": data if isinstance(data, list) else [],
                }
        except httpx.TimeoutException:
            logger.warning("crtsh_query_timeout", extra={"source": self.source})
            return {"source": self.source, "available": True, "error": "timeout"}
        except Exception:  # noqa: BLE001 — never raise out of a DWM client
            logger.info("crtsh_query_failed", extra={"source": self.source})
            return {"source": self.source, "available": True, "error": "failed"}


class CertSpotterClient:
    """certspotter issuances (``/v1/issuances?domain=&include_subdomains=true``).

    Keyless with a low anonymous rate limit; an optional ``CERTSPOTTER_API_TOKEN``
    raises it (sent as a Bearer token when present).
    """

    source = "certspotter"

    def __init__(self) -> None:
        self._base = (
            (os.environ.get("CERTSPOTTER_BASE_URL") or "https://api.certspotter.com")
            .strip()
            .rstrip("/")
        )
        self._token = (os.environ.get("CERTSPOTTER_API_TOKEN") or "").strip()

    def is_available(self) -> bool:
        return _dwm_on() and bool(getattr(settings, "dwm_ct_logs_enabled", True))

    async def query(self, *, domain: str) -> dict[str, Any]:
        domain = (domain or "").strip().lower().lstrip(".")
        if not domain:
            return {"source": self.source, "available": True, "data": []}
        url = (
            f"{self._base}/v1/issuances?domain={quote(domain, safe='')}"
            "&include_subdomains=true&expand=dns_names"
        )
        headers = {"User-Agent": _UA, "Accept": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 429:
                    return {"source": self.source, "available": True, "rate_limited": True}
                resp.raise_for_status()
                if _too_large(resp):
                    return {"source": self.source, "available": True, "data": []}
                data = resp.json()
                return {
                    "source": self.source,
                    "available": True,
                    "data": data if isinstance(data, list) else [],
                }
        except httpx.TimeoutException:
            logger.warning("certspotter_query_timeout", extra={"source": self.source})
            return {"source": self.source, "available": True, "error": "timeout"}
        except Exception:  # noqa: BLE001
            logger.info("certspotter_query_failed", extra={"source": self.source})
            return {"source": self.source, "available": True, "error": "failed"}


class ShodanInternetDbClient:
    """Shodan InternetDB (``https://internetdb.shodan.io/<ip>``). Keyless.

    Returns a compact exposure record per IP: open ``ports``, known ``vulns``
    (CVE ids), ``hostnames``, ``cpes``, ``tags``. No API key required.
    """

    source = "shodan_internetdb"

    def __init__(self) -> None:
        self._base = (
            (os.environ.get("SHODAN_INTERNETDB_BASE_URL") or "https://internetdb.shodan.io")
            .strip()
            .rstrip("/")
        )

    def is_available(self) -> bool:
        return _dwm_on() and bool(getattr(settings, "dwm_shodan_internetdb_enabled", True))

    async def query(self, *, ip: str) -> dict[str, Any]:
        ip = (ip or "").strip()
        if not ip:
            return {"source": self.source, "available": True, "data": {}}
        url = f"{self._base}/{quote(ip, safe='')}"
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
                resp = await client.get(
                    url, headers={"User-Agent": _UA, "Accept": "application/json"}
                )
                if resp.status_code == 404:
                    # No record for this IP — "ran, found nothing", not an error.
                    return {"source": self.source, "available": True, "data": {}}
                if resp.status_code == 429:
                    return {"source": self.source, "available": True, "rate_limited": True}
                resp.raise_for_status()
                data = resp.json()
                return {
                    "source": self.source,
                    "available": True,
                    "data": data if isinstance(data, dict) else {},
                }
        except httpx.TimeoutException:
            logger.warning("shodan_internetdb_query_timeout", extra={"source": self.source})
            return {"source": self.source, "available": True, "error": "timeout"}
        except Exception:  # noqa: BLE001
            logger.info("shodan_internetdb_query_failed", extra={"source": self.source})
            return {"source": self.source, "available": True, "error": "failed"}


__all__ = ["CertSpotterClient", "CrtShClient", "ShodanInternetDbClient"]
