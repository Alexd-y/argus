"""KEV (Known Exploited Vulnerabilities) client.

Pulls the CISA KEV catalog (https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
and offers two access paths:

* :meth:`KevClient.is_listed` — fast O(1) lookup used inline by the
  enrichment pipeline. Backed by a 24h Redis cache of the CVE-ID set.
* :meth:`KevClient.fetch_kev_catalog` — full structured fetch used by
  the daily Celery beat job (``kev_catalog_refresh_task``). Returns a
  list of :class:`KevRecord` instances ready for upsert into Postgres
  (``kev_catalog`` table). Honours upstream HTTP caching via ``ETag``
  / ``If-None-Match`` so repeated polls cost a single 304 round-trip.

The HTTP transport is injected via the same :class:`HttpClientProtocol`
defined in :mod:`src.findings.epss_client` so the two clients share a
single fake in tests. ``HttpClientProtocol.get`` accepts an optional
``headers`` keyword (added in ARG-044) which legacy implementations may
ignore — KEV ETag handling will simply skip if the underlying client
does not forward it.

Air-gap mode (``airgap=True``) short-circuits all remote fetches; the
operator is expected to seed the ``kev_catalog`` table out-of-band and
``is_listed`` will fall through to the cached Redis set (or return
``False``).
"""

from __future__ import annotations

import json
import logging
import re
from datetime import date
from typing import Any, Final

from src.findings.epss_client import HttpClientProtocol, HttpResponse, RedisLike
from src.findings.kev_persistence import KevRecord

_logger = logging.getLogger(__name__)


_CVE_RE: Final[re.Pattern[str]] = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_KEV_CATALOG_URL: Final[str] = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
_DEFAULT_TTL_SECONDS: Final[int] = 86_400
_DEFAULT_TIMEOUT_S: Final[float] = 30.0
_CATALOG_CACHE_KEY: Final[str] = "argus:kev:catalog"
_ETAG_CACHE_KEY: Final[str] = "argus:kev:etag"


class KevClient:
    """Lookup interface for the CISA Known Exploited Vulnerabilities catalog."""

    def __init__(
        self,
        http_client: HttpClientProtocol,
        redis_client: RedisLike | None = None,
        *,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
        catalog_url: str = _KEV_CATALOG_URL,
        timeout_s: float = _DEFAULT_TIMEOUT_S,
        airgap: bool = False,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        self._http = http_client
        self._redis = redis_client
        self._ttl = ttl_seconds
        self._catalog_url = catalog_url
        self._timeout = timeout_s
        self._airgap = bool(airgap)

    async def is_listed(self, cve_id: str) -> bool:
        """Return True if ``cve_id`` is in the KEV catalog.

        Returns False on validation failure or cache+HTTP miss — fail-safe
        default (we'd rather miss a KEV listing than incorrectly flag an
        unrelated CVE as actively exploited).
        """
        if not _CVE_RE.fullmatch(cve_id):
            _logger.warning(
                "kev.invalid_cve",
                extra={"event": "kev_invalid_cve", "cve_id_len": len(cve_id)},
            )
            return False

        catalog = self._cache_get_catalog()
        if catalog is None:
            if self._airgap:
                return False
            catalog = await self._fetch_catalog_set()
            if catalog is not None:
                self._cache_put_catalog(catalog)
        if catalog is None:
            return False
        return cve_id in catalog

    async def refresh(self) -> int:
        """Force-refresh the cached catalog set from CISA, returning the count.

        Used by the lightweight live-warmup path — does NOT update the
        Postgres ``kev_catalog`` table (that is the responsibility of the
        Celery beat job; see :meth:`fetch_kev_catalog`).
        """
        if self._airgap:
            return 0
        catalog = await self._fetch_catalog_set()
        if catalog is None:
            return 0
        self._cache_put_catalog(catalog)
        return len(catalog)

    async def fetch_kev_catalog(self) -> list[KevRecord] | None:
        """Fetch the full structured KEV catalog for Postgres persistence.

        Returns:
            * ``None`` if the upstream returned 304 Not Modified (cache
              still valid; caller should skip the upsert) or if any
              transport / parsing error occurred.
            * A list of :class:`KevRecord` instances on a 200 response.

        ETag is cached in Redis (``argus:kev:etag``) and re-sent as
        ``If-None-Match`` on subsequent polls. Air-gap mode returns
        ``None`` immediately.
        """
        if self._airgap:
            _logger.info("kev.airgap_skip", extra={"event": "kev_airgap_skip"})
            return None

        headers: dict[str, str] = {}
        cached_etag = self._cache_get_etag()
        if cached_etag:
            headers["If-None-Match"] = cached_etag

        try:
            response = await self._http_get(self._catalog_url, headers=headers)
        except Exception:
            _logger.warning("kev.http_failed", extra={"event": "kev_http_failed"})
            return None

        status = int(getattr(response, "status_code", 0))
        if status == 304:
            _logger.info(
                "kev.not_modified",
                extra={"event": "kev_not_modified", "etag_len": len(cached_etag or "")},
            )
            return None
        if status != 200:
            _logger.warning(
                "kev.http_non_200",
                extra={"event": "kev_http_non_200", "status": status},
            )
            return None

        records = _parse_kev_catalog_records(response)
        if records is None:
            return None

        new_etag = _extract_etag(response)
        if new_etag:
            self._cache_put_etag(new_etag)
        return records

    def _cache_get_catalog(self) -> frozenset[str] | None:
        if self._redis is None:
            return None
        try:
            raw = self._redis.get(_CATALOG_CACHE_KEY)
        except Exception:
            _logger.warning(
                "kev.cache_get_failed", extra={"event": "kev_cache_get_failed"}
            )
            return None
        if raw is None:
            return None
        try:
            text = raw if isinstance(raw, str) else raw.decode("utf-8")
            decoded = json.loads(text)
        except (ValueError, UnicodeDecodeError, AttributeError, json.JSONDecodeError):
            return None
        if not isinstance(decoded, list):
            return None
        return frozenset(item for item in decoded if isinstance(item, str))

    def _cache_put_catalog(self, catalog: frozenset[str]) -> None:
        if self._redis is None:
            return
        try:
            payload = json.dumps(sorted(catalog), ensure_ascii=False)
            self._redis.setex(_CATALOG_CACHE_KEY, self._ttl, payload)
        except Exception:
            _logger.warning(
                "kev.cache_put_failed", extra={"event": "kev_cache_put_failed"}
            )

    def _cache_get_etag(self) -> str | None:
        if self._redis is None:
            return None
        try:
            raw = self._redis.get(_ETAG_CACHE_KEY)
        except Exception:
            return None
        if raw is None:
            return None
        try:
            return raw if isinstance(raw, str) else raw.decode("utf-8")
        except (UnicodeDecodeError, AttributeError):
            return None

    def _cache_put_etag(self, etag: str) -> None:
        if self._redis is None:
            return
        try:
            self._redis.setex(_ETAG_CACHE_KEY, self._ttl, etag)
        except Exception:
            _logger.warning(
                "kev.etag_cache_put_failed",
                extra={"event": "kev_etag_cache_put_failed"},
            )

    async def _fetch_catalog_set(self) -> frozenset[str] | None:
        try:
            response = await self._http_get(self._catalog_url, headers=None)
        except Exception:
            _logger.warning("kev.http_failed", extra={"event": "kev_http_failed"})
            return None

        status = getattr(response, "status_code", 0)
        if status != 200:
            _logger.warning(
                "kev.http_non_200",
                extra={"event": "kev_http_non_200", "status": int(status)},
            )
            return None

        return _parse_kev_catalog(response)

    async def _http_get(
        self, url: str, *, headers: dict[str, str] | None
    ) -> HttpResponse:
        """Adapter around :class:`HttpClientProtocol`.

        Older fakes (notably the test conftest) only accept ``url`` and
        ``timeout``; we attempt to forward ``headers`` and gracefully fall
        back if the underlying client raises ``TypeError`` (signalling the
        kwarg is unsupported).
        """
        if not headers:
            return await self._http.get(url, timeout=self._timeout)
        try:
            return await self._http.get(  # type: ignore[call-arg]
                url, timeout=self._timeout, headers=headers
            )
        except TypeError:
            # Fallback: HTTP client doesn't support headers — proceed
            # without ETag (still correct, just not bandwidth-optimal).
            return await self._http.get(url, timeout=self._timeout)


def _parse_kev_catalog(response: HttpResponse) -> frozenset[str] | None:
    """Extract the set of CVE IDs from a CISA KEV catalog response."""
    try:
        payload = response.json()
    except (ValueError, TypeError, json.JSONDecodeError):
        _logger.warning("kev.malformed_json", extra={"event": "kev_malformed_json"})
        return None

    if not isinstance(payload, dict):
        return None
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return None
    cves: set[str] = set()
    for entry in vulnerabilities:
        if not isinstance(entry, dict):
            continue
        cve_id = entry.get("cveID")
        if isinstance(cve_id, str) and _CVE_RE.fullmatch(cve_id):
            cves.add(cve_id)
    return frozenset(cves)


def _parse_kev_catalog_records(response: HttpResponse) -> list[KevRecord] | None:
    """Extract structured :class:`KevRecord` rows for Postgres persistence."""
    try:
        payload = response.json()
    except (ValueError, TypeError, json.JSONDecodeError):
        _logger.warning(
            "kev.records_malformed_json",
            extra={"event": "kev_records_malformed_json"},
        )
        return None
    if not isinstance(payload, dict):
        return None
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return None
    out: list[KevRecord] = []
    for entry in vulnerabilities:
        record = _entry_to_record(entry)
        if record is not None:
            out.append(record)
    return out


def _entry_to_record(entry: object) -> KevRecord | None:
    if not isinstance(entry, dict):
        return None
    cve_raw = entry.get("cveID")
    if not isinstance(cve_raw, str):
        return None
    cve_id = cve_raw.upper()
    if not _CVE_RE.fullmatch(cve_id):
        return None
    date_added = _to_date(entry.get("dateAdded"))
    if date_added is None:
        return None
    return KevRecord(
        cve_id=cve_id,
        vendor_project=str(entry.get("vendorProject") or ""),
        product=str(entry.get("product") or ""),
        vulnerability_name=str(entry.get("vulnerabilityName") or ""),
        date_added=date_added,
        short_description=str(entry.get("shortDescription") or ""),
        required_action=str(entry.get("requiredAction") or ""),
        due_date=_to_date(entry.get("dueDate")),
        known_ransomware_use=_to_bool(entry.get("knownRansomwareCampaignUse")),
        notes=_optional_str(entry.get("notes")),
    )


def _to_date(value: object) -> date | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def _to_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"known", "true", "yes", "1"}
    return False


def _optional_str(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        s = value.strip()
        return s or None
    return None


def _extract_etag(response: HttpResponse) -> str | None:
    headers = getattr(response, "headers", None)
    if headers is None:
        return None
    try:
        # Mapping-like access (covers dict, httpx.Headers).
        value = headers.get("ETag") or headers.get("etag")  # type: ignore[union-attr]
    except (AttributeError, TypeError):
        return None
    if not isinstance(value, str):
        return None
    return value or None


def _coerce_bool(value: Any) -> bool:
    return _to_bool(value)


__all__ = [
    "HttpClientProtocol",
    "HttpResponse",
    "KevClient",
    "RedisLike",
]
