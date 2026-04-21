"""EPSS (Exploit Prediction Scoring System) client.

Pulls per-CVE probability scores from FIRST.org's public EPSS API
(https://www.first.org/epss/) with optional Redis caching.

The HTTP transport is injected via :class:`HttpClientProtocol` so unit
tests can supply a fake without touching the network. Cache backend is
also abstracted via :class:`RedisLike` (any object exposing ``get`` /
``setex``).

ARG-044 additions:

* :meth:`EpssClient.fetch_epss_batch` — bulk lookup honouring FIRST.org's
  rate limits (60 requests / minute) via an :class:`asyncio.Semaphore`.
  Used by ``epss_batch_refresh_task`` (Celery beat) to populate the
  ``epss_scores`` Postgres table once per day.
* Air-gap mode (``airgap=True``) — disables remote fetching entirely so
  on-premises deployments without internet egress can still operate (the
  enrichment pipeline degrades gracefully to ``epss_score=None``).
* Exponential-backoff retry on transient HTTP failures (5xx + network
  errors); 4xx propagates a ``None`` immediately to avoid hammering the
  upstream with unrecoverable requests.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import date
from typing import Any, Final, Protocol, runtime_checkable

_logger = logging.getLogger(__name__)


_CVE_RE: Final[re.Pattern[str]] = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_EPSS_API_URL: Final[str] = "https://api.first.org/data/v1/epss"
_DEFAULT_TTL_SECONDS: Final[int] = 86_400
_DEFAULT_TIMEOUT_S: Final[float] = 5.0
_DEFAULT_BATCH_TIMEOUT_S: Final[float] = 30.0
_CACHE_PREFIX: Final[str] = "argus:epss:"
_DEFAULT_CHUNK_SIZE: Final[int] = 100
_DEFAULT_RATE_LIMIT_PER_MIN: Final[int] = 60
_DEFAULT_MAX_RETRIES: Final[int] = 3
_DEFAULT_BACKOFF_BASE_S: Final[float] = 0.5
_DEFAULT_BACKOFF_CAP_S: Final[float] = 8.0


@runtime_checkable
class HttpResponse(Protocol):
    """Minimal HTTP response surface used by EPSS / KEV clients."""

    @property
    def status_code(self) -> int: ...

    def json(self) -> Any: ...

    @property
    def text(self) -> str: ...


@runtime_checkable
class HttpClientProtocol(Protocol):
    """Minimal async HTTP client surface (subset of httpx.AsyncClient.get)."""

    async def get(self, url: str, *, timeout: float) -> HttpResponse: ...


@runtime_checkable
class RedisLike(Protocol):
    """Minimal Redis surface used for EPSS caching (subset of redis.Redis)."""

    def get(self, key: str) -> str | bytes | None: ...

    def setex(self, key: str, seconds: int, value: str) -> Any: ...


@dataclass(frozen=True)
class EpssBatchEntry:
    """Per-CVE row returned by :meth:`EpssClient.fetch_epss_batch`.

    Mirrors the FIRST.org JSON schema (``epss``, ``percentile``, ``date``)
    but with strict typing and date parsing already done.
    """

    cve_id: str
    epss_score: float
    epss_percentile: float
    model_date: date


class EpssClient:
    """Cached lookups for EPSS probability scores.

    Construction is dependency-injected: an HTTP client and (optionally)
    a Redis-like cache client. Production wiring lives in the FastAPI
    bootstrap, not here.
    """

    def __init__(
        self,
        http_client: HttpClientProtocol,
        redis_client: RedisLike | None = None,
        *,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
        api_url: str = _EPSS_API_URL,
        timeout_s: float = _DEFAULT_TIMEOUT_S,
        batch_timeout_s: float = _DEFAULT_BATCH_TIMEOUT_S,
        rate_limit_per_minute: int = _DEFAULT_RATE_LIMIT_PER_MIN,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        backoff_base_s: float = _DEFAULT_BACKOFF_BASE_S,
        backoff_cap_s: float = _DEFAULT_BACKOFF_CAP_S,
        airgap: bool = False,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        if batch_timeout_s <= 0:
            raise ValueError("batch_timeout_s must be positive")
        if rate_limit_per_minute <= 0:
            raise ValueError("rate_limit_per_minute must be positive")
        if max_retries < 0:
            raise ValueError("max_retries must be non-negative")
        self._http = http_client
        self._redis = redis_client
        self._ttl = ttl_seconds
        self._api_url = api_url
        self._timeout = timeout_s
        self._batch_timeout = batch_timeout_s
        self._max_retries = max_retries
        self._backoff_base = backoff_base_s
        self._backoff_cap = backoff_cap_s
        self._airgap = bool(airgap)
        self._semaphore = asyncio.Semaphore(rate_limit_per_minute)

    async def get(self, cve_id: str) -> float | None:
        """Return EPSS probability for ``cve_id`` (0.0-1.0) or ``None``.

        Returns ``None`` on validation failure, cache miss + HTTP error, or
        malformed API response. Never raises — EPSS is enrichment, never a
        hard dependency.
        """
        if not _CVE_RE.fullmatch(cve_id.upper()):
            _logger.warning(
                "epss.invalid_cve",
                extra={"event": "epss_invalid_cve", "cve_id_len": len(cve_id)},
            )
            return None
        normalized = cve_id.upper()

        cached = self._cache_get(normalized)
        if cached is not None:
            return cached

        if self._airgap:
            return None

        score = await self._fetch_remote(normalized)
        if score is not None:
            self._cache_put(normalized, score)
        return score

    async def fetch_epss_batch(
        self,
        cve_ids: Iterable[str],
        *,
        chunk_size: int = _DEFAULT_CHUNK_SIZE,
    ) -> dict[str, EpssBatchEntry]:
        """Bulk-fetch EPSS rows for ``cve_ids`` from FIRST.org.

        Returns a mapping ``cve_id → EpssBatchEntry``. Missing rows are
        omitted (FIRST.org silently drops unknown CVEs). Honours the
        per-instance rate limit semaphore so concurrent callers cannot
        burst past 60 rpm. Air-gap mode short-circuits to an empty dict.
        """
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        if self._airgap:
            return {}
        normalised: list[str] = []
        seen: set[str] = set()
        for cid in cve_ids:
            up = cid.upper()
            if _CVE_RE.fullmatch(up) and up not in seen:
                normalised.append(up)
                seen.add(up)
        if not normalised:
            return {}
        out: dict[str, EpssBatchEntry] = {}
        for chunk in _chunked(normalised, chunk_size):
            async with self._semaphore:
                rows = await self._fetch_batch_chunk(chunk)
                for entry in rows:
                    out[entry.cve_id] = entry
        return out

    def _cache_key(self, cve_id: str) -> str:
        return f"{_CACHE_PREFIX}{cve_id.upper()}"

    def _cache_get(self, cve_id: str) -> float | None:
        if self._redis is None:
            return None
        try:
            raw = self._redis.get(self._cache_key(cve_id))
        except Exception:
            _logger.warning(
                "epss.cache_get_failed", extra={"event": "epss_cache_get_failed"}
            )
            return None
        if raw is None:
            return None
        try:
            value = float(raw if isinstance(raw, str) else raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, AttributeError):
            return None
        if 0.0 <= value <= 1.0:
            return value
        return None

    def _cache_put(self, cve_id: str, score: float) -> None:
        if self._redis is None:
            return
        try:
            self._redis.setex(self._cache_key(cve_id), self._ttl, f"{score:.6f}")
        except Exception:
            _logger.warning(
                "epss.cache_put_failed", extra={"event": "epss_cache_put_failed"}
            )

    async def _fetch_remote(self, cve_id: str) -> float | None:
        url = f"{self._api_url}?cve={cve_id}"
        # Single-CVE lookup is latency-sensitive (live enrichment in the
        # FindingNormalizer fast path). We do not retry — the caller treats
        # ``None`` as "EPSS unknown" and degrades gracefully.
        try:
            response = await self._http.get(url, timeout=self._timeout)
        except Exception:
            _logger.warning(
                "epss.http_failed", extra={"event": "epss_http_failed"}
            )
            return None
        if int(getattr(response, "status_code", 0)) != 200:
            _logger.warning(
                "epss.http_non_200",
                extra={
                    "event": "epss_http_non_200",
                    "status": int(getattr(response, "status_code", 0)),
                },
            )
            return None
        return _parse_epss_response(response)

    async def _fetch_batch_chunk(self, chunk: Sequence[str]) -> list[EpssBatchEntry]:
        joined = ",".join(chunk)
        url = f"{self._api_url}?cve={joined}&envelope=true&pretty=false"
        # Batch refresh runs on a Celery beat (daily cadence) — latency is
        # not a concern, so we retry transient 5xx / 429 with capped
        # exponential backoff to ride out brief upstream blips.
        response = await self._request_with_retry(url, timeout=self._batch_timeout)
        if response is None:
            return []
        return _parse_epss_batch_response(response)

    async def _request_with_retry(
        self, url: str, *, timeout: float
    ) -> HttpResponse | None:
        attempt = 0
        while True:
            try:
                response = await self._http.get(url, timeout=timeout)
            except Exception:
                _logger.warning(
                    "epss.http_failed",
                    extra={"event": "epss_http_failed", "attempt": attempt},
                )
                if attempt >= self._max_retries:
                    return None
                await self._sleep_backoff(attempt)
                attempt += 1
                continue
            status = int(getattr(response, "status_code", 0))
            if status == 200:
                return response
            if 500 <= status < 600 or status == 429:
                _logger.warning(
                    "epss.http_retryable",
                    extra={"event": "epss_http_retryable", "status": status},
                )
                if attempt >= self._max_retries:
                    return None
                await self._sleep_backoff(attempt)
                attempt += 1
                continue
            _logger.warning(
                "epss.http_non_200",
                extra={"event": "epss_http_non_200", "status": status},
            )
            return None

    async def _sleep_backoff(self, attempt: int) -> None:
        delay = min(self._backoff_cap, self._backoff_base * (2**attempt))
        await asyncio.sleep(delay)


def _chunked(items: Sequence[str], size: int) -> Iterable[list[str]]:
    if size <= 0:
        raise ValueError("size must be positive")
    for i in range(0, len(items), size):
        yield list(items[i : i + size])


def _parse_epss_response(response: HttpResponse) -> float | None:
    """Extract the EPSS probability from a FIRST.org single-CVE response."""
    try:
        payload = response.json()
    except (ValueError, TypeError, json.JSONDecodeError):
        _logger.warning("epss.malformed_json", extra={"event": "epss_malformed_json"})
        return None

    if not isinstance(payload, dict):
        return None
    data = payload.get("data")
    if not isinstance(data, list) or not data:
        return None
    first = data[0]
    if not isinstance(first, dict):
        return None
    raw = first.get("epss")
    if raw is None:
        return None
    try:
        score = float(raw)
    except (TypeError, ValueError):
        return None
    if 0.0 <= score <= 1.0:
        return score
    return None


def _parse_epss_batch_response(response: HttpResponse) -> list[EpssBatchEntry]:
    """Extract a list of :class:`EpssBatchEntry` from a batch response."""
    try:
        payload = response.json()
    except (ValueError, TypeError, json.JSONDecodeError):
        _logger.warning(
            "epss.batch_malformed_json",
            extra={"event": "epss_batch_malformed_json"},
        )
        return []
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if not isinstance(data, list):
        return []
    out: list[EpssBatchEntry] = []
    for row in data:
        entry = _row_to_batch_entry(row)
        if entry is not None:
            out.append(entry)
    return out


def _row_to_batch_entry(row: object) -> EpssBatchEntry | None:
    if not isinstance(row, dict):
        return None
    cve_raw = row.get("cve")
    if not isinstance(cve_raw, str):
        return None
    cve_id = cve_raw.upper()
    if not _CVE_RE.fullmatch(cve_id):
        return None
    score = _to_float(row.get("epss"))
    if score is None or not 0.0 <= score <= 1.0:
        return None
    percentile = _to_float(row.get("percentile"))
    if percentile is None or not 0.0 <= percentile <= 1.0:
        return None
    model_date = _to_date(row.get("date"))
    if model_date is None:
        return None
    return EpssBatchEntry(
        cve_id=cve_id,
        epss_score=score,
        epss_percentile=percentile,
        model_date=model_date,
    )


def _to_float(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _to_date(value: object) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


__all__ = [
    "EpssBatchEntry",
    "EpssClient",
    "HttpClientProtocol",
    "HttpResponse",
    "RedisLike",
]
