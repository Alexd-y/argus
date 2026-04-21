"""Shared plumbing for every webhook adapter (ARG-035).

Adapters keep their wire-specific shape (Slack Block Kit, Linear GraphQL,
Jira REST) inside their own module; everything else — circuit breaker,
exponential-jittered retry, idempotency dedup, target-URL hashing — is
implemented here so the three concrete classes stay short and uniform.

Design contracts:

* The HTTP layer is :class:`httpx.AsyncClient` (project default), wrapped
  in a small adapter-owned cache so connections are pooled across calls
  but unit tests can swap a :class:`httpx.MockTransport` per adapter.
* Retry with exponential jittered backoff: 3 attempts, base 1.0s, factor
  4.0 (1s / 4s / 16s), full-jitter on each delay (random uniform 0..delay)
  so synchronised retries from many tenants do not stampede an upstream.
* Circuit breaker is per-(adapter × tenant). The dispatcher is the only
  consumer that observes the state — adapters call into a thin facade.
* Idempotency dedup is also per-(adapter × tenant) using a bounded LRU
  set of recently-delivered ``event_id`` (default 1 024 entries). This
  prevents a re-tried delivery from creating a duplicate Linear / Jira
  ticket; Slack messages are inherently idempotent at the wire level
  but we still skip the duplicate post to save the upstream request.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import secrets as _secrets_module
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Final

import httpx

from src.mcp.services.notifications.schemas import (
    AdapterResult,
    CircuitState,
    NotificationEvent,
)

_logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS: Final[float] = 10.0
DEFAULT_MAX_ATTEMPTS: Final[int] = 3
DEFAULT_BACKOFF_BASE_SECONDS: Final[float] = 1.0
DEFAULT_BACKOFF_FACTOR: Final[float] = 4.0
DEFAULT_BACKOFF_CAP_SECONDS: Final[float] = 30.0
DEFAULT_CIRCUIT_FAILURE_THRESHOLD: Final[int] = 5
DEFAULT_CIRCUIT_COOLDOWN_SECONDS: Final[int] = 60
DEFAULT_DEDUP_CAPACITY: Final[int] = 1_024
TARGET_REDACTED_LEN: Final[int] = 12

_TIMEOUT_ENV: Final[str] = "MCP_NOTIFICATIONS_HTTP_TIMEOUT_SECONDS"
_MAX_ATTEMPTS_ENV: Final[str] = "MCP_NOTIFICATIONS_MAX_ATTEMPTS"


def _utcnow() -> datetime:
    """Return current UTC time (helper for monkeypatching in tests)."""
    return datetime.now(tz=timezone.utc)


def _resolve_timeout_seconds() -> float:
    """Pull the HTTP timeout from env, falling back to the project default."""
    raw = os.environ.get(_TIMEOUT_ENV, "").strip()
    if not raw:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        value = float(raw)
    except ValueError:
        _logger.warning(
            "mcp.notifications.timeout_invalid",
            extra={"value": raw, "fallback_seconds": DEFAULT_TIMEOUT_SECONDS},
        )
        return DEFAULT_TIMEOUT_SECONDS
    if not (0.5 <= value <= 120.0):
        _logger.warning(
            "mcp.notifications.timeout_out_of_range",
            extra={"value": value, "fallback_seconds": DEFAULT_TIMEOUT_SECONDS},
        )
        return DEFAULT_TIMEOUT_SECONDS
    return value


def _resolve_max_attempts() -> int:
    raw = os.environ.get(_MAX_ATTEMPTS_ENV, "").strip()
    if not raw:
        return DEFAULT_MAX_ATTEMPTS
    try:
        value = int(raw)
    except ValueError:
        _logger.warning(
            "mcp.notifications.max_attempts_invalid",
            extra={"value": raw, "fallback": DEFAULT_MAX_ATTEMPTS},
        )
        return DEFAULT_MAX_ATTEMPTS
    if not (1 <= value <= 6):
        _logger.warning(
            "mcp.notifications.max_attempts_out_of_range",
            extra={"value": value, "fallback": DEFAULT_MAX_ATTEMPTS},
        )
        return DEFAULT_MAX_ATTEMPTS
    return value


def hash_target(url: str) -> str:
    """Return ``sha256(url)[:12]`` — the redacted handle for audit logs.

    The full URL never enters the audit chain or the AdapterResult: only
    this 12-char prefix does. The hash is deterministic so an operator can
    correlate two records without ever seeing the secret-bearing URL.
    """
    if not url:
        return "no-target" + "-" * (TARGET_REDACTED_LEN - len("no-target"))
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    return digest[:TARGET_REDACTED_LEN]


class _BoundedRecentSet:
    """Tiny LRU-ish recent-event set used for idempotent dedup.

    Insert order is preserved; on overflow the oldest entry is evicted.
    The class is intentionally not thread-safe for free-for-all use; the
    adapter wraps every access with an :class:`asyncio.Lock` so reads /
    writes inside the asyncio runtime are serialised per-adapter.
    """

    __slots__ = ("_items", "_capacity")

    def __init__(self, capacity: int = DEFAULT_DEDUP_CAPACITY) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self._items: "OrderedDict[str, None]" = OrderedDict()
        self._capacity = capacity

    def __contains__(self, key: object) -> bool:
        return isinstance(key, str) and key in self._items

    def add(self, key: str) -> None:
        if key in self._items:
            self._items.move_to_end(key)
            return
        self._items[key] = None
        if len(self._items) > self._capacity:
            self._items.popitem(last=False)

    def remove(self, key: str) -> None:
        self._items.pop(key, None)

    def __len__(self) -> int:
        return len(self._items)


class CircuitBreaker:
    """In-process circuit breaker keyed by ``(adapter_name, tenant_id)``.

    The breaker opens after ``failure_threshold`` consecutive failures and
    short-circuits :meth:`is_open` calls for the next ``cooldown_seconds``.
    A successful delivery resets the counter; the breaker auto-closes once
    cooldown elapses (clients call :meth:`is_open` again before each send,
    so there is no background timer to leak resources).
    """

    def __init__(
        self,
        *,
        failure_threshold: int = DEFAULT_CIRCUIT_FAILURE_THRESHOLD,
        cooldown_seconds: int = DEFAULT_CIRCUIT_COOLDOWN_SECONDS,
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if cooldown_seconds < 1:
            raise ValueError("cooldown_seconds must be >= 1")
        self._failure_threshold = failure_threshold
        self._cooldown_seconds = cooldown_seconds
        self._clock = clock
        self._state: dict[tuple[str, str], CircuitState] = {}
        self._lock = asyncio.Lock()

    async def is_open(self, *, adapter_name: str, tenant_id: str) -> bool:
        """Return ``True`` iff the breaker is currently short-circuiting."""
        async with self._lock:
            state = self._state.get((adapter_name, tenant_id))
            if state is None or state.opened_at is None:
                return False
            if state.failure_count < self._failure_threshold:
                return False
            cooldown_end = state.opened_at + timedelta(seconds=state.cooldown_seconds)
            if self._clock() >= cooldown_end:
                self._state.pop((adapter_name, tenant_id), None)
                return False
            return True

    async def record_success(self, *, adapter_name: str, tenant_id: str) -> None:
        async with self._lock:
            self._state.pop((adapter_name, tenant_id), None)

    async def record_failure(self, *, adapter_name: str, tenant_id: str) -> bool:
        """Record a failure; return ``True`` iff the breaker tripped open now."""
        async with self._lock:
            existing = self._state.get((adapter_name, tenant_id))
            failure_count = (existing.failure_count if existing else 0) + 1
            opened_at: datetime | None = existing.opened_at if existing else None
            tripped_now = False
            if failure_count >= self._failure_threshold and opened_at is None:
                opened_at = self._clock()
                tripped_now = True
            new_state = CircuitState(
                failure_count=failure_count,
                opened_at=opened_at,
                cooldown_seconds=self._cooldown_seconds,
            )
            self._state[(adapter_name, tenant_id)] = new_state
            if tripped_now:
                _logger.warning(
                    "mcp.notifications.circuit_open",
                    extra={
                        "adapter_name": adapter_name,
                        "tenant_id": tenant_id,
                        "failure_count": failure_count,
                        "cooldown_seconds": self._cooldown_seconds,
                    },
                )
            return tripped_now

    def snapshot(self, *, adapter_name: str, tenant_id: str) -> CircuitState | None:
        """Return a copy of the breaker state (test-only helper)."""
        return self._state.get((adapter_name, tenant_id))


def compute_backoff_seconds(
    attempt: int,
    *,
    base: float = DEFAULT_BACKOFF_BASE_SECONDS,
    factor: float = DEFAULT_BACKOFF_FACTOR,
    cap: float = DEFAULT_BACKOFF_CAP_SECONDS,
    rng: Callable[[], float] | None = None,
) -> float:
    """Return a jittered exponential backoff for ``attempt`` (0-indexed).

    Default settings yield 1s / 4s / 16s before jitter; jitter is full-spectrum
    (uniform 0..delay) so that synchronised retries across tenants spread out
    instead of hammering the upstream in lockstep.
    """
    if attempt < 0:
        raise ValueError("attempt must be >= 0")
    raw_delay = min(cap, base * (factor**attempt))
    rand_source: Callable[[], float] = rng if rng is not None else _full_jitter_random
    jitter_factor = max(0.0, min(1.0, rand_source()))
    return raw_delay * jitter_factor


def _full_jitter_random() -> float:
    """Uniform random in [0, 1) using the cryptographic RNG.

    Bandit B311 flags ``random.random`` even though jitter is non-security
    critical; using ``secrets.randbits`` keeps both the linter and the
    "no-weak-RNG-anywhere" rule happy without pulling in a new dependency.
    """
    return _secrets_module.randbits(53) / (1 << 53)


class _Retryer:
    """Drives a fixed-attempt retry loop with jittered backoff between attempts."""

    def __init__(
        self,
        *,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        base_seconds: float = DEFAULT_BACKOFF_BASE_SECONDS,
        factor: float = DEFAULT_BACKOFF_FACTOR,
        cap_seconds: float = DEFAULT_BACKOFF_CAP_SECONDS,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        rng: Callable[[], float] | None = None,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        self._max_attempts = max_attempts
        self._base_seconds = base_seconds
        self._factor = factor
        self._cap_seconds = cap_seconds
        self._sleep: Callable[[float], Awaitable[None]] = (
            sleep if sleep is not None else asyncio.sleep
        )
        self._rng = rng

    @property
    def max_attempts(self) -> int:
        return self._max_attempts

    async def sleep_between(self, attempt_index: int) -> None:
        """Sleep between attempt ``attempt_index`` and ``attempt_index + 1``."""
        delay = compute_backoff_seconds(
            attempt_index,
            base=self._base_seconds,
            factor=self._factor,
            cap=self._cap_seconds,
            rng=self._rng,
        )
        if delay > 0:
            await self._sleep(delay)


class NotifierBase:
    """Base class for webhook adapters; encapsulates retry / circuit / dedup.

    Concrete subclasses implement :meth:`_attempt_send` (one HTTP attempt)
    and :meth:`_describe_target` (returns the URL the request will hit).
    Everything else — wrap-with-retry, circuit lookup, idempotency check,
    audit-safe AdapterResult construction — lives here so the three real
    adapters stay short and consistent.
    """

    name: str = "base"

    def __init__(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        circuit_breaker: CircuitBreaker | None = None,
        timeout_seconds: float | None = None,
        max_attempts: int | None = None,
        backoff_base_seconds: float = DEFAULT_BACKOFF_BASE_SECONDS,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
        backoff_cap_seconds: float = DEFAULT_BACKOFF_CAP_SECONDS,
        dedup_capacity: int = DEFAULT_DEDUP_CAPACITY,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        rng: Callable[[], float] | None = None,
    ) -> None:
        self._timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else _resolve_timeout_seconds()
        )
        resolved_attempts = (
            max_attempts if max_attempts is not None else _resolve_max_attempts()
        )
        self._owned_client = client is None
        self._client = (
            client
            if client is not None
            else httpx.AsyncClient(timeout=self._timeout_seconds)
        )
        self._circuit = (
            circuit_breaker if circuit_breaker is not None else CircuitBreaker()
        )
        self._retryer = _Retryer(
            max_attempts=resolved_attempts,
            base_seconds=backoff_base_seconds,
            factor=backoff_factor,
            cap_seconds=backoff_cap_seconds,
            sleep=sleep,
            rng=rng,
        )
        self._dedup_lock = asyncio.Lock()
        self._dedup: dict[str, _BoundedRecentSet] = {}
        self._dedup_capacity = dedup_capacity

    @property
    def http_client(self) -> httpx.AsyncClient:
        """Return the underlying client (test-only — keeps mock injection clean)."""
        return self._client

    @property
    def circuit_breaker(self) -> CircuitBreaker:
        return self._circuit

    @property
    def max_attempts(self) -> int:
        return self._retryer.max_attempts

    async def aclose(self) -> None:
        """Release the underlying httpx client (only when this adapter owns it)."""
        if self._owned_client:
            await self._client.aclose()

    async def __aenter__(self) -> "NotifierBase":
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.aclose()

    async def _check_idempotent(self, *, tenant_id: str, event_id: str) -> bool:
        async with self._dedup_lock:
            bucket = self._dedup.get(tenant_id)
            return bucket is not None and event_id in bucket

    async def _record_idempotent(self, *, tenant_id: str, event_id: str) -> None:
        async with self._dedup_lock:
            bucket = self._dedup.get(tenant_id)
            if bucket is None:
                bucket = _BoundedRecentSet(self._dedup_capacity)
                self._dedup[tenant_id] = bucket
            bucket.add(event_id)

    async def _drop_idempotent(self, *, tenant_id: str, event_id: str) -> None:
        async with self._dedup_lock:
            bucket = self._dedup.get(tenant_id)
            if bucket is not None:
                bucket.remove(event_id)

    def _disabled_result(
        self, event: NotificationEvent, *, target_redacted: str, reason: str
    ) -> AdapterResult:
        return AdapterResult(
            adapter_name=self.name,
            event_id=event.event_id,
            delivered=False,
            attempts=0,
            target_redacted=target_redacted,
            skipped_reason=reason,
        )

    async def send_with_retry(
        self,
        event: NotificationEvent,
        *,
        tenant_id: str,
    ) -> AdapterResult:
        """Wrap :meth:`_attempt_send` in retry / circuit / dedup logic."""
        try:
            target = self._describe_target(event=event, tenant_id=tenant_id)
        except _AdapterDisabled as exc:
            return self._disabled_result(
                event,
                target_redacted=exc.target_redacted,
                reason=exc.reason,
            )

        target_redacted = hash_target(target)

        if await self._check_idempotent(tenant_id=tenant_id, event_id=event.event_id):
            return AdapterResult(
                adapter_name=self.name,
                event_id=event.event_id,
                delivered=False,
                attempts=0,
                target_redacted=target_redacted,
                skipped_reason="idempotent_duplicate",
                duplicate_of=event.event_id,
            )

        if await self._circuit.is_open(adapter_name=self.name, tenant_id=tenant_id):
            return AdapterResult(
                adapter_name=self.name,
                event_id=event.event_id,
                delivered=False,
                attempts=0,
                target_redacted=target_redacted,
                skipped_reason="circuit_open",
                error_code="circuit_open",
            )

        last_error_code: str | None = "unknown_error"
        last_status: int | None = None
        attempts = 0
        for attempt in range(self._retryer.max_attempts):
            attempts = attempt + 1
            try:
                response = await self._attempt_send(
                    event=event, tenant_id=tenant_id, target=target
                )
            except httpx.TimeoutException:
                last_error_code = "timeout"
                last_status = None
            except httpx.HTTPError:
                last_error_code = "network_error"
                last_status = None
            else:
                if 200 <= response.status_code < 300:
                    await self._circuit.record_success(
                        adapter_name=self.name, tenant_id=tenant_id
                    )
                    await self._record_idempotent(
                        tenant_id=tenant_id, event_id=event.event_id
                    )
                    return AdapterResult(
                        adapter_name=self.name,
                        event_id=event.event_id,
                        delivered=True,
                        status_code=response.status_code,
                        attempts=attempts,
                        target_redacted=target_redacted,
                    )
                last_status = response.status_code
                if 400 <= response.status_code < 500 and response.status_code not in {
                    408,
                    425,
                    429,
                }:
                    last_error_code = "http_4xx"
                    break
                last_error_code = (
                    "http_4xx" if response.status_code < 500 else "http_5xx"
                )
            if attempt + 1 < self._retryer.max_attempts:
                await self._retryer.sleep_between(attempt)

        await self._circuit.record_failure(adapter_name=self.name, tenant_id=tenant_id)
        return AdapterResult(
            adapter_name=self.name,
            event_id=event.event_id,
            delivered=False,
            status_code=last_status,
            attempts=attempts,
            target_redacted=target_redacted,
            error_code=last_error_code,
        )

    def _describe_target(
        self, *, event: NotificationEvent, tenant_id: str
    ) -> str:  # pragma: no cover — overridden
        raise NotImplementedError

    async def _attempt_send(
        self,
        *,
        event: NotificationEvent,
        tenant_id: str,
        target: str,
    ) -> httpx.Response:  # pragma: no cover — overridden
        raise NotImplementedError


class _AdapterDisabled(Exception):
    """Raised by :meth:`NotifierBase._describe_target` when the adapter is offline.

    Carries a closed-taxonomy reason and a target-redacted handle so the
    caller can still emit a deterministic AdapterResult without exposing
    the raw URL / token.
    """

    def __init__(self, *, reason: str, target_redacted: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.target_redacted = target_redacted


__all__ = [
    "DEFAULT_BACKOFF_BASE_SECONDS",
    "DEFAULT_BACKOFF_CAP_SECONDS",
    "DEFAULT_BACKOFF_FACTOR",
    "DEFAULT_CIRCUIT_COOLDOWN_SECONDS",
    "DEFAULT_CIRCUIT_FAILURE_THRESHOLD",
    "DEFAULT_DEDUP_CAPACITY",
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_TIMEOUT_SECONDS",
    "TARGET_REDACTED_LEN",
    "CircuitBreaker",
    "NotifierBase",
    "_AdapterDisabled",
    "_BoundedRecentSet",
    "_Retryer",
    "compute_backoff_seconds",
    "hash_target",
]
