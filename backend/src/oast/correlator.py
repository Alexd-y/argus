"""OAST interaction correlator (Backlog/dev1_md §11).

The correlator is the bridge between the asynchronous OAST listeners (DNS,
HTTP, SMTP) and the validator loop running inside the orchestrator. It
exposes three responsibilities and nothing else:

* **Ingest** — :meth:`OASTCorrelator.ingest` accepts a freshly observed
  :class:`OASTInteraction` from any listener implementation, sanitises the
  metadata strings (control characters stripped, lengths capped), stores it
  against the matching token, and signals every awaiter.

* **Wait** — :meth:`OASTCorrelator.wait_for_interaction` blocks (via an
  :class:`asyncio.Event`, never a polling loop) until an interaction lands
  or the configurable correlator window elapses. The default window is
  60 seconds; the maximum is 300 seconds to bound worst-case latency on
  retry storms.

* **Inspect** — :meth:`OASTCorrelator.list_interactions` returns the
  currently known interaction list for a token; useful for the verifier
  agent (cycle 1 ARG-008) and for evidence packaging.

Design notes:

* **No listener I/O.** The correlator never opens sockets or DNS resolvers. It
  consumes events produced by external listeners (see
  :mod:`src.oast.listener_protocol`). An optional
  ``on_interaction_stored`` callback may perform best-effort persistence
  (e.g. Redis Streams) after a successful ingest.
* **Tenant isolation.** The correlator validates that interactions match
  the owning tenant of the token; foreign interactions are dropped silently
  with a warning log so noisy DNS scanners cannot poison the lookup table.
* **Idempotent ingestion.** Listeners may replay events (think SMTP
  retries) — the correlator deduplicates by ``(token_id, interaction.id)``
  so the verifier observes each unique callback exactly once.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import threading
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Final
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    field_validator,
    model_validator,
)
from typing_extensions import Self

from src.core.observability import get_tracer, safe_set_span_attribute
from src.oast.provisioner import OASTProvisioner


_logger = logging.getLogger(__name__)
_tracer = get_tracer("argus.oast.correlator")


_DEFAULT_WINDOW_SECONDS: Final[int] = 60
_MAX_WINDOW_SECONDS: Final[int] = 300
_MAX_METADATA_VALUE_LEN: Final[int] = 256
_MAX_METADATA_KEYS: Final[int] = 16
_MAX_INTERACTIONS_PER_TOKEN: Final[int] = 256
_DEFAULT_MAX_RETENTION: Final[timedelta] = timedelta(hours=1)
_DEFAULT_PURGE_GRACE: Final[timedelta] = timedelta(minutes=5)
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
_CTRL_CHAR_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_METADATA_KEY_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


# Each token gets a single :class:`asyncio.Event` shared by every waiter and
# pinned to the loop that minted it. The loop reference lets ``ingest`` (which
# may run on a Celery worker thread) dispatch the wake via
# :meth:`asyncio.AbstractEventLoop.call_soon_threadsafe` without reaching into
# CPython internals.
_EventEntry = tuple[asyncio.Event, asyncio.AbstractEventLoop]


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class InteractionKind(StrEnum):
    """Closed taxonomy of OAST callback kinds.

    A single token may collect multiple callbacks of different kinds
    (DNS A query followed by an HTTP GET); the correlator stores all of
    them against the token id.
    """

    DNS_A = "dns_a"
    DNS_AAAA = "dns_aaaa"
    DNS_TXT = "dns_txt"
    DNS_ANY = "dns_any"
    HTTP_REQUEST = "http_request"
    HTTPS_REQUEST = "https_request"
    SMTP_RCPT = "smtp_rcpt"


def _sanitize_metadata(metadata: dict[str, str]) -> dict[str, str]:
    """Strip control characters and truncate every value/key to safe bounds.

    Listeners feed metadata they extracted from raw bytes (DNS qname,
    HTTP headers, SMTP envelope). Although they SHOULD already strip
    obvious garbage, we re-apply the invariant here so the correlator
    can never store malicious bytes that downstream serialisers would
    fail on.
    """
    if len(metadata) > _MAX_METADATA_KEYS:
        raise ValueError(
            f"metadata has {len(metadata)} keys; max is {_MAX_METADATA_KEYS}"
        )
    cleaned: dict[str, str] = {}
    for key, value in metadata.items():
        if not isinstance(key, str) or not _METADATA_KEY_RE.fullmatch(key):
            raise ValueError(
                f"metadata key {key!r} must match ^[a-z][a-z0-9_]{{0,31}}$"
            )
        if not isinstance(value, str):
            raise ValueError(
                f"metadata value for key {key!r} must be a str, got "
                f"{type(value).__name__}"
            )
        scrubbed = _CTRL_CHAR_RE.sub("", value)
        if len(scrubbed) > _MAX_METADATA_VALUE_LEN:
            scrubbed = scrubbed[:_MAX_METADATA_VALUE_LEN]
        cleaned[key] = scrubbed
    return cleaned


class OASTInteraction(BaseModel):
    """A single observed callback against an issued OAST token.

    The model intentionally does NOT carry the raw request bytes; those
    live in the evidence store keyed on :attr:`raw_request_hash` so we can
    verify integrity later without bloating the in-memory correlator.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    token_id: UUID
    kind: InteractionKind
    received_at: datetime = Field(default_factory=_utcnow)
    source_ip: StrictStr = Field(min_length=1, max_length=64)
    metadata: dict[StrictStr, StrictStr] = Field(default_factory=dict)
    raw_request_hash: StrictStr = Field(min_length=64, max_length=64)

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, value: dict[str, str]) -> dict[str, str]:
        return _sanitize_metadata(dict(value))

    @field_validator("source_ip")
    @classmethod
    def _validate_source_ip(cls, value: str) -> str:
        scrubbed = _CTRL_CHAR_RE.sub("", value)
        if not scrubbed:
            raise ValueError("source_ip must not be empty after sanitisation")
        return scrubbed

    @field_validator("raw_request_hash")
    @classmethod
    def _validate_hash(cls, value: str) -> str:
        if not _SHA256_RE.fullmatch(value):
            raise ValueError("raw_request_hash must be lowercase 64-char hex")
        return value

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if self.received_at.tzinfo is None:
            raise ValueError("received_at must be timezone-aware")
        return self

    @classmethod
    def build(
        cls,
        *,
        id: UUID,
        token_id: UUID,
        kind: InteractionKind,
        source_ip: str,
        raw_request_bytes: bytes,
        metadata: dict[str, str] | None = None,
        received_at: datetime | None = None,
    ) -> "OASTInteraction":
        """Convenience constructor that hashes ``raw_request_bytes`` for you.

        Listeners feed the bytes they already have on hand (one DNS UDP
        datagram, one HTTP request line + headers + body); the correlator
        only stores the digest.
        """
        digest = hashlib.sha256(raw_request_bytes).hexdigest()
        return cls(
            id=id,
            token_id=token_id,
            kind=kind,
            source_ip=source_ip,
            raw_request_hash=digest,
            metadata=dict(metadata or {}),
            received_at=received_at or _utcnow(),
        )


# ---------------------------------------------------------------------------
# Correlator
# ---------------------------------------------------------------------------


class OASTCorrelator:
    """Aggregate OAST interactions and unblock waiters when they arrive.

    Parameters
    ----------
    provisioner
        Source of truth for token tenancy. The correlator queries the
        provisioner before storing an interaction so foreign or unknown
        tokens are silently rejected (and logged at INFO so SOC pipelines
        can pick them up if needed).
    default_window_s
        Default value for :paramref:`wait_for_interaction.timeout_s` when
        the caller passes ``None``.
    max_window_s
        Hard ceiling on the wait window — clamps both the default and any
        explicit ``timeout_s`` passed to
        :meth:`wait_for_interaction`. 300 s matches the Backlog limit on
        OAST validator deadlines.
    max_per_token
        Defensive bound on per-token storage. A noisy target could trigger
        thousands of callbacks; we cap at ``max_per_token`` and drop the
        excess with a WARNING log so the correlator memory footprint is
        predictable.
    max_retention
        Per-interaction age ceiling. Records older than ``now - max_retention``
        are evicted by :meth:`purge_expired`. Defaults to one hour, which
        comfortably outlasts the longest validator wait window (300 s) plus
        post-validation evidence packaging windows.
    """

    def __init__(
        self,
        provisioner: OASTProvisioner,
        *,
        default_window_s: int = _DEFAULT_WINDOW_SECONDS,
        max_window_s: int = _MAX_WINDOW_SECONDS,
        max_per_token: int = _MAX_INTERACTIONS_PER_TOKEN,
        max_retention: timedelta = _DEFAULT_MAX_RETENTION,
        on_interaction_stored: Callable[[OASTInteraction], None] | None = None,
    ) -> None:
        if default_window_s <= 0:
            raise ValueError("default_window_s must be positive")
        if max_window_s <= 0:
            raise ValueError("max_window_s must be positive")
        if default_window_s > max_window_s:
            raise ValueError(
                "default_window_s must be <= max_window_s"
                f" (got {default_window_s} vs {max_window_s})"
            )
        if max_per_token <= 0:
            raise ValueError("max_per_token must be positive")
        if max_retention.total_seconds() <= 0:
            raise ValueError("max_retention must be positive")

        self._provisioner = provisioner
        self._default_window_s = default_window_s
        self._max_window_s = max_window_s
        self._max_per_token = max_per_token
        self._max_retention = max_retention
        self._on_interaction_stored = on_interaction_stored

        self._interactions: dict[UUID, list[OASTInteraction]] = {}
        self._seen_ids: dict[UUID, set[UUID]] = {}
        self._events: dict[UUID, _EventEntry] = {}
        self._lock = threading.Lock()

    # -- public API ----------------------------------------------------------

    @property
    def default_window_s(self) -> int:
        return self._default_window_s

    @property
    def max_window_s(self) -> int:
        return self._max_window_s

    @property
    def max_retention(self) -> timedelta:
        return self._max_retention

    def ingest(self, interaction: OASTInteraction) -> bool:
        """Store ``interaction`` and unblock any awaiter on its token.

        Returns ``True`` when the interaction was stored, ``False`` when
        it was dropped (unknown token, foreign tenant, or duplicate id).
        """
        with _tracer.start_as_current_span("oast.correlate") as span:
            safe_set_span_attribute(span, "argus.token_id", str(interaction.token_id))
            safe_set_span_attribute(span, "argus.kind", interaction.kind.value)
            stored = self._ingest_inner(interaction)
            safe_set_span_attribute(span, "argus.stored", stored)
            if stored and self._on_interaction_stored is not None:
                try:
                    self._on_interaction_stored(interaction)
                except Exception as exc:
                    _logger.warning(
                        "oast.correlator.on_interaction_stored_failed",
                        extra={
                            "event": "oast.correlator.on_interaction_stored_failed",
                            "error_type": type(exc).__name__,
                        },
                    )
            return stored

    def _ingest_inner(self, interaction: OASTInteraction) -> bool:
        """Inner ingest body wrapped by the OTel span in :meth:`ingest`."""
        token = self._provisioner.get(interaction.token_id)
        if token is None:
            _logger.info(
                "oast.correlator.unknown_token",
                extra={
                    "token_id": str(interaction.token_id),
                    "kind": interaction.kind.value,
                    "source_ip": interaction.source_ip,
                },
            )
            return False

        # Capacity + dedup checks happen under the lock so concurrent
        # ingest calls never race past the threshold.
        with self._lock:
            seen = self._seen_ids.setdefault(token.id, set())
            if interaction.id in seen:
                _logger.debug(
                    "oast.correlator.duplicate_interaction",
                    extra={
                        "token_id": str(token.id),
                        "interaction_id": str(interaction.id),
                    },
                )
                return False
            bucket = self._interactions.setdefault(token.id, [])
            if len(bucket) >= self._max_per_token:
                _logger.warning(
                    "oast.correlator.bucket_full",
                    extra={
                        "token_id": str(token.id),
                        "max_per_token": self._max_per_token,
                    },
                )
                return False
            bucket.append(interaction)
            seen.add(interaction.id)
            event_entry = self._events.get(token.id)

        if event_entry is not None:
            # Schedule the set on the event's loop so cross-thread ingest
            # (e.g. from a Celery worker pushing into FastAPI's loop) is
            # safe even when the loop is bound to a different thread.
            self._signal(*event_entry)

        _logger.debug(
            "oast.correlator.interaction_stored",
            extra={
                "token_id": str(token.id),
                "kind": interaction.kind.value,
                "source_ip": interaction.source_ip,
            },
        )
        return True

    def list_interactions(
        self,
        token_id: UUID,
        *,
        kinds: Iterable[InteractionKind] | None = None,
    ) -> list[OASTInteraction]:
        """Return a snapshot of the interactions stored for ``token_id``.

        ``kinds`` filters by callback kind; pass ``None`` for all kinds.
        The result is a fresh list so callers may mutate it without
        affecting the correlator's internal state.
        """
        kind_filter = frozenset(kinds) if kinds is not None else None
        with self._lock:
            bucket = list(self._interactions.get(token_id, ()))
        if kind_filter is None:
            return bucket
        return [item for item in bucket if item.kind in kind_filter]

    async def wait_for_interaction(
        self,
        token_id: UUID,
        *,
        timeout_s: int | None = None,
        kinds: Iterable[InteractionKind] | None = None,
    ) -> list[OASTInteraction]:
        """Wait until at least one matching interaction is available.

        The wait is asynchronous and uses :class:`asyncio.Event`; callers
        consume zero CPU while waiting. When ``timeout_s`` elapses the
        method returns whatever interactions are currently stored
        (possibly an empty list) so the verifier can decide between
        retrying and downgrading to the canary fallback.

        Parameters
        ----------
        token_id
            Identifier returned by :meth:`OASTProvisioner.issue`.
        timeout_s
            Wait window in seconds. Defaults to :attr:`default_window_s`
            and is clamped to :attr:`max_window_s`. Negative values are
            rejected; ``0`` returns immediately with current state.
        kinds
            Optional set of kinds to filter on; the wait completes only
            when an interaction of one of those kinds has been stored.
        """
        kind_filter = frozenset(kinds) if kinds is not None else None
        wait_s = self._resolve_window(timeout_s)
        existing = self._snapshot_matching(token_id, kind_filter)
        if existing:
            return existing
        if wait_s == 0:
            return existing

        event = self._get_or_create_event(token_id)
        deadline = _utcnow().timestamp() + wait_s
        while True:
            remaining = deadline - _utcnow().timestamp()
            if remaining <= 0:
                break
            try:
                await asyncio.wait_for(event.wait(), timeout=remaining)
            except asyncio.TimeoutError:
                break
            # Consume the wake immediately so the next iteration cannot
            # busy-loop on a stale "set" flag. ``ingest`` always appends to
            # the bucket BEFORE signalling, so any interaction that
            # triggered this wake is guaranteed to be visible to the
            # snapshot below; ingests that race AFTER the clear simply set
            # the event again and the next iteration picks them up.
            event.clear()
            current = self._snapshot_matching(token_id, kind_filter)
            if current:
                return current
            # If our event slot has been reclaimed (``purge_expired`` GC,
            # ``clear``, or a different loop minting a fresh event), exit
            # rather than re-registering an orphan event that nobody will
            # signal again — the wake we just consumed *was* the eviction
            # notification.
            with self._lock:
                slot = self._events.get(token_id)
            if slot is None or slot[0] is not event:
                break
            # Spurious wake (e.g. ingest happened for a different filter):
            # event is already cleared, so the next ``await event.wait()``
            # blocks until ingest signals again.

        return self._snapshot_matching(token_id, kind_filter)

    def purge_expired(
        self,
        *,
        before: datetime | None = None,
        grace: timedelta = _DEFAULT_PURGE_GRACE,
    ) -> int:
        """Drop interactions whose token expired or that exceed the retention window.

        Two eviction policies are applied in a single sweep:

        * **Token-level**: if the provisioner no longer recognises a token
          OR the token's ``expires_at`` is older than ``before - grace``,
          the entire bucket (interactions, dedup set, event entry) is
          dropped. Any blocked waiter is signalled so it returns its
          current snapshot promptly instead of hanging until its own
          deadline.
        * **Interaction-level**: surviving buckets are filtered to drop
          interactions whose ``received_at`` is older than
          ``before - max_retention``. Empty buckets are then evicted as
          well to keep memory usage bounded.

        Parameters
        ----------
        before
            Reference moment. Defaults to ``_utcnow()``. Must be
            timezone-aware.
        grace
            Extra buffer added to ``token.expires_at`` before token-level
            eviction. Absorbs late OAST callbacks that may still be useful
            for evidence packaging. Must be non-negative.

        Returns
        -------
        int
            Number of interactions evicted (NOT buckets / events).
        """
        if grace.total_seconds() < 0:
            raise ValueError("grace must be non-negative")
        moment = before if before is not None else _utcnow()
        if moment.tzinfo is None:
            raise ValueError("before must be timezone-aware")

        token_threshold = moment - grace
        interaction_threshold = moment - self._max_retention

        evicted = 0
        with self._lock:
            for token_id in list(self._interactions.keys()):
                token = self._provisioner.get(token_id)
                if token is None or token.expires_at < token_threshold:
                    bucket = self._interactions.pop(token_id, [])
                    evicted += len(bucket)
                    self._seen_ids.pop(token_id, None)
                    entry = self._events.pop(token_id, None)
                    if entry is not None:
                        # Wake any waiter so it can return its (now empty)
                        # snapshot without waiting for its deadline.
                        self._signal(*entry)
                    continue

                bucket = self._interactions[token_id]
                kept = [
                    item for item in bucket if item.received_at >= interaction_threshold
                ]
                evicted += len(bucket) - len(kept)
                if kept:
                    self._interactions[token_id] = kept
                    self._seen_ids[token_id] = {item.id for item in kept}
                else:
                    self._interactions.pop(token_id, None)
                    self._seen_ids.pop(token_id, None)

            # Standalone events (waiters that registered before any ingest)
            # also need GC when their token is gone, otherwise ``self._events``
            # grows without bound across long-running scans.
            for token_id in list(self._events.keys()):
                if token_id in self._interactions:
                    continue
                token = self._provisioner.get(token_id)
                if token is None or token.expires_at < token_threshold:
                    entry = self._events.pop(token_id)
                    self._signal(*entry)

        if evicted:
            _logger.info(
                "oast.correlator.purged_interactions",
                extra={
                    "count": evicted,
                    "grace_seconds": grace.total_seconds(),
                    "max_retention_seconds": self._max_retention.total_seconds(),
                },
            )
        return evicted

    # -- helpers -------------------------------------------------------------

    def _resolve_window(self, timeout_s: int | None) -> int:
        if timeout_s is None:
            return self._default_window_s
        if timeout_s < 0:
            raise ValueError("timeout_s must be >= 0")
        return min(timeout_s, self._max_window_s)

    def _snapshot_matching(
        self, token_id: UUID, kinds: frozenset[InteractionKind] | None
    ) -> list[OASTInteraction]:
        with self._lock:
            bucket = list(self._interactions.get(token_id, ()))
        if kinds is None:
            return bucket
        return [item for item in bucket if item.kind in kinds]

    def _get_or_create_event(self, token_id: UUID) -> asyncio.Event:
        loop = asyncio.get_running_loop()
        with self._lock:
            existing = self._events.get(token_id)
            if existing is not None:
                event, captured_loop = existing
                if captured_loop is loop:
                    return event
                # The previous event is bound to a different loop (only
                # realistic in test fixtures that recycle the correlator
                # across loops). Drop it and create a fresh one for the
                # current loop so we never call ``set`` on a closed loop.
            event = asyncio.Event()
            self._events[token_id] = (event, loop)
            return event

    @staticmethod
    def _signal(event: asyncio.Event, loop: asyncio.AbstractEventLoop) -> None:
        """Set ``event`` from any thread via its captured ``loop``."""
        if loop.is_closed():
            return
        try:
            current = asyncio.get_running_loop()
        except RuntimeError:
            current = None
        if current is loop:
            event.set()
            return
        try:
            loop.call_soon_threadsafe(event.set)
        except RuntimeError:
            # Loop closed between ``is_closed`` check and the schedule
            # call (race). The waiter is gone; nothing to do.
            return

    # -- introspection helpers (test surfaces) ------------------------------

    def known_tokens(self) -> Iterator[UUID]:
        with self._lock:
            return iter(list(self._interactions.keys()))

    def clear(self) -> None:
        """Drop every stored interaction (used by tests + restart logic)."""
        with self._lock:
            self._interactions.clear()
            self._seen_ids.clear()
            entries = list(self._events.values())
            self._events.clear()
        # Wake every parked waiter so they observe the now-empty snapshot
        # and return promptly. Done OUTSIDE the lock so a same-loop
        # ``call_soon`` cannot reenter the correlator under our own lock.
        for entry in entries:
            self._signal(*entry)


__all__ = [
    "InteractionKind",
    "OASTCorrelator",
    "OASTInteraction",
]
