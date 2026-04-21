"""ARG-041 — In-process LLM provider health registry.

The registry is the single source of truth that ``/providers/health`` and
``/ready`` consult. Any LLM client (OpenAI, Anthropic, Gemini, DeepSeek)
records every outbound call here so the registry can compute a 60-second
rolling 5xx error rate, expose the circuit-breaker state, and surface the
last-success timestamp.

Design constraints:

* **In-process only.** A pod has its own view; a fleet-wide rollup happens
  in Prometheus / Grafana, not here. This keeps the readiness probe lock-free
  and free of external dependencies.
* **Bounded memory.** A single deque per provider (max 256 records) caps
  memory at ≈30 KB / provider regardless of traffic.
* **Thread-safe.** All mutators take a per-provider lock so concurrent
  HTTPX clients can record without races. Reads take a snapshot under the
  lock to avoid torn observations.
* **Provider whitelist.** Unknown provider names are silently bucketed into
  ``"_other"`` so a misconfigured client can never explode the registry's
  cardinality.

The circuit-breaker state is *not* enforced here — it is a derived
observation written by the resilience layer (``src.llm.circuit_breaker`` —
to be wired in a follow-up task). Until then the state defaults to
``"closed"``; consumers should treat ``"unknown"`` as informational.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Final, Literal

#: Canonical providers ARGUS supports today. The ``_other`` bucket catches
#: anything outside the whitelist so the registry stays low-cardinality.
KNOWN_PROVIDERS: Final[tuple[str, ...]] = (
    "openai",
    "anthropic",
    "google",
    "deepseek",
    "openrouter",
    "kimi",
    "perplexity",
)

_OTHER_PROVIDER: Final[str] = "_other"

#: Rolling-window length used by the error-rate calculation. 60 s is short
#: enough to react quickly during incidents, long enough to keep a single
#: 5xx spike from declaring the provider DOWN.
_WINDOW_SECONDS: Final[float] = 60.0

#: Hard cap on per-provider record count — bounds memory and CPU per scrape.
_MAX_RECORDS_PER_PROVIDER: Final[int] = 256

CircuitState = Literal["closed", "open", "half_open", "unknown"]


@dataclass(frozen=True, slots=True)
class _CallRecord:
    ts: float
    status_code: int  # HTTP status; 0 if connection failed before response


@dataclass(slots=True)
class ProviderState:
    """Snapshot returned by :func:`snapshot` — pure data, safe to share."""

    provider: str
    state: CircuitState = "closed"
    last_success_ts: float | None = None
    error_rate_5xx: float = 0.0
    error_count_60s: int = 0
    request_count_60s: int = 0
    records: deque[_CallRecord] = field(default_factory=lambda: deque(maxlen=_MAX_RECORDS_PER_PROVIDER))


class ProviderHealthRegistry:
    """Thread-safe per-provider health tracker.

    Public API is deliberately small:

    * :meth:`record_call` — log one outbound request (status code).
    * :meth:`set_state` — flip the circuit-breaker state.
    * :meth:`snapshot` — return per-provider snapshots for the JSON response.
    """

    def __init__(self, *, clock: "callable[[], float] | None" = None) -> None:
        self._clock = clock or time.time
        self._states: dict[str, ProviderState] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _normalize(provider: str) -> str:
        s = (provider or "").strip().lower()
        return s if s in KNOWN_PROVIDERS else _OTHER_PROVIDER

    def _state_for(self, provider: str) -> ProviderState:
        normalized = self._normalize(provider)
        st = self._states.get(normalized)
        if st is None:
            st = ProviderState(provider=normalized)
            self._states[normalized] = st
        return st

    def record_call(self, provider: str, *, status_code: int) -> None:
        """Record one outbound call. ``status_code=0`` denotes a connection error.

        ``status_code`` 2xx counts as success and bumps ``last_success_ts``;
        5xx (or 0 for connect errors) counts toward the 60s error rate.
        """
        ts = self._clock()
        with self._lock:
            st = self._state_for(provider)
            st.records.append(_CallRecord(ts=ts, status_code=int(status_code)))
            if 200 <= int(status_code) < 300:
                st.last_success_ts = ts

    def set_state(self, provider: str, state: CircuitState) -> None:
        """Flip the circuit-breaker state for *provider*."""
        with self._lock:
            st = self._state_for(provider)
            st.state = state

    def snapshot(self) -> list[ProviderState]:
        """Return a snapshot list (one per known provider) for JSON output.

        Computes the 60-second 5xx error rate at read time so callers always
        see a current value. Providers with zero traffic in the window are
        included with ``state="closed"`` and zero counts so the JSON response
        keeps a stable shape.
        """
        now = self._clock()
        out: list[ProviderState] = []
        with self._lock:
            for provider in KNOWN_PROVIDERS + (_OTHER_PROVIDER,):
                src = self._states.get(provider)
                if src is None:
                    out.append(ProviderState(provider=provider))
                    continue
                requests = 0
                errors = 0
                for record in src.records:
                    if now - record.ts > _WINDOW_SECONDS:
                        continue
                    requests += 1
                    if record.status_code == 0 or 500 <= record.status_code < 600:
                        errors += 1
                rate = (errors / requests) if requests > 0 else 0.0
                out.append(
                    ProviderState(
                        provider=src.provider,
                        state=src.state,
                        last_success_ts=src.last_success_ts,
                        error_rate_5xx=round(rate, 4),
                        error_count_60s=errors,
                        request_count_60s=requests,
                        records=src.records,
                    ),
                )
        return out

    def reset(self) -> None:
        """Drop all state — for tests only."""
        with self._lock:
            self._states.clear()


_default_registry: ProviderHealthRegistry | None = None
_default_lock = threading.Lock()


def get_provider_health_registry() -> ProviderHealthRegistry:
    """Return the process-wide default registry (lazy init)."""
    global _default_registry
    if _default_registry is None:
        with _default_lock:
            if _default_registry is None:
                _default_registry = ProviderHealthRegistry()
    return _default_registry


def reset_provider_health_registry() -> None:
    """Drop the process-wide registry — for tests only."""
    global _default_registry
    with _default_lock:
        _default_registry = None


__all__ = [
    "KNOWN_PROVIDERS",
    "ProviderHealthRegistry",
    "ProviderState",
    "get_provider_health_registry",
    "reset_provider_health_registry",
]
