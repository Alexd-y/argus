"""Per-(tool, host) circuit breaker for Quick execution.

Minimal interface — not a copy of the MCP notification breaker. N consecutive
failures for a tool+host skip remaining templates for that host; the scan
continues. Coverage reason is ``circuit_open``.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from src.quick.budget import normalize_host_key
from src.quick.clock import Clock, SystemClock, as_utc
from src.quick.metrics import record_tool_failure

logger = logging.getLogger(__name__)

DEFAULT_FAILURE_THRESHOLD = 3
CIRCUIT_OPEN_REASON = "circuit_open"


class CircuitBreakerState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: StrictStr
    host_key: StrictStr
    failure_count: StrictInt = Field(ge=0)
    opened: bool = False
    opened_at: datetime | None = None


class QuickCircuitBreaker:
    """Synchronous breaker keyed by ``(tool_id, host)``. Open does not fail the scan."""

    def __init__(
        self,
        *,
        failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
        clock: Clock | None = None,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        self._failure_threshold = failure_threshold
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._lock = threading.Lock()
        self._state: dict[tuple[str, str], CircuitBreakerState] = {}

    @staticmethod
    def make_key(tool_id: str, host_key: str) -> tuple[str, str]:
        return ((tool_id or "").strip().lower(), normalize_host_key(host_key))

    def is_open(self, tool_id: str, host_key: str) -> bool:
        key = self.make_key(tool_id, host_key)
        with self._lock:
            state = self._state.get(key)
            return bool(state is not None and state.opened)

    def record_success(self, tool_id: str, host_key: str) -> None:
        key = self.make_key(tool_id, host_key)
        with self._lock:
            self._state.pop(key, None)

    def record_failure(self, tool_id: str, host_key: str) -> bool:
        """Record a failure. Returns True iff the breaker just opened."""
        key = self.make_key(tool_id, host_key)
        with self._lock:
            existing = self._state.get(key)
            count = (existing.failure_count if existing else 0) + 1
            already_open = bool(existing is not None and existing.opened)
            opened = count >= self._failure_threshold
            opened_at = existing.opened_at if existing is not None else None
            tripped_now = opened and not already_open
            if tripped_now:
                opened_at = as_utc(self._clock.now())
            self._state[key] = CircuitBreakerState(
                tool_id=key[0],
                host_key=key[1],
                failure_count=count,
                opened=opened,
                opened_at=opened_at,
            )
            record_tool_failure(
                tool=key[0],
                reason="circuit_open" if opened else "error",
            )
            if tripped_now:
                logger.warning(
                    "quick_circuit_open",
                    extra={
                        "event": "quick_circuit_open",
                        "tool_id": key[0],
                        "host_key": key[1],
                        "failure_count": count,
                        "coverage_reason": CIRCUIT_OPEN_REASON,
                    },
                )
            return tripped_now

    def snapshot(self, tool_id: str, host_key: str) -> CircuitBreakerState | None:
        key = self.make_key(tool_id, host_key)
        with self._lock:
            return self._state.get(key)

    @staticmethod
    def coverage_reason() -> str:
        return CIRCUIT_OPEN_REASON


_BREAKER = QuickCircuitBreaker()


def default_circuit_breaker() -> QuickCircuitBreaker:
    return _BREAKER


__all__ = [
    "CIRCUIT_OPEN_REASON",
    "DEFAULT_FAILURE_THRESHOLD",
    "CircuitBreakerState",
    "QuickCircuitBreaker",
    "default_circuit_breaker",
]
