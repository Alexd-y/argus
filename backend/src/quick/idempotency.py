"""Idempotency keys for Quick tool runs.

Key material is ``(scan_id, tool_id, target_ref, template_digest, plan_version)``.
A second delivery with the same key must not start another tool process.
Worker-lost retries are allowed only while a budget lease remains.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

logger = logging.getLogger(__name__)

_KEY_MAX = 256
_EMPTY_DIGEST = "none"


class IdempotencyClaim(StrEnum):
    ACQUIRED = "acquired"
    DUPLICATE_SUCCEEDED = "duplicate_succeeded"
    IN_FLIGHT = "in_flight"
    RETRY_ALLOWED = "retry_allowed"
    BLOCKED = "blocked"


class IdempotencyRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    key: StrictStr = Field(min_length=1, max_length=_KEY_MAX)
    scan_id: StrictStr = Field(min_length=1, max_length=36)
    tool_id: StrictStr = Field(min_length=1, max_length=128)
    status: StrictStr = Field(min_length=1, max_length=32)
    plan_version: StrictInt = Field(ge=1)


def build_idempotency_key(
    *,
    scan_id: str,
    tool_id: str,
    target_ref: str,
    template_digest: str | None,
    plan_version: int,
) -> str:
    """Stable key matching the Quick planner format, truncated or hashed to 256 chars."""
    digest = (template_digest or "").strip() or _EMPTY_DIGEST
    raw = (
        f"{scan_id}:{tool_id}:{target_ref}:{digest}:{int(plan_version)}"
    )
    if len(raw) <= _KEY_MAX:
        return raw
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class QuickIdempotencyStore:
    """Process-local claim table. DB uniqueness on ``quick_tasks.idempotency_key`` is the durable gate."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, IdempotencyRecord] = {}

    def claim(
        self,
        key: str,
        *,
        scan_id: str,
        tool_id: str,
        plan_version: int,
        lease_remaining: bool,
    ) -> IdempotencyClaim:
        """Acquire the key or explain why the run must not start."""
        with self._lock:
            existing = self._records.get(key)
            if existing is None:
                self._records[key] = IdempotencyRecord(
                    key=key,
                    scan_id=scan_id,
                    tool_id=tool_id,
                    status="running",
                    plan_version=plan_version,
                )
                return IdempotencyClaim.ACQUIRED
            if existing.status == "succeeded":
                logger.info(
                    "quick_idempotency_duplicate",
                    extra={
                        "event": "quick_idempotency_duplicate",
                        "scan_id": scan_id,
                        "tool_id": tool_id,
                    },
                )
                return IdempotencyClaim.DUPLICATE_SUCCEEDED
            if existing.status == "running":
                if lease_remaining:
                    return IdempotencyClaim.IN_FLIGHT
                return IdempotencyClaim.BLOCKED
            if existing.status in {"failed", "timed_out", "lost"} and lease_remaining:
                self._records[key] = existing.model_copy(update={"status": "running"})
                return IdempotencyClaim.RETRY_ALLOWED
            return IdempotencyClaim.BLOCKED

    def complete(self, key: str, *, succeeded: bool) -> None:
        with self._lock:
            existing = self._records.get(key)
            if existing is None:
                return
            status = "succeeded" if succeeded else "failed"
            self._records[key] = existing.model_copy(update={"status": status})

    def mark_lost(self, key: str) -> None:
        """Worker disappeared before completion — retry is allowed if the lease remains."""
        with self._lock:
            existing = self._records.get(key)
            if existing is None or existing.status == "succeeded":
                return
            self._records[key] = existing.model_copy(update={"status": "lost"})

    def get(self, key: str) -> IdempotencyRecord | None:
        with self._lock:
            return self._records.get(key)


_STORE = QuickIdempotencyStore()


def default_idempotency_store() -> QuickIdempotencyStore:
    return _STORE


__all__ = [
    "IdempotencyClaim",
    "IdempotencyRecord",
    "QuickIdempotencyStore",
    "build_idempotency_key",
    "default_idempotency_store",
]
