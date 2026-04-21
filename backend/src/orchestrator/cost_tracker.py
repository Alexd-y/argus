"""Per-tenant / per-scan LLM cost & token bookkeeping (Backlog/dev1_md §13, §14).

Every :class:`~src.orchestrator.llm_provider.LLMResponse` that flows through
the orchestrator is recorded as a :class:`CostRecord`. The tracker exposes
two aggregations:

* :meth:`CostTracker.total_for_scan` — used by the retry loop to enforce
  per-scan budget caps.
* :meth:`CostTracker.total_for_tenant` — used by the policy plane to
  enforce daily / monthly budget caps (per Backlog/dev1_md §14). The
  ``since`` keyword projects to the relevant time window.

Design constraints
------------------
* Pure in-memory; thread-safe via a single :class:`threading.Lock`. The
  total volume per cycle is small (~10²–10³ calls per scan), so a simple
  list / dict aggregation is more than adequate.
* No I/O. Production deploys swap in a Redis / Postgres-backed sink behind
  the same surface (mirrors :mod:`src.policy.audit`).
* :class:`CostRecord` is frozen + ``extra="forbid"`` to keep the model
  honest; the tracker never mutates a record once recorded.
"""

from __future__ import annotations

import logging
import threading
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Final
from uuid import UUID, uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictFloat,
    StrictInt,
    StrictStr,
)

from src.orchestrator.prompt_registry import AgentRole

_logger = logging.getLogger(__name__)


_MIN_RECORD_AGE = 0  # seconds; records are timestamp-checked, not aged out


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class CostRecord(BaseModel):
    """One immutable LLM cost / token bookkeeping row."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    record_id: UUID = Field(default_factory=uuid4)
    correlation_id: UUID
    tenant_id: UUID
    scan_id: UUID
    agent_role: AgentRole
    prompt_id: StrictStr = Field(min_length=1, max_length=128)
    model_id: StrictStr = Field(min_length=1, max_length=128)
    prompt_tokens: StrictInt = Field(ge=0)
    completion_tokens: StrictInt = Field(ge=0)
    usd_cost: StrictFloat = Field(ge=0.0)
    latency_ms: StrictInt = Field(ge=0)
    attempt: StrictInt = Field(ge=1, le=16)
    created_at: datetime = Field(default_factory=_utcnow)


class CostSummary(BaseModel):
    """Aggregated counters over a slice of :class:`CostRecord`s."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    total_prompt_tokens: StrictInt = Field(ge=0)
    total_completion_tokens: StrictInt = Field(ge=0)
    total_usd: StrictFloat = Field(ge=0.0)
    record_count: StrictInt = Field(ge=0)
    by_role: dict[str, StrictInt] = Field(default_factory=dict)


_DEFAULT_USD_PRECISION: Final[int] = 6


class CostTracker:
    """Thread-safe in-memory aggregator for LLM cost / token records.

    Production deployments are expected to wrap this surface with a
    persistent backend (Postgres `llm_cost_records` table, Redis hash,
    or an OTel metric exporter) — the public API is the contract every
    backend must satisfy.
    """

    def __init__(self) -> None:
        self._records_by_scan: dict[UUID, list[CostRecord]] = defaultdict(list)
        self._records_by_tenant: dict[UUID, list[CostRecord]] = defaultdict(list)
        self._lock = threading.Lock()

    # -- public API ----------------------------------------------------------

    def record(
        self,
        *,
        correlation_id: UUID,
        tenant_id: UUID,
        scan_id: UUID,
        agent_role: AgentRole,
        prompt_id: str,
        model_id: str,
        prompt_tokens: int,
        completion_tokens: int,
        usd_cost: float,
        latency_ms: int,
        attempt: int,
    ) -> CostRecord:
        """Persist a :class:`CostRecord` and return the materialised row."""
        record = CostRecord(
            correlation_id=correlation_id,
            tenant_id=tenant_id,
            scan_id=scan_id,
            agent_role=agent_role,
            prompt_id=prompt_id,
            model_id=model_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            usd_cost=usd_cost,
            latency_ms=latency_ms,
            attempt=attempt,
        )
        with self._lock:
            self._records_by_scan[scan_id].append(record)
            self._records_by_tenant[tenant_id].append(record)
        _logger.info(
            "orchestrator.cost.recorded",
            extra={
                "correlation_id": str(correlation_id),
                "tenant_id": str(tenant_id),
                "scan_id": str(scan_id),
                "agent_role": agent_role.value,
                "prompt_id": prompt_id,
                "model_id": model_id,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "usd_cost": round(usd_cost, _DEFAULT_USD_PRECISION),
                "latency_ms": latency_ms,
                "attempt": attempt,
            },
        )
        return record

    def total_for_scan(self, scan_id: UUID) -> CostSummary:
        """Aggregate every :class:`CostRecord` for ``scan_id``."""
        with self._lock:
            records = list(self._records_by_scan.get(scan_id, ()))
        return _summarise(records)

    def total_for_tenant(
        self,
        tenant_id: UUID,
        *,
        since: datetime | None = None,
    ) -> CostSummary:
        """Aggregate :class:`CostRecord`s for ``tenant_id``.

        ``since`` filters to ``record.created_at >= since`` (timezone-aware).
        Pass ``None`` to include every record.
        """
        with self._lock:
            records = list(self._records_by_tenant.get(tenant_id, ()))
        if since is not None:
            if since.tzinfo is None:
                raise ValueError("since must be timezone-aware (UTC recommended)")
            records = [r for r in records if r.created_at >= since]
        return _summarise(records)

    def list_records_for_scan(self, scan_id: UUID) -> list[CostRecord]:
        """Return a snapshot of records for ``scan_id`` (read-only copy)."""
        with self._lock:
            return list(self._records_by_scan.get(scan_id, ()))


def _summarise(records: Iterable[CostRecord]) -> CostSummary:
    """Reduce ``records`` into a :class:`CostSummary`."""
    total_prompt = 0
    total_completion = 0
    total_usd = 0.0
    by_role: Counter[str] = Counter()
    count = 0
    for record in records:
        total_prompt += record.prompt_tokens
        total_completion += record.completion_tokens
        total_usd += record.usd_cost
        by_role[record.agent_role.value] += (
            record.prompt_tokens + record.completion_tokens
        )
        count += 1
    return CostSummary(
        total_prompt_tokens=total_prompt,
        total_completion_tokens=total_completion,
        total_usd=round(total_usd, _DEFAULT_USD_PRECISION),
        record_count=count,
        by_role=dict(by_role),
    )


__all__ = [
    "CostRecord",
    "CostSummary",
    "CostTracker",
]
