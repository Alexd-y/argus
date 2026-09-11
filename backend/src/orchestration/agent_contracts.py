"""Typed agent-task contracts (platform-hardening A, §4).

Separates the *logical task* from an *attempt* at executing it and from the
*result* it produces. A retry after failure is a new ``AgentAttempt`` (new
``attempt_id``) under the same ``task_id`` so per-attempt costs are never lost
and exactly one result is accepted as final for a given task version.

These are pure, dependency-light Pydantic models — safe to import and test
offline. Durable persistence (claim/lease/fencing) is layered on top separately
and is not required to use the contracts themselves.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AgentTaskState(StrEnum):
    """Lifecycle states for a logical agent task."""

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INCONCLUSIVE = "inconclusive"
    # Explicitly defined per §4: task is waiting for a bounded retry backoff.
    RETRY_WAIT = "retry_wait"


class AttemptOutcome(StrEnum):
    """Terminal outcome of a single execution attempt."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INCONCLUSIVE = "inconclusive"


class CoverageStatus(StrEnum):
    """The four §4 distinctions — never conflate "no findings" with "not run"."""

    TESTED_NO_FINDINGS = "tested_no_findings"
    NOT_TESTED = "not_tested"
    FAILED = "failed"
    INSUFFICIENT_DATA = "insufficient_data"


class AgentUsage(BaseModel):
    """Actual (or estimated) resource usage for an attempt.

    ``estimated`` distinguishes provider-metadata usage from a heuristic
    estimate. Local-model cost is not asserted as a proven $0: when there is no
    money estimate, tokens/duration are still recorded and ``cost_usd`` stays
    ``None``.
    """

    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float | None = None
    duration_seconds: float = 0.0
    provider: str = ""
    model: str = ""
    estimated: bool = False

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens


class AgentTaskSpec(BaseModel):
    """Immutable description of a logical agent task."""

    task_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    tenant_id: str
    scan_id: str
    phase: str
    agent_role: str
    parent_task_id: str | None = None
    # Normalised fingerprint of the input — used for dedup/idempotency.
    input_fingerprint: str = ""
    task_version: int = 1
    input_evidence_refs: list[str] = Field(default_factory=list)
    tool_constraints: list[str] = Field(default_factory=list)
    scope_constraints: dict[str, Any] = Field(default_factory=dict)
    # Budget for THIS task (tokens and optional cost ceiling).
    max_tokens: int = 0
    max_cost_usd: float | None = None
    deadline: datetime | None = None
    prompt_version: str = ""
    model_version: str = ""
    idempotency_key: str = ""

    def with_fingerprint(self, payload: Any) -> AgentTaskSpec:
        """Return a copy with input_fingerprint/idempotency_key derived."""
        fp = compute_input_fingerprint(payload)
        key = self.idempotency_key or make_idempotency_key(
            self.tenant_id, self.scan_id, self.agent_role, fp, self.task_version
        )
        return self.model_copy(update={"input_fingerprint": fp, "idempotency_key": key})


class AgentAttempt(BaseModel):
    """A single execution attempt of a task. Retries create new attempts."""

    attempt_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    task_id: str
    attempt_number: int = 1
    state: AgentTaskState = AgentTaskState.QUEUED
    worker_id: str = ""
    fencing_token: int = 0
    started_at: datetime | None = None
    finished_at: datetime | None = None
    lease_expires_at: datetime | None = None
    outcome: AttemptOutcome | None = None
    usage: AgentUsage = Field(default_factory=AgentUsage)
    error: str = ""


class AgentResult(BaseModel):
    """Structured result of an attempt.

    An empty result is NOT success (§4): callers must set ``coverage`` and
    ``outcome`` explicitly. ``no findings`` is a valid tested outcome, distinct
    from not-run / failed / insufficient-data.
    """

    task_id: str
    attempt_id: str
    outcome: AttemptOutcome
    coverage: CoverageStatus
    hypotheses: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    usage: AgentUsage = Field(default_factory=AgentUsage)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    coverage_note: str = ""
    stop_reason: str = ""

    @property
    def is_success(self) -> bool:
        return self.outcome == AttemptOutcome.SUCCEEDED

    @property
    def is_conclusive(self) -> bool:
        """A result that establishes something (tested, whether or not found)."""
        return self.outcome in (AttemptOutcome.SUCCEEDED,) and self.coverage in (
            CoverageStatus.TESTED_NO_FINDINGS,
        ) or bool(self.findings)


def compute_input_fingerprint(payload: Any) -> str:
    """Stable SHA-256 over a normalised (sorted, string-coerced) payload."""
    try:
        normalized = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        normalized = str(payload)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def make_idempotency_key(
    tenant_id: str,
    scan_id: str,
    agent_role: str,
    input_fingerprint: str,
    task_version: int,
) -> str:
    """Deterministic idempotency key for a logical task version."""
    raw = f"{tenant_id}|{scan_id}|{agent_role}|{input_fingerprint}|v{task_version}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def utcnow() -> datetime:
    return datetime.now(UTC)


__all__ = [
    "AgentAttempt",
    "AgentResult",
    "AgentTaskSpec",
    "AgentTaskState",
    "AgentUsage",
    "AttemptOutcome",
    "CoverageStatus",
    "compute_input_fingerprint",
    "make_idempotency_key",
    "utcnow",
]
