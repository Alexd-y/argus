"""Unified LLM request/response contracts (master prompt §5.1, §5.2)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from src.execution_mode.mode import ExecutionMode

__all__ = [
    "CircuitState",
    "Citation",
    "ContentClass",
    "ExecutionMode",
    "FallbackAttempt",
    "LlmRequest",
    "LlmResponseEnvelope",
    "LlmResponseStatus",
    "UsageMetrics",
]


class ContentClass(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    TENANT_CONFIDENTIAL = "tenant_confidential"
    SECRET_REF_ONLY = "secret_ref_only"
    LAB_ARTIFACT = "lab_artifact"


class LlmResponseStatus(StrEnum):
    OK = "ok"
    NEEDS_EVIDENCE = "needs_evidence"
    BLOCKED_BOUNDARY = "blocked_boundary"
    PROVIDER_ERROR = "provider_error"
    SCHEMA_ERROR = "schema_error"
    UNKNOWN_ID = "unknown_id"


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class Citation(BaseModel):
    chunk_id: str = ""
    source_id: str = ""
    sha256: str = ""


class UsageMetrics(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: int = 0
    cost_usd: float = 0.0


class FallbackAttempt(BaseModel):
    provider: str = ""
    error_code: str = ""


class LlmRequest(BaseModel):
    request_id: str
    tenant_id: str
    engagement_id: str
    scan_id: str | None = None
    phase: str
    task_type: str
    execution_mode: ExecutionMode
    content_class: ContentClass
    preferred_alias: str
    required_capabilities: list[str] = Field(default_factory=list)
    context_budget_tokens: int = 32000
    latency_budget_ms: int = 30000
    cost_budget_usd: float = 0.0
    policy_context_ref: str = ""
    lab_lease_ref: str | None = None
    lab_cloud_allowed: bool = False
    evidence_refs: list[str] = Field(default_factory=list)
    rag_query: str | None = None
    response_schema_id: str | None = None
    prompt_id: str = ""
    prompt_version: str = ""
    user_prompt: str = ""
    system_prompt: str | None = None


class LlmResponseEnvelope(BaseModel):
    request_id: str
    status: LlmResponseStatus
    provider: str = ""
    model: str = ""
    alias: str = ""
    routing_reason_codes: list[str] = Field(default_factory=list)
    fallback_attempts: list[FallbackAttempt] = Field(default_factory=list)
    prompt_id: str = ""
    prompt_version: str = ""
    schema_id: str | None = None
    result: dict[str, Any] = Field(default_factory=dict)
    citations: list[Citation] = Field(default_factory=list)
    inferred_claims: list[str] = Field(default_factory=list)
    usage: UsageMetrics = Field(default_factory=UsageMetrics)
    trace_id: str = ""
