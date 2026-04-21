"""Schemas for MCP ``findings.*`` tools (Backlog/dev1_md §13)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr

from src.mcp.schemas.common import PaginationInput, ToolResultStatus


class Severity(StrEnum):
    """Closed taxonomy of severity values exposed to MCP clients."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingFilter(BaseModel):
    """Optional filters for ``findings.list``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    severity: Severity | None = None
    confidence: StrictStr | None = Field(
        default=None,
        max_length=20,
        description="One of ``confirmed``, ``likely``, ``possible``, ``advisory``.",
    )
    cwe: StrictStr | None = Field(
        default=None,
        max_length=20,
        description="Filter by CWE id (e.g. ``CWE-79``).",
    )
    owasp_category: StrictStr | None = Field(
        default=None,
        max_length=8,
        pattern=r"^A(0[1-9]|10)$",
        description="OWASP Top 10:2025 short id (``A01``…``A10``).",
    )
    include_false_positive: StrictBool = False


class FindingListInput(BaseModel):
    """``findings.list(scan_id, filter)`` arguments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scan_id: StrictStr = Field(min_length=8, max_length=64)
    filters: FindingFilter = Field(default_factory=FindingFilter)
    pagination: PaginationInput = Field(default_factory=PaginationInput)


class FindingSummary(BaseModel):
    """Compact representation of a finding for list views."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: StrictStr = Field(min_length=8, max_length=64)
    severity: Severity
    title: StrictStr = Field(min_length=1, max_length=500)
    cwe: StrictStr | None = Field(default=None, max_length=20)
    owasp_category: StrictStr | None = Field(default=None, max_length=8)
    confidence: StrictStr = Field(default="likely", max_length=20)
    false_positive: StrictBool = False
    created_at: datetime | None = None


class FindingListResult(BaseModel):
    """Result of ``findings.list``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    items: tuple[FindingSummary, ...] = Field(default_factory=tuple)
    total: int = Field(ge=0)
    next_offset: int | None = Field(default=None, ge=0)


class FindingGetInput(BaseModel):
    """``findings.get(finding_id)`` arguments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: StrictStr = Field(min_length=8, max_length=64)


class FindingDetail(BaseModel):
    """Full finding payload exposed via ``findings.get``.

    Notes
    -----
    The ``proof_of_concept`` and ``evidence_refs`` payloads are surfaced
    *only* after :class:`src.evidence.redaction` has scrubbed secrets — the
    MCP server never serves raw artifacts.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: StrictStr = Field(min_length=8, max_length=64)
    scan_id: StrictStr = Field(min_length=8, max_length=64)
    severity: Severity
    title: StrictStr = Field(min_length=1, max_length=500)
    description: StrictStr | None = Field(default=None, max_length=8_000)
    cwe: StrictStr | None = Field(default=None, max_length=20)
    cvss: float | None = Field(default=None, ge=0.0, le=10.0)
    owasp_category: StrictStr | None = Field(default=None, max_length=8)
    confidence: StrictStr = Field(default="likely", max_length=20)
    evidence_type: StrictStr | None = Field(default=None, max_length=40)
    proof_of_concept: dict[str, object] | None = None
    evidence_refs: tuple[StrictStr, ...] = Field(default_factory=tuple, max_length=64)
    reproducible_steps: StrictStr | None = Field(default=None, max_length=8_000)
    false_positive: StrictBool = False
    false_positive_reason: StrictStr | None = Field(default=None, max_length=500)
    created_at: datetime | None = None


class FindingMarkFalsePositiveInput(BaseModel):
    """``findings.mark_false_positive(finding_id, reason)`` arguments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: StrictStr = Field(min_length=8, max_length=64)
    reason: StrictStr = Field(
        min_length=10,
        max_length=500,
        description="Operator-provided justification (recorded in audit log).",
    )


class FindingMarkResult(BaseModel):
    """Result of ``findings.mark_false_positive``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: StrictStr = Field(min_length=8, max_length=64)
    status: ToolResultStatus
    audit_event_id: StrictStr | None = Field(default=None, max_length=64)


__all__ = [
    "FindingDetail",
    "FindingFilter",
    "FindingGetInput",
    "FindingListInput",
    "FindingListResult",
    "FindingMarkFalsePositiveInput",
    "FindingMarkResult",
    "FindingSummary",
    "Severity",
]
