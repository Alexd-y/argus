"""Schemas for MCP ``tool.*`` tools (Backlog/dev1_md §13)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

from src.mcp.schemas.common import PaginationInput


class ToolRiskLevel(StrEnum):
    """Mirrors :class:`src.pipeline.contracts.tool_job.RiskLevel` for MCP."""

    PASSIVE = "passive"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    DESTRUCTIVE = "destructive"


class ToolRunStatus(StrEnum):
    """Closed taxonomy of tool-run lifecycle states."""

    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    APPROVAL_PENDING = "approval_pending"


class ToolCatalogListInput(BaseModel):
    """``tool.catalog.list(filter)`` arguments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    category: StrictStr | None = Field(
        default=None,
        max_length=64,
        description="Filter by tool category (e.g. ``web_va``, ``recon_passive``).",
    )
    risk_level: ToolRiskLevel | None = None
    requires_approval: StrictBool | None = None
    pagination: PaginationInput = Field(default_factory=PaginationInput)


class ToolCatalogEntry(BaseModel):
    """One catalog row exposed via MCP.

    The entry intentionally omits ``command_template``, ``image``, and other
    sandbox-internal fields — the LLM never needs them to reason about
    capabilities, and they would leak the templating contract to a
    potentially-untrusted client.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: StrictStr = Field(min_length=2, max_length=64)
    category: StrictStr = Field(min_length=2, max_length=64)
    phase: StrictStr = Field(min_length=2, max_length=64)
    risk_level: ToolRiskLevel
    requires_approval: StrictBool
    description: StrictStr = Field(default="", max_length=2_048)
    cwe_hints: tuple[StrictInt, ...] = Field(default_factory=tuple, max_length=32)


class ToolCatalogListResult(BaseModel):
    """Result of ``tool.catalog.list``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    items: tuple[ToolCatalogEntry, ...] = Field(default_factory=tuple)
    total: int = Field(ge=0)


class ToolRunTriggerInput(BaseModel):
    """``tool.run.trigger(tool_id, target, params)`` arguments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: StrictStr = Field(min_length=2, max_length=64)
    target: StrictStr = Field(min_length=1, max_length=2_048)
    scan_id: StrictStr | None = Field(default=None, min_length=8, max_length=64)
    params: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Whitelisted argv overrides — keys must match the tool's allowed "
            "placeholder set (see src.sandbox.templating.ALLOWED_PLACEHOLDERS)."
        ),
    )
    justification: StrictStr | None = Field(
        default=None,
        max_length=512,
        description="Required when the resolved tool has ``risk_level >= high``.",
    )


class ToolRunTriggerResult(BaseModel):
    """Result of ``tool.run.trigger``.

    For HIGH / DESTRUCTIVE tools the MCP server NEVER kicks off the actual
    run; instead it records an :class:`ApprovalRequest`, logs an audit
    event, and returns ``status=approval_pending`` with the request id so
    an operator can sign it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_run_id: StrictStr | None = Field(default=None, min_length=8, max_length=64)
    tool_id: StrictStr = Field(min_length=2, max_length=64)
    status: ToolRunStatus
    risk_level: ToolRiskLevel
    requires_approval: StrictBool = False
    approval_request_id: StrictStr | None = Field(
        default=None, min_length=8, max_length=64
    )
    audit_event_id: StrictStr | None = Field(default=None, max_length=64)


class ToolRunStatusInput(BaseModel):
    """``tool.run.status(tool_run_id)`` arguments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_run_id: StrictStr = Field(min_length=8, max_length=64)


class ToolRunStatusResult(BaseModel):
    """Result of ``tool.run.status``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_run_id: StrictStr = Field(min_length=8, max_length=64)
    tool_id: StrictStr = Field(min_length=2, max_length=64)
    status: ToolRunStatus
    started_at: datetime | None = None
    finished_at: datetime | None = None
    finding_count: int = Field(ge=0, default=0)
    approval_request_id: StrictStr | None = Field(
        default=None, min_length=8, max_length=64
    )


__all__ = [
    "ToolCatalogEntry",
    "ToolCatalogListInput",
    "ToolCatalogListResult",
    "ToolRiskLevel",
    "ToolRunStatus",
    "ToolRunStatusInput",
    "ToolRunStatusResult",
    "ToolRunTriggerInput",
    "ToolRunTriggerResult",
]
