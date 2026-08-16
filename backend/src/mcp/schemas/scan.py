"""Schemas for MCP ``scan.*`` tools (Backlog/dev1_md §13)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from src.mcp.schemas.common import ToolResultStatus
from src.quick.create import reject_raw_command_fields

_TARGET_PATTERN = r"^(https?://)?[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?(/.*)?$"


class ScanProfile(StrEnum):
    """Public-facing scan **depth** names exposed to MCP clients.

    Maps 1-to-1 to ``Settings.scan_mode`` (``quick`` / ``standard`` / ``deep``).
    This is **not** ``execution_mode``: ``ScanProfile.QUICK`` is Strix-style
    depth, while Quick execution mode is the separate ``execution_mode`` field.
    """

    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class ScanStatus(StrEnum):
    """Closed taxonomy of high-level scan lifecycle states.

    Mirrors the ``scans.status`` column but is intentionally smaller: the
    MCP layer never exposes internal pipeline phases (``recon`` /
    ``vuln_analysis`` / ``exploitation``) — those leak implementation
    structure to the LLM.
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanScopeInput(BaseModel):
    """Optional scope hints supplied when creating a scan.

    The MCP server's :class:`ScopeEngine` integration ignores anything the
    client cannot explicitly substantiate — these hints only narrow the
    automatic discovery (e.g. ``include_subdomains=False`` to avoid spending
    budget on unrelated apex domains).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    include_subdomains: StrictBool = False
    max_depth: StrictInt = Field(default=3, ge=1, le=10)
    follow_redirects: StrictBool = True


class QuickMcpOptions(BaseModel):
    """Typed Quick options for ``scan.create``. No argv/command fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    profile: StrictStr = Field(default="balanced", max_length=32)
    severity_floor: StrictStr | None = Field(default=None, max_length=32)
    enable_ai: StrictBool | None = None
    enable_oast: StrictBool | None = None
    enable_headless_on_signal: StrictBool | None = None
    wall_clock_budget_seconds: StrictInt | None = Field(default=None, ge=1, le=86_400)
    ai_budget_seconds: StrictInt | None = Field(default=None, ge=0, le=86_400)
    authenticated_context_id: StrictStr | None = Field(default=None, max_length=36)
    cloud_llm_allowed: StrictBool | None = None


class ScanCreateInput(BaseModel):
    """``scan.create(target, scope, profile, execution_mode)`` arguments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target: StrictStr = Field(
        min_length=1,
        max_length=512,
        pattern=_TARGET_PATTERN,
        description="URL or domain to scan (must already be in the tenant's allow-list).",
    )
    profile: ScanProfile = ScanProfile.STANDARD
    execution_mode: StrictStr | None = Field(
        default=None,
        max_length=32,
        description=(
            "Immutable execution profile: production | lab_unrestricted | quick. "
            "Distinct from profile (scan depth). Omit for production."
        ),
    )
    quick: QuickMcpOptions | None = None
    scope: ScanScopeInput = Field(default_factory=ScanScopeInput)
    justification: StrictStr | None = Field(
        default=None,
        max_length=512,
        description="Operator-provided justification; required for HIGH-risk profiles.",
    )
    scan_options: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Existing scan options payload (execution_mode, lab_lease). "
            "Must not contain argv/command strings."
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def _reject_raw_commands(cls, data: Any) -> Any:
        if isinstance(data, dict):
            reject_raw_command_fields(data)
        return data


class ScanCreateResult(BaseModel):
    """Result of ``scan.create``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scan_id: StrictStr = Field(min_length=8, max_length=64)
    status: ScanStatus
    target: StrictStr = Field(min_length=1, max_length=512)
    profile: ScanProfile
    execution_mode: StrictStr | None = Field(
        default=None,
        max_length=32,
        description="Resolved execution profile; omitted for legacy clients.",
    )
    requires_approval: StrictBool = False
    audit_event_id: StrictStr | None = Field(default=None, max_length=64)


class ScanStatusInput(BaseModel):
    """``scan.status(scan_id)`` arguments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scan_id: StrictStr = Field(min_length=8, max_length=64)


class ScanStatusResult(BaseModel):
    """Result of ``scan.status``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scan_id: StrictStr = Field(min_length=8, max_length=64)
    status: ScanStatus
    progress_percent: StrictInt = Field(ge=0, le=100)
    target: StrictStr = Field(min_length=1, max_length=512)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    finding_counts: dict[str, int] = Field(
        default_factory=dict,
        description="Severity → count snapshot (e.g. {'critical': 2, 'high': 5}).",
    )


class ScanCancelInput(BaseModel):
    """``scan.cancel(scan_id, reason)`` arguments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scan_id: StrictStr = Field(min_length=8, max_length=64)
    reason: StrictStr = Field(
        min_length=4,
        max_length=200,
        description="Operator-provided reason for cancellation (recorded in audit log).",
    )


class ScanCancelResult(BaseModel):
    """Result of ``scan.cancel``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scan_id: StrictStr = Field(min_length=8, max_length=64)
    status: ToolResultStatus
    new_state: ScanStatus
    audit_event_id: StrictStr | None = Field(default=None, max_length=64)


class ScanPlanInput(BaseModel):
    """``scan.plan(scan_id)`` arguments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scan_id: StrictStr = Field(min_length=8, max_length=64)


class ScanPlanResult(BaseModel):
    """Result of ``scan.plan`` — typed plan, never argv/command."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scan_id: StrictStr = Field(min_length=8, max_length=64)
    mode: StrictStr = "quick"
    profile: StrictStr
    plan_version: StrictInt = Field(ge=0)
    deadline_at: StrictStr
    budget: dict[str, Any] = Field(default_factory=dict)
    stages: tuple[Any, ...] = Field(default_factory=tuple)
    tasks: tuple[Any, ...] = Field(default_factory=tuple)
    coverage_intent: tuple[Any, ...] = Field(default_factory=tuple)
    assumptions: tuple[Any, ...] = Field(default_factory=tuple)


class ScanCoverageInput(BaseModel):
    """``scan.coverage(scan_id)`` arguments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scan_id: StrictStr = Field(min_length=8, max_length=64)


class ScanCoverageResult(BaseModel):
    """Result of ``scan.coverage`` with additive ``reason_code``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scan_id: StrictStr = Field(min_length=8, max_length=64)
    results: tuple[dict[str, Any], ...] = Field(default_factory=tuple)


__all__ = [
    "QuickMcpOptions",
    "ScanCancelInput",
    "ScanCancelResult",
    "ScanCoverageInput",
    "ScanCoverageResult",
    "ScanCreateInput",
    "ScanCreateResult",
    "ScanPlanInput",
    "ScanPlanResult",
    "ScanProfile",
    "ScanScopeInput",
    "ScanStatus",
    "ScanStatusInput",
    "ScanStatusResult",
]
