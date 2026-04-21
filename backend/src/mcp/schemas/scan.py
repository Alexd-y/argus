"""Schemas for MCP ``scan.*`` tools (Backlog/dev1_md §13)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
)

from src.mcp.schemas.common import ToolResultStatus

_TARGET_PATTERN = r"^(https?://)?[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?(/.*)?$"


class ScanProfile(StrEnum):
    """Public-facing scan profile names exposed to MCP clients.

    Maps 1-to-1 to ``Settings.scan_mode`` (``quick`` / ``standard`` / ``deep``)
    so that ``scan.create`` arguments stay in sync with the rest of the
    backend. The MCP client cannot pick a deeper profile than its tenant
    plan allows; that gate sits in :class:`PolicyEngine`.
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


class ScanCreateInput(BaseModel):
    """``scan.create(target, scope, profile)`` arguments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target: StrictStr = Field(
        min_length=1,
        max_length=512,
        pattern=_TARGET_PATTERN,
        description="URL or domain to scan (must already be in the tenant's allow-list).",
    )
    profile: ScanProfile = ScanProfile.STANDARD
    scope: ScanScopeInput = Field(default_factory=ScanScopeInput)
    justification: StrictStr | None = Field(
        default=None,
        max_length=512,
        description="Operator-provided justification; required for HIGH-risk profiles.",
    )


class ScanCreateResult(BaseModel):
    """Result of ``scan.create``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scan_id: StrictStr = Field(min_length=8, max_length=64)
    status: ScanStatus
    target: StrictStr = Field(min_length=1, max_length=512)
    profile: ScanProfile
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


__all__ = [
    "ScanCancelInput",
    "ScanCancelResult",
    "ScanCreateInput",
    "ScanCreateResult",
    "ScanProfile",
    "ScanScopeInput",
    "ScanStatus",
    "ScanStatusInput",
    "ScanStatusResult",
]
