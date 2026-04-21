"""Schemas for MCP ``approvals.*`` tools (Backlog/dev1_md §13)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr

from src.mcp.schemas.common import PaginationInput


class ApprovalDecisionAction(StrEnum):
    """Closed taxonomy of operator decisions surfaced via MCP."""

    GRANT = "grant"
    DENY = "deny"
    REVOKE = "revoke"


class ApprovalListInput(BaseModel):
    """``approvals.list(tenant_id, status)`` arguments.

    Note
    ----
    The ``tenant_id`` argument is informational only — the MCP server always
    filters by the *authenticated* tenant (extracted from the bearer token /
    ``X-Tenant-ID`` header). A mismatch raises
    :class:`src.mcp.exceptions.TenantMismatchError`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: StrictStr | None = Field(
        default=None,
        max_length=16,
        description="One of ``pending``, ``granted``, ``denied``, ``revoked``, ``expired``.",
    )
    tool_id: StrictStr | None = Field(default=None, min_length=2, max_length=64)
    tenant_id: StrictStr | None = Field(
        default=None,
        max_length=64,
        description=(
            "Optional caller-supplied tenant identifier (must match the "
            "authenticated tenant; otherwise a TenantMismatchError is raised)."
        ),
    )
    pagination: PaginationInput = Field(default_factory=PaginationInput)


class ApprovalSummary(BaseModel):
    """Compact representation of an approval row for list views."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: StrictStr = Field(min_length=8, max_length=64)
    tool_id: StrictStr = Field(min_length=2, max_length=64)
    target: StrictStr = Field(min_length=1, max_length=2_048)
    action: StrictStr = Field(max_length=16)
    status: StrictStr = Field(max_length=16)
    created_at: datetime
    expires_at: datetime
    requires_dual_control: StrictBool = False
    signatures_present: int = Field(ge=0, le=8)


class ApprovalListResult(BaseModel):
    """Result of ``approvals.list``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    items: tuple[ApprovalSummary, ...] = Field(default_factory=tuple)
    total: int = Field(ge=0)


class ApprovalDecideInput(BaseModel):
    """``approvals.decide`` arguments — operator records a decision.

    The MCP server NEVER signs approvals on the operator's behalf. The
    ``signature_b64`` is computed externally by the operator UI from
    ``ApprovalRequest.canonical_bytes()`` and submitted here — the MCP
    layer only verifies and persists the resulting decision.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: StrictStr = Field(min_length=8, max_length=64)
    decision: ApprovalDecisionAction
    signature_b64: StrictStr | None = Field(
        default=None,
        min_length=86,
        max_length=128,
        description=(
            "Required when ``decision == grant``. Ed25519 signature over "
            "``ApprovalRequest.canonical_bytes`` produced by the operator UI."
        ),
    )
    public_key_id: StrictStr | None = Field(
        default=None,
        min_length=16,
        max_length=16,
        description="Operator's Ed25519 public key id (16-char hex).",
    )
    justification: StrictStr | None = Field(
        default=None,
        max_length=500,
        description=(
            "Operator note attached to the decision. Required when "
            "``decision == deny`` or ``decision == revoke``."
        ),
    )


class ApprovalDecideResult(BaseModel):
    """Result of ``approvals.decide``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id: StrictStr = Field(min_length=8, max_length=64)
    new_status: StrictStr = Field(max_length=16)
    audit_event_id: StrictStr | None = Field(default=None, max_length=64)


__all__ = [
    "ApprovalDecideInput",
    "ApprovalDecideResult",
    "ApprovalDecisionAction",
    "ApprovalListInput",
    "ApprovalListResult",
    "ApprovalSummary",
]
