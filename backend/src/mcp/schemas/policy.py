"""Schemas for MCP ``policy.*`` and ``scope.*`` tools (Backlog/dev1_md §13)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr


class PolicyRiskLevel(StrEnum):
    """Closed taxonomy of action risk levels.

    Mirrors :class:`src.pipeline.contracts.tool_job.RiskLevel` so the MCP
    tool can pass the value straight through to :class:`PolicyEngine`.
    """

    PASSIVE = "passive"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    DESTRUCTIVE = "destructive"


class PolicyEvaluationOutcome(StrEnum):
    """Public outcome of a ``policy.evaluate`` call."""

    ALLOWED = "allowed"
    DENIED = "denied"
    REQUIRES_APPROVAL = "requires_approval"


class ScopeVerifyInput(BaseModel):
    """``scope.verify(target, tenant_id)`` arguments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target: StrictStr = Field(min_length=1, max_length=2_048)
    port: StrictInt | None = Field(default=None, ge=1, le=65_535)
    tenant_id: StrictStr | None = Field(
        default=None,
        max_length=64,
        description=(
            "Optional caller-supplied tenant identifier (must match the "
            "authenticated tenant; otherwise a TenantMismatchError is raised)."
        ),
    )


class ScopeVerifyResult(BaseModel):
    """Result of ``scope.verify``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    target: StrictStr = Field(min_length=1, max_length=2_048)
    allowed: StrictBool
    failure_summary: StrictStr | None = Field(default=None, max_length=64)
    matched_rule_index: StrictInt | None = Field(default=None, ge=0)
    audit_event_id: StrictStr | None = Field(default=None, max_length=64)


class PolicyEvaluateInput(BaseModel):
    """``policy.evaluate(tool_id, target, risk_level)`` arguments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: StrictStr = Field(min_length=2, max_length=64)
    target: StrictStr = Field(min_length=1, max_length=2_048)
    risk_level: PolicyRiskLevel = PolicyRiskLevel.PASSIVE
    payload_family: StrictStr | None = Field(default=None, max_length=64)
    estimated_cost_cents: StrictInt = Field(default=0, ge=0, le=10_000)


class PolicyEvaluateResult(BaseModel):
    """Result of ``policy.evaluate``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    outcome: PolicyEvaluationOutcome
    failure_summary: StrictStr | None = Field(default=None, max_length=64)
    requires_approval: StrictBool = False
    risk_level: PolicyRiskLevel
    audit_event_id: StrictStr | None = Field(default=None, max_length=64)


__all__ = [
    "PolicyEvaluateInput",
    "PolicyEvaluateResult",
    "PolicyEvaluationOutcome",
    "PolicyRiskLevel",
    "ScopeVerifyInput",
    "ScopeVerifyResult",
]
