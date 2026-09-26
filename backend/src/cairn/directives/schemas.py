"""Directive taxonomy + Pydantic contracts (§18.3)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DirectiveKind(StrEnum):
    BROAD_RECON_GOAL = "broad_recon_goal"
    SERVICE_DEEP_DIVE = "service_deep_dive"
    PORT_FINGERPRINT = "port_fingerprint"
    VERSION_PINNING = "version_pinning"
    CVE_ENUMERATION = "cve_enumeration"
    CVE_VALIDATION = "cve_validation"
    CROSS_CORRELATION = "cross_correlation"
    EXPLOIT_CHAIN = "exploit_chain"
    AUTH_SURFACE = "auth_surface"
    DATA_EXPOSURE_PROOF = "data_exposure_proof"
    LATERAL_MOVEMENT = "lateral_movement"
    NEGATIVE_RESULT_CLOSURE = "negative_result_closure"


class Intrusiveness(StrEnum):
    PASSIVE = "passive"
    ACTIVE_SAFE = "active_safe"
    ACTIVE_INTRUSIVE = "active_intrusive"
    DESTRUCTIVE_FORBIDDEN = "destructive_forbidden"


class ProofRequirement(StrEnum):
    NONE = "none"
    REPRODUCIBLE_REQUEST = "reproducible_request"
    TOOL_OUTPUT = "tool_output"
    OAST_CALLBACK = "oast_callback"
    COMMAND_EXECUTION = "command_execution"
    SHELL = "shell"
    DATA_READBACK = "data_readback"


class FocusType(StrEnum):
    TARGET = "target"
    HOST = "host"
    PORT = "port"
    SERVICE = "service"
    COMPONENT = "component"
    CVE = "cve"
    ENDPOINT = "endpoint"
    CREDENTIAL = "credential"


#: Ordering used to clamp intrusiveness (never raised above the allowed level).
_INTRUSIVENESS_RANK: dict[Intrusiveness, int] = {
    Intrusiveness.PASSIVE: 0,
    Intrusiveness.ACTIVE_SAFE: 1,
    Intrusiveness.ACTIVE_INTRUSIVE: 2,
    Intrusiveness.DESTRUCTIVE_FORBIDDEN: 99,  # never allowed
}


class DirectiveFocus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: FocusType
    value: str
    service_name: str | None = None
    service_version: str | None = None
    port: int | None = None
    protocol: str | None = None


class DirectiveStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    step_no: int
    action: str
    rationale: str = ""
    expected_signal: str = ""


class ScopeGuard(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    forbidden_actions: list[str] = Field(default_factory=list)


class PentestDirective(BaseModel):
    """A generated pentest directive (application-owned safety fields included)."""

    model_config = ConfigDict(extra="forbid")

    kind: DirectiveKind
    title: str = Field(max_length=120)
    directive_text: str
    focus: DirectiveFocus
    steps: list[DirectiveStep] = Field(default_factory=list)
    success_criterion: str
    proof_requirement: ProofRequirement = ProofRequirement.TOOL_OUTPUT
    unknown_handling: str = ""
    intrusiveness: Intrusiveness = Intrusiveness.ACTIVE_SAFE
    external_research_allowed: bool = False
    tool_hints: list[str] = Field(default_factory=list)
    priority_score: float = Field(default=0.0, ge=0.0, le=1.0)
    priority_rationale: str = ""
    scope_guard: ScopeGuard = Field(default_factory=ScopeGuard)
    basis_fact_refs: list[str] = Field(default_factory=list)
    basis_finding_ids: list[str] = Field(default_factory=list)


class PentestDirectiveBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    directives: list[PentestDirective] = Field(default_factory=list)


JSON_SCHEMA_PENTEST_DIRECTIVE_BATCH: dict[str, Any] = PentestDirectiveBatch.model_json_schema()


def allowed_intrusiveness_for(execution_mode: str, *, has_target_lease: bool) -> Intrusiveness:
    """Compute the maximum intrusiveness the app permits (§18.6 #1).

    production → active_safe max; lab_unrestricted with a valid lease → active_intrusive.
    destructive is never allowed.
    """
    if execution_mode == "lab_unrestricted" and has_target_lease:
        return Intrusiveness.ACTIVE_INTRUSIVE
    return Intrusiveness.ACTIVE_SAFE


def clamp_intrusiveness(requested: Intrusiveness, allowed: Intrusiveness) -> Intrusiveness:
    """Never raise intrusiveness above the allowed level (model cannot escalate)."""
    if _INTRUSIVENESS_RANK[requested] > _INTRUSIVENESS_RANK[allowed]:
        return allowed
    return requested


def exceeds_allowed(requested: Intrusiveness, allowed: Intrusiveness) -> bool:
    return _INTRUSIVENESS_RANK[requested] > _INTRUSIVENESS_RANK[allowed]


__all__ = [
    "JSON_SCHEMA_PENTEST_DIRECTIVE_BATCH",
    "DirectiveFocus",
    "DirectiveKind",
    "DirectiveStep",
    "FocusType",
    "Intrusiveness",
    "PentestDirective",
    "PentestDirectiveBatch",
    "ProofRequirement",
    "ScopeGuard",
    "allowed_intrusiveness_for",
    "clamp_intrusiveness",
    "exceeds_allowed",
]
