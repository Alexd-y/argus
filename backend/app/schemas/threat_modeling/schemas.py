"""Pydantic schemas for threat modeling — assets, boundaries, flows, scenarios, artifacts."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, StrictFloat

from app.schemas.ai.common import EvidenceRef, PriorityLevel

# --- Core domain models ---


class CriticalAsset(BaseModel):
    """Critical asset identified during threat modeling."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=500)
    asset_type: str = Field(min_length=1, max_length=100)
    description: str | None = Field(default=None, max_length=2000)


class TrustBoundary(BaseModel):
    """Trust boundary between components or zones."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=500)
    description: str | None = Field(default=None, max_length=2000)
    components: list[str] = Field(default_factory=list, max_length=100)


class AttackerProfile(BaseModel):
    """Attacker profile/capability assumed for a scenario."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=200)
    capability_level: str = Field(min_length=1, max_length=50)
    description: str | None = Field(default=None, max_length=2000)


class EntryPoint(BaseModel):
    """Entry point into the system (API, UI, file upload, etc.)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=500)
    entry_type: str = Field(min_length=1, max_length=100)
    host_or_component: str | None = Field(default=None, max_length=500)
    description: str | None = Field(default=None, max_length=2000)


class ApplicationFlow(BaseModel):
    """Data/control flow between components."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=500)
    sink: str = Field(min_length=1, max_length=500)
    data_type: str | None = Field(default=None, max_length=200)
    description: str | None = Field(default=None, max_length=2000)


class ScenarioScore(BaseModel):
    """Likelihood and impact score for a threat scenario."""

    model_config = ConfigDict(extra="forbid")

    likelihood: StrictFloat = Field(ge=0.0, le=1.0)
    impact: StrictFloat = Field(ge=0.0, le=1.0)
    risk_score: StrictFloat | None = Field(default=None, ge=0.0, le=1.0)


class EvidenceLink(BaseModel):
    """Evidence reference with optional context/label."""

    model_config = ConfigDict(extra="forbid")

    ref: EvidenceRef
    label: str | None = Field(default=None, max_length=200)


class ThreatScenario(BaseModel):
    """Threat scenario with full context for testing roadmap."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=500)
    related_assets: list[str] = Field(default_factory=list, max_length=50)
    host_component: str | None = Field(default=None, max_length=500)
    entry_point: str | None = Field(default=None, max_length=200)
    attacker_profile: str | None = Field(default=None, max_length=200)
    trust_boundary: str | None = Field(default=None, max_length=200)
    description: str = Field(min_length=1, max_length=5000)
    likelihood: StrictFloat = Field(ge=0.0, le=1.0)
    impact: StrictFloat = Field(ge=0.0, le=1.0)
    priority: PriorityLevel
    recon_evidence_refs: list[EvidenceRef] = Field(default_factory=list, max_length=100)
    assumptions: list[str] = Field(default_factory=list, max_length=50)
    recommended_next_manual_checks: list[str] = Field(default_factory=list, max_length=50)


class TestingRoadmapItem(BaseModel):
    """Single item in the testing roadmap."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=500)
    priority: PriorityLevel
    evidence_refs: list[EvidenceRef] = Field(default_factory=list, max_length=50)
    recommended_actions: list[str] = Field(default_factory=list, max_length=20)


class ThreatModelInputBundle(BaseModel):
    """Input bundle for threat model run — aggregated recon artifacts."""

    model_config = ConfigDict(extra="forbid")

    engagement_id: str = Field(min_length=1, max_length=36)
    target_id: str | None = Field(default=None, max_length=36)
    critical_assets: list[CriticalAsset] = Field(default_factory=list, max_length=200)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list, max_length=100)
    attacker_profiles: list[AttackerProfile] = Field(default_factory=list, max_length=50)
    entry_points: list[EntryPoint] = Field(default_factory=list, max_length=200)
    application_flows: list[ApplicationFlow] = Field(default_factory=list, max_length=200)
    artifact_refs: list[str] = Field(default_factory=list, max_length=500)

    # Raw recon data for AI consumption (from input_loader)
    priority_hypotheses: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    anomalies: list[dict[str, Any]] | dict[str, Any] = Field(default_factory=list)  # noqa: RUF013
    intel_findings: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    api_surface: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    endpoint_inventory: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    route_inventory: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    dns_summary: dict[str, Any] | None = None
    live_hosts: list[dict[str, Any]] = Field(default_factory=list, max_length=500)
    tech_profile: list[dict[str, Any]] = Field(default_factory=list, max_length=500)


class AIReasoningTrace(BaseModel):
    """Trace of AI reasoning steps during threat model generation."""

    model_config = ConfigDict(extra="forbid")

    step_id: str = Field(min_length=1, max_length=100)
    step_type: str = Field(min_length=1, max_length=50)
    description: str = Field(min_length=1, max_length=5000)
    input_refs: list[str] = Field(default_factory=list, max_length=50)
    output_refs: list[str] = Field(default_factory=list, max_length=50)
    timestamp: datetime | None = Field(default=None)


class MCPInvocationTrace(BaseModel):
    """Trace of MCP tool invocations during threat model generation."""

    model_config = ConfigDict(extra="forbid")

    invocation_id: str = Field(min_length=1, max_length=100)
    tool_name: str = Field(min_length=1, max_length=200)
    input_summary: dict[str, Any] = Field(default_factory=dict)
    output_summary: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime | None = Field(default=None)


class ThreatModelArtifact(BaseModel):
    """Complete threat model artifact — output of a threat model run."""

    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(min_length=1, max_length=200)
    job_id: str = Field(min_length=1, max_length=200)
    scenarios: list[ThreatScenario] = Field(default_factory=list, max_length=500)
    testing_roadmap: list[TestingRoadmapItem] = Field(default_factory=list, max_length=500)
    ai_reasoning_traces: list[AIReasoningTrace] = Field(default_factory=list, max_length=200)
    mcp_invocation_traces: list[MCPInvocationTrace] = Field(default_factory=list, max_length=200)
    evidence_links: list[EvidenceLink] = Field(default_factory=list, max_length=500)


class ThreatModelRun(BaseModel):
    """Pydantic schema for threat model run — API/validation layer."""

    model_config = ConfigDict(extra="forbid")

    engagement_id: str = Field(min_length=1, max_length=36)
    target_id: str | None = Field(default=None, max_length=36)
    status: str = Field(min_length=1, max_length=50)
    started_at: datetime | None = Field(default=None)
    completed_at: datetime | None = Field(default=None)
    input_bundle_ref: str = Field(min_length=1, max_length=1024)
    artifact_refs: list[str] = Field(default_factory=list, max_length=500)
    job_id: str = Field(min_length=1, max_length=200)
    run_id: str = Field(min_length=1, max_length=200)
