from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class CriticalAsset(BaseModel):
    id: str
    name: str
    asset_type: str
    description: str | None = None


class TrustBoundary(BaseModel):
    id: str
    name: str
    description: str | None = None
    components: list[str] = []


class EntryPoint(BaseModel):
    id: str
    name: str
    entry_type: str
    host_or_component: str | None = None
    description: str | None = None


class AttackerProfile(BaseModel):
    id: str
    name: str
    capability_level: str
    description: str | None = None


class ApplicationFlow(BaseModel):
    id: str
    source: str
    sink: str
    data_type: str | None = None
    description: str | None = None


class MCPInvocationTrace(BaseModel):
    invocation_id: str
    tool_name: str
    input_summary: dict[str, Any] = {}
    output_summary: dict[str, Any] = {}
    timestamp: datetime | None = None


class AIReasoningTrace(BaseModel):
    step_id: str
    step_type: str
    description: str
    input_refs: list[str] = []
    output_refs: list[str] = []
    timestamp: datetime | None = None


class ThreatScenario(BaseModel):
    id: str
    title: str
    related_assets: list[str] = []
    host_component: str | None = None
    entry_point: str | None = None
    attacker_profile: str | None = None
    trust_boundary: str | None = None
    description: str
    likelihood: float = 0.5
    impact: float = 0.5
    priority: Any = "medium"
    recon_evidence_refs: list[str] = []
    assumptions: list[str] = []
    recommended_next_manual_checks: list[str] = []


class TestingRoadmapItem(BaseModel):
    scenario_id: str
    title: str
    priority: Any = "medium"
    evidence_refs: list[str] = []
    recommended_actions: list[str] = []


class ThreatModelArtifact(BaseModel):
    run_id: str
    job_id: str
    scenarios: list[ThreatScenario] = []
    testing_roadmap: list[TestingRoadmapItem] = []
    ai_reasoning_traces: list[AIReasoningTrace] = []
    mcp_invocation_traces: list[MCPInvocationTrace] = []


class ThreatModelInputBundle(BaseModel):
    engagement_id: str
    target_id: str | None = None
    critical_assets: list[CriticalAsset] = []
    trust_boundaries: list[TrustBoundary] = []
    entry_points: list[EntryPoint] = []
    attacker_profiles: list[AttackerProfile] = []
    application_flows: list[ApplicationFlow] = []
    artifact_refs: list[str] = []
    priority_hypotheses: list[dict[str, Any]] = []
    anomalies: list[dict[str, Any]] | dict[str, Any] = []
    intel_findings: list[dict[str, Any]] = []
    api_surface: list[dict[str, Any]] = []
    endpoint_inventory: list[dict[str, Any]] = []
    route_inventory: list[dict[str, Any]] = []
    dns_summary: dict[str, Any] | None = None
    live_hosts: list[dict[str, Any]] = []
    tech_profile: list[dict[str, Any]] = []


class ThreatModelRun(BaseModel):
    engagement_id: str
    target_id: str | None = None
    status: str = "pending"
    started_at: datetime | None = None
    completed_at: datetime | None = None
    input_bundle_ref: str | None = None
    artifact_refs: list[str] = []
    job_id: str | None = None
    run_id: str | None = None
