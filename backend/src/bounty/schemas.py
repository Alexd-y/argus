"""Pydantic schemas for the Bug Bounty Planning Module."""

from __future__ import annotations

from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class SurfaceType(StrEnum):
    """Attack surface classification categories."""

    WEB_APP = "web_app"
    API = "api"
    ADMIN_PANEL = "admin_panel"
    AUTH_SYSTEM = "auth_system"
    MOBILE = "mobile"
    CLOUD_INFRA = "cloud_infra"
    SUBDOMAIN = "subdomain"
    CDN_ASSETS = "cdn_assets"


class ScopeIngestRequest(BaseModel):
    """Input for scope ingestion — JSON, raw text, or platform slug."""

    raw_text: str | None = Field(default=None, description="Raw paste from HackerOne/Bugcrowd")
    scope_json: dict[str, Any] | None = Field(default=None, description="Structured JSON scope")
    platform: str | None = Field(default=None, description="hackerone | bugcrowd | intigriti | private")
    program_slug: str | None = Field(default=None, description="Platform program slug for API import")


class BountyScopeRule(BaseModel):
    """A single include/exclude scope rule."""

    rule_type: str = Field(default="include", description="include | exclude")
    target: str = Field(description="Domain, URL, IP, CIDR, or wildcard pattern")
    target_type: str = Field(default="domain", description="domain | url | ip | cidr | wildcard | regex")


class BountyScope(BaseModel):
    """Complete bug bounty program scope."""

    program_name: str = ""
    platform: str = ""
    reward_range: str = ""
    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    vulnerability_types: list[str] = Field(default_factory=list)
    excluded_vuln_types: list[str] = Field(default_factory=list)
    special_rules: list[str] = Field(default_factory=list)
    notes: str = ""


class ClassifiedSurface(BaseModel):
    """A classified attack surface with recommended test steps."""

    surface_type: SurfaceType
    targets: list[str] = Field(default_factory=list)
    priority: str = "MEDIUM"
    test_steps: list[str] = Field(default_factory=list)
    recommended_mode: str = "standard"
    recommended_scan_options: dict[str, Any] = Field(default_factory=dict)


class VulnPriority(BaseModel):
    """A vulnerability type prioritised by typical bounty payout."""

    vuln: str
    score: int = Field(ge=1, le=10)
    owasp: str = ""
    test_module: str = ""


class TestPlanPhase(BaseModel):
    """A single phase in the test plan."""

    phase: int
    name: str
    priority: str = "MEDIUM"
    surfaces: list[str] = Field(default_factory=list)
    steps: list[str] = Field(default_factory=list)
    recommended_scan_options: dict[str, Any] = Field(default_factory=dict)


class BountyTestPlan(BaseModel):
    """Complete phased test plan generated from bug bounty scope."""

    plan_id: UUID | None = None
    program_name: str = ""
    platform: str = ""
    reward_range: str = ""
    surfaces: list[ClassifiedSurface] = Field(default_factory=list)
    prioritized_vulns: list[VulnPriority] = Field(default_factory=list)
    phases: list[TestPlanPhase] = Field(default_factory=list)
    llm_insights: str | None = None
    scope: BountyScope = Field(default_factory=BountyScope)
