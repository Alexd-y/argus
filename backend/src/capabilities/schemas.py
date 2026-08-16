"""Capability knowledge graph and coverage accounting schemas (Stage E)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, StrictStr, model_validator


class CapabilityFamily(StrEnum):
    """Top-level capability families from the ARGUS capability map."""

    FOUNDATIONS_NETWORKING = "foundations.networking"
    NETWORK_CISCO = "network.cisco"
    WINDOWS_SERVER = "windows.server"
    LINUX_SYSTEM = "linux.system"
    WEB_APPLICATION = "web.application"
    PENTEST_INFRASTRUCTURE = "pentest.infrastructure"
    PRIVILEGE_ESCALATION_LINUX = "privilege_escalation.linux"
    PRIVILEGE_ESCALATION_WINDOWS = "privilege_escalation.windows"
    NETWORK_ATTACK_PATHS = "network.attack_paths"
    REVERSE_ENGINEERING = "reverse_engineering"
    MALWARE_ANALYSIS = "malware_analysis"
    TRAINING_CERTIFICATION = "training.certification"
    CLOUD_EXPOSURE = "cloud.exposure"
    NUCLEI_PROTOCOL = "nuclei.protocol"


class CapabilityEdgeType(StrEnum):
    """Directed edge semantics in the capability graph."""

    PREREQUISITE = "prerequisite"
    PART_OF = "part_of"
    APPLIES_TO_ASSET = "applies_to_asset"
    ENABLES_DETECTION = "enables_detection"
    VALIDATED_BY = "validated_by"
    MAPPED_TO_CWE = "mapped_to_cwe"
    MAPPED_TO_ATTACK = "mapped_to_attack"
    REQUIRES_AUTH_ROLE = "requires_auth_role"
    SUPERSEDES = "supersedes"


class ProductionRisk(StrEnum):
    """Production policy risk label for a capability node."""

    PASSIVE = "passive"
    ACTIVE = "active"
    INTRUSIVE = "intrusive"
    DESTRUCTIVE = "destructive"


class CoverageStatus(StrEnum):
    """Honest coverage accounting — absence of finding is not coverage."""

    PLANNED = "planned"
    RUNNING = "running"
    COVERED_NO_FINDING = "covered_no_finding"
    COVERED_WITH_FINDING = "covered_with_finding"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    NOT_APPLICABLE = "not_applicable"
    NOT_TESTED = "not_tested"


COVERED_STATUSES: Final[frozenset[CoverageStatus]] = frozenset(
    {
        CoverageStatus.COVERED_NO_FINDING,
        CoverageStatus.COVERED_WITH_FINDING,
        CoverageStatus.PARTIAL,
    }
)


class CapabilityApplicability(BaseModel):
    """Predicate describing when a capability applies to an asset fingerprint.

    Empty collections mean "no extra constraint" for that dimension. Defaults
    keep existing frozen seed nodes valid without an explicit seed rewrite.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocols: tuple[StrictStr, ...] = ()
    products: tuple[StrictStr, ...] = ()
    services: tuple[StrictStr, ...] = ()
    asset_types: tuple[StrictStr, ...] = ()
    require_tls: bool = False
    require_auth_surface: bool = False
    require_api_hints: bool = False
    require_cloud_exposure: bool = False
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class CapabilityNode(BaseModel):
    """Versioned node in the global capability knowledge graph."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr = Field(min_length=3, max_length=256)
    family: CapabilityFamily | StrictStr
    labels: tuple[StrictStr, ...] = ()
    asset_types: tuple[StrictStr, ...] = ()
    execution_modes: tuple[StrictStr, ...] = ("production", "lab_unrestricted")
    production_risk: ProductionRisk | StrictStr = ProductionRisk.ACTIVE
    lab_allowed: bool = True
    allowed_phases: tuple[StrictStr, ...] = ()
    evidence_types: tuple[StrictStr, ...] = ()
    tools: tuple[StrictStr, ...] = ()
    attack_techniques: tuple[StrictStr, ...] = ()
    training_only: bool = False
    version: int = Field(default=1, ge=1)
    quick_eligible: bool = False
    estimated_cost_seconds: int = Field(default=30, ge=0, le=86_400)
    applicability: CapabilityApplicability = Field(default_factory=CapabilityApplicability)


class CapabilityEdge(BaseModel):
    """Directed edge between two capability nodes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_id: StrictStr = Field(min_length=3, max_length=256)
    target_id: StrictStr = Field(min_length=3, max_length=256)
    edge_type: CapabilityEdgeType
    weight: float = Field(default=1.0, ge=0.0, le=100.0)


class AssetCapabilityProfile(BaseModel):
    """Capabilities inferred or confirmed for a single asset."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    asset_id: StrictStr = Field(min_length=1, max_length=36)
    tenant_id: StrictStr = Field(min_length=1, max_length=36)
    engagement_id: StrictStr = Field(min_length=1, max_length=36)
    capability_ids: tuple[StrictStr, ...] = ()
    inferred: bool = False
    updated_at: datetime | None = None


class CoverageRequirement(BaseModel):
    """Planned coverage obligation for asset × capability during a scan."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr = Field(min_length=1, max_length=36)
    tenant_id: StrictStr = Field(min_length=1, max_length=36)
    scan_id: StrictStr = Field(min_length=1, max_length=36)
    asset_id: StrictStr = Field(min_length=1, max_length=36)
    capability_id: StrictStr = Field(min_length=3, max_length=256)
    required_evidence_types: tuple[StrictStr, ...] = ()


class CoverageResult(BaseModel):
    """Observed coverage outcome for a requirement."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    requirement_id: StrictStr = Field(min_length=1, max_length=36)
    tenant_id: StrictStr = Field(min_length=1, max_length=36)
    scan_id: StrictStr = Field(min_length=1, max_length=36)
    asset_id: StrictStr = Field(min_length=1, max_length=36)
    capability_id: StrictStr = Field(min_length=3, max_length=256)
    status: CoverageStatus
    execution_evidence_id: StrictStr | None = None
    blocked_reason: StrictStr | None = None
    finding_id: StrictStr | None = None
    recorded_at: datetime | None = None
    reason_code: StrictStr | None = None
    template_ids: tuple[StrictStr, ...] = ()
    evidence_ids: tuple[StrictStr, ...] = ()

    @model_validator(mode="after")
    def _covered_requires_execution_evidence(self) -> CoverageResult:
        if self.status in COVERED_STATUSES and not self.execution_evidence_id:
            raise ValueError(
                f"status {self.status.value} requires execution_evidence_id"
            )
        if self.status is CoverageStatus.COVERED_WITH_FINDING and not self.finding_id:
            raise ValueError("covered_with_finding requires finding_id")
        return self
