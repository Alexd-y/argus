"""Nuclei control plane — typed contracts (§9.4, §9.8)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
)


class TemplateSource(StrEnum):
    INTERNAL = "internal"
    PROJECTDISCOVERY = "projectdiscovery"
    TENANT = "tenant"
    GENERATED = "generated"
    REMOTE = "remote"


class NucleiTemplateManifest(BaseModel):
    """Immutable template manifest with provenance (§9.4)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    template_id: StrictStr = Field(min_length=1, max_length=256)
    version: StrictStr = Field(min_length=1, max_length=64)
    source: TemplateSource | StrictStr
    sha256: StrictStr = Field(min_length=64, max_length=64)
    signature: StrictStr | None = None
    verified: StrictBool = False
    protocols: tuple[StrictStr, ...] = Field(default_factory=tuple)
    capabilities: tuple[StrictStr, ...] = Field(default_factory=tuple)
    risk_level: StrictStr = "passive"
    requires_oast: StrictBool = False
    requires_headless: StrictBool = False
    tags: tuple[StrictStr, ...] = Field(default_factory=tuple)
    product: StrictStr | None = Field(default=None, max_length=256)
    product_version: StrictStr | None = Field(default=None, max_length=64)
    severity: StrictStr = "info"
    execution_modes: tuple[StrictStr, ...] = Field(
        default_factory=lambda: ("production", "lab_unrestricted", "quick")
    )
    provenance: dict[str, Any] = Field(default_factory=dict)


def digest_nuclei_template_ids(template_ids: Sequence[str]) -> str:
    """SHA-256 of the exact ordered template id list (frozen selector digest)."""
    canonical = json.dumps(list(template_ids), separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class NucleiTemplateSelectionManifest(BaseModel):
    """Immutable Quick/production template selection — ids + digest, never CLI."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    template_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)
    digest_sha256: StrictStr = Field(min_length=64, max_length=64)
    profile_id: StrictStr = Field(default="quick-default", min_length=1, max_length=128)


class TemplateProposal(BaseModel):
    """Qwythos/WRB template authoring IR (§9.8)."""

    model_config = ConfigDict(extra="forbid")

    proposal_id: StrictStr | None = None
    intent: StrictStr = Field(min_length=1, max_length=4096)
    evidence_basis: tuple[StrictStr, ...] = Field(default_factory=tuple)
    protocol: Literal[
        "http",
        "dns",
        "network",
        "ssl",
        "websocket",
        "headless",
        "javascript",
        "code",
        "file",
    ] = "http"
    requests: list[dict[str, Any]] = Field(default_factory=list)
    match_logic: dict[str, Any] = Field(default_factory=dict)
    extractors: list[dict[str, Any]] = Field(default_factory=list)
    payload_family_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)
    custom_payloads: tuple[StrictStr, ...] = Field(default_factory=tuple)
    negative_controls: tuple[StrictStr, ...] = Field(default_factory=tuple)
    risk_level: StrictStr = "safe_active"
    uncertainties: tuple[StrictStr, ...] = Field(default_factory=tuple)


class LabTemplateArtifact(BaseModel):
    """Immediate lab execution artifact — provenance always recorded (§9.3 LAB)."""

    model_config = ConfigDict(extra="forbid")

    artifact_id: StrictStr = Field(min_length=1, max_length=36)
    template_id: StrictStr = Field(min_length=1, max_length=256)
    content_sha256: StrictStr = Field(min_length=64, max_length=64)
    content_path: StrictStr | None = None
    yaml_content: StrictStr | None = None
    provenance: dict[str, Any] = Field(default_factory=dict)
    provenance_hash: StrictStr | None = None
    ingested_at: datetime | None = None


class ScanProfile(BaseModel):
    """Versioned Nuclei execution profile loaded from YAML (§9.5, §9.6)."""

    model_config = ConfigDict(extra="allow")

    id: StrictStr = Field(min_length=1, max_length=128)
    version: StrictInt = 1

    # Production-oriented gates
    allowed_protocols: tuple[StrictStr, ...] | list[StrictStr] = Field(default_factory=tuple)
    allowed_risk_levels: tuple[StrictStr, ...] | list[StrictStr] = Field(default_factory=tuple)
    require_verified_templates: StrictBool = True
    disable_unsigned_templates: StrictBool = True
    oast: StrictStr | None = None
    requires_oast_templates: StrictBool = False
    requires_approval: StrictBool = False

    # LAB capability flags (§9.6)
    allow_remote_templates: StrictBool = False
    allow_remote_workflows: StrictBool = False
    allow_protocols: tuple[StrictStr, ...] | list[StrictStr] = Field(default_factory=tuple)
    allow_code: StrictBool = False
    allow_javascript: StrictBool = False
    allow_headless: StrictBool = False
    allow_file: StrictBool = False
    allow_self_contained: StrictBool = False
    allow_global_matchers: StrictBool = False
    allow_local_file_access: StrictBool = False
    allow_environment_variables: StrictBool = False
    allow_custom_headers: StrictBool = False
    allow_client_certificates: StrictBool = False
    allow_raw_network: StrictBool = False
    allow_oast: StrictBool = False
    allow_dast: StrictBool = False

    # Rate / budget — null omits CLI flags
    rate_limit_rps: StrictInt | None = None
    concurrency: StrictInt | None = None
    payload_concurrency: StrictInt | None = None
    per_host_rate_limit: StrictBool = False
    max_host_errors: StrictInt | None = None
    max_requests_total: StrictInt | None = None
    timeout_s: StrictInt | StrictStr | None = None
    retries: StrictInt | StrictStr | None = None

    # Evidence
    max_response_read_bytes: StrictInt | None = None
    max_response_evidence_bytes: StrictInt | None = None
    store_raw: StrictStr | Literal[False] = "findings_only"
    redact: tuple[StrictStr, ...] | list[StrictStr] | StrictBool = Field(default_factory=tuple)

    # Production exclusions
    severity_allow: tuple[StrictStr, ...] | list[StrictStr] = Field(default_factory=tuple)
    disable_code: StrictBool = False
    disable_javascript: StrictBool = False
    disable_headless: StrictBool = False
    dast: StrictStr | None = None
    fuzz_aggression: StrictStr | None = None
    fuzz_types: tuple[StrictStr, ...] | list[StrictStr] = Field(default_factory=tuple)
    fuzz_modes: tuple[StrictStr, ...] | list[StrictStr] = Field(default_factory=tuple)
    attack_types: tuple[StrictStr, ...] | list[StrictStr] = Field(default_factory=tuple)

    @property
    def is_lab_unrestricted(self) -> bool:
        return self.id == "lab_unrestricted"


class NucleiCompileRequest(BaseModel):
    """Single entry point for argv compilation."""

    model_config = ConfigDict(extra="forbid")

    profile: StrictStr | ScanProfile
    mode: StrictStr = "production"
    target_url: StrictStr = Field(min_length=1, max_length=8192)
    templates: tuple[StrictStr, ...] = Field(default_factory=tuple)
    use_argus_templates: StrictBool = False
    templates_dir: StrictStr | None = None
    allow_code: StrictBool | None = None
    allow_headless: StrictBool | None = None
    allow_javascript: StrictBool | None = None
    silent: StrictBool = True
    timeout_s: StrictInt | None = None
    retries: StrictInt | None = None


class TemplateAnalysisResult(BaseModel):
    """Advisory capability/risk analysis output."""

    model_config = ConfigDict(extra="forbid")

    template_id: StrictStr
    risk_level: StrictStr
    protocols: tuple[StrictStr, ...] = Field(default_factory=tuple)
    capabilities: tuple[StrictStr, ...] = Field(default_factory=tuple)
    requires_oast: StrictBool = False
    advisory_warnings: tuple[StrictStr, ...] = Field(default_factory=tuple)
    production_allowed: StrictBool = True
    lab_allowed: StrictBool = True


class NucleiExecutionPlan(BaseModel):
    """Planned nuclei execution — production gates vs LAB bypass."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_id: StrictStr
    mode: StrictStr
    template_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)
    requires_approval: StrictBool = False
    blocked_reasons: tuple[StrictStr, ...] = Field(default_factory=tuple)
    risk_budget_remaining: StrictFloat | None = None


class NucleiReleaseRecord(BaseModel):
    """Template release provenance stub (§9.11)."""

    model_config = ConfigDict(extra="forbid")

    release_id: StrictStr
    version: StrictStr
    digest_sha256: StrictStr
    provenance: dict[str, Any] = Field(default_factory=dict)
    provenance_hash: StrictStr
    status: Literal["pending", "active", "rolled_back"] = "pending"
    activated_at: datetime | None = None
    previous_release_id: StrictStr | None = None
