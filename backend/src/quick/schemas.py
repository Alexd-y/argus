"""Pydantic contracts for Quick execution mode.

Immutable frozen models reject extra fields. Credentials never appear here —
``authenticated_context_id`` is a secret-store reference only.
"""

from __future__ import annotations

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


class _Frozen(BaseModel):
    """Shared frozen / extra-forbid config for Quick domain objects."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class QuickProfileName(StrEnum):
    COMPACT = "compact"
    BALANCED = "balanced"
    EXTENDED = "extended"


class QuickTaskStage(StrEnum):
    DISCOVERY = "discovery"
    FINGERPRINT = "fingerprint"
    TEST = "test"
    VERIFY = "verify"
    TRIAGE = "triage"
    REPORT = "report"


class QuickTaskStatus(StrEnum):
    QUEUED = "queued"
    LEASED = "leased"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"


class QuickCoverageState(StrEnum):
    TESTED = "tested"
    PARTIALLY_TESTED = "partially_tested"
    NOT_APPLICABLE = "not_applicable"
    NOT_SCHEDULED = "not_scheduled"
    TIMED_OUT = "timed_out"
    FAILED = "failed"


class QuickBudgetKind(StrEnum):
    WALL_CLOCK = "wall_clock"
    DISCOVERY = "discovery"
    FINGERPRINT = "fingerprint"
    VERIFICATION = "verification"
    AI = "ai"
    REPORT = "report"
    REQUEST = "request"
    PER_HOST = "per_host"
    CONCURRENCY = "concurrency"


class FindingTriageVerdict(StrEnum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    NEEDS_VERIFICATION = "needs_verification"
    HYPOTHESIS = "hypothesis"
    FALSE_POSITIVE_CANDIDATE = "false_positive_candidate"


class SeverityFloor(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class QuickBudget(_Frozen):
    """Typed wall-clock / request / concurrency budget for one Quick scan."""

    wall_clock_budget_seconds: StrictInt = Field(ge=1, le=86_400)
    discovery_budget_seconds: StrictInt = Field(ge=0, le=86_400)
    fingerprint_budget_seconds: StrictInt = Field(ge=0, le=86_400)
    verification_budget_seconds: StrictInt = Field(ge=0, le=86_400)
    ai_budget_seconds: StrictInt = Field(ge=0, le=86_400)
    report_budget_seconds: StrictInt = Field(ge=0, le=86_400)
    request_budget: StrictInt = Field(ge=0)
    per_host_budget: StrictInt = Field(ge=0)
    concurrency_budget: StrictInt = Field(ge=1, le=256)
    reserve_for_validation_percent: StrictInt = Field(ge=0, le=50)


class QuickScanConfig(_Frozen):
    """Resolved Quick profile for a single scan (secret refs only, no credentials)."""

    profile: QuickProfileName
    wall_clock_budget_seconds: StrictInt = Field(ge=1, le=86_400)
    ai_budget_seconds: StrictInt = Field(ge=0, le=86_400)
    reserve_for_validation_percent: StrictInt = Field(ge=0, le=50)
    max_targets: StrictInt = Field(ge=1, le=10_000)
    max_urls_per_host: StrictInt = Field(ge=1, le=10_000)
    crawl_depth: StrictInt = Field(ge=0, le=10)
    severity_floor: SeverityFloor = SeverityFloor.MEDIUM
    enable_ai: StrictBool = True
    enable_oast: StrictBool = True
    enable_headless_on_signal: StrictBool = True
    authenticated_context_id: StrictStr | None = Field(default=None, max_length=36)
    template_policy_id: StrictStr = Field(default="quick-default", min_length=1, max_length=128)
    cloud_llm_allowed: StrictBool = False


class QuickTask(_Frozen):
    """One scheduled tool/capability invocation in a Quick plan."""

    task_id: StrictStr = Field(min_length=1, max_length=36)
    stage: QuickTaskStage
    target_ref: StrictStr = Field(min_length=1, max_length=256)
    tool_id: StrictStr = Field(min_length=1, max_length=128)
    capability_id: StrictStr = Field(min_length=1, max_length=256)
    estimated_seconds: StrictInt = Field(ge=0, le=86_400)
    estimated_requests: StrictInt = Field(ge=0)
    priority_score: StrictFloat = Field(ge=0.0, le=1.0)
    depends_on: tuple[StrictStr, ...] = Field(default_factory=tuple)
    success_signal: tuple[StrictStr, ...] = Field(default_factory=tuple)
    stop_conditions: tuple[StrictStr, ...] = Field(default_factory=tuple)
    policy_decision_id: StrictStr | None = Field(default=None, max_length=36)
    budget_lease_id: StrictStr | None = Field(default=None, max_length=36)
    idempotency_key: StrictStr = Field(min_length=1, max_length=256)
    status: QuickTaskStatus = QuickTaskStatus.QUEUED


class QuickCoverageRecord(_Frozen):
    """Coverage DTO mapped onto existing CoverageStatus + reason_code (QUICK-005)."""

    asset_id: StrictStr = Field(min_length=1, max_length=36)
    capability_id: StrictStr = Field(min_length=1, max_length=256)
    state: QuickCoverageState
    reason_code: StrictStr = Field(min_length=1, max_length=128)
    tools: tuple[StrictStr, ...] = Field(default_factory=tuple)
    template_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)
    evidence_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)
    started_at: datetime | None = None
    finished_at: datetime | None = None


class QuickScanPlan(_Frozen):
    """Immutable plan snapshot. Revisions are append-only (see QuickPlanRevision)."""

    scan_id: StrictStr = Field(min_length=1, max_length=36)
    mode: Literal["quick"] = "quick"
    profile: QuickProfileName
    deadline_at: datetime
    budget: QuickBudget
    assumptions: tuple[StrictStr, ...] = Field(default_factory=tuple)
    stages: tuple[StrictStr, ...] = Field(default_factory=tuple)
    tasks: tuple[QuickTask, ...] = Field(default_factory=tuple)
    fallbacks: tuple[StrictStr, ...] = Field(default_factory=tuple)
    coverage_intent: tuple[QuickCoverageRecord, ...] = Field(default_factory=tuple)
    plan_version: StrictInt = Field(ge=1)
    prompt_version: StrictStr = Field(min_length=1, max_length=128)
    model_route: StrictStr = Field(min_length=1, max_length=128)


class QuickPlanRevision(_Frozen):
    """Adaptive widening record — never mutates execution_mode."""

    scan_id: StrictStr = Field(min_length=1, max_length=36)
    from_version: StrictInt = Field(ge=1)
    to_version: StrictInt = Field(ge=1)
    revision_reason: StrictStr = Field(min_length=1, max_length=512)
    evidence_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)
    cost_estimate_seconds: StrictInt = Field(ge=0, le=86_400)
    remaining_budget_seconds: StrictInt = Field(ge=0, le=86_400)
    created_at: datetime


class FingerprintFact(_Frozen):
    """Single fingerprint attribute with confidence and evidence (never a guess as fact)."""

    value: StrictStr | None = Field(default=None, max_length=512)
    confidence: StrictFloat = Field(ge=0.0, le=1.0)
    evidence_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)


class AssetFingerprint(_Frozen):
    """Typed asset fingerprint produced in Quick stage 2."""

    asset_id: StrictStr = Field(min_length=1, max_length=36)
    protocol: FingerprintFact | None = None
    service: FingerprintFact | None = None
    product: FingerprintFact | None = None
    version: FingerprintFact | None = None
    web_server: FingerprintFact | None = None
    framework: FingerprintFact | None = None
    cms: FingerprintFact | None = None
    language: FingerprintFact | None = None
    runtime: FingerprintFact | None = None
    waf_cdn_hints: FingerprintFact | None = None
    authentication_surface: FingerprintFact | None = None
    api_hints: FingerprintFact | None = None
    cloud_storage_admin_debug: FingerprintFact | None = None
    tls_security_header_posture: FingerprintFact | None = None
    network_os_hints: FingerprintFact | None = None
    evidence_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)


class FindingTriage(_Frozen):
    """AI/rules triage output — cannot be the sole writer of a finding."""

    finding_id: StrictStr = Field(min_length=1, max_length=36)
    verdict: FindingTriageVerdict
    severity: SeverityFloor
    confidence: StrictFloat = Field(ge=0.0, le=1.0)
    cwe_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)
    cve_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)
    owasp: StrictStr | None = Field(default=None, max_length=64)
    fact_summary: StrictStr = Field(min_length=1, max_length=4096)
    hypothesis_summary: StrictStr | None = Field(default=None, max_length=4096)
    suggested_verification: StrictStr | None = Field(default=None, max_length=512)
    estimated_verification_seconds: StrictInt | None = Field(default=None, ge=0, le=86_400)
    citations: tuple[StrictStr, ...] = Field(default_factory=tuple)


class SecurityCritique(_Frozen):
    """WRB critic output for disputed high/critical results."""

    triage_id: StrictStr = Field(min_length=1, max_length=36)
    evidence_to_weakness_valid: StrictBool
    alternative_explanations: tuple[StrictStr, ...] = Field(default_factory=tuple)
    false_positive_indicators: tuple[StrictStr, ...] = Field(default_factory=tuple)
    suggested_verification: StrictStr | None = Field(default=None, max_length=512)
    estimated_cost_seconds: StrictInt | None = Field(default=None, ge=0, le=86_400)
    citations: tuple[StrictStr, ...] = Field(default_factory=tuple)


class QuickReport(_Frozen):
    """Quick report payload. Absence of a finding is never proof of safety."""

    scan_id: StrictStr = Field(min_length=1, max_length=36)
    profile: QuickProfileName
    executive_summary: tuple[StrictStr, ...] = Field(min_length=1, max_length=10)
    verified_finding_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)
    other_finding_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)
    assets_summary: tuple[StrictStr, ...] = Field(default_factory=tuple)
    coverage: tuple[QuickCoverageRecord, ...] = Field(default_factory=tuple)
    skipped_timeouts_failures: tuple[StrictStr, ...] = Field(default_factory=tuple)
    budget_usage: dict[str, Any] = Field(default_factory=dict)
    versions: dict[str, StrictStr] = Field(default_factory=dict)
    recommended_next_mode: Literal["production", "lab_unrestricted", "standard", "deep"] = "production"
    follow_up_actions: tuple[StrictStr, ...] = Field(default_factory=tuple)
    incompleteness_warning: StrictStr = Field(
        default=(
            "This quick scan does not prove the absence of vulnerabilities. "
            "Uncovered capabilities are gaps, not a clean bill of health."
        ),
        min_length=1,
        max_length=1024,
    )
