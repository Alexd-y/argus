"""Pydantic schemas per api-contracts.md."""

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.owasp_top10_2025 import OwaspTop102025CategoryId

# Target: URL or domain, 1-512 chars
TARGET_PATTERN = r"^(https?://)?[a-zA-Z0-9][a-zA-Z0-9.-]*(:[0-9]{1,5})?(/.*)?$"


# --- Scan ---
class ScanOptionsAuth(BaseModel):
    """Authentication options for scan."""

    enabled: bool = False
    type: str = "basic"
    username: str = ""
    password: str = ""
    token: str = ""


class ScanOptionsScope(BaseModel):
    """Scope options for scan."""

    maxDepth: int = Field(ge=1, le=10, default=3)
    includeSubs: bool = False
    excludePatterns: str = ""


class ScanOptionsAdvanced(BaseModel):
    """Advanced scan options."""

    timeout: int = Field(ge=5, le=120, default=30)
    userAgent: str = "chrome"
    proxy: str = ""
    customHeaders: str = ""


class ScanOptionsVulnerabilities(BaseModel):
    """Vulnerability checks to run."""

    xss: bool = True
    sqli: bool = True
    csrf: bool = True
    ssrf: bool = False
    lfi: bool = False
    rce: bool = False


class ScanOptionsKal(BaseModel):
    """KAL sandbox gates (server env must also allow password audit when applicable)."""

    model_config = ConfigDict(extra="ignore")

    password_audit_opt_in: bool = False
    recon_dns_enumeration_opt_in: bool = False
    va_network_capture_opt_in: bool = False


class ScanOptions(BaseModel):
    """Full scan options per api-contracts."""

    model_config = ConfigDict(extra="ignore")

    scanType: str = "quick"
    reportFormat: str = "pdf"
    rateLimit: str = "normal"
    ports: str = "80,443,8080,8443"
    followRedirects: bool = True
    vulnerabilities: ScanOptionsVulnerabilities = Field(default_factory=ScanOptionsVulnerabilities)
    authentication: ScanOptionsAuth = Field(default_factory=ScanOptionsAuth)
    scope: ScanOptionsScope = Field(default_factory=ScanOptionsScope)
    advanced: ScanOptionsAdvanced = Field(default_factory=ScanOptionsAdvanced)
    kal: ScanOptionsKal = Field(default_factory=ScanOptionsKal)


class ScanCreateRequest(BaseModel):
    """POST /scans request."""

    model_config = ConfigDict(extra="ignore")

    target: str = Field(
        min_length=1,
        max_length=512,
        pattern=TARGET_PATTERN,
        description="URL or domain to scan",
    )
    email: str
    options: ScanOptions = Field(default_factory=ScanOptions)
    scan_mode: Literal["quick", "standard", "deep"] = Field(
        default="standard",
        description="Scan depth: quick (high-impact only), standard (OWASP Top 10), deep (exhaustive)",
    )
    report_language: str = Field(
        default="en",
        min_length=2,
        max_length=5,
        pattern="^en$",
        description="Report language — English only",
    )


class ScanCreateResponse(BaseModel):
    """POST /scans response."""

    scan_id: str
    status: str
    message: str | None = None


class ScanDetailResponse(BaseModel):
    """GET /scans/:id response."""

    id: str
    status: str
    progress: int
    phase: str
    target: str
    created_at: str


class ScanListItemResponse(BaseModel):
    """GET /scans list item (ARGUS v4)."""

    id: str
    status: str
    progress: int
    phase: str
    target: str
    created_at: str
    scan_mode: str = "standard"


class ScanSmartCreateRequest(BaseModel):
    """POST /scans/smart — intelligent scan enqueue."""

    model_config = ConfigDict(extra="ignore")

    target: str = Field(
        min_length=1,
        max_length=512,
        pattern=TARGET_PATTERN,
    )
    objective: str = Field(default="", max_length=2048)
    max_phases: int = Field(default=5, ge=1, le=20)
    tenant_id: str | None = Field(default=None, max_length=36)


class ScanSkillCreateRequest(BaseModel):
    """POST /scans/skill — skill-focused scan."""

    model_config = ConfigDict(extra="ignore")

    target: str = Field(
        min_length=1,
        max_length=512,
        pattern=TARGET_PATTERN,
    )
    skill: str = Field(..., min_length=1, max_length=256)
    tenant_id: str | None = Field(default=None, max_length=36)


class ScanCancelResponse(BaseModel):
    """POST /scans/{id}/cancel."""

    scan_id: str
    status: str
    message: str | None = None


BulkScanCancelItemStatus = Literal["cancelled", "skipped_terminal", "not_found"]


class BulkScanCancelItemResult(BaseModel):
    """Per-scan outcome for POST /admin/scans/bulk-cancel."""

    scan_id: str
    status: BulkScanCancelItemStatus


class AdminBulkScanCancelRequest(BaseModel):
    """POST /admin/scans/bulk-cancel — tenant-scoped bulk cancel."""

    tenant_id: UUID
    scan_ids: list[UUID] = Field(..., min_length=1, max_length=100)


class AdminBulkScanCancelResponse(BaseModel):
    """202 response — Appendix B style counts plus per-id outcomes."""

    cancelled_count: int = Field(ge=0)
    skipped_terminal_count: int = Field(ge=0)
    not_found_count: int = Field(ge=0)
    audit_id: str
    results: list[BulkScanCancelItemResult]


AdminScanSort = Literal["created_at_desc", "created_at_asc"]


class AdminScanListItemResponse(BaseModel):
    """GET /admin/scans — one row (tenant-scoped)."""

    id: str
    status: str
    progress: int
    phase: str
    target: str
    created_at: str
    updated_at: str
    scan_mode: str = "standard"


class AdminScanListResponse(BaseModel):
    """GET /admin/scans — paginated list."""

    scans: list[AdminScanListItemResponse]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)


class AdminScanToolMetricResponse(BaseModel):
    """Per-tool execution summary (from ``tool_runs``)."""

    tool_name: str
    status: str
    duration_sec: float | None = None
    started_at: str | None = None
    finished_at: str | None = None


class AdminScanErrorItemResponse(BaseModel):
    """Sanitized scan error line for admin UI (no stack traces)."""

    at: str
    phase: str | None = None
    message: str


class AdminScanDetailResponse(BaseModel):
    """GET /admin/scans/{scan_id} — drill-down metrics + error summary."""

    id: str
    status: str
    progress: int
    phase: str
    target: str
    created_at: str
    updated_at: str
    scan_mode: str = "standard"
    tool_metrics: list[AdminScanToolMetricResponse]
    error_summary: list[AdminScanErrorItemResponse]


BulkFindingSuppressItemStatus = Literal[
    "suppressed",
    "skipped_already_suppressed",
    "not_found",
]


class BulkFindingSuppressItemResult(BaseModel):
    """Per-finding outcome for POST /admin/findings/bulk-suppress."""

    finding_id: str
    status: BulkFindingSuppressItemStatus


class AdminBulkFindingSuppressRequest(BaseModel):
    """POST /admin/findings/bulk-suppress — marks findings as false positive / suppressed."""

    tenant_id: UUID
    finding_ids: list[UUID] = Field(..., min_length=1, max_length=100)
    reason: str = Field(..., min_length=1, max_length=4000)


class AdminBulkFindingSuppressResponse(BaseModel):
    suppressed_count: int = Field(ge=0)
    skipped_already_suppressed_count: int = Field(ge=0)
    not_found_count: int = Field(ge=0)
    audit_id: str
    results: list[BulkFindingSuppressItemResult]


# --- Admin findings (T24 — cross-tenant query API) ---

AdminFindingSeverity = Literal["critical", "high", "medium", "low", "info"]
AdminFindingConfidence = Literal["confirmed", "likely", "possible", "advisory"]


class AdminFindingSummary(BaseModel):
    """Single row in GET /admin/findings response (admin triage console).

    Field set is the storage-backed projection of ``Finding`` (no runtime intel
    enrichment fields like ``epss_score`` / ``kev_listed`` / ``ssvc_decision``,
    which originate from separate intel tables joined at report-render time).
    Frontend must treat extra columns as additive over time.
    """

    id: str
    tenant_id: str
    scan_id: str
    report_id: str | None = None
    severity: str
    title: str
    description: str | None = None
    cwe: str | None = None
    cvss: float | None = None
    owasp_category: str | None = None
    confidence: str
    dedup_status: str | None = None
    false_positive: bool = False
    created_at: str


class AdminFindingsListResponse(BaseModel):
    """GET /admin/findings paginated envelope."""

    findings: list[AdminFindingSummary]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)
    has_more: bool


class ScanCostApiResponse(BaseModel):
    """GET /scans/{scan_id}/cost — mirrors ScanCostTracker.breakdown subset."""

    scan_id: str
    total_cost_usd: float = 0.0
    total_tokens: int = 0
    total_calls: int = 0
    by_phase: dict[str, Any] = Field(default_factory=dict)
    source: str = Field(description="db_cost_summary | tracker_empty")


class SandboxExecuteRequest(BaseModel):
    """POST /sandbox/execute."""

    command: str = Field(..., min_length=1, max_length=4096)
    use_sandbox: bool = False
    timeout_sec: int | None = Field(default=None, ge=5, le=600)
    #: When set, tool-result cache is namespaced by scan (avoids stale hits on re-scan).
    scan_id: str = Field(default="", max_length=36)


class SandboxPythonRequest(BaseModel):
    """POST /sandbox/python — constrained one-shot code run."""

    code: str = Field(..., min_length=1, max_length=65536)
    timeout_sec: int = Field(default=15, ge=5, le=120)


class SandboxExecuteResponse(BaseModel):
    success: bool
    stdout: str = ""
    stderr: str = ""
    return_code: int = -1
    execution_time: float = 0.0
    truncated: bool = False
    from_cache: bool = False
    recovery_info: dict[str, Any] | None = Field(
        default=None,
        description="Tool recovery metadata: original tool, alternatives tried, final result",
    )


class ScanArtifactItem(BaseModel):
    """GET /scans/{scan_id}/artifacts — one object in tenant scan prefix (MinIO/S3)."""

    key: str
    size: int = Field(ge=0, description="Object size in bytes")
    last_modified: str = Field(description="UTC instant as ISO-8601 with Z")
    content_type: str
    download_url: str | None = Field(
        default=None,
        description="Presigned GET URL when presigned=true",
    )


# --- Report ---
class ReportSummary(BaseModel):
    """Report summary per api-contracts."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    technologies: list[str] = Field(default_factory=list)
    sslIssues: int = 0
    headerIssues: int = 0
    leaksFound: bool = False


FindingConfidenceLiteral = Literal["confirmed", "likely", "possible", "advisory"]
FindingEvidenceTypeLiteral = Literal[
    "observed",
    "tool_output",
    "version_match",
    "cve_correlation",
    "threat_model_inference",
]


class Finding(BaseModel):
    """Finding in report per api-contracts."""

    severity: str
    title: str
    description: str
    cwe: str | None = None
    cvss: float | None = None
    owasp_category: OwaspTop102025CategoryId | None = None
    proof_of_concept: dict[str, Any] | None = None
    confidence: FindingConfidenceLiteral = "likely"
    evidence_type: FindingEvidenceTypeLiteral | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    reproducible_steps: str | None = None
    applicability_notes: str | None = None
    adversarial_score: float | None = None
    dedup_status: str | None = None
    # ARG-044 — intel-enrichment fields (all optional / backward-compat).
    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    kev_listed: bool = False
    kev_added_date: str | None = None  # ISO-8601 date
    ssvc_decision: str | None = None  # "Act" | "Attend" | "Track*" | "Track"


class FindingDetailResponse(BaseModel):
    """GET /findings/{id} — full finding row + scan context ids."""

    id: str
    scan_id: str
    report_id: str | None = None
    severity: str
    title: str
    description: str
    cwe: str | None = None
    cvss: float | None = None
    owasp_category: OwaspTop102025CategoryId | None = None
    proof_of_concept: dict[str, Any] | None = None
    confidence: FindingConfidenceLiteral = "likely"
    evidence_type: FindingEvidenceTypeLiteral | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    reproducible_steps: str | None = None
    applicability_notes: str | None = None
    adversarial_score: float | None = None
    dedup_status: str | None = None
    created_at: str | None = None
    # ARG-044 — intel-enrichment fields (all optional / backward-compat).
    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    kev_listed: bool = False
    kev_added_date: str | None = None
    ssvc_decision: str | None = None


class FindingValidationApiResponse(BaseModel):
    """POST /findings/{id}/validate."""

    finding_id: str
    status: str
    confidence: str = "medium"
    reasoning: str = ""
    poc_command: str | None = None
    actual_impact: str = ""
    preconditions: list[str] = Field(default_factory=list)
    reject_reason: str | None = None
    exploit_public: bool = False
    exploit_sources: list[str] = Field(default_factory=list)
    stages_passed: list[str] = Field(default_factory=list)


class FindingPocBodyResponse(BaseModel):
    """GET /findings/{id}/poc or generate response body."""

    finding_id: str
    poc: dict[str, Any] | None = None
    poc_code: str | None = None
    playwright_script: str | None = None
    generator_model: str | None = None
    can_generate: bool = False
    hint: str | None = None


class ScanTimelineEventItem(BaseModel):
    """One ScanEvent row in chronological order with timing hints."""

    id: str
    event: str
    phase: str | None = None
    progress: int | None = None
    message: str | None = None
    created_at: str
    duration_sec: float | None = None
    gap_from_previous_sec: float | None = Field(
        default=None,
        description="Seconds since previous event; null for the first event",
    )


class ScanTimelineResponse(BaseModel):
    """GET /scans/{scan_id}/timeline."""

    scan_id: str
    events: list[ScanTimelineEventItem] = Field(default_factory=list)
    total_duration_sec: float = Field(
        ge=0.0,
        description="Wall time from first to last event timestamp",
    )


class FindingFalsePositiveRequest(BaseModel):
    """POST /findings/{finding_id}/false-positive."""

    model_config = ConfigDict(extra="ignore")

    reason: str = Field(..., min_length=1, max_length=8192)


class FindingFalsePositiveResponse(BaseModel):
    """Body after marking a finding as false positive."""

    finding_id: str
    false_positive: bool = True
    false_positive_reason: str
    dedup_status: str | None = None


class FindingRemediationSection(BaseModel):
    """Extracted markdown block from a packaged skill."""

    skill_id: str
    heading: str
    body: str


class FindingRemediationResponse(BaseModel):
    """GET /findings/{finding_id}/remediation."""

    finding_id: str
    skills_considered: list[str] = Field(default_factory=list)
    sections: list[FindingRemediationSection] = Field(default_factory=list)
    source: Literal["skills", "skills+llm"] = "skills"
    llm_summary: str | None = None


class ScanFindingsStatisticsResponse(BaseModel):
    """GET /scans/{scan_id}/findings/statistics."""

    scan_id: str
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_owasp: dict[str, int] = Field(default_factory=dict)
    by_confidence: dict[str, int] = Field(default_factory=dict)
    unique_cwes: list[str] = Field(default_factory=list)
    validated: int = Field(ge=0, description="Count with confidence=confirmed")
    false_positives: int = Field(ge=0)
    risk_score: float = Field(
        ge=0.0,
        description="Weighted severity sum excluding false positives",
    )


class ReportListResponse(BaseModel):
    """GET /reports response (single report in list or by target)."""

    report_id: str
    target: str
    summary: ReportSummary
    findings: list[Finding] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    generation_status: str = Field(
        default="ready",
        description="Report artifact generation: pending | processing | ready | failed",
    )
    tier: str = Field(default="midgard", description="Report tier from generate request")
    requested_formats: list[str] | None = Field(
        default=None,
        description="Formats requested at generation time (from Report.requested_formats JSONB)",
    )


class ReportDetailResponse(BaseModel):
    """GET /reports/:id full report."""

    report_id: str
    target: str
    summary: ReportSummary
    findings: list[Finding] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    created_at: str | None = None
    scan_id: str | None = None
    generation_status: str = Field(
        default="ready",
        description="Report artifact generation: pending | processing | ready | failed",
    )
    tier: str = Field(default="midgard", description="Report tier from generate request")
    requested_formats: list[str] | None = Field(
        default=None,
        description="Formats requested at generation time (from Report.requested_formats JSONB)",
    )


ReportTierLiteral = Literal["midgard", "asgard", "valhalla"]


class ReportGenerateRequest(BaseModel):
    """POST /scans/{scan_id}/reports/generate — RPT-007."""

    type: ReportTierLiteral = Field(..., description="Report tier / template family")
    formats: list[str] = Field(..., min_length=1, description="Export formats to produce")

    @field_validator("formats", mode="before")
    @classmethod
    def normalize_format_strings(cls, v: Any) -> list[str]:
        if not isinstance(v, list):
            raise TypeError("formats must be a list")
        return [str(x).lower().strip() for x in v if str(x).strip()]

    @field_validator("formats")
    @classmethod
    def validate_formats(cls, v: list[str]) -> list[str]:
        allowed = frozenset({"pdf", "html", "json", "csv"})
        if not v:
            raise ValueError("formats must contain at least one value")
        bad = [x for x in v if x not in allowed]
        if bad:
            raise ValueError(f"Invalid format(s): use pdf, html, json, csv (got: {bad})")
        # de-dupe preserving order
        seen: set[str] = set()
        out: list[str] = []
        for x in v:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out


class ReportGenerateAcceptedResponse(BaseModel):
    """202 Accepted after queuing report generation (RPT-007)."""

    report_id: str
    task_id: str | None = Field(default=None, description="Background task id when queued via Celery")


DEFAULT_GENERATE_ALL_FORMATS: tuple[str, ...] = ("pdf", "html", "json", "csv")


class ReportGenerateAllRequest(BaseModel):
    """POST /scans/{scan_id}/reports/generate-all — optional body; default formats = all four."""

    model_config = ConfigDict(extra="ignore")

    formats: list[str] | None = Field(
        default=None,
        description="Export formats; omit or null for pdf, html, json, csv",
    )

    @field_validator("formats", mode="before")
    @classmethod
    def normalize_format_strings_optional(cls, v: Any) -> list[str] | None:
        if v is None:
            return None
        if not isinstance(v, list):
            raise TypeError("formats must be a list or null")
        return [str(x).lower().strip() for x in v if str(x).strip()]

    @field_validator("formats")
    @classmethod
    def validate_formats_optional(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        if not v:
            raise ValueError("formats must contain at least one value when provided")
        allowed = frozenset({"pdf", "html", "json", "csv"})
        bad = [x for x in v if x not in allowed]
        if bad:
            raise ValueError(f"Invalid format(s): use pdf, html, json, csv (got: {bad})")
        seen: set[str] = set()
        out: list[str] = []
        for x in v:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    def resolved_formats(self) -> list[str]:
        if self.formats is None:
            return list(DEFAULT_GENERATE_ALL_FORMATS)
        return list(self.formats)


class ReportGenerateAllAcceptedResponse(BaseModel):
    """202 Accepted after queuing bulk report generation."""

    bundle_id: str
    report_ids: list[str]
    task_id: str | None = Field(default=None, description="Celery task id for generate_all_reports")
    count: int = Field(description="Number of report rows created (tiers × formats)")


# --- Health ---
class HealthResponse(BaseModel):
    """GET /health response."""

    status: str
    version: str | None = None


class CheckDetail(BaseModel):
    """ARG-041 — single dependency probe outcome inside /ready."""

    ok: bool
    latency_ms: float | None = None
    error: str | None = None


class ReadinessResponse(BaseModel):
    """GET /ready response — DB, Redis, storage, LLM provider checks (ARG-041)."""

    status: Literal["ok", "degraded"]
    database: bool
    redis: bool
    storage: bool
    llm_providers: bool
    checks: dict[str, CheckDetail] | None = None


class ProviderHealth(BaseModel):
    """ARG-041 — single LLM provider health snapshot inside /providers/health."""

    provider: str
    state: Literal["closed", "open", "half_open", "unknown"]
    last_success_ts: float | None = None
    error_rate_5xx: float = Field(ge=0.0, le=1.0, default=0.0)
    error_count_60s: int = Field(ge=0, default=0)
    request_count_60s: int = Field(ge=0, default=0)


class ProvidersHealthResponse(BaseModel):
    """GET /providers/health response."""

    status: Literal["ok", "degraded"]
    providers: list[ProviderHealth]


class QueueDepth(BaseModel):
    """ARG-041 — single Celery queue length probe."""

    queue: str
    depth: int = Field(ge=0)


class QueuesHealthResponse(BaseModel):
    """GET /queues/health response — Celery queue depths + worker count."""

    status: Literal["ok", "degraded"]
    queues: list[QueueDepth]
    worker_count: int = Field(ge=0)
    redis_reachable: bool


# --- Error ---
class ErrorResponse(BaseModel):
    """Error response per api-contracts."""

    error: str
    code: str | None = None
    details: dict[str, Any] | None = None


# --- Auth ---
class TokenPayload(BaseModel):
    """JWT payload."""

    sub: str
    tenant_id: str
    exp: int
    iat: int
    type: str = "access"


# --- Intelligence (/api/v1/intelligence/*) ---
IntelligenceAnalysisType = Literal["comprehensive", "quick", "passive"]
IntelligenceTestingPriority = Literal["high", "medium", "low"]


class IntelligenceAnalyzeTargetRequest(BaseModel):
    """POST /intelligence/analyze-target."""

    target: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="URL, hostname, or IP to analyze",
    )
    analysis_type: IntelligenceAnalysisType = Field(
        default="comprehensive",
        description="Depth: comprehensive, quick, or passive",
    )


class IntelligenceAnalyzeTargetData(BaseModel):
    """Structured target intelligence from LLM (validated subset; extra keys allowed in response)."""

    model_config = ConfigDict(extra="ignore")

    attack_surface: list[Any] = Field(default_factory=list)
    tech_stack: dict[str, Any] = Field(default_factory=dict)
    vuln_categories: list[Any] = Field(default_factory=list)
    recommended_tools: list[Any] = Field(default_factory=list)
    testing_priority: IntelligenceTestingPriority = "medium"
    estimated_time_minutes: int = Field(default=60, ge=1, le=10080)


class IntelligenceCveRequest(BaseModel):
    """POST /intelligence/cve."""

    cve_id: str = Field(
        ...,
        min_length=9,
        max_length=32,
        pattern=r"^CVE-\d{4}-\d+$",
        description="CVE identifier, e.g. CVE-2024-1234",
    )
    product: str | None = Field(
        default=None,
        max_length=256,
        description="Optional affected product name for context",
    )


class IntelligenceCveIntelBody(BaseModel):
    """CVE enrichment payload (Perplexity-backed)."""

    model_config = ConfigDict(extra="ignore")

    cve_id: str
    cvss_v3: float | None = None
    severity: str | None = None
    description: str = ""
    exploit_available: bool = False
    exploit_sources: list[str] = Field(default_factory=list)
    patch_available: bool = False
    patch_url: str | None = None
    actively_exploited: bool = False
    affected_versions: list[str] = Field(default_factory=list)
    remediation: str = ""


class IntelligenceOsintDomainRequest(BaseModel):
    """POST /intelligence/osint-domain."""

    domain: str = Field(..., min_length=1, max_length=253, description="Hostname or domain")


class IntelligenceShodanServiceItem(BaseModel):
    """One Shodan service entry."""

    model_config = ConfigDict(extra="ignore")

    port: int
    transport: str = "tcp"
    product: str | None = None
    version: str | None = None
    cpe: list[str] = Field(default_factory=list)


class IntelligenceShodanSummary(BaseModel):
    """Reduced Shodan host summary for OSINT combine."""

    model_config = ConfigDict(extra="ignore")

    ip: str | None = None
    hostnames: list[str] = Field(default_factory=list)
    org: str | None = None
    country: str | None = None
    open_ports: list[int] = Field(default_factory=list)
    vulns: list[str] = Field(default_factory=list)
    services: list[IntelligenceShodanServiceItem] = Field(default_factory=list)
