"""Pydantic schemas per api-contracts.md."""

from datetime import datetime
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
    vulnerabilities: ScanOptionsVulnerabilities = Field(
        default_factory=ScanOptionsVulnerabilities
    )
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


# --- Admin audit-log chain integrity verification (T25) ---


class AuditChainVerifyResponse(BaseModel):
    """POST /admin/audit-logs/verify-chain envelope.

    Carries the verdict of replaying the SHA-256 hash chain over the
    ``audit_logs`` rows in the requested time-window. ``ok`` is ``True`` for a
    clean chain (or an empty window); ``False`` signals tamper-evident drift,
    in which case ``drift_event_id`` and ``drift_detected_at`` localize the
    first inconsistent row. Frontend (T22) renders an OK / DRIFT badge from
    these fields.

    ``effective_since`` / ``effective_until`` echo the resolved time-window
    actually scanned (the implicit "last 90 days" default is applied when the
    caller omits one or both bounds). UI / SIEM consume them to render the
    real verified range — never assume the request bounds match the response
    bounds without comparing.
    """

    ok: bool
    verified_count: int = Field(
        ge=0,
        description="Number of rows that passed verification (0 when window empty).",
    )
    last_verified_index: int = Field(
        ge=-1,
        description=(
            "Zero-based index of the last verified row in the time-window slice; "
            "``-1`` when no rows verified (empty window or drift on the first row)."
        ),
    )
    drift_event_id: str | None = Field(
        default=None,
        description="``id`` of the row at which drift was detected; null on success.",
    )
    drift_detected_at: datetime | None = Field(
        default=None,
        description="``created_at`` of the drifted row; null on success.",
    )
    effective_since: datetime = Field(
        description=(
            "Lower bound of the time-window actually scanned (resolved from the "
            "request ``since`` or the implicit 90-day default anchored to "
            "``effective_until``). Always present so callers can verify the "
            "real range."
        ),
    )
    effective_until: datetime = Field(
        description=(
            "Upper bound of the time-window actually scanned (resolved from the "
            "request ``until`` or anchored to ``utcnow`` when omitted). Always "
            "present so callers can verify the real range."
        ),
    )


# --- Emergency stop / throttle (T31, ARG-052) ---

EMERGENCY_REASON_MIN_LEN: int = 10
EMERGENCY_REASON_MAX_LEN: int = 1000
EMERGENCY_STOP_PHRASE: str = "STOP ALL SCANS"
EMERGENCY_RESUME_PHRASE: str = "RESUME ALL SCANS"

EmergencyThrottleDurationMinutes = Literal[15, 60, 240, 1440]

EmergencyAuditEventType = Literal[
    "emergency.stop_all",
    "emergency.resume_all",
    "emergency.throttle",
]


class _EmergencyReasonBase(BaseModel):
    """Common reason validation; min/max length plus stripped non-blank check."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(
        ...,
        min_length=EMERGENCY_REASON_MIN_LEN,
        max_length=EMERGENCY_REASON_MAX_LEN,
        description=(
            "Operator-supplied free-text justification recorded in the audit "
            "trail. Must be at least 10 non-whitespace characters."
        ),
    )

    @field_validator("reason")
    @classmethod
    def _normalize_reason(cls, value: str) -> str:
        normalized = value.strip()
        if len(normalized) < EMERGENCY_REASON_MIN_LEN:
            raise ValueError(
                f"reason must contain at least {EMERGENCY_REASON_MIN_LEN} "
                "non-whitespace characters"
            )
        return normalized


class EmergencyStopAllRequest(_EmergencyReasonBase):
    """POST /admin/system/emergency/stop_all — body."""

    confirmation_phrase: str = Field(
        ...,
        description=(
            "Must equal the literal phrase ``STOP ALL SCANS`` (case-sensitive). "
            "Defends against accidental cross-tenant kill from CLI typos."
        ),
    )

    @field_validator("confirmation_phrase")
    @classmethod
    def _enforce_phrase(cls, value: str) -> str:
        if value != EMERGENCY_STOP_PHRASE:
            raise ValueError("confirmation_phrase mismatch")
        return value


class EmergencyStopAllResponse(BaseModel):
    """202 — fanout summary plus audit fingerprint."""

    status: Literal["stopped"]
    cancelled_count: int = Field(ge=0)
    skipped_terminal_count: int = Field(ge=0)
    tenants_affected: int = Field(ge=0)
    activated_at: datetime
    audit_id: str


class EmergencyResumeAllRequest(_EmergencyReasonBase):
    """POST /admin/system/emergency/resume_all — body."""

    confirmation_phrase: str = Field(
        ...,
        description=(
            "Must equal the literal phrase ``RESUME ALL SCANS`` (case-sensitive)."
        ),
    )

    @field_validator("confirmation_phrase")
    @classmethod
    def _enforce_phrase(cls, value: str) -> str:
        if value != EMERGENCY_RESUME_PHRASE:
            raise ValueError("confirmation_phrase mismatch")
        return value


class EmergencyResumeAllResponse(BaseModel):
    """200 — emergency lifted."""

    status: Literal["resumed"]
    resumed_at: datetime
    audit_id: str


class EmergencyThrottleRequest(_EmergencyReasonBase):
    """POST /admin/system/emergency/throttle — per-tenant TTL throttle."""

    tenant_id: UUID
    duration_minutes: EmergencyThrottleDurationMinutes = Field(
        ...,
        description="Allowed values: 15, 60, 240, or 1440 minutes.",
    )


class EmergencyThrottleResponse(BaseModel):
    """200 — TTL flag set; ``expires_at`` is the absolute resume instant."""

    status: Literal["throttled"]
    tenant_id: str
    duration_minutes: EmergencyThrottleDurationMinutes
    expires_at: datetime
    audit_id: str


class EmergencyGlobalStateOut(BaseModel):
    """Global kill-switch presence + reason summary (no operator subject leaked)."""

    active: bool
    reason: str | None = None
    activated_at: datetime | None = None


class EmergencyTenantThrottleOut(BaseModel):
    """One per-tenant active throttle entry."""

    tenant_id: str
    reason: str
    activated_at: datetime
    expires_at: datetime
    duration_seconds: int = Field(ge=0)


class EmergencyStatusResponse(BaseModel):
    """GET /admin/system/emergency/status — current emergency posture."""

    global_state: EmergencyGlobalStateOut
    tenant_throttles: list[EmergencyTenantThrottleOut] = Field(default_factory=list)
    queried_at: datetime


class EmergencyAuditTrailItem(BaseModel):
    """One audit row projected for the emergency UI (T30 audit trail viewer)."""

    audit_id: str
    event_type: EmergencyAuditEventType
    tenant_id_hash: str
    operator_subject_hash: str | None = None
    reason: str | None = None
    details: dict[str, Any] | None = None
    created_at: datetime


class EmergencyAuditTrailResponse(BaseModel):
    """GET /admin/system/emergency/audit-trail — recent emergency events."""

    items: list[EmergencyAuditTrailItem]
    limit: int = Field(ge=1, le=200)
    has_more: bool


# --- Scan schedules CRUD (T33, ARG-056) ---

ScanScheduleMode = Literal["standard", "deep"]
SCAN_SCHEDULE_NAME_MAX: int = 255
SCAN_SCHEDULE_CRON_MAX: int = 64
SCAN_SCHEDULE_TARGET_MAX: int = 2048
SCAN_SCHEDULE_RUN_NOW_REASON_MIN: int = 10
SCAN_SCHEDULE_RUN_NOW_REASON_MAX: int = 500


def _strip_url_query_and_fragment(value: str | None) -> str | None:
    """Strip ``?query`` and ``#fragment`` from a target URL (S2.2).

    Persisted ``target_url`` values flow into AuditLog rows and Celery
    task arguments. Query strings and fragments commonly carry PII or
    secrets (``?token=...``, ``?email=...``), and dropping them at the
    schema boundary keeps every downstream consumer safe-by-default.
    The host + path are sufficient for every supported scan tool.

    Returns ``None`` when ``value`` is ``None`` (PATCH-style omission)
    so the caller's optional-field semantics remain unchanged.
    """
    if value is None:
        return None
    from urllib.parse import urlsplit, urlunsplit

    parts = urlsplit(value)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


class ScanScheduleCreateRequest(BaseModel):
    """POST /admin/scan-schedules — create a recurring scheduled scan.

    All fields are required. The ``maintenance_window_cron`` field is
    optional and defaults to ``None`` (no window — fires whenever the
    primary cron ticks). ``cron_expression`` is validated by
    :func:`src.scheduling.cron_parser.validate_cron` at the API layer with
    the project DOS-guard floor (5 minutes); ``maintenance_window_cron``
    uses a relaxed 60-minute floor because operators usually set windows
    on hourly granularity.
    """

    model_config = ConfigDict(extra="forbid")

    tenant_id: UUID = Field(
        ..., description="Owning tenant; admin must equal own tenant, super-admin any."
    )
    name: str = Field(..., min_length=1, max_length=SCAN_SCHEDULE_NAME_MAX)
    cron_expression: str = Field(..., min_length=1, max_length=SCAN_SCHEDULE_CRON_MAX)
    target_url: str = Field(
        ...,
        min_length=1,
        max_length=SCAN_SCHEDULE_TARGET_MAX,
        pattern=TARGET_PATTERN,
    )
    scan_mode: ScanScheduleMode = "standard"
    enabled: bool = True
    maintenance_window_cron: str | None = Field(
        default=None, max_length=SCAN_SCHEDULE_CRON_MAX
    )

    @field_validator("target_url")
    @classmethod
    def _normalize_target_url(cls, value: str) -> str:
        normalized = _strip_url_query_and_fragment(value)
        # Pydantic only invokes this validator when ``value`` is non-None
        # (the field is required), so ``normalized`` cannot be None here.
        assert normalized is not None
        return normalized


class ScanScheduleUpdateRequest(BaseModel):
    """PATCH /admin/scan-schedules/{id} — partial update.

    PATCH semantics:
      * Any field set to ``None`` (omitted) is treated as "no change".
      * To CLEAR ``maintenance_window_cron`` the client currently cannot
        send ``null`` distinguishable from omission — this is a documented
        v1 deferment. Operators who need to remove the window must
        recreate the schedule. A future iteration may switch to a
        sentinel-based clear semantic.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(
        default=None, min_length=1, max_length=SCAN_SCHEDULE_NAME_MAX
    )
    cron_expression: str | None = Field(
        default=None, min_length=1, max_length=SCAN_SCHEDULE_CRON_MAX
    )
    target_url: str | None = Field(
        default=None,
        min_length=1,
        max_length=SCAN_SCHEDULE_TARGET_MAX,
        pattern=TARGET_PATTERN,
    )
    scan_mode: ScanScheduleMode | None = None
    enabled: bool | None = None
    maintenance_window_cron: str | None = Field(
        default=None, max_length=SCAN_SCHEDULE_CRON_MAX
    )

    @field_validator("target_url")
    @classmethod
    def _normalize_target_url(cls, value: str | None) -> str | None:
        return _strip_url_query_and_fragment(value)


class ScanScheduleResponse(BaseModel):
    """One row of ``scan_schedules`` projected for the operator console."""

    id: UUID
    tenant_id: UUID
    name: str
    cron_expression: str
    target_url: str
    scan_mode: str
    enabled: bool
    maintenance_window_cron: str | None
    last_run_at: datetime | None
    next_run_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ScanSchedulesListResponse(BaseModel):
    """GET /admin/scan-schedules — paginated list."""

    items: list[ScanScheduleResponse]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)


class ScanScheduleRunNowRequest(BaseModel):
    """POST /admin/scan-schedules/{id}/run-now — manual override.

    ``bypass_maintenance_window`` defaults to False so the operator must
    explicitly opt into firing during a declared maintenance window.
    """

    model_config = ConfigDict(extra="forbid")

    bypass_maintenance_window: bool = False
    reason: str = Field(
        ...,
        min_length=SCAN_SCHEDULE_RUN_NOW_REASON_MIN,
        max_length=SCAN_SCHEDULE_RUN_NOW_REASON_MAX,
        description="Free-text justification recorded in the audit trail.",
    )

    @field_validator("reason")
    @classmethod
    def _validate_reason_strip(cls, value: str) -> str:
        normalized = value.strip()
        if len(normalized) < SCAN_SCHEDULE_RUN_NOW_REASON_MIN:
            raise ValueError(
                f"reason must contain at least {SCAN_SCHEDULE_RUN_NOW_REASON_MIN} "
                "non-whitespace characters"
            )
        return normalized


class ScanScheduleRunNowResponse(BaseModel):
    """202 — schedule fired manually; returns Celery task id and audit id."""

    schedule_id: UUID
    enqueued_task_id: str
    bypassed_maintenance_window: bool
    enqueued_at: datetime
    audit_id: str


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
    tier: str = Field(
        default="midgard", description="Report tier from generate request"
    )
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
    tier: str = Field(
        default="midgard", description="Report tier from generate request"
    )
    requested_formats: list[str] | None = Field(
        default=None,
        description="Formats requested at generation time (from Report.requested_formats JSONB)",
    )


ReportTierLiteral = Literal["midgard", "asgard", "valhalla"]


class ReportGenerateRequest(BaseModel):
    """POST /scans/{scan_id}/reports/generate — RPT-007."""

    type: ReportTierLiteral = Field(..., description="Report tier / template family")
    formats: list[str] = Field(
        ..., min_length=1, description="Export formats to produce"
    )

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
            raise ValueError(
                f"Invalid format(s): use pdf, html, json, csv (got: {bad})"
            )
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
    task_id: str | None = Field(
        default=None, description="Background task id when queued via Celery"
    )


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
            raise ValueError(
                f"Invalid format(s): use pdf, html, json, csv (got: {bad})"
            )
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
    task_id: str | None = Field(
        default=None, description="Celery task id for generate_all_reports"
    )
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

    domain: str = Field(
        ..., min_length=1, max_length=253, description="Hostname or domain"
    )


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


# --- Webhook DLQ admin (T39, ARG-053) ---

WEBHOOK_DLQ_REASON_MIN_LEN: int = 10
WEBHOOK_DLQ_REASON_MAX_LEN: int = 500

WebhookDlqTriageStatus = Literal["pending", "replayed", "abandoned"]


class WebhookDlqEntryItem(BaseModel):
    """One DLQ row projected for the operator console (T39, ARG-053).

    ``target_url_hash`` is the 64-hex sha256 of the original webhook URL;
    the raw URL (which carries the secret webhook token) NEVER leaves
    the database. The frontend treats the hash as an opaque identifier
    for cross-row correlation.
    """

    id: UUID
    tenant_id: UUID
    adapter_name: str
    event_type: str
    event_id: str
    target_url_hash: str
    attempt_count: int = Field(ge=0)
    last_error_code: str
    last_status_code: int | None = None
    next_retry_at: datetime | None = None
    created_at: datetime
    replayed_at: datetime | None = None
    abandoned_at: datetime | None = None
    abandoned_reason: str | None = None
    triage_status: WebhookDlqTriageStatus


class WebhookDlqListResponse(BaseModel):
    """GET /admin/webhooks/dlq — paginated DLQ list."""

    items: list[WebhookDlqEntryItem]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=200)
    offset: int = Field(ge=0)


class WebhookDlqReplayRequest(BaseModel):
    """POST /admin/webhooks/dlq/{entry_id}/replay — body."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(
        ...,
        min_length=WEBHOOK_DLQ_REASON_MIN_LEN,
        max_length=WEBHOOK_DLQ_REASON_MAX_LEN,
        description=(
            "Operator-supplied free-text justification (10..500 chars) "
            "recorded in the audit trail."
        ),
    )

    @field_validator("reason")
    @classmethod
    def _normalize_reason(cls, value: str) -> str:
        normalized = value.strip()
        if len(normalized) < WEBHOOK_DLQ_REASON_MIN_LEN:
            raise ValueError(
                f"reason must contain at least {WEBHOOK_DLQ_REASON_MIN_LEN} "
                "non-whitespace characters"
            )
        return normalized


class WebhookDlqReplayResponse(BaseModel):
    """202 — replay processed (success OR failure).

    ``success=True`` + ``message_code='replay_succeeded'`` flips the row
    to terminal ``replayed`` state. ``success=False`` +
    ``message_code='replay_failed'`` increments ``attempt_count`` and
    leaves the row in the DLQ for the next operator / beat retry.
    """

    entry_id: UUID
    success: bool
    attempt_count: int = Field(ge=0)
    new_status: Literal["replayed", "pending"]
    audit_id: UUID
    message_code: Literal["replay_succeeded", "replay_failed"]


class WebhookDlqAbandonRequest(BaseModel):
    """POST /admin/webhooks/dlq/{entry_id}/abandon — body."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(
        ...,
        min_length=WEBHOOK_DLQ_REASON_MIN_LEN,
        max_length=WEBHOOK_DLQ_REASON_MAX_LEN,
        description=(
            "Operator-supplied free-text justification (10..500 chars) "
            "recorded in the audit trail."
        ),
    )

    @field_validator("reason")
    @classmethod
    def _normalize_reason(cls, value: str) -> str:
        normalized = value.strip()
        if len(normalized) < WEBHOOK_DLQ_REASON_MIN_LEN:
            raise ValueError(
                f"reason must contain at least {WEBHOOK_DLQ_REASON_MIN_LEN} "
                "non-whitespace characters"
            )
        return normalized


class WebhookDlqAbandonResponse(BaseModel):
    """200 — row marked abandoned with ``abandoned_reason='operator'``."""

    entry_id: UUID
    new_status: Literal["abandoned"]
    audit_id: UUID
