"""Pydantic schemas per api-contracts.md."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

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


class Finding(BaseModel):
    """Finding in report per api-contracts."""

    severity: str
    title: str
    description: str
    cwe: str | None = None
    cvss: float | None = None


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


class ReadinessResponse(BaseModel):
    """GET /ready response — DB, Redis, storage checks."""

    status: str  # "ok" | "degraded"
    database: bool
    redis: bool
    storage: bool


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
