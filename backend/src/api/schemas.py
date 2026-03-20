"""Pydantic schemas per api-contracts.md."""

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

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


class ReportDetailResponse(BaseModel):
    """GET /reports/:id full report."""

    report_id: str
    target: str
    summary: ReportSummary
    findings: list[Finding] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    created_at: str | None = None
    scan_id: str | None = None


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
