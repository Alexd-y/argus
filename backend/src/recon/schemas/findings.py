"""Canonical finding data shapes — normalized output from all recon tools."""

from pydantic import BaseModel, Field


class SubdomainFinding(BaseModel):
    """Discovered subdomain."""
    subdomain: str
    source: str = ""
    is_wildcard: bool = False
    parent_domain: str = ""


class DnsRecordFinding(BaseModel):
    """DNS record entry."""
    hostname: str
    record_type: str  # A, AAAA, CNAME, MX, NS, TXT, CAA, SOA, PTR
    value: str
    ttl: int | None = None
    comment: str = ""


class IpAddressFinding(BaseModel):
    """Resolved IP address with metadata."""
    ip: str
    hostname: str | None = None
    is_cdn: bool = False
    cdn_name: str | None = None
    asn: str | None = None
    org: str | None = None
    country: str | None = None
    cloud_provider: str | None = None


class ServiceFinding(BaseModel):
    """Network service discovered on a port."""
    ip: str
    port: int
    protocol: str = "tcp"
    service_name: str | None = None
    version: str | None = None
    banner: str | None = None
    is_expected: bool = True
    risk_level: str = "info"  # info / low / medium / high / critical


class UrlFinding(BaseModel):
    """Discovered URL/endpoint."""
    url: str
    method: str = "GET"
    status_code: int | None = None
    content_type: str | None = None
    content_length: int | None = None
    title: str | None = None
    redirect_location: str | None = None
    source: str = ""


class ParameterFinding(BaseModel):
    """URL parameter identified for testing."""
    url: str
    param_name: str
    param_type: str = "query"  # query / path / header / cookie / body
    location: str = "url"
    example_values: list[str] = Field(default_factory=list)
    category: str = ""  # redirect / id / file / search / auth / pagination
    is_sensitive: bool = False


class TechnologyFinding(BaseModel):
    """Detected technology/framework."""
    url: str = ""
    name: str
    version: str | None = None
    category: str | None = None  # server / framework / cms / cdn / waf / frontend / analytics
    confidence: float = 1.0
    evidence: str = ""


class TlsInfoFinding(BaseModel):
    """TLS/SSL inspection result."""
    hostname: str
    port: int = 443
    protocol_version: str = ""
    cipher_suite: str = ""
    cert_issuer: str | None = None
    cert_subject: str | None = None
    cert_expiry: str | None = None
    cert_san: list[str] = Field(default_factory=list)
    has_hsts: bool = False
    issues: list[str] = Field(default_factory=list)


class HeaderInfoFinding(BaseModel):
    """HTTP security header analysis."""
    url: str
    header_name: str
    header_value: str | None = None
    is_present: bool = True
    is_secure: bool = True
    recommendation: str = ""


class JsFinding(BaseModel):
    """Finding from JavaScript analysis."""
    url: str
    finding_type: str  # api_endpoint / internal_url / token / key / debug / config
    value: str
    context: str | None = None
    category: str = ""  # api / auth / storage / analytics / debug / third_party


class SecretCandidate(BaseModel):
    """Potential secret/credential found in source."""
    url: str = ""
    secret_type: str  # api_key / token / password / aws_key / private_key / etc
    value_masked: str
    file_path: str | None = None
    line: int | None = None
    confidence: float = 0.5


class ApiEndpointFinding(BaseModel):
    """API endpoint discovered."""
    base_url: str
    path: str
    method: str = "GET"
    auth_required: bool | None = None
    params: list[str] = Field(default_factory=list)
    content_type: str | None = None
    api_version: str | None = None
    source: str = ""


class OsintEntry(BaseModel):
    """OSINT finding from public sources."""
    source: str  # github / gitlab / pastebin / document / job_posting / etc
    entry_type: str  # repo / code_snippet / document / metadata / reference
    value: str
    url: str | None = None
    context: str | None = None
    relevance: str = "medium"


class ContentEntry(BaseModel):
    """Content discovery result."""
    url: str
    status_code: int
    content_length: int | None = None
    content_type: str | None = None
    category: str = ""  # admin / config / backup / debug / upload / sensitive
    is_interesting: bool = False
    notes: str = ""
