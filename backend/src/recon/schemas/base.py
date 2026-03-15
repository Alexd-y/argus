"""Base enums and shared types for recon schemas."""

from enum import IntEnum, StrEnum


class ReconStage(IntEnum):
    """Recon workflow stages mapped from methodology docs."""
    SCOPE_PREP = 0
    DOMAIN_DNS = 1
    SUBDOMAIN_ENUM = 2
    DNS_VALIDATION = 3
    LIVE_HOSTS = 4
    HOST_CLUSTERING = 5
    FINGERPRINTING = 6
    ENTRY_POINTS = 7
    URL_CRAWLING = 8
    PARAM_ANALYSIS = 9
    JS_ANALYSIS = 10
    API_SURFACE = 11
    PORT_SCANNING = 12
    TLS_HEADERS = 13
    CONTENT_DISCOVERY = 14
    OSINT = 15
    HYPOTHESIS = 16
    ATTACK_MAP = 17
    REPORTING = 18


class FindingType(StrEnum):
    """Canonical finding types for normalized recon data."""
    SUBDOMAIN = "subdomain"
    DNS_RECORD = "dns_record"
    IP_ADDRESS = "ip_address"
    SERVICE = "service"
    URL = "url"
    PARAMETER = "parameter"
    TECHNOLOGY = "technology"
    TLS_INFO = "tls_info"
    JS_FINDING = "js_finding"
    SECRET_CANDIDATE = "secret_candidate"
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    API_ENDPOINT = "api_endpoint"
    HEADER_INFO = "header_info"
    OSINT_ENTRY = "osint_entry"
    CONTENT_ENTRY = "content_entry"


class ArtifactType(StrEnum):
    """Artifact classification."""
    RAW = "raw"
    NORMALIZED = "normalized"
    DERIVED = "derived"
    REPORT = "report"


class JobStatus(StrEnum):
    """Scan job lifecycle states."""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class EngagementStatus(StrEnum):
    """Engagement lifecycle states."""
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class HypothesisPriority(StrEnum):
    """Hypothesis priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class HypothesisStatus(StrEnum):
    """Hypothesis investigation states."""
    PENDING = "pending"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    DISMISSED = "dismissed"


class TargetType(StrEnum):
    """Target classification."""
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    URL = "url"


class Environment(StrEnum):
    """Target environment classification."""
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TESTING = "testing"
