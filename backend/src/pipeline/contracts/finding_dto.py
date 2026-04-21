"""DTOs for Finding / Evidence flowing between phases.

These are intentionally separate from the SQLAlchemy ORM models in
``src.db.models`` (which add storage concerns: id types, timestamps, RLS).
The DTOs mirror the domain model defined in Backlog/dev1_md §10 exactly,
and live in ``pipeline.contracts`` so the orchestrator and sandbox can
exchange findings without importing the persistence layer.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timezone
from enum import StrEnum
from typing import Self
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    model_validator,
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_S3_KEY_RE = re.compile(r"^[A-Za-z0-9!_.\-*'()/]{1,1024}$")
_CVSS_VECTOR_RE = re.compile(r"^CVSS:[34]\.[0-9]/[A-Z:/0-9]+$")


class FindingCategory(StrEnum):
    """Top-level vulnerability category (Backlog/dev1_md §10)."""

    SQLI = "sqli"
    XSS = "xss"
    RCE = "rce"
    LFI = "lfi"
    SSRF = "ssrf"
    SSTI = "ssti"
    XXE = "xxe"
    NOSQLI = "nosqli"
    LDAPI = "ldapi"
    CMDI = "cmdi"
    OPEN_REDIRECT = "open_redirect"
    CSRF = "csrf"
    CORS = "cors"
    AUTH = "auth"
    IDOR = "idor"
    JWT = "jwt"
    MISCONFIG = "misconfig"
    INFO = "info"
    SUPPLY_CHAIN = "supply_chain"
    CRYPTO = "crypto"
    SECRET_LEAK = "secret_leak"
    DOS = "dos"
    OTHER = "other"


class ConfidenceLevel(StrEnum):
    """Confidence in a finding (Backlog/dev1_md §10)."""

    SUSPECTED = "suspected"
    LIKELY = "likely"
    CONFIRMED = "confirmed"
    EXPLOITABLE = "exploitable"


class FindingStatus(StrEnum):
    """Lifecycle status of a finding (Backlog/dev1_md §10)."""

    NEW = "new"
    VALIDATED = "validated"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"


class EvidenceKind(StrEnum):
    """Type of evidence attached to a finding (Backlog/dev1_md §10)."""

    RAW_OUTPUT = "raw_output"
    PARSED = "parsed"
    SCREENSHOT = "screenshot"
    PCAP = "pcap"
    OAST_CALLBACK = "oast_callback"
    VIDEO = "video"
    HAR = "har"
    DIFF = "diff"


class SSVCDecision(StrEnum):
    """CISA SSVC stakeholder-specific decision (Backlog/dev1_md §10)."""

    TRACK = "Track"
    TRACK_STAR = "Track*"
    ATTEND = "Attend"
    ACT = "Act"


class RemediationDTO(BaseModel):
    """Remediation hint attached to a finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    summary: StrictStr = Field(min_length=1, max_length=2000)
    references: list[StrictStr] = Field(default_factory=list, max_length=32)
    code_fix_hint: StrictStr | None = Field(default=None, max_length=4000)
    config_fix_hint: StrictStr | None = Field(default=None, max_length=4000)


class ReproducerSpecDTO(BaseModel):
    """Reproducer recipe for a finding (safe, non-destructive)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    method: StrictStr = Field(min_length=1, max_length=16)
    target: StrictStr = Field(min_length=1, max_length=2048)
    request_template: StrictStr = Field(min_length=1, max_length=8000)
    expected_signal: StrictStr = Field(min_length=1, max_length=2000)
    canary_token: StrictStr | None = Field(default=None, min_length=8, max_length=128)


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class EvidenceDTO(BaseModel):
    """Evidence record (Backlog/dev1_md §10)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    finding_id: UUID
    tool_run_id: UUID
    kind: EvidenceKind
    s3_key: StrictStr = Field(min_length=1, max_length=1024)
    sha256: StrictStr = Field(min_length=64, max_length=64)
    redactions_applied: StrictInt = Field(ge=0, le=10_000, default=0)
    created_at: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if not _SHA256_RE.fullmatch(self.sha256):
            raise ValueError("sha256 must be lowercase 64-char hex")
        if not _S3_KEY_RE.fullmatch(self.s3_key):
            raise ValueError("s3_key contains illegal characters")
        return self


class FindingDTO(BaseModel):
    """Finding record (Backlog/dev1_md §10)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    tenant_id: UUID
    scan_id: UUID
    asset_id: UUID
    tool_run_id: UUID
    category: FindingCategory
    cwe: list[StrictInt] = Field(min_length=1, max_length=16)
    cvss_v3_vector: StrictStr = Field(min_length=8, max_length=128)
    cvss_v3_score: StrictFloat = Field(ge=0.0, le=10.0)
    # ARG-044 — intel-tier enrichment. All five fields are optional /
    # default to a "no signal" value so the DTO stays backward-compatible
    # with Cycle 1-3 producers that only populate the CVSS axis.
    epss_score: StrictFloat | None = Field(default=None, ge=0.0, le=1.0)
    epss_percentile: StrictFloat | None = Field(default=None, ge=0.0, le=1.0)
    kev_listed: StrictBool = False
    kev_added_date: date | None = None
    ssvc_decision: SSVCDecision = SSVCDecision.TRACK
    owasp_wstg: list[StrictStr] = Field(default_factory=list, max_length=32)
    mitre_attack: list[StrictStr] = Field(default_factory=list, max_length=32)
    confidence: ConfidenceLevel
    status: FindingStatus
    evidence_ids: list[UUID] = Field(default_factory=list, max_length=64)
    reproducer: ReproducerSpecDTO | None = None
    remediation: RemediationDTO | None = None
    first_seen: datetime = Field(default_factory=_utcnow)
    last_seen: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _validate(self) -> Self:
        for cwe_id in self.cwe:
            if cwe_id <= 0:
                raise ValueError(f"CWE id must be positive, got {cwe_id}")
        if not _CVSS_VECTOR_RE.fullmatch(self.cvss_v3_vector):
            raise ValueError(
                "cvss_v3_vector must look like 'CVSS:3.x/AV:.../...' or 'CVSS:4.0/...'"
            )
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not precede first_seen")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("evidence_ids must not contain duplicates")
        return self
