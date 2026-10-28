"""Pydantic contracts for Dark Web Monitoring (DWM).

Modelled on the strict, LLM-facing style of
``src.orchestration.exploitation_queue`` (``ConfigDict(extra="forbid")``, a
``description`` on every field, strict scalar types) and the JSON-Schema export
idiom of ``src.cairn.contracts`` (module-level ``JSON_SCHEMA_* =
Model.model_json_schema()``).

The ``evidence_tier`` of every observation is HARD-CAPPED at
:data:`DWM_EVIDENCE_TIER_CAP` (2 = SUSPECTED). DWM is external OSINT and never
asserts CONFIRMED/EXPLOITED — enforced by a validator here and again in
``classifier.py``.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from typing import Any
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    field_validator,
    model_validator,
)

#: Hard ceiling for any DWM observation's evidence tier (SUSPECTED).
DWM_EVIDENCE_TIER_CAP: int = 2


class DwmEvidenceTier(IntEnum):
    """Subset of :class:`src.pipeline.contracts.finding_dto.EvidenceTier`.

    DWM may only ever emit INFORMATIONAL or SUSPECTED.
    """

    INFORMATIONAL = 1
    SUSPECTED = 2


class SelectorKind(StrEnum):
    DOMAIN = "domain"
    EMAIL = "email"
    FINDING = "finding"
    KEYWORD = "keyword"
    INFRA = "infra"


class SourceNetwork(StrEnum):
    TOR = "tor"
    I2P = "i2p"
    TELEGRAM = "telegram"
    FORUM = "forum"
    CLEARNET_INDEX = "clearnet_index"
    BREACH_DB = "breach_db"
    PASTE = "paste"
    FEED = "feed"
    REPO = "repo"


class ExposureType(StrEnum):
    CREDENTIAL = "credential"
    STEALER_LOG = "stealer_log"
    PII = "pii"
    SECRET_KEY = "secret_key"
    MENTION = "mention"
    ACCESS_SALE = "access_sale"
    DOCUMENT = "document"


class DarkWebSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DarkWebConfidence(StrEnum):
    """DWM confidence band. Deliberately excludes ``confirmed`` — DWM is never
    proof of exploitation."""

    LIKELY = "likely"
    POSSIBLE = "possible"
    ADVISORY = "advisory"


class DarkWebReportStatus(StrEnum):
    """Distinguish "did not run" from "ran and found nothing" (provability)."""

    DISABLED = "disabled"
    NOT_ENTITLED = "not_entitled"
    NOT_COLLECTED = "not_collected"
    RAN_EMPTY = "ran_empty"
    PRESENT = "present"


def selector_hash(value: str) -> str:
    """sha256 of a selector value (email/domain never stored plaintext indexed)."""

    return hashlib.sha256((value or "").strip().lower().encode("utf-8")).hexdigest()


class DarkWebSelector(BaseModel):
    """What to hunt for — a scope-validated monitoring query term."""

    model_config = ConfigDict(extra="forbid")

    id: StrictStr = Field(default_factory=lambda: uuid4().hex[:16])
    kind: SelectorKind = Field(description="Selector type: domain, email, finding, keyword, infra.")
    #: The literal term the collector queries. Sensitive for EMAIL — never persisted plaintext.
    value: StrictStr = Field(min_length=1, max_length=2048, description="Literal term to monitor.")
    value_hash: StrictStr = Field(
        default="", max_length=64, description="sha256(value); auto-filled."
    )
    finding_id: StrictStr = Field(
        default="", max_length=36, description="Source finding (T2) if any."
    )
    tags: list[StrictStr] = Field(default_factory=list, max_length=16, description="Grouping tags.")

    @model_validator(mode="after")
    def _fill_hash(self) -> DarkWebSelector:
        if not self.value_hash:
            object.__setattr__(self, "value_hash", selector_hash(self.value))
        return self


class DarkWebRawRecord(BaseModel):
    """A raw hit returned by a collector, before parse/classify/persist.

    ``content`` may contain sensitive text; it is persisted ONLY as an encrypted
    MinIO object (content-addressed by sha256), never in an indexable column and
    never in a report.
    """

    model_config = ConfigDict(extra="forbid")

    selector_id: StrictStr = Field(default="", max_length=36)
    source_network: SourceNetwork = Field(description="Where the hit was found.")
    source_ref: StrictStr = Field(
        default="", max_length=2048, description="URL / channel / breach name."
    )
    exposure_hint: ExposureType | None = Field(
        default=None, description="Collector's exposure guess."
    )
    content: StrictStr = Field(default="", description="Raw record text (sensitive; MinIO-only).")
    observed_at: datetime | None = Field(
        default=None, description="When the data appeared in the source."
    )
    collector: StrictStr = Field(
        default="", max_length=60, description="Collector name + catalog version."
    )
    extra: dict[str, Any] = Field(
        default_factory=dict, description="Collector-specific metadata (no secrets)."
    )


class DarkWebObservation(BaseModel):
    """A classified, report-safe DWM observation (mirrors the DB row)."""

    model_config = ConfigDict(extra="forbid")

    id: StrictStr = Field(default_factory=lambda: uuid4().hex[:16])
    selector_kind: SelectorKind = Field(description="Kind of selector that matched.")
    selector_value_hash: StrictStr = Field(
        default="", max_length=64, description="sha256 of selector value."
    )
    finding_id: StrictStr = Field(
        default="", max_length=36, description="Correlated finding (T2) if any."
    )
    source_network: SourceNetwork = Field(description="Network/marketplace the hit came from.")
    source_ref: StrictStr = Field(
        default="", max_length=2048, description="Reproducible source locator (no secret)."
    )
    exposure_type: ExposureType = Field(description="What kind of exposure this is.")
    severity: DarkWebSeverity = Field(
        default=DarkWebSeverity.INFO, description="Severity per classifier_rules."
    )
    confidence: DarkWebConfidence = Field(
        default=DarkWebConfidence.ADVISORY, description="Confidence band — never 'confirmed'."
    )
    evidence_tier: int = Field(
        default=1,
        description="1=INFORMATIONAL, 2=SUSPECTED. Hard-capped at 2 (clamped, never rejected).",
    )
    observed_at: datetime | None = Field(
        default=None, description="When data appeared in the source."
    )
    collected_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    raw_object_key: StrictStr = Field(
        default="", max_length=512, description="MinIO (argus-darkweb) key."
    )
    raw_sha256: StrictStr = Field(
        default="", max_length=64, description="sha256 of the raw record."
    )
    chain_hash: StrictStr = Field(default="", max_length=64, description="Audit hash-chain link.")
    redacted_summary: StrictStr = Field(
        default="", max_length=4096, description="Masked, report-safe summary."
    )
    collector: StrictStr = Field(
        default="", max_length=60, description="Collector name + catalog version."
    )
    provenance: dict[str, Any] = Field(
        default_factory=dict, description="Structured provenance (no secrets)."
    )

    @field_validator("evidence_tier", mode="before")
    @classmethod
    def _cap_tier(cls, v: Any) -> int:
        # Defence-in-depth: clamp into {1,2} no matter what a caller passes.
        try:
            iv = int(v)
        except (TypeError, ValueError):
            return 1
        if iv < 1:
            return 1
        if iv > DWM_EVIDENCE_TIER_CAP:
            return DWM_EVIDENCE_TIER_CAP
        return iv


class DarkWebReport(BaseModel):
    """Aggregated DWM result handed to the report tier projection."""

    model_config = ConfigDict(extra="forbid")

    scan_id: StrictStr = Field(default="", max_length=36, description="Correlation id.")
    target: StrictStr = Field(
        default="", max_length=2048, description="Monitored authorized target."
    )
    status: DarkWebReportStatus = Field(
        default=DarkWebReportStatus.NOT_COLLECTED,
        description="disabled|not_entitled|not_collected|ran_empty|present.",
    )
    selectors_count: int = Field(default=0, ge=0, description="Number of active selectors.")
    observations: list[DarkWebObservation] = Field(
        default_factory=list, max_length=4096, description="Discovered observations."
    )
    generated_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))

    # -- aggregates (exec-level, safe for Asgard) --------------------------------

    def counts_by_exposure(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for o in self.observations:
            out[o.exposure_type.value] = out.get(o.exposure_type.value, 0) + 1
        return out

    def counts_by_severity(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for o in self.observations:
            out[o.severity.value] = out.get(o.severity.value, 0) + 1
        return out

    def counts_by_source(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for o in self.observations:
            out[o.source_network.value] = out.get(o.source_network.value, 0) + 1
        return out

    def resolve_status(self) -> DarkWebReportStatus:
        """Promote NOT_COLLECTED→RAN_EMPTY/PRESENT once a sweep has run."""

        if self.status in (DarkWebReportStatus.DISABLED, DarkWebReportStatus.NOT_ENTITLED):
            return self.status
        if self.observations:
            return DarkWebReportStatus.PRESENT
        if self.status == DarkWebReportStatus.NOT_COLLECTED:
            return DarkWebReportStatus.NOT_COLLECTED
        return DarkWebReportStatus.RAN_EMPTY

    def to_summary_dict(self) -> dict[str, Any]:
        """Serialise for ``ReportData.dark_web_monitoring`` (full detail)."""

        status = self.resolve_status()
        return {
            "status": status.value,
            "target": self.target,
            "scan_id": self.scan_id,
            "selectors_count": self.selectors_count,
            "observation_count": len(self.observations),
            "counts_by_exposure": self.counts_by_exposure(),
            "counts_by_severity": self.counts_by_severity(),
            "counts_by_source": self.counts_by_source(),
            "generated_at": self.generated_at.isoformat(),
            "observations": [o.model_dump(mode="json") for o in self.observations],
        }


# -- JSON Schema exports (for call_llm_unified(..., response_schema=...)) --------
JSON_SCHEMA_DARK_WEB_SELECTOR: dict[str, Any] = DarkWebSelector.model_json_schema()
JSON_SCHEMA_DARK_WEB_OBSERVATION: dict[str, Any] = DarkWebObservation.model_json_schema()
JSON_SCHEMA_DARK_WEB_REPORT: dict[str, Any] = DarkWebReport.model_json_schema()


__all__ = [
    "DWM_EVIDENCE_TIER_CAP",
    "DarkWebConfidence",
    "DarkWebObservation",
    "DarkWebRawRecord",
    "DarkWebReport",
    "DarkWebReportStatus",
    "DarkWebSelector",
    "DarkWebSeverity",
    "DwmEvidenceTier",
    "ExposureType",
    "JSON_SCHEMA_DARK_WEB_OBSERVATION",
    "JSON_SCHEMA_DARK_WEB_REPORT",
    "JSON_SCHEMA_DARK_WEB_SELECTOR",
    "SelectorKind",
    "SourceNetwork",
    "selector_hash",
]
