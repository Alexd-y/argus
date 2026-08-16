"""Quick tool-output normalization → Finding / Occurrence / Evidence DTOs.

Raw artifacts go to MinIO when the phase is in ``RAW_ARTIFACT_PHASES``.
Normalized findings carry asset, endpoint, parameter, protocol, and
template/tool identity. Secrets are stripped before any LLM-facing JSON.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping, Sequence
from typing import Any, Final
from urllib.parse import urlparse
from uuid import UUID, uuid5

from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictStr

from src.findings.fingerprint import (
    compute_evidence_signal_hash,
    compute_finding_key,
    compute_occurrence_key,
    normalize_protocol,
    template_detector_id,
)
from src.quick.provenance import (
    FINGERPRINT_VERSION,
    QuickProvenance,
    build_provenance,
    compute_evidence_hash,
    evidence_json_for_llm,
    mint_evidence_id,
    redact_mapping_for_llm,
)
from src.quick.schemas import FindingTriageVerdict
from src.recon.raw_artifact_sink import sink_raw_json
from src.storage.s3 import RAW_ARTIFACT_PHASES

logger = logging.getLogger(__name__)

_FINDING_NS: Final[UUID] = UUID("6e2c1a90-4b7d-4e11-9c08-2f7a1d4b9e20")
_MAX_TITLE: Final[int] = 500
_MAX_ENDPOINT: Final[int] = 2048
_MATCHER_STYLE_TOKENS: Final[frozenset[str]] = frozenset(
    {
        "status",
        "size",
        "word",
        "regex",
        "binary",
        "dsl",
        "xpath",
        "digest",
    }
)
_SEVERITY_RANK: Final[dict[str, int]] = {
    "info": 0,
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


class QuickNormalizeContext(BaseModel):
    """Identity for one tool run being normalized."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: StrictStr = Field(min_length=1, max_length=36)
    scan_id: StrictStr = Field(min_length=1, max_length=36)
    engagement_id: StrictStr = Field(min_length=1, max_length=36)
    asset_id: StrictStr = Field(min_length=1, max_length=36)
    asset: StrictStr = Field(min_length=1, max_length=512)
    tool_id: StrictStr = Field(min_length=1, max_length=128)
    tool_version: StrictStr = Field(default="unknown", max_length=64)
    capability_id: StrictStr = Field(min_length=1, max_length=256)
    phase: StrictStr = Field(default="vuln_analysis", max_length=64)
    task_id: StrictStr | None = Field(default=None, max_length=36)
    policy_decision_id: StrictStr | None = Field(default=None, max_length=36)
    lease_id: StrictStr | None = Field(default=None, max_length=36)
    template_id: StrictStr | None = Field(default=None, max_length=256)
    template_digest: StrictStr | None = Field(default=None, max_length=64)
    protocol: StrictStr | None = Field(default=None, max_length=32)


class QuickEvidenceDTO(BaseModel):
    """One evidence record. ``payload`` is already redacted for LLM use."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: StrictStr = Field(min_length=1, max_length=36)
    evidence_hash: StrictStr = Field(min_length=64, max_length=64)
    tool_id: StrictStr
    tool_version: StrictStr
    template_id: StrictStr | None = None
    artifact_key: StrictStr | None = None
    payload: dict[str, Any] = Field(default_factory=dict)


class QuickOccurrenceDTO(BaseModel):
    """Scanner occurrence bound to a logical finding fingerprint."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    occurrence_key: StrictStr = Field(min_length=64, max_length=64)
    finding_key: StrictStr = Field(min_length=64, max_length=64)
    scanner: StrictStr
    detector_id: StrictStr
    detector_version: StrictStr
    evidence_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)
    protocol: StrictStr
    parameter: StrictStr
    endpoint: StrictStr
    late_oast: bool = False
    request_signature: StrictStr = ""


class QuickFindingDTO(BaseModel):
    """Normalized Quick finding. AI is not the sole writer of verdict."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_id: StrictStr = Field(min_length=1, max_length=36)
    finding_key: StrictStr = Field(min_length=64, max_length=64)
    fingerprint_version: StrictStr = FINGERPRINT_VERSION
    tenant_id: StrictStr
    scan_id: StrictStr
    engagement_id: StrictStr
    asset_id: StrictStr
    asset: StrictStr
    endpoint: StrictStr
    parameter: StrictStr
    protocol: StrictStr
    category: StrictStr
    severity: StrictStr
    title: StrictStr
    confidence: StrictFloat = Field(ge=0.0, le=1.0)
    verdict: FindingTriageVerdict
    hypothesis: dict[str, Any] | None = None
    evidence_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)
    occurrence_keys: tuple[StrictStr, ...] = Field(default_factory=tuple)
    coverage_capability_id: StrictStr
    task_id: StrictStr | None = None
    policy_decision_id: StrictStr | None = None
    lease_id: StrictStr | None = None
    template_id: StrictStr | None = None
    tool_id: StrictStr
    dedup_status: StrictStr = "unique"
    provenance: QuickProvenance
    contradicting_evidence_ids: tuple[StrictStr, ...] = Field(default_factory=tuple)


class QuickNormalizationResult(BaseModel):
    """One logical finding plus its occurrence and evidence from a tool run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    finding: QuickFindingDTO
    occurrence: QuickOccurrenceDTO
    evidence: QuickEvidenceDTO


def _first_str(payload: Mapping[str, Any], keys: Sequence[str]) -> str:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _severity_of(payload: Mapping[str, Any]) -> str:
    raw = _first_str(payload, ("severity", "risk", "level")).lower()
    if raw in _SEVERITY_RANK:
        return "info" if raw == "informational" else raw
    return "medium"


def _category_of(payload: Mapping[str, Any], *, tool_id: str) -> str:
    raw = _first_str(
        payload,
        ("category", "vuln_type", "type", "kind"),
    ).lower()
    if raw:
        return raw[:128]
    tags = payload.get("tags")
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, str) and tag.strip():
                return tag.strip().lower()[:128]
    return tool_id.strip().lower()[:128] or "unknown"


def _endpoint_of(payload: Mapping[str, Any], *, asset: str) -> str:
    endpoint = _first_str(
        payload,
        ("matched_at", "matched-at", "endpoint", "url", "affected_url", "location", "host"),
    )
    return (endpoint or asset)[:_MAX_ENDPOINT]


def _parameter_of(payload: Mapping[str, Any], endpoint: str) -> str:
    explicit = _first_str(
        payload,
        ("parameter", "param", "extracted-results", "extracted_results"),
    )
    if explicit:
        return explicit[:256]
    component = _first_str(payload, ("component",))
    if component and component.lower() not in _MATCHER_STYLE_TOKENS:
        return component[:256]
    try:
        parsed = urlparse(endpoint)
    except ValueError:
        return ""
    if not parsed.query:
        return ""
    first = parsed.query.split("&", 1)[0]
    return first.split("=", 1)[0][:256]


def _protocol_of(ctx: QuickNormalizeContext, endpoint: str) -> str:
    return normalize_protocol(ctx.protocol, location=endpoint or ctx.asset)


def _template_of(payload: Mapping[str, Any], ctx: QuickNormalizeContext) -> str | None:
    raw = _first_str(payload, ("template_id", "template-id", "detector_id"))
    if raw:
        return raw[:256]
    if ctx.template_id:
        return ctx.template_id[:256]
    return None


def _confidence_of(payload: Mapping[str, Any], severity: str) -> float:
    raw = payload.get("confidence")
    if isinstance(raw, int | float) and 0.0 <= float(raw) <= 1.0:
        return float(raw)
    if isinstance(raw, str):
        token = raw.strip().lower()
        mapping = {
            "confirmed": 0.95,
            "likely": 0.75,
            "suspected": 0.45,
            "possible": 0.35,
            "advisory": 0.2,
        }
        if token in mapping:
            return mapping[token]
    rank = _SEVERITY_RANK.get(severity, 2)
    return {0: 0.2, 1: 0.35, 2: 0.5, 3: 0.7, 4: 0.85}.get(rank, 0.5)


def _iter_payloads(raw: Mapping[str, Any] | Sequence[Any] | str | bytes) -> list[dict[str, Any]]:
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace")
        return _iter_payloads(text)
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return []
        if stripped.startswith(("{", "[")):
            try:
                return _iter_payloads(json.loads(stripped))
            except json.JSONDecodeError:
                pass
        rows: list[dict[str, Any]] = []
        for line in stripped.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(item, dict):
                rows.append(item)
        return rows
    if isinstance(raw, Mapping):
        for key in ("findings", "results", "matches", "vulnerabilities"):
            nested = raw.get(key)
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]
        return [dict(raw)]
    if isinstance(raw, Sequence):
        return [item for item in raw if isinstance(item, dict)]
    return []


def _store_raw_artifact(
    *,
    ctx: QuickNormalizeContext,
    payload: Mapping[str, Any],
) -> str | None:
    phase = ctx.phase.strip()
    if phase not in RAW_ARTIFACT_PHASES:
        return None
    try:
        return sink_raw_json(
            tenant_id=ctx.tenant_id,
            scan_id=ctx.scan_id,
            phase=phase,
            artifact_type="quick_tool_raw",
            payload=redact_mapping_for_llm(dict(payload)),
        )
    except (OSError, ValueError, TypeError):
        logger.warning(
            "quick_raw_artifact_store_failed",
            extra={
                "event": "quick_raw_artifact_store_failed",
                "scan_id": ctx.scan_id,
                "phase": phase,
                "tool_id": ctx.tool_id,
            },
        )
        return None


def _deterministic_verdict(*, severity: str, confidence: float, has_evidence: bool) -> FindingTriageVerdict:
    if not has_evidence:
        return FindingTriageVerdict.HYPOTHESIS
    if severity in {"info", "informational"} and confidence < 0.5:
        return FindingTriageVerdict.FALSE_POSITIVE_CANDIDATE
    if confidence >= 0.9 and severity in {"critical", "high"}:
        return FindingTriageVerdict.CONFIRMED
    if confidence >= 0.65:
        return FindingTriageVerdict.LIKELY
    if confidence >= 0.35:
        return FindingTriageVerdict.NEEDS_VERIFICATION
    return FindingTriageVerdict.HYPOTHESIS


def normalize_match(
    payload: Mapping[str, Any],
    *,
    ctx: QuickNormalizeContext,
) -> QuickNormalizationResult:
    """Normalize one tool match into finding + occurrence + evidence."""
    endpoint = _endpoint_of(payload, asset=ctx.asset)
    parameter = _parameter_of(payload, endpoint)
    protocol = _protocol_of(ctx, endpoint)
    category = _category_of(payload, tool_id=ctx.tool_id)
    severity = _severity_of(payload)
    template_id = _template_of(payload, ctx)
    title = (_first_str(payload, ("title", "name", "summary")) or template_id or ctx.tool_id)[
        :_MAX_TITLE
    ]
    detector_id = template_detector_id(template_id, tool_id=ctx.tool_id)
    location = endpoint or ctx.asset

    finding_key = compute_finding_key(
        tenant_id=ctx.tenant_id,
        engagement_id=ctx.engagement_id,
        asset=ctx.asset,
        category=category,
        normalized_location=location,
        parameter_or_component=parameter,
        root_cause_family=category,
    )
    finding_id = str(uuid5(_FINDING_NS, finding_key))

    llm_payload = evidence_json_for_llm(
        {
            "tool_id": ctx.tool_id,
            "template_id": template_id,
            "host": payload.get("host"),
            "matched_at": endpoint,
            "severity": severity,
            "category": category,
            "matcher_name": payload.get("matcher_name") or payload.get("matcher-name"),
            "name": title,
        }
    )
    evidence_hash = compute_evidence_hash(llm_payload)
    evidence_id = mint_evidence_id(
        scan_id=ctx.scan_id,
        task_id=ctx.task_id,
        evidence_hash=evidence_hash,
    )
    artifact_key = _store_raw_artifact(ctx=ctx, payload=payload)
    request_signature = (endpoint or finding_key)[:2048]
    signal_hash = compute_evidence_signal_hash(llm_payload)
    occurrence_key = compute_occurrence_key(
        finding_key=finding_key,
        scanner=ctx.tool_id,
        detector_id=detector_id,
        detector_version=ctx.tool_version or "unknown",
        request_signature=request_signature,
        evidence_signal_hash=signal_hash,
    )
    confidence = _confidence_of(payload, severity)
    verdict = _deterministic_verdict(
        severity=severity,
        confidence=confidence,
        has_evidence=True,
    )
    provenance = build_provenance(
        evidence_hash=evidence_hash,
        tool_id=ctx.tool_id,
        tool_version=ctx.tool_version or "unknown",
        scan_id=ctx.scan_id,
        template_id=template_id,
        template_digest=ctx.template_digest,
        policy_decision_id=ctx.policy_decision_id,
        lease_id=ctx.lease_id,
        task_id=ctx.task_id,
        artifact_key=artifact_key,
    )
    evidence = QuickEvidenceDTO(
        evidence_id=evidence_id,
        evidence_hash=evidence_hash,
        tool_id=ctx.tool_id,
        tool_version=ctx.tool_version or "unknown",
        template_id=template_id,
        artifact_key=artifact_key,
        payload=llm_payload,
    )
    occurrence = QuickOccurrenceDTO(
        occurrence_key=occurrence_key,
        finding_key=finding_key,
        scanner=ctx.tool_id,
        detector_id=detector_id,
        detector_version=ctx.tool_version or "unknown",
        evidence_ids=(evidence_id,),
        protocol=protocol,
        parameter=parameter or "unknown-component",
        endpoint=endpoint,
        request_signature=request_signature,
    )
    finding = QuickFindingDTO(
        finding_id=finding_id,
        finding_key=finding_key,
        tenant_id=ctx.tenant_id,
        scan_id=ctx.scan_id,
        engagement_id=ctx.engagement_id,
        asset_id=ctx.asset_id,
        asset=ctx.asset,
        endpoint=endpoint,
        parameter=parameter or "unknown-component",
        protocol=protocol,
        category=category,
        severity=severity,
        title=title,
        confidence=confidence,
        verdict=verdict,
        hypothesis=None,
        evidence_ids=(evidence_id,),
        occurrence_keys=(occurrence_key,),
        coverage_capability_id=ctx.capability_id,
        task_id=ctx.task_id,
        policy_decision_id=ctx.policy_decision_id,
        lease_id=ctx.lease_id,
        template_id=template_id,
        tool_id=ctx.tool_id,
        provenance=provenance,
    )
    return QuickNormalizationResult(
        finding=finding,
        occurrence=occurrence,
        evidence=evidence,
    )


def normalize_tool_output(
    raw: Mapping[str, Any] | Sequence[Any] | str | bytes,
    *,
    ctx: QuickNormalizeContext,
) -> tuple[QuickNormalizationResult, ...]:
    """Normalize a tool stdout/JSONL/dict payload into Quick DTOs."""
    results = [normalize_match(item, ctx=ctx) for item in _iter_payloads(raw)]
    results.sort(key=lambda item: (item.finding.finding_key, item.occurrence.occurrence_key))
    return tuple(results)
