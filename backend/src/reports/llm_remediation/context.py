"""Per-finding LLM context package construction with secret redaction (§6, SI-3).

The LLM receives only a *minimal sufficient* structured package: resolvable
reference IDs and redacted evidence fragments, never raw secrets or unfiltered
logs. The full originals stay in secure storage, addressable by ID.

A stable ``source_context_hash`` over the redacted package feeds the cache key
and ties an accepted analysis to the exact inputs it was produced from
(idempotency + reuse, prompt §9 / L23).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from src.reports.ai_text_generation import canonical_payload_hash
from src.reports.llm_remediation.closure_status import ClosureComputationResult

# Bump when the redaction rules change so caches invalidate (prompt §9).
REDACTION_VERSION = "redact-v1"

# Conservative secret patterns. Each replaces the sensitive value with a typed
# marker so the model still sees *that* a secret exists without its value.
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "«redacted:jwt»"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}"), "«redacted:bearer»"),
    (
        re.compile(r"(?i)\b(authorization|cookie|set-cookie)\b\s*[:=]\s*[^\r\n]+"),
        r"\1: «redacted:header»",
    ),
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token|otp|totp)\b"
            r"\s*[:=]\s*[\"']?[^\s\"',;]+"
        ),
        r"\1=«redacted:secret»",
    ),
    # Long high-entropy blobs (base64/hex) that are almost certainly keys.
    (re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b"), "«redacted:blob»"),
    (re.compile(r"\b[0-9a-fA-F]{40,}\b"), "«redacted:hex»"),
)


def redact_text(value: str) -> str:
    """Mask secret-like substrings in a free-text evidence fragment (SI-3)."""

    redacted = value
    for pattern, replacement in _SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _redact_obj(obj: Any) -> Any:
    """Recursively redact strings inside a JSON-like structure."""

    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: _redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_redact_obj(v) for v in obj]
    return obj


@dataclass(frozen=True)
class FindingContext:
    """A validated, redacted context package for one finding."""

    finding_id: str
    payload: dict[str, Any]
    context_hash: str

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def _coerce_str_list(value: Any, *, limit: int = 64) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value][:limit]
    return [str(value)]


def build_finding_context(
    finding: dict[str, Any],
    *,
    report_meta: dict[str, Any],
    permitted: ClosureComputationResult,
    allowed_evidence_ids: list[str] | None = None,
    evidence_fragments: dict[str, str] | None = None,
    locale: str = "ru",
) -> FindingContext:
    """Assemble the §6 context package for a single finding.

    ``finding`` is the report-normalised finding mapping. ``evidence_fragments``
    maps an evidence ID to a raw fragment; only IDs present in
    ``allowed_evidence_ids`` are included and every fragment is redacted.
    """

    finding_id = str(finding.get("finding_id") or finding.get("id") or "")
    allowed = set(allowed_evidence_ids or [])
    fragments = evidence_fragments or {}

    redacted_fragments: dict[str, str] = {
        eid: redact_text(str(text))
        for eid, text in fragments.items()
        if not allowed or eid in allowed
    }

    payload: dict[str, Any] = {
        "identity": {
            "report_id": report_meta.get("report_id"),
            "report_version": report_meta.get("report_version"),
            "scan_id": report_meta.get("scan_id"),
            "tenant_id": report_meta.get("tenant_id"),
            "finding_id": finding_id,
            "schema_version": report_meta.get("schema_version"),
            "rules_version": report_meta.get("rules_version"),
            "locale": locale,
            "data_cut": report_meta.get("data_cut"),
        },
        "classification": {
            "type": finding.get("type") or finding.get("category"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "cwe": finding.get("cwe"),
            "cvss": finding.get("cvss") or finding.get("cvss_v3_vector"),
            "verification_status": finding.get("validation_status")
            or finding.get("verification_status"),
            "confidence": finding.get("confidence"),
            "confidence_rationale": finding.get("confidence_rationale"),
            "limitations": finding.get("limitations"),
        },
        "asset": {
            "asset": finding.get("asset") or finding.get("target"),
            "environment": finding.get("environment"),
            "endpoint": finding.get("affected_endpoint") or finding.get("endpoint"),
            "port": finding.get("port"),
            "role": finding.get("role"),
            "components": _coerce_str_list(finding.get("components")),
            "confirmed_versions": _coerce_str_list(finding.get("confirmed_versions")),
        },
        "finding": {
            "description": redact_text(str(finding.get("description") or "")),
            "expected_security_property": finding.get("expected_security_property"),
            "root_cause_established": finding.get("root_cause")
            if finding.get("root_cause")
            else "unknown",
            "demonstrated": finding.get("demonstrated"),
            "hypothesis": finding.get("hypothesis"),
            "existing_recommendations": _redact_obj(finding.get("existing_recommendations") or []),
            "known_limitations": _coerce_str_list(finding.get("known_limitations")),
        },
        "evidence": {
            "allowed_evidence_ids": sorted(allowed),
            "fragments": redacted_fragments,
        },
        "references": {
            "approved_reference_ids": _coerce_str_list(finding.get("approved_reference_ids")),
        },
        "prior_state": {
            "prior_plan_present": bool(finding.get("prior_plan")),
            "changes_applied": _redact_obj(finding.get("changes_applied") or []),
        },
        "retest": {
            "permitted_closure_status": permitted.permitted_status.value,
            "satisfied_criteria_ids": permitted.satisfied_criteria_ids,
            "unsatisfied_criteria_ids": permitted.unsatisfied_criteria_ids,
            "untested_criteria_ids": permitted.untested_criteria_ids,
            "supporting_retest_ids": permitted.supporting_retest_ids,
            "supporting_evidence_ids": permitted.supporting_evidence_ids,
        },
        "constraints": {
            "reviewer_constraints": finding.get("reviewer_constraints"),
            "redaction_version": REDACTION_VERSION,
        },
    }

    context_hash = canonical_payload_hash(payload)
    return FindingContext(finding_id=finding_id, payload=payload, context_hash=context_hash)


__all__ = [
    "REDACTION_VERSION",
    "FindingContext",
    "build_finding_context",
    "redact_text",
]
