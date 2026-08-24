"""Structured observability events (R13) — profile/lease/tool/parser/payload/llm/report.

These are *log-based* structured events (JSON-friendly ``extra`` dicts), not new
Prometheus families — ``src.core.observability`` enforces a strict metric-family
cap, so per-decision events live here instead.

Every event carries the canonical correlation fields (tenant_id, scan_id,
engagement_id, correlation_id, scan_profile, phase, reason_code,
registry_versions) and is passed through :func:`redact` so credentials, cookies,
authorization headers, tokens, secrets and LAB lease signing material never
reach the logs (R13 "не логировать секреты").
"""

from __future__ import annotations

import logging
from typing import Any, Final

logger = logging.getLogger("argus.events")

# --- event name constants (R13 catalogue) ----------------------------------

EVENT_SCAN_PROFILE_RESOLVED: Final[str] = "scan_profile_resolved"
EVENT_SCAN_PROFILE_CONFLICT: Final[str] = "scan_profile_conflict"
EVENT_LAB_LEASE_PREFLIGHT_ALLOWED: Final[str] = "lab_lease_preflight_allowed"
EVENT_LAB_LEASE_PREFLIGHT_DENIED: Final[str] = "lab_lease_preflight_denied"
EVENT_PROFILE_CAPABILITY_ALLOWED: Final[str] = "profile_capability_allowed"
EVENT_PROFILE_CAPABILITY_DENIED: Final[str] = "profile_capability_denied"
EVENT_TOOL_SELECTED: Final[str] = "tool_selected"
EVENT_TOOL_SKIPPED: Final[str] = "tool_skipped"
EVENT_TOOL_UNAVAILABLE: Final[str] = "tool_unavailable"
EVENT_PARSER_SUCCESS: Final[str] = "parser_success"
EVENT_PARSER_UNAVAILABLE: Final[str] = "parser_unavailable"
EVENT_PARSER_FAILED: Final[str] = "parser_failed"
EVENT_PAYLOAD_FAMILY_SELECTED: Final[str] = "payload_family_selected"
EVENT_PAYLOAD_FAMILY_DENIED: Final[str] = "payload_family_denied"
EVENT_LLM_PLAN_APPROVED: Final[str] = "llm_plan_approved"
EVENT_LLM_PLAN_REJECTED: Final[str] = "llm_plan_rejected"
EVENT_LLM_PLAN_ABSTAINED: Final[str] = "llm_plan_abstained"
EVENT_EVIDENCE_CONTRACT_SATISFIED: Final[str] = "evidence_contract_satisfied"
EVENT_EVIDENCE_CONTRACT_FAILED: Final[str] = "evidence_contract_failed"
EVENT_REPORT_SNAPSHOT_CREATED: Final[str] = "report_snapshot_created"
EVENT_REPORT_FORMAT_RENDERED: Final[str] = "report_format_rendered"
EVENT_REPORT_FORMAT_FAILED: Final[str] = "report_format_failed"

ALL_EVENTS: Final[frozenset[str]] = frozenset(
    {
        EVENT_SCAN_PROFILE_RESOLVED,
        EVENT_SCAN_PROFILE_CONFLICT,
        EVENT_LAB_LEASE_PREFLIGHT_ALLOWED,
        EVENT_LAB_LEASE_PREFLIGHT_DENIED,
        EVENT_PROFILE_CAPABILITY_ALLOWED,
        EVENT_PROFILE_CAPABILITY_DENIED,
        EVENT_TOOL_SELECTED,
        EVENT_TOOL_SKIPPED,
        EVENT_TOOL_UNAVAILABLE,
        EVENT_PARSER_SUCCESS,
        EVENT_PARSER_UNAVAILABLE,
        EVENT_PARSER_FAILED,
        EVENT_PAYLOAD_FAMILY_SELECTED,
        EVENT_PAYLOAD_FAMILY_DENIED,
        EVENT_LLM_PLAN_APPROVED,
        EVENT_LLM_PLAN_REJECTED,
        EVENT_LLM_PLAN_ABSTAINED,
        EVENT_EVIDENCE_CONTRACT_SATISFIED,
        EVENT_EVIDENCE_CONTRACT_FAILED,
        EVENT_REPORT_SNAPSHOT_CREATED,
        EVENT_REPORT_FORMAT_RENDERED,
        EVENT_REPORT_FORMAT_FAILED,
    }
)

REDACTED: Final[str] = "[REDACTED]"

# Substrings that mark a field as sensitive (case-insensitive).
_SENSITIVE_KEY_SUBSTRINGS: Final[tuple[str, ...]] = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "cookie",
    "set-cookie",
    "api_key",
    "apikey",
    "x-api-key",
    "private_key",
    "privatekey",
    "credential",
    "boundary_proof",
    "signature",
    "lease_signature",
    "signing_key",
    "session",
    "bearer",
)

_MAX_DEPTH: Final[int] = 6


def _is_sensitive_key(key: str) -> bool:
    k = key.lower()
    return any(sub in k for sub in _SENSITIVE_KEY_SUBSTRINGS)


def redact(value: Any, *, _depth: int = 0) -> Any:
    """Recursively redact sensitive keys from a value (dict/list/scalar)."""
    if _depth > _MAX_DEPTH:
        return REDACTED
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            key = str(k)
            if _is_sensitive_key(key):
                out[key] = REDACTED
            else:
                out[key] = redact(v, _depth=_depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(item, _depth=_depth + 1) for item in value]
    return value


def emit_event(
    event: str,
    *,
    tenant_id: str | None = None,
    scan_id: str | None = None,
    engagement_id: str | None = None,
    correlation_id: str | None = None,
    scan_profile: str | None = None,
    phase: str | None = None,
    reason_code: str | None = None,
    registry_versions: dict[str, Any] | None = None,
    level: int = logging.INFO,
    **extra: Any,
) -> dict[str, Any]:
    """Emit a redacted structured event and return the payload (for testing).

    Canonical correlation fields are first-class; anything in ``extra`` is
    redacted before being logged.
    """
    payload: dict[str, Any] = {"event": event}
    if tenant_id is not None:
        payload["tenant_id"] = tenant_id
    if scan_id is not None:
        payload["scan_id"] = scan_id
    if engagement_id is not None:
        payload["engagement_id"] = engagement_id
    if correlation_id is not None:
        payload["correlation_id"] = correlation_id
    if scan_profile is not None:
        payload["scan_profile"] = scan_profile
    if phase is not None:
        payload["phase"] = phase
    if reason_code is not None:
        payload["reason_code"] = reason_code
    if registry_versions:
        payload["registry_versions"] = redact(registry_versions)
    if extra:
        payload.update(redact(extra))

    logger.log(level, event, extra={"argus_event": payload})
    return payload


__all__ = [
    "ALL_EVENTS",
    "EVENT_EVIDENCE_CONTRACT_FAILED",
    "EVENT_EVIDENCE_CONTRACT_SATISFIED",
    "EVENT_LAB_LEASE_PREFLIGHT_ALLOWED",
    "EVENT_LAB_LEASE_PREFLIGHT_DENIED",
    "EVENT_LLM_PLAN_ABSTAINED",
    "EVENT_LLM_PLAN_APPROVED",
    "EVENT_LLM_PLAN_REJECTED",
    "EVENT_PARSER_FAILED",
    "EVENT_PARSER_SUCCESS",
    "EVENT_PARSER_UNAVAILABLE",
    "EVENT_PAYLOAD_FAMILY_DENIED",
    "EVENT_PAYLOAD_FAMILY_SELECTED",
    "EVENT_PROFILE_CAPABILITY_ALLOWED",
    "EVENT_PROFILE_CAPABILITY_DENIED",
    "EVENT_REPORT_FORMAT_FAILED",
    "EVENT_REPORT_FORMAT_RENDERED",
    "EVENT_REPORT_SNAPSHOT_CREATED",
    "EVENT_SCAN_PROFILE_CONFLICT",
    "EVENT_SCAN_PROFILE_RESOLVED",
    "EVENT_TOOL_SELECTED",
    "EVENT_TOOL_SKIPPED",
    "EVENT_TOOL_UNAVAILABLE",
    "REDACTED",
    "emit_event",
    "redact",
]
