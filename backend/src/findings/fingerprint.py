"""Finding / occurrence fingerprint keys (master prompt §11).

Canonical version is ``argus:finding_fingerprint:v1``. Protocol and Nuclei
template id are **not** mixed into the logical finding key: parameter is
already in the v1 payload, protocol is derived from location/asset, and
template identity lives on the occurrence (``detector_id``). Bumping the
version would break 056 finding_occurrences diffs/retests.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Final

_CANON_VERSION: str = "argus:finding_fingerprint:v1"
FINGERPRINT_VERSION: Final[str] = _CANON_VERSION

_PROTOCOL_PREFIXES: Final[tuple[tuple[str, str], ...]] = (
    ("https://", "https"),
    ("http://", "http"),
    ("wss://", "wss"),
    ("ws://", "ws"),
    ("tls://", "tls"),
    ("ssl://", "ssl"),
    ("tcp://", "tcp"),
    ("udp://", "udp"),
    ("dns://", "dns"),
)


def _normalize_location(location: str) -> str:
    text = (location or "").strip().lower()
    text = re.sub(r"^https?://[^/]+", "", text)
    text = re.sub(r"/+", "/", text)
    return text[:2048] or "unknown-location"


def _normalize_component(value: str | None) -> str:
    return (value or "").strip().lower()[:256] or "unknown-component"


def _normalize_category(category: str | None) -> str:
    return (category or "unknown").strip().lower()[:128]


def _normalize_root_cause(root_cause_family: str | None) -> str:
    return (root_cause_family or "unknown").strip().lower()[:128]


def normalize_protocol(value: str | None = None, *, location: str | None = None) -> str:
    """Return a short protocol token. Not part of the v1 finding_key payload."""
    if value and value.strip():
        return value.strip().lower()[:32]
    loc = (location or "").strip().lower()
    for prefix, protocol in _PROTOCOL_PREFIXES:
        if loc.startswith(prefix):
            return protocol
    return "unknown-protocol"


def template_detector_id(template_id: str | None, *, tool_id: str) -> str:
    """Occurrence ``detector_id``: template id when present, else tool id."""
    text = (template_id or "").strip() or (tool_id or "").strip()
    return text[:256] or "unknown"


def finding_key(
    *,
    tenant_id: str,
    engagement_id: str,
    asset: str,
    category: str,
    normalized_location: str,
    parameter_or_component: str,
    root_cause_family: str,
) -> str:
    """Return sha256 logical finding key."""
    return compute_finding_key(
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        asset=asset,
        category=category,
        normalized_location=normalized_location,
        parameter_or_component=parameter_or_component,
        root_cause_family=root_cause_family,
    )


def compute_finding_key(
    *,
    tenant_id: str,
    engagement_id: str,
    asset: str,
    category: str,
    normalized_location: str,
    parameter_or_component: str | None = None,
    root_cause_family: str | None = None,
) -> str:
    """Return sha256 logical finding key per master prompt §11."""
    canonical = json.dumps(
        {
            "v": _CANON_VERSION,
            "tenant": tenant_id.strip(),
            "engagement": engagement_id.strip(),
            "asset": asset.strip().lower(),
            "category": _normalize_category(category),
            "location": _normalize_location(normalized_location),
            "parameter": _normalize_component(parameter_or_component),
            "root_cause": _normalize_root_cause(root_cause_family),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def occurrence_key(
    *,
    finding_key_value: str,
    scanner: str,
    detector_id: str,
    detector_version: str,
    request_signature: str,
    evidence_signal_hash: str,
) -> str:
    """Return sha256 occurrence key."""
    return compute_occurrence_key(
        finding_key=finding_key_value,
        scanner=scanner,
        detector_id=detector_id,
        detector_version=detector_version,
        request_signature=request_signature,
        evidence_signal_hash=evidence_signal_hash,
    )


def compute_occurrence_key(
    *,
    finding_key: str,
    scanner: str,
    detector_id: str,
    detector_version: str,
    request_signature: str,
    evidence_signal_hash: str,
) -> str:
    """Return sha256 occurrence key bound to scanner evidence."""
    canonical = json.dumps(
        {
            "v": _CANON_VERSION,
            "finding_key": finding_key,
            "scanner": scanner.strip().lower(),
            "detector_id": detector_id.strip(),
            "detector_version": detector_version.strip(),
            "request_signature": request_signature.strip(),
            "evidence_signal_hash": evidence_signal_hash.strip().lower(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_evidence_signal_hash(evidence: dict[str, Any] | str | bytes) -> str:
    """Hash evidence signal material for occurrence keys."""
    if isinstance(evidence, bytes):
        payload = evidence
    elif isinstance(evidence, str):
        payload = evidence.encode("utf-8")
    else:
        payload = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    return hashlib.sha256(payload).hexdigest()


def finding_key_from_dict(payload: dict[str, Any]) -> str:
    """Derive finding key from a normalized finding dict."""
    return compute_finding_key(
        tenant_id=str(payload.get("tenant_id") or ""),
        engagement_id=str(payload.get("engagement_id") or ""),
        asset=str(payload.get("asset") or payload.get("affected_asset") or ""),
        category=str(payload.get("category") or payload.get("vuln_type") or ""),
        normalized_location=str(
            payload.get("normalized_location")
            or payload.get("affected_url")
            or payload.get("location")
            or ""
        ),
        parameter_or_component=str(
            payload.get("parameter_or_component") or payload.get("parameter") or ""
        ),
        root_cause_family=str(payload.get("root_cause_family") or ""),
    )
