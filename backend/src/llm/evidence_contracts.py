"""Evidence pack contracts — compact, phase-specific digests for LLM prompting.

Scanners already produce the facts; the model should connect them, not wade through
raw nmap/ffuf/dalfox dumps. These builders project verbose finding/tool data into
small, JSON-safe digests keyed by contract name (matching ``phase_routing.yaml``).

Pure functions, no I/O. Safe to call defensively — never raise on malformed input.
"""

from __future__ import annotations

from typing import Any, Callable

_MAX_ITEMS = 40
_MAX_STR = 400


def _s(value: Any, limit: int = _MAX_STR) -> str:
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    return text[:limit]


def _first(finding: dict[str, Any], *keys: str, default: str = "") -> str:
    for k in keys:
        v = finding.get(k)
        if v:
            return _s(v)
    return default


def _project(finding: dict[str, Any], fields: dict[str, tuple[str, ...]]) -> dict[str, Any]:
    """Project a finding onto a compact dict using per-output-key alias tuples."""
    out: dict[str, Any] = {}
    for out_key, aliases in fields.items():
        out[out_key] = _first(finding, *aliases)
    return out


# --- Per-contract field maps (output_key -> source aliases) ---

_VULN_FIELDS: dict[str, tuple[str, ...]] = {
    "finding_id": ("finding_id", "id"),
    "title": ("title",),
    "severity": ("severity",),
    "cwe": ("cwe",),
    "owasp": ("owasp_category", "owasp"),
    "url": ("url", "affected_url", "location"),
    "parameter": ("parameter", "param", "param_name"),
    "evidence_type": ("evidence_type",),
    "validation_status": ("validation_status",),
    "confidence": ("confidence",),
    "evidence": ("evidence", "description"),
}

_EXPLOIT_FIELDS: dict[str, tuple[str, ...]] = {
    "finding_id": ("finding_id", "id"),
    "vuln_type": ("vuln_type", "type", "category"),
    "severity": ("severity",),
    "cwe": ("cwe",),
    "target": ("url", "affected_url", "target", "location"),
    "parameter": ("parameter", "param", "param_name"),
    "method": ("method",),
    "confidence": ("confidence",),
    "suggested_payload": ("suggested_payload", "payload", "poc"),
}


def build_vuln_evidence_pack(findings: list[dict[str, Any]], **_: Any) -> dict[str, Any]:
    rows = [
        _project(f, _VULN_FIELDS)
        for f in (findings or [])
        if isinstance(f, dict)
    ][:_MAX_ITEMS]
    return {"schema_version": "vuln_evidence_pack_v2", "findings": rows, "count": len(rows)}


def build_exploit_candidate_pack(findings: list[dict[str, Any]], **_: Any) -> dict[str, Any]:
    rows = [
        _project(f, _EXPLOIT_FIELDS)
        for f in (findings or [])
        if isinstance(f, dict)
    ][:_MAX_ITEMS]
    return {"schema_version": "exploit_candidate_pack_v1", "candidates": rows, "count": len(rows)}


def build_recon_digest(recon: dict[str, Any] | None = None, **_: Any) -> dict[str, Any]:
    recon = recon or {}
    return {
        "schema_version": "recon_digest_v1",
        "assets": (recon.get("assets") or [])[:_MAX_ITEMS],
        "technologies": (recon.get("technologies") or [])[:_MAX_ITEMS],
        "ports": (recon.get("ports") or [])[:_MAX_ITEMS],
        "endpoints": (recon.get("endpoints") or [])[:_MAX_ITEMS],
    }


def build_threat_model_input(
    findings: list[dict[str, Any]] | None = None,
    recon: dict[str, Any] | None = None,
    **_: Any,
) -> dict[str, Any]:
    return {
        "schema_version": "threat_model_input_v1",
        "recon": build_recon_digest(recon),
        "signals": build_vuln_evidence_pack(findings or [])["findings"],
    }


def build_post_exploit_impact_pack(
    exploits: list[dict[str, Any]] | None = None, **_: Any
) -> dict[str, Any]:
    rows = [
        {
            "finding_id": _first(e, "finding_id", "id"),
            "technique": _first(e, "technique", "tool"),
            "impact": _first(e, "impact"),
            "status": _first(e, "status"),
        }
        for e in (exploits or [])
        if isinstance(e, dict)
    ][:_MAX_ITEMS]
    return {"schema_version": "post_exploit_impact_pack_v1", "exploits": rows, "count": len(rows)}


def build_report_section_input(findings: list[dict[str, Any]] | None = None, **_: Any) -> dict[str, Any]:
    return {
        "schema_version": "report_section_input_v1",
        "findings": build_vuln_evidence_pack(findings or [])["findings"],
    }


EVIDENCE_CONTRACTS: dict[str, Callable[..., dict[str, Any]]] = {
    "recon_digest_v1": build_recon_digest,
    "threat_model_input_v1": build_threat_model_input,
    "vuln_evidence_pack_v2": build_vuln_evidence_pack,
    "exploit_candidate_pack_v1": build_exploit_candidate_pack,
    "post_exploit_impact_pack_v1": build_post_exploit_impact_pack,
    "report_section_input_v1": build_report_section_input,
}


def build_evidence_pack(contract: str | None, **ctx: Any) -> dict[str, Any] | None:
    """Build a digest for *contract* name; returns None for unknown/missing contract."""
    if not contract:
        return None
    builder = EVIDENCE_CONTRACTS.get(contract)
    if builder is None:
        return None
    try:
        return builder(**ctx)
    except Exception:  # pragma: no cover — defensive; never break the call path
        return None
