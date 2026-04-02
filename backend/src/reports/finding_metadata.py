"""Finding evidence metadata — normalize confidence, evidence type, refs (T4)."""

from __future__ import annotations

import re
from typing import Any, Literal

FindingConfidence = Literal["confirmed", "likely", "possible", "advisory"]
FindingEvidenceType = Literal[
    "observed",
    "tool_output",
    "version_match",
    "cve_correlation",
    "threat_model_inference",
]

_CONFIDENCE_SET: frozenset[str] = frozenset(
    {"confirmed", "likely", "possible", "advisory"}
)
_EVIDENCE_TYPE_SET: frozenset[str] = frozenset(
    {
        "observed",
        "tool_output",
        "version_match",
        "cve_correlation",
        "threat_model_inference",
    }
)

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def normalize_confidence(raw: Any, *, default: FindingConfidence = "likely") -> FindingConfidence:
    if raw is None:
        return default
    s = str(raw).strip().lower()
    if s in _CONFIDENCE_SET:
        return s  # type: ignore[return-value]
    return default


def normalize_evidence_type(raw: Any) -> FindingEvidenceType | None:
    if raw is None:
        return None
    s = str(raw).strip().lower().replace("-", "_")
    if s in _EVIDENCE_TYPE_SET:
        return s  # type: ignore[return-value]
    return None


def normalize_evidence_refs(raw: Any, *, max_items: int = 32, max_len: int = 500) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str) and raw.strip():
        return [raw.strip()[:max_len]]
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw[:max_items]:
        if item is None:
            continue
        s = str(item).strip()
        if s:
            out.append(s[:max_len])
    return out


def clip_optional_text(raw: Any, max_len: int) -> str | None:
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    return s[:max_len]


def finding_text_blob(f: dict[str, Any]) -> str:
    parts = [
        str(f.get("title") or ""),
        str(f.get("description") or ""),
        str(f.get("remediation") or ""),
        str(f.get("affected_asset") or ""),
    ]
    poc = f.get("proof_of_concept")
    if isinstance(poc, dict):
        for k in ("cve", "cve_id", "cve_ids", "notes", "curl_command"):
            v = poc.get(k)
            if isinstance(v, str):
                parts.append(v)
            elif isinstance(v, list):
                parts.extend(str(x) for x in v[:8])
    return " ".join(parts)


def extract_cve_ids_from_finding(f: dict[str, Any]) -> list[str]:
    blob = finding_text_blob(f)
    return sorted({m.group(0).upper() for m in _CVE_RE.finditer(blob)})


def format_evidence_cell(evidence_type: str | None, evidence_refs: list[str]) -> str:
    et = (evidence_type or "").strip().lower().replace("-", "_") or "—"
    if not evidence_refs:
        return et
    refs = "; ".join(evidence_refs[:8])
    if len(evidence_refs) > 8:
        refs += "…"
    return f"{et}: {refs}"


def apply_default_finding_metadata(f: dict[str, Any]) -> None:
    """Fill confidence / evidence_type / evidence_refs when absent (in-place)."""
    src = f.get("source")
    st = str(f.get("source_tool") or "").strip().lower()

    if f.get("confidence") is None or not str(f.get("confidence") or "").strip():
        if src == "active_scan":
            f["confidence"] = "confirmed"
        else:
            f["confidence"] = "likely"
    else:
        f["confidence"] = normalize_confidence(f.get("confidence"))

    et_in = normalize_evidence_type(f.get("evidence_type"))
    if et_in is not None:
        f["evidence_type"] = et_in
    else:
        if src == "active_scan":
            f["evidence_type"] = "observed"
        elif st == "trivy":
            f["evidence_type"] = "version_match"
        elif extract_cve_ids_from_finding(f):
            f["evidence_type"] = "cve_correlation"
        else:
            f["evidence_type"] = "threat_model_inference"

    refs = normalize_evidence_refs(f.get("evidence_refs"))
    if src == "active_scan" and st and not any(r.startswith("tool:") for r in refs):
        refs.insert(0, f"tool:{st}")
    f["evidence_refs"] = refs

    rs = clip_optional_text(f.get("reproducible_steps"), 16_000)
    if rs is not None:
        f["reproducible_steps"] = rs
    elif "reproducible_steps" in f and not str(f.get("reproducible_steps") or "").strip():
        del f["reproducible_steps"]

    an = clip_optional_text(f.get("applicability_notes"), 8_000)
    if an is not None:
        f["applicability_notes"] = an
    elif "applicability_notes" in f and not str(f.get("applicability_notes") or "").strip():
        del f["applicability_notes"]
