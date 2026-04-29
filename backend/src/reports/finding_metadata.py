"""Finding evidence metadata — normalize confidence, evidence type, refs (T4)."""

from __future__ import annotations

import logging
import re
from typing import Any, Literal

from pydantic import BaseModel

from src.findings.cvss import parse_cvss_vector

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
_CWE_PREFIX_RE = re.compile(r"^CWE-?", re.IGNORECASE)

logger = logging.getLogger(__name__)


class CvssVector(BaseModel):
    """CVSS:3.1 vector string with computed base score and severity."""

    vector_string: str
    base_score: float
    severity: str
    cwe_id: str


# CWE → (CVSS:3.1 vector, base score, severity) lookup for findings without a scanner-provided score.
# Reference: NIST NVD scoring guidance — https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator
# Entries use typical worst-case vectors; context adjustments in _apply_context_adjustments() may lower scores.
_CWE_CVSS_MAP: dict[str, tuple[str, float, str]] = {
    "79": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium"),
    "79-stored": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4, "medium"),
    "89": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    "918": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", 8.2, "high"),
    "22": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "high"),
    "352": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", 6.5, "medium"),
    "611": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "high"),
    "94": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    "78": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    "502": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    "200": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "medium"),
    "16": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "medium"),
    "693": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N", 5.3, "medium"),
    "295": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4, "high"),
    "326": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9, "medium"),
    "601": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1, "medium"),
    "434": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    "287": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    "639": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1, "high"),
    "1021": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3, "medium"),
    "319": ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9, "medium"),
    "532": ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5, "medium"),
    "798": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
    "307": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5, "high"),
    "863": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1, "high"),
    "943": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "critical"),
}


def _apply_context_adjustments(vector: str, context: dict[str, Any]) -> str:
    """Adjust CVSS vector components based on finding context."""
    if context.get("authenticated"):
        vector = vector.replace("/PR:N/", "/PR:L/")
    if context.get("local"):
        vector = vector.replace("/AV:N/", "/AV:L/")
    return vector


def estimate_cvss_vector(
    cwe_id: int | str,
    context: dict[str, Any] | None = None,
) -> CvssVector | None:
    """Estimate CVSS:3.1 vector string from CWE ID.

    Context-aware adjustments:
    - ``authenticated``: True → modify PR from N to L
    - ``local``: True → modify AV from N to L
    - ``xss_type``: "stored" → use stored XSS variant for CWE-79
    """
    raw = str(cwe_id).strip()
    normalized = _CWE_PREFIX_RE.sub("", raw)
    if not normalized:
        return None

    ctx = context or {}

    lookup_key = normalized
    if normalized == "79" and str(ctx.get("xss_type") or "").lower() == "stored":
        lookup_key = "79-stored"

    entry = _CWE_CVSS_MAP.get(lookup_key)
    if entry is None:
        return None

    vector_string, base_score, severity = entry
    if ctx:
        adjusted = _apply_context_adjustments(vector_string, ctx)
        if adjusted != vector_string:
            try:
                parsed = parse_cvss_vector(adjusted)
            except ValueError as exc:
                logger.warning(
                    "cvss_context_adjustment_parse_failed",
                    extra={
                        "cwe_id": f"CWE-{normalized}",
                        "vector": adjusted,
                        "error": str(exc),
                    },
                )
            else:
                vector_string = adjusted
                base_score = parsed.base
                severity = parsed.severity.lower()
        else:
            vector_string = adjusted

    cwe_label = f"CWE-{normalized}"

    logger.debug(
        "cvss_vector_estimated",
        extra={"cwe_id": cwe_label, "vector": vector_string, "score": base_score},
    )

    return CvssVector(
        vector_string=vector_string,
        base_score=base_score,
        severity=severity,
        cwe_id=cwe_label,
    )


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


def _has_real_poc_evidence(poc: Any) -> bool:
    """Check if PoC dict contains real evidence beyond just a tool name."""
    if not isinstance(poc, dict):
        return False
    if poc.get("verified_via_browser") is True:
        return True
    vm = str(poc.get("verification_method") or "").strip()
    if vm in ("browser", "http_reflection"):
        return True
    if poc.get("screenshot_key"):
        return True
    snippet = str(poc.get("response_snippet") or "").strip()
    if len(snippet) > 20:
        return True
    return bool(poc.get("request") and poc.get("response"))


def apply_default_finding_metadata(f: dict[str, Any]) -> None:
    """Fill confidence / evidence_type / evidence_refs when absent (in-place)."""
    src = f.get("source")
    st = str(f.get("source_tool") or "").strip().lower()

    if f.get("confidence") is None or not str(f.get("confidence") or "").strip():
        if src == "active_scan":
            poc = f.get("proof_of_concept")
            if _has_real_poc_evidence(poc):
                f["confidence"] = "confirmed"
            else:
                f["confidence"] = "likely"
        elif src == "threat_model":
            f["confidence"] = "possible"
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

    if f.get("cvss_vector") is None:
        cwe = f.get("cwe_id") or f.get("cwe")
        if cwe:
            ctx: dict[str, Any] = {"xss_type": f.get("xss_type")}
            if f.get("requires_auth"):
                ctx["authenticated"] = True
            cv = estimate_cvss_vector(cwe, context=ctx)
            if cv:
                f["cvss_vector"] = cv.vector_string
                if f.get("cvss_score") is None:
                    f["cvss_score"] = cv.base_score
