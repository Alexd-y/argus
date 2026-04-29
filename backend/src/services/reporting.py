"""RPT-005 — Report template context: ScanReportData + tiered AI sections (sync or Celery)."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.core.datetime_format import format_created_at_iso_z
from src.core.llm_config import has_any_llm_key
from src.data_sources.hibp_pwned_passwords import (
    validate_hibp_pwned_password_summary_light,
)
from src.orchestration.prompt_registry import (
    EXPLOITATION,
    REPORT_AI_SECTION_ATTACK_SCENARIOS,
    REPORT_AI_SECTION_BUSINESS_RISK,
    REPORT_AI_SECTION_COMPLIANCE_CHECK,
    REPORT_AI_SECTION_COST_SUMMARY,
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY,
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA,
    REPORT_AI_SECTION_EXPLOIT_CHAINS,
    REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS,
    REPORT_AI_SECTION_PRIORITIZATION_ROADMAP,
    REPORT_AI_SECTION_REMEDIATION_STAGES,
    REPORT_AI_SECTION_REMEDIATION_STEP,
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION,
    REPORT_AI_SECTION_ZERO_DAY_POTENTIAL,
    VULN_ANALYSIS,
)
from src.owasp.owasp_loader import get_owasp_category_info
from src.owasp_top10_2025 import (
    OWASP_TOP10_2025_CATEGORY_IDS,
    OWASP_TOP10_2025_CATEGORY_TITLES,
    parse_owasp_category,
)
from src.reports.ai_text_generation import (
    REPORT_AI_SKIPPED_GENERATION_FAILED,
    REPORT_AI_SKIPPED_NO_LLM,
    AITextDeduplicator,
    run_ai_text_generation,
)
from src.reports.data_collector import (
    FindingRow,
    OwaspCategorySummaryEntry,
    PhaseInputRow,
    PhaseOutputRow,
    ReportDataCollector,
    ScanReportData,
    TimelineRow,
    executive_severity_totals_from_finding_rows,
    severity_histogram_from_finding_rows,
)
from src.reports.finding_metadata import (
    estimate_cvss_vector,
    format_evidence_cell,
    normalize_confidence,
    normalize_evidence_refs,
    normalize_evidence_type,
)
from src.reports.generators import (
    VALHALLA_OWASP_2021_SECURITY_MISCONFIGURATION_CODE,
    ReportData,
    build_owasp_compliance_rows,
    build_report_data_from_scan_report,
)
from src.reports.report_quality_gate import (
    build_report_quality_gate,
    is_http_header_gap_topic,
    sanitize_ai_sections_for_quality,
)
from src.reports.valhalla_finding_normalization import (
    header_gap_verification_commands,
    owasp_top10_2021_label,
    valhalla_header_finding_remediation_text,
)
from src.reports.valhalla_report_context import (
    ValhallaReportContext,
    derive_exploit_available_flag,
    finding_qualifies_for_xss_structured_context,
)
from src.storage.s3 import (
    OBJECT_TYPE_RAW,
    RAW_ARTIFACT_PHASES,
    get_finding_poc_screenshot_presigned_url,
    get_presigned_url_by_key,
    list_scan_artifacts,
)

logger = logging.getLogger(__name__)

_SCAN_ARTIFACT_PHASE_LABELS: dict[str, str] = {
    "recon": "Reconnaissance",
    "threat_modeling": "Threat Modeling",
    "vuln_analysis": "Vulnerability Analysis",
    "exploitation": "Exploitation",
    "post_exploitation": "Post-Exploitation",
    "legacy_raw": "Raw (legacy path)",
    "other": "Other",
}

# Matches ``{timestamp}_{artifact_type}.{ext}`` from ``build_raw_phase_object_key`` / RawPhaseSink
_RAW_TOOL_OUTPUT_NAME_RE = re.compile(
    r"^\d{8}T\d{6}_[0-9a-f]{12}_[a-z][a-z0-9_]{0,127}\.[a-zA-Z0-9]{1,16}$"
)

# Raw artifact basename: ``{ts}_{artifact_type}.{ext}`` — active VA tools use ``tool_<name>_scan_...``
_ACTIVE_WEB_SCAN_TOOL_RE = re.compile(r"_tool_([a-z0-9]+)_scan_", re.IGNORECASE)
_ACTIVE_WEB_SCAN_PHASE_KEYS: frozenset[str] = frozenset(
    {(VULN_ANALYSIS or "vuln_analysis").lower(), (EXPLOITATION or "exploitation").lower()}
)

# OWASP2-007 / RPT: AI slots that contextualize active (dynamic) testing in the report
_ACTIVE_WEB_SCAN_AI_KEYS_ORDERED: tuple[str, ...] = (
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION,
    REPORT_AI_SECTION_REMEDIATION_STEP,
    REPORT_AI_SECTION_BUSINESS_RISK,
    REPORT_AI_SECTION_PRIORITIZATION_ROADMAP,
    REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS,
)

_ACTIVE_WEB_SCAN_AI_LABELS: dict[str, str] = {
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION: "Vulnerability Description (AI)",
    REPORT_AI_SECTION_REMEDIATION_STEP: "Remediation Steps (AI)",
    REPORT_AI_SECTION_BUSINESS_RISK: "Business Risks (AI)",
    REPORT_AI_SECTION_PRIORITIZATION_ROADMAP: "Prioritization Roadmap (AI)",
    REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS: "Hardening Recommendations (AI)",
}

# Safe, non-executable documentation string (no live XSS payload; placeholder only)
ACTIVE_WEB_SCAN_CURL_XSS_EXAMPLE = (
    "curl -sS -G 'https://TARGET.example/search' "
    "--data-urlencode 'q=REPLACE_WITH_SAFE_ENCODED_TEST_STRING'"
)

_ACTIVE_WEB_SCAN_AI_SUMMARY_MAX_LEN = 720

# OWASP-004: per-field cap for OWASP reference embedded in RPT-004 AI context (token/size bound)
_OWASP_AI_REFERENCE_FIELD_MAX_LEN = 400
_VALHALLA_AI_EXCERPT_MAX = 900
_VALHALLA_AI_TECH_ROWS = 28
_VALHALLA_AI_DEP_ROWS = 24
_VALHALLA_AI_OUTDATED_ROWS = 18
_VALHALLA_AI_POC_MAX_LEN = 600
_VALHALLA_AI_AFFECTED_URL_MAX = 1024
_VALHALLA_AI_FINDING_DESC_MAX = 400
_VALHALLA_AI_RISK_MATRIX_IDS_PER_CELL = 24
_VALHALLA_AI_CRITICAL_VULNS_MAX = 48
_VALHALLA_AI_XSS_ROWS = 32
_CVE_IDS_FOR_AI_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

_SCAN_ARTIFACT_PHASE_ORDER: tuple[str, ...] = (
    "recon",
    "threat_modeling",
    "vuln_analysis",
    "exploitation",
    "post_exploitation",
    "legacy_raw",
    "other",
)


def _phase_bucket_for_artifact_key(key: str, tenant_id: str, scan_id: str) -> str:
    """Map object key to a stable grouping key for the Artifacts table (RAW-005)."""
    parts = key.split("/")
    if len(parts) < 3 or parts[0] != tenant_id or parts[1] != scan_id:
        return "other"
    rest = parts[2:]
    if not rest:
        return "other"
    if rest[0] == OBJECT_TYPE_RAW:
        return "legacy_raw"
    if len(rest) >= 2 and rest[0] in RAW_ARTIFACT_PHASES and rest[1] == OBJECT_TYPE_RAW:
        return rest[0]
    return "other"


def _phase_query_value(bucket: str) -> str:
    """Query param ``phase`` for GET /scans/{id}/artifacts; empty = list all raw-scoped keys."""
    return bucket if bucket in RAW_ARTIFACT_PHASES else ""


def _is_raw_tool_output_file_name(file_name: str) -> bool:
    """True if basename matches phase-scoped raw upload pattern (orchestrator tool stdout/stderr, etc.)."""
    if not file_name or not isinstance(file_name, str):
        return False
    return bool(_RAW_TOOL_OUTPUT_NAME_RE.fullmatch(file_name.strip()))


def _artifact_display_file_name(key: str, tenant_id: str, scan_id: str) -> str:
    """Suffix after ``.../raw/`` for listing (avoids rsplit on ``/`` inside arbitrary keys e.g. ``</script>``)."""
    prefix = f"{tenant_id}/{scan_id}/"
    if not key.startswith(prefix):
        return key.rsplit("/", 1)[-1] if "/" in key else key
    rest = key[len(prefix) :]
    raw_marker = f"/{OBJECT_TYPE_RAW}/"
    idx = rest.find(raw_marker)
    if idx >= 0:
        return rest[idx + len(raw_marker) :]
    if rest.startswith(f"{OBJECT_TYPE_RAW}/"):
        return rest[len(OBJECT_TYPE_RAW) + 1 :]
    return key.rsplit("/", 1)[-1] if "/" in key else key


def build_scan_artifacts_section_context(
    tenant_id: str,
    scan_id: str,
    *,
    attempt_listing: bool,
) -> dict[str, Any]:
    """
    Context for ``partials/artifacts.html.j2``: grouped raw artifacts, presigned URLs when available.

    File names and labels are passed through Jinja autoescape (no XSS from MinIO keys).
    """
    if not attempt_listing or not (tenant_id or "").strip() or not (scan_id or "").strip():
        return {"status": "skipped", "phase_blocks": []}

    rows = list_scan_artifacts(tenant_id, scan_id, raw_only=True)
    if rows is None:
        return {"status": "unavailable", "phase_blocks": []}

    grouped: dict[str, list[dict[str, Any]]] = {k: [] for k in _SCAN_ARTIFACT_PHASE_ORDER}
    for row in rows:
        key = row.get("key") or ""
        if not key:
            continue
        bucket = _phase_bucket_for_artifact_key(key, tenant_id, scan_id)
        if bucket not in grouped:
            grouped[bucket] = []
        file_name = _artifact_display_file_name(key, tenant_id, scan_id)
        lm = row.get("last_modified")
        grouped[bucket].append(
            {
                "file_name": file_name,
                "key": key,
                "size": int(row.get("size") or 0),
                "last_modified": format_created_at_iso_z(lm) if lm is not None else format_created_at_iso_z(None),
                "download_url": get_presigned_url_by_key(key),
            }
        )

    phase_blocks: list[dict[str, Any]] = []
    for bucket in _SCAN_ARTIFACT_PHASE_ORDER:
        items = grouped.get(bucket) or []
        if not items:
            continue
        items.sort(key=lambda x: str(x.get("key") or ""))
        tool_output_rows = [r for r in items if _is_raw_tool_output_file_name(str(r.get("file_name") or ""))]
        other_rows = [r for r in items if not _is_raw_tool_output_file_name(str(r.get("file_name") or ""))]
        phase_blocks.append(
            {
                "phase_key": bucket,
                "phase_label": _SCAN_ARTIFACT_PHASE_LABELS.get(bucket, bucket),
                "phase_query": _phase_query_value(bucket),
                "rows": items,
                "tool_output_rows": tool_output_rows,
                "other_rows": other_rows,
            }
        )

    return {"status": "ok", "phase_blocks": phase_blocks}


REPORT_TIERS: frozenset[str] = frozenset({"midgard", "asgard", "valhalla"})

TIER_METADATA: dict[str, dict[str, Any]] = {
    "midgard": {
        "label": "Midgard",
        "focus": "summary",
        "active_web_scan": False,
    },
    "asgard": {
        "label": "Asgard",
        "focus": "technical",
        "active_web_scan": True,
    },
    "valhalla": {
        "label": "Valhalla",
        "focus": "leadership_technical",
        "active_web_scan": True,
    },
}
TIER_STUBS = TIER_METADATA  # deprecated alias


def _json_or_str(obj: Any, max_len: int) -> str:
    try:
        t = json.dumps(obj, ensure_ascii=False)
    except (TypeError, ValueError):
        t = str(obj)
    t = (t or "").strip()
    if len(t) > max_len:
        return t[: max_len - 1].rstrip() + "…"
    return t


def valhalla_nmap_appendix_excerpt(phase_outputs: list[PhaseOutputRow]) -> str:
    """Pick a bounded nmap-like excerpt from phase outputs for the appendix."""
    for row in phase_outputs:
        od = row.output_data
        if isinstance(od, dict):
            text = _json_or_str(od, 500_000)
        elif od is not None:
            text = str(od)
        else:
            continue
        low = text.lower()
        if "nmap" not in low:
            continue
        idx = low.find("nmap scan report")
        if idx >= 0:
            return text[idx : idx + 4000]
        if "/tcp" in text or "/udp" in text:
            return text[:4000]
    return ""


def valhalla_phase_inputs_config_excerpt(
    phase_inputs: list[PhaseInputRow],
    *,
    max_len: int = 4000,
) -> str:
    parts: list[str] = []
    for row in phase_inputs[:20]:
        if not row.input_data:
            continue
        parts.append(_json_or_str(row.input_data, 8000))
    blob = "\n---\n".join(parts)
    if len(blob) > max_len:
        return blob[: max_len - 1].rstrip() + "…"
    return blob


def valhalla_timeline_appendix_rows(
    timeline: list[TimelineRow],
    *,
    max_items: int = 32,
) -> list[dict[str, Any]]:
    rows: list[TimelineRow] = sorted(
        timeline,
        key=lambda x: (x.order_index, (x.phase or "")),
    )[:max_items]
    out: list[dict[str, Any]] = []
    for t in rows:
        ent = t.entry
        snippet = _json_or_str(ent, 800) if ent is not None else ""
        out.append(
            {
                "phase": t.phase or "",
                "order_index": t.order_index,
                "snippet": snippet,
            }
        )
    return out


def _cve_from_proof_of_concept(poc: dict[str, Any] | None) -> str | None:
    if not isinstance(poc, dict) or not poc:
        return None
    for key in ("cve", "cve_id", "CVE", "CVE_ID"):
        v = poc.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()[:64]
    return None


def _poc_nonempty_str(val: Any) -> str | None:
    if val is None:
        return None
    if isinstance(val, str):
        s = val.strip()
        return s or None
    return None


def _format_xss_payload_reflected_display(poc: dict[str, Any]) -> str | None:
    pr = poc.get("payload_reflected")
    if isinstance(pr, str) and pr.strip():
        return pr.strip()
    if isinstance(pr, bool):
        return "yes" if pr else "no"
    return None


def _build_xss_verification_line(poc: dict[str, Any], row: dict[str, Any]) -> str | None:
    tokens: list[str] = []
    vm = _poc_nonempty_str(poc.get("verification_method"))
    if vm:
        vl = vm.lower()
        if vl == "http_reflection":
            tokens.append("verification_method: HTTP reflection")
        elif vl == "http":
            tokens.append("verification_method: HTTP")
        else:
            tokens.append(f"verification_method: {vm}")
    vvb = poc.get("verified_via_browser")
    if vvb is True:
        tokens.append("verified_via_browser: yes")
    elif vvb is False:
        tokens.append("verified_via_browser: no")
    if row.get("poc_screenshot_url") or _poc_nonempty_str(poc.get("poc_screenshot_url")):
        tokens.append("poc_screenshot_url: present")
    elif _poc_nonempty_str(poc.get("screenshot_key")):
        tokens.append("screenshot_key: present")
    if _poc_nonempty_str(poc.get("curl_command")):
        joined = " ".join(tokens).lower()
        if "curl" not in joined:
            tokens.append("curl PoC present")
    if not tokens:
        return None
    return "; ".join(tokens)


def _xss_poc_narrative_for_report(poc: dict[str, Any], param: str | None) -> str | None:
    for key in ("poc_narrative", "narrative", "poc_summary"):
        v = _poc_nonempty_str(poc.get(key))
        if v:
            return v[:4000]
    pe = _poc_nonempty_str(poc.get("payload_entered")) or _poc_nonempty_str(poc.get("payload"))
    rc = _poc_nonempty_str(poc.get("reflection_context")) or _poc_nonempty_str(poc.get("context"))
    p_label = param.strip() if isinstance(param, str) and param.strip() else "parameter"
    if pe and rc:
        return (
            f"A payload was injected via the \"{p_label}\" parameter; "
            f"reflection detected in \"{rc}\" context. "
            "Confirmation method is specified in the Verification line field."
        )
    if pe and isinstance(param, str) and param.strip():
        return f"Payload was delivered through the \"{param.strip()}\" parameter."
    return None


def _build_xss_poc_detail_for_jinja(poc: dict[str, Any], row: dict[str, Any]) -> dict[str, str] | None:
    """Non-empty XSS subsection fields for Valhalla HTML (VHL / T7); keys align with PoC JSON."""
    param = row.get("parameter") or row.get("param") or _poc_nonempty_str(poc.get("parameter"))
    param_s = param if isinstance(param, str) else None

    payload_entered = _poc_nonempty_str(poc.get("payload_entered")) or _poc_nonempty_str(
        poc.get("payload")
    )
    payload_reflected = _format_xss_payload_reflected_display(poc)
    payload_used = _poc_nonempty_str(poc.get("payload_used"))
    if payload_used and payload_used == (payload_entered or ""):
        payload_used = None
    reflection_context = _poc_nonempty_str(poc.get("reflection_context")) or _poc_nonempty_str(
        poc.get("context")
    )
    verification_line = _build_xss_verification_line(poc, row)
    narrative = _xss_poc_narrative_for_report(poc, param_s)
    shot = row.get("poc_screenshot_url") or _poc_nonempty_str(poc.get("poc_screenshot_url"))

    out: dict[str, str] = {}
    if payload_entered:
        out["payload_entered"] = payload_entered
    if payload_reflected is not None:
        out["payload_reflected"] = payload_reflected
    if payload_used:
        out["payload_used"] = payload_used
    if reflection_context:
        out["reflection_context"] = reflection_context
    if verification_line:
        out["verification_line"] = verification_line
    if narrative:
        out["poc_narrative"] = narrative
    if shot:
        out["poc_screenshot_url"] = shot
    return out or None


def findings_rows_for_jinja(
    data: ScanReportData, *, report_tier: str | None = None
) -> list[dict[str, Any]]:
    """Serializable finding rows for report templates (autoescaped at render)."""
    tier_norm = normalize_report_tier(report_tier) if report_tier else None
    rows: list[dict[str, Any]] = []
    for f in data.findings:
        parsed_owasp = (
            parse_owasp_category(f.owasp_category) if isinstance(f.owasp_category, str) else None
        )
        header_gap = is_http_header_gap_topic(f)
        if tier_norm == "valhalla" and header_gap:
            parsed_owasp = "A02"
        row: dict[str, Any] = {
            "id": f.id or "",
            "severity": f.severity or "",
            "title": f.title or "",
            "description": f.description or "",
            "cwe": f.cwe,
            "cvss": f.cvss,
            "owasp_category": parsed_owasp,
            "validation_status": f.validation_status or "unverified",
            "evidence_quality": f.evidence_quality or "none",
        }
        if parsed_owasp:
            row["owasp_title"] = OWASP_TOP10_2025_CATEGORY_TITLES.get(parsed_owasp, parsed_owasp)
        if tier_norm == "valhalla" and parsed_owasp == "A02":
            row["owasp_display_code"] = VALHALLA_OWASP_2021_SECURITY_MISCONFIGURATION_CODE
            row["owasp_top10_2021"] = "A05:2021"
        elif tier_norm == "valhalla" and parsed_owasp:
            lbl21 = owasp_top10_2021_label(parsed_owasp)
            if lbl21:
                row["owasp_top10_2021"] = lbl21
        poc: dict[str, Any] = {}
        if isinstance(f.proof_of_concept, dict):
            poc = dict(f.proof_of_concept)
        row["proof_of_concept"] = poc
        param_v = poc.get("parameter")
        if isinstance(param_v, str) and param_v.strip():
            row["parameter"] = param_v.strip()
            row["param"] = row["parameter"]
        sk = poc.get("screenshot_key")
        if isinstance(sk, str) and sk.strip():
            url = get_finding_poc_screenshot_presigned_url(
                sk.strip(),
                data.tenant_id,
                data.scan_id,
            )
            if url:
                row["poc_screenshot_url"] = url
        row["cve"] = _cve_from_proof_of_concept(poc if poc else None)
        conf = normalize_confidence(f.confidence, default="likely")
        row["confidence"] = conf
        row["is_advisory"] = conf == "advisory"
        et = normalize_evidence_type(f.evidence_type)
        refs = normalize_evidence_refs(f.evidence_refs)
        row["evidence_type"] = et
        row["evidence_refs"] = refs
        if tier_norm == "valhalla" and header_gap:
            url_guess = ""
            if poc:
                url_guess = str(poc.get("request_url") or poc.get("url") or "").strip()
            if not url_guess:
                au = getattr(f, "affected_url", None)
                if isinstance(au, str) and au.strip():
                    url_guess = au.strip()
            row["verification_commands"] = header_gap_verification_commands(url_guess)
            row["remediation_text"] = valhalla_header_finding_remediation_text()
            row["evidence_ids"] = list(refs) if refs else []
        row["evidence_summary"] = format_evidence_cell(et, refs)
        row["applicability_notes"] = (f.applicability_notes or "").strip()
        row["reproducible_steps"] = (f.reproducible_steps or "").strip()
        f_qualifier = {"title": row["title"], "cwe": f.cwe, "proof_of_concept": poc}
        if finding_qualifies_for_xss_structured_context(f_qualifier):
            row["xss_poc_detail"] = _build_xss_poc_detail_for_jinja(poc, row)
        else:
            row["xss_poc_detail"] = None
        rows.append(row)
    return rows


def render_findings_table_html(
    tier: str,
    findings_rows: list[dict[str, Any]],
    *,
    embed_poc_screenshot_inline: bool | None = None,
    owasp_summary: Mapping[str, OwaspCategorySummaryEntry] | None = None,
) -> str:
    """Render ``partials/findings_table.html.j2`` with production Jinja env (RPT-008)."""
    from src.reports.template_env import get_report_jinja_environment

    embed = settings.report_poc_embed_screenshot_inline if embed_poc_screenshot_inline is None else embed_poc_screenshot_inline
    tier_norm = normalize_report_tier(tier)
    env = get_report_jinja_environment()
    summary_arg = owasp_summary if owasp_summary else None
    v2021 = tier_norm == "valhalla"
    return env.get_template("partials/findings_table.html.j2").render(
        tier=tier_norm,
        findings=findings_rows,
        embed_poc_screenshot_inline=bool(embed),
        valhalla_owasp_2021_labels=v2021,
        owasp_compliance_rows=build_owasp_compliance_rows(
            findings_rows,
            owasp_summary=summary_arg,
            use_valhalla_owasp_2021_misconfig_labels=v2021,
        ),
        owasp_top10_labels=OWASP_TOP10_2025_CATEGORY_TITLES,
    )


def recon_summary_for_jinja(data: ScanReportData) -> dict[str, Any]:
    """Recon / scan lifecycle summary for report HTML (no raw MinIO bodies)."""
    target = ""
    if data.scan and data.scan.target_url:
        target = data.scan.target_url
    elif data.report and data.report.target:
        target = data.report.target or ""
    technologies: list[str] = []
    if data.report and data.report.technologies:
        technologies = [str(t) for t in data.report.technologies]
    summary_counts: dict[str, Any] = dict(
        executive_severity_totals_from_finding_rows(data.findings)
    )
    timeline_preview: list[dict[str, Any]] = []
    for t in sorted(data.timeline, key=lambda x: (x.order_index, x.phase))[:24]:
        snippet = ""
        if t.entry is not None:
            snippet = str(t.entry)[:240]
        timeline_preview.append(
            {"phase": t.phase, "order_index": t.order_index, "snippet": snippet}
        )
    return {
        "target_url": target,
        "scan": data.scan.model_dump(mode="json") if data.scan else None,
        "summary_counts": summary_counts,
        "technologies": technologies,
        "timeline_preview": timeline_preview,
        "phase_inputs_count": len(data.phase_inputs),
        "phase_outputs_count": len(data.phase_outputs),
        "timeline_count": len(data.timeline),
        "findings_count": len(data.findings),
    }


def exploitation_outputs_for_jinja(data: ScanReportData) -> list[dict[str, Any]]:
    """Phase outputs tagged as exploitation (Valhalla section)."""
    phase_key = (EXPLOITATION or "exploitation").lower()
    out: list[dict[str, Any]] = []
    for row in data.phase_outputs:
        if (row.phase or "").lower() == phase_key:
            out.append({"phase": row.phase, "output_data": row.output_data})
    return out

_SECTIONS_MIDGARD: tuple[str, ...] = (
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY,
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION,
)

_SECTIONS_ASGARD: tuple[str, ...] = (
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY,
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION,
    REPORT_AI_SECTION_REMEDIATION_STEP,
    REPORT_AI_SECTION_BUSINESS_RISK,
    REPORT_AI_SECTION_COMPLIANCE_CHECK,
)

_SECTIONS_VALHALLA: tuple[str, ...] = (
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA,
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION,
    REPORT_AI_SECTION_ATTACK_SCENARIOS,
    REPORT_AI_SECTION_EXPLOIT_CHAINS,
    REPORT_AI_SECTION_REMEDIATION_STEP,
    REPORT_AI_SECTION_REMEDIATION_STAGES,
    REPORT_AI_SECTION_BUSINESS_RISK,
    REPORT_AI_SECTION_COMPLIANCE_CHECK,
    REPORT_AI_SECTION_PRIORITIZATION_ROADMAP,
    REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS,
    REPORT_AI_SECTION_ZERO_DAY_POTENTIAL,
    REPORT_AI_SECTION_COST_SUMMARY,
)


def report_tier_sections(tier: str) -> tuple[str, ...]:
    """RPT-004 section keys to run for the given report tier."""
    t = (tier or "midgard").lower()
    if t == "asgard":
        return _SECTIONS_ASGARD
    if t == "valhalla":
        return _SECTIONS_VALHALLA
    return _SECTIONS_MIDGARD


def normalize_report_tier(tier: str) -> str:
    t = (tier or "midgard").lower()
    return t if t in REPORT_TIERS else "midgard"


def _owasp_summary_for_ai_payload(findings: list[FindingRow]) -> dict[str, Any] | None:
    """
    Aggregate OWASP Top 10:2025 counts for the AI report context.
    Returns None when no finding has a valid category (backward compatible: key omitted).
    """
    counts: dict[str, int] = dict.fromkeys(OWASP_TOP10_2025_CATEGORY_IDS, 0)
    classified = 0
    for f in findings:
        raw = getattr(f, "owasp_category", None)
        cat = parse_owasp_category(raw.strip()) if isinstance(raw, str) and raw.strip() else None
        if cat is None:
            continue
        classified += 1
        counts[cat] = counts.get(cat, 0) + 1
    if classified == 0:
        return None
    gap_categories = [cid for cid in OWASP_TOP10_2025_CATEGORY_IDS if counts.get(cid, 0) == 0]
    unclassified = max(0, len(findings) - classified)
    return {
        "counts": dict(counts),
        "gap_categories": gap_categories,
        "classified_finding_count": classified,
        "unclassified_finding_count": unclassified,
    }


def _compact_owasp_fields(info: dict[str, Any]) -> dict[str, str]:
    """Pick OWASP reference keys and truncate for LLM context (OWASP-004).

    Supports both EN (``title``) and legacy RU (``title_ru``) layouts.
    """
    out: dict[str, str] = {}
    title = info.get("title") or info.get("title_ru")
    if isinstance(title, str) and title.strip():
        out["title"] = _truncate_report_text(title, _OWASP_AI_REFERENCE_FIELD_MAX_LEN)
    title_ru = info.get("title_ru")
    if isinstance(title_ru, str) and title_ru.strip():
        out["title_ru"] = _truncate_report_text(title_ru, _OWASP_AI_REFERENCE_FIELD_MAX_LEN)
    for key in ("example_attack", "how_to_find", "how_to_fix"):
        raw = info.get(key)
        if isinstance(raw, str) and raw.strip():
            out[key] = _truncate_report_text(raw, _OWASP_AI_REFERENCE_FIELD_MAX_LEN)
    return out


def _owasp_category_reference_for_ai(
    owasp_summary: dict[str, Any] | None,
) -> dict[str, dict[str, str]] | None:
    """
    When the scan has OWASP-classified findings (``owasp_summary`` present), attach compact text
    for each A01–A10 category that appears in the scan via findings (``counts[cid] > 0``) or that
    is listed in ``gap_categories`` (zero mapped findings but category row present in Top-10 coverage).
    Omits categories missing from the loaded JSON.
    """
    if owasp_summary is None:
        return None
    counts_raw = owasp_summary.get("counts")
    counts: dict[str, int] = counts_raw if isinstance(counts_raw, dict) else {}
    gaps_raw = owasp_summary.get("gap_categories")
    gaps: set[str] = set(gaps_raw) if isinstance(gaps_raw, list) else set()
    ref: dict[str, dict[str, str]] = {}
    for cid in OWASP_TOP10_2025_CATEGORY_IDS:
        n = int(counts.get(cid, 0) or 0)
        if n <= 0 and cid not in gaps:
            continue
        info = get_owasp_category_info(cid)
        if not info:
            continue
        compact = _compact_owasp_fields(info)
        if compact:
            ref[cid] = compact
    return ref or None


def _truncate_report_text(text: str, max_len: int) -> str:
    t = (text or "").strip()
    if len(t) <= max_len:
        return t
    return t[: max_len - 1].rstrip() + "…"


_FIRST_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z\u0410-\u042f\u0401])")


def _first_n_sentences(text: str, n: int = 2, max_len: int = 300) -> str:
    """Extract first N sentences as a compact summary for cross-section dedup context."""
    if not text or not text.strip():
        return ""
    normalized = " ".join(text.split())
    sentences = _FIRST_SENTENCE_RE.split(normalized)
    result = " ".join(sentences[:n]).strip()
    if len(result) > max_len:
        return result[: max_len - 1].rstrip() + "\u2026"
    return result


def _default_scan_target_for_ai(data: ScanReportData) -> str | None:
    if data.scan and (data.scan.target_url or "").strip():
        return data.scan.target_url.strip()
    if data.report and (data.report.target or "").strip():
        return data.report.target.strip()
    return None


def _asset_from_poc_or_url(poc: dict[str, Any], url: str | None) -> str | None:
    a = poc.get("affected_asset")
    if isinstance(a, str) and a.strip():
        return _truncate_report_text(a.strip(), 512)
    if url:
        try:
            p = urlparse(url)
            if p.netloc:
                return p.netloc[:512]
        except Exception as exc:
            logger.debug("asset_url_parse_failed", extra={"url": url}, exc_info=exc)
            return None
    return None


def _finding_row_as_dict_for_exploit(f: FindingRow) -> dict[str, Any]:
    """Shape accepted by ``derive_exploit_available_flag`` (VHQ-005)."""
    return f.model_dump(mode="python")


def _collect_cve_ids_for_ai_finding(
    title: str,
    description: str | None,
    cwe: str | None,
    poc: dict[str, Any],
) -> list[str]:
    """CVE tokens from title, description, CWE line, and PoC keys ``cve`` / ``cve_id`` / ``cve_ids``."""
    parts: list[str] = [title]
    if description:
        parts.append(description)
    if cwe:
        parts.append(cwe)
    blob = "\n".join(parts)
    found: set[str] = {m.group(0).upper() for m in _CVE_IDS_FOR_AI_RE.finditer(blob)}
    for key in ("cve", "cve_id", "cve_ids"):
        raw = poc.get(key)
        if isinstance(raw, str) and raw.strip():
            found.update(m.group(0).upper() for m in _CVE_IDS_FOR_AI_RE.finditer(raw))
        elif isinstance(raw, list):
            for it in raw:
                if isinstance(it, str):
                    found.update(m.group(0).upper() for m in _CVE_IDS_FOR_AI_RE.finditer(it))
    return sorted(found)


def _affected_url_asset_for_ai_payload(
    poc: dict[str, Any],
    default_target: str | None,
) -> tuple[str | None, str | None]:
    for k in ("affected_url", "url", "target_url"):
        v = poc.get(k)
        if isinstance(v, str) and v.strip():
            u = v.strip()
            tu = _truncate_report_text(u, _VALHALLA_AI_AFFECTED_URL_MAX)
            return tu, _asset_from_poc_or_url(poc, u)
    if default_target and default_target.strip():
        dt = default_target.strip()
        tdt = _truncate_report_text(dt, _VALHALLA_AI_AFFECTED_URL_MAX)
        return tdt, _asset_from_poc_or_url(poc, dt)
    asset_only = _asset_from_poc_or_url(poc, None)
    return None, asset_only


def _valhalla_one_line_summary(vc: ValhallaReportContext) -> str:
    parts: list[str] = []
    if vc.robots_txt_analysis.found:
        parts.append("robots.txt observed")
    if vc.sitemap_analysis.found:
        parts.append(f"sitemap_urls≈{vc.sitemap_analysis.url_count}")
    parts.append(f"tech_rows={len(vc.tech_stack_table)}")
    miss = vc.security_headers_analysis.missing_recommended
    if miss:
        parts.append(f"missing_recommended_headers={len(miss)}")
    if vc.outdated_components:
        parts.append(f"outdated_component_signals={len(vc.outdated_components)}")
    if vc.dependency_analysis:
        parts.append(f"dependency_rows={len(vc.dependency_analysis)}")
    if (vc.threat_model_excerpt or "").strip():
        parts.append("threat_model_excerpt_present")
    if (vc.exploitation_post_excerpt or "").strip():
        parts.append("exploitation_context_present")
    if vc.leaked_emails:
        parts.append(f"masked_email_indicators={len(vc.leaked_emails)}")
    if vc.xss_structured:
        parts.append(f"xss_structured_rows={len(vc.xss_structured)}")
    ssl = vc.ssl_tls_analysis
    if ssl.weak_ciphers:
        parts.append("tls_weak_cipher_signals")
    if ssl.hsts:
        parts.append("hsts_signal_present")
    if ssl.protocols:
        parts.append(f"tls_protocol_notes={len(ssl.protocols)}")
    return "; ".join(parts) if parts else "minimal_surface_signal"


def _compact_valhalla_context_for_ai(vc: ValhallaReportContext) -> dict[str, Any]:
    """Token-bounded Valhalla block for LLM context (VHL-003)."""
    rob = vc.robots_txt_analysis
    sm = vc.sitemap_analysis
    hdr = vc.security_headers_analysis
    ssl = vc.ssl_tls_analysis
    return {
        "engagement_title": (vc.valhalla_engagement_title or "")[:256],
        "full_valhalla": bool(vc.full_valhalla),
        "wstg_execution_degraded": bool(vc.wstg_execution_degraded),
        "wstg_coverage_zero_executed": bool(vc.wstg_coverage_zero_executed),
        "summary": _valhalla_one_line_summary(vc),
        "robots_txt": {
            "found": rob.found,
            "disallowed_paths_sample": (rob.disallowed_paths_sample or [])[:12],
            "sitemap_hints": (rob.sitemap_hints or [])[:8],
            "raw_excerpt": _truncate_report_text(rob.raw_excerpt or "", 600) if rob.raw_excerpt else None,
        },
        "sitemap": {
            "found": sm.found,
            "url_count": sm.url_count,
            "sample_urls": (sm.sample_urls or [])[:16],
        },
        "tech_stack_sample": [
            {"category": r.category, "name": r.name, "detail": _truncate_report_text(r.detail, 200)}
            for r in (vc.tech_stack_table or [])[:_VALHALLA_AI_TECH_ROWS]
        ],
        "outdated_components": [
            {
                "component": o.component,
                "cves": (o.cves or [])[:8],
                "support_status": o.support_status,
                "exploit_available": bool(o.exploit_available),
            }
            for o in (vc.outdated_components or [])[:_VALHALLA_AI_OUTDATED_ROWS]
        ],
        "ssl_tls": {
            "issuer": ssl.issuer,
            "validity": ssl.validity,
            "hsts": ssl.hsts,
            "protocols": (ssl.protocols or [])[:16],
            "weak_protocols": (ssl.weak_protocols or [])[:12],
            "weak_ciphers": (ssl.weak_ciphers or [])[:12],
        },
        "security_headers": {
            "summary": hdr.summary,
            "missing_recommended": (hdr.missing_recommended or [])[:16],
            "row_count": len(hdr.rows or []),
            "rows_sample": [
                {
                    "host": _truncate_report_text(str(r.get("host") or ""), 120),
                    "header": _truncate_report_text(str(r.get("header") or ""), 80),
                    "present": bool(r.get("present")),
                    "value_sample": _truncate_report_text(str(r.get("value_sample") or ""), 160),
                }
                for r in (hdr.rows or [])[:24]
            ],
        },
        "robots_sitemap_analysis": {
            "robots_found": vc.robots_sitemap_merged.robots_found,
            "sitemap_found": vc.robots_sitemap_merged.sitemap_found,
            "security_txt_reachable": vc.robots_sitemap_merged.security_txt_reachable,
            "disallow_rule_count": vc.robots_sitemap_merged.disallow_rule_count,
            "allow_rule_count": vc.robots_sitemap_merged.allow_rule_count,
            "sitemap_url_count": vc.robots_sitemap_merged.sitemap_url_count,
            "sensitive_path_hints": (vc.robots_sitemap_merged.sensitive_path_hints or [])[:16],
            "notes": _truncate_report_text(vc.robots_sitemap_merged.notes or "", 400),
        },
        "dependency_sample": [
            {
                "package": d.package,
                "version": d.version,
                "severity": d.severity,
                "detail": _truncate_report_text(d.detail or "", 240) if d.detail else None,
            }
            for d in (vc.dependency_analysis or [])[:_VALHALLA_AI_DEP_ROWS]
        ],
        "threat_model_excerpt": _truncate_report_text(vc.threat_model_excerpt, _VALHALLA_AI_EXCERPT_MAX),
        "exploitation_post_excerpt": _truncate_report_text(
            vc.exploitation_post_excerpt, _VALHALLA_AI_EXCERPT_MAX
        ),
        "threat_model_phase_link": (vc.threat_model_phase_link or "")[:512],
        "leaked_emails_masked_n": len(vc.leaked_emails or []),
        "leaked_emails_masked_sample": list((vc.leaked_emails or [])[:12]),
        "appendix_tools": [
            {"name": t.name, "version": t.version}
            for t in (vc.appendix_tools or [])[:96]
        ],
        "tech_stack_structured": {
            "web_server": _truncate_report_text(vc.tech_stack_structured.web_server or "", 240),
            "os": _truncate_report_text(vc.tech_stack_structured.os or "", 200),
            "cms": _truncate_report_text(vc.tech_stack_structured.cms or "", 240),
            "frameworks": [
                _truncate_report_text(x, 160)
                for x in (vc.tech_stack_structured.frameworks or [])[:24]
            ],
            "js_libraries": [
                _truncate_report_text(x, 160)
                for x in (vc.tech_stack_structured.js_libraries or [])[:24]
            ],
            "ports_summary": _truncate_report_text(
                vc.tech_stack_structured.ports_summary or "", 320
            ),
            "services_summary": _truncate_report_text(
                vc.tech_stack_structured.services_summary or "", 500
            ),
            "entries": [
                {
                    "technology": _truncate_report_text(e.technology or "", 200),
                    "version": (e.version or "")[:64] if e.version else None,
                    "confidence": float(e.confidence) if e.confidence is not None else None,
                }
                for e in (vc.tech_stack_structured.entries or [])[:48]
            ],
        },
        "risk_matrix": {
            "variant": vc.risk_matrix.variant,
            "cells": [
                {
                    "impact": c.impact,
                    "likelihood": c.likelihood,
                    "count": c.count,
                    "finding_ids": (c.finding_ids or [])[:_VALHALLA_AI_RISK_MATRIX_IDS_PER_CELL],
                }
                for c in (vc.risk_matrix.cells or [])
            ],
        },
        "critical_vulns": [
            {
                "vuln_id": v.vuln_id,
                "title": _truncate_report_text(v.title or "", 500),
                "cvss": float(v.cvss) if isinstance(v.cvss, (int, float)) else None,
                "description": _truncate_report_text(v.description or "", _VALHALLA_AI_FINDING_DESC_MAX),
                "exploit_available": bool(v.exploit_demonstrated),
                "exploit_demonstrated": bool(v.exploit_demonstrated),
            }
            for v in (vc.critical_vulns or [])[:_VALHALLA_AI_CRITICAL_VULNS_MAX]
        ],
        "xss_structured": [
            {
                "finding_id": _truncate_report_text(x.finding_id or "", 256),
                "title": _truncate_report_text(x.title or "", 300),
                "parameter": _truncate_report_text(x.parameter or "", 256) if x.parameter else None,
                "payload_entered": _truncate_report_text(x.payload_entered or "", _VALHALLA_AI_POC_MAX_LEN)
                if x.payload_entered
                else None,
                "payload_reflected": _truncate_report_text(x.payload_reflected or "", _VALHALLA_AI_POC_MAX_LEN)
                if x.payload_reflected
                else None,
                "payload_used": _truncate_report_text(x.payload_used or "", _VALHALLA_AI_POC_MAX_LEN)
                if x.payload_used
                else None,
                "reflection_context": _truncate_report_text(x.reflection_context or "", 400)
                if x.reflection_context
                else None,
                "verification_method": _truncate_report_text(x.verification_method or "", 128)
                if x.verification_method
                else None,
                "verified_via_browser": x.verified_via_browser,
                "browser_alert_text": _truncate_report_text(x.browser_alert_text or "", 400)
                if x.browser_alert_text
                else None,
                "artifact_keys": [
                    _truncate_report_text(k, 512) for k in (x.artifact_keys or [])[:16] if k
                ],
                "artifact_urls": [
                    _truncate_report_text(u, 1024) for u in (x.artifact_urls or [])[:8] if u
                ],
            }
            for x in (vc.xss_structured or [])[:_VALHALLA_AI_XSS_ROWS]
        ],
    }


def _owasp_compliance_table_for_ai(data: ScanReportData, *, report_tier: str) -> list[dict[str, Any]]:
    """OWASP Top 10 rows aligned with HTML compliance table (compact)."""
    t = normalize_report_tier(report_tier)
    v2021 = t == "valhalla"
    rows = build_owasp_compliance_rows(
        findings_rows_for_jinja(data, report_tier=t),
        owasp_summary=data.owasp_summary if data.owasp_summary else None,
        wstg_coverage=data.valhalla_context.wstg_coverage,
        use_valhalla_owasp_2021_misconfig_labels=v2021,
    )
    out: list[dict[str, Any]] = []
    for r in rows:
        item: dict[str, Any] = {
            "category_id": r.get("category_id"),
            "title": _truncate_report_text(str(r.get("title") or ""), 200),
            "has_findings": bool(r.get("has_findings")),
            "assessed": r.get("assessed"),
            "assessment_result": r.get("assessment_result"),
            "findings_present": r.get("findings_present"),
            "count": int(r.get("count") or 0),
            "row_class": r.get("row_class"),
        }
        dc = r.get("display_category_code")
        if isinstance(dc, str) and dc.strip():
            item["display_category_code"] = dc.strip()
        out.append(item)
    return out


def _collect_active_web_scan_tool_names(scan_artifacts: dict[str, Any]) -> list[str]:
    """Unique tool ids inferred from vuln_analysis / exploitation raw artifact names."""
    found: set[str] = set()
    blocks = scan_artifacts.get("phase_blocks") if isinstance(scan_artifacts, dict) else None
    if not isinstance(blocks, list):
        return []
    for block in blocks:
        if not isinstance(block, dict):
            continue
        pk = str(block.get("phase_key") or "").lower()
        if pk not in _ACTIVE_WEB_SCAN_PHASE_KEYS:
            continue
        for row in block.get("rows") or []:
            if not isinstance(row, dict):
                continue
            fn = str(row.get("file_name") or "")
            for m in _ACTIVE_WEB_SCAN_TOOL_RE.finditer(fn):
                found.add(m.group(1).lower())
            if "va_active_scan" in fn.lower():
                found.add("va_active_scan")
    return sorted(found)


def _active_web_scan_artifact_rows_exist(scan_artifacts: dict[str, Any]) -> bool:
    blocks = scan_artifacts.get("phase_blocks") if isinstance(scan_artifacts, dict) else None
    if not isinstance(blocks, list):
        return False
    for block in blocks:
        if not isinstance(block, dict):
            continue
        pk = str(block.get("phase_key") or "").lower()
        if pk not in _ACTIVE_WEB_SCAN_PHASE_KEYS:
            continue
        rows = block.get("rows")
        if isinstance(rows, list) and len(rows) > 0:
            return True
    return False


def _active_web_scan_ai_summary_rows(
    ai_section_texts: dict[str, str],
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    skip_texts = frozenset({REPORT_AI_SKIPPED_NO_LLM, REPORT_AI_SKIPPED_GENERATION_FAILED})
    for key in _ACTIVE_WEB_SCAN_AI_KEYS_ORDERED:
        raw = ai_section_texts.get(key)
        if not isinstance(raw, str) or not raw.strip():
            continue
        if raw.strip() in skip_texts:
            continue
        label = _ACTIVE_WEB_SCAN_AI_LABELS.get(key, key)
        rows.append(
            {
                "section_key": key,
                "label": label,
                "text": _truncate_report_text(raw, _ACTIVE_WEB_SCAN_AI_SUMMARY_MAX_LEN),
            }
        )
    return rows


def build_active_web_scan_section_context(
    tier: str,
    scan_artifacts: dict[str, Any],
    ai_section_texts: dict[str, str],
) -> dict[str, Any]:
    """
    OWASP2-007 — Active web scanning: tools from artifacts, artifact block reference, brief AI context.
    """
    tier_norm = normalize_report_tier(tier)
    tools_run = _collect_active_web_scan_tool_names(scan_artifacts)
    ai_rows = _active_web_scan_ai_summary_rows(ai_section_texts)
    has_artifact_signal = _active_web_scan_artifact_rows_exist(scan_artifacts)
    has_signals = bool(tools_run) or bool(ai_rows) or has_artifact_signal
    placeholder_visible = {"midgard": False, "asgard": True, "valhalla": True}.get(
        tier_norm, False
    )
    visible = placeholder_visible or has_signals
    return {
        "visible": visible,
        "tier": tier_norm,
        "tools_run": tools_run,
        "artifacts_section_id": "scan-artifacts",
        "ai_summary_rows": ai_rows,
        "curl_xss_example": ACTIVE_WEB_SCAN_CURL_XSS_EXAMPLE,
        "has_signals": has_signals,
    }


@dataclass
class ReportContextBuildResult:
    """Outcome of ``ReportGenerator.build_context`` (no storage side effects)."""

    scan_report_data: ScanReportData
    template_context: dict[str, Any]
    ai_section_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    celery_task_ids: dict[str, str] | None = None


class ReportGenerator:
    """
    Collects ``ScanReportData``, runs or schedules RPT-004 AI sections by tier,
    and builds a Jinja-oriented context dict. Export bytes and object storage
    upload stay outside this class.
    """

    def __init__(self, collector: ReportDataCollector | None = None) -> None:
        self._collector = collector or ReportDataCollector()

    async def collect_scan_report_data(
        self,
        session: AsyncSession,
        tenant_id: str,
        scan_id: str,
        *,
        report_id: str | None = None,
        include_minio: bool = True,
    ) -> ScanReportData:
        return await self._collector.collect_async(
            session,
            tenant_id,
            scan_id,
            report_id=report_id,
            include_minio=include_minio,
        )

    @staticmethod
    def build_ai_input_payload(data: ScanReportData, *, tier: str | None = None) -> dict[str, Any]:
        """Compact, log-safe context for RPT-004 / VHL-003 prompts (no artifact bodies)."""
        severity_counts = severity_histogram_from_finding_rows(data.findings)
        executive_severity_totals = executive_severity_totals_from_finding_rows(data.findings)
        tier_norm = normalize_report_tier(
            tier if tier is not None else ((data.report.tier if data.report else "") or "midgard")
        )
        default_target = _default_scan_target_for_ai(data)
        findings_short: list[dict[str, Any]] = []
        for f in data.findings[:80]:
            item: dict[str, Any] = {
                "severity": f.severity,
                "title": (f.title or "")[:240],
                "cwe": f.cwe,
                "confidence": f.confidence,
                "validation_status": f.validation_status,
                "evidence_quality": f.evidence_quality,
                "evidence_refs": normalize_evidence_refs(f.evidence_refs)[:12],
            }
            ow_raw = f.owasp_category
            ow_parsed = (
                parse_owasp_category(ow_raw.strip())
                if isinstance(ow_raw, str) and ow_raw.strip()
                else None
            )
            if ow_parsed is not None:
                item["owasp_category"] = ow_parsed
            elif tier_norm == "valhalla" and isinstance(ow_raw, str) and ow_raw.strip():
                item["owasp_category"] = ow_raw.strip()[:32]
            poc = f.proof_of_concept
            poc_d: dict[str, Any] = poc if isinstance(poc, dict) else {}
            if tier_norm == "valhalla":
                if f.id:
                    item["finding_id"] = str(f.id)
                desc_ai = f.description or ""
                if desc_ai:
                    item["description"] = _truncate_report_text(
                        desc_ai, _VALHALLA_AI_FINDING_DESC_MAX
                    )
                item["cve_ids"] = _collect_cve_ids_for_ai_finding(
                    f.title or "",
                    f.description,
                    f.cwe,
                    poc_d,
                )
                item["exploit_available"] = derive_exploit_available_flag(
                    _finding_row_as_dict_for_exploit(f)
                )
                cv = getattr(f, "cvss_score", None)
                if cv is None:
                    cv = f.cvss
                item["cvss"] = float(cv) if isinstance(cv, (int, float)) else None
                item["cvss_score"] = item["cvss"]
                cvss_vec = poc_d.get("cvss_vector")
                if not cvss_vec and f.cwe:
                    estimated = estimate_cvss_vector(f.cwe)
                    if estimated:
                        cvss_vec = estimated.vector_string
                if isinstance(cvss_vec, str) and cvss_vec.strip():
                    item["cvss_vector"] = cvss_vec.strip()[:128]
                au, aa = _affected_url_asset_for_ai_payload(poc_d, default_target)
                if au:
                    item["affected_url"] = au
                if aa:
                    item["affected_asset"] = aa
                param_v = poc_d.get("parameter")
                if isinstance(param_v, str) and param_v.strip():
                    item["parameter"] = param_v.strip()[:512]
                cc = poc_d.get("curl_command")
                if isinstance(cc, str) and cc.strip():
                    item["poc_curl"] = _truncate_report_text(cc.strip(), _VALHALLA_AI_POC_MAX_LEN)
                pl = poc_d.get("payload")
                if isinstance(pl, str) and pl.strip():
                    item["poc_payload"] = _truncate_report_text(pl.strip(), _VALHALLA_AI_POC_MAX_LEN)
                js = poc_d.get("javascript_code")
                if isinstance(js, str) and js.strip():
                    item["poc_javascript"] = _truncate_report_text(js.strip(), _VALHALLA_AI_POC_MAX_LEN)
                req = poc_d.get("request")
                if isinstance(req, str) and req.strip():
                    item["poc_request"] = _truncate_report_text(req.strip(), _VALHALLA_AI_POC_MAX_LEN)
                sk = poc_d.get("screenshot_key")
                item["screenshot_present"] = bool(isinstance(sk, str) and sk.strip())
            elif isinstance(poc, dict):
                cc = poc.get("curl_command")
                if isinstance(cc, str) and cc.strip():
                    item["poc_curl"] = cc.strip()[:600]
                js = poc.get("javascript_code")
                if isinstance(js, str) and js.strip():
                    item["poc_javascript"] = js.strip()[:600]
                req = poc.get("request")
                if isinstance(req, str) and req.strip():
                    item["poc_request"] = req.strip()[:600]
            findings_short.append(item)
        cwe_ids_found = sorted(
            {f.cwe for f in data.findings if isinstance(f.cwe, str) and f.cwe.strip()}
        )
        tools_executed = sorted(
            {tr.tool_name for tr in data.tool_runs if tr.tool_name and tr.tool_name.strip()}
        )
        payload: dict[str, Any] = {
            "scan_id": data.scan_id,
            "tenant_id": data.tenant_id,
            "report_language": settings.report_language,
            "finding_count": len(data.findings),
            "severity_counts": severity_counts,
            "executive_severity_totals": executive_severity_totals,
            "findings": findings_short,
            "timeline_phases": [t.phase for t in data.timeline[:40]],
            "cwe_ids_found": cwe_ids_found,
            "tools_executed": tools_executed,
        }
        if data.scan is not None:
            payload["target_url"] = data.scan.target_url
            payload["scan_status"] = data.scan.status
            payload["scan_phase"] = data.scan.phase
            payload["scan_mode"] = getattr(data.scan, "scan_mode", "standard")
        if data.report is not None:
            payload["report_tier"] = data.report.tier
            payload["report_target"] = data.report.target
        owasp_summary = _owasp_summary_for_ai_payload(data.findings)
        if owasp_summary is not None:
            payload["owasp_summary"] = owasp_summary
        owasp_ref = _owasp_category_reference_for_ai(owasp_summary)
        if owasp_ref is not None:
            payload["owasp_category_reference"] = owasp_ref
            payload["owasp_category_reference_ru"] = owasp_ref
        payload["owasp_compliance_table"] = _owasp_compliance_table_for_ai(
            data, report_tier=tier_norm
        )
        quality_gate = build_report_quality_gate(data).as_dict()
        payload["report_quality_gate"] = quality_gate
        if tier_norm == "valhalla":
            compact_vc = _compact_valhalla_context_for_ai(data.valhalla_context)
            payload["valhalla_context"] = compact_vc
            vc = data.valhalla_context
            payload["tech_stack_structured"] = compact_vc.get("tech_stack_structured")
            payload["ssl_tls_analysis"] = compact_vc.get("ssl_tls")
            payload["security_headers_analysis"] = compact_vc.get("security_headers")
            payload["outdated_components_table"] = compact_vc.get("outdated_components")
            payload["robots_sitemap_analysis"] = compact_vc.get("robots_sitemap_analysis")
            fallback_messages = {
                "tech_stack": vc.tech_stack_fallback_message,
                "ssl_tls": vc.ssl_tls_fallback_message,
                "security_headers": vc.security_headers_fallback_message,
                "outdated_components": vc.outdated_components_fallback_message,
                "robots_sitemap": vc.robots_sitemap_fallback_message,
                "leaked_emails": vc.leaked_emails_fallback_message,
            }
            payload["valhalla_fallback_messages"] = fallback_messages
            # Backward-compatible key consumed by older Valhalla prompts/tests.
            payload["valhalla_fallback_messages_ru"] = fallback_messages
            hibp = data.hibp_pwned_password_summary
            if isinstance(hibp, dict) and hibp:
                payload["hibp_pwned_password_summary"] = hibp
        return payload

    def run_ai_sections_sync(
        self,
        tenant_id: str,
        scan_id: str,
        tier: str,
        data: ScanReportData,
        *,
        redis_client: Any | None = None,
        llm_callable: Callable[[str, dict], str] | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Invoke ``run_ai_text_generation`` for each tier section with cross-section dedup.

        ARGUS-008: each subsequent section receives a summary of previously generated sections
        so the LLM avoids duplication. After all sections are generated, ``AITextDeduplicator``
        removes any remaining duplicate sentences across sections.
        """
        tier_norm = normalize_report_tier(tier)
        payload = self.build_ai_input_payload(data, tier=tier_norm)
        results: dict[str, dict[str, Any]] = {}
        generated_summaries: dict[str, str] = {}

        for section_key in report_tier_sections(tier_norm):
            results[section_key] = run_ai_text_generation(
                tenant_id,
                scan_id,
                tier_norm,
                section_key,
                payload,
                redis_client=redis_client,
                llm_callable=llm_callable,
                other_sections_summary=generated_summaries if generated_summaries else None,
            )
            text = results[section_key].get("text", "")
            if isinstance(text, str) and text.strip() and results[section_key].get("status") == "ok":
                generated_summaries[section_key] = _first_n_sentences(text, 2)

        text_map = self.ai_results_to_text_map(results)
        if len(text_map) > 1:
            deduplicator = AITextDeduplicator()
            deduped = deduplicator.deduplicate_sections(text_map)
            for key, deduped_text in deduped.items():
                if key in results and results[key].get("text") != deduped_text:
                    results[key]["text"] = deduped_text

        return results

    def schedule_ai_sections_celery(
        self,
        tenant_id: str,
        scan_id: str,
        tier: str,
        data: ScanReportData,
    ) -> dict[str, str]:
        """Enqueue ``argus.ai_text_generation`` per section; returns Celery task ids."""
        from src.tasks import ai_text_generation_task

        tier_norm = normalize_report_tier(tier)
        payload = self.build_ai_input_payload(data, tier=tier_norm)
        ids: dict[str, str] = {}
        for section_key in report_tier_sections(tier_norm):
            async_result = ai_text_generation_task.delay(
                tenant_id,
                scan_id,
                tier_norm,
                section_key,
                payload,
            )
            ids[section_key] = async_result.id
        logger.info(
            "report_ai_sections_scheduled",
            extra={
                "event": "report_ai_sections_scheduled",
                "scan_id": scan_id,
                "tenant_id": tenant_id,
                "tier": tier_norm,
                "sections_n": len(ids),
            },
        )
        return ids

    @staticmethod
    def ai_results_to_text_map(ai_section_results: dict[str, dict[str, Any]]) -> dict[str, str]:
        out: dict[str, str] = {}
        for key, res in ai_section_results.items():
            text = res.get("text")
            if not isinstance(text, str) or not text.strip():
                continue
            st = res.get("status")
            err = res.get("error")
            if st == "ok" or st == "skipped_no_llm" or err in ("llm_unavailable", "generation_failed"):
                out[key] = text.strip()
        return out

    def resolve_celery_ai_results(
        self,
        celery_task_ids: dict[str, str],
        *,
        timeout: float = 300.0,
    ) -> dict[str, dict[str, Any]]:
        """Resolve Celery AI section tasks and apply cross-section dedup.

        Mirrors the dedup logic in ``run_ai_sections_sync`` for parity.
        Defensive: if any task fails or dedup errors, the report still generates.
        """
        from celery.result import AsyncResult

        results: dict[str, dict[str, Any]] = {}
        for section_key, task_id in celery_task_ids.items():
            try:
                res = AsyncResult(task_id)
                result = res.get(timeout=timeout)
                if isinstance(result, dict):
                    results[section_key] = result
                else:
                    results[section_key] = {
                        "text": str(result) if result else "",
                        "status": "ok",
                    }
            except Exception:
                logger.warning(
                    "celery_ai_task_resolve_failed",
                    extra={
                        "event": "celery_ai_task_resolve_failed",
                        "section_key": section_key,
                        "task_id": task_id,
                    },
                    exc_info=True,
                )
                results[section_key] = {
                    "text": REPORT_AI_SKIPPED_GENERATION_FAILED,
                    "status": "error",
                    "error": "celery_task_failed",
                }

        text_map = self.ai_results_to_text_map(results)
        if len(text_map) > 1:
            try:
                deduplicator = AITextDeduplicator()
                deduped = deduplicator.deduplicate_sections(text_map)
                for key, deduped_text in deduped.items():
                    if key in results and results[key].get("text") != deduped_text:
                        results[key]["text"] = deduped_text
            except Exception:
                logger.warning(
                    "ai_text_dedup_celery_failed",
                    extra={"event": "ai_text_dedup_celery_failed"},
                    exc_info=True,
                )

        return results

    def prepare_template_context(
        self,
        tier: str,
        data: ScanReportData,
        ai_section_texts: dict[str, str],
        *,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Pure Jinja context: scan/report snapshots, per-tier slot maps, and shared ``ai_sections``.

        Applies ``AITextDeduplicator`` as a safety net before fallback filling, ensuring
        dedup runs regardless of how AI texts were produced (sync or Celery).
        """
        tier_norm = normalize_report_tier(tier)
        texts: dict[str, str] = dict(ai_section_texts)
        if len(texts) > 1:
            try:
                deduplicator = AITextDeduplicator()
                texts = deduplicator.deduplicate_sections(texts)
            except Exception:
                logger.warning(
                    "ai_text_dedup_context_failed",
                    extra={"event": "ai_text_dedup_context_failed"},
                    exc_info=True,
                )
        for sk in report_tier_sections(tier_norm):
            if (texts.get(sk) or "").strip():
                continue
            texts[sk] = (
                REPORT_AI_SKIPPED_NO_LLM
                if not has_any_llm_key()
                else REPORT_AI_SKIPPED_GENERATION_FAILED
            )
        quality_gate = build_report_quality_gate(data)
        texts, ai_quality_warnings = sanitize_ai_sections_for_quality(
            texts,
            data,
            quality_gate,
            enforce_quality_gate=tier_norm == "valhalla",
        )
        for warning in ai_quality_warnings:
            if warning not in quality_gate.warnings:
                quality_gate.warnings.append(warning)
        extra_merged: dict[str, Any] = dict(extra) if extra else {}
        embed_key = "embed_poc_screenshot_inline"
        embed_override = extra_merged.pop(embed_key, None)
        if embed_override is not None:
            embed_poc_screenshot_inline = bool(embed_override)
        else:
            embed_poc_screenshot_inline = (
                True
                if tier_norm == "valhalla"
                else settings.report_poc_embed_screenshot_inline
            )
        jinja_tiers: dict[str, Any] = {}
        for name in ("midgard", "asgard", "valhalla"):
            keys = report_tier_sections(name)
            jinja_tiers[name] = {
                "active": name == tier_norm,
                "slots": {k: texts.get(k, "") for k in keys},
            }
        finding_rows = findings_rows_for_jinja(data, report_tier=tier_norm)
        severity_counts_ctx = executive_severity_totals_from_finding_rows(data.findings)
        v2021_owasp = tier_norm == "valhalla"
        ctx: dict[str, Any] = {
            "embed_poc_screenshot_inline": embed_poc_screenshot_inline,
            "tier": tier_norm,
            "tier_stubs": TIER_METADATA,
            "tenant_id": data.tenant_id,
            "scan_id": data.scan_id,
            "report_language": settings.report_language,
            "severity_counts": severity_counts_ctx,
            "scan": data.scan.model_dump(mode="json") if data.scan else None,
            "report": data.report.model_dump(mode="json") if data.report else None,
            "findings_count": len(data.findings),
            "timeline_count": len(data.timeline),
            "phase_inputs_count": len(data.phase_inputs),
            "phase_outputs_count": len(data.phase_outputs),
            "findings": finding_rows,
            "owasp_compliance_rows": build_owasp_compliance_rows(
                finding_rows,
                owasp_summary=data.owasp_summary if data.owasp_summary else None,
                wstg_coverage=data.valhalla_context.wstg_coverage,
                use_valhalla_owasp_2021_misconfig_labels=v2021_owasp,
            ),
            "valhalla_owasp_2021_labels": v2021_owasp,
            "owasp_top10_labels": OWASP_TOP10_2025_CATEGORY_TITLES,
            "recon_summary": recon_summary_for_jinja(data),
            "exploitation": exploitation_outputs_for_jinja(data),
            "valhalla_context": data.valhalla_context.model_dump(mode="json"),
            "wstg_coverage": data.valhalla_context.wstg_coverage,
            "test_limitations": data.valhalla_context.test_limitations,
            "report_executor_display_name": settings.report_executor_display_name,
            "tool_runs": [tr.model_dump(mode="json") for tr in data.tool_runs],
            "valhalla_appendix_nmap_excerpt": valhalla_nmap_appendix_excerpt(data.phase_outputs),
            "valhalla_appendix_phase_inputs_excerpt": valhalla_phase_inputs_config_excerpt(
                data.phase_inputs
            ),
            "valhalla_appendix_timeline_rows": valhalla_timeline_appendix_rows(data.timeline),
            "hibp_pwned_password_summary": data.hibp_pwned_password_summary,
            "report_quality": quality_gate.as_dict(),
            "ai_quality_warnings": ai_quality_warnings,
            "ai_sections": dict(texts),
            "jinja": jinja_tiers,
        }
        if extra_merged:
            ctx.update(extra_merged)
        if "scan_artifacts" not in ctx:
            ctx["scan_artifacts"] = {"status": "skipped", "phase_blocks": []}
        ctx["active_web_scan"] = build_active_web_scan_section_context(
            tier_norm,
            ctx["scan_artifacts"],
            texts,
        )
        if tier_norm == "valhalla":
            validate_hibp_pwned_password_summary_light(data.hibp_pwned_password_summary)

        _KNOWN_RU_FIELDS = frozenset({
            "owasp_category_reference",
        })
        report_language = ctx.get("report_language", "en")
        if report_language == "en":
            for key, val in ctx.items():
                if key in _KNOWN_RU_FIELDS:
                    continue
                if isinstance(val, str) and any("\u0400" <= c <= "\u04FF" for c in val):
                    logger.warning(
                        "cyrillic_text_in_en_report_context",
                        extra={"event": "cyrillic_text_in_en_report_context", "key": key},
                    )

        return ctx

    async def build_context(
        self,
        session: AsyncSession,
        tenant_id: str,
        scan_id: str,
        tier: str,
        *,
        report_id: str | None = None,
        include_minio: bool = True,
        sync_ai: bool = True,
        redis_client: Any | None = None,
        llm_callable: Callable[[str, dict], str] | None = None,
    ) -> ReportContextBuildResult:
        """
        Load scan graph + artifacts, then either run AI inline or schedule Celery tasks.
        Does not upload rendered artifacts (see ``src.reports.storage.upload`` at call site).
        """
        tier_norm = normalize_report_tier(tier)
        raw = await self.collect_scan_report_data(
            session,
            tenant_id,
            scan_id,
            report_id=report_id,
            include_minio=include_minio,
        )
        celery_ids: dict[str, str] | None = None
        ai_results: dict[str, dict[str, Any]] = {}
        if sync_ai:
            ai_results = self.run_ai_sections_sync(
                tenant_id,
                scan_id,
                tier_norm,
                raw,
                redis_client=redis_client,
                llm_callable=llm_callable,
            )
        else:
            celery_ids = self.schedule_ai_sections_celery(tenant_id, scan_id, tier_norm, raw)

        texts = self.ai_results_to_text_map(ai_results)
        scan_artifacts_ctx = build_scan_artifacts_section_context(
            tenant_id,
            scan_id,
            attempt_listing=include_minio,
        )
        template_context = self.prepare_template_context(
            tier_norm,
            raw,
            texts,
            extra={"scan_artifacts": scan_artifacts_ctx},
        )
        return ReportContextBuildResult(
            scan_report_data=raw,
            template_context=template_context,
            ai_section_results=ai_results,
            celery_task_ids=celery_ids,
        )

    @staticmethod
    def to_generator_report_data(
        data: ScanReportData,
        ai_section_texts: dict[str, str],
        *,
        report_id: str | None = None,
    ) -> ReportData:
        """Delegate to ``build_report_data_from_scan_report`` for HTML/JSON/PDF/CSV generators."""
        quality_gate = build_report_quality_gate(data)
        ai_section_texts, _warnings = sanitize_ai_sections_for_quality(
            dict(ai_section_texts),
            data,
            quality_gate,
            enforce_quality_gate=bool(data.report and data.report.tier == "valhalla"),
        )
        exec_key = (
            REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA
            if ai_section_texts.get(REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA)
            else REPORT_AI_SECTION_EXECUTIVE_SUMMARY
        )
        executive = (
            ai_section_texts.get(exec_key)
            or ai_section_texts.get(REPORT_AI_SECTION_EXECUTIVE_SUMMARY)
            or ai_section_texts.get(REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA)
        )
        rem = ai_section_texts.get(REPORT_AI_SECTION_REMEDIATION_STEP, "")
        remediation: list[str] = [rem] if rem else []
        insights = [t for t in ai_section_texts.values() if t]
        return build_report_data_from_scan_report(
            data,
            report_id=report_id,
            executive_summary=executive,
            remediation=remediation,
            ai_insights=insights,
        )


async def build_report_export_payload(
    session: AsyncSession,
    *,
    tenant_id: str,
    report_id: str,
    scan_id: str,
    tier: str | None,
    include_minio: bool = True,
    sync_ai: bool = True,
    redis_client: Any | None = None,
    generator: ReportGenerator | None = None,
) -> tuple[ReportData, dict[str, Any]]:
    """
    Canonical on-demand export: same chain as ``run_generate_report_pipeline`` —
    ``ReportGenerator.build_context`` → ``to_generator_report_data`` plus full ``template_context``.

    Callers must pass a tenant-scoped ``scan_id`` (e.g. from ``resolve_scan_id_for_report``).
    """
    from src.core.redis_client import get_redis

    gen = generator or ReportGenerator()
    # Hot paths should pass ``redis_client`` to avoid sync get_redis() in async code.
    redis = redis_client if redis_client is not None else get_redis()
    built = await gen.build_context(
        session,
        tenant_id,
        scan_id,
        tier,
        report_id=report_id,
        include_minio=include_minio,
        sync_ai=sync_ai,
        redis_client=redis,
    )
    texts = gen.ai_results_to_text_map(built.ai_section_results)
    report_data = gen.to_generator_report_data(
        built.scan_report_data,
        texts,
        report_id=report_id,
    )
    return report_data, built.template_context
