"""VHL-010 — Valhalla-tier full report pipeline: context assembly, AI generation, rendering.

Implements the complete Valhalla report lifecycle:
1. ValhallaReportContext — flat Pydantic model with ALL data for a Valhalla report
2. build_valhalla_context() — assembles context from phase outputs + DB
3. generate_valhalla_sections() — calls LLM for all 13 AI sections
4. render_valhalla_report() — renders HTML/Markdown
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import String, cast, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.orchestration.prompt_registry import (
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
    REPORT_AI_SECTION_KEYS,
    get_report_ai_section_prompt,
)
from src.reports.ai_text_generation import (
    REPORT_AI_SKIPPED_GENERATION_FAILED,
    REPORT_AI_SKIPPED_NO_LLM,
    AITextDeduplicator,
    build_ai_text_cache_key,
    canonical_payload_hash,
)
from src.llm.facade import call_llm_sync
from src.llm.task_router import LLMTask
from src.owasp_top10_2025 import (
    OWASP_TOP10_2025_CATEGORY_IDS,
    OWASP_TOP10_2025_CATEGORY_TITLES,
    parse_owasp_category,
)
from src.reports.generators import (
    build_owasp_compliance_rows,
)
from src.reports.report_quality_gate import (
    ReportQualityGate,
    build_report_quality_gate,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# VHL-010 — Valhalla AI section generation order (13 sections)
# ---------------------------------------------------------------------------

_VALHALLA_AI_SECTION_ORDER: tuple[str, ...] = (
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA,
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY,
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION,
    REPORT_AI_SECTION_REMEDIATION_STEP,
    REPORT_AI_SECTION_BUSINESS_RISK,
    REPORT_AI_SECTION_COMPLIANCE_CHECK,
    REPORT_AI_SECTION_PRIORITIZATION_ROADMAP,
    REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS,
    REPORT_AI_SECTION_ATTACK_SCENARIOS,
    REPORT_AI_SECTION_EXPLOIT_CHAINS,
    REPORT_AI_SECTION_REMEDIATION_STAGES,
    REPORT_AI_SECTION_ZERO_DAY_POTENTIAL,
    REPORT_AI_SECTION_COST_SUMMARY,
)

_SEVERITY_RANK: dict[str, int] = {
    "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4,
}

_FIRST_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z\u0410-\u042f\u0401])")

_CVE_IDS_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _first_n_sentences(text: str, n: int = 2, max_len: int = 300) -> str:
    if not text or not text.strip():
        return ""
    normalized = " ".join(text.split())
    sentences = _FIRST_SENTENCE_RE.split(normalized)
    result = " ".join(sentences[:n]).strip()
    if len(result) > max_len:
        return result[: max_len - 1].rstrip() + "\u2026"
    return result


def _truncate(text: str, max_len: int) -> str:
    t = (text or "").strip()
    if len(t) <= max_len:
        return t
    return t[: max_len - 1].rstrip() + "\u2026"


# ---------------------------------------------------------------------------
# 1. ValhallaReportContext — flat Pydantic model for report pipeline
# ---------------------------------------------------------------------------


class ValhallaReportContext(BaseModel):
    """Complete context for Valhalla-tier report generation.

    Flattened from scan phase outputs, DB state, and structured analysis.
    All fields are JSON-serialisable for AI prompt injection and rendering.
    """

    engagement_title: str = "Valhalla Automated Security Assessment"
    target_url: str = ""
    scan_id: str = ""
    tenant_id: str = ""
    report_tier: str = "valhalla"
    generated_at: str = ""

    # Phase outputs
    recon_summary: dict[str, Any] = Field(default_factory=dict)
    threat_model: dict[str, Any] = Field(default_factory=dict)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    exploits: list[dict[str, Any]] = Field(default_factory=list)
    post_exploitation: dict[str, Any] = Field(default_factory=dict)

    # Structured data
    severity_counts: dict[str, int] = Field(
        default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    )
    finding_count: int = 0
    tech_stack_structured: dict[str, Any] = Field(default_factory=dict)
    ssl_tls_analysis: dict[str, Any] = Field(default_factory=dict)
    security_headers_analysis: dict[str, Any] = Field(default_factory=dict)
    outdated_components_table: list[dict[str, Any]] = Field(default_factory=list)
    robots_sitemap_analysis: dict[str, Any] = Field(default_factory=dict)
    owasp_compliance_table: list[dict[str, Any]] = Field(default_factory=list)
    owasp_summary: dict[str, Any] = Field(default_factory=dict)
    risk_matrix: dict[str, Any] = Field(default_factory=dict)
    critical_vulns: list[dict[str, Any]] = Field(default_factory=list)
    xss_structured: list[dict[str, Any]] = Field(default_factory=list)
    threat_model_excerpt: str = ""
    exploitation_post_excerpt: str = ""
    hibp_pwned_password_summary: dict[str, Any] | None = None
    report_quality_gate: dict[str, Any] = Field(default_factory=dict)
    coverage: dict[str, Any] = Field(default_factory=dict)
    tool_errors_summary: dict[str, Any] = Field(default_factory=dict)
    tools_executed: list[str] = Field(default_factory=list)
    executive_severity_totals: dict[str, int] = Field(default_factory=dict)

    # Valhalla-specific
    attack_scenarios: list[dict[str, Any]] = Field(default_factory=list)
    exploit_chains: list[dict[str, Any]] = Field(default_factory=list)
    remediation_stages: dict[str, Any] = Field(default_factory=dict)
    zero_day_assessment: dict[str, Any] = Field(default_factory=dict)
    cost_summary: dict[str, Any] = Field(default_factory=dict)

    # AI-generated section texts
    ai_sections: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# 2. build_valhalla_context() — assembles context from all phase outputs + DB
# ---------------------------------------------------------------------------


def _counts_from_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        s = (f.get("severity") or "").lower()
        if s == "informational":
            s = "info"
        if s in counts:
            counts[s] += 1
    return counts


def _build_owasp_compliance_table(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows_dicts: list[dict[str, Any]] = []
    for f in findings:
        rows_dicts.append(
            {
                "severity": f.get("severity", ""),
                "title": f.get("title", ""),
                "description": f.get("description", ""),
                "cwe": f.get("cwe"),
                "owasp_category": f.get("owasp_category"),
                "evidence_refs": f.get("evidence_refs", []),
            }
        )
    return build_owasp_compliance_rows(
        rows_dicts,
        use_valhalla_owasp_2021_misconfig_labels=True,
    )


def _build_risk_matrix(findings: list[dict[str, Any]]) -> dict[str, Any]:
    cells: dict[tuple[str, str], list[str]] = {}
    for i, f in enumerate(findings):
        impact = _estimate_impact(f)
        likelihood = _estimate_likelihood(f)
        key = (impact, likelihood)
        if key not in cells:
            cells[key] = []
        fid = f.get("id") or f.get("finding_id") or f"F{i:04d}"
        cells[key].append(str(fid)[:64])
    cell_list: list[dict[str, Any]] = []
    for (impact, likelihood), fids in sorted(cells.items()):
        cell_list.append(
            {
                "impact": impact,
                "likelihood": likelihood,
                "count": len(fids),
                "finding_ids": fids[:32],
            }
        )
    return {
        "variant": "matrix",
        "cells": cell_list,
        "distribution": [],
    }


def _estimate_impact(f: dict[str, Any]) -> str:
    sev = (f.get("severity") or "").lower()
    cvss = f.get("cvss") or f.get("cvss_score")
    if isinstance(cvss, (int, float)):
        if cvss >= 9.0:
            return "high"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        return "low"
    if sev in ("critical", "high"):
        return "high"
    if sev == "medium":
        return "medium"
    return "low"


def _estimate_likelihood(f: dict[str, Any]) -> str:
    confidence = (f.get("confidence") or "").lower()
    if confidence in ("confirmed", "likely"):
        return "high"
    if confidence == "possible":
        return "medium"
    return "low"


def _collect_critical_vulns(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in findings:
        sev = (f.get("severity") or "").lower()
        cvss = f.get("cvss") or f.get("cvss_score")
        if sev == "critical" or (isinstance(cvss, (int, float)) and cvss >= 9.0):
            poc = f.get("proof_of_concept") or {}
            poc_v = None
            cve_refs: list[str] = []
            if isinstance(poc, dict):
                poc_v = poc.get("payload") or poc.get("curl_command")
                for v in poc.values():
                    if isinstance(v, str):
                        cve_refs.extend(_CVE_IDS_RE.findall(v))
            out.append(
                {
                    "vuln_id": str(f.get("id") or f.get("finding_id") or ""),
                    "title": _truncate(str(f.get("title") or ""), 500),
                    "description": _truncate(str(f.get("description") or ""), 400),
                    "cvss": float(cvss) if isinstance(cvss, (int, float)) else None,
                    "cvss_vector": poc.get("cvss_vector") if isinstance(poc, dict) else None,
                    "exploit_available": bool(f.get("exploit_demonstrated")),
                    "exploit_demonstrated": bool(f.get("exploit_demonstrated")),
                    "severity": sev,
                    "payload": poc_v if isinstance(poc_v, str) else None,
                    "cves": sorted(set(cve_refs))[:8],
                }
            )
    return out


def _build_xss_structured(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in findings:
        cwe = str(f.get("cwe") or "").upper()
        title_l = str(f.get("title") or "").lower()
        is_xss = "79" in cwe or "xss" in title_l or "cross-site" in title_l
        if not is_xss:
            continue
        poc = f.get("proof_of_concept")
        if not isinstance(poc, dict):
            continue
        out.append(
            {
                "finding_id": str(f.get("id") or f.get("finding_id") or ""),
                "title": _truncate(str(f.get("title") or ""), 300),
                "parameter": _truncate(str(poc.get("parameter") or ""), 256) or None,
                "payload_entered": _truncate(str(poc.get("payload_entered") or poc.get("payload") or ""), 600) or None,
                "payload_reflected": _truncate(str(poc.get("payload_reflected") or ""), 600) or None,
                "payload_used": _truncate(str(poc.get("payload_used") or ""), 600) or None,
                "reflection_context": _truncate(str(poc.get("reflection_context") or poc.get("context") or ""), 400) or None,
                "verification_method": _truncate(str(poc.get("verification_method") or ""), 128) or None,
                "verified_via_browser": poc.get("verified_via_browser"),
                "browser_alert_text": _truncate(str(poc.get("browser_alert_text") or ""), 400) or None,
                "artifact_keys": [str(k)[:512] for k in poc.get("artifact_keys", []) if k][:16],
                "artifact_urls": [str(u)[:1024] for u in poc.get("artifact_urls", []) if u][:8],
            }
        )
        if len(out) >= 40:
            break
    return out


def _build_attack_scenarios(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    validated = [f for f in findings if f.get("confidence") in ("confirmed", "likely")
                 and f.get("evidence_quality") in ("strong", "moderate")]
    if len(validated) < 2:
        return []
    critical = [f for f in validated if (f.get("severity") or "").lower() in ("critical", "high")]
    if not critical:
        critical = validated[:2]
    scenarios: list[dict[str, Any]] = []
    for i in range(0, min(len(critical), 3), 1):
        chain: list[str] = []
        idx = i
        for _ in range(min(2, len(validated))):
            chain.append(str(critical[idx % len(critical)].get("title") or ""))
            idx += 1
        scenarios.append(
            {
                "index": i + 1,
                "title": f"Attack Scenario {i + 1}",
                "chained_findings": chain,
                "persona": "Targeted attacker",
                "likelihood": "Medium",
                "likelihood_reasoning": "Validated findings chain through the attack surface",
                "impact_summary": "Potential for privilege escalation or data exposure via chained exploitation.",
            }
        )
    return scenarios


def _build_exploit_chains(exploits: list[dict[str, Any]], findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    verified = [e for e in exploits if e.get("status") in ("verified", "executed")]
    chains: list[dict[str, Any]] = []
    for i, ex in enumerate(verified[:4], 1):
        fid = ex.get("finding_id", "")
        matched = next((f for f in findings if f.get("id") == fid or f.get("finding_id") == fid), None)
        chains.append(
            {
                "index": i,
                "title": ex.get("title", f"Exploit Chain {i}"),
                "finding_id": fid,
                "technique": ex.get("technique", ""),
                "tool": ex.get("tool", ""),
                "status": ex.get("status", ""),
                "impact": ex.get("impact", ""),
                "difficulty": ex.get("difficulty", "medium"),
                "matched_finding": matched.get("title") if matched else None,
            }
        )
    return chains


def _build_remediation_stages(findings: list[dict[str, Any]]) -> dict[str, Any]:
    critical = [f for f in findings if (f.get("severity") or "").lower() in ("critical", "high")]
    high_cvss = [f for f in findings
                 if isinstance((f.get("cvss") or f.get("cvss_score")), (int, float))
                 and float(f.get("cvss") or f.get("cvss_score") or 0) >= 7.0]
    medium = [f for f in findings if (f.get("severity") or "").lower() == "medium"]

    tier1: list[dict[str, Any]] = []
    for f in (critical + [h for h in high_cvss if h not in critical])[:8]:
        tier1.append(
            {
                "finding_id": str(f.get("id") or ""),
                "title": str(f.get("title") or ""),
                "severity": f.get("severity"),
                "effort": "Complex Refactor" if f.get("description") and len(str(f.get("description") or "")) > 800 else "Moderate",
                "deadline": "48 hours",
            }
        )

    tier2: list[dict[str, Any]] = []
    for f in medium[:6]:
        tier2.append(
            {
                "finding_id": str(f.get("id") or ""),
                "title": str(f.get("title") or ""),
                "severity": f.get("severity"),
                "effort": "Quick Fix",
                "deadline": "2 weeks",
            }
        )

    tier3: list[dict[str, Any]] = [
        {"category": "SDLC", "action": "Integrate security testing into CI/CD pipeline", "effort": "Complex Refactor"},
        {"category": "Monitoring", "action": "Deploy WAF and centralized logging", "effort": "Moderate"},
        {"category": "Dependencies", "action": "Implement automated dependency scanning and SBOM generation", "effort": "Moderate"},
    ]

    return {
        "tier_1_immediate": tier1,
        "tier_2_short_term": tier2,
        "tier_3_architectural": tier3,
    }


def _build_zero_day_assessment(findings: list[dict[str, Any]]) -> dict[str, Any]:
    non_standard = 0
    for f in findings:
        cwe = str(f.get("cwe") or "").upper()
        title = str(f.get("title") or "").lower()
        if any(kw in title for kw in ("custom", "proprietary", "unusual", "non-standard")):
            non_standard += 1
    rating = "Low"
    if non_standard >= 2:
        rating = "Medium"
    elif non_standard >= 5:
        rating = "High"
    return {
        "rating": rating,
        "non_standard_attack_surfaces": non_standard,
        "notes": "Assessment based on finding CWE/title patterns. Manual review recommended for novel attack surfaces.",
        "chaining_potential": any(
            (f.get("severity") or "").lower() in ("low", "medium")
            and f.get("confidence") == "confirmed"
            for f in findings
        ),
    }


async def build_valhalla_report_context(
    scan_id: str,
    tenant_id: str,
    *,
    recon_output: dict[str, Any] | None = None,
    threat_model_output: dict[str, Any] | None = None,
    findings: list[dict[str, Any]] | None = None,
    exploitation_output: dict[str, Any] | None = None,
    post_exploitation_output: dict[str, Any] | None = None,
    session: Any = None,
) -> ValhallaReportContext:
    """Build complete Valhalla context from all scan phase outputs and DB state.

    When ``session`` is provided (SQLAlchemy AsyncSession), this function loads
    finding records and scan metadata from the DB to supplement or replace the
    passed-in ``findings`` list. Otherwise it relies entirely on the kwargs.
    """
    now_iso = datetime.utcnow().isoformat() + "Z"

    resolved_findings: list[dict[str, Any]] = list(findings or [])
    # Load from DB when session is available
    if session is not None and isinstance(session, AsyncSession):
        try:
            from src.db.models import Finding as FindingModel
            result = await session.execute(
                select(FindingModel).where(
                    cast(FindingModel.scan_id, String) == str(scan_id),
                    cast(FindingModel.tenant_id, String) == str(tenant_id),
                )
            )
            db_findings = list(result.scalars().all())
            if db_findings:
                resolved_findings = [
                    {
                        "id": str(getattr(f, "id", "")),
                        "finding_id": str(getattr(f, "id", "")),
                        "severity": getattr(f, "severity", "info"),
                        "title": getattr(f, "title", ""),
                        "description": getattr(f, "description", ""),
                        "cwe": getattr(f, "cwe", None),
                        "cvss": getattr(f, "cvss", None),
                        "cvss_score": getattr(
                            f, "cvss_score", getattr(f, "cvss", None)
                        ),
                        "cvss_vector": getattr(f, "cvss_vector", None),
                        "exploit_demonstrated": bool(
                            getattr(f, "exploit_demonstrated", False)
                        ),
                        "exploit_summary": getattr(f, "exploit_summary", None),
                        "owasp_category": getattr(f, "owasp_category", None),
                        "proof_of_concept": (
                            getattr(f, "proof_of_concept", {})
                            if isinstance(getattr(f, "proof_of_concept", None), dict)
                            else {}
                        ),
                        "confidence": getattr(f, "confidence", "likely"),
                        "validation_status": getattr(f, "validation_status", "unverified"),
                        "evidence_quality": getattr(f, "evidence_quality", "none"),
                        "evidence_type": getattr(f, "evidence_type", None),
                        "evidence_refs": list(
                            getattr(f, "evidence_refs", []) or []
                        ),
                        "reproducible_steps": getattr(f, "reproducible_steps", None),
                        "applicability_notes": getattr(f, "applicability_notes", None),
                    }
                    for f in db_findings
                ]
        except Exception:
            logger.debug(
                "valhalla_ctx_db_findings_load_failed",
                extra={"scan_id": scan_id, "tenant_id": tenant_id},
                exc_info=True,
            )

    rec = recon_output or {}
    tm = threat_model_output or {}
    exp_out = exploitation_output or {}
    pe = post_exploitation_output or {}

    sev_counts = _counts_from_findings(resolved_findings)
    exec_totals = dict(sev_counts)

    target = str(rec.get("target_url") or rec.get("target") or "")
    engagement_title = "Valhalla Penetration Test Assessment"

    # Tech stack from recon output
    tech_stack: dict[str, Any] = {}
    if isinstance(rec, dict):
        tech_data = rec.get("tech_stack") or rec.get("tech_profile") or rec.get("technologies")
        if isinstance(tech_data, dict):
            tech_stack = tech_data
        elif isinstance(tech_data, list):
            tech_stack = {"entries": tech_data}
        if target and not tech_stack.get("web_server"):
            tech_stack["web_server"] = target

    # OWASP compliance
    owasp_compliance = _build_owasp_compliance_table(resolved_findings)

    # OWASP summary
    owasp_counts: dict[str, int] = dict.fromkeys(OWASP_TOP10_2025_CATEGORY_IDS, 0)
    for f in resolved_findings:
        oc = f.get("owasp_category")
        if isinstance(oc, str) and oc in owasp_counts:
            owasp_counts[oc] += 1
    ow_sum = {"counts": owasp_counts, "gap_categories": [
        c for c in OWASP_TOP10_2025_CATEGORY_IDS if owasp_counts.get(c, 0) == 0
    ], "classified_finding_count": sum(1 for f in resolved_findings
                                       if f.get("owasp_category") in OWASP_TOP10_2025_CATEGORY_IDS),
       "unclassified_finding_count": sum(1 for f in resolved_findings
                                         if f.get("owasp_category") not in OWASP_TOP10_2025_CATEGORY_IDS)}

    risk_m = _build_risk_matrix(resolved_findings)
    crit_v = _collect_critical_vulns(resolved_findings)
    xss_s = _build_xss_structured(resolved_findings)
    attack_s = _build_attack_scenarios(resolved_findings)

    # Exploits
    exploits_list: list[dict[str, Any]] = []
    if isinstance(exp_out, dict):
        ex_list = exp_out.get("exploits") or exp_out.get("exploits_list") or []
        if isinstance(ex_list, list):
            exploits_list = [dict(e) for e in ex_list if isinstance(e, dict)]

    exploit_chains_list = _build_exploit_chains(exploits_list, resolved_findings)
    remediation_stages = _build_remediation_stages(resolved_findings)
    zero_day = _build_zero_day_assessment(resolved_findings)

    ssl_tls: dict[str, Any] = {}
    if isinstance(rec, dict):
        ssl_tls = rec.get("ssl_tls") or rec.get("ssl_analysis") or {}

    headers: dict[str, Any] = {}
    if isinstance(rec, dict):
        headers = rec.get("security_headers") or rec.get("headers_analysis") or {}

    outdated: list[dict[str, Any]] = []
    if isinstance(rec, dict):
        outdated = rec.get("outdated_components") or rec.get("outdated_deps") or []

    robots_sitemap: dict[str, Any] = {}
    if isinstance(rec, dict):
        robots_sitemap = rec.get("robots_sitemap") or rec.get("robots_analysis") or {}

    threat_excerpt = ""
    if isinstance(tm, dict):
        threat_excerpt = _truncate(
            str(tm.get("excerpt") or json.dumps(tm, default=str)[:2000]),
            2000,
        )

    exploit_excerpt = ""
    if isinstance(exp_out, dict):
        exploit_excerpt = _truncate(json.dumps(exp_out, default=str)[:2500], 2500)

    hibp_summary: dict[str, Any] | None = None
    if isinstance(pe, dict):
        hibp_raw = pe.get("hibp") or pe.get("pwned_passwords")
        if isinstance(hibp_raw, dict) and hibp_raw:
            hibp_summary = hibp_raw

    tool_list: list[str] = sorted(
        {str(f.get("evidence_type") or "").lower()
         for f in resolved_findings if f.get("evidence_type")}
    )

    qg: dict[str, Any] = {
        "warnings": [],
        "wstg_coverage_pct": 0.0,
        "wstg_low_coverage": False,
        "critical_scanner_failed": False,
        "failed_domains": {},
        "scan_type": "standard",
        "authenticated": False,
        "coverage_label": "partial",
        "tool_health": "healthy",
        "evidence_confidence": "moderate",
        "report_mode_label": "Automated security assessment",
        "section_status": {},
        "injection_evidence_fail": False,
        "injection_evidence_warnings": [],
        "injection_finding_gates": [],
        "active_injection_coverage": {},
    }

    coverage_dict: dict[str, Any] = {
        "phases_executed": list(
            {str(f.get("evidence_type") or "recon") for f in resolved_findings}
        ),
    }

    tool_errors: dict[str, Any] = {"errors": []}

    cost_summary: dict[str, Any] = {
        "total_calls": 0,
        "total_tokens": 0,
        "total_cost_usd": 0.0,
        "by_provider": {},
        "by_model": {},
        "scan_id": str(scan_id),
        "tenant_id": str(tenant_id),
    }

    return ValhallaReportContext(
        engagement_title=engagement_title,
        target_url=str(target)[:2048],
        scan_id=str(scan_id),
        tenant_id=str(tenant_id),
        report_tier="valhalla",
        generated_at=now_iso,
        recon_summary=dict(rec) if isinstance(rec, dict) else {},
        threat_model=dict(tm) if isinstance(tm, dict) else {},
        findings=resolved_findings,
        exploits=exploits_list,
        post_exploitation=dict(pe) if isinstance(pe, dict) else {},
        severity_counts=sev_counts,
        finding_count=len(resolved_findings),
        tech_stack_structured=tech_stack,
        ssl_tls_analysis=ssl_tls,
        security_headers_analysis=headers,
        outdated_components_table=outdated,
        robots_sitemap_analysis=robots_sitemap,
        owasp_compliance_table=owasp_compliance,
        owasp_summary=ow_sum,
        risk_matrix=risk_m,
        critical_vulns=crit_v,
        xss_structured=xss_s,
        threat_model_excerpt=threat_excerpt,
        exploitation_post_excerpt=exploit_excerpt,
        hibp_pwned_password_summary=hibp_summary,
        report_quality_gate=qg,
        coverage=coverage_dict,
        tool_errors_summary=tool_errors,
        tools_executed=tool_list,
        executive_severity_totals=exec_totals,
        attack_scenarios=attack_s,
        exploit_chains=exploit_chains_list,
        remediation_stages=remediation_stages,
        zero_day_assessment=zero_day,
        cost_summary=cost_summary,
    )


# ---------------------------------------------------------------------------
# 3. generate_valhalla_sections() — LLM for all 13 Valhalla AI sections
# ---------------------------------------------------------------------------


def _valhalla_ai_payload(context: ValhallaReportContext) -> dict[str, Any]:
    """Compact JSON payload for Valhalla AI section prompts."""
    return {
        "engagement_title": context.engagement_title,
        "scan_id": context.scan_id,
        "tenant_id": context.tenant_id,
        "target_url": context.target_url,
        "report_tier": "valhalla",
        "executive_severity_totals": context.executive_severity_totals,
        "severity_counts": context.severity_counts,
        "finding_count": context.finding_count,
        "findings": [
            {
                "finding_id": f.get("id") or f.get("finding_id", ""),
                "severity": f.get("severity", ""),
                "title": f.get("title", ""),
                "description": _truncate(str(f.get("description") or ""), 400),
                "cwe": f.get("cwe"),
                "cvss": f.get("cvss") or f.get("cvss_score"),
                "confidence": f.get("confidence"),
                "validation_status": f.get("validation_status"),
                "evidence_quality": f.get("evidence_quality"),
                "owasp_category": f.get("owasp_category"),
                "exploit_demonstrated": f.get("exploit_demonstrated"),
            }
            for f in context.findings[:60]
        ],
        "owasp_compliance_table": context.owasp_compliance_table,
        "owasp_summary": context.owasp_summary,
        "risk_matrix": context.risk_matrix,
        "critical_vulns": context.critical_vulns,
        "tech_stack_structured": context.tech_stack_structured,
        "ssl_tls_analysis": context.ssl_tls_analysis,
        "security_headers_analysis": context.security_headers_analysis,
        "outdated_components_table": context.outdated_components_table,
        "robots_sitemap_analysis": context.robots_sitemap_analysis,
        "threat_model_excerpt": context.threat_model_excerpt,
        "exploitation_post_excerpt": context.exploitation_post_excerpt,
        "xss_structured": context.xss_structured,
        "hibp_pwned_password_summary": context.hibp_pwned_password_summary,
        "report_quality_gate": context.report_quality_gate,
        "tools_executed": context.tools_executed,
        "attack_scenarios": context.attack_scenarios,
        "exploit_chains": context.exploit_chains,
        "remediation_stages": context.remediation_stages,
        "zero_day_assessment": context.zero_day_assessment,
        "cost_summary": context.cost_summary,
    }


async def generate_valhalla_sections(
    context: ValhallaReportContext,
    *,
    llm_callable: Callable[[str, dict], str] | None = None,
) -> dict[str, str]:
    """Generate all Valhalla AI report sections (13 sections).

    Each subsequent section receives summaries of already-generated sections
    to prevent content duplication. After all sections are generated,
    ``AITextDeduplicator`` removes any remaining duplicate sentences.

    Returns ``{section_key: generated_text}``.
    """
    from src.core.llm_config import has_any_llm_key

    payload = _valhalla_ai_payload(context)
    generated: dict[str, str] = {}
    generated_summaries: dict[str, str] = {}

    for section_key in _VALHALLA_AI_SECTION_ORDER:
        if section_key not in REPORT_AI_SECTION_KEYS:
            logger.warning(
                "valhalla_ai_unknown_section",
                extra={"section_key": section_key},
            )
            continue

        if llm_callable is None and not has_any_llm_key():
            generated[section_key] = REPORT_AI_SKIPPED_NO_LLM
            continue

        try:
            system_prompt, user_prompt, prompt_version = get_report_ai_section_prompt(
                section_key, payload, other_sections_summary=generated_summaries or None
            )
        except Exception:
            logger.warning(
                "valhalla_ai_prompt_build_failed",
                extra={"section_key": section_key},
                exc_info=True,
            )
            generated[section_key] = REPORT_AI_SKIPPED_GENERATION_FAILED
            continue

        try:
            if llm_callable is not None:
                combined = f"{system_prompt}\n\n{user_prompt}"
                text = (llm_callable(combined, {"task": section_key, "tier": "valhalla"}) or "").strip()
            else:
                text = call_llm_sync(
                    system_prompt,
                    user_prompt,
                    task=LLMTask.REPORT_SECTION,
                    scan_id=context.scan_id,
                    phase="reporting",
                ).strip()
        except Exception:
            logger.warning(
                "valhalla_ai_generation_failed",
                extra={"section_key": section_key},
                exc_info=True,
            )
            generated[section_key] = REPORT_AI_SKIPPED_GENERATION_FAILED
            continue

        if not text:
            generated[section_key] = REPORT_AI_SKIPPED_GENERATION_FAILED
            continue

        generated[section_key] = text
        generated_summaries[section_key] = _first_n_sentences(text, 2)

    # Cross-section deduplication
    if len(generated) > 1:
        try:
            deduplicator = AITextDeduplicator()
            deduped = deduplicator.deduplicate_sections(generated)
            generated = deduped
        except Exception:
            logger.warning(
                "valhalla_ai_dedup_failed",
                exc_info=True,
            )

    # Store in context
    context.ai_sections = dict(generated)
    return dict(generated)


# ---------------------------------------------------------------------------
# 4. render_valhalla_report() — HTML / Markdown rendering
# ---------------------------------------------------------------------------


def _css_severity_bar_chart(sev_counts: dict[str, int]) -> str:
    """Inline CSS bar chart for severity distribution."""
    total = max(1, sum(sev_counts.values()))
    order = [("critical", "#dc3545"), ("high", "#fd7e14"), ("medium", "#ffc107"), ("low", "#28a745"), ("info", "#17a2b8")]
    bars: list[str] = []
    for label, color in order:
        count = sev_counts.get(label, 0)
        pct = (count / total) * 100
        bars.append(
            f'<div class="chart-row">'
            f'<span class="chart-label">{label.title()}</span>'
            f'<div class="chart-bar-wrapper"><div class="chart-bar" style="width:{pct:.1f}%;background:{color}"></div></div>'
            f'<span class="chart-count">{count}</span>'
            f"</div>"
        )
    return "\n".join(bars)


def _findings_table_html(findings: list[dict[str, Any]]) -> str:
    """Sortable findings table for Valhalla HTML report."""
    sorted_f = sorted(findings, key=lambda f: _SEVERITY_RANK.get((f.get("severity") or "").lower(), 99))
    rows: list[str] = []
    badge: dict[str, str] = {
        "critical": '<span class="badge badge-critical">CRITICAL</span>',
        "high": '<span class="badge badge-high">HIGH</span>',
        "medium": '<span class="badge badge-medium">MEDIUM</span>',
        "low": '<span class="badge badge-low">LOW</span>',
        "info": '<span class="badge badge-info">INFO</span>',
        "informational": '<span class="badge badge-info">INFO</span>',
    }
    for f in sorted_f:
        sev = (f.get("severity") or "info").lower()
        b = badge.get(sev, badge["info"])
        cvss = f.get("cvss") or f.get("cvss_score")
        cvss_str = f"{float(cvss):.1f}" if isinstance(cvss, (int, float)) else "—"
        rows.append(
            "<tr>"
            f"<td>{b}</td>"
            f"<td>{f.get('title', '')}</td>"
            f"<td>{f.get('cwe', '—')}</td>"
            f"<td>{cvss_str}</td>"
            f"<td>{f.get('confidence', '—')}</td>"
            f"<td>{f.get('evidence_quality', '—')}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _render_ai_section(key: str, context: ValhallaReportContext) -> str:
    """Render a single AI section block with proper heading."""
    label_map: dict[str, str] = {
        REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA: "Executive Summary",
        REPORT_AI_SECTION_EXECUTIVE_SUMMARY: "Executive Summary — Business Brief",
        REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION: "Vulnerability Description",
        REPORT_AI_SECTION_REMEDIATION_STEP: "Remediation Steps",
        REPORT_AI_SECTION_BUSINESS_RISK: "Business Risk Assessment",
        REPORT_AI_SECTION_COMPLIANCE_CHECK: "Compliance Mapping",
        REPORT_AI_SECTION_PRIORITIZATION_ROADMAP: "Prioritization Roadmap",
        REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS: "Hardening Recommendations",
        REPORT_AI_SECTION_ATTACK_SCENARIOS: "Attack Scenarios",
        REPORT_AI_SECTION_EXPLOIT_CHAINS: "Exploit Chains",
        REPORT_AI_SECTION_REMEDIATION_STAGES: "Remediation Stages",
        REPORT_AI_SECTION_ZERO_DAY_POTENTIAL: "Zero-Day Potential Assessment",
        REPORT_AI_SECTION_COST_SUMMARY: "Cost Summary",
    }
    label = label_map.get(key, key.replace("_", " ").title())
    text = context.ai_sections.get(key, "") or "(No AI-generated content for this section.)"
    text_safe = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text_html = text_safe.replace("\n\n", "</p><p>").replace("\n", "<br>")
    return (
        f'<section id="section-{key}" class="ai-section">'
        f"<h2>{label}</h2>"
        f"<div class=\"ai-content\"><p>{text_html}</p></div>"
        f"</section>"
    )


def render_valhalla_report(
    context: ValhallaReportContext,
    *,
    format: str = "html",
    output_path: str | None = None,
) -> bytes:
    """Render Valhalla report in the specified format.

    ``format`` supports:
    - ``"html"`` — full HTML document with dark-theme ARGUS branding
    - ``"md"`` — Markdown output (plain, for archival)

    When ``output_path`` is provided, writes the rendered bytes to disk
    and returns them.
    """
    if format == "md":
        return _render_valhalla_markdown(context)

    # Full Valhalla HTML
    # Compute OWASP compliance rows from the OWASP table already built
    owasp_rows = context.owasp_compliance_table
    owasp_table_html = ""
    for r in owasp_rows:
        cls = r.get("row_class", "")
        owasp_table_html += (
            "<tr>"
            f"<td>{r.get('category_id', '')}</td>"
            f"<td>{r.get('title', '')}</td>"
            f"<td>{r.get('assessed', '')}</td>"
            f"<td>{r.get('findings_present', '0')}</td>"
            f"<td class=\"{cls}\">{r.get('assessment_result', '')}</td>"
            "</tr>"
        )

    # Critical findings section
    crit_rows_html = ""
    for v in context.critical_vulns[:24]:
        crit_rows_html += (
            "<tr>"
            f"<td><span class=\"badge badge-critical\">CRITICAL</span></td>"
            f"<td>{v.get('title', '')}</td>"
            f"<td>{v.get('cvss', '—')}</td>"
            f"<td>{'Yes' if v.get('exploit_available') else '—'}</td>"
            "</tr>"
        )

    # All AI sections
    ai_sections_html = ""
    for key in _VALHALLA_AI_SECTION_ORDER:
        ai_sections_html += _render_ai_section(key, context) + "\n"

    # Attack scenarios structured
    attack_table_html = ""
    for s in context.attack_scenarios:
        attack_table_html += (
            "<tr>"
            f"<td>{s.get('index', '')}</td>"
            f"<td>{s.get('persona', '')}</td>"
            f"<td>{s.get('likelihood', '')}</td>"
            f"<td>{', '.join(s.get('chained_findings', [])[:3])}</td>"
            "</tr>"
        )

    # Exploit chains structured
    exploit_table_html = ""
    for c in context.exploit_chains:
        exploit_table_html += (
            "<tr>"
            f"<td>{c.get('index', '')}</td>"
            f"<td>{c.get('title', '')}</td>"
            f"<td>{c.get('status', '')}</td>"
            f"<td>{c.get('difficulty', '')}</td>"
            f"<td>{c.get('impact', '')}</td>"
            "</tr>"
        )

    # Remediation tiers
    rem_html = ""
    for tier_name, tier_label in [("tier_1_immediate", "Tier 1 — Immediate (48h)"), ("tier_2_short_term", "Tier 2 — Short-Term (2 weeks)"), ("tier_3_architectural", "Tier 3 — Architectural (SDLC)")]:
        items = context.remediation_stages.get(tier_name, [])
        if not items and tier_name == "tier_3_architectural":
            items = [
                {"action": "Integrate security testing into CI/CD pipeline", "effort": "Complex Refactor"},
                {"action": "Deploy WAF and centralized logging", "effort": "Moderate"},
                {"action": "Implement automated dependency scanning", "effort": "Moderate"},
            ]
        rem_html += f"<h3>{tier_label}</h3><table class=\"data-table\"><thead><tr><th>Finding ID</th><th>Title</th><th>Effort</th></tr></thead><tbody>"
        for item in (items if isinstance(items, list) else []):
            if isinstance(item, dict):
                rem_html += (f"<tr><td>{item.get('finding_id', '—')}</td>"
                             f"<td>{item.get('title') or item.get('action', '—')}</td>"
                             f"<td>{item.get('effort', '—')}</td></tr>")
        rem_html += "</tbody></table>"

    # Risk matrix table
    risk_table_html = ""
    for cell in context.risk_matrix.get("cells", []):
        risk_table_html += (
            "<tr>"
            f"<td>{cell.get('impact', '')}</td>"
            f"<td>{cell.get('likelihood', '')}</td>"
            f"<td>{cell.get('count', 0)}</td>"
            f"<td>{', '.join(cell.get('finding_ids', [])[:6])}</td>"
            "</tr>"
        )

    # HIBP summary
    hibp_block = ""
    hibp = context.hibp_pwned_password_summary
    if isinstance(hibp, dict) and hibp:
        hibp_block = (
            '<section id="section-hibp" class="ai-section">'
            "<h2>HIBP Pwned Password Analysis</h2>"
            "<table class=\"data-table\"><tbody>"
            f"<tr><td>Checks Run</td><td>{hibp.get('checks_run', '—')}</td></tr>"
            f"<tr><td>Pwned Count</td><td>{hibp.get('pwned_count', '—')}</td></tr>"
            f"<tr><td>Exposure Signal</td><td>{hibp.get('data_breach_password_exposure', hibp.get('breach_signal_note', '—'))}</td></tr>"
            "</tbody></table></section>"
        )

    tech_stack_html = ""
    if isinstance(context.tech_stack_structured, dict) and context.tech_stack_structured:
        ts = context.tech_stack_structured
        tech_stack_html = (
            '<section id="section-techstack" class="structured-section">'
            "<h2>Technology Stack</h2>"
            "<table class=\"data-table\"><tbody>"
            f"<tr><td>Web Server</td><td>{ts.get('web_server', '—')}</td></tr>"
            f"<tr><td>Operating System</td><td>{ts.get('os', '—')}</td></tr>"
            f"<tr><td>CMS</td><td>{ts.get('cms', '—')}</td></tr>"
            f"<tr><td>Frameworks</td><td>{', '.join(ts.get('frameworks', [])[:8]) or '—'}</td></tr>"
            f"<tr><td>JS Libraries</td><td>{', '.join(ts.get('js_libraries', [])[:8]) or '—'}</td></tr>"
            "</tbody></table></section>"
        )

    ssl_html = ""
    if isinstance(context.ssl_tls_analysis, dict) and context.ssl_tls_analysis:
        s = context.ssl_tls_analysis
        ssl_html = (
            '<section id="section-ssltls" class="structured-section">'
            "<h2>SSL/TLS Configuration</h2>"
            "<table class=\"data-table\"><tbody>"
            f"<tr><td>Issuer</td><td>{s.get('issuer', '—')}</td></tr>"
            f"<tr><td>Validity</td><td>{s.get('validity', '—')}</td></tr>"
            f"<tr><td>HSTS</td><td>{s.get('hsts', '—')}</td></tr>"
            f"<tr><td>Protocols</td><td>{', '.join(s.get('protocols', [])[:8]) or '—'}</td></tr>"
            f"<tr><td>Weak Protocols</td><td>{', '.join(s.get('weak_protocols', [])[:8]) or 'None'}</td></tr>"
            f"<tr><td>Weak Ciphers</td><td>{', '.join(s.get('weak_ciphers', [])[:8]) or 'None'}</td></tr>"
            "</tbody></table></section>"
        )

    headers_html = ""
    if isinstance(context.security_headers_analysis, dict) and context.security_headers_analysis:
        h = context.security_headers_analysis
        missing = h.get("missing_recommended", [])
        headers_html = (
            '<section id="section-headers" class="structured-section">'
            "<h2>HTTP Security Headers</h2>"
            "<table class=\"data-table\"><tbody>"
            f"<tr><td>Summary</td><td>{h.get('summary', '—')}</td></tr>"
            f"<tr><td>Missing Recommended</td><td>{', '.join(missing[:8]) if missing else 'None'}</td></tr>"
            "</tbody></table></section>"
        )

    full_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Valhalla Report — {context.engagement_title}</title>
<style>
  :root {{
    --bg-primary: #0a0e17;
    --bg-secondary: #111827;
    --bg-card: #1a2332;
    --text-primary: #e2e8f0;
    --text-secondary: #94a3b8;
    --border: #1e293b;
    --accent: #38bdf8;
    --accent-glow: rgba(56, 189, 248, 0.15);
    --critical: #ef4444;
    --high: #f97316;
    --medium: #eab308;
    --low: #22c55e;
    --info: #06b6d4;
  }}
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.625;
    font-size: 15px;
  }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  header.valhalla-header {{
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    border-bottom: 2px solid var(--accent);
    padding: 40px 48px 32px;
    position: relative;
    overflow: hidden;
  }}
  header.valhalla-header::before {{
    content: '';
    position: absolute;
    inset: 0;
    background: radial-gradient(ellipse at 20% 50%, var(--accent-glow) 0%, transparent 60%);
  }}
  .header-content {{ position: relative; z-index: 1; max-width: 1100px; margin: 0 auto; }}
  .header-content .brand {{
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 3px;
    color: var(--accent);
    margin-bottom: 10px;
    font-weight: 700;
  }}
  .header-content h1 {{
    font-size: 32px;
    font-weight: 800;
    color: #f1f5f9;
    margin-bottom: 8px;
  }}
  .header-content .meta-line {{
    color: var(--text-secondary);
    font-size: 14px;
    margin-top: 12px;
  }}
  .header-content .meta-line span {{ margin-right: 20px; }}
  .header-content .tier-badge {{
    display: inline-block;
    padding: 4px 14px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 2px;
    background: linear-gradient(135deg, #7c3aed, #4f46e5);
    color: #e0e7ff;
    margin-bottom: 14px;
  }}

  main {{ max-width: 1100px; margin: 0 auto; padding: 32px 48px 64px; }}
  section {{ margin-bottom: 40px; }}
  h2 {{
    font-size: 22px;
    font-weight: 700;
    color: #f1f5f9;
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
    margin-bottom: 20px;
  }}
  h3 {{
    font-size: 17px;
    font-weight: 600;
    color: #cbd5e1;
    margin: 18px 0 10px;
  }}

  .card {{
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 24px 28px;
    margin-bottom: 24px;
  }}

  .chart-row {{
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 6px 0;
  }}
  .chart-label {{
    width: 85px;
    font-size: 13px;
    font-weight: 600;
    text-transform: uppercase;
    color: var(--text-secondary);
    text-align: right;
  }}
  .chart-bar-wrapper {{
    flex: 1;
    background: var(--bg-primary);
    border-radius: 4px;
    overflow: hidden;
    height: 18px;
  }}
  .chart-bar {{
    height: 100%;
    border-radius: 4px;
    transition: width 0.4s ease;
    min-width: 2px;
  }}
  .chart-count {{
    width: 44px;
    text-align: right;
    font-size: 15px;
    font-weight: 700;
    color: var(--text-primary);
  }}

  table.data-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 14px;
  }}
  table.data-table thead th {{
    text-align: left;
    padding: 10px 12px;
    color: var(--text-secondary);
    font-weight: 600;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
    border-bottom: 2px solid var(--border);
  }}
  table.data-table tbody td {{
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
    color: var(--text-primary);
  }}
  table.data-table tbody tr:hover {{
    background: rgba(56, 189, 248, 0.04);
  }}

  .badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
  }}
  .badge-critical {{ background: rgba(239, 68, 68, 0.15); color: #ef4444; }}
  .badge-high      {{ background: rgba(249, 115, 22, 0.15); color: #f97316; }}
  .badge-medium    {{ background: rgba(234, 179, 8, 0.15); color: #eab308; }}
  .badge-low       {{ background: rgba(34, 197, 94, 0.15); color: #22c55e; }}
  .badge-info      {{ background: rgba(6, 182, 212, 0.15); color: #06b6d4; }}

  .ai-content {{
    color: #cbd5e1;
  }}
  .ai-content p {{
    margin-bottom: 14px;
  }}

  .owasp-compliance-0 {{ color: var(--low); }}
  .owasp-compliance-warn {{ color: var(--medium); }}
  .owasp-compliance-high {{ color: var(--critical); }}
  .owasp-compliance-not-assessed {{ color: var(--text-secondary); font-style: italic; }}

  footer.valhalla-footer {{
    max-width: 1100px;
    margin: 0 auto;
    padding: 24px 48px 40px;
    border-top: 1px solid var(--border);
    color: var(--text-secondary);
    font-size: 12px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}

  @media (max-width: 768px) {{
    main, header.valhalla-header {{ padding-left: 20px; padding-right: 20px; }}
  }}
</style>
</head>
<body>

<header class="valhalla-header">
  <div class="header-content">
    <div class="tier-badge">Valhalla Tier</div>
    <p class="brand">ARGUS Offensive Security Platform</p>
    <h1>{context.engagement_title}</h1>
    <div class="meta-line">
      <span>Target: {context.target_url}</span>
      <span>Scan: {context.scan_id[:12]}…</span>
      <span>Generated: {context.generated_at[:19]}</span>
    </div>
  </div>
</header>

<main>

<!-- Executive Summary -->
<section id="section-executive" class="card">
  <h2>Executive Summary</h2>
  <div class="ai-content"><p>{context.ai_sections.get(REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA, '') or context.ai_sections.get(REPORT_AI_SECTION_EXECUTIVE_SUMMARY, '(No executive summary generated.)')}</p></div>
</section>

<!-- Severity Distribution Chart -->
<section id="section-severity-chart">
  <h2>Severity Distribution</h2>
  <div class="card">
    {_css_severity_bar_chart(context.severity_counts)}
    <p style="margin-top:16px;color:var(--text-secondary);font-size:13px;">
      Total Findings: <strong>{context.finding_count}</strong>
    </p>
  </div>
</section>

<!-- OWASP Compliance -->
<section id="section-owasp-compliance">
  <h2>OWASP Top 10 Compliance</h2>
  <table class="data-table">
    <thead>
      <tr>
        <th>Category</th><th>Title</th><th>Assessed</th><th>Findings</th><th>Result</th>
      </tr>
    </thead>
    <tbody>
      {owasp_table_html}
    </tbody>
  </table>
</section>

<!-- Findings Table -->
<section id="section-findings">
  <h2>Findings</h2>
  <div style="overflow-x:auto;">
    <table class="data-table">
      <thead>
        <tr>
          <th>Severity</th><th>Title</th><th>CWE</th><th>CVSS</th><th>Confidence</th><th>Evidence</th>
        </tr>
      </thead>
      <tbody>
        {_findings_table_html(context.findings)}
      </tbody>
    </table>
  </div>
</section>

<!-- Critical Findings -->
<section id="section-critical">
  <h2>Critical Findings</h2>
  <table class="data-table">
    <thead>
      <tr><th>Severity</th><th>Title</th><th>CVSS</th><th>Exploit Available</th></tr>
    </thead>
    <tbody>
      {crit_rows_html if crit_rows_html else '<tr><td colspan="4" style="color:var(--text-secondary)">No critical findings identified.</td></tr>'}
    </tbody>
  </table>
</section>

<!-- Risk Matrix -->
<section id="section-risk-matrix">
  <h2>Risk Matrix</h2>
  <table class="data-table">
    <thead>
      <tr><th>Impact</th><th>Likelihood</th><th>Count</th><th>Finding IDs</th></tr>
    </thead>
    <tbody>
      {risk_table_html if risk_table_html else '<tr><td colspan="4" style="color:var(--text-secondary)">Insufficient data for risk matrix computation.</td></tr>'}
    </tbody>
  </table>
</section>

<!-- Structured Data -->
{tech_stack_html}
{ssl_html}
{headers_html}

<!-- Attack Scenarios (Structured) -->
<section id="section-attack-scenarios-structured">
  <h2>Attack Scenarios</h2>
  <table class="data-table">
    <thead>
      <tr><th>#</th><th>Attacker Persona</th><th>Likelihood</th><th>Chained Findings</th></tr>
    </thead>
    <tbody>
      {attack_table_html if attack_table_html else '<tr><td colspan="4" style="color:var(--text-secondary)">Insufficient validated findings for attack scenario chaining.</td></tr>'}
    </tbody>
  </table>
</section>

<!-- Exploit Chains (Structured) -->
<section id="section-exploit-chains-structured">
  <h2>Exploit Chains</h2>
  <table class="data-table">
    <thead>
      <tr><th>#</th><th>Title</th><th>Status</th><th>Difficulty</th><th>Impact</th></tr>
    </thead>
    <tbody>
      {exploit_table_html if exploit_table_html else '<tr><td colspan="5" style="color:var(--text-secondary)">No verified exploit chains demonstrated.</td></tr>'}
    </tbody>
  </table>
</section>

<!-- Remediation Stages (Structured) -->
<section id="section-remediation-stages-structured">
  <h2>Remediation Stages</h2>
  {rem_html}
</section>

<!-- AI-Generated Sections -->
{ai_sections_html}

<!-- HIBP -->
{hibp_block}

</main>

<footer class="valhalla-footer">
  <span>ARGUS Valhalla Report &mdash; {context.scan_id[:12]}…</span>
  <span>Generated: {context.generated_at[:19]}Z</span>
  <span>Tier: Valhalla</span>
</footer>

</body>
</html>"""

    if output_path:
        encoded = full_html.encode("utf-8")
        with open(output_path, "wb") as f:
            f.write(encoded)
        return encoded
    return full_html.encode("utf-8")


def _render_valhalla_markdown(context: ValhallaReportContext) -> bytes:
    """Render Valhalla report as Markdown."""
    lines: list[str] = [
        f"# {context.engagement_title}",
        "",
        f"**Target:** {context.target_url}",
        f"**Scan ID:** {context.scan_id}",
        f"**Tier:** Valhalla",
        f"**Generated:** {context.generated_at}",
        "",
        "---",
        "",
        "## Severity Distribution",
        "",
    ]
    for sev in ("critical", "high", "medium", "low", "info"):
        count = context.severity_counts.get(sev, 0)
        lines.append(f"- **{sev.title()}:** {count}")
    lines.append(f"\n**Total Findings:** {context.finding_count}\n")

    lines.append("---\n\n## Findings\n")
    for f in sorted(context.findings, key=lambda x: _SEVERITY_RANK.get((x.get("severity") or "").lower(), 99)):
        lines.append(f"### {f.get('title', 'Untitled')}")
        lines.append(f"- **Severity:** {f.get('severity', 'info')}")
        lines.append(f"- **CWE:** {f.get('cwe', '—')}")
        lines.append(f"- **CVSS:** {f.get('cvss', '—')}")
        lines.append(f"- **Confidence:** {f.get('confidence', '—')}")
        lines.append(f"- **Description:** {_truncate(str(f.get('description', '')), 300)}")
        lines.append("")

    for key in _VALHALLA_AI_SECTION_ORDER:
        text = context.ai_sections.get(key, "")
        if not text.strip():
            continue
        label = key.replace("_", " ").title()
        lines.append(f"---\n\n## {label}\n\n{text}\n")

    return "\n".join(lines).encode("utf-8")


# ---------------------------------------------------------------------------
# 5. Top-level pipeline entry — generate_valhalla_report()
# ---------------------------------------------------------------------------


async def generate_valhalla_report(
    session: AsyncSession,
    *,
    scan_id: str,
    tenant_id: str,
    report_id: str | None = None,
    recon_output: dict[str, Any] | None = None,
    threat_model_output: dict[str, Any] | None = None,
    findings_list: list[dict[str, Any]] | None = None,
    exploitation_output: dict[str, Any] | None = None,
    post_exploitation_output: dict[str, Any] | None = None,
    llm_callable: Callable[[str, dict], str] | None = None,
) -> dict[str, Any]:
    """Run the full Valhalla report pipeline: context → AI → render.

    Returns a dict:
      - ``context``: the assembled ValhallaReportContext (model_dump JSON)
      - ``ai_sections``: dict of generated section texts
      - ``html_bytes``: rendered HTML bytes (if rendered)
      - ``status``: ``"completed"`` or ``"partial"`` (when LLM unavailable)
    """
    # 1. Build context
    built_context = await build_valhalla_report_context(
        scan_id=scan_id,
        tenant_id=tenant_id,
        recon_output=recon_output,
        threat_model_output=threat_model_output,
        findings=findings_list,
        exploitation_output=exploitation_output,
        post_exploitation_output=post_exploitation_output,
        session=session,
    )

    # 2. Generate AI sections
    sections = await generate_valhalla_sections(
        built_context,
        llm_callable=llm_callable,
    )

    # 3. Render HTML
    html_bytes = render_valhalla_report(built_context, format="html")

    # Determine status
    has_llm_text = any(v and v not in (REPORT_AI_SKIPPED_NO_LLM, REPORT_AI_SKIPPED_GENERATION_FAILED)
                       for v in sections.values())
    status = "completed" if has_llm_text else "partial_no_llm"

    return {
        "context": built_context.model_dump(mode="json"),
        "ai_sections": sections,
        "html_bytes": html_bytes,
        "html_size": len(html_bytes),
        "status": status,
        "scan_id": scan_id,
        "tenant_id": tenant_id,
    }
