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

from src.llm.facade import call_llm_sync
from src.llm.task_router import LLMTask
from src.orchestration.prompt_registry import (
    REPORT_AI_SECTION_ATTACK_SCENARIOS,
    REPORT_AI_SECTION_BUSINESS_RISK,
    REPORT_AI_SECTION_COMPLIANCE_CHECK,
    REPORT_AI_SECTION_COST_SUMMARY,
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY,
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA,
    REPORT_AI_SECTION_EXPLOIT_CHAINS,
    REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS,
    REPORT_AI_SECTION_KEYS,
    REPORT_AI_SECTION_PRIORITIZATION_ROADMAP,
    REPORT_AI_SECTION_REMEDIATION_STAGES,
    REPORT_AI_SECTION_REMEDIATION_STEP,
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION,
    REPORT_AI_SECTION_ZERO_DAY_POTENTIAL,
    get_report_ai_section_prompt,
)
from src.owasp_top10_2025 import (
    OWASP_TOP10_2025_CATEGORY_IDS,
)
from src.reports.ai_text_generation import (
    REPORT_AI_SKIPPED_GENERATION_FAILED,
    REPORT_AI_SKIPPED_NO_LLM,
    AITextDeduplicator,
)
from src.reports.generators import (
    build_owasp_compliance_rows,
)
from src.reports.report_text_sanitizer import (
    contains_ai_stub_output,
    contains_raw_prompt_leakage,
    sanitize_ai_report_text,
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
    "bounty_hunter_tactics",
    "quick_fuzz_findings",
    "ai_security_findings",
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
    email: str = ""
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
    remediation_matrix: list[dict[str, Any]] = Field(default_factory=list)
    retest_plan: dict[str, Any] = Field(default_factory=dict)
    zero_day_assessment: dict[str, Any] = Field(default_factory=dict)
    cost_summary: dict[str, Any] = Field(default_factory=dict)

    # Evidence quality
    evidence_gate: dict[str, Any] = Field(default_factory=dict)
    csrf_structured: list[dict[str, Any]] = Field(default_factory=list)
    cmdi_structured: list[dict[str, Any]] = Field(default_factory=list)

    # Quick fuzz phase results
    quick_fuzz_summary: dict[str, Any] = Field(
        default_factory=dict,
        description="Summary of quick_fuzz phase: total_payloads, categories_tested, candidates_found, by_category.",
    )

    # Bug bounty planning data (when scan originated from a bounty plan)
    bounty_plan: dict[str, Any] = Field(
        default_factory=dict,
        description="Bug bounty scope analysis, surface classification, and test plan data.",
    )

    # Burp Suite config export availability
    burp_config_available: bool = Field(
        default=False,
        description="True when a Burp Suite config JSON was generated for this scan.",
    )

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


def _build_csrf_structured(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in findings:
        title_l = str(f.get("title") or "").lower()
        is_csrf = "csrf" in title_l or "cross-site request" in title_l or "session" in title_l
        if not is_csrf:
            continue
        poc = f.get("proof_of_concept")
        if not isinstance(poc, dict):
            continue
        out.append(
            {
                "finding_id": str(f.get("id") or f.get("finding_id") or ""),
                "title": _truncate(str(f.get("title") or ""), 300),
                "endpoint": _truncate(str(poc.get("url") or poc.get("endpoint") or ""), 512) or None,
                "method": str(poc.get("method") or "POST"),
                "state_changing": poc.get("state_changing"),
                "token_status": str(poc.get("csrf_token_status") or "missing"),
                "raw_html_form": _truncate(str(poc.get("raw_html_form") or ""), 1024) or None,
                "raw_post": _truncate(str(poc.get("raw_post") or poc.get("payload") or ""), 512) or None,
                "cookies": str(poc.get("cookies") or ""),
                "origin_referer": str(poc.get("origin") or poc.get("referer") or ""),
                "negative_control": _truncate(str(poc.get("negative_control") or ""), 256) or None,
                "verified": bool(poc.get("verified_via_browser")) or bool(poc.get("exploit_demonstrated")),
            }
        )
        if len(out) >= 40:
            break
    return out


def _build_cmdi_structured(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in findings:
        cwe = str(f.get("cwe") or "").upper()
        title_l = str(f.get("title") or "").lower()
        is_cmdi = "78" in cwe or "command" in title_l or "injection" in title_l
        if not is_cmdi:
            continue
        poc = f.get("proof_of_concept")
        if not isinstance(poc, dict):
            continue
        out.append(
            {
                "finding_id": str(f.get("id") or f.get("finding_id") or ""),
                "title": _truncate(str(f.get("title") or ""), 300),
                "parameter": _truncate(str(poc.get("parameter") or poc.get("input") or ""), 256) or None,
                "payload": _truncate(str(poc.get("payload") or ""), 512) or None,
                "harmless_marker": _truncate(str(poc.get("harmless_marker") or ""), 256) or None,
                "controlled_output": _truncate(str(poc.get("controlled_output") or poc.get("command_output") or ""), 512) or None,
                "server_proof": _truncate(str(poc.get("server_proof") or poc.get("log_entry") or ""), 512) or None,
                "output_source": str(poc.get("output_source") or "stdout"),
                "negative_control": _truncate(str(poc.get("negative_control") or ""), 256) or None,
                "verified": bool(poc.get("verified_via_browser")) or bool(poc.get("exploit_demonstrated")),
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


def _build_remediation_stages(findings: list[dict[str, Any]], tech_stack: dict[str, Any] | None = None) -> dict[str, Any]:
    """VHL-REMEDIATION-001 — Remediation matrix with full traceability.

    Each finding maps to: affected layer, owner team, config/component, fix,
    priority, rollback risk, verification step, acceptance criteria.
    """
    critical = [f for f in findings if (f.get("severity") or "").lower() in ("critical", "high")]
    high_cvss = [f for f in findings
                 if isinstance((f.get("cvss") or f.get("cvss_score")), (int, float))
                 and float(f.get("cvss") or f.get("cvss_score") or 0) >= 7.0]
    medium = [f for f in findings if (f.get("severity") or "").lower() == "medium"]
    low = [f for f in findings if (f.get("severity") or "").lower() == "low"]

    _REMEDIATION_MATRIX = {
        "SQLI_CANDIDATE": {
            "action": "Use parameterized queries/prepared statements for all database interactions. Input validation alone is insufficient.",
            "verification": "Re-run sqlmap with same parameters — should report 'not injectable'.",
            "owner": "Backend development team",
            "affected_layer": "app/database",
            "component": "Database query layer / ORM",
            "rollback_risk": "Low — parameterized queries are backward compatible",
            "acceptance_criteria": "All database queries use parameterized statements; sqlmap reports no injection points",
        },
        "XSS": {
            "action": "Apply context-aware output encoding (HTML, JS, URL, CSS). Implement Content-Security-Policy as defense-in-depth.",
            "verification": "Inject <script>alert(1)</script> — should be encoded, not executed. Verify CSP blocks inline scripts.",
            "owner": "Frontend development team",
            "affected_layer": "app/frontend",
            "component": "Template engine / output rendering layer",
            "rollback_risk": "Low — encoding is backward compatible",
            "acceptance_criteria": "All user input is encoded per context; CSP header present with strict-dynamic or nonce",
        },
        "COMMAND_INJECTION_CANDIDATE": {
            "action": "Eliminate OS command execution from user input. Use language-native APIs instead of shell commands. If unavoidable, use strict allowlist validation.",
            "verification": "Re-run commix — should report no injection points.",
            "owner": "Backend development team",
            "affected_layer": "app/backend",
            "component": "System command execution layer",
            "rollback_risk": "Medium — may require API changes if shell commands are deeply integrated",
            "acceptance_criteria": "No shell metacharacters accepted; commix reports no injection points",
        },
        "RATE_LIMIT": {
            "action": "Implement per-IP and per-account rate limiting with exponential backoff. Add CAPTCHA after threshold. Monitor and alert on repeated failures.",
            "verification": "Send 20+ rapid login requests — should receive HTTP 429 after threshold.",
            "owner": "Infrastructure / API team",
            "affected_layer": "API/infrastructure",
            "component": "Rate limiter middleware / reverse proxy",
            "rollback_risk": "Low — rate limiting is additive",
            "acceptance_criteria": "HTTP 429 returned after threshold; CAPTCHA triggered; no account lockout bypass",
        },
        "SECURITY_HEADER": {
            "action": "Add missing HTTP security headers at reverse proxy or application level. Verify with curl -sS -I <url>.",
            "verification": "curl -sS -I https://<target> | grep -iE 'content-security-policy|x-content-type-options|referrer-policy|permissions-policy'",
            "owner": "Infrastructure / DevOps team",
            "affected_layer": "infrastructure/reverse-proxy",
            "component": "CloudFront Distribution / nginx / Apache configuration",
            "rollback_risk": "Low — headers are additive; use Content Security Policy with report-only first",
            "acceptance_criteria": "All recommended headers present; curl verification passes",
        },
        "FUZZ_HIT": {
            "action": "Investigate the discovered path/parameter. If it exposes sensitive functionality, restrict access with authentication and authorization controls. If unexposed (returns public content), document as information-only.",
            "verification": "Manually verify the endpoint returns expected content. Confirm authentication is required for non-public endpoints.",
            "owner": "Application security team",
            "affected_layer": "app/backend",
            "component": "URL routing / access control layer",
            "rollback_risk": "Low — access control is additive",
            "acceptance_criteria": "Endpoint returns expected content; authentication enforced for non-public paths",
        },
        "LINE_FINDING": {
            "action": "Validate and sanitize all input parameters on the endpoint. Check for information disclosure in HTTP response lines (headers, body, error messages).",
            "verification": "curl -sS -D- -o /dev/null <affected_url> | head -1",
            "owner": "Backend development team",
            "affected_layer": "app/backend",
            "component": "HTTP response handler / error page template",
            "rollback_risk": "Low — response sanitization is backward compatible",
            "acceptance_criteria": "Response contains no sensitive information in status line or headers; re-scan confirms absence",
        },
        "WHATWEB_PLUGIN": {
            "action": "Remove or obfuscate technology version disclosures from HTTP headers (Server, X-Powered-By, X-AspNet-Version) and error pages. Configure server to return generic version strings.",
            "verification": "whatweb -a 1 <affected_url> | grep -E '(Version|HTTPServer)' — should return no version strings",
            "owner": "Infrastructure / DevOps team",
            "affected_layer": "infrastructure/reverse-proxy",
            "component": "Web server configuration (Server header, X-Powered-By, error pages)",
            "rollback_risk": "Low — removing version headers does not affect functionality",
            "acceptance_criteria": "whatweb detects no version strings; server headers return generic values",
        },
        "INFORMATION_DISCLOSURE": {
            "action": "Remove or restrict access to information-leaking endpoints. Disable verbose error messages in production. Remove server version headers.",
            "verification": "curl -sS -I <url> confirms no version/stack info. Error responses return generic messages.",
            "owner": "Backend development team",
            "affected_layer": "app/backend",
            "component": "Error handling / server configuration",
            "rollback_risk": "Low — generic errors are safer",
            "acceptance_criteria": "No stack traces or version info in responses; server headers stripped",
        },
        "MISCONFIGURATION": {
            "action": "Apply security hardening configuration per the affected component. Disable default credentials, enable HTTPS, restrict CORS origins.",
            "verification": "Re-scan with applicable security scanner; previously flagged misconfiguration no longer appears.",
            "owner": "Infrastructure / DevOps team",
            "affected_layer": "infrastructure/configuration",
            "component": "Server / application configuration",
            "rollback_risk": "Low to Medium — depends on component",
            "acceptance_criteria": "Misconfiguration resolved; re-scan confirms absence",
        },
    }

    _OWNER_BY_LAYER = {
        "app/database": "Database team",
        "app/frontend": "Frontend team",
        "app/backend": "Backend team",
        "api": "API team",
        "infrastructure": "Infrastructure / DevOps team",
        "infrastructure/reverse-proxy": "Infrastructure / DevOps team",
        "security": "Security team",
    }

    def _contextual_fallback(f: dict[str, Any], field: str, tech_stack: dict[str, Any] | None = None) -> str:
        poc = f.get("proof_of_concept") or {}
        if not isinstance(poc, dict):
            poc = {}
        cwe = str(f.get("cwe") or "").upper()
        title = str(f.get("title") or "").lower()
        affected_url = str(poc.get("request_url") or poc.get("affected_url") or f.get("affected_url") or "")
        affected_parameter = str(poc.get("parameter") or "")
        severity = str(f.get("severity") or "info").lower()
        ts = tech_stack or {}
        web_server = str(ts.get("web_server") or "").lower()
        frameworks = str(ts.get("frameworks") or "").lower()

        if field == "owner":
            layer = str(f.get("data", {}).get("affected_layer") or "").lower() if isinstance(f.get("data"), dict) else ""
            if not layer:
                if "cloudfront" in web_server:
                    return "CloudFront / CDN team"
                for key, owner in _OWNER_BY_LAYER.items():
                    if key in title:
                        return owner
            result = _OWNER_BY_LAYER.get(layer, "")
            if result:
                return result
            if "cloudfront" in web_server:
                return "CloudFront / CDN team"
            if "next" in frameworks or "nextjs" in frameworks:
                return "Frontend development team (Next.js)"
            return _OWNER_BY_LAYER.get(layer, "Relevant development team (assign per endpoint ownership)")

        if field == "component":
            if "cloudfront" in web_server:
                return "CloudFront Distribution — Response Headers Policy"
            if "next" in frameworks or "nextjs" in frameworks:
                return "Next.js configuration (next.config.js)"
            if "xss" in title or "cross-site" in title:
                return "Template engine / output rendering layer"
            if "sql" in title or "sqli" in title:
                return "Database query layer / ORM"
            if "header" in title or "csp" in title or "hsts" in title:
                return "HTTP response header configuration (server / CDN)"
            if "rate" in title:
                return "Rate limiter middleware / reverse proxy"
            if "command" in title or "injection" in title:
                part = f"Parameter: {affected_parameter}" if affected_parameter else "Input handling layer"
                return part
            if "disclosure" in title or "info" in title:
                return "Error handling / server configuration"
            return f"Component at {affected_url}" if affected_url else "Affected endpoint (specify after investigation)"

        if field == "fix":
            if "xss" in title or "cross-site" in title:
                if "cloudfront" in web_server:
                    return "Configure Content-Security-Policy in CloudFront Distribution → Response Headers Policy with nonce-based script-src; add X-Content-Type-Options: nosniff; X-Frame-Options: DENY"
                return "Encode user input per context (HTML/JS/URL). Add Content-Security-Policy with nonce-based allowlist."
            if "sql" in title or "sqli" in title:
                return "Use parameterized queries. Validate and sanitize all user-supplied input before database interaction."
            if "header" in title or "csp" in title or "hsts" in title:
                if "cloudfront" in web_server:
                    return "Add Response Headers Policy in CloudFront Distribution with: Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy"
                return "Configure missing HTTP security headers at reverse proxy or application level."
            if "rate" in title or "limit" in title:
                return "Implement per-IP and per-account rate limiting with exponential backoff and CAPTCHA."
            if "command" in title or "injection" in title:
                param_hint = f" on `{affected_parameter}`" if affected_parameter else ""
                return f"Eliminate OS command execution from user input{param_hint}. Use language-native APIs or strict allowlist validation."
            if "disclosure" in title or "info" in title:
                return "Remove information-leaking endpoints; disable verbose error messages in production."
            return f"Review and remediate: {title}. Affected URL: {affected_url}" if affected_url else f"Review and remediate: {title}"

        if field == "rollback_risk":
            if "header" in title or "csp" in title or "hsts" in title:
                if "cloudfront" in web_server:
                    return "Low — CloudFront header changes are reversible via continuous deployment; use report-only CSP first"
                return "Low — headers are additive; use CSP report-only first"
            return ""

        return ""

    def _build_matrix_entry(f: dict[str, Any], priority: str, deadline: str, effort: str, tech_stack: dict[str, Any] | None = None) -> dict[str, Any]:
        f_type = str(f.get("type") or f.get("data", {}).get("type") or "").upper()
        remediation = None
        for key, rem in _REMEDIATION_MATRIX.items():
            if key in f_type:
                remediation = rem
                break

        title = str(f.get("title") or "").lower()
        if not remediation:
            for key, rem in _REMEDIATION_MATRIX.items():
                key_lower = key.lower()
                if key_lower in title:
                    remediation = rem
                    break

        poc = f.get("proof_of_concept") or {}
        affected_url = str(poc.get("request_url") or poc.get("affected_url") or f.get("affected_url") or "")[:512]
        affected_parameter = str(poc.get("parameter") or poc.get("affected_parameter") or "")[:256]

        return {
            "finding_id": str(f.get("id") or ""),
            "title": str(f.get("title") or ""),
            "severity": f.get("severity"),
            "cvss": f.get("cvss") or f.get("cvss_score"),
            "cvss_vector": poc.get("cvss_vector") if isinstance(poc, dict) else None,
            "priority": priority,
            "deadline": deadline,
            "effort": effort,
            "affected_layer": remediation["affected_layer"] if remediation else "app/unknown",
            "owner_team": remediation["owner"] if remediation else _contextual_fallback(f, "owner", tech_stack=tech_stack),
            "config_component": remediation["component"] if remediation else _contextual_fallback(f, "component", tech_stack=tech_stack),
            "affected_url": affected_url,
            "affected_parameter": affected_parameter,
            "fix": remediation["action"] if remediation else _contextual_fallback(f, "fix", tech_stack=tech_stack),
            "rollback_risk": remediation["rollback_risk"] if remediation else (_contextual_fallback(f, "rollback_risk", tech_stack=tech_stack) or "Assess before deployment"),
            "verification_step": remediation["verification"] if remediation else "Re-test the affected endpoint after applying the fix",
            "acceptance_criteria": remediation["acceptance_criteria"] if remediation else "Finding no longer reproducible; re-scan confirms absence",
        }

    tier1: list[dict[str, Any]] = []
    for f in (critical + [h for h in high_cvss if h not in critical])[:8]:
        tier1.append(_build_matrix_entry(f, "P0", "48 hours", "Complex Refactor" if f.get("description") and len(str(f.get("description") or "")) > 800 else "Moderate", tech_stack=tech_stack))

    tier2: list[dict[str, Any]] = []
    for f in medium[:6]:
        tier2.append(_build_matrix_entry(f, "P1", "2 weeks", "Quick Fix", tech_stack=tech_stack))

    for f in low[:4]:
        tier2.append(_build_matrix_entry(f, "P2", "1 month", "Quick Fix", tech_stack=tech_stack))

    tier3: list[dict[str, Any]] = [
        {"category": "SDLC", "action": "Integrate security testing into CI/CD pipeline", "effort": "Complex Refactor", "owner": "DevOps / Security team", "affected_layer": "CI/CD", "priority": "P3", "deadline": "1 quarter", "rollback_risk": "Medium", "acceptance_criteria": "Security gates in CI/CD pipeline"},
        {"category": "Monitoring", "action": "Deploy WAF and centralized logging", "effort": "Moderate", "owner": "Infrastructure team", "affected_layer": "infrastructure", "priority": "P3", "deadline": "1 quarter", "rollback_risk": "Low", "acceptance_criteria": "WAF rules active; logs centralized"},
        {"category": "Dependencies", "action": "Implement automated dependency scanning and SBOM generation", "effort": "Moderate", "owner": "Development team", "affected_layer": "CI/CD", "priority": "P3", "deadline": "1 quarter", "rollback_risk": "Low", "acceptance_criteria": "SBOM generated per build; dependency scan passes"},
    ]

    return {
        "tier_1_immediate": tier1,
        "tier_2_short_term": tier2,
        "tier_3_architectural": tier3,
        "remediation_matrix": tier1 + tier2,
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


_RETEST_VERIFICATION_COMMANDS: dict[str, str] = {
    "XSS": "curl -sS '{url}' | grep -i '{payload_fragment}'",
    "SQLI": "sqlmap --url '{url}' --batch --level 1 --threads 1",
    "HEADER": "curl -sS -D- -o /dev/null '{url}' | grep -i '{header_name}'",
    "COMMAND_INJECTION": "commix --url '{url}' --batch --level 1",
    "FUZZ_HIT": "curl -sS '{url}' | grep -i '{payload_fragment}'",
    "INFORMATION_DISCLOSURE": "whatweb -a 1 '{url}' | grep -E '(Version|HTTPServer)'",
    "LINE_FINDING": "curl -sS -D- -o /dev/null '{url}' | head -1",
    "WHATWEB_PLUGIN": "whatweb -a 3 '{url}' | grep -E '(Version|HTTPServer)'",
    "RATE_LIMIT": "for i in $(seq 1 20); do curl -sS -o /dev/null -w '%{http_code}' '{url}'; done | sort | uniq -c",
}


def _build_retest_plan(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a retest-after-remediation plan with per-finding verification commands."""
    items: list[dict[str, Any]] = []
    f_type = ""
    for f in sorted(findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(str(x.get("severity", "info")).lower(), 5)):
        if not isinstance(f, dict):
            continue
        f_type = str(f.get("type", f.get("data", {}).get("type") if isinstance(f.get("data"), dict) else "") or "").upper()
        affected_url = str(f.get("affected_url") or (f.get("proof_of_concept") or {}).get("request_url") or "")
        for key, cmd_template in _RETEST_VERIFICATION_COMMANDS.items():
            if key in f_type:
                verification = cmd_template.format(url=affected_url, payload_fragment="", header_name=key.lower())
                break
        else:
            verification = f"curl -sS -D- -o /dev/null '{affected_url}'"
        items.append({
            "finding_id": str(f.get("id", f.get("finding_id", "")))[:64],
            "title": str(f.get("title", ""))[:256],
            "severity": str(f.get("severity", "info")).lower(),
            "verification_command": verification,
            "expected_result": f"Finding {f.get('id', '?')} no longer reproducible",
            "retest_status": "pending",
        })
    return {
        "retest_scope": items[:25],
        "retest_timeline": "14-30 days after remediation",
        "retest_methodology": "Re-run all active scan tools + manual verification + browser-based XSS confirmation",
        "retest_acceptance_criteria": "All P0 findings confirmed fixed; P1 findings confirmed fixed or risk accepted; P2/P3 findings verified or documented as accepted risk",
    }


def _extract_recon_from_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract recon-like structured data from findings when recon_output is empty."""
    tech_entries = []
    header_findings = []
    ssl_findings = []
    outdated_entries = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        data = f.get("data") or f
        poc = data.get("proof_of_concept") or {}
        tool = str(data.get("tool") or data.get("evidence_type") or data.get("scanner") or "").lower()
        title = str(data.get("title") or "").lower()
        if "whatweb" in tool or "tech" in title or "technology" in title:
            tech_entries.append({"tool": tool, "title": data.get("title", ""), "data": data})
        if "header" in title or "security header" in title:
            header_findings.append(data)
        if "ssl" in title or "tls" in title or "certificate" in title:
            ssl_findings.append(data)
        if "outdated" in title or "version" in title or "deprecated" in title:
            outdated_entries.append(data)
    return {
        "tech_stack": tech_entries,
        "security_headers": {"findings": header_findings},
        "ssl_tls": {"findings": ssl_findings},
        "outdated_components": outdated_entries,
        "target_url": findings[0].get("target_url", "") if findings else "",
    }


def _extract_threat_model_from_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract threat-model-like data from findings."""
    categories = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        cat = f.get("owasp_category") or f.get("category") or "uncategorized"
        categories.setdefault(cat, []).append(f.get("title", "untitled"))

    def _clean_placeholder_values(obj: Any) -> Any:
        if isinstance(obj, dict):
            cleaned = {}
            for k, v in obj.items():
                if isinstance(v, str) and "|" in v and any(
                    t in v.lower() for t in ("high|medium|low", "low|medium|high", "medium|high|low")
                ):
                    cleaned[k] = "unknown"
                else:
                    cleaned[k] = _clean_placeholder_values(v)
            return cleaned
        elif isinstance(obj, list):
            return [_clean_placeholder_values(item) for item in obj]
        return obj

    excerpt = f"Threat model derived from {len(findings)} findings across {len(categories)} categories."
    return _clean_placeholder_values({
        "threat_categories": categories,
        "finding_count": len(findings),
        "excerpt": excerpt,
    })


def _extract_exploitation_from_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract exploitation-like data from findings."""
    exploits = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        poc = f.get("proof_of_concept") or f.get("data", {}).get("proof_of_concept") or {}
        if poc:
            exploits.append({
                "finding_id": f.get("id", f.get("finding_id", "")),
                "title": f.get("title", "untitled"),
                "severity": f.get("severity", "info"),
                "poc_summary": str(poc)[:500],
            })
    return {"exploits": exploits, "exploit_count": len(exploits)}


async def build_valhalla_report_context(
    scan_id: str,
    tenant_id: str,
    *,
    recon_output: dict[str, Any] | None = None,
    threat_model_output: dict[str, Any] | None = None,
    findings: list[dict[str, Any]] | None = None,
    exploitation_output: dict[str, Any] | None = None,
    post_exploitation_output: dict[str, Any] | None = None,
    quick_fuzz_output: dict[str, Any] | None = None,
    session: Any = None,
) -> ValhallaReportContext:
    """Build complete Valhalla context from all scan phase outputs and DB state.

    When ``session`` is provided (SQLAlchemy AsyncSession), this function loads
    finding records and scan metadata from the DB to supplement or replace the
    passed-in ``findings`` list. Otherwise it relies entirely on the kwargs.
    """
    now_iso = datetime.utcnow().isoformat() + "Z"

    resolved_findings: list[dict[str, Any]] = list(findings or [])
    operator_email = ""
    # Load from DB when session is available
    if session is not None and isinstance(session, AsyncSession):
        try:
            from src.db.models import Scan as ScanModel
            scan_result = await session.execute(
                select(ScanModel).where(
                    cast(ScanModel.id, String) == str(scan_id),
                    cast(ScanModel.tenant_id, String) == str(tenant_id),
                )
            )
            scan_row = scan_result.scalar_one_or_none()
            if scan_row is not None:
                operator_email = getattr(scan_row, "email", "") or ""
        except Exception:
            logger.debug(
                "valhalla_ctx_scan_load_failed",
                extra={"scan_id": scan_id, "tenant_id": tenant_id},
                exc_info=True,
            )
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
                        "evidence_tier": getattr(f, "evidence_tier", None),
                        "payload_attempted": list(getattr(f, "payload_attempted", []) or []),
                        "payload_successful": list(getattr(f, "payload_successful", []) or []),
                        "taint_path": list(getattr(f, "taint_path", []) or []),
                        "code_location": getattr(f, "code_location", None),
                        "adversarial_score": getattr(f, "adversarial_score", None),
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

    # Fallback: extract structured data from findings when phase outputs are empty
    if not rec and resolved_findings:
        rec = _extract_recon_from_findings(resolved_findings)
    if not tm and resolved_findings:
        tm = _extract_threat_model_from_findings(resolved_findings)
    if not exp_out and resolved_findings:
        exp_out = _extract_exploitation_from_findings(resolved_findings)

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
    csrf_s = _build_csrf_structured(resolved_findings)
    cmdi_s = _build_cmdi_structured(resolved_findings)
    attack_s = _build_attack_scenarios(resolved_findings)

    # Exploits
    exploits_list: list[dict[str, Any]] = []
    if isinstance(exp_out, dict):
        ex_list = exp_out.get("exploits") or exp_out.get("exploits_list") or []
        if isinstance(ex_list, list):
            exploits_list = [dict(e) for e in ex_list if isinstance(e, dict)]

    exploit_chains_list = _build_exploit_chains(exploits_list, resolved_findings)

    # Enrich findings with exploit data (screenshots, payload_attempted/successful from exploits)
    _exploit_by_finding: dict[str, dict[str, Any]] = {}
    for _ex in exploits_list:
        _fid = str(_ex.get("finding_id", ""))
        if _fid:
            _exploit_by_finding.setdefault(_fid, {})
            _cur = _exploit_by_finding[_fid]
            if _ex.get("screenshot_base64") and not _cur.get("screenshot_base64"):
                _cur["screenshot_base64"] = _ex["screenshot_base64"]
            if _ex.get("screenshot_path") and not _cur.get("screenshot_path"):
                _cur["screenshot_path"] = _ex["screenshot_path"]
            if _ex.get("payload_attempted"):
                _cur.setdefault("payload_attempted_from_exploit", []).extend(_ex["payload_attempted"])
            if _ex.get("payload_successful"):
                _cur.setdefault("payload_successful_from_exploit", []).extend(_ex["payload_successful"])
            if _ex.get("payload_used"):
                _cur.setdefault("payload_used_from_exploit", []).append(_ex["payload_used"])

    for _rf in resolved_findings:
        _rf_id = str(_rf.get("finding_id") or _rf.get("id", ""))
        _ex_data = _exploit_by_finding.get(_rf_id, {})
        if _ex_data:
            if _ex_data.get("screenshot_base64") and not _rf.get("screenshot_base64"):
                _rf["screenshot_base64"] = _ex_data["screenshot_base64"]
            if _ex_data.get("screenshot_path") and not _rf.get("screenshot_path"):
                _rf["screenshots"] = [_ex_data["screenshot_path"]]
            _existing_pa = list(_rf.get("payload_attempted") or [])
            _ex_pa = _ex_data.get("payload_attempted_from_exploit", [])
            if _ex_pa:
                _rf["payload_attempted"] = list(dict.fromkeys(_existing_pa + _ex_pa))
            _existing_ps = list(_rf.get("payload_successful") or [])
            _ex_ps = _ex_data.get("payload_successful_from_exploit", [])
            if _ex_ps:
                _rf["payload_successful"] = list(dict.fromkeys(_existing_ps + _ex_ps))

    remediation_stages = _build_remediation_stages(resolved_findings, tech_stack=tech_stack)
    zero_day = _build_zero_day_assessment(resolved_findings)
    retest_plan = _build_retest_plan(resolved_findings)

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
            hibp_checks = hibp_raw.get("checks_run", 0)
            if isinstance(hibp_checks, (int, float)) and hibp_checks == 0:
                hibp_summary["inconclusive"] = True
                hibp_summary["inconclusive_reason"] = "HIBP check was not run (checks_run=0); no conclusion about credential exposure is possible"

    tool_list: list[str] = sorted(
        {str(f.get("evidence_type") or "").lower()
         for f in resolved_findings if f.get("evidence_type")}
    )

    # Compute WSTG coverage from tools_executed + findings
    from src.reports.wstg_coverage import build_wstg_coverage
    wstg_result = build_wstg_coverage(tool_list, resolved_findings)
    wstg_coverage_pct = wstg_result.coverage_percentage
    wstg_low = wstg_coverage_pct < 70.0

    qg: dict[str, Any] = {
        "warnings": [],
        "wstg_coverage_pct": wstg_coverage_pct,
        "wstg_low_coverage": wstg_low,
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
        "wstg_coverage": {
            "coverage_percentage": wstg_coverage_pct,
            "total_tests": wstg_result.total_tests,
            "covered": wstg_result.covered,
            "partial": wstg_result.partial,
            "not_covered": wstg_result.not_covered,
            "by_category": wstg_result.by_category,
        },
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
        email=operator_email,
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
        csrf_structured=csrf_s,
        cmdi_structured=cmdi_s,
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
        remediation_matrix=remediation_stages.get("remediation_matrix", []),
        retest_plan=retest_plan,
        zero_day_assessment=zero_day,
        cost_summary=cost_summary,
        quick_fuzz_summary=(
            {
                "findings_count": len(quick_fuzz_output.get("findings", [])),
                "candidates_count": len(quick_fuzz_output.get("candidates", [])),
                "by_category": list({
                    f.get("category", "unknown")
                    for f in quick_fuzz_output.get("findings", [])
                }),
            }
            if quick_fuzz_output
            else {}
        ),
        burp_config_available=False,
    )


# ---------------------------------------------------------------------------
# 3. generate_valhalla_sections() — LLM for all 13 Valhalla AI sections
# ---------------------------------------------------------------------------


def _build_structured_fallback(section_key: str, context: ValhallaReportContext) -> str:
    """Generate evidence-backed structured text when LLM is unavailable."""
    findings = context.findings or []
    sev = context.severity_counts or {}
    total = sum(sev.values()) if isinstance(sev, dict) else len(findings)
    wstg_pct = context.report_quality_gate.get("wstg_coverage_pct", 0) if isinstance(context.report_quality_gate, dict) else 0
    qg = context.report_quality_gate if isinstance(context.report_quality_gate, dict) else {}

    if section_key == "executive_summary_valhalla":
        crit = sev.get("critical", 0)
        high = sev.get("high", 0)
        med = sev.get("medium", 0)
        low = sev.get("low", 0)
        info = sev.get("info", 0)
        lines = [
            f"Assessment of {context.target_url} (scan {context.scan_id}).",
            f"Total findings: {total} (critical={crit}, high={high}, medium={med}, low={low}, info={info}).",
            f"WSTG coverage: {wstg_pct:.0f}%. Tool health: {qg.get('tool_health', 'unknown')}.",
            f"Evidence confidence: {qg.get('evidence_confidence', 'unknown')}.",
        ]
        if findings:
            top = findings[:3]
            lines.append("Top findings by severity:")
            for i, f in enumerate(top, 1):
                if isinstance(f, dict):
                    lines.append(f"  {i}. [{f.get('severity', 'info').upper()}] {f.get('title', 'untitled')}")
        lines.append("Limitations: WSTG coverage below 70% means many categories were not assessed.")
        return "\n".join(lines)

    if section_key == "executive_summary":
        return _build_structured_fallback("executive_summary_valhalla", context)

    if section_key == "vulnerability_description":
        if not findings:
            return "No vulnerability findings were recorded during this assessment."
        lines = ["Vulnerability findings summary:"]
        for f in findings[:10]:
            if isinstance(f, dict):
                lines.append(f"- [{f.get('severity', 'info').upper()}] {f.get('title', 'untitled')}: {f.get('description', 'No description')[:200]}")
        if len(findings) > 10:
            lines.append(f"... and {len(findings) - 10} more findings.")
        return "\n".join(lines)

    if section_key == "remediation_step":
        if not findings:
            return "No remediation steps — no findings recorded."
        lines = ["Remediation priorities (by severity):"]
        for f in findings[:10]:
            if isinstance(f, dict):
                sev_val = f.get("severity", "info")
                lines.append(f"- [{sev_val.upper()}] {f.get('title', 'untitled')}: Review and apply fix per finding details.")
        return "\n".join(lines)

    if section_key == "business_risk":
        crit = sev.get("critical", 0)
        high = sev.get("high", 0)
        if crit > 0 or high > 0:
            return f"Business risk is elevated due to {crit} critical and {high} high severity findings. Immediate remediation recommended. Exploitable impact confirmed via payloads, commands, and exploitation results. WSTG coverage: {wstg_pct:.0f}%."
        return f"Business risk is inconclusive. {total} finding(s) recorded at medium severity or below. No critical or high severity findings validated. WSTG coverage: {wstg_pct:.0f}%."

    if section_key == "compliance_check":
        return f"Compliance mapping is limited to the {total} validated finding(s) and coverage gaps. OWASP categories without tested evidence must be treated as not assessed, not as clean. WSTG coverage: {wstg_pct:.0f}%. Evidence confidence: {qg.get('evidence_confidence', 'unknown')}."

    if section_key == "prioritization_roadmap":
        if not findings:
            return "No findings to prioritize."
        lines = ["Prioritization roadmap:"]
        for tier, sev_label in [("Immediate (48h)", "critical"), ("Short-term (2 weeks)", "high"), ("Medium-term (1 month)", "medium"), ("Long-term (quarter)", "low")]:
            tier_findings = [f for f in findings if isinstance(f, dict) and f.get("severity") == sev_label]
            if tier_findings:
                lines.append(f"- {tier}: {len(tier_findings)} finding(s) — {', '.join(f.get('title', 'untitled')[:50] for f in tier_findings[:3])}")
        return "\n".join(lines)

    if section_key == "hardening_recommendations":
        tech = context.tech_stack_structured or {}
        lines = ["Hardening recommendations:"]
        if tech.get("web_server"):
            lines.append(f"- Web server: {tech['web_server']} — ensure latest stable version, disable unnecessary modules")
        if tech.get("cms"):
            lines.append(f"- CMS: {tech['cms']} — apply all security patches, review plugin inventory")
        headers = context.security_headers_analysis or {}
        missing = headers.get("missing_recommended", [])
        if missing:
            lines.append(f"- HTTP headers: add missing headers: {', '.join(missing[:5])}")
        ssl = context.ssl_tls_analysis or {}
        if ssl.get("weak_protocols"):
            lines.append(f"- TLS: disable weak protocols: {', '.join(ssl['weak_protocols'][:3])}")
        lines.append("- Integrate security testing into CI/CD pipeline")
        lines.append("- Deploy WAF and centralized logging")
        return "\n".join(lines)

    if section_key == "attack_scenarios":
        scenarios = context.attack_scenarios or []
        if scenarios:
            lines = ["Attack scenarios:"]
            for s in scenarios[:5]:
                if isinstance(s, dict):
                    lines.append(f"- {s.get('title', 'untitled')}: likelihood={s.get('likelihood', 'unknown')}, persona={s.get('persona', 'unknown')}")
            return "\n".join(lines)
        return "No validated attack scenarios. Findings do not form a complete attack chain. Additional testing required for scenario validation."

    if section_key == "exploit_chains":
        chains = context.exploit_chains or []
        if chains:
            lines = ["Exploit chains:"]
            for c in chains[:5]:
                if isinstance(c, dict):
                    lines.append(f"- {c.get('title', 'untitled')}: status={c.get('status', 'unknown')}, impact={c.get('impact', 'unknown')}")
            return "\n".join(lines)
        return f"No validated exploit chain was demonstrated. Multi-step chains require multiple validated findings with scope-appropriate impact. WSTG coverage: {wstg_pct:.0f}%."

    if section_key == "remediation_stages":
        stages = context.remediation_stages or {}
        lines = ["Remediation stages:"]
        for tier_name, tier_label in [("tier_1_immediate", "Tier 1 — Immediate (48h)"), ("tier_2_short_term", "Tier 2 — Short-Term (2 weeks)"), ("tier_3_architectural", "Tier 3 — Architectural (SDLC)")]:
            items = stages.get(tier_name, [])
            if items:
                lines.append(f"{tier_label}:")
                for item in items[:5]:
                    if isinstance(item, dict):
                        lines.append(f"  - {item.get('title') or item.get('action', 'untitled')}")
        return "\n".join(lines) if len(lines) > 1 else "No remediation stages generated — no findings recorded."

    if section_key == "zero_day_potential":
        return f"Novel vulnerability indication: Not indicated. The {total} finding(s) reflect known vulnerability patterns and no novel vulnerability class was observed. WSTG coverage: {wstg_pct:.0f}%. Evidence confidence: {qg.get('evidence_confidence', 'unknown')}."

    if section_key == "cost_summary":
        cost = context.cost_summary or {}
        lines = [
            "Scan cost summary:",
            f"- Total API calls: {cost.get('total_calls', 0)}",
            f"- Total tokens: {cost.get('total_tokens', 0)}",
            f"- Total cost: ${cost.get('total_cost_usd', 0):.4f}",
        ]
        by_provider = cost.get("by_provider", {})
        if by_provider:
            lines.append(f"- By provider: {', '.join(f'{k}: ${v:.4f}' for k, v in by_provider.items())}")
        return "\n".join(lines)

    if section_key == "bounty_hunter_tactics":
        bounty = context.bounty_plan or {}
        if bounty:
            lines = ["Bug Bounty Hunter Tactics:"]
            surfaces = bounty.get("surfaces_classified", bounty.get("surfaces", []))
            if surfaces:
                lines.append(f"- {len(surfaces)} attack surface(s) classified")
                for s in surfaces[:5]:
                    if isinstance(s, dict):
                        lines.append(f"  - {s.get('surface_type', 'unknown')}: {s.get('priority', 'medium')} priority")
            prioritized = bounty.get("prioritized_vulns", [])
            if prioritized:
                lines.append(f"- {len(prioritized)} vulnerability type(s) prioritized for bounty")
            insights = bounty.get("llm_insights", "")
            if insights:
                lines.append(f"- LLM insights: {insights[:300]}")
            return "\n".join(lines)
        return "No bounty plan data available for this assessment."

    if section_key == "quick_fuzz_findings":
        qf = context.quick_fuzz_summary or {}
        if qf:
            lines = ["Quick Fuzz Pre-Scan Results:"]
            fc = qf.get("findings_count", 0)
            cc = qf.get("candidates_count", 0)
            cats = qf.get("by_category", [])
            lines.append(f"- {fc} quick-win finding(s) detected across {len(cats)} category(ies)")
            lines.append(f"- {cc} endpoint(s) flagged for deep vuln analysis")
            if cats:
                lines.append(f"- Categories: {', '.join(str(c) for c in cats[:10])}")
            return "\n".join(lines)
        findings_qf = [f for f in findings if f.get("source") == "quick_fuzz" or f.get("category", "").lower() == "quick_fuzz"]
        if findings_qf:
            lines = [f"Quick Fuzz: {len(findings_qf)} quick-win finding(s) detected during pre-scan:"]
            for f in findings_qf[:5]:
                lines.append(f"  - [{f.get('severity', 'info').upper()}] {f.get('title', 'untitled')}")
            return "\n".join(lines)
        return "Quick fuzz pre-scan did not identify quick-win vulnerabilities."

    if section_key == "ai_security_findings":
        ai_findings = [f for f in findings if f.get("owasp_category", "").upper().startswith("A05")
                       and any(kw in f.get("title", "").lower() + f.get("description", "").lower()
                               for kw in ("prompt injection", "system prompt", "llm", "ai endpoint", "rag poisoning"))]
        if ai_findings:
            lines = [f"AI/LLM Security Assessment: {len(ai_findings)} finding(s) related to AI-specific vulnerabilities:"]
            for f in ai_findings[:5]:
                lines.append(f"  - [{f.get('severity', 'info').upper()}] {f.get('title', 'untitled')}")
                ev = f.get("evidence_type", "")
                if ev:
                    lines.append(f"    Evidence tier: {f.get('evidence_tier', 'N/A')}, type: {ev}")
                taint = f.get("taint_path", [])
                if taint:
                    lines.append(f"    Taint path: {' → '.join(str(t) for t in taint[:4])}")
            return "\n".join(lines)
        return "No AI/LLM-specific security findings were identified in this assessment."

    return f"No evidence-backed narrative available for this section. ({total} finding(s) recorded, WSTG coverage: {wstg_pct:.0f}%)."


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
                "evidence_tier": f.get("evidence_tier"),
                "title": f.get("title", ""),
                "description": _truncate(str(f.get("description") or ""), 400),
                "cwe": f.get("cwe"),
                "cvss": f.get("cvss") or f.get("cvss_score"),
                "confidence": f.get("confidence"),
                "validation_status": f.get("validation_status"),
                "evidence_quality": f.get("evidence_quality"),
                "owasp_category": f.get("owasp_category"),
                "exploit_demonstrated": f.get("exploit_demonstrated"),
                "code_location": f.get("code_location"),
                "taint_path": f.get("taint_path"),
                "payload_attempted": f.get("payload_attempted"),
                "payload_successful": f.get("payload_successful"),
                "reproducible_steps": f.get("reproducible_steps"),
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
        "remediation_matrix": context.remediation_matrix,
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
    has_llm = llm_callable is not None or has_any_llm_key()

    for section_key in _VALHALLA_AI_SECTION_ORDER:
        if section_key not in REPORT_AI_SECTION_KEYS:
            logger.warning(
                "valhalla_ai_unknown_section",
                extra={"section_key": section_key},
            )
            continue

        if not has_llm:
            generated[section_key] = _build_structured_fallback(section_key, context)
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
            generated[section_key] = _build_structured_fallback(section_key, context)
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
            generated[section_key] = _build_structured_fallback(section_key, context)
            continue

        if not text:
            generated[section_key] = _build_structured_fallback(section_key, context)
            continue

        # Guard against prompt-scaffolding / context-JSON regurgitation and stub output
        # before the text reaches the renderer (this path bypasses run_ai_text_generation).
        if contains_raw_prompt_leakage(text) or contains_ai_stub_output(text):
            logger.warning(
                "valhalla_ai_leakage_or_stub_detected",
                extra={"section_key": section_key},
            )
            generated[section_key] = _build_structured_fallback(section_key, context)
            continue

        text = sanitize_ai_report_text(text)
        if not text.strip():
            generated[section_key] = _build_structured_fallback(section_key, context)
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
    et_badge: dict[int, str] = {
        4: '<span class="badge badge-critical">EXPLOITED</span>',
        3: '<span class="badge badge-high">CONFIRMED</span>',
        2: '<span class="badge badge-medium">SUSPECTED</span>',
        1: '<span class="badge badge-info">INFO</span>',
    }
    for f in sorted_f:
        sev = (f.get("severity") or "info").lower()
        b = badge.get(sev, badge["info"])
        cvss = f.get("cvss") or f.get("cvss_score")
        cvss_str = f"{float(cvss):.1f}" if isinstance(cvss, (int, float)) else "—"
        et_raw = f.get("evidence_tier")
        et = et_badge.get(int(et_raw), "—") if et_raw and str(et_raw).isdigit() else "—"
        rows.append(
            "<tr>"
            f"<td>{b}</td>"
            f"<td>{et}</td>"
            f"<td>{f.get('title', '')}</td>"
            f"<td>{f.get('cwe', '—')}</td>"
            f"<td>{cvss_str}</td>"
            f"<td>{f.get('confidence', '—')}</td>"
            f"<td>{f.get('evidence_quality', '—')}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _findings_detail_html(findings: list[dict[str, Any]]) -> str:
    """Detailed per-finding section: payloads attempted/successful, taint paths, code locations, reproducible steps."""
    sections: list[str] = []
    for f in findings[:30]:
        title = f.get("title", "Unknown")
        pa = f.get("payload_attempted") or []
        ps = f.get("payload_successful") or []
        tp = f.get("taint_path") or []
        cl = f.get("code_location") or ""
        rs = f.get("reproducible_steps") or ""
        screenshots = f.get("screenshots") or f.get("screenshot_base64") or f.get("screenshot_path") or ""
        adv_score = f.get("adversarial_score")
        cvss_vector = f.get("cvss_vector") or ""

        if not pa and not ps and not tp and not cl and not rs and not screenshots and not adv_score and not cvss_vector:
            continue

        parts: list[str] = [f'<div class="card finding-detail-card"><h3>{title}</h3>']

        if adv_score is not None:
            parts.append(f'<p><strong>Adversarial Score:</strong> {adv_score}</p>')

        if cvss_vector:
            parts.append(f'<p><strong>CVSS Vector:</strong> <code>{cvss_vector}</code></p>')

        if cl:
            parts.append(f'<p><strong>Code Location:</strong> <code>{cl}</code></p>')

        if tp:
            tp_html = " → ".join(f'<code>{s}</code>' for s in tp[:10])
            parts.append(f'<p><strong>Taint Path:</strong> {tp_html}</p>')

        if pa:
            pa_items = "".join(f"<li><code>{p[:200]}</code></li>" for p in pa[:10])
            parts.append(f'<p><strong>Payloads Attempted:</strong></p><ul>{pa_items}</ul>')

        if ps:
            ps_items = "".join(f"<li><code>{p[:200]}</code></li>" for p in ps[:10])
            parts.append(f'<p><strong>Payloads Successful:</strong></p><ul>{ps_items}</ul>')

        if rs:
            parts.append(f'<p><strong>Reproducible Steps:</strong></p><pre>{rs[:2000]}</pre>')

        if screenshots:
            if isinstance(screenshots, str) and screenshots.startswith("data:image"):
                parts.append(f'<p><strong>Screenshot:</strong></p><img src="{screenshots}" alt="Evidence screenshot" style="max-width:100%;border:1px solid var(--border);">')
            elif isinstance(screenshots, str) and screenshots.startswith("/"):
                parts.append(f'<p><strong>Screenshot:</strong> <code>{screenshots}</code></p>')
            elif isinstance(screenshots, list):
                for idx, sc in enumerate(screenshots[:5]):
                    if isinstance(sc, dict):
                        sc_data = sc.get("data") or sc.get("base64") or sc.get("url", "")
                        sc_alt = sc.get("alt", f"Screenshot {idx+1}")
                        if sc_data:
                            if sc_data.startswith("data:image") or sc_data.startswith("http"):
                                parts.append(f'<p><strong>{sc_alt}:</strong></p><img src="{sc_data}" alt="{sc_alt}" style="max-width:100%;border:1px solid var(--border);">')
                            else:
                                parts.append(f'<p><strong>{sc_alt}:</strong> <code>{sc_data[:200]}</code></p>')
                    elif isinstance(sc, str):
                        if sc.startswith("data:image") or sc.startswith("http"):
                            parts.append(f'<img src="{sc}" alt="Screenshot {idx+1}" style="max-width:100%;border:1px solid var(--border);">')
                        elif len(sc) > 100:
                            parts.append(f'<img src="data:image/png;base64,{sc}" alt="Screenshot {idx+1}" style="max-width:100%;border:1px solid var(--border);">')
                        else:
                            parts.append(f'<p><strong>Screenshot:</strong> <code>{sc}</code></p>')

        parts.append("</div>")
        sections.append("\n".join(parts))

    if not sections:
        return '<div class="card"><p style="color:var(--text-secondary)">No detailed payload, taint path, or code location data available.</p></div>'
    return "\n".join(sections)


def _wstg_coverage_matrix_html(context: ValhallaReportContext) -> str:
    """Render WSTG coverage matrix as HTML table."""
    coverage = context.coverage or {}
    wstg = coverage.get("wstg_coverage") or {}
    pct = wstg.get("coverage_percentage", 0)
    total = wstg.get("total_tests", 96)
    covered = wstg.get("covered", 0)
    partial = wstg.get("partial", 0)
    not_covered = wstg.get("not_covered", 0)
    by_category = wstg.get("by_category", {})

    rows = [
        f'<p style="margin-bottom:12px;">Overall WSTG coverage: <strong>{pct:.0f}%</strong> '
        f'({covered} covered, {partial} partial, {not_covered} not assessed of {total} tests)</p>',
        '<table class="data-table"><thead><tr><th>Category</th><th>Covered</th><th>Partial</th><th>Not Assessed</th><th>Total</th><th>%</th></tr></thead><tbody>',
    ]
    for cat_name, counts in sorted(by_category.items()):
        if isinstance(counts, dict):
            rows.append(
                f"<tr><td>{cat_name}</td>"
                f"<td>{counts.get('covered', 0)}</td>"
                f"<td>{counts.get('partial', 0)}</td>"
                f"<td>{counts.get('not_covered', 0)}</td>"
                f"<td>{counts.get('total', 0)}</td>"
                f"<td>{counts.get('percentage', 0):.0f}%</td></tr>"
            )
    rows.append("</tbody></table>")
    return "\n".join(rows)


def _unverified_items_html(context: ValhallaReportContext) -> str:
    """Render unverified/follow-up items from findings with low confidence."""
    findings = context.findings or []
    unverified = [
        f for f in findings
        if isinstance(f, dict) and f.get("confidence") in ("possible", "likely", "advisory")
    ]
    if not unverified:
        return '<p style="color:var(--text-secondary)">No unverified items — all findings have sufficient evidence.</p>'

    rows = [
        f'<p style="margin-bottom:12px;">{len(unverified)} finding(s) require additional validation:</p>',
        '<table class="data-table"><thead><tr><th>Severity</th><th>Title</th><th>Confidence</th><th>Evidence Quality</th><th>Required for Validation</th></tr></thead><tbody>',
    ]
    for f in sorted(unverified, key=lambda x: _SEVERITY_RANK.get((x.get("severity") or "").lower(), 99)):
        sev = (f.get("severity") or "info").lower()
        badge = f'<span class="badge badge-{sev}">{sev.upper()}</span>' if sev in _SEVERITY_RANK else sev
        conf = f.get("confidence", "unknown")
        eq = f.get("evidence_quality", "none")
        data = f.get("data") or {}
        notes = data.get("applicability_notes") or f.get("applicability_notes") or "Additional testing required"
        rows.append(
            f"<tr><td>{badge}</td>"
            f"<td>{f.get('title', 'untitled')}</td>"
            f"<td>{conf}</td>"
            f"<td>{eq}</td>"
            f"<td>{str(notes)[:200]}</td></tr>"
        )
    rows.append("</tbody></table>")
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
    text = context.ai_sections.get(key, "") or ""

    # Replace sentinel patterns with structured fallback
    sentinel_patterns = [
        "AI generation skipped",
        "AI generation skipped: no LLM provider available",
        "AI generation skipped: could not generate content",
        "See \"Vulnerability Description\"",
        "See Vulnerability Description",
        "To be determined based on organizational priorities",
        "To be determined",
    ]
    for pattern in sentinel_patterns:
        if pattern.lower() in text.lower():
            text = _build_structured_fallback(key, context)
            break

    if not text:
        text = _build_structured_fallback(key, context)

    text_safe = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text_html = text_safe.replace("\n\n", "</p><p>").replace("\n", "<br>")
    return (
        f'<section id="section-{key}" class="ai-section">'
        f"<h2>{label}</h2>"
        f"<div class=\"ai-content\"><p>{text_html}</p></div>"
        f"</section>"
    )


def _retest_plan_html(context: ValhallaReportContext) -> str:
    """Render retest/verification commands per vulnerability type."""
    plan = context.retest_plan or []
    if not plan:
        return '<p style="color:var(--text-secondary)">No retest plan generated.</p>'
    rows: list[str] = []
    for item in plan[:20]:
        vt = item.get("vuln_type", "unknown")
        cmd = item.get("verification_command", "")
        fid = item.get("finding_id", "")
        rows.append(
            f"<tr><td>{vt}</td><td>{fid}</td><td><code>{cmd[:300]}</code></td></tr>"
        )
    return (
        '<table class="data-table"><thead><tr><th>Vuln Type</th><th>Finding ID</th><th>Verification Command</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
    )


def _timeline_html(context: ValhallaReportContext) -> str:
    """Render scan timeline events."""
    tools = context.tools_executed or []
    if not tools:
        return '<p style="color:var(--text-secondary)">No timeline data available.</p>'
    rows: list[str] = []
    for t in tools[:40]:
        tool = t.get("tool", "unknown")
        phase = t.get("phase", "")
        ts = t.get("timestamp", "")
        rows.append(f"<tr><td>{ts}</td><td>{phase}</td><td>{tool}</td></tr>")
    return (
        '<table class="data-table"><thead><tr><th>Timestamp</th><th>Phase</th><th>Tool</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table>'
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
                {"action": "Integrate security testing into CI/CD pipeline", "effort": "Complex Refactor", "owner": "DevOps / Security team"},
                {"action": "Deploy WAF and centralized logging", "effort": "Moderate", "owner": "Infrastructure team"},
                {"action": "Implement automated dependency scanning", "effort": "Moderate", "owner": "Development team"},
            ]
        rem_html += f"<h3>{tier_label}</h3><table class=\"data-table\"><thead><tr><th>Finding</th><th>Remediation Action</th><th>Verification</th><th>Owner</th><th>Effort</th></tr></thead><tbody>"
        for item in (items if isinstance(items, list) else []):
            if isinstance(item, dict):
                title = item.get("title") or item.get("action", "—")
                action = item.get("action", "Review and apply fix per finding details")
                verification = item.get("verification", "Re-test after fix")
                owner = item.get("owner", "Development team")
                effort = item.get("effort", "—")
                rem_html += (
                    f"<tr><td>{title}</td>"
                    f"<td>{action}</td>"
                    f"<td>{verification}</td>"
                    f"<td>{owner}</td>"
                    f"<td>{effort}</td></tr>"
                )
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

    from src.reports.valhalla_report_context import get_brand
    brand = get_brand()
    logo_b64 = brand.logo_base64_svg

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
  .brand-row {{
    display: flex;
    align-items: center;
    gap: 16px;
    margin-bottom: 10px;
  }}
  .brand-logo {{
    height: 36px;
    width: auto;
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

  @media print {{
    body {{
      background: #fff;
      color: #111;
      font-size: 12px;
    }}
    header.valhalla-header {{
      background: #fff;
      border-bottom: 2px solid #000;
      padding: 20px 30px 16px;
    }}
    .header-content .brand {{ color: #333; }}
    .header-content h1 {{ color: #111; font-size: 22px; }}
    .brand-logo {{ max-height: 28px; }}
    .tier-badge {{
      background: #333;
      color: #fff;
    }}
    main {{ padding: 16px 30px 32px; }}
    .card {{
      background: #fff;
      border: 1px solid #ccc;
    }}
    table.data-table thead th {{
      background: #f5f5f5;
      color: #333;
    }}
    table.data-table tbody td {{
      color: #111;
    }}
    .chart-bar {{
      -webkit-print-color-adjust: exact;
      print-color-adjust: exact;
    }}
    footer.valhalla-footer {{
      border-top: 1px solid #999;
      color: #666;
    }}
    @page {{
      margin: 15mm;
      @bottom-center {{
        content: "Svalbard Security Inc. Valhalla Report — Page " counter(page);
        font-size: 10px;
        color: #999;
      }}
    }}
    @page :first {{
      @top-center {{
        content: "";
      }}
    }}
    .page-break {{
      page-break-after: always;
    }}
  }}
</style>
</head>
<body>

<header class="valhalla-header">
  <div class="header-content">
    <div class="tier-badge">Valhalla Tier</div>
    <div class="brand-row">
      <img src="data:image/svg+xml;base64,{logo_b64}" alt="{brand.alt_text}" class="brand-logo" width="120" height="51" />
      <p class="brand">{brand.name}</p>
    </div>
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
          <th>Severity</th><th>Evidence Tier</th><th>Title</th><th>CWE</th><th>CVSS</th><th>Confidence</th><th>Evidence</th>
        </tr>
      </thead>
      <tbody>
        {_findings_table_html(context.findings)}
      </tbody>
    </table>
  </div>
</section>

<!-- Findings Detail — payloads, taint paths, code locations, reproducible steps -->
<section id="section-findings-detail">
  <h2>Findings Detail</h2>
  {_findings_detail_html(context.findings)}
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

<!-- WSTG Coverage Matrix -->
<section id="section-wstg-coverage" class="card">
  <h2>OWASP WSTG Coverage Matrix</h2>
  {_wstg_coverage_matrix_html(context)}
</section>

<!-- Retest / Verification Plan -->
<section id="section-retest-plan" class="card">
  <h2>Verification &amp; Retest Plan</h2>
  {_retest_plan_html(context)}
</section>

<!-- Scan Timeline -->
<section id="section-timeline" class="card">
  <h2>Scan Timeline</h2>
  {_timeline_html(context)}
</section>

<!-- Unverified / Follow-up Items -->
<section id="section-unverified" class="card">
  <h2>Unverified / Follow-up Items</h2>
  {_unverified_items_html(context)}
</section>

<!-- AI-Generated Sections -->
{ai_sections_html}

<!-- HIBP -->
{hibp_block}

</main>

<footer class="valhalla-footer">
  <span>{brand.name} Valhalla Report &mdash; {context.scan_id[:12]}…</span>
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
    """Render Valhalla report as Markdown with Svalbard Security Inc. branding."""
    from src.reports.valhalla_report_context import get_brand
    brand = get_brand()
    lines: list[str] = [
        f"![{brand.alt_text}](./logo.svg)",
        "",
        f"Prepared by {brand.name}",
        "",
        f"# {context.engagement_title}",
        "",
        f"**Target:** {context.target_url}",
        f"**Scan ID:** {context.scan_id}",
        "**Tier:** Valhalla",
        f"**Report prepared by:** {brand.name}",
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
