"""Centralized prompt registry and JSON schemas for LLM phase outputs."""

import json
import re
from typing import Any

# Max length for user-provided strings in prompts (mitigates prompt injection)
MAX_PROMPT_STRING_LENGTH = 4096
MAX_PROMPT_OBJECT_LENGTH = 65536

# Patterns that may indicate prompt injection attempts
_SUSPICIOUS_PATTERNS = [
    r"ignore\s+(previous|all|the\s+above|prior)\s+instructions?",
    r"ignore\s+everything",
    r"disregard\s+(previous|all|instructions?)",
    r"you\s+are\s+now",
    r"new\s+(instruction|role|persona)",
    r"system\s*:",
    r"assistant\s*:",
    r"human\s*:",
    r"jailbreak",
    r"override\s+(instructions?|system)",
    r"<\|im_end\|>",
    r"<\|im_start\|>",
]


def _sanitize_for_prompt(text: str, max_length: int = MAX_PROMPT_STRING_LENGTH) -> str:
    """
    Sanitize user-provided text before embedding in LLM prompts.
    Mitigates prompt injection: removes newlines, limits length, truncates at suspicious substrings.
    """
    if not isinstance(text, str):
        text = str(text)
    # Normalize whitespace: collapse newlines and multiple spaces to single space
    text = " ".join(text.split())
    # Truncate at first suspicious pattern (case-insensitive)
    text_lower = text.lower()
    for pat in _SUSPICIOUS_PATTERNS:
        match = re.search(pat, text_lower, re.IGNORECASE)
        if match:
            text = text[: match.start()]
    text = text.strip()
    return text[:max_length]


def _sanitize_kwargs_for_prompt(kwargs: dict[str, Any]) -> dict[str, Any]:
    """Sanitize all kwargs before passing to template.format."""
    result: dict[str, Any] = {}
    for k, v in kwargs.items():
        if isinstance(v, str):
            result[k] = _sanitize_for_prompt(v, MAX_PROMPT_STRING_LENGTH)
        elif isinstance(v, (dict, list)):
            serialized = json.dumps(v, default=str)
            result[k] = _sanitize_for_prompt(serialized, MAX_PROMPT_OBJECT_LENGTH)
        else:
            result[k] = _sanitize_for_prompt(str(v), MAX_PROMPT_STRING_LENGTH)
    return result


# Phase names aligned with ScanPhase
RECON = "recon"
THREAT_MODELING = "threat_modeling"
VULN_ANALYSIS = "vuln_analysis"
EXPLOITATION = "exploitation"
POST_EXPLOITATION = "post_exploitation"
REPORTING = "reporting"

# KAL-008 — bump when orchestration semantics change (provider / local prompt cache invalidation).
ORCHESTRATION_PROMPT_VERSION = "kal008-20250327"
VA_ACTIVE_SCAN_PLANNING_PROMPT_VERSION = "va-plan-kal008-20250327"

# Kali MCP (policy-gated argv) categories and allowlisted binaries — align with src.recon.mcp.policy.
KALI_MCP_ORCHESTRATION_BLOCK = (
    "=== KALI MCP TOOL TAXONOMY (policy allowlist; fail-closed) ===\n"
    "Categories map to specific binaries only; do not suggest tools outside the category.\n"
    "- network_scanning: nmap, rustscan, masscan\n"
    "- web_fingerprinting: httpx, whatweb, wpscan, nikto, theHarvester (OSINT; gated)\n"
    "- api_testing: httpx, nuclei, curl\n"
    "- bruteforce_testing: gobuster, feroxbuster, dirsearch, ffuf, wfuzz, dirb\n"
    "- ssl_analysis: testssl.sh; openssl only subcommands s_client, s_time, version, ciphers\n"
    "- dns_enumeration: dig, subfinder, amass, dnsx, host, nslookup\n"
    "- password_audit: hydra, medusa — GATED: allowed only when category is password_audit AND "
    "both request/tenant opt-in and server-side password-audit enablement apply; otherwise treat as denied.\n\n"
    "MCP run_* (VA sandbox, separate allowlist): run_dalfox, run_xsstrike, run_ffuf, run_sqlmap, "
    "run_nuclei, run_whatweb, run_nikto, run_testssl — dispatched only through policy-checked "
    "sandbox/Celery paths; argv must stay non-interactive and injection-safe (no shell metacharacters).\n\n"
    "When to suggest MCP run_* vs full ARGUS scan pipeline:\n"
    "- Prefer targeted MCP run_* when the operator needs a single focused check (one tool, one URL/host, "
    "quick validation, iterative triage) and scope is explicit.\n"
    "- Prefer the full scan pipeline (recon → threat modeling → vuln_analysis with integrated active scan "
    "when sandbox is enabled) for comprehensive coverage, phase correlation, audit trail, and stored artifacts.\n\n"
    "Safety and authorization:\n"
    "- Restrict all recommendations to in-scope, authorized targets; never suggest probing third parties.\n"
    "- Do not recommend destructive actions (data destruction, service-wide DoS, indiscriminate credential attacks) "
    "or exploitation without explicit policy/approval where the engagement requires it.\n"
    "- Never assume password_audit or hydra/medusa are permitted — state that they require explicit policy gates.\n"
    "=== END KALI MCP BLOCK ===\n"
)

VA_SANDBOX_MCP_RUN_BLOCK = (
    "=== VA PHASE — SANDBOX MCP run_* (vuln/active validation) ===\n"
    "These operations complement (not replace) Kali category MCP: they run inside the VA sandbox allowlist.\n"
    "Correlate any run_* suggestions with evidence from the threat model and assets; avoid redundant full-pipeline "
    "re-runs when a single allowlisted run_* would answer a narrow question.\n"
    "=== END VA SANDBOX MCP BLOCK ===\n"
)

SYSTEM_PROMPT_BASE = (
    "You are an expert penetration tester and security analyst. "
    "You analyze REAL tool output (nmap, dig, whois, crt.sh, Shodan, NVD). "
    "Respond ONLY with valid JSON. No markdown, no explanation, only the JSON object. "
    f"[orchestration_prompt_version={ORCHESTRATION_PROMPT_VERSION}]"
)

FIXER_SYSTEM_PROMPT = (
    "You are a JSON repair assistant. The previous response contained invalid JSON. "
    "Return ONLY the corrected JSON object, nothing else. No markdown, no explanation. "
    f"[orchestration_prompt_version={ORCHESTRATION_PROMPT_VERSION}]"
)

# Phase -> (system_prompt, user_prompt_template)
PHASE_PROMPTS: dict[str, tuple[str, str]] = {
    RECON: (
        SYSTEM_PROMPT_BASE,
        (
            "You are performing reconnaissance on target: {target}.\n"
            "Options: {options}\n\n"
            + KALI_MCP_ORCHESTRATION_BLOCK
            + "\n"
            + "Below is REAL output from security tools. Analyze it carefully.\n\n"
            + "=== TOOL RESULTS ===\n{tool_results}\n=== END TOOL RESULTS ===\n\n"
            + "Based on the real tool output above, return a JSON object with:\n"
            + '- "assets": array of discovered assets (IPs, domains, services with versions)\n'
            + '- "subdomains": array of discovered subdomains\n'
            + '- "ports": array of open port numbers (integers)\n\n'
            + "Extract ONLY real data from the tool output. Do NOT invent or guess.\n"
            + 'Return JSON: {{"assets": ["string"], "subdomains": ["string"], "ports": [number]}}'
        ),
    ),
    THREAT_MODELING: (
        SYSTEM_PROMPT_BASE,
        "Build a threat model for the following real assets discovered during recon.\n\n"
        "Assets: {assets}\n\n"
        "=== NVD CVE DATA ===\n{nvd_data}\n=== END NVD DATA ===\n\n"
        "Based on the real assets and known CVEs above, return a JSON threat model:\n"
        '- "threat_model.threats": array of specific, actionable threats referencing real CVEs\n'
        '- "threat_model.attack_surface": array of exposed services/endpoints\n'
        '- "threat_model.cves": array of relevant CVE IDs\n\n'
        'Return JSON: {{"threat_model": {{"threats": ["string"], "attack_surface": ["string"], "cves": ["CVE-XXXX-XXXX"]}}}}',
    ),
    VULN_ANALYSIS: (
        SYSTEM_PROMPT_BASE,
        (
            KALI_MCP_ORCHESTRATION_BLOCK
            + "\n"
            + VA_SANDBOX_MCP_RUN_BLOCK
            + "\n"
            + "Analyze vulnerabilities based on the real threat model and assets.\n\n"
            + "Threat model: {threat_model}\n"
            + "Assets: {assets}\n\n"
            + "{active_scan_context}"
            + "For each vulnerability, provide:\n"
            + '- "severity": critical/high/medium/low/info\n'
            + '- "title": descriptive title\n'
            + '- "cwe": CWE identifier (e.g. CWE-79)\n'
            + '- "cvss": CVSS score (float)\n'
            + '- "description": detailed description\n'
            + '- "affected_asset": which asset is affected\n'
            + '- "remediation": recommended fix\n\n'
            + "Only report vulnerabilities supported by evidence from the threat model.\n"
            + "If active scan findings are provided above, incorporate them into your analysis — "
            + "confirm, correlate, or augment them with additional context.\n"
            + 'Return JSON: {{"findings": [{{"severity": "string", "title": "string", "cwe": "string", '
            + '"cvss": 0.0, "description": "string", "affected_asset": "string", "remediation": "string"}}]}}'
        ),
    ),
    EXPLOITATION: (
        SYSTEM_PROMPT_BASE,
        "Based on the following real vulnerability findings, plan theoretical exploit paths.\n"
        "Do NOT execute any exploits. Provide a theoretical analysis only.\n\n"
        "Findings: {findings}\n\n"
        "For each exploitable finding:\n"
        '- "finding_id": reference to the finding\n'
        '- "status": "theoretical"\n'
        '- "title": exploit name\n'
        '- "technique": MITRE ATT&CK technique ID if applicable\n'
        '- "description": how the exploit would work\n'
        '- "impact": potential impact\n'
        '- "difficulty": easy/medium/hard\n\n'
        'Return JSON: {{"exploits": [{{"finding_id": "string", "status": "theoretical", '
        '"title": "string", "technique": "string", "description": "string", '
        '"impact": "string", "difficulty": "string"}}], '
        '"evidence": [{{"type": "string", "description": "string", "finding_id": "string"}}]}}',
    ),
    POST_EXPLOITATION: (
        SYSTEM_PROMPT_BASE,
        "Based on the following theoretical exploits, analyze post-exploitation scenarios.\n\n"
        "Exploits: {exploits}\n\n"
        "Analyze:\n"
        '- "lateral": lateral movement opportunities\n'
        '- "persistence": persistence mechanisms an attacker could establish\n'
        "Each item should reference the exploit and describe the technique.\n\n"
        'Return JSON: {{"lateral": [{{"technique": "string", "description": "string", '
        '"from_exploit": "string"}}], '
        '"persistence": [{{"type": "string", "description": "string", "risk_level": "string"}}]}}',
    ),
    REPORTING: (
        SYSTEM_PROMPT_BASE,
        "Generate a comprehensive penetration test report from the following real data.\n\n"
        "=== FULL PENTEST SUMMARY ===\n{summary}\n=== END SUMMARY ===\n\n"
        "The report must include:\n"
        '- "summary": object with counts by severity (critical, high, medium, low, info) and overall risk rating\n'
        '- "executive_summary": high-level overview for management (2-3 paragraphs)\n'
        '- "sections": array of report section strings (scope, methodology, findings, recommendations)\n'
        '- "findings_detail": array of detailed findings with severity, description, impact, remediation\n'
        '- "ai_insights": array of strategic security insights and recommendations\n'
        '- "risk_rating": overall risk rating (critical/high/medium/low)\n\n'
        'Return JSON: {{"report": {{"summary": {{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, '
        '"risk_rating": "string"}}, "executive_summary": "string", '
        '"sections": ["string"], "findings_detail": [object], "ai_insights": ["string"]}}}}',
    ),
}


# Default values for optional template placeholders (avoids KeyError when not passed)
_TEMPLATE_DEFAULTS: dict[str, Any] = {
    "tool_results": "",
    "nvd_data": "No CVE data available",
    "active_scan_context": "",
}


def get_prompt(phase: str, **kwargs: Any) -> tuple[str, str]:
    """Return (system_prompt, user_prompt) for the given phase with kwargs applied."""
    if phase not in PHASE_PROMPTS:
        raise ValueError(f"Unknown phase: {phase}")
    system, template = PHASE_PROMPTS[phase]
    sanitized = _sanitize_kwargs_for_prompt(kwargs)
    merged = {**_TEMPLATE_DEFAULTS, **sanitized}
    user = template.format(**merged)
    return system, user


def get_fixer_prompt(invalid_json: str, expected_schema: dict[str, Any]) -> tuple[str, str]:
    """Return (system_prompt, user_prompt) for JSON fixer retry."""
    import json as _json

    schema_str = _json.dumps(expected_schema, indent=2)
    user = (
        f"The following response is invalid JSON. Fix it to match this schema.\n\n"
        f"Expected schema:\n{schema_str}\n\n"
        f"Invalid response:\n{invalid_json}\n\n"
        "Return ONLY the corrected JSON object."
    )
    return FIXER_SYSTEM_PROMPT, user


# JSON schemas per phase — align with phases.py output models
RECON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["assets", "subdomains", "ports"],
    "properties": {
        "assets": {"type": "array", "items": {"type": "string"}},
        "subdomains": {"type": "array", "items": {"type": "string"}},
        "ports": {"type": "array", "items": {"type": "integer"}},
    },
}

THREAT_MODEL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["threat_model"],
    "properties": {
        "threat_model": {
            "type": "object",
            "properties": {
                "threats": {"type": "array", "items": {"type": "string"}},
                "attack_surface": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
}

VULN_ANALYSIS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["findings"],
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string"},
                    "title": {"type": "string"},
                    "cwe": {"type": "string"},
                },
            },
        },
    },
}

EXPLOITATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["exploits", "evidence"],
    "properties": {
        "exploits": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "status": {"type": "string"},
                    "title": {"type": "string"},
                },
            },
        },
        "evidence": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "path": {"type": "string"},
                    "finding_id": {"type": "string"},
                },
            },
        },
    },
}

POST_EXPLOITATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["lateral", "persistence"],
    "properties": {
        "lateral": {
            "type": "array",
            "items": {"type": "object"},
        },
        "persistence": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "description": {"type": "string"},
                },
            },
        },
    },
}

REPORTING_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["report"],
    "properties": {
        "report": {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "object",
                    "properties": {
                        "critical": {"type": "integer"},
                        "high": {"type": "integer"},
                        "medium": {"type": "integer"},
                    },
                },
                "sections": {"type": "array", "items": {"type": "string"}},
                "ai_insights": {"type": "array", "items": {"type": "string"}},
            },
        },
    },
}

PHASE_SCHEMAS: dict[str, dict[str, Any]] = {
    RECON: RECON_SCHEMA,
    THREAT_MODELING: THREAT_MODEL_SCHEMA,
    VULN_ANALYSIS: VULN_ANALYSIS_SCHEMA,
    EXPLOITATION: EXPLOITATION_SCHEMA,
    POST_EXPLOITATION: POST_EXPLOITATION_SCHEMA,
    REPORTING: REPORTING_SCHEMA,
}


def get_schema(phase: str) -> dict[str, Any]:
    """Return JSON schema for the given phase output."""
    if phase not in PHASE_SCHEMAS:
        raise ValueError(f"Unknown phase: {phase}")
    return PHASE_SCHEMAS[phase]


# ---------------------------------------------------------------------------
# RPT-004 / VHL-003 — Report AI text sections (Prompt Registry for Celery ai_text_generation)
# ---------------------------------------------------------------------------

REPORT_AI_SECTION_EXECUTIVE_SUMMARY = "executive_summary"
REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION = "vulnerability_description"
REPORT_AI_SECTION_REMEDIATION_STEP = "remediation_step"
REPORT_AI_SECTION_BUSINESS_RISK = "business_risk"
REPORT_AI_SECTION_COMPLIANCE_CHECK = "compliance_check"
REPORT_AI_SECTION_PRIORITIZATION_ROADMAP = "prioritization_roadmap"
REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS = "hardening_recommendations"
REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA = "executive_summary_valhalla"
# Valhalla-tier only (RPT-005 ``report_tier_sections``); registered here for Celery/cache.
REPORT_AI_SECTION_ATTACK_SCENARIOS = "attack_scenarios"
REPORT_AI_SECTION_EXPLOIT_CHAINS = "exploit_chains"
REPORT_AI_SECTION_REMEDIATION_STAGES = "remediation_stages"
REPORT_AI_SECTION_ZERO_DAY_POTENTIAL = "zero_day_potential"

REPORT_AI_SECTION_KEYS: frozenset[str] = frozenset(
    {
        REPORT_AI_SECTION_EXECUTIVE_SUMMARY,
        REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION,
        REPORT_AI_SECTION_REMEDIATION_STEP,
        REPORT_AI_SECTION_BUSINESS_RISK,
        REPORT_AI_SECTION_COMPLIANCE_CHECK,
        REPORT_AI_SECTION_PRIORITIZATION_ROADMAP,
        REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS,
        REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA,
        REPORT_AI_SECTION_ATTACK_SCENARIOS,
        REPORT_AI_SECTION_EXPLOIT_CHAINS,
        REPORT_AI_SECTION_REMEDIATION_STAGES,
        REPORT_AI_SECTION_ZERO_DAY_POTENTIAL,
    }
)

# Bump segment when template semantics change (invalidates Redis cache for that section).
REPORT_AI_PROMPT_VERSIONS: dict[str, str] = {
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY: "vhq006-20250328",
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION: "vhq006-20250328",
    REPORT_AI_SECTION_REMEDIATION_STEP: "vhq006-20250328",
    REPORT_AI_SECTION_BUSINESS_RISK: "vhq006-20250328",
    REPORT_AI_SECTION_COMPLIANCE_CHECK: "vhq006-20250328",
    REPORT_AI_SECTION_PRIORITIZATION_ROADMAP: "vhq006-20250328",
    REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS: "vhq006-20250328",
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA: "vhq006-20250328",
    REPORT_AI_SECTION_ATTACK_SCENARIOS: "vhq006-20250328",
    REPORT_AI_SECTION_EXPLOIT_CHAINS: "vhq006-20250328",
    REPORT_AI_SECTION_REMEDIATION_STAGES: "vhq006-20250328",
    REPORT_AI_SECTION_ZERO_DAY_POTENTIAL: "vhq006-20250328",
}

REPORT_AI_SYSTEM = (
    "You are a senior penetration testing report author. "
    "Use only facts present in the context JSON. Do not fabricate CVEs, systems, or test results. "
    "When the context includes owasp_summary (OWASP Top 10:2025), use counts and gap_categories "
    "(categories with zero mapped findings) only as factual coverage signals—do not invent issues "
    "for gaps. "
    "When owasp_compliance_table is present, treat each row as category coverage (counts / presence), "
    "not as proof of absence of other issue types. "
    "When hibp_pwned_password_summary is present, state credential-breach exposure only as aggregate "
    "facts there (e.g. pwned_count, checks_run)—never infer passwords or raw breach contents. "
    "When valhalla_context is present, ground Valhalla-style narrative in that summary, risk_matrix, "
    "critical_vulns, tech_stack_structured, and excerpts only. "
    "When the JSON also includes top-level keys tech_stack_structured, ssl_tls_analysis, "
    "security_headers_analysis, outdated_components_table, robots_sitemap_analysis (Valhalla tier), "
    "use them as the primary structured facts for stack/TLS/headers/deps/robots sections; if a key is "
    "absent or its fields are empty, state explicitly that the data was not collected or is unavailable—"
    "do not invent tool output. "
    "When findings entries include finding_id, title, parameter, affected_url (or affected_asset), "
    "reference those concrete fields in technical sections—do not substitute generic placeholders. "
    "Output plain prose suitable for embedding in a formal report (no JSON, no code fences unless quoting)."
)

REPORT_AI_USER_TEMPLATES: dict[str, str] = {
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY: (
        "Write a concise executive summary (2–4 short paragraphs) for business stakeholders.\n"
        "Cover scope, overall risk posture, and top themes. Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION: (
        "Describe the vulnerability in technical but readable language: root cause, affected component, "
        "and exploitation preconditions as supported by the context. "
        "For each distinct issue you discuss, cite the concrete ``finding_id`` and ``title`` from the "
        "findings list; when ``parameter`` and ``affected_url`` (or ``affected_asset``) exist on that "
        "finding, mention them explicitly. "
        "When ``valhalla_context.risk_matrix`` and ``valhalla_context.critical_vulns`` exist, align "
        "severity narrative with those structures without inventing extra findings. "
        "Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_REMEDIATION_STEP: (
        "Provide actionable remediation steps ordered by practicality. Reference controls and verification "
        "where the context allows. "
        "If the context JSON includes ``owasp_category_reference_ru`` (OWASP Top 10:2025, RU), use it for "
        "category-specific remediation: tie findings to the right A01–A10 keys and ground technical steps "
        "in the provided ``how_to_fix`` and checks in ``how_to_find`` (do not invent extra OWASP text). "
        "Reference ``finding_id`` + title + parameter/affected_url where those fields exist on findings. "
        "Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_BUSINESS_RISK: (
        "Explain business impact: operational, financial, and reputational angles grounded in the context. "
        "Avoid alarmism without evidence. "
        "When ``valhalla_context`` is present, tie material risks to its summary, ``risk_matrix``, "
        "``critical_vulns``, surface/TLS/headers, dependencies, and threat/exploit excerpts where supported. "
        "Reference concrete ``finding_id`` and titles when tying risk to specific validated issues. "
        "When ``owasp_compliance_table`` is present, reference category rows with findings vs gaps using "
        "only counts and has_findings from that table. "
        "When ``hibp_pwned_password_summary`` is present, mention aggregate credential exposure "
        "(e.g. whether any checked samples appeared in Pwned Passwords data: pwned_count vs checks_run) "
        "— do not claim full breach history or user identities beyond that summary. "
        "When ``owasp_category_reference_ru`` is present, use ``title_ru`` and ``example_attack`` only as "
        "factual OWASP framing for categories that map to findings in the context — not as new findings. "
        "Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_COMPLIANCE_CHECK: (
        "Map findings in the context to relevant compliance themes (e.g. confidentiality, integrity, "
        "availability, privacy). Only cite frameworks or controls implied or named in the context. "
        "If ``owasp_category_reference_ru`` is present, align category discussion with ``how_to_find`` / "
        "``how_to_fix`` for the relevant A01–A10 codes from ``owasp_summary`` and per-finding categories. "
        "Where findings include ``finding_id``, ``parameter``, and ``affected_url``, reference them when "
        "mapping issues to control themes. Use ``valhalla_context.critical_vulns`` and ``risk_matrix`` "
        "as factual prioritization signals when present. "
        "Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_PRIORITIZATION_ROADMAP: (
        "Propose a prioritized remediation roadmap (near-term vs longer-term) using severity and "
        "dependencies evident in the context. "
        "When ``valhalla_context`` is present, align sequencing with ``risk_matrix``, ``critical_vulns``, "
        "dependency/TLS/header signals, and threat-model excerpts where they support ordering. "
        "Name specific ``finding_id`` values and titles for top items when those fields exist. "
        "When ``owasp_compliance_table`` is present, weight categories with higher finding counts and "
        "explicit gaps only as stated in the table. "
        "When ``hibp_pwned_password_summary`` is present and shows pwned_count > 0, include "
        "credential hygiene / rotation themes among near-term items without exposing secrets. "
        "When ``owasp_category_reference_ru`` is available, prioritize and phase work using that reference "
        "``how_to_fix`` / ``how_to_find`` per affected OWASP category (A01–A10) from the context. "
        "Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS: (
        "List hardening and defense-in-depth recommendations aligned with the engagement context "
        "(configuration, monitoring, architecture). "
        "When ``valhalla_context.tech_stack_structured`` is present, tie recommendations to observed "
        "stack signals (web server, CMS, frameworks, JS libraries, OS hints): include at least a few "
        "concrete examples—safe configuration commands (non-destructive, illustrative) and/or canonical "
        "doc links such as OWASP Cheat Sheet Series pages that match the stack (e.g. TLS, headers, XSS, "
        "SQLi) without fabricating tool output. "
        "Reference ``finding_id`` + title + parameter/affected_url for findings that motivate each "
        "control when those fields exist. "
        "Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA: (
        "Write an executive summary in a direct, high-signal style suitable for a technical leadership "
        "brief (Valhalla report variant): bullets for key risks, one paragraph for posture, no fluff. "
        "You MUST anchor bullets in ``valhalla_context.summary``, ``risk_matrix``, ``critical_vulns``, "
        "and excerpts when those objects exist; if absent, use only scan findings and severity counts. "
        "When discussing specific issues, cite ``finding_id`` + title + parameter/affected_url from "
        "findings entries where present. "
        "When ``owasp_compliance_table`` exists, cite at most the top 3 categories by count plus any "
        "critical/high-only themes—do not restate the full table. "
        "When ``hibp_pwned_password_summary`` exists, add one bullet only if it changes posture "
        "(e.g. checks_run and whether pwned_count > 0); omit if absent or inapplicable. "
        "Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_ATTACK_SCENARIOS: (
        "Describe plausible attack scenarios that chain the threat-model context with validated findings. "
        "Use ``valhalla_context.threat_model_excerpt`` / ``exploitation_post_excerpt``, ``risk_matrix``, "
        "``critical_vulns``, and the findings list; label assumptions clearly when evidence is partial. "
        "Each scenario must reference concrete ``finding_id``, title, and parameter/affected_url when "
        "those fields exist on the cited findings. "
        "Do not describe live exploitation steps or weaponized payloads. Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_EXPLOIT_CHAINS: (
        "Outline multi-step exploit chains (recon → initial access → impact) grounded strictly in "
        "findings, threat-model excerpts, and ``valhalla_context`` technical signals (stack, headers, TLS, "
        "dependencies, ``risk_matrix``, ``critical_vulns``). "
        "Each chain: name, stages, required preconditions, and mapped finding_id + title + severity "
        "(and parameter/affected_url when available). "
        "Theoretical only; no instructions for abuse. Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_REMEDIATION_STAGES: (
        "Structure remediation in three horizons: (1) immediate (0–48h), (2) within ~2 weeks, "
        "(3) long-term (architecture / SDLC). "
        "You MUST bucket items from ``valhalla_context.critical_vulns`` whose severity is critical or high "
        "(or CVSS ≥ 7.0 when severity is absent) into these horizons with actionable steps: immediate "
        "for confirmed/exploit-backed critical exposure; ~2 weeks for dependent fixes and validation; "
        "long-term for structural controls and SDLC. "
        "Also use severities, ``owasp_compliance_table``, ``valhalla_context`` dependency/TLS/header gaps, "
        "``risk_matrix``, and ``hibp_pwned_password_summary`` (if present) to justify staging. "
        "Reference ``finding_id`` + title + parameter/affected_url when tying steps to findings. "
        "Plain prose with clear subheadings for each horizon. Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_ZERO_DAY_POTENTIAL: (
        "Assess zero-day / n-day research exposure conservatively: outdated components, missing hardening, "
        "and attack surface from ``valhalla_context`` (including ``critical_vulns``, ``risk_matrix``, stack) "
        "and findings. "
        "Tie discussion to concrete ``finding_id`` and titles where applicable. "
        "Clearly separate known CVE-backed risk from speculative unknown-vulnerability risk; do not "
        "claim active zero-days. Context JSON:\n{context_json}"
    ),
}


# ---------------------------------------------------------------------------
# VA — AI-assisted active scan planning (OWASP / sandbox tool argv suggestions)
# ---------------------------------------------------------------------------

ACTIVE_SCAN_PLANNING_SYSTEM = (
    "You are an expert penetration tester planning passive-to-active validation steps. "
    "You MUST output only a JSON array (no markdown fences, no prose). "
    "Each array element is an object with keys \"tool\" (string) and \"args\" (array of strings) "
    "representing one sandbox tool invocation (full argv after the binary name). "
    "Use only tools from this allowlist: dalfox, xsstrike, ffuf, sqlmap, nuclei, gobuster, feroxbuster, wfuzz, commix. "
    "Planned invocations map to MCP run_* operations (e.g. run_nuclei, run_ffuf) when the worker dispatches them; "
    "use this planner for incremental VA sandbox runs. For full engagement coverage and phase correlation, "
    "the operator should use the full ARGUS scan pipeline instead of ad-hoc run_* alone. "
    "Stay within authorized scope; do not propose destructive or out-of-scope actions. "
    "Args must be a safe, non-interactive argv for the sandbox runner (no shell metacharacters; "
    "use full http(s) URLs from the provided target_urls only). "
    "Do not duplicate scans already implied by the baseline plan for the same tool and URL path. "
    "If no additional scans are justified, return an empty array []. "
    f"[va_active_scan_planning_prompt_version={VA_ACTIVE_SCAN_PLANNING_PROMPT_VERSION}]"
)

ACTIVE_SCAN_PLANNING_USER_TEMPLATE = (
    "Plan sandbox scanner invocations from the following bundle summary (JSON). "
    "Prefer short, focused extra runs that complement a baseline scan (e.g. nuclei templates, "
    "ffuf on interesting paths). "
    "Return ONLY a JSON array of objects: {{\"tool\": \"...\", \"args\": [\"...\", ...]}}.\n\n"
    "=== BUNDLE SUMMARY ===\n{bundle_summary_json}\n=== END ==="
)


def build_active_scan_planning_user_prompt(bundle_summary: dict[str, Any]) -> str:
    """Serialize and sanitize bundle summary for the active-scan planning user message."""
    raw = json.dumps(bundle_summary, ensure_ascii=False, sort_keys=True, default=str)
    sanitized = _sanitize_for_prompt(raw, MAX_PROMPT_OBJECT_LENGTH)
    return ACTIVE_SCAN_PLANNING_USER_TEMPLATE.format(bundle_summary_json=sanitized)


ACTIVE_SCAN_PLANNING_JSON_ARRAY_FIXER_USER = (
    "The following text was supposed to be ONLY a JSON array of objects, each with "
    '"tool" (string) and "args" (array of strings). '
    "Return ONLY the corrected JSON array, nothing else.\n\nInvalid response:\n{invalid_fragment}"
)


def get_report_ai_section_prompt(
    section_key: str, input_payload: dict[str, Any]
) -> tuple[str, str, str]:
    """Return (system_prompt, user_prompt, prompt_version) for a registered report AI section."""
    if section_key not in REPORT_AI_SECTION_KEYS:
        raise ValueError(f"Unknown report AI section: {section_key}")
    version = REPORT_AI_PROMPT_VERSIONS[section_key]
    template = REPORT_AI_USER_TEMPLATES[section_key]
    raw_json = json.dumps(input_payload, sort_keys=True, separators=(",", ":"), default=str)
    context_json = _sanitize_for_prompt(raw_json, MAX_PROMPT_OBJECT_LENGTH)
    user = template.format(context_json=context_json)
    return REPORT_AI_SYSTEM, user, version
