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
        "Build a STRIDE-based threat model for the following target using real recon data.\n\n"
        "Assets: {assets}\n\n"
        "=== ENRICHED RECON CONTEXT ===\n{recon_context}\n=== END RECON CONTEXT ===\n\n"
        "=== NVD CVE DATA ===\n{nvd_data}\n=== END NVD DATA ===\n\n"
        "Instructions:\n"
        "1. For EACH detected technology with a version, look up relevant CVEs from the NVD data above. "
        "If a CVE matches a detected version range, include it with severity and description.\n"
        "2. For EACH identified entry point (login form, API endpoint, file upload, admin panel), "
        "perform STRIDE analysis and produce specific attack vectors.\n"
        "3. Map every threat to the concrete component it affects.\n"
        "4. Provide specific, actionable mitigations per threat — not generic advice.\n\n"
        "Return a JSON object with this structure:\n"
        '{{"threat_model": {{\n'
        '  "attack_surface": [\n'
        '    {{"component": "string", "type": "web_form|api_endpoint|file_upload|admin_panel|service", '
        '"exposure_level": "external|internal|authenticated", "url": "string"}}\n'
        "  ],\n"
        '  "threats": [\n'
        '    {{"category": "S|T|R|I|D|E", "description": "string", '
        '"component": "string", "likelihood": "high|medium|low", "impact": "high|medium|low"}}\n'
        "  ],\n"
        '  "cves": [\n'
        '    {{"cve_id": "CVE-XXXX-XXXX", "technology": "string", '
        '"severity": "critical|high|medium|low", "description": "string"}}\n'
        "  ],\n"
        '  "mitigations": [\n'
        '    {{"threat_ref": "string", "recommendation": "string", "priority": "high|medium|low"}}\n'
        "  ]\n"
        "}}}}\n\n"
        "STRIDE categories: S=Spoofing, T=Tampering, R=Repudiation, I=Information Disclosure, "
        "D=Denial of Service, E=Elevation of Privilege.\n"
        "Extract ONLY real data. Do NOT invent technologies, endpoints, or CVEs not present in the input.",
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
            + '- "remediation": recommended fix\n'
            + '- "confidence": confirmed | likely | possible | advisory (match evidence strength)\n'
            + '- "evidence_type": observed | tool_output | version_match | cve_correlation | threat_model_inference\n'
            + '- "evidence_refs": array of short strings (tool ids, URLs, artifact keys, CVE ids)\n'
            + '- "reproducible_steps": optional string (how to verify)\n'
            + '- "applicability_notes": optional string (stack/hosting limits)\n\n'
            + "Only report vulnerabilities supported by evidence from the threat model.\n"
            + "If active scan findings are provided above, incorporate them into your analysis — "
            + "confirm, correlate, or augment them with additional context.\n"
            + 'Return JSON: {{"findings": [{{"severity": "string", "title": "string", "cwe": "string", '
            + '"cvss": 0.0, "description": "string", "affected_asset": "string", "remediation": "string", '
            + '"confidence": "string", "evidence_type": "string", "evidence_refs": ["string"], '
            + '"reproducible_steps": "string", "applicability_notes": "string"}}]}}'
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
        "Generate all text in English. Keep technical terms (CVE, CVSS, CWE, OWASP) in English.\n\n"
        "Generate an evidence-bound security assessment report from the following real data.\n\n"
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
    "recon_context": "No enriched recon context available.",
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
                "attack_surface": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "component": {"type": "string"},
                            "type": {"type": "string"},
                            "exposure_level": {"type": "string"},
                            "url": {"type": "string"},
                        },
                    },
                },
                "threats": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "category": {"type": "string"},
                            "description": {"type": "string"},
                            "component": {"type": "string"},
                            "likelihood": {"type": "string"},
                            "impact": {"type": "string"},
                        },
                    },
                },
                "cves": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "cve_id": {"type": "string"},
                            "technology": {"type": "string"},
                            "severity": {"type": "string"},
                            "description": {"type": "string"},
                        },
                    },
                },
                "mitigations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "threat_ref": {"type": "string"},
                            "recommendation": {"type": "string"},
                            "priority": {"type": "string"},
                        },
                    },
                },
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
                    "cvss": {"type": "number"},
                    "description": {"type": "string"},
                    "finding_id": {"type": "string"},
                    "vuln_type": {"type": "string"},
                    "affected_url": {"type": "string"},
                    "parameter": {"type": "string"},
                    "confidence": {"type": "string"},
                    "evidence_type": {"type": "string"},
                    "evidence_refs": {"type": "array", "items": {"type": "string"}},
                    "reproducible_steps": {"type": "string"},
                    "applicability_notes": {"type": "string"},
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
REPORT_AI_SECTION_COST_SUMMARY = "cost_summary"

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
        REPORT_AI_SECTION_COST_SUMMARY,
    }
)

# Bump segment when template semantics change (invalidates Redis cache for that section).
REPORT_AI_PROMPT_VERSIONS: dict[str, str] = {
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY: "vhq015-20260425",
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION: "vhq015-20260425",
    REPORT_AI_SECTION_REMEDIATION_STEP: "vhq015-20260425",
    REPORT_AI_SECTION_BUSINESS_RISK: "vhq015-20260425",
    REPORT_AI_SECTION_COMPLIANCE_CHECK: "vhq015-20260425",
    REPORT_AI_SECTION_PRIORITIZATION_ROADMAP: "vhq015-20260425",
    REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS: "vhq015-20260425",
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA: "vhq015-20260425",
    REPORT_AI_SECTION_ATTACK_SCENARIOS: "vhq015-20260425",
    REPORT_AI_SECTION_EXPLOIT_CHAINS: "vhq015-20260425",
    REPORT_AI_SECTION_REMEDIATION_STAGES: "vhq015-20260425",
    REPORT_AI_SECTION_ZERO_DAY_POTENTIAL: "vhq015-20260425",
    REPORT_AI_SECTION_COST_SUMMARY: "vhq015-20260425",
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
    "facts there: use EXACT integers from pwned_count and checks_run (and data_breach_password_exposure / "
    "breach_signal_note when present)—never estimate, never infer passwords or raw breach contents. "
    "When valhalla_context is present, ground Valhalla-style narrative in that summary, risk_matrix, "
    "critical_vulns, tech_stack_structured, and excerpts only. "
    "When the JSON also includes top-level keys tech_stack_structured, ssl_tls_analysis, "
    "security_headers_analysis, outdated_components_table, robots_sitemap_analysis (Valhalla tier), "
    "use them as the primary structured facts for stack/TLS/headers/deps/robots sections; if a key is "
    "absent or its fields are empty, state explicitly that the data was not collected or is unavailable—"
    "do not invent tool output. "
    "Use report_quality_gate plus valhalla_context.mandatory_sections and "
    "valhalla_context.coverage.tool_errors_summary as quality gates: if WSTG coverage is below 70%, "
    "if a critical scanner failed, or if a section status is partial, not_executed, no_data, or "
    "not_assessed, describe the limitation and tool failure/collection reason. Never convert an empty "
    "table into proof that the risk is absent; for example, "
    "an empty outdated_components_table with not_executed or partial status means SCA data is missing, not "
    "that all components are current. "
    "When findings entries include finding_id, title, parameter, affected_url (or affected_asset), "
    "reference those concrete fields in technical sections—do not substitute generic placeholders. "
    "When ``valhalla_context.xss_structured`` is non-empty, each row is authoritative XSS evidence: "
    "use ``finding_id``, ``parameter``, ``payload_entered``, ``payload_used``, ``payload_reflected``, "
    "``reflection_context``, ``verification_method``, ``verified_via_browser``, ``browser_alert_text``, "
    "``artifact_keys`` (MinIO/object keys), and ``artifact_urls`` (presigned or direct screenshot URLs "
    "when present) verbatim in narrative—quote or paraphrase only what appears there. Tie remediation to "
    "that reflection context and verification path (e.g. browser vs HTTP reflection); do not replace with "
    "generic advice like \"validate all user input\" or \"sanitize input\" without naming the concrete "
    "parameter, sink context, and control implied by the data. "
    "Never state vulnerability counts, severity histograms, or HIBP hit/check numbers unless they match "
    "the exact integers in executive_severity_totals, severity_counts, finding_count, and "
    "hibp_pwned_password_summary when those keys exist. "
    "Output plain prose suitable for embedding in a formal report (no JSON, no code fences unless quoting)."
    "\n\n"
    "STRICT RULES FOR ALL REPORT SECTIONS:\n"
    "1. NEVER claim critical findings exist if severity_counts shows 0 critical findings. "
    "Always use the EXACT severity distribution from the data.\n"
    "2. Each AI section MUST contain UNIQUE content. No sentence or paragraph may appear in more than "
    "one section. Cross-reference other sections instead of repeating.\n"
    "3. When tech_stack_structured has data, remediation may be tailored to that detected stack. "
    "When the stack is empty, no_data, partial, or not_assessed, use stack-neutral controls only.\n"
    "4. Include CVSS:3.1 vector string (e.g., CVSS:3.1/AV:N/AC:L/...) alongside severity score for "
    "EVERY referenced finding when cvss_vector is available in the context.\n"
    "5. For each finding reference, include: finding name (title), CWE ID, CVSS score, and affected URL.\n"
    "6. Remediation MUST NOT assume Express, Nginx, Node, Django, or any framework unless the context "
    "confirms that stack. Prefer application middleware, reverse proxy/WAF, identity provider controls, "
    "per-account and per-IP throttling, exponential backoff, lockout/CAPTCHA, monitoring, and verification.\n"
    "7. NEVER use phrases like 'the assessment revealed' or 'it was found that' without specifying "
    "WHICH finding (by title and finding_id) and WHERE (affected_url).\n"
    "8. Use the ACTUAL severity distribution from severity_counts and executive_severity_totals in the "
    "context JSON \u2014 reference these exact integers.\n"
    "9. Each section has a section_id provided in the SECTION CONTEXT preamble. Content for this "
    "section_id MUST NOT duplicate content from sections listed in ALREADY WRITTEN SECTIONS.\n"
    "10. Forbidden unsupported phrases: relatively stable; positive observation; absence of critical "
    "vulnerabilities; no critical vulnerabilities; no findings means secure; confirmed these findings without false positives; "
    "unauthorized transactions; regulatory fines; financial fraud; data breach; zero-day potential; "
    "significant vulnerability; critical HTTP headers; could be exploited by attackers; compromise the application; "
    "absence of effective rate limiting; does not implement rate limiting; allowing attackers to perform rapid login attempts; "
    "comprehensive penetration test. Use not assessed / inconclusive limitation language instead.\n"
    "11. Findings with evidence_quality none/weak or validation_status missing/unverified must not be "
    "called confirmed, validated, critical to business impact, or part of an exploit chain.\n"
    "12. HTTP response header findings are passive configuration observations. Do not call them significant "
    "or critical vulnerabilities, do not claim application compromise, and do not describe exploitability "
    "beyond browser-side defense-in-depth unless separate validated impact evidence exists. For customer-facing "
    "Valhalla text, map this class to OWASP Top 10:2021 A05:2021 Security Misconfiguration, not A02."
)

REPORT_AI_USER_TEMPLATES: dict[str, str] = {
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY: (
        "ROLE: You are a Chief Information Security Officer (CISO) summarizing assessment results for business stakeholders.\n"
        "LANGUAGE: Write in English.\n\n"
        "Write a concise, evidence-bound executive summary (1\u20132 short paragraphs) for business stakeholders.\n\n"
        "REQUIREMENTS:\n"
        "1. SEVERITY DISTRIBUTION: Start with the EXACT severity breakdown from severity_counts and "
        "executive_severity_totals \u2014 state the precise number of critical, high, medium, low, and info "
        "findings. Never approximate.\n"
        "2. BUSINESS IMPACT BY FINDING: Tie business impact to SPECIFIC findings by title (from the "
        "findings list). Do not use generic statements like 'several vulnerabilities were found'.\n"
        "3. QUANTIFIED RISK METRICS: Include concrete quantification where possible (e.g., '3 of 5 tested "
        "endpoints are vulnerable to XSS', '2 critical findings affect the authentication flow', "
        "'60%% of findings are in OWASP A03 category').\n"
        "4. Cover scope (target_url, finding_count), validation status, evidence quality, failed tools, "
        "and coverage limitations. Do not state an overall security posture when coverage is partial or "
        "inconclusive.\n"
        "5. When owasp_compliance_table exists, distinguish Finding Present, Assessed, Not Assessed, "
        "and No Finding After Assessment. Do not report Not Assessed as clean.\n"
        "6. When hibp_pwned_password_summary exists and pwned_count > 0, add one sentence on "
        "credential exposure using exact pwned_count and checks_run integers.\n\n"
        "Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION: (
        "ROLE: You are a senior application security engineer with deep knowledge of OWASP Top 10:2025 and CWE.\n"
        "LANGUAGE: Write in English.\n\n"
        "Describe the vulnerability in technical but readable language: root cause, affected component, "
        "and exploitation preconditions as supported by the context. "
        "Ground every sentence in fields present on the cited finding or in valhalla_context / PoC "
        "snippets—do not invent CVE IDs, endpoints, parameters, or tool output not shown in the JSON. "
        "For each distinct issue you discuss, cite the concrete ``finding_id`` and ``title`` from the "
        "findings list; when ``parameter`` and ``affected_url`` (or ``affected_asset``) exist on that "
        "finding, mention them explicitly. "
        "For XSS, if ``valhalla_context.xss_structured`` contains a row for that ``finding_id``, you MUST "
        "weave in that row's ``parameter``, ``payload_entered`` / ``payload_used`` / ``payload_reflected``, "
        "``reflection_context``, ``verification_method``, ``verified_via_browser``, ``browser_alert_text``, "
        "``artifact_keys``, and ``artifact_urls`` (when non-empty)—do not hand-wave with generic validation wording. "
        "When ``valhalla_context.risk_matrix`` and ``valhalla_context.critical_vulns`` exist, align "
        "severity narrative with those structures without inventing extra findings. "
        "Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_REMEDIATION_STEP: (
        "ROLE: You are a DevSecOps engineer providing actionable remediation guidance.\n"
        "LANGUAGE: Write in English.\n\n"
        "Provide actionable remediation steps strictly PRIORITIZED BY CVSS SCORE (highest first). "
        "For each finding, structure the remediation as follows:\n\n"
        "STRUCTURE PER FINDING:\n"
        "- Finding reference: finding_id, title, CWE, CVSS score (and cvss_vector when available), affected_url\n"
        "- EFFORT ESTIMATE: tag each fix as [Quick Fix] (< 1 hour, config change or one-liner), "
        "[Moderate] (1\u20138 hours, code changes in limited scope), or [Complex Refactor] (> 8 hours, "
        "architectural or multi-component change)\n"
        "- IMPLEMENTATION CONTROL: tailor examples only to technology stack detected in tech_stack_structured. "
        "When tech_stack_structured is empty, partial, no_data, or not_assessed, use stack-neutral controls "
        "and avoid Express/Nginx/Node/Django-specific snippets.\n"
        "- VERIFICATION COMMAND: include a curl or similar command to verify the fix is applied "
        "(e.g., ``curl -sS -D- https://target/path | grep 'X-Content-Type-Options'``). "
        "Use the actual affected_url from the finding when available.\n\n"
        "GROUNDING RULES:\n"
        "If the context JSON includes ``owasp_category_reference_ru`` (OWASP Top 10:2025, RU), use it for "
        "category-specific remediation: tie findings to the right A01\u2013A10 keys and ground technical steps "
        "in the provided ``how_to_fix`` and checks in ``how_to_find`` (do not invent extra OWASP text). "
        "Reference ``finding_id`` + title + parameter/affected_url where those fields exist on findings. "
        "For XSS rows in ``valhalla_context.xss_structured``, remediation must reflect ``reflection_context`` "
        "(HTML attribute, body, JS sink, etc.) and how it was verified (``verification_method``, "
        "``verified_via_browser``); cite ``artifact_keys`` and ``artifact_urls`` when listed. "
        "When ``tools_executed`` is present, mention which tool originally detected the issue.\n\n"
        "CONSTRAINTS:\n"
        "Avoid one-line boilerplate such as 'validate input' without tying controls to the named parameter "
        "and context from the JSON. Every remediation item MUST have a concrete control and verification "
        "method; code/config examples are allowed only when stack evidence supports them. "
        "Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_BUSINESS_RISK: (
        "ROLE: You are a risk management consultant translating technical findings to business impact.\n"
        "LANGUAGE: Write in English.\n\n"
        "Explain only conditional and proportional business impact grounded in validated evidence. "
        "Avoid alarmism without evidence. For weak/unverified authentication rate-limit evidence, the allowed "
        "impact wording is limited to susceptibility to brute-force or credential stuffing attempts if valid "
        "credentials are known or reused. "
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
        "ROLE: You are a GRC (Governance, Risk, Compliance) analyst mapping findings to compliance frameworks.\n"
        "LANGUAGE: Write in English.\n\n"
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
        "ROLE: You are a security program manager building a prioritized remediation roadmap.\n"
        "LANGUAGE: Write in English.\n\n"
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
        "ROLE: You are an infrastructure security architect providing defense-in-depth hardening guidance.\n"
        "LANGUAGE: Write in English.\n\n"
        "List hardening and defense-in-depth recommendations aligned with the engagement context "
        "(configuration, monitoring, architecture). "
        "When ``valhalla_context.tech_stack_structured`` is present, tie recommendations to observed "
        "stack signals (web server, CMS, frameworks, JS libraries, OS hints): include at least a few "
        "concrete examples—safe configuration commands (non-destructive, illustrative) and/or canonical "
        "doc links such as OWASP Cheat Sheet Series pages that match the stack (e.g. TLS, headers, XSS, "
        "SQLi) without fabricating tool output. "
        "Reference ``finding_id`` + title + parameter/affected_url for findings that motivate each "
        "control when those fields exist. "
        "When ``valhalla_context.xss_structured`` is present, align XSS hardening with each row's "
        "``reflection_context``, verification facts, and listed ``artifact_keys`` / ``artifact_urls``—"
        "not generic \"sanitize everything\" lists. "
        "Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA: (
        "ROLE: You are a senior penetration tester writing an executive summary for a leadership-technical brief.\n"
        "LANGUAGE: Write in English.\n\n"
        "FOCUS:\n"
        "1. Coverage-limited assessment summary. If report_quality_gate.coverage_label is partial or "
        "inconclusive, state that no overall security posture verdict can be drawn. If "
        "``valhalla_context.engagement_title`` or ``report_quality.report_mode_label`` includes "
        "``degraded execution``, name that limitation and do not imply a full manual pentest.\n"
        "2. SEVERITY DISTRIBUTION: state the EXACT breakdown from executive_severity_totals (critical, "
        "high, medium, low, info counts) in the opening paragraph.\n"
        "3. The 1\u20133 most significant evidence-backed findings by title and validation status. Business "
        "impact must be conditional and proportional to evidence_quality.\n"
        "4. QUANTIFIED RISK METRICS: include concrete ratios where the data supports them (e.g., "
        "'N of M endpoints vulnerable to XSS', 'X%% of findings map to OWASP A03').\n"
        "5. What was not assessed, inconclusive, or limited by failed tools/coverage gaps.\n"
        "6. Immediate priority actions (max 3 bullet points).\n\n"
        "NUMBERS: use EXACT integers from `executive_severity_totals` and `finding_count` \u2014 copy verbatim, never estimate.\n"
        "When `owasp_compliance_table` exists, cite at most the top 2 categories by count.\n"
        "When `hibp_pwned_password_summary` exists and pwned_count > 0, add one sentence on credential exposure.\n\n"
        "CONSTRAINTS:\n"
        "- Write 1\u20132 paragraphs of plain prose. No Markdown formatting. No bullet lists unless data supports immediate actions.\n"
        "- SYNTHESIZE, do not enumerate \u2014 this is NOT a findings table. The reader already has the detailed findings.\n"
        "- Do NOT repeat finding IDs, technical parameters, or affected URLs \u2014 keep it executive-level.\n"
        "- Do NOT fabricate CVEs, systems, or test results not in the context.\n"
        "- Ground every claim in `findings`, `report_quality_gate`, `valhalla_context.coverage`, or `executive_severity_totals`.\n\n"
        "Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_ATTACK_SCENARIOS: (
        "ROLE: You are a threat modeling expert constructing realistic attack scenarios.\n"
        "LANGUAGE: Write in English.\n\n"
        "HEADER-ONLY / PASSIVE FINDINGS: Do not describe rate limiting, credential stuffing, or login POST "
        "workflows unless those signals exist in structured findings. Missing HTTP security headers are "
        "misconfiguration observations, not RCE/SQLi; do not fabricate multi-step exploit chains for them.\n\n"
        "FOCUS: Describe validated attack chains only. If there are fewer than two validated findings, or "
        "the evidence is weak/unverified, state that no validated chain was demonstrated.\n"
        "Each scenario MUST:\n"
        "- Combine 2+ validated findings into a multi-step attack path\n"
        "- Name a realistic attacker persona: opportunistic scanner / targeted attacker / insider threat\n"
        "- Estimate likelihood (Low / Medium / High) with one-sentence reasoning\n"
        "- Describe the concrete damage if the chain succeeds (data exfiltration, lateral movement, service disruption)\n"
        "- Reference `finding_id`, title, parameter, and affected_url from the chained findings\n\n"
        "GROUNDING:\n"
        "- Use `valhalla_context.threat_model_excerpt`, `exploitation_post_excerpt`, `risk_matrix`, and `critical_vulns`\n"
        "- When `xss_structured` is present, use concrete payload/reflection data for XSS chain steps\n"
        "- Label assumptions clearly when evidence is partial\n\n"
        "CONSTRAINTS:\n"
        "- Do NOT summarize individual findings — the reader already has the findings table.\n"
        "- Do NOT describe live exploitation steps or weaponized payloads.\n"
        "- Do NOT repeat content from the Executive Summary — focus on attack CHAINS, not posture.\n"
        "- If only weak/unverified rate-limit evidence exists, write: No validated exploit chain was demonstrated.\n\n"
        "Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_EXPLOIT_CHAINS: (
        "ROLE: You are a red team operator describing scope-appropriate exploit narratives from validated findings.\n"
        "LANGUAGE: Write in English.\n\n"
        "HEADER-ONLY: For passive HTTP response header gaps, provide at most a short, honest chain sketch: "
        "attacker can influence browser security boundaries / clickjacking / protocol confusion only as far as "
        "the evidence shows — explicitly state that header absence is not code execution, SQL injection, or "
        "auth bypass, unless separate findings prove that. Do not mention rate limits, login POST, or credential "
        "stuffing for header-only data.\n\n"
        "Outline multi-step exploit chains only when multiple validated findings with exploit_demonstrated / "
        "strong evidence support the chain. "
        "If no chain is validated, state that no validated exploit chain was demonstrated. "
        "Ground any chain in finding rows, ``critical_vulns`` (if present), ``risk_matrix``, and "
        "``valhalla_context`` — not generic industry boilerplate. "
        "Theoretical only; no instructions for abuse. Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_REMEDIATION_STAGES: (
        "ROLE: You are a DevSecOps engineer writing a prioritized remediation plan.\n"
        "LANGUAGE: Write in English.\n\n"
        "FOCUS: Structure remediation in exactly 3 tiers:\n\n"
        "TIER 1 \u2014 Fix immediately (within 48 hours):\n"
        "- Findings with confirmed exploit evidence OR CVSS >= 7.0 OR severity critical/high\n"
        "- For each: WHAT to change, WHERE (application middleware / reverse proxy / WAF / identity provider "
        "unless stack evidence is known), and HOW to verify the fix\n"
        "- Tag each fix: [Quick Fix] / [Moderate] / [Complex Refactor]\n"
        "- Include a verification command (curl or tool command) for each fix\n\n"
        "TIER 2 \u2014 Fix within 2 weeks:\n"
        "- Medium-priority findings, dependency updates, configuration hardening\n"
        "- For each: specific action, stack-neutral control if the stack is unknown, and verification method\n"
        "- Tag each fix: [Quick Fix] / [Moderate] / [Complex Refactor]\n\n"
        "TIER 3 \u2014 Architectural / SDLC improvements:\n"
        "- Structural issues: missing CSP, no WAF, weak SDLC practices\n"
        "- Process improvements: security testing in CI/CD, dependency scanning, code review policies\n"
        "- Include concrete configuration examples only for detected stack evidence; otherwise stay stack-neutral\n\n"
        "GROUNDING:\n"
        "- Reference `finding_id` + title + parameter/affected_url for each remediation item\n"
        "- Use `valhalla_context.critical_vulns`, `risk_matrix`, `owasp_compliance_table` for prioritization\n"
        "- Use `hibp_pwned_password_summary` if present and pwned_count > 0 for credential rotation in Tier 1\n"
        "- When `owasp_category_reference_ru` is present, use `how_to_fix` for category-specific steps\n\n"
        "CONSTRAINTS:\n"
        "- Do NOT repeat executive summary or attack scenarios — this is ACTION-ORIENTED only.\n"
        "- Do NOT invent CVEs, owners, or deadlines not supported by the JSON.\n"
        "- Each tier MUST reference at least one concrete finding_id.\n"
        "- Do NOT use generic advice like 'validate all input' without naming the specific parameter and fix.\n"
        "- Plain prose with clear subheadings for each tier.\n\n"
        "Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_ZERO_DAY_POTENTIAL: (
        "ROLE: You are a vulnerability researcher assessing zero-day and novel exploitation potential.\n"
        "LANGUAGE: Write in English.\n\n"
        "FOCUS — assess novel vulnerability indication strictly; do not speculate beyond evidence:\n"
        "1. Do any findings suggest non-standard attack surfaces that automated scanners typically miss?\n"
        "2. Are there chaining opportunities that could ELEVATE low/medium-severity findings to critical impact?\n"
        "3. Do outdated components (from `valhalla_context.tech_stack_structured` or `outdated_components_table`) have known n-day exposure windows?\n"
        "4. What additional MANUAL testing would be highest-value given this attack surface?\n"
        "5. Final novel vulnerability indication rating: Not indicated / Low / Medium / High — with a one-sentence justification.\n\n"
        "GROUNDING:\n"
        "- Use `valhalla_context.critical_vulns`, `risk_matrix`, tech stack, TLS/header analysis, and findings\n"
        "- Tie discussion to concrete `finding_id` and titles where applicable\n"
        "- Clearly separate known CVE-backed risk from speculative unknown-vulnerability risk\n\n"
        "CONSTRAINTS:\n"
        "- Do NOT claim active zero-days, zero-day potential, or novel exploitability without evidence.\n"
        "- If `valhalla_context.mandatory_sections.outdated_components.status` is partial, not_executed, "
        "or no_data, state that dependency/version evidence is unavailable; do NOT say the application is "
        "not at risk from known third-party vulnerabilities merely because `outdated_components_table` is empty.\n"
        "- If stack, TLS, headers, or email sections are partial/not_executed/no_data, tie manual testing "
        "recommendations to those explicit collection gaps and `coverage.tool_errors_summary`.\n"
        "- Do NOT repeat the findings list or executive summary — focus ONLY on research/novel potential.\n"
        "- Be honest if findings are standard scanner output and zero-day potential is genuinely low.\n"
        "- Do NOT invent CVEs, component versions, or attack techniques not supported by the context.\n"
        "- Plain prose, 2–4 paragraphs. End with the rating line.\n\n"
        "Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_COST_SUMMARY: (
        "ROLE: You are a security program manager summarizing scan economics and resource utilization.\n"
        "LANGUAGE: Write in English.\n\n"
        "FOCUS:\n"
        "1. What was scanned, how many findings were discovered, and noise reduction from the validation pipeline.\n"
        "2. LLM cost breakdown if cost_summary data is available: total cost, cost per confirmed finding, most expensive phase.\n\n"
        "CONSTRAINTS:\n"
        "- Keep it factual and brief (2 short paragraphs). This is metadata, not analysis.\n"
        "- Use EXACT numbers from the context JSON — do not estimate.\n"
        "- Do NOT repeat executive summary content.\n\n"
        "Context JSON:\n{context_json}"
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
    section_key: str,
    input_payload: dict[str, Any],
    *,
    other_sections_summary: dict[str, str] | None = None,
) -> tuple[str, str, str]:
    """Return (system_prompt, user_prompt, prompt_version) for a registered report AI section.

    ``other_sections_summary`` maps section_key → short summary of already-generated sections.
    When provided, a preamble is prepended instructing the LLM to avoid duplicating that content.
    """
    if section_key not in REPORT_AI_SECTION_KEYS:
        raise ValueError(f"Unknown report AI section: {section_key}")
    version = REPORT_AI_PROMPT_VERSIONS[section_key]
    template = REPORT_AI_USER_TEMPLATES[section_key]
    raw_json = json.dumps(input_payload, sort_keys=True, separators=(",", ":"), default=str)
    context_json = _sanitize_for_prompt(raw_json, MAX_PROMPT_OBJECT_LENGTH)

    section_preamble = f"--- SECTION CONTEXT ---\nSECTION_ID: {section_key}\n"
    if other_sections_summary:
        section_preamble += (
            "ALREADY WRITTEN SECTIONS (do NOT repeat their content, "
            "cross-reference by section name instead):\n"
        )
        for sk, summary in other_sections_summary.items():
            safe_summary = _sanitize_for_prompt(summary, 300)
            section_preamble += f"  [{sk}]: {safe_summary}\n"
    section_preamble += "--- END SECTION CONTEXT ---\n\n"

    user = section_preamble + template.format(context_json=context_json)
    return REPORT_AI_SYSTEM, user, version
