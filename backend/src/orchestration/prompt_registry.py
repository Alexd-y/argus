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

SYSTEM_PROMPT_BASE = (
    "You are an expert penetration tester and security analyst. "
    "You analyze REAL tool output (nmap, dig, whois, crt.sh, Shodan, NVD). "
    "Respond ONLY with valid JSON. No markdown, no explanation, only the JSON object."
)

FIXER_SYSTEM_PROMPT = (
    "You are a JSON repair assistant. The previous response contained invalid JSON. "
    "Return ONLY the corrected JSON object, nothing else. No markdown, no explanation."
)

# Phase -> (system_prompt, user_prompt_template)
PHASE_PROMPTS: dict[str, tuple[str, str]] = {
    RECON: (
        SYSTEM_PROMPT_BASE,
        "You are performing reconnaissance on target: {target}.\n"
        "Options: {options}\n\n"
        "Below is REAL output from security tools. Analyze it carefully.\n\n"
        "=== TOOL RESULTS ===\n{tool_results}\n=== END TOOL RESULTS ===\n\n"
        "Based on the real tool output above, return a JSON object with:\n"
        '- "assets": array of discovered assets (IPs, domains, services with versions)\n'
        '- "subdomains": array of discovered subdomains\n'
        '- "ports": array of open port numbers (integers)\n\n'
        "Extract ONLY real data from the tool output. Do NOT invent or guess.\n"
        'Return JSON: {{"assets": ["string"], "subdomains": ["string"], "ports": [number]}}',
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
        "Analyze vulnerabilities based on the real threat model and assets.\n\n"
        "Threat model: {threat_model}\n"
        "Assets: {assets}\n\n"
        "{active_scan_context}"
        "For each vulnerability, provide:\n"
        '- "severity": critical/high/medium/low/info\n'
        '- "title": descriptive title\n'
        '- "cwe": CWE identifier (e.g. CWE-79)\n'
        '- "cvss": CVSS score (float)\n'
        '- "description": detailed description\n'
        '- "affected_asset": which asset is affected\n'
        '- "remediation": recommended fix\n\n'
        "Only report vulnerabilities supported by evidence from the threat model.\n"
        "If active scan findings are provided above, incorporate them into your analysis — "
        "confirm, correlate, or augment them with additional context.\n"
        'Return JSON: {{"findings": [{{"severity": "string", "title": "string", "cwe": "string", '
        '"cvss": 0.0, "description": "string", "affected_asset": "string", "remediation": "string"}}]}}',
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
# RPT-004 — Report AI text sections (Prompt Registry for Celery ai_text_generation)
# ---------------------------------------------------------------------------

REPORT_AI_SECTION_EXECUTIVE_SUMMARY = "executive_summary"
REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION = "vulnerability_description"
REPORT_AI_SECTION_REMEDIATION_STEP = "remediation_step"
REPORT_AI_SECTION_BUSINESS_RISK = "business_risk"
REPORT_AI_SECTION_COMPLIANCE_CHECK = "compliance_check"
REPORT_AI_SECTION_PRIORITIZATION_ROADMAP = "prioritization_roadmap"
REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS = "hardening_recommendations"
REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA = "executive_summary_valhalla"

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
    }
)

# Bump segment when template semantics change (invalidates Redis cache for that section).
REPORT_AI_PROMPT_VERSIONS: dict[str, str] = {
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY: "rpt004-20250320a",
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION: "rpt004-20250320a",
    REPORT_AI_SECTION_REMEDIATION_STEP: "rpt004-20250320a",
    REPORT_AI_SECTION_BUSINESS_RISK: "rpt004-20250320a",
    REPORT_AI_SECTION_COMPLIANCE_CHECK: "rpt004-20250320a",
    REPORT_AI_SECTION_PRIORITIZATION_ROADMAP: "rpt004-20250320a",
    REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS: "rpt004-20250320a",
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA: "rpt004-20250320a",
}

REPORT_AI_SYSTEM = (
    "You are a senior penetration testing report author. "
    "Use only facts present in the context JSON. Do not fabricate CVEs, systems, or test results. "
    "Output plain prose suitable for embedding in a formal report (no JSON, no code fences unless quoting)."
)

REPORT_AI_USER_TEMPLATES: dict[str, str] = {
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY: (
        "Write a concise executive summary (2–4 short paragraphs) for business stakeholders.\n"
        "Cover scope, overall risk posture, and top themes. Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION: (
        "Describe the vulnerability in technical but readable language: root cause, affected component, "
        "and exploitation preconditions as supported by the context. Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_REMEDIATION_STEP: (
        "Provide actionable remediation steps ordered by practicality. Reference controls and verification "
        "where the context allows. Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_BUSINESS_RISK: (
        "Explain business impact: operational, financial, and reputational angles grounded in the context. "
        "Avoid alarmism without evidence. Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_COMPLIANCE_CHECK: (
        "Map findings in the context to relevant compliance themes (e.g. confidentiality, integrity, "
        "availability, privacy). Only cite frameworks or controls implied or named in the context. "
        "Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_PRIORITIZATION_ROADMAP: (
        "Propose a prioritized remediation roadmap (near-term vs longer-term) using severity and "
        "dependencies evident in the context. Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS: (
        "List hardening and defense-in-depth recommendations aligned with the engagement context "
        "(configuration, monitoring, architecture). Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA: (
        "Write an executive summary in a direct, high-signal style suitable for a technical leadership "
        "brief (Valhalla report variant): bullets for key risks, one paragraph for posture, no fluff. "
        "Context JSON:\n{context_json}"
    ),
}


# ---------------------------------------------------------------------------
# VA — AI-assisted active scan planning (OWASP / sandbox tool argv suggestions)
# ---------------------------------------------------------------------------

ACTIVE_SCAN_PLANNING_SYSTEM = (
    "You are an expert penetration tester planning passive-to-active validation steps. "
    "You MUST output only a JSON array (no markdown fences, no prose). "
    "Each array element is an object with keys \"tool\" (string) and \"args\" (array of strings). "
    "Use only tools from this allowlist: dalfox, xsstrike, ffuf, sqlmap, nuclei, gobuster, wfuzz, commix. "
    "Args must be a safe, non-interactive argv for the sandbox runner (no shell metacharacters; "
    "use full http(s) URLs from the provided target_urls only). "
    "If no additional scans are justified, return an empty array []."
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
