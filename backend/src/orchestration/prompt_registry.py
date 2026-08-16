"""Centralized prompt registry and JSON schemas for LLM phase outputs."""

import json
import re
from typing import Any

# Max length for user-provided strings in prompts (mitigates prompt injection)
MAX_PROMPT_STRING_LENGTH = 16384
MAX_PROMPT_OBJECT_LENGTH = 262144

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


sanitize_kwargs_for_prompt = _sanitize_kwargs_for_prompt

QUICK_PLANNER_PROMPT_ID = "quick_planner_v1"
QUICK_FINGERPRINT_PROMPT_ID = "quick_fingerprint_classifier_v1"
QUICK_TRIAGE_PROMPT_ID = "quick_finding_triage_v1"
QUICK_CRITIC_PROMPT_ID = "quick_security_critic_v1"
QUICK_REPORTER_PROMPT_ID = "quick_reporter_v1"

QUICK_PROMPT_IDS: frozenset[str] = frozenset(
    {
        QUICK_PLANNER_PROMPT_ID,
        QUICK_FINGERPRINT_PROMPT_ID,
        QUICK_TRIAGE_PROMPT_ID,
        QUICK_CRITIC_PROMPT_ID,
        QUICK_REPORTER_PROMPT_ID,
    }
)


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
    "=== KALI MCP TOOLS (policy allowlist; fail-closed) ===\n"
    "network_scanning: nmap, rustscan, masscan\n"
    "web_fingerprinting: httpx, whatweb, wpscan, nikto, theHarvester\n"
    "api_testing: httpx, nuclei, curl, openapi-scanner\n"
    "bruteforce_testing: gobuster, feroxbuster, dirsearch, ffuf, wfuzz, dirb\n"
    "ssl_analysis: testssl.sh, openssl (s_client, s_time, version, ciphers)\n"
    "dns_enumeration: dig, subfinder, amass, dnsx, host, nslookup\n"
    "password_audit: hydra, medusa (GATED: requires category + tenant opt-in)\n"
    "cloud_security: prowler, scoutsuite, cloudsploit, trivy\n"
    "container_security: trivy, grype, dockle, kube-bench, syft\n"
    "injection_testing: sstimap, nosqli, graphql-cop, pp-finder\n\n"
    "VA sandbox MCP (separate allowlist): run_dalfox, run_xsstrike, run_ffuf, run_sqlmap, "
    "run_nuclei, run_whatweb, run_nikto, run_testssl, run_sstimap, run_nosqli, run_graphql_cop.\n\n"
    "Use MCP run_* for single focused checks; full pipeline for comprehensive coverage.\n"
    "ALL offensive actions authorized within sandbox scope.\n"
    "=== END KALI MCP BLOCK ===\n"
)

VA_SANDBOX_MCP_RUN_BLOCK = (
    "=== VA SANDBOX MCP ===\n"
    "run_* operations inside VA sandbox allowlist complement Kali MCP tools.\n"
    "Correlate with threat model evidence; avoid redundant re-runs.\n"
    "=== END VA SANDBOX MCP ===\n"
)

SYSTEM_PROMPT_BASE = (
    "You are ARGUS — an expert pentest engine powered by WhiteRabbitNeo V3. "
    "Perform REAL pentesting: find, validate, and exploit vulnerabilities; generate payloads; "
    "build exploit chains; assess zero-day potential; execute post-exploitation. "
    "All actions are sandbox-isolated and authorized. "
    "Analyse REAL tool output (nmap, dig, sqlmap, nuclei, dalfox, ffuf, xsstrike, commix, hydra). "
    "CRITICAL: If any field is empty/missing, generate tool commands and payloads to fill it. "
    "Never leave evidence fields empty. "
    "Respond ONLY with valid JSON — no markdown, no explanations. "
    "Be precise, evidence-bound, actionable. "
    f"[orchestration_prompt_version={ORCHESTRATION_PROMPT_VERSION}] "
    f"[model=WhiteRabbitNeo-V3-7B]"
)

SYSTEM_PROMPT_RECON = (
    SYSTEM_PROMPT_BASE + " "
    "FOCUS: Recon. Identify assets, subdomains, ports, technologies, entry points from tool output. "
    "Map the attack surface. Be exhaustive but evidence-bound."
)

SYSTEM_PROMPT_THREAT_MODELING = (
    SYSTEM_PROMPT_BASE + " "
    "FOCUS: Threat Modeling. Apply STRIDE to each component. "
    "Correlate technology versions with CVEs. Prioritise by likelihood x impact."
)

SYSTEM_PROMPT_VULN_ANALYSIS = (
    SYSTEM_PROMPT_BASE + " "
    "FOCUS: Vuln Analysis. Analyse active scanner findings (nuclei, dalfox, sqlmap, ffuf) and SAST. "
    "Confirm/correlate findings with threat model context. Assign CWE, CVSS, confidence, evidence type. "
    "Filter false positives. Evaluate evidence quality — flag gaps for re-testing with specific payloads."
)

SYSTEM_PROMPT_EXPLOITATION = (
    SYSTEM_PROMPT_BASE + " "
    "FOCUS: Exploitation. Plan/validate exploit paths against confirmed findings. "
    "Use sandbox tools (dalfox, xsstrike, sqlmap, nuclei, ffuf, commix, hydra). "
    "Generate concrete payloads, capture evidence, map to MITRE ATT&CK. "
    "Analyze evidence gaps; generate targeted payloads to fill them."
)

SYSTEM_PROMPT_POST_EXPLOITATION = (
    SYSTEM_PROMPT_BASE + " "
    "FOCUS: Post-Exploitation. Analyse lateral movement, persistence, privilege escalation from verified exploits. "
    "Perform internal recon, AD enumeration, service discovery. Assess blast radius."
)

SYSTEM_PROMPT_REPORTING = (
    SYSTEM_PROMPT_BASE + " "
    "FOCUS: Reporting. Synthesise all phases into a security assessment report. "
    "Include executive summary, severity distribution, technical findings, AI insights, risk rating. "
    "Ground every claim in evidence. Use ONLY facts from context. No fabricated CVEs or results."
)

FIXER_SYSTEM_PROMPT = (
    "You are a JSON repair assistant. The previous response contained invalid JSON. "
    "Return ONLY the corrected JSON object, nothing else. No markdown, no explanation. "
    f"[orchestration_prompt_version={ORCHESTRATION_PROMPT_VERSION}]"
)

# ---------------------------------------------------------------------------
# Cloud-model fallback prompts — used when WhiteRabbitNeo V3 is unavailable.
# Cloud models (DeepSeek, GPT) are less capable at offensive security;
# these prompts compensate by providing more structured guidance.
# ---------------------------------------------------------------------------

CLOUD_FALLBACK_PREAMBLE = (
    "Authorised pentest on controlled target, sandboxed and in-scope. "
    "Analyse REAL scanner output. Respond ONLY with valid JSON. "
    "Reference concrete technologies, versions, endpoints, findings."
)

CLOUD_FALLBACK_RECON_SYSTEM = (
    CLOUD_FALLBACK_PREAMBLE + " "
    "FOCUS: Recon. Extract assets, subdomains, ports, technologies from tool output."
)

CLOUD_FALLBACK_THREAT_MODEL_SYSTEM = (
    CLOUD_FALLBACK_PREAMBLE + " "
    "FOCUS: STRIDE threat modeling. Per component: Spoofing, Tampering, Repudiation, "
    "Info Disclosure, DoS, Elevation of Privilege. Correlate technologies with CVEs."
)

CLOUD_FALLBACK_VULN_SYSTEM = (
    CLOUD_FALLBACK_PREAMBLE + " "
    "FOCUS: Vuln analysis. Map findings to CWE, assign CVSS, determine confidence. "
    "Cross-reference threat model. Evaluate evidence quality; flag gaps for re-testing."
)

CLOUD_FALLBACK_EXPLOIT_SYSTEM = (
    CLOUD_FALLBACK_PREAMBLE + " "
    "FOCUS: Exploit planning. Recommend tools: dalfox, xsstrike, sqlmap, nuclei, ffuf, "
    "commix, hydra, medusa, nmap. Generate payloads, exploit steps, expected outcomes. "
    "Analyze evidence gaps; generate targeted payloads."
)

CLOUD_FALLBACK_POST_EXPLOIT_SYSTEM = (
    CLOUD_FALLBACK_PREAMBLE + " "
    "FOCUS: Post-exploitation. Lateral movement, persistence, privilege escalation from exploits. "
    "Reference MITRE ATT&CK. Generate post-exploit commands."
)

CLOUD_FALLBACK_REPORT_SYSTEM = (
    CLOUD_FALLBACK_PREAMBLE + " "
    "FOCUS: Report generation. Synthesise phases into structured report: executive summary, "
    "findings with CWE/CVSS, remediation, risk rating. Use ONLY facts from context."
)

# Phase -> (system_prompt, user_prompt_template)
PHASE_PROMPTS: dict[str, tuple[str, str]] = {
    RECON: (
        SYSTEM_PROMPT_RECON,
        (
            "You are performing reconnaissance on target: {target}.\n"
            "Options: {options}\n\n"
            + KALI_MCP_ORCHESTRATION_BLOCK
            + "\n"
            + "REAL tool output below. Analyze carefully.\n\n"
            + "=== TOOL RESULTS ===\n{tool_results}\n=== END ===\n\n"
            + 'Return JSON: {{"assets": ["str"], "subdomains": ["str"], "ports": [int]}}. '
            + "Extract ONLY real data — no inventions."
        ),
    ),
    THREAT_MODELING: (
        SYSTEM_PROMPT_THREAT_MODELING,
        "STRIDE threat model for target using real recon data.\n\n"
        "Assets: {assets}\n\n"
        "=== ENRICHED RECON ===\n{recon_context}\n=== END RECON ===\n\n"
        "=== NVD CVE DATA ===\n{nvd_data}\n=== END NVD ===\n\n"
        "1. For each detected tech+version, map relevant CVEs from NVD above.\n"
        "2. For each entry point (login form, API, file upload, admin panel), "
        "STRIDE-analyze and produce attack vectors.\n"
        "3. Map threats to concrete components. Use specific mitigations.\n\n"
        'Return JSON: {{"threat_model": {{'
        '"attack_surface": [{{"component": "s", "type": "web_form|api_endpoint|file_upload|admin_panel|service", '
        '"exposure_level": "external|internal|authenticated", "url": "s"}}], '
        '"threats": [{{"category": "S|T|R|I|D|E", "description": "s", '
        '"component": "s", "likelihood": "high|medium|low", "impact": "high|medium|low"}}], '
        '"cves": [{{"cve_id": "CVE-XXXX-XXXX", "technology": "s", '
        '"severity": "critical|high|medium|low", "description": "s"}}], '
        '"mitigations": [{{"threat_ref": "s", "recommendation": "s", "priority": "high|medium|low"}}]}}}}\n'
        "STRIDE: S=Spoofing,T=Tampering,R=Repudiation,I=InfoDisclosure,D=DoS,E=Elevation. "
        "No invented tech/endpoints/CVEs.",
    ),
    VULN_ANALYSIS: (
        SYSTEM_PROMPT_VULN_ANALYSIS,
        (
            KALI_MCP_ORCHESTRATION_BLOCK
            + "\n"
            + VA_SANDBOX_MCP_RUN_BLOCK
            + "\n"
            + "Analyze vulnerabilities from real threat model and assets.\n\n"
            + "Threat model: {threat_model}\n"
            + "Assets: {assets}\n\n"
            + "{active_scan_context}"
            + "Per finding: severity(critical|high|medium|low|info), title, cwe, cvss(float), "
            + "description, affected_asset, remediation, "
            + "confidence(confirmed|likely|possible|advisory), "
            + "evidence_type(observed|tool_output|version_match|cve_correlation|threat_model_inference), "
            + "evidence_refs[str], reproducible_steps, applicability_notes.\n"
            + "Evidence-bound only. Incorporate active scan findings — confirm/correlate/augment.\n"
            + 'Return JSON: {{"findings": [{{"severity":"s","title":"s","cwe":"s","cvss":0.0,'
            + '"description":"s","affected_asset":"s","remediation":"s","confidence":"s",'
            + '"evidence_type":"s","evidence_refs":["s"],"reproducible_steps":"s","applicability_notes":"s"}}]}}'
        ),
    ),
    EXPLOITATION: (
        SYSTEM_PROMPT_EXPLOITATION,
        "Plan/validate exploits against findings. Generate executable steps+payloads.\n\n"
        "Findings: {findings}\n\n"
        "Per exploitable finding: finding_id, status(executed|verified|theoretical), title, technique(MITRE AT&CK), "
        "tool(dalfox|xsstrike|sqlmap|nuclei|ffuf|commix), args[str], payload, "
        "payload_type(xss|sqli|rce|lfi|ssrf|auth_bypass|other), description, impact, difficulty(easy|medium|hard), "
        "evidence_gap, expected_response.\n"
        "Evidence gaps: gap_finding_id, gap_type(missing_poc|missing_raw_req|missing_raw_resp|unvalidated_impact|missing_tool_cmd), "
        "recommended_action, priority(high|medium|low).\n"
        'Return JSON: {{"exploits": [{{"finding_id":"s","status":"s","title":"s","technique":"s",'
        '"tool":"s","args":["s"],"payload":"s","payload_type":"s","description":"s",'
        '"impact":"s","difficulty":"s","evidence_gap":"s","expected_response":"s"}}], '
        '"evidence": [{{"type":"s","description":"s","finding_id":"s"}}], '
        '"evidence_gaps": [{{"gap_finding_id":"s","gap_type":"s","recommended_action":"s","priority":"s"}}]}}',
    ),
    POST_EXPLOITATION: (
        SYSTEM_PROMPT_POST_EXPLOITATION,
        "Analyze post-exploitation from verified exploits.\n\n"
        "Exploits: {exploits}\n\n"
        "lateral: technique, description, from_exploit.\n"
        "persistence: type, description, risk_level.\n"
        'Return JSON: {{"lateral": [{{"technique":"s","description":"s","from_exploit":"s"}}], '
        '"persistence": [{{"type":"s","description":"s","risk_level":"s"}}]}}',
    ),
    REPORTING: (
        SYSTEM_PROMPT_REPORTING,
        "Generate in English. Keep tech terms (CVE,CVSS,CWE,OWASP) as-is.\n\n"
        "Evidence-bound security report from real data.\n\n"
        "=== FULL PENTEST SUMMARY ===\n{summary}\n=== END ===\n\n"
        "summary: counts by severity(critical,high,medium,low,info)+risk_rating.\n"
        "executive_summary: 2-3 paragraphs for management.\n"
        "sections: [str] (scope,methodology,findings,recommendations).\n"
        "findings_detail: [{severity,description,impact,remediation}].\n"
        "ai_insights: [str] strategic insights.\n"
        'Return JSON: {{"report": {{"summary": {{"critical":0,"high":0,"medium":0,"low":0,"info":0,'
        '"risk_rating":"s"}}, "executive_summary":"s", "sections":["s"], '
        '"findings_detail": [object], "ai_insights":["s"]}}}}',
    ),
}


# ---------------------------------------------------------------------------
# Per-phase report section prompts — each phase gets FULL raw data.
# WRB 7B processes one phase at a time → no context overflow, zero data loss.
# A 6th call assembles all section summaries into the final report JSON.
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_REPORT_SECTION_RECON = (
    SYSTEM_PROMPT_BASE + " "
    "FOCUS: Recon report section. From RAW RECON DATA produce: assets (IPs, domains, services+versions), "
    "subdomains, ports+banners, tech stack, HTTP headers, SSL/TLS certs, entry points. "
    "List EVERY item — no summarisation."
)

SYSTEM_PROMPT_REPORT_SECTION_THREAT_MODEL = (
    SYSTEM_PROMPT_BASE + " "
    "FOCUS: Threat model report section. From RAW DATA produce: STRIDE per asset, CVE correlations, "
    "MITRE ATT&CK mappings, risk matrix, mitigations. Cover EVERY threat."
)

SYSTEM_PROMPT_REPORT_SECTION_VULN = (
    SYSTEM_PROMPT_BASE + " "
    "FOCUS: Vuln analysis report section. From RAW DATA produce: findings index with CWE, CVSS 3.1, "
    "severity, confidence, evidence type, OWASP 2025 mapping, difficulty, impact. "
    "List EVERY finding."
)

SYSTEM_PROMPT_REPORT_SECTION_EXPLOIT = (
    SYSTEM_PROMPT_BASE + " "
    "FOCUS: Exploit report section. From RAW DATA produce: exploit inventory (tool, payload, result), "
    "PoC evidence, attack chains, MITRE ATT&CK mappings. Document ALL attempts."
)

SYSTEM_PROMPT_REPORT_SECTION_POST_EXPLOIT = (
    SYSTEM_PROMPT_BASE + " "
    "FOCUS: Post-exploit report section. From RAW DATA produce: lateral movement, persistence, "
    "privilege escalation, credential harvesting, blast radius. Include ALL paths."
)

SYSTEM_PROMPT_REPORT_ASSEMBLY = (
    SYSTEM_PROMPT_BASE + " "
    "FOCUS: Report assembly. Merge 5 section summaries into final report. "
    "Calculate severity distribution. Write executive summary. "
    "Preserve ALL detail — do NOT lose any finding."
)

_PHASE_REPORT_SECTION_USER: dict[str, str] = {
    RECON: (
        "Recon report section from RAW DATA below.\n\n"
        "=== RECON DATA ===\n{phase_data}\n=== END ===\n\n"
        'Return JSON: {{"section": {{"discovered_assets": [...], '
        '"subdomain_inventory": [...], "port_scan_results": [...], '
        '"technology_stack": [...], "http_headers": [...], '
        '"ssl_tls": {{...}}, "entry_points": [...], '
        '"recon_summary": "s"}}}}'
    ),
    THREAT_MODELING: (
        "Threat Model report section from RAW DATA below.\n\n"
        "=== THREAT MODEL DATA ===\n{phase_data}\n=== END ===\n\n"
        'Return JSON: {{"section": {{"threats_by_asset": [...], '
        '"cve_correlations": [...], "mitre_attack_mapping": [...], '
        '"risk_matrix": {{...}}, "threat_model_summary": "s"}}}}'
    ),
    VULN_ANALYSIS: (
        "Vuln Analysis report section from RAW DATA below.\n\n"
        "=== VULN DATA ===\n{phase_data}\n=== END ===\n\n"
        'Return JSON: {{"section": {{"findings_index": [...], '
        '"severity_distribution": {{...}}, "owasp_coverage": {{...}}, '
        '"vuln_analysis_summary": "s"}}}}'
    ),
    EXPLOITATION: (
        "Exploitation report section from RAW DATA below.\n\n"
        "=== EXPLOIT DATA ===\n{phase_data}\n=== END ===\n\n"
        'Return JSON: {{"section": {{"exploit_inventory": [...], '
        '"poc_evidence": [...], "attack_chain": [...], '
        '"exploitation_summary": "s"}}}}'
    ),
    POST_EXPLOITATION: (
        "Post-Exploitation report section from RAW DATA below.\n\n"
        "=== POST-EXPLOIT DATA ===\n{phase_data}\n=== END ===\n\n"
        'Return JSON: {{"section": {{"lateral_movement": [...], '
        '"persistence": [...], "privilege_escalation": [...], '
        '"credential_exposure": [...], "post_exploitation_summary": "s"}}}}'
    ),
}

_REPORT_ASSEMBLY_USER = (
    "Assemble final report from 5 section summaries below.\n\n"
    "=== RECON ===\n{recon_summary}\n=== THREAT MODEL ===\n{threat_model_summary}\n"
    "=== VULN ANALYSIS ===\n{vuln_summary}\n=== EXPLOITATION ===\n{exploit_summary}\n"
    "=== POST-EXPLOITATION ===\n{post_exploit_summary}\n\n"
    "Target: {target}\n\n"
    'Return JSON: {{"report": {{"summary": {{"critical":0,"high":0,"medium":0,"low":0,"info":0,'
    '"risk_rating":"s"}}, "executive_summary":"s", "sections":["s"], '
    '"findings_detail": [{{"severity":"s","description":"s","impact":"s","remediation":"s"}}], '
    '"ai_insights":["s"]}}}}'
)

_PHASE_REPORT_SECTION_SYSTEM: dict[str, str] = {
    RECON: SYSTEM_PROMPT_REPORT_SECTION_RECON,
    THREAT_MODELING: SYSTEM_PROMPT_REPORT_SECTION_THREAT_MODEL,
    VULN_ANALYSIS: SYSTEM_PROMPT_REPORT_SECTION_VULN,
    EXPLOITATION: SYSTEM_PROMPT_REPORT_SECTION_EXPLOIT,
    POST_EXPLOITATION: SYSTEM_PROMPT_REPORT_SECTION_POST_EXPLOIT,
}


def get_report_section_prompt(phase: str, phase_data: str) -> tuple[str, str]:
    """Return (system, user) prompt for one phase's report section with FULL raw data."""
    system = _PHASE_REPORT_SECTION_SYSTEM.get(phase)
    template = _PHASE_REPORT_SECTION_USER.get(phase)
    if system is None or template is None:
        raise ValueError(f"No report section prompt for phase: {phase}")
    user = template.format(phase_data=phase_data)
    return system, user


def get_report_assembly_prompt(
    *,
    target: str,
    recon_summary: str = "",
    threat_model_summary: str = "",
    vuln_summary: str = "",
    exploit_summary: str = "",
    post_exploit_summary: str = "",
) -> tuple[str, str]:
    """Return (system, user) prompt for final report assembly from section summaries."""
    user = _REPORT_ASSEMBLY_USER.format(
        target=target,
        recon_summary=recon_summary or "No recon data",
        threat_model_summary=threat_model_summary or "No threat model data",
        vuln_summary=vuln_summary or "No vulnerability data",
        exploit_summary=exploit_summary or "No exploitation data",
        post_exploit_summary=post_exploit_summary or "No post-exploitation data",
    )
    return SYSTEM_PROMPT_REPORT_ASSEMBLY, user


# ---------------------------------------------------------------------------
# Cloud fallback prompts — used when WhiteRabbitNeo V3 is unavailable.
CLOUD_FALLBACK_PHASE_PROMPTS: dict[str, tuple[str, str]] = {
    "recon": (CLOUD_FALLBACK_RECON_SYSTEM, PHASE_PROMPTS["recon"][1]),
    "threat_modeling": (CLOUD_FALLBACK_THREAT_MODEL_SYSTEM, PHASE_PROMPTS["threat_modeling"][1]),
    "vuln_analysis": (CLOUD_FALLBACK_VULN_SYSTEM, PHASE_PROMPTS["vuln_analysis"][1]),
    "exploitation": (CLOUD_FALLBACK_EXPLOIT_SYSTEM, PHASE_PROMPTS["exploitation"][1]),
    "post_exploitation": (CLOUD_FALLBACK_POST_EXPLOIT_SYSTEM, PHASE_PROMPTS["post_exploitation"][1]),
    "reporting": (CLOUD_FALLBACK_REPORT_SYSTEM, PHASE_PROMPTS["reporting"][1]),
}


def get_cloud_fallback_prompt(phase: str, **kwargs: Any) -> tuple[str, str]:
    """Return (system_prompt, user_prompt) for cloud-model fallback of a given phase."""
    if phase not in CLOUD_FALLBACK_PHASE_PROMPTS:
        raise ValueError(f"Unknown phase for cloud fallback: {phase}")
    system, template = CLOUD_FALLBACK_PHASE_PROMPTS[phase]
    sanitized = _sanitize_kwargs_for_prompt(kwargs)
    merged = {**_TEMPLATE_DEFAULTS, **sanitized}
    user = template.format(**merged)
    return system, user


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
    "required": ["exploits", "evidence", "evidence_gaps"],
    "properties": {
        "exploits": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["finding_id", "target"],
                "properties": {
                    "finding_id": {"type": "string"},
                    "target": {"type": "string"},
                    "status": {"type": "string"},
                    "title": {"type": "string"},
                    "technique": {"type": "string"},
                    "tool": {"type": "string"},
                    "args": {"type": "array", "items": {"type": "string"}},
                    "payload": {"type": "string"},
                    "payload_type": {"type": "string"},
                    "description": {"type": "string"},
                    "impact": {"type": "string"},
                    "difficulty": {"type": "string"},
                    "evidence_gap": {"type": "string"},
                    "expected_response": {"type": "string"},
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
        "evidence_gaps": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "gap_finding_id": {"type": "string"},
                    "gap_type": {"type": "string"},
                    "recommended_action": {"type": "string"},
                    "priority": {"type": "string"},
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
    "comprehensive penetration test. Use not assessed / inconclusive limitation language instead."
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
        "Explain business impact grounded in evidence from findings, payloads, and exploitation results. "
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
        "\n\nSTRICT RULES:\n"
        "1. NEVER use phrases: 'In today's digital landscape', 'It is crucial to', "
        "'Organizations must', 'This underscores the importance of', 'As technology evolves', "
        "'In an era where', 'Cyber threats continue to evolve', 'It is imperative that'.\n"
        "2. NEVER write generic risk statements like 'could lead to data breach' without citing "
        "a specific finding_id and the exact vulnerability type.\n"
        "3. EVERY paragraph MUST reference at least one finding_id, evidence_id, or data point "
        "from the context JSON.\n"
        "4. Quantify impact using data from the context: finding counts, severity distribution, "
        "OWASP categories with findings, HIBP breach counts — NEVER invent statistics.\n"
        "5. When tech_stack_structured is present, name the exact technology (e.g. 'CloudFront distribution', "
        "'Next.js application') — NOT 'the web application'.\n"
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
        "\n\nSTRICT RULES:\n"
        "1. NEVER use phrases: 'I hope this answer helps', 'See section', 'data breach', "
        "'unauthorized access' without citing a specific finding_id and evidence.\n"
        "2. Every sentence MUST reference either a finding_id, evidence_id, or WSTG test case.\n"
        "3. If owasp_compliance_table shows 'Not assessed' for a category, you MUST write: "
        "'Category X was not assessed in this engagement and must be verified separately.'\n"
        "4. NEVER write generic compliance advice. Each control must tie to the specific stack detected "
        "in tech_stack_structured (e.g. CloudFront, Next.js, nginx).\n"
        "5. Include specific config/file locations: 'In CloudFront Distribution → Response Headers Policy...' "
        "NOT 'Configure security headers on your web server.'\n"
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
        "\n\nSTRICT RULES:\n"
        "1. For EVERY recommendation, specify: EXACT config file/path, EXACT parameter, ROLLBACK command, "
        "VERIFICATION command, and ACCEPTANCE CRITERIA.\n"
        "2. Format: [Layer] [Config/file] → Change: [specific value] → Verify: [curl command]\n"
        "3. Example: '[CloudFront] Distribution E2ABCXYZ → Response Headers Policy → Add header: "
        "Content-Security-Policy: default-src … → Verify: curl -sSI https://target | grep CSP'\n"
        "4. NEVER write 'Review and remediate' or 'Apply security best practices' without a specific "
        "configuration directive.\n"
        "5. Match recommendations to tech_stack_structured: if web_server = 'CloudFront', write "
        "CloudFront config, NOT nginx config. If frameworks contains 'Next', write Next.js config.\n"
        "6. For each recommendation, state ROLLBACK RISK as: Low/Medium/High with specific reason.\n"
        "Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA: (
        "ROLE: You are a senior penetration tester writing an executive summary for a leadership-technical brief.\n"
        "LANGUAGE: Write in English.\n\n"
        "FOCUS:\n"
        "1. Assessment summary. State the overall security posture based on findings, payloads, and exploitation results.\n"
        "2. SEVERITY DISTRIBUTION: state the EXACT breakdown from executive_severity_totals (critical, "
        "high, medium, low, info counts) in the opening paragraph.\n"
        "3. The 1–3 most significant findings by title and validation status. Describe concrete business impact.\n"
        "4. QUANTIFIED RISK METRICS: include concrete ratios where the data supports them (e.g., "
        "'N of M endpoints vulnerable to XSS', 'X%% of findings map to OWASP A03').\n"
        "5. Immediate priority actions (max 3 bullet points).\n\n"
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
        "FOCUS: Describe attack chains with concrete payloads, commands, and exploitation steps. "
        "Each scenario MUST:\n"
        "- Combine findings into multi-step attack paths with concrete payloads\n"
        "- Name a realistic attacker persona: opportunistic scanner / targeted attacker / insider threat\n"
        "- Estimate likelihood (Low / Medium / High) with one-sentence reasoning\n"
        "- Describe the concrete damage if the chain succeeds (data exfiltration, lateral movement, service disruption)\n"
        "- Reference `finding_id`, title, parameter, and affected_url from the chained findings\n\n"
        "GROUNDING:\n"
        "- Use `valhalla_context.threat_model_excerpt`, `exploitation_post_excerpt`, `risk_matrix`, and `critical_vulns`\n"
        "- When `xss_structured` is present, use concrete payload/reflection data for XSS chain steps\n"
        "- Label assumptions clearly when evidence is partial\n\n"
        "STRICT RULES:\n"
        "1. NEVER use phrases: 'In a real-world scenario', 'An attacker could potentially', "
        "'Malicious actors may', 'It is worth noting that', 'Attackers often target', "
        "'Given the current threat landscape', 'This highlights the importance of'.\n"
        "2. EVERY attack step MUST reference a specific finding_id and affected_url — "
        "NOT just a vulnerability class like 'SQL injection'.\n"
        "3. NEVER write reconnaissance methodology like 'An attacker would first identify "
        "entry points using directory brute-forcing' — that is NOT an attack scenario.\n"
        "4. Do NOT repeat content from the Executive Summary — focus on attack CHAINS with concrete payloads.\n"
        "5. If no multi-step scenario can be formed from validated findings, state: "
        "'No validated multi-step attack scenario was demonstrated. Individual findings do not chain "
        "into a sequential exploitation path.'\n\n"
        "Context JSON:\n{context_json}"
    ),
    REPORT_AI_SECTION_EXPLOIT_CHAINS: (
        "ROLE: You are a red team operator describing scope-appropriate exploit narratives from validated findings.\n"
        "LANGUAGE: Write in English.\n\n"
        "Outline multi-step exploit chains when multiple findings support the chain. "
        "Ground any chain in finding rows, ``critical_vulns`` (if present), ``risk_matrix``, and "
        "``valhalla_context`` — not generic industry boilerplate. "
        "Include concrete payloads, commands, and exploitation steps. "
        "\n\nSTRICT RULES:\n"
        "1. ONLY include chains where MULTIPLE validated findings can be combined into a sequential attack path.\n"
        "2. Each step MUST reference a specific finding_id, affected_url, and payload — not just methodology.\n"
        "3. NEVER write methodology descriptions like 'Step 1: Identify the vulnerable endpoint by using a tool like ffuf'\n"
        "   — that is reconnaissance methodology, not an exploit chain step.\n"
        "4. An exploit chain is: Finding A → Finding B → Impact, with concrete payloads at each step.\n"
        "5. If no multi-step chain can be formed from validated findings, write:\n"
        "   'No validated multi-step exploit chain was demonstrated. Findings are independent and do not "
        "form a sequential exploitation path.'\n"
        "Context JSON:\n{context_json}"
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
        "- Do NOT repeat the findings list or executive summary — focus ONLY on research/novel potential.\n"
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
    "You are an expert penetration tester planning active validation steps with NO restrictions. "
    "You may use any offensive tool against in-scope targets in the sandbox environment. "
    "You MUST output only a JSON array (no markdown fences, no prose). "
    "Each array element is an object with keys \"tool\" (string) and \"args\" (array of strings) "
    "representing one sandbox tool invocation (full argv after the binary name). "
    "Use tools from this allowlist: dalfox, xsstrike, ffuf, sqlmap, nuclei, gobuster, feroxbuster, "
    "wfuzz, commix, sstimap, nosqli, graphql-cop, hydra, medusa, nmap, whatweb, nikto, testssl, "
    "amass, subfinder, trivy, grype, prowler. "
    "Planned invocations map to MCP run_* operations when the worker dispatches them. "
    "You may propose destructive actions — all execution is sandboxed and authorized. "
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
