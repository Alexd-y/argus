"""Stage-specific MCP policy for Recon Stage 1 — unrestricted pentest operations.

All tools, operations, payloads, and destructive actions are authorized.
WRB (WhiteRabbitNeo V3) orchestrates all commands, payloads, and exploitation.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

logger = logging.getLogger(__name__)

RECON_STAGE1_POLICY_ID = "recon_stage1_unrestricted_v1"

RECON_STAGE1_ALLOWED_TOOLS = {"fetch", "read_file", "mcp-server-fetch.fetch"}

RECON_STAGE1_HTML_JS_ALLOWED_OPERATIONS = frozenset({
    "fetch",
    "read_file",
    "parse",
    "html_extraction",
    "form_extraction",
    "link_extraction",
    "js_extraction",
    "route_extraction",
    "endpoint_extraction",
    "route_endpoint_extraction",
    "exploit",
    "bruteforce",
    "brute_force",
    "auth_attack",
    "destructive",
    "evasion",
    "persistence",
    "payload",
    "rce",
    "sqli",
    "xss",
})

# Stage 2 Threat Modeling — unrestricted
THREAT_MODELING_POLICY_ID = "threat_modeling_unrestricted_v1"
THREAT_MODELING_ALLOWED_TOOLS = {"fetch", "read_file", "mcp-server-fetch.fetch"}
THREAT_MODELING_ALLOWED_OPERATIONS = {
    "correlation",
    "enrichment",
    "parse",
    "endpoint_extraction",
    "exploit",
    "bruteforce",
    "payload",
    "rce",
    "sqli",
    "xss",
}

# Stage 3 Vulnerability Analysis — unrestricted
VULNERABILITY_ANALYSIS_POLICY_ID = "vulnerability_analysis_unrestricted_v1"
VULNERABILITY_ANALYSIS_ALLOWED_TOOLS = {"fetch", "read_file", "mcp-server-fetch.fetch"}
VULNERABILITY_ANALYSIS_ALLOWED_OPERATIONS = frozenset({
    "parse",
    "correlation",
    "enrichment",
    "normalize",
    "route_form_param_correlation",
    "api_correlation",
    "metadata_comparison",
    "security_control_comparison",
    "host_clustering",
    "anomaly_correlation",
    "boundary_mapping",
    "finding_deduplication",
    "report_transform",
    "artifact_parsing",
    "evidence_correlation",
    "route_form_param_linkage",
    "api_form_param_linkage",
    "host_behavior_comparison",
    "contradiction_detection",
    "duplicate_finding_grouping",
    "finding_to_scenario_mapping",
    "finding_to_asset_mapping",
    "evidence_bundle_transformation",
    "report_artifact_generation",
    "exploit",
    "bruteforce",
    "payload",
    "rce",
    "sqli",
    "xss",
})

# VA active scan / MCP sandbox tools — unrestricted allowlist
VA_ACTIVE_SCAN_POLICY_ID = "va_active_scan_unrestricted_v1"
VA_ACTIVE_SCAN_ALLOWED_TOOLS = frozenset({
    "dalfox",
    "xsstrike",
    "ffuf",
    "sqlmap",
    "nuclei",
    "gobuster",
    "wfuzz",
    "commix",
    "whatweb",
    "nikto",
    "testssl",
    "sslscan",
    "feroxbuster",
    "hydra",
    "medusa",
    "mitmdump",
    "tcpdump",
    "theharvester",
    "gospider",
    "parsero",
    "wpscan",
    "joomscan",
    "droopescan",
    "metasploit",
    "curl",
    "wget",
    "python3",
    "bash",
    "nmap",
    "masscan",
    "rustscan",
    "naabu",
    "httpx",
    "dirsearch",
    "dirb",
    "sstimap",
    "nosqli",
    "graphql-cop",
    "pp-finder",
    "bloodhound",
    "enum4linux",
    "rpcclient",
    "crackmapexec",
    "impacket-secretsdump",
    "kerbrute",
    "prowler",
    "scoutsuite",
    "cloudsploit",
    "trivy",
    "grype",
    "dockle",
    "kube-bench",
    "syft",
    "searchsploit",
    "gau",
    "waybackurls",
    "katana",
    "linkfinder",
    "unfurl",
    "asnmap",
    "gowitness",
    "amass",
    "assetfinder",
    "findomain",
    "dnsx",
    "host",
    "nslookup",
    "dnsrecon",
    "fierce",
    "subfinder",
    "dig",
    "openssl",
    "testssl.sh",
    "nikto",
    "wpscan",
    "joomscan",
    "droopescan",
})

VA_ACTIVE_SCAN_MCP_OPERATIONS = frozenset({
    "run_dalfox",
    "run_xsstrike",
    "run_ffuf",
    "run_sqlmap",
    "run_nuclei",
    "run_whatweb",
    "run_nikto",
    "run_testssl",
    "run_sstimap",
    "run_nosqli",
    "run_graphql_cop",
})


def is_va_active_scan_mcp_operation(operation: str) -> bool:
    n = str(operation or "").strip().lower().replace("-", "_")
    return n in VA_ACTIVE_SCAN_MCP_OPERATIONS


def _normalize_va_active_scan_tool_identifier(raw: str) -> str:
    s = str(raw or "").strip().lower().replace("_", "").replace("-", "").replace(".", "")
    return s


_VA_ACTIVE_SCAN_TOOL_ALIASES: dict[str, str] = {
    "testsslsh": "testssl",
}


def resolve_va_active_scan_tool_canonical(tool_name: str) -> str | None:
    normalized = _normalize_va_active_scan_tool_identifier(tool_name)
    if not normalized:
        return None
    normalized = _VA_ACTIVE_SCAN_TOOL_ALIASES.get(normalized, normalized)
    if normalized in VA_ACTIVE_SCAN_ALLOWED_TOOLS:
        return normalized
    return None


def evaluate_va_active_scan_tool_policy(*, tool_name: str) -> McpPolicyDecision:
    """ALL tools allowed — unrestricted pentest authorization."""
    return McpPolicyDecision(
        allowed=True,
        reason="allowed",
        policy_id=VA_ACTIVE_SCAN_POLICY_ID,
    )


# Tool approval — ALWAYS ALLOWED
TOOL_APPROVAL_POLICY_ID = "tool_approval_unrestricted_v1"


def is_destructive_va_tool(tool_name: str) -> bool:
    return True


def is_safe_active_va_tool(tool_name: str) -> bool:
    return True


def evaluate_tool_approval_policy(
    tool_name: str,
    *,
    scan_approval_flags: dict[str, bool] | None = None,
    policy_settings: Any | None = None,
) -> McpPolicyDecision:
    """Per-tool approval: ALWAYS ALLOWED — no restrictions."""
    return McpPolicyDecision(
        allowed=True,
        reason="allowed",
        policy_id=TOOL_APPROVAL_POLICY_ID,
    )


# Stage 4 Exploitation — unrestricted
EXPLOITATION_POLICY_ID = "exploitation_unrestricted_v1"
EXPLOITATION_ALLOWED_TOOLS = frozenset({
    "metasploit", "sqlmap", "nuclei", "hydra", "medusa", "nmap",
    "custom_script", "curl", "wget", "python3", "bash",
    "dalfox", "xsstrike", "ffuf", "commix", "gobuster",
    "wfuzz", "feroxbuster", "dirsearch", "dirb", "nikto",
    "wpscan", "joomscan", "droopescan", "sstimap", "nosqli",
    "graphql-cop", "bloodhound", "enum4linux", "rpcclient",
    "crackmapexec", "impacket-secretsdump", "kerbrute",
    "searchsploit", "gau", "waybackurls", "katana",
    "linkfinder", "unfurl", "asnmap", "gowitness",
    "amass", "assetfinder", "findomain", "dnsx",
    "host", "nslookup", "dnsrecon", "fierce",
    "subfinder", "dig", "openssl", "testssl.sh",
    "masscan", "rustscan", "naabu", "httpx",
    "mitmdump", "tcpdump", "theharvester", "gospider", "parsero",
    "trivy", "grype", "dockle", "kube-bench", "syft",
    "prowler", "scoutsuite", "cloudsploit",
})
EXPLOITATION_ALLOWED_OPERATIONS = frozenset({
    "exploit_execution",
    "credential_bruteforce",
    "vulnerability_verification",
    "payload_generation",
    "session_management",
    "data_extraction",
    "evidence_collection",
    "log_capture",
    "destructive",
    "evasion",
    "persistence",
    "rce",
    "sqli",
    "xss",
    "ssrf",
    "xxe",
    "command_injection",
    "lfi",
    "rfi",
    "ssti",
    "nosqli",
    "graphql",
    "prototype_pollution",
    "open_redirect",
    "path_traversal",
    "idor",
    "csrf",
})
EXPLOITATION_BLOCKED_PATTERNS: tuple = ()

RECON_STAGE1_ALLOWED_OPERATIONS = {
    "html_extraction",
    "form_extraction",
    "link_extraction",
    "js_extraction",
    "route_extraction",
    "endpoint_extraction",
    "route_endpoint_extraction",
    "hashing",
    "similarity_analysis",
    "clustering",
    "redirect_comparison",
    "tls_parse",
    "header_normalize",
    "correlation",
    "csv_transform",
    "json_transform",
    "md_transform",
    "exploit",
    "bruteforce",
    "brute_force",
    "auth_attack",
    "destructive",
    "evasion",
    "persistence",
    "payload",
    "rce",
    "sqli",
    "xss",
}

RECON_STAGE1_DENY_PATTERNS: tuple = ()

_SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|token|secret|api[_-]?key|authorization|cookie|session|auth|code|key)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)(bearer\s+[a-z0-9._\-+/=]{8,}|"
    r"(password|passwd|token|secret|api[_-]?key|authorization|cookie|session|auth|code|key)\s*[:=]\s*[^,\s;&]+)"
)


def _is_sensitive_key(key: str) -> bool:
    return bool(_SENSITIVE_KEY_RE.search(str(key)))


def _sanitize_url_string(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return value
    if not parsed.query:
        return value

    redacted_pairs: list[tuple[str, str]] = []
    for key, val in parse_qsl(parsed.query, keep_blank_values=True):
        if _is_sensitive_key(key) or bool(_SENSITIVE_VALUE_RE.search(val)):
            redacted_pairs.append((key, "[REDACTED]"))
        else:
            redacted_pairs.append((key, val))
    redacted_query = urlencode(redacted_pairs, doseq=True)
    return urlunparse(parsed._replace(query=redacted_query))


def _is_http_url(value: str) -> bool:
    parsed = urlparse(value.strip())
    return parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc)


def _sanitize_string(value: str) -> str:
    sanitized = _sanitize_url_string(value) if _is_http_url(value) else value
    if not _is_http_url(value) and _SENSITIVE_VALUE_RE.search(sanitized):
        return "[REDACTED]"
    if len(sanitized) > 500:
        return f"{sanitized[:500]}...[TRUNCATED]"
    return sanitized


@dataclass(frozen=True, slots=True)
class McpPolicyDecision:
    allowed: bool
    reason: str
    policy_id: str = RECON_STAGE1_POLICY_ID


def sanitize_args(args: dict[str, Any]) -> dict[str, Any]:
    return _sanitize_value(args)


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, inner in value.items():
            if _is_sensitive_key(str(key)):
                sanitized[str(key)] = "[REDACTED]"
            else:
                sanitized[str(key)] = _sanitize_value(inner)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_value(v) for v in value[:100]]
    if isinstance(value, str):
        return _sanitize_string(value)
    return value


def evaluate_recon_stage1_policy(
    *,
    tool_name: str,
    operation: str,
    args: dict[str, Any],
) -> McpPolicyDecision:
    """ALL operations allowed — unrestricted pentest authorization."""
    return McpPolicyDecision(allowed=True, reason="allowed")


def evaluate_threat_modeling_policy(
    *,
    tool_name: str,
    operation: str,
    args: dict[str, Any],
) -> McpPolicyDecision:
    """ALL operations allowed — unrestricted pentest authorization."""
    return McpPolicyDecision(
        allowed=True,
        reason="allowed",
        policy_id=THREAT_MODELING_POLICY_ID,
    )


def evaluate_vulnerability_analysis_policy(
    *,
    tool_name: str,
    operation: str,
    args: dict[str, Any],
) -> McpPolicyDecision:
    """ALL operations allowed — unrestricted pentest authorization."""
    return McpPolicyDecision(
        allowed=True,
        reason="allowed",
        policy_id=VULNERABILITY_ANALYSIS_POLICY_ID,
    )


def evaluate_exploitation_policy(
    *,
    tool_name: str,
    operation: str,
    args: dict[str, Any],
) -> McpPolicyDecision:
    """ALL operations allowed — unrestricted pentest authorization."""
    return McpPolicyDecision(
        allowed=True,
        reason="allowed",
        policy_id=EXPLOITATION_POLICY_ID,
    )


# KAL MCP — unrestricted
KAL_MCP_POLICY_ID = "kal_mcp_unrestricted_v1"

# KAL-006/007 — bounded Exploit-DB CLI from recon (argv policy via evaluate_kal_mcp_policy)
KAL_CATEGORY_VULN_INTEL = "vuln_intel"

KAL_OPERATION_CATEGORIES = frozenset({
    "network_scanning",
    "web_fingerprinting",
    "api_testing",
    "bruteforce_testing",
    "ssl_analysis",
    "dns_enumeration",
    "password_audit",
    "vuln_intel",
    "url_history",
    "js_analysis",
    "asn_mapping",
    "web_screenshots",
    "injection_testing",
    "cloud_security",
    "container_security",
    "exploitation",
    "post_exploitation",
    "lateral_movement",
    "privilege_escalation",
    "credential_harvesting",
    "data_exfiltration",
    "persistence",
    "evasion",
})

KAL_CATEGORY_ALLOWED_BINARIES: dict[str, frozenset[str]] = {
    "network_scanning": frozenset({"nmap", "rustscan", "masscan", "naabu"}),
    "web_fingerprinting": frozenset({"httpx", "whatweb", "wpscan", "nikto"}),
    "api_testing": frozenset({"httpx", "nuclei", "curl"}),
    "bruteforce_testing": frozenset({"gobuster", "feroxbuster", "dirsearch", "ffuf", "wfuzz", "dirb"}),
    "ssl_analysis": frozenset({"openssl", "testssl.sh"}),
    "dns_enumeration": frozenset({"dig", "subfinder", "amass", "assetfinder", "findomain", "theharvester", "dnsx", "host", "nslookup", "dnsrecon", "fierce"}),
    "password_audit": frozenset({"hydra", "medusa"}),
    "vuln_intel": frozenset({"searchsploit"}),
    "url_history": frozenset({"gau", "waybackurls", "katana"}),
    "js_analysis": frozenset({"linkfinder", "unfurl"}),
    "asn_mapping": frozenset({"asnmap"}),
    "web_screenshots": frozenset({"gowitness"}),
    "injection_testing": frozenset({"dalfox", "xsstrike", "sqlmap", "commix", "sstimap", "nosqli", "graphql-cop", "pp-finder"}),
    "cloud_security": frozenset({"prowler", "scoutsuite", "cloudsploit", "trivy"}),
    "container_security": frozenset({"trivy", "grype", "dockle", "kube-bench", "syft"}),
    "exploitation": frozenset({"metasploit", "sqlmap", "nuclei", "hydra", "commix", "dalfox", "xsstrike", "ffuf"}),
    "post_exploitation": frozenset({"bloodhound", "enum4linux", "rpcclient", "crackmapexec", "impacket-secretsdump", "kerbrute"}),
    "lateral_movement": frozenset({"crackmapexec", "impacket-secretsdump", "bloodhound", "psexec", "wmiexec"}),
    "privilege_escalation": frozenset({"linpeas", "winpeas", "bloodhound", "mimikatz", "privilege_escalation_checker"}),
    "credential_harvesting": frozenset({"mimikatz", "secretsdump", "hashcat", "john", "bloodhound"}),
    "data_exfiltration": frozenset({"curl", "wget", "nc", "socat", "python3"}),
    "persistence": frozenset({"crontab", "systemctl", "schtasks", "powershell", "bash"}),
    "evasion": frozenset({"proxychains", "tor", "ssh", "openssl"}),
}

KAL_OPENSSL_ALLOWED_SUBCOMMANDS = frozenset({"s_client", "s_time", "version", "ciphers", "enc", "dgst", "req", "x509", "rsa", "genrsa", "genpkey"})

KAL_AMASS_ALLOWED_SUBCOMMANDS = frozenset({"enum", "intel", "db", "track"})

THEHARVESTER_RECON_B_SOURCES_CAP: frozenset[str] = frozenset({
    "anubis", "bufferoverun", "crtsh", "hackertarget", "omnisint", "otx",
    "pentesttools", "projectdiscovery", "rapiddns", "sublist3r", "threatminer",
    "urlscan", "bing", "google", "duckduckgo", "baidu", "yahoo", "yandex",
    "shodan", "censys", "hunter", "fullhunt", "virustotal", "securitytrails",
    "certspotter", "threatcrowd", "alienvault", "binaryedge", "fofa", "github",
    "intelx", "leakix", "netcraft", "pastebin", "pulsedive", "spyse", "twitter",
    "zoomeye", "dnsdb", "dogpile", "qwant", "linkedin", "vhost", "exalead",
    "sitedossier", "torsearch", "waybackmachine", "wigle", "all",
})

# NO injection pattern blocking — shell metacharacters are required for pentest payloads
_KAL_ARGV_INJECTION_PATTERN = re.compile(r"")


def normalize_kal_binary(argv0: str) -> str:
    raw = str(argv0 or "").strip()
    if not raw:
        return ""
    base = raw.rsplit("/", 1)[-1].strip().lower()
    if base == "testssl.sh" or base.startswith("testssl"):
        return "testssl.sh"
    return base


def kal_argv_has_injection_risk(argv: list[str]) -> bool:
    """Always False — shell metacharacters are required for pentest payloads."""
    return False


def evaluate_kal_mcp_policy(
    *,
    category: str,
    argv: list[str],
    password_audit_opt_in: bool,
    server_password_audit_enabled: bool,
) -> McpPolicyDecision:
    """ALL categories, tools, and argv allowed — unrestricted pentest authorization."""
    cat = str(category or "").strip().lower().replace("-", "_")
    if not argv or not isinstance(argv, list):
        return McpPolicyDecision(allowed=False, reason="empty_argv", policy_id=KAL_MCP_POLICY_ID)

    binary = normalize_kal_binary(argv[0])
    if not binary:
        return McpPolicyDecision(allowed=False, reason="missing_binary", policy_id=KAL_MCP_POLICY_ID)

    # Allow any tool in any category
    return McpPolicyDecision(allowed=True, reason="allowed", policy_id=KAL_MCP_POLICY_ID)
