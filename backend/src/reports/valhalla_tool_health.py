"""Valhalla customer-facing tool status: capability mapping and string sanitization (VH-004).

Strips host paths, Docker socket references, and verbose stderr from strings shown in PDF/HTML.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

_DOCKER_NOISE = re.compile(
    r"docker|containerd|/var/run/docker|docker\.sock|com\.docker|moby|"
    r"\\\.docker|daemon\.json|Error response from daemon",
    re.IGNORECASE,
)
_WIN_UNIX_PATH = re.compile(
    r"(?:[A-Za-z]:\\|/)(?:usr|var|opt|tmp|home|root|AppData|Program Files)[^\s,;|]{0,200}",
)
_MINIO_S3 = re.compile(
    r"minio|s3://|amazonaws\.com/[^\s]+|presigned|X-Amz-",
    re.IGNORECASE,
)
_JSON_BLOB = re.compile(r"\{[^{}]{20,800}\}")

CapabilityId = Literal[
    "dns_asn",
    "url_history",
    "port_discovery",
    "tls_assessment",
    "security_headers",
    "email_osint",
    "sca_dependencies",
    "technology_fingerprinting",
    "web_server_scan",
    "vuln_active_scan",
    "content_discovery",
    "credential_exposure",
    "auth_testing",
    "container_security",
    "cloud_security",
    "api_security",
    "cms_scan",
    "other",
]

_CAP_ALIASES: dict[str, tuple[CapabilityId, str]] = {
    # DNS / ASN / Surface Discovery
    "amass": ("dns_asn", "DNS / surface / ASN (recon)"),
    "subfinder": ("dns_asn", "DNS / surface / ASN (recon)"),
    "sublist3r": ("dns_asn", "DNS / surface / ASN (recon)"),
    "assetfinder": ("dns_asn", "DNS / surface / ASN (recon)"),
    "shuffledns": ("dns_asn", "DNS / surface / ASN (recon)"),
    "dnsx": ("dns_asn", "DNS / surface / ASN (recon)"),
    "dnsrecon": ("dns_asn", "DNS / surface / ASN (recon)"),
    "fierce": ("dns_asn", "DNS / surface / ASN (recon)"),
    "dig": ("dns_asn", "DNS / surface / ASN (recon)"),
    "host": ("dns_asn", "DNS / surface / ASN (recon)"),
    "whois": ("dns_asn", "DNS / surface / ASN (recon)"),
    "asnmap": ("dns_asn", "DNS / surface / ASN (recon)"),
    # Email / OSINT
    "theharvester": ("email_osint", "Email / OSINT"),
    "the_harvester": ("email_osint", "Email / OSINT"),
    "harvester": ("email_osint", "Email / OSINT"),
    "hibp": ("credential_exposure", "Credential exposure / HIBP"),
    "hibp_client": ("credential_exposure", "Credential exposure / HIBP"),
    "haveibeenpwned": ("credential_exposure", "Credential exposure / HIBP"),
    "shodan": ("email_osint", "Email / OSINT"),
    "censys": ("email_osint", "Email / OSINT"),
    "securitytrails": ("email_osint", "Email / OSINT"),
    "virustotal": ("email_osint", "Email / OSINT"),
    "abuseipdb": ("email_osint", "Email / OSINT"),
    "urlscan": ("email_osint", "Email / OSINT"),
    # URL / Live Host Discovery
    "httpx": ("url_history", "URL / live host discovery"),
    "httprobe": ("url_history", "URL / live host discovery"),
    "gau": ("url_history", "URL / history (passive)"),
    "waybackurls": ("url_history", "URL / history (passive)"),
    "katana": ("url_history", "URL / spider / crawler"),
    "hakrawler": ("url_history", "URL / spider / crawler"),
    "gospider": ("url_history", "URL / spider / crawler"),
    "gowitness": ("url_history", "URL / screenshots"),
    "eyewitness": ("url_history", "URL / screenshots"),
    "aquatone": ("url_history", "URL / screenshots"),
    # Port & Service Mapping
    "nmap": ("port_discovery", "Port & service mapping"),
    "naabu": ("port_discovery", "Port & service mapping"),
    "masscan": ("port_discovery", "Port & service mapping"),
    "rustscan": ("port_discovery", "Port & service mapping"),
    "amap": ("port_discovery", "Port & service mapping"),
    "netcat": ("port_discovery", "Port & service mapping"),
    "tlsx": ("tls_assessment", "TLS / SSL configuration"),
    # TLS / SSL Configuration
    "testssl": ("tls_assessment", "TLS / SSL configuration"),
    "testssl.sh": ("tls_assessment", "TLS / SSL configuration"),
    "sslscan": ("tls_assessment", "TLS / SSL configuration"),
    "sslyze": ("tls_assessment", "TLS / SSL configuration"),
    "openssl": ("tls_assessment", "TLS / SSL configuration"),
    "zgrab2": ("tls_assessment", "TLS / SSL configuration"),
    "cfssl": ("tls_assessment", "TLS / SSL configuration"),
    # Security Headers & WAF
    "wafw00f": ("security_headers", "WAF / security headers fingerprint"),
    "corsy": ("security_headers", "CORS / security headers"),
    "corscanner": ("security_headers", "CORS / security headers"),
    "crlfuzz": ("security_headers", "CRLF / smuggling probe"),
    "smuggler": ("security_headers", "HTTP request smuggling"),
    "h2csmuggler": ("security_headers", "HTTP/2 downgrade"),
    # Web Server / Misconfiguration Scan
    "nikto": ("web_server_scan", "Web server / misconfiguration scan"),
    "jaeles": ("web_server_scan", "Web server / signature scan"),
    "interactsh": ("web_server_scan", "OAST / out-of-band detection"),
    # Technology Fingerprinting
    "whatweb": ("technology_fingerprinting", "Technology fingerprinting"),
    "wappalyzer": ("technology_fingerprinting", "Technology fingerprinting"),
    "builtwith": ("technology_fingerprinting", "Technology fingerprinting"),
    "retire.js": ("sca_dependencies", "SCA / JS dependency risk"),
    # Active Pattern / Template Scanning
    "nuclei": ("vuln_active_scan", "Active pattern / template scanning"),
    "dalfox": ("vuln_active_scan", "XSS payload scanning"),
    "ffuf": ("vuln_active_scan", "Fuzzing / directory bruteforce"),
    "feroxbuster": ("vuln_active_scan", "Directory / content bruteforce"),
    "gobuster": ("vuln_active_scan", "Directory / DNS bruteforce"),
    "dirsearch": ("vuln_active_scan", "Directory / content bruteforce"),
    "wfuzz": ("vuln_active_scan", "Web fuzzing"),
    "xsstrike": ("vuln_active_scan", "XSS detection"),
    "sqlmap": ("vuln_active_scan", "SQL injection"),
    "commix": ("vuln_active_scan", "Command injection"),
    "tplmap": ("vuln_active_scan", "Template injection"),
    "arjun": ("vuln_active_scan", "HTTP parameter discovery"),
    "paramspider": ("vuln_active_scan", "HTTP parameter discovery"),
    "kxss": ("vuln_active_scan", "XSS param reflection"),
    "gf": ("vuln_active_scan", "Pattern filtering / grep"),
    "uro": ("vuln_active_scan", "URL deduplication"),
    "qsreplace": ("vuln_active_scan", "Query string manipulation"),
    # SCA / Dependency & Image Scanning
    "trivy": ("sca_dependencies", "SCA / dependency & image scanning"),
    "grype": ("sca_dependencies", "SCA / dependency scanning"),
    "syft": ("sca_dependencies", "SBOM generation"),
    "osv-scanner": ("sca_dependencies", "OSV vulnerability scanner"),
    "safety": ("sca_dependencies", "SCA / dependency (Python)"),
    "pip-audit": ("sca_dependencies", "SCA / dependency (Python)"),
    "npm": ("sca_dependencies", "SCA / dependency (npm)"),
    "npm audit": ("sca_dependencies", "SCA / dependency (npm)"),
    "yarn audit": ("sca_dependencies", "SCA / dependency (yarn)"),
    "pnpm audit": ("sca_dependencies", "SCA / dependency (pnpm)"),
    "composer audit": ("sca_dependencies", "SCA / dependency (PHP)"),
    "bundle-audit": ("sca_dependencies", "SCA / dependency (Ruby)"),
    "cargo audit": ("sca_dependencies", "SCA / dependency (Rust)"),
    "govulncheck": ("sca_dependencies", "SCA / dependency (Go)"),
    # Secret Scanning
    "gitleaks": ("sca_dependencies", "Secret scanning"),
    "trufflehog": ("sca_dependencies", "Secret scanning"),
    "detect-secrets": ("sca_dependencies", "Secret scanning"),
    "git-secrets": ("sca_dependencies", "Secret scanning"),
    "semgrep": ("sca_dependencies", "Static analysis / secrets"),
    # CMS Scanning
    "wpscan": ("cms_scan", "WordPress security scan"),
    "droopescan": ("cms_scan", "Drupal security scan"),
    "cmseek": ("cms_scan", "CMS detection"),
    "cmsmap": ("cms_scan", "CMS vulnerability scan"),
    # API Security
    "jwt_tool": ("api_security", "JWT analysis / manipulation"),
    "jwt-hack": ("api_security", "JWT analysis"),
    "graphql-cop": ("api_security", "GraphQL security audit"),
    "clairvoyance": ("api_security", "GraphQL introspection"),
    "inql": ("api_security", "GraphQL IDE / security"),
    "kiterunner": ("api_security", "API route bruteforce"),
    "schemathesis": ("api_security", "API schema fuzzing"),
    "postman": ("api_security", "API testing"),
    # Auth / Brute Force
    "hydra": ("auth_testing", "Brute force / auth testing"),
    "patator": ("auth_testing", "Brute force / auth testing"),
    # Cloud Security
    "cloud_enum": ("cloud_security", "Cloud resource enumeration"),
    "s3scanner": ("cloud_security", "S3 bucket scanner"),
    "gcpbucketbrute": ("cloud_security", "GCP bucket brute force"),
    "scout-suite": ("cloud_security", "Cloud security audit"),
    "prowler": ("cloud_security", "AWS security audit"),
    # Container / Kubernetes Security
    "kube-hunter": ("container_security", "Kubernetes security"),
    "kube-bench": ("container_security", "Kubernetes hardening"),
    "kube-score": ("container_security", "Kubernetes best practices"),
    "checkov": ("container_security", "IaC security scanning"),
    "terrascan": ("container_security", "IaC compliance scanning"),
    "tfsec": ("container_security", "Terraform security"),
    "kubeaudit": ("container_security", "Kubernetes audit"),
    "kube-linter": ("container_security", "Kubernetes linting"),
    "kube-no-trouble": ("container_security", "Kubernetes deprecation check"),
    # HTTP Client / Utilities
    "curl": ("url_history", "HTTP client / utility"),
    "httpie": ("url_history", "HTTP client / utility"),
    # ARGUS tools
    "va_active_scan": ("vuln_active_scan", "ARGUS active scan engine"),
    "va_active_scan_tool": ("vuln_active_scan", "ARGUS tool dispatcher"),
}

_TOOL_DISPLAY_NAMES: dict[str, str] = {
    "amass": "Amass", "subfinder": "Subfinder", "sublist3r": "Sublist3r",
    "assetfinder": "Assetfinder", "shuffledns": "ShuffleDNS", "dnsx": "dnsx",
    "dnsrecon": "DNSRecon", "fierce": "Fierce", "dig": "dig", "host": "host",
    "whois": "whois", "asnmap": "ASNMap",
    "theharvester": "theHarvester", "the_harvester": "theHarvester", "harvester": "theHarvester",
    "hibp": "HIBP Client", "hibp_client": "HIBP Client", "haveibeenpwned": "HIBP",
    "shodan": "Shodan", "censys": "Censys", "securitytrails": "SecurityTrails",
    "virustotal": "VirusTotal", "abuseipdb": "AbuseIPDB", "urlscan": "urlscan.io",
    "httpx": "httpx", "httprobe": "httprobe", "gau": "gau",
    "waybackurls": "waybackurls", "wayback": "waybackurls",
    "katana": "Katana", "hakrawler": "Hakrawler", "gospider": "GoSpider",
    "gowitness": "GoWitness", "eyewitness": "EyeWitness", "aquatone": "Aquatone",
    "nmap": "Nmap", "naabu": "Naabu", "masscan": "Masscan",
    "rustscan": "RustScan", "amap": "Amap", "netcat": "netcat",
    "tlsx": "tlsx",
    "testssl": "testssl.sh", "sslscan": "sslscan", "sslyze": "SSLyze",
    "openssl": "OpenSSL", "zgrab2": "ZGrab2", "cfssl": "CFSSL",
    "wafw00f": "WafW00f", "corsy": "Corsy", "corscanner": "CORScanner",
    "crlfuzz": "CRLFuzz", "smuggler": "Smuggler", "h2csmuggler": "H2C Smuggler",
    "nikto": "Nikto", "jaeles": "Jaeles", "interactsh": "Interactsh",
    "whatweb": "WhatWeb", "wappalyzer": "Wappalyzer", "builtwith": "BuiltWith",
    "retire.js": "Retire.js",
    "nuclei": "Nuclei", "dalfox": "Dalfox", "ffuf": "ffuf",
    "feroxbuster": "Feroxbuster", "gobuster": "Gobuster", "dirsearch": "Dirsearch",
    "wfuzz": "Wfuzz", "xsstrike": "XSStrike", "sqlmap": "SQLMap",
    "commix": "Commix", "tplmap": "Tplmap", "arjun": "Arjun",
    "paramspider": "ParamSpider", "kxss": "kxss", "gf": "gf",
    "uro": "uro", "qsreplace": "qsreplace",
    "trivy": "Trivy", "grype": "Grype", "syft": "Syft",
    "osv-scanner": "OSV Scanner", "safety": "Safety",
    "pipaudit": "pip-audit", "npm": "npm audit",
    "gitleaks": "Gitleaks", "trufflehog": "TruffleHog",
    "detect-secrets": "Detect Secrets", "git-secrets": "Git Secrets",
    "semgrep": "Semgrep",
    "wpscan": "WPScan", "droopescan": "Droopescan", "cmseek": "CMSeek", "cmsmap": "CMSMap",
    "jwt_tool": "JWT Tool", "jwt-hack": "JWT Hack",
    "graphql-cop": "GraphQL Cop", "clairvoyance": "Clairvoyance",
    "inql": "InQL", "kiterunner": "Kiterunner", "schemathesis": "Schemathesis", "postman": "Postman",
    "hydra": "Hydra", "patator": "Patator",
    "cloud_enum": "Cloud Enum", "s3scanner": "S3Scanner",
    "gcpbucketbrute": "GCPBucketBrute", "scout-suite": "ScoutSuite", "prowler": "Prowler",
    "kube-hunter": "Kube-Hunter", "kube-bench": "Kube-Bench", "kube-score": "Kube-Score",
    "checkov": "Checkov", "terrascan": "Terrascan", "tfsec": "tfsec",
    "kubeaudit": "Kubeaudit", "kube-linter": "Kube-Linter", "kube-no-trouble": "KubeNoTrouble",
    "curl": "curl", "httpie": "HTTPie",
    "va_active_scan": "ARGUS Active Scan", "va_active_scan_tool": "ARGUS Tool Dispatcher",
}


def row_has_docker_or_infra_noise(row: dict[str, str] | None) -> bool:
    if not row:
        return False
    blob = " ".join(
        str(row.get(k) or "")
        for k in ("tool", "status", "note")
    )
    return bool(_DOCKER_NOISE.search(blob))


def sanitize_customer_tool_text(text: str, *, max_len: int = 320) -> str:
    """Remove paths, MinIO/S3 references, and JSON blobs; collapse whitespace."""
    s = (text or "").strip()
    if not s:
        return ""
    s = _WIN_UNIX_PATH.sub("[path]", s)
    s = _MINIO_S3.sub("[storage]", s)
    s = _JSON_BLOB.sub("[structured output omitted]", s)
    s = s.replace("\\\\", "/")
    # Residual long hex / base64-like tokens (common in stderr)
    s = re.sub(r"\b[0-9a-fA-F]{32,}\b", "[token]", s)
    s = re.sub(r"\s+", " ", s).strip()
    if len(s) > max_len:
        s = s[: max_len - 1].rstrip() + "…"
    return s


def _norm_tool_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (name or "").lower())


def _capability_for_tool(tool: str) -> tuple[CapabilityId, str]:
    key = _norm_tool_name(tool)
    for alias, (cid, label) in _CAP_ALIASES.items():
        if alias in key or key in alias:
            return cid, label
    return "other", "Tool execution (general)"


def _display_tool_name(tool: str) -> str:
    key = _norm_tool_name(tool)
    for alias, label in _TOOL_DISPLAY_NAMES.items():
        if alias in key or key in alias:
            return label
    cleaned = re.sub(r"(?i)(?:^|_)(?:scan|tool|va|web_surface|stdout|stderr).*$", "", tool or "")
    cleaned = re.sub(r"[_-]{2,}", "_", cleaned).strip("_- ")
    return sanitize_customer_tool_text(cleaned or tool, max_len=80)


ToolHealthState = Literal[
    "ok",
    "ok_fallback",
    "degraded",
    "parser_error",
    "not_assessed",
    "not_run",
    "skipped",
]

_CAPABILITY_MANDATORY_SECTIONS: dict[CapabilityId, tuple[str, ...]] = {
    "port_discovery": ("port_exposure",),
    "tls_assessment": ("ssl_tls_analysis",),
    "security_headers": ("security_headers_analysis",),
    "email_osint": ("leaked_emails",),
    "sca_dependencies": ("outdated_components",),
    "technology_fingerprinting": ("tech_stack_structured",),
    "web_server_scan": ("security_headers_analysis", "tech_stack_structured"),
}

_SECTION_DISPLAY: dict[str, str] = {
    "tech_stack_structured": "technology stack",
    "ssl_tls_analysis": "TLS assessment",
    "security_headers_analysis": "security headers",
    "leaked_emails": "email exposure",
    "port_exposure": "port exposure",
    "outdated_components": "dependency/SCA",
}

_STATUS_FAILED = frozenset({"failed", "error", "timeout", "cancelled", "canceled", "aborted", "no_output"})
_STATUS_OK = frozenset(
    {
        "success",
        "succeeded",
        "completed",
        "complete",
        "ok",
        "finished",
        "done",
    }
)


@dataclass(frozen=True, slots=True)
class ToolHealthCapabilityRow:
    capability: str
    capability_id: str
    representative_tools: str
    state: ToolHealthState
    customer_summary: str
    tool_commands: str = ""
    tool_versions: str = ""
    artifact_paths: str = ""
    failure_reason: str = ""


def build_tool_health_summary_rows(
    *,
    tool_run_summaries: list[tuple[str, str]] | None,
    appendix_tool_names: list[str] | None,
    raw_error_rows: list[dict[str, str]] | None,
    mandatory_section_status: dict[str, str] | None = None,
    tool_commands: dict[str, str] | None = None,
    tool_versions: dict[str, str] | None = None,
    artifact_paths: dict[str, str] | None = None,
) -> list[ToolHealthCapabilityRow]:
    """Build one row per capability from tool names + run statuses; customer-safe text only (Step 11 enhanced)."""
    by_cap: dict[CapabilityId, dict[str, Any]] = {}
    cmds = tool_commands or {}
    vers = tool_versions or {}
    arts = artifact_paths or {}

    def ensure(cid: CapabilityId, label: str) -> dict[str, Any]:
        if cid not in by_cap:
            by_cap[cid] = {
                "label": label,
                "tools": set(),
                "any_ok": False,
                "any_fail": False,
                "any_fallback": False,
                "commands": [],
                "versions": [],
                "artifacts": [],
                "failure_reasons": [],
            }
        return by_cap[cid]

    name_to_status: dict[str, str] = {}
    if tool_run_summaries:
        for name, st in tool_run_summaries:
            n = (name or "").strip()
            if n:
                name_to_status[n.lower()] = (st or "").strip().lower()

    names: list[str] = list(appendix_tool_names or [])
    for n, _ in (tool_run_summaries or []):
        if n and n.strip():
            names.append(n.strip())
    # Unique preserve order
    seen_n: set[str] = set()
    ordered: list[str] = []
    for n in names:
        k = n.lower()
        if k in seen_n:
            continue
        seen_n.add(k)
        ordered.append(n)

    err_by_tool: dict[str, str] = {}
    for row in raw_error_rows or []:
        t = str(row.get("tool") or "").strip()
        if t:
            err_by_tool[t.lower()] = sanitize_customer_tool_text(
                f"{row.get('status', '')} {row.get('note', '')}"
            )
            cid, label = _capability_for_tool(t)
            bucket = ensure(cid, label)
            bucket["tools"].add(_display_tool_name(t))
            bucket["any_fail"] = True
            fail_note = sanitize_customer_tool_text(str(row.get("note", ""))[:200])
            if fail_note:
                bucket["failure_reasons"].append(fail_note)

    for tool in ordered:
        cid, label = _capability_for_tool(tool)
        bucket = ensure(cid, label)
        bucket["tools"].add(_display_tool_name(tool))
        st = name_to_status.get(tool.lower(), "")
        st_low = (st or "").lower()
        if st_low in _STATUS_OK or (st_low and st_low not in _STATUS_FAILED and "fail" not in st_low):
            bucket["any_ok"] = True
        if st_low in _STATUS_FAILED or "fail" in st_low:
            bucket["any_fail"] = True
        note = err_by_tool.get(tool.lower(), "")
        if note and "stderr" in note.lower() and "empty" in note.lower():
            bucket["any_fallback"] = True
        tool_key = tool.lower()
        if tool_key in cmds:
            bucket["commands"].append(sanitize_customer_tool_text(cmds[tool_key], max_len=200))
        if tool_key in vers:
            bucket["versions"].append(str(vers[tool_key])[:64])
        if tool_key in arts:
            bucket["artifacts"].append(sanitize_customer_tool_text(arts[tool_key], max_len=200))

    rows: list[ToolHealthCapabilityRow] = []
    mandatory = {str(k): str(v or "").strip().lower() for k, v in (mandatory_section_status or {}).items()}
    for cid, data in sorted(by_cap.items(), key=lambda x: (x[1]["label"] or "").lower()):
        label = str(data["label"])
        tools_str = ", ".join(sorted(data["tools"]))[:500]
        if data["any_fail"] and data["any_ok"]:
            state: ToolHealthState = "degraded"
            summary = "Mixed results: at least one tool in this group completed; others failed or returned no data."
        elif data["any_fallback"]:
            state = "ok_fallback"
            summary = "Completed with fallback: output may be partial (stderr only or exit code non-zero while partial data was recovered)."
        elif data["any_fail"] and not data["any_ok"]:
            state = "degraded"
            summary = "Execution did not complete successfully for this capability group; treat related sections as not fully assessed."
        else:
            state = "ok"
            summary = "Tool output available for this capability where applicable; see technical sections for parsed results."

        mapped_sections = _CAPABILITY_MANDATORY_SECTIONS.get(cid, ())
        mapped_statuses = {section: mandatory.get(section, "") for section in mapped_sections}
        if any(status in {"completed_with_fallback", "parsed_from_fallback"} for status in mapped_statuses.values()):
            if state == "ok":
                state = "ok_fallback"
            summary = "Completed with parsed fallback data; see related technical section for evidence and limitations."
        if any(status == "no_observed_items_after_parsing" for status in mapped_statuses.values()):
            if state == "ok":
                summary = "Completed: artifacts were parsed and no relevant observed items were found."
        if any(status in {"not_assessed", "no_data"} for status in mapped_statuses.values()):
            names = ", ".join(
                _SECTION_DISPLAY.get(section, section)
                for section, status in mapped_statuses.items()
                if status in {"not_assessed", "no_data"}
            )
            if data["any_ok"]:
                state = "degraded"
                summary = (
                    "Tool execution metadata indicates completion, but no parsed customer-facing data was "
                    f"produced for {names or 'this capability'}; treat this as inconclusive."
                )
            else:
                state = "not_assessed"
                summary = (
                    "No conclusion can be drawn because the parsed report section"
                    f" for {names or 'this capability'} is not assessed."
                )
        elif any(status == "parser_error" for status in mapped_statuses.values()):
            state = "parser_error"
            summary = "Parser output for this capability is empty or inconsistent despite related artifacts; treat as inconclusive."
        elif any(status == "partial" for status in mapped_statuses.values()):
            state = "degraded"
            summary = "Parsed evidence for this capability is partial; no full-domain conclusion can be drawn."
        elif mapped_statuses and all(status == "not_executed" for status in mapped_statuses.values()):
            state = "not_run"
            summary = "The related assessment domain was not executed for this run."

        rows.append(
            ToolHealthCapabilityRow(
                capability=label,
                capability_id=cid,
                representative_tools=tools_str,
                state=state,
                customer_summary=sanitize_customer_tool_text(summary, max_len=400),
                tool_commands="; ".join(data.get("commands", [])[:3])[:500] or "—",
                tool_versions="; ".join(data.get("versions", [])[:3])[:200] or "—",
                artifact_paths="; ".join(data.get("artifacts", [])[:3])[:500] or "—",
                failure_reason="; ".join(data.get("failure_reasons", [])[:2])[:400] or "—",
            )
        )

    if not rows and (appendix_tool_names or tool_run_summaries):
        rows.append(
            ToolHealthCapabilityRow(
                capability="Tool execution (general)",
                capability_id="other",
                representative_tools="—",
                state="not_run",
                customer_summary="No capability mapping recorded for this run.",
            )
        )
    return rows


def tool_health_rows_to_jinja(
    rows: list[ToolHealthCapabilityRow] | None,
) -> list[dict[str, Any]]:
    if not rows:
        return []
    out: list[dict[str, Any]] = []
    for r in rows:
        state = r.state
        display = {
            "ok": "Completed",
            "ok_fallback": "Completed with fallback",
            "degraded": "Partial / inconclusive",
            "parser_error": "Parser error / inconclusive",
            "not_assessed": "Not assessed",
            "not_run": "Not run",
            "skipped": "Skipped",
        }.get(state, state)
        out.append(
            {
                "capability": r.capability,
                "capability_id": r.capability_id,
                "tools": r.representative_tools,
                "state": state,
                "state_label": display,
                "summary": r.customer_summary,
                "tool_commands": r.tool_commands,
                "tool_versions": r.tool_versions,
                "artifact_paths": r.artifact_paths,
                "failure_reason": r.failure_reason,
            }
        )
    return out


def any_docker_setup_noise_in_tool_rows(rows: list[dict[str, str]] | None) -> bool:
    for row in rows or []:
        if row_has_docker_or_infra_noise(row):
            return True
    return False


def summarize_tool_error_rows_for_internal(rows: list[dict[str, str]] | None) -> list[dict[str, str]]:
    """Copy of rows with sanitized `note` for any customer surface (legacy)."""
    out: list[dict[str, str]] = []
    for row in rows or []:
        out.append(
            {
                "tool": str(row.get("tool") or "")[:200],
                "status": str(row.get("status") or "")[:80],
                "note": sanitize_customer_tool_text(str(row.get("note") or ""), max_len=240),
            }
        )
    return out
