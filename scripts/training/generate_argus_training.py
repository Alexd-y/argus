"""
ARGUS WhiteRabbitNeo Training Data — ARGUS-Native Generator

Generates training examples from ARGUS's own tool YAML descriptors,
payload YAML descriptors, and prompt registry. This creates the core
"argus_internal" source training data covering all 10 task types.

No sanitization — all real tool commands, payload templates, and
configuration preserved verbatim.

Usage:
    python scripts/training/generate_argus_training.py --tools-dir backend/config/tools --payloads-dir backend/config/payloads --output training_data/argus_internal.jsonl
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Optional

import yaml


VALID_TASK_TYPES = [
    "tool_command_generation",
    "payload_generation",
    "payload_family_selection",
    "tool_selection",
    "finding_triage",
    "validation_plan",
    "methodology_checklist",
    "finding_to_remediation",
    "attack_chain_summary",
    "report_section",
]

VALID_PHASES = ["recon", "vuln_analysis", "exploitation", "post_exploitation", "cross_phase"]

SYSTEM_PROMPTS = {
    "tool_command_generation": "You are ARGUS Tool Command Expert. You select and configure the correct ARGUS sandbox tool for a given penetration testing task. You know all 157 ARGUS tools, their phases, categories, risk levels, network policies, and command templates. Given a phase, target description, and scope, you output the exact ARGUS tool_id, command arguments, and rationale. Output strict JSON only.",
    "payload_generation": "You are ARGUS Payload Generator. You generate concrete payload variants for ARGUS payload families covering all 54 families (safe, offensive, and approval-gated). Given a vulnerability type, context, and target, you output the family_id, seed payloads with techniques, encoding pipeline, parameters needed, risk level, and whether approval is required. Output strict JSON only.",
    "payload_family_selection": "You are ARGUS Payload Family Selector. Given a vulnerability description, evidence, and context, you select the appropriate ARGUS payload family, determine risk level, approval requirements, OAST needs, and validation strategy. You cover all 54 payload families including offensive variants. Output strict JSON only.",
    "tool_selection": "You are ARGUS Planner. Given a scan phase, findings summary, and target context, you select an ordered list of ARGUS tools to run, with rationale for each selection. You consider dependencies between tools and phase transitions. Output strict JSON only.",
    "finding_triage": "You are ARGUS Local Cybersecurity Analyst. You triage findings from pentest tool output. Given tool output, exit code, stderr, and finding metadata, you assess severity, confidence, and risk. You are conservative: only mark confirmed/exploitable with clear evidence. Output strict JSON only.",
    "validation_plan": "You are ARGUS Planner Agent. Given a finding description, vulnerability type, and target context, you generate a ValidationPlanV1: select the correct ARGUS payload family, tool, and validation strategy. You cover all 54 payload families. Output strict JSON matching ValidationPlanV1 schema.",
    "methodology_checklist": "You are ARGUS Security Analyst. Given a scan phase and target type, you output an ordered penetration testing methodology checklist with specific steps, tool recommendations, and verification criteria. You draw from OWASP WSTG, PTES, and ARGUS pipeline methodology. Output strict JSON only.",
    "finding_to_remediation": "You are ARGUS Remediation Advisor. Given a finding with vulnerability type, severity, affected asset, and evidence, you produce prioritized remediation steps with verification commands. You include defense-in-depth recommendations. Output strict JSON only.",
    "attack_chain_summary": "You are ARGUS Red Team Expert. Given multiple findings from a pentest, you construct realistic attack chains with TTPs (MITRE ATT&CK), showing how vulnerabilities can be chained from initial access to impact. You are specific about techniques and tools. Output strict JSON only.",
    "report_section": "You are ARGUS Reporter. Given scan results, findings, and context, you write a concise, evidence-grounded report section. You never claim findings without evidence. You assign CVSS:3.1 vector strings. You avoid speculation. Output prose matching ARGUS report format.",
}

PHASE_TOOLS = {
    "recon": ["nmap_tcp_top", "nmap_tcp_full", "nmap_udp", "nmap_version", "nmap_vuln",
               "subfinder", "amass_passive", "httpx", "gospider", "katana", "hakrawler",
               "feroxbuster", "ffuf_dir", "ffuf_param", "ffuf_vhost", "gobuster_dir",
               "gobuster_auth", "dirsearch", "whatweb", "wappalyzer_cli", "webanalyze",
               "masscan", "naabu", "rustscan", "dnsx", "dnsrecon", "dig", "host",
               "crt_sh", "chaos", "findomain", "assetfinder", "gau", "waybackurls",
               "paramspider", "arjun", "subjs", "linkfinder", "kiterunner", "openapi_scanner",
               "postman_newman", "shodan_cli", "censys", "securitytrails", "otx_alienvault",
               "theharvester", "urlscan", "gowitness", "eyewitness", "whois", "whois_rdap",
               "nikto", "wpscan", "joomscan", "droopescan", "cmsmap", "magescan",
               "sslscan", "sslyze", "testssl", "tlsx", "jarm", "ssl_enum_ciphers",
               "nuclei", "cloudsploit", "prowler", "scoutsuite", "trivy_image", "trivy_fs",
               "grype", "syft", "checkov", "tfsec", "terrascan", "kics", "semgrep", "bandit",
               "gitleaks", "detect_secrets", "trufflehog", "oast_dns_probe", "oastify_client",
               "interactsh_client"],
    "vuln_analysis": ["sqlmap_safe", "sqlmap_confirm", "dalfox", "xsstrike", "xsser",
                      "nosqlmap", "ghauri", "tplmap", "wapiti", "zap_baseline", "arachni",
                      "skipfish", "w3af_console", "nuclei", "nmap_vuln", "ffuf_dir", "ffuf_param",
                      "ffuf_vhost", "gobuster_dir", "dirsearch", "nikto", "wpscan", "joomscan",
                      "droopescan", "cmsmap", "magescan", "graphql_cop", "graphw00f", "clairvoyance",
                      "inql", "jwt_tool", "spring_boot_actuator", "nextjs_check", "secretfinder",
                      "kxss", "ssrfmap", "gopherus", "wfuzz", "cloud_metadata_check",
                      "oast_dns_probe", "oastify_client"],
    "exploitation": ["hydra", "medusa", "ncrack", "patator", "crackmapexec", "smbmap", "smbclient",
                     "evil_winrm", "ntlmrelayx", "responder", "kerbrute", "impacket_examples",
                     "impacket_secretsdump", "sqlmap_confirm", "cloud_metadata_check", "commix"],
    "post_exploitation": ["hashcat", "john", "hashid", "hash_analyzer", "ophcrack",
                          "bloodhound_python", "rpcclient_enum", "ldapsearch", "enum4linux_ng",
                          "snmp_check", "snmpwalk", "onesixtyone", "ike_scan", "redis_cli_probe",
                          "mongodb_probe", "jenkins_enum", "puppeteer_screens", "playwright_runner",
                          "playwright_xss_verify", "cookie_probe", "cors_probe"],
}

PHASE_TARGET_TYPES = {
    "recon": ["web_app", "internal_network", "api", "cloud", "ad_environment"],
    "vuln_analysis": ["web_app", "api", "cloud"],
    "exploitation": ["web_app", "internal_network", "ad_environment"],
    "post_exploitation": ["web_app", "internal_network", "ad_environment"],
}

TARGET_DESCRIPTIONS = {
    "recon": [
        "external web application with multiple subdomains",
        "internal corporate network with Active Directory",
        "cloud-hosted API with Kubernetes infrastructure",
        "web application behind CDN with API endpoints",
        "external-facing web server with multiple virtual hosts",
        "internal network with Windows domain controllers",
        "SaaS platform with REST API and OAuth2 authentication",
        "e-commerce platform with payment processing",
    ],
    "vuln_analysis": [
        "web application with login form and user input parameters",
        "REST API with JSON endpoints and authentication",
        "WordPress site with plugins and user uploads",
        "internal web application behind authenticating proxy",
        "GraphQL API with introspection enabled",
        "cloud-hosted application with S3 buckets and IAM roles",
    ],
    "exploitation": [
        "SMB service on internal network with null session",
        "Windows domain with cached credentials",
        "web application with confirmed SQL injection",
        "SSH service with weak credentials",
        "Active Directory environment with Kerberos",
        "internal web application with RCE vulnerability",
    ],
    "post_exploitation": [
        "compromised Linux server with lateral movement potential",
        "Windows domain with Domain Admin hash",
        "compromised container with cloud metadata access",
        "internal network with pivot points",
        "compromised host with stored credentials",
    ],
}

FINDING_DESCRIPTIONS = {
    "sqli": "SQL injection vulnerability in login form parameter",
    "xss": "Reflected XSS in search parameter",
    "xss_dom": "DOM-based XSS in JavaScript event handler",
    "xss_stored": "Stored XSS in user profile field",
    "ssrf": "Server-Side Request Forgery in URL parameter",
    "rce": "OS command injection in ping functionality",
    "lfi_rfi": "Local file inclusion in file path parameter",
    "xxe": "XML External Entity injection in XML upload",
    "auth_bypass": "Authentication bypass via JWT manipulation",
    "idor": "Insecure Direct Object Reference in user ID parameter",
    "ssti": "Server-Side Template Injection in template engine",
    "cors_misconfig": "CORS misconfiguration allowing arbitrary origins",
    "deserialization": "Insecure deserialization in Java application",
    "graphql": "GraphQL query depth abuse and introspection leak",
    "jwt_none_alg": "JWT none algorithm attack",
    "nosqli": "NoSQL injection in MongoDB query",
    "path_traversal": "Path traversal in file download endpoint",
    "open_redirect": "Open redirect in logout URL parameter",
    "csrf_token_bypass": "CSRF token bypass via token reuse",
    "http_smuggling": "HTTP request smuggling via CL.TE",
    "prototype_pollution": "Prototype pollution in JavaScript merge function",
    "race_condition": "Race condition in coupon redemption",
    "mass_assignment": "Mass assignment in user registration endpoint",
    "cache_poisoning": "Web cache poisoning via unkeyed header",
    "buffer_overflow": "Buffer overflow in legacy C daemon",
    "type_juggling": "PHP type juggling in comparison function",
    "format_string": "Format string vulnerability in logging function",
    "smtp_injection": "SMTP header injection in contact form",
    "crlf": "CRLF injection in URL redirect parameter",
    "ldap_injection": "LDAP injection in authentication search",
    "xpath_injection": "XPath injection in XML search endpoint",
    "oauth_misconfig": "OAuth2 misconfiguration allowing token theft",
}


def load_yaml_files(directory: Path) -> list[dict]:
    loaded = []
    for f in sorted(directory.glob("*.yaml")):
        try:
            with open(f, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if data:
                data["_source_file"] = f.name
                loaded.append(data)
        except Exception as e:
            print(f"  [warn] Failed to load {f.name}: {e}")
    return loaded


def generate_tool_command_example(tool: dict) -> Optional[dict]:
    tool_id = tool.get("tool_id", "")
    phase = tool.get("phase", "recon")
    description = tool.get("description", "")
    command_template = tool.get("command_template", [])
    risk_level = tool.get("risk_level", "low")
    requires_approval = tool.get("requires_approval", False)
    cwe_hints = tool.get("cwe_hints", [])
    owasp_wstg = tool.get("owasp_wstg", [])
    category = tool.get("category", "")
    cmd_str = " ".join(str(c) for c in command_template)

    placeholders = re.findall(r"\{(\w+)\}", cmd_str)
    args_list = []
    for p in placeholders:
        if p in ("out_dir", "in_dir"):
            args_list.append({"param": p, "value": f"/tmp/argus/{tool_id}", "description": "ARGUS sandbox output directory"})
        elif p == "url":
            args_list.append({"param": p, "value": "https://target.example.com", "description": "Target URL"})
        elif p == "ip":
            args_list.append({"param": p, "value": "10.10.1.100", "description": "Target IP address"})
        elif p == "host":
            args_list.append({"param": p, "value": "target.example.com", "description": "Target hostname"})
        elif p == "port":
            args_list.append({"param": p, "value": "443", "description": "Target port"})
        elif p == "safe":
            args_list.append({"param": p, "value": "https://target.example.com/", "description": "Safe URL for request pacing"})
        elif p == "target_proto":
            args_list.append({"param": p, "value": "ssh", "description": "Target protocol for bruteforce"})
        else:
            args_list.append({"param": p, "value": f"<{p}>", "description": f"Target {p}"})

    target_desc = TARGET_DESCRIPTIONS.get(phase, TARGET_DESCRIPTIONS["recon"])[0]

    user_content = f"Plan ARGUS tool commands for Phase: {phase} on target {target_desc} with scope: {description}.\n\nAvailable tool: {tool_id} ({category}, risk: {risk_level})"

    assistant_content = json.dumps({
        "phase": phase,
        "target": "target.example.com",
        "scope": description[:100],
        "tools": [{
            "tool_id": tool_id,
            "args": args_list,
            "command": cmd_str,
            "rationale": description[:200],
            "risk_level": risk_level,
            "approval_required": requires_approval,
        }],
        "estimated_duration": "5-30 minutes" if phase == "recon" else "10-60 minutes",
        "dependencies": [],
    }, ensure_ascii=False)

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPTS["tool_command_generation"]},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ],
        "metadata": {
            "task": "tool_command_generation",
            "source": "argus_tool_catalog",
            "license": "internal",
            "argus_phase": phase,
            "argus_tool_ids": [tool_id],
            "argus_payload_families": [],
            "cwe_ids": cwe_hints if isinstance(cwe_hints, list) else [],
        },
    }


def generate_payload_example(payload: dict) -> Optional[dict]:
    family_id = payload.get("family_id", "")
    description = payload.get("description", "")
    cwe_ids = payload.get("cwe_ids", [])
    owasp = payload.get("owasp_top10", [])
    risk_level = payload.get("risk_level", "low")
    requires_approval = payload.get("requires_approval", False)
    oast_required = payload.get("oast_required", False)
    seeds = payload.get("payloads", [])
    mutations = payload.get("mutations", [])
    encodings = payload.get("encodings", [])

    safe_suffix = "_safe" if family_id.endswith("_safe") else ""
    is_safe = family_id.endswith("_safe")
    vuln_type = FINDING_DESCRIPTIONS.get(family_id, f"{family_id} vulnerability")

    seeds_output = []
    for s in seeds:
        seeds_output.append({
            "id": s.get("id", ""),
            "template": s.get("template", ""),
            "confidence": s.get("confidence", "suspected"),
            "technique": s.get("notes", ""),
        })

    encoding_names = [e.get("name", "identity") for e in encodings] if encodings else ["identity"]
    pipeline = encoding_names[0] if len(encoding_names) == 1 else "url_only"

    params = set()
    for s in seeds:
        for p in re.findall(r"\{(\w+)\}", s.get("template", "")):
            if p not in ("param",):
                params.add(p)
    params_needed = ["url", "param"] + sorted(params)

    assistant_content = json.dumps({
        "family_id": family_id,
        "seeds": seeds_output,
        "encoding_pipeline": pipeline,
        "parameters_needed": params_needed,
        "risk_level": risk_level,
        "requires_approval": requires_approval,
        "oast_required": oast_required,
        "cwe_ids": cwe_ids if isinstance(cwe_ids, list) else [],
        "owasp": owasp if isinstance(owasp, list) else [],
        "rationale": description[:300] if description else f"{family_id} payload family for {vuln_type}.",
    }, ensure_ascii=False)

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPTS["payload_generation"]},
            {"role": "user", "content": f"Generate payload seeds for the '{family_id}' family targeting a {vuln_type}.\n\nContext: {description}\nCWE: {cwe_ids}\nOWASP: {owasp}"},
            {"role": "assistant", "content": assistant_content},
        ],
        "metadata": {
            "task": "payload_generation",
            "source": "argus_payload_registry",
            "license": "internal",
            "argus_phase": "exploitation" if not is_safe else "vuln_analysis",
            "argus_tool_ids": [],
            "argus_payload_families": [family_id],
            "cwe_ids": cwe_ids if isinstance(cwe_ids, list) else [],
        },
    }


def generate_family_selection_example(payload: dict) -> Optional[dict]:
    family_id = payload.get("family_id", "")
    cwe_ids = payload.get("cwe_ids", [])
    owasp = payload.get("owasp_top10", [])
    risk_level = payload.get("risk_level", "low")
    requires_approval = payload.get("requires_approval", False)
    oast_required = payload.get("oast_required", False)
    description = payload.get("description", "")
    seeds = payload.get("payloads", [])

    vuln_type = FINDING_DESCRIPTIONS.get(family_id, f"{family_id} vulnerability")

    family_base = family_id.replace("_safe", "").replace("_dom", "").replace("_stored", "").replace("_contextual", "")
    if family_base == "xss":
        alt_families = ["xss", "xss_dom", "xss_stored", "xss_contextual"]
    elif family_base == "sqli":
        alt_families = ["sqli", "sqli_safe"]
    elif family_base == "ssrf":
        alt_families = ["ssrf", "ssrf_oast_safe"]
    elif family_base == "jwt":
        alt_families = ["jwt", "jwt_none_alg", "jwt_safe"]
    elif family_base == "xxe":
        alt_families = ["xxe", "xxe_oast_safe"]
    elif family_base == "crlf":
        alt_families = ["crlf", "crlf_safe"]
    elif family_base == "ssti":
        alt_families = ["ssti", "ssti_safe"]
    elif family_base == "ldap":
        alt_families = ["ldapi", "ldapi_safe", "ldap_injection"]
    elif family_base == "xpath":
        alt_families = ["xpath_injection", "xpathi_safe"]
    else:
        alt_families = [family_id]

    strategy_map = {
        "xss": "browser_canary_oast", "xss_dom": "browser_canary_oast",
        "sqli": "database_canary_oast", "ssrf": "oast_callback",
        "rce": "oast_callback", "xxe": "oast_callback",
        "ssti": "template_render_canary", "nosqli": "database_canary",
        "lfi_rfi": "file_read_verification", "auth_bypass": "auth_bypass_verification",
        "idor": "id_enumeration_verification",
    }
    strategy = strategy_map.get(family_base, "oast_callback") if oast_required else "reflection_verification"

    assistant_content = json.dumps({
        "family_id": family_id,
        "alternative_families": [f for f in alt_families if f != family_id],
        "risk_level": risk_level,
        "approval_required": requires_approval,
        "oast_required": oast_required,
        "cwe_ids": cwe_ids if isinstance(cwe_ids, list) else [],
        "owasp": owasp if isinstance(owasp, list) else [],
        "validation_strategy": strategy,
        "payload_count": len(seeds),
        "rationale": description[:200] if description else f"Primary: {family_id} for {vuln_type}.",
    }, ensure_ascii=False)

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPTS["payload_family_selection"]},
            {"role": "user", "content": f"Finding: {vuln_type}\nVulnerability type: {family_id}\nEvidence: Tool output indicates {vuln_type.lower()}\nTarget: web application at target.example.com"},
            {"role": "assistant", "content": assistant_content},
        ],
        "metadata": {
            "task": "payload_family_selection",
            "source": "argus_payload_registry",
            "license": "internal",
            "argus_phase": "vuln_analysis",
            "argus_tool_ids": [],
            "argus_payload_families": [family_id],
            "cwe_ids": cwe_ids if isinstance(cwe_ids, list) else [],
        },
    }


def generate_tool_selection_examples(tools: list[dict]) -> list[dict]:
    records = []
    for phase, phase_tools in PHASE_TOOLS.items():
        target_desc = TARGET_DESCRIPTIONS.get(phase, ["web application"])[0]

        phase_tool_data = [t for t in tools if t.get("tool_id") in phase_tools][:15]

        tool_entries = []
        for t in phase_tool_data:
            tool_entries.append({
                "tool_id": t["tool_id"],
                "priority": len(tool_entries) + 1,
                "rationale": t.get("description", "")[:150],
            })

        if not tool_entries:
            continue

        findings_map = {
            "recon": "Discovered multiple subdomains and open ports. HTTP services identified on ports 80, 443, 8080.",
            "vuln_analysis": "Potential XSS and SQL injection in web forms. Outdated TLS configuration detected.",
            "exploitation": "Confirmed SQL injection in login form. SMB null session access on internal network.",
            "post_exploitation": "Obtained hash values from compromised host. Possible lateral movement via SMB.",
        }

        user_content = (
            f"Phase: {phase}\n"
            f"Findings summary: {findings_map.get(phase, 'Initial reconnaissance phase.')}\n"
            f"Target context: {target_desc}\n\n"
            f"Select the most appropriate ARGUS tools for this phase and findings."
        )

        assistant_content = json.dumps({
            "phase": phase,
            "tools": tool_entries[:8],
            "estimated_duration": "15-45 minutes",
        }, ensure_ascii=False)

        records.append({
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPTS["tool_selection"]},
                {"role": "user", "content": user_content},
                {"role": "assistant", "content": assistant_content},
            ],
            "metadata": {
                "task": "tool_selection",
                "source": "argus_tool_catalog",
                "license": "internal",
                "argus_phase": phase,
                "argus_tool_ids": [t["tool_id"] for t in tool_entries[:8]],
                "argus_payload_families": [],
                "cwe_ids": [],
            },
        })
    return records


def generate_finding_triage_example(tool: dict) -> Optional[dict]:
    tool_id = tool.get("tool_id", "")
    phase = tool.get("phase", "recon")
    category = tool.get("category", "")

    triage_scenarios = {
        "dalfox": {
            "stdout": '[{"type":"Vulnerable","param":"q","payload":"<script>alert(1)</script>","evidence":"reflected in HTML context"}]',
            "exit_code": 0, "title": "XSS in search parameter", "vuln_type": "XSS",
        },
        "sqlmap_safe": {
            "stdout": "sqlmap identified: '1' OR '1'='1' -- appears injectable",
            "exit_code": 0, "title": "SQL injection in user parameter", "vuln_type": "SQLi",
        },
        "nmap_tcp_top": {
            "stdout": "PORT     STATE SERVICE\n22/tcp   open  ssh\n80/tcp   open  http\n443/tcp  open  https\n3306/tcp open  mysql",
            "exit_code": 0, "title": "Open ports discovered", "vuln_type": "Informational",
        },
        "nuclei": {
            "stdout": '[CVE-2021-44228] [http] [high] https://target.example.com - Log4j RCE',
            "exit_code": 0, "title": "Log4Shell vulnerability", "vuln_type": "RCE",
        },
        "nikto": {
            "stdout": "OSVDB-0: Server leaks IPv4 addresses in headers",
            "exit_code": 0, "title": "Information disclosure via headers", "vuln_type": "Info Leak",
        },
        "ffuf_dir": {
            "stdout": "admin                    [Status: 200, Size: 4523]\n.backup                  [Status: 403, Size: 289]",
            "exit_code": 0, "title": "Hidden directory discovered", "vuln_type": "Informational",
        },
        "hydra": {
            "stdout": "[22][ssh] host: 10.10.1.100   login: admin   password: password123",
            "exit_code": 0, "title": "Weak SSH credentials", "vuln_type": "Auth Bypass",
        },
        "crackmapexec": {
            "stdout": "SMB    10.10.1.100    445    DC01    domain.local    [*] Windows Server 2019",
            "exit_code": 0, "title": "SMB domain enumeration", "vuln_type": "Informational",
        },
        "bloodhound_python": {
            "stdout": "Session: admin@domain.local collected 1547 edges, 234 nodes",
            "exit_code": 0, "title": "AD data collection successful", "vuln_type": "Info Collection",
        },
    }

    scenario = triage_scenarios.get(tool_id, {
        "stdout": f"[{tool_id}] Scan completed. Findings detected.",
        "exit_code": 0, "title": f"Finding from {tool_id}", "vuln_type": "Informational",
    })

    severity_map = {
        "RCE": ("confirmed", "high", "high", "strong", "Proceed to exploitation with appropriate payload family"),
        "XSS": ("likely", "medium", "medium", "moderate", "Validate with XSS payload family and OAST callback"),
        "SQLi": ("likely", "high", "high", "strong", "Validate with sqli or sqli_safe payload family"),
        "Auth Bypass": ("confirmed", "high", "high", "strong", "Investigate lateral movement and credential reuse"),
        "Informational": ("suspected", "low", "low", "weak", "Continue scanning for more specific findings"),
        "Info Leak": ("likely", "low", "medium", "moderate", "Remediate information disclosure headers"),
        "Info Collection": ("confirmed", "low", "low", "moderate", "Analyze collected data for attack paths"),
    }
    conf, sev, risk, ev_quality, action = severity_map.get(
        scenario["vuln_type"], ("suspected", "medium", "medium", "moderate", "Continue investigation")
    )

    user_content = (
        f"Tool: {tool_id}\n"
        f"Exit code: {scenario['exit_code']}\n"
        f"Stdout excerpt: {scenario['stdout']}\n"
        f"Stderr excerpt: \n"
        f"Finding title: {scenario['title']}\n"
        f"Vulnerability type: {scenario['vuln_type']}"
    )

    assistant_content = json.dumps({
        "confidence": conf,
        "severity": sev,
        "risk_level": risk,
        "evidence_quality": ev_quality,
        "rationale": f"{tool_id} output indicates {scenario['vuln_type']}. {action}.",
        "recommended_action": action,
    }, ensure_ascii=False)

    cwe_hints = tool.get("cwe_hints", [])
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPTS["finding_triage"]},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ],
        "metadata": {
            "task": "finding_triage",
            "source": "argus_tool_catalog",
            "license": "internal",
            "argus_phase": phase,
            "argus_tool_ids": [tool_id],
            "argus_payload_families": [],
            "cwe_ids": cwe_hints if isinstance(cwe_hints, list) else [],
        },
    }


def generate_validation_plan_example(payload: dict) -> Optional[dict]:
    family_id = payload.get("family_id", "")
    cwe_ids = payload.get("cwe_ids", [])
    risk_level = payload.get("risk_level", "low")
    requires_approval = payload.get("requires_approval", False)
    oast_required = payload.get("oast_required", False)
    seeds = payload.get("payloads", [])

    vuln_type = FINDING_DESCRIPTIONS.get(family_id, f"{family_id} vulnerability")

    tool_map = {
        "sqli": "sqlmap_safe", "sqli_safe": "sqlmap_safe",
        "xss": "dalfox", "xss_dom": "dalfox", "xss_stored": "dalfox", "xss_contextual": "dalfox",
        "ssrf": "ffuf_param", "ssrf_oast_safe": "ffuf_param",
        "rce": "commix", "command_injection_safe": "commix",
        "lfi_rfi": "ffuf_dir", "path_traversal": "ffuf_dir", "traversal_safe": "ffuf_dir",
        "xxe": "nuclei", "xxe_oast_safe": "nuclei",
        "ssti": "tplmap", "ssti_safe": "tplmap",
        "nosqli": "nosqlmap", "nosqli_safe": "nosqlmap",
        "graphql": "graphql_cop", "graphql_safe": "graphw00f",
        "jwt": "jwt_tool", "jwt_none_alg": "jwt_tool", "jwt_safe": "jwt_tool",
        "auth_bypass": "nuclei", "idor": "ffuf_param",
        "cors_misconfig": "cors_probe", "csrf_safe": "nuclei",
        "deserialization": "nuclei", "http_smuggling": "nuclei",
        "ldap_injection": "ldapsearch", "ldapi": "ldapsearch",
        "xpath_injection": "nuclei", "xpathi_safe": "nuclei",
    }
    tool_id = tool_map.get(family_id, "nuclei")

    strategy_map = {
        "oast_callback": ["1. Send canary payload via {tool_id}", "2. Check OAST callback for DNS/HTTP interaction", "3. Verify exploit execution"],
        "browser_canary_oast": ["1. Send canary payload via {tool_id}", "2. Check OAST callback for interaction", "3. Verify XSS execution in browser context"],
        "database_canary": ["1. Inject canary payload via {tool_id}", "2. Observe differential response", "3. Extract data via UNION or error-based technique"],
        "reflection_verification": ["1. Submit canary payload via {tool_id}", "2. Check response body for canary reflection", "3. Verify parameter influence"],
    }

    if oast_required:
        strategy = "oast_callback"
    elif family_id.startswith("xss"):
        strategy = "browser_canary_oast"
    elif family_id in ("sqli", "nosqli"):
        strategy = "database_canary"
    else:
        strategy = "reflection_verification"

    steps = [s.replace("{tool_id}", tool_id) for s in strategy_map.get(strategy, strategy_map["reflection_verification"])]

    user_content = (
        f"Finding: {vuln_type}\n"
        f"Vulnerability type: {family_id}\n"
        f"Severity: {risk_level}\n"
        f"Target: target.example.com\n"
        f"Evidence: Tool output indicates {vuln_type.lower()}"
    )

    assistant_content = json.dumps({
        "plan_id": f"vp-{family_id}",
        "family_id": family_id,
        "tool_id": tool_id,
        "validation_strategy": strategy,
        "hypothesis": f"{vuln_type} confirmed via {strategy} validation",
        "approval_required": requires_approval,
        "payloads": [s.get("template", "") for s in seeds[:3]],
        "verification_steps": steps,
    }, ensure_ascii=False)

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPTS["validation_plan"]},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ],
        "metadata": {
            "task": "validation_plan",
            "source": "argus_payload_registry",
            "license": "internal",
            "argus_phase": "vuln_analysis",
            "argus_tool_ids": [tool_id],
            "argus_payload_families": [family_id],
            "cwe_ids": cwe_ids if isinstance(cwe_ids, list) else [],
        },
    }


def generate_methodology_example(phase: str) -> dict:
    step_templates = {
        "recon": [
            {"order": 1, "action": "Passive subdomain enumeration", "tools": ["subfinder", "amass_passive", "crt_sh"], "verification": "Count discovered subdomains, check for wildcard DNS"},
            {"order": 2, "action": "HTTP fingerprinting of live hosts", "tools": ["httpx"], "verification": "Confirm live web servers, extract titles and status codes"},
            {"order": 3, "action": "Port scanning on discovered hosts", "tools": ["nmap_tcp_top", "nmap_version"], "verification": "Identify open ports and service versions"},
            {"order": 4, "action": "Web technology detection", "tools": ["whatweb", "wappalyzer_cli"], "verification": "Identify frameworks, CMS, and server software"},
            {"order": 5, "action": "Directory and file enumeration", "tools": ["ffuf_dir", "feroxbuster", "gobuster_dir"], "verification": "Discover hidden paths and API endpoints"},
            {"order": 6, "action": "Parameter mining for injection points", "tools": ["paramspider", "arjun"], "verification": "Map all user-controllable input parameters"},
            {"order": 7, "action": "JavaScript endpoint discovery", "tools": ["subjs", "linkfinder"], "verification": "Extract API routes and sensitive paths from JS"},
            {"order": 8, "action": "URL history gathering", "tools": ["gau", "waybackurls"], "verification": "Collect historical URLs for changed endpoints"},
        ],
        "vuln_analysis": [
            {"order": 1, "action": "Automated vulnerability scanning", "tools": ["nuclei", "nikto"], "verification": "Run template-based detection for known CVEs and misconfigurations"},
            {"order": 2, "action": "XSS testing on identified parameters", "tools": ["dalfox", "xsstrike"], "verification": "Confirm reflected/stored/DOM XSS with OAST callbacks"},
            {"order": 3, "action": "SQL injection testing", "tools": ["sqlmap_safe"], "verification": "Confirm SQLi via boolean, error-based, or time-based techniques"},
            {"order": 4, "action": "SSTI/LFI/SSRF testing", "tools": ["tplmap", "ffuf_param", "nuclei"], "verification": "Verify template injection, file inclusion, SSRF vectors"},
            {"order": 5, "action": "Authentication and authorization testing", "tools": ["nuclei", "jwt_tool"], "verification": "Test auth bypass, IDOR, JWT manipulation"},
            {"order": 6, "action": "TLS and header security", "tools": ["sslscan", "testssl"], "verification": "Check for weak ciphers, missing headers, certificate issues"},
        ],
        "exploitation": [
            {"order": 1, "action": "Credential bruteforce on identified services", "tools": ["hydra", "medusa"], "verification": "Identify valid credentials for SSH, HTTP, SMB"},
            {"order": 2, "action": "SMB/AD enumeration and exploitation", "tools": ["crackmapexec", "smbmap", "smbclient"], "verification": "Enumerate shares, test null sessions, extract AD data"},
            {"order": 3, "action": "Confirmed exploit execution", "tools": ["sqlmap_confirm", "ntlmrelayx"], "verification": "Execute confirmed exploits with OAST verification"},
            {"order": 4, "action": "Lateral movement", "tools": ["impacket_examples", "evil_winrm"], "verification": "Move to additional hosts using gained credentials"},
        ],
        "post_exploitation": [
            {"order": 1, "action": "Credential cracking and analysis", "tools": ["hashcat", "john", "hashid"], "verification": "Crack obtained hashes, identify hash types"},
            {"order": 2, "action": "Active Directory data analysis", "tools": ["bloodhound_python"], "verification": "Map attack paths, identify domain admin paths"},
            {"order": 3, "action": "Privilege escalation enumeration", "tools": ["ldapsearch", "enum4linux_ng"], "verification": "Identify misconfigurations enabling privesc"},
            {"order": 4, "action": "Evidence collection and documentation", "tools": ["puppeteer_screens"], "verification": "Screenshot evidence of successful exploitation"},
        ],
    }

    steps = step_templates.get(phase, step_templates["recon"])
    tools_used = list(set(t for s in steps for t in s["tools"]))
    target_types = PHASE_TARGET_TYPES.get(phase, ["web_app"])

    records = []
    for ttype in target_types:
        user_content = (
            f"Phase: {phase}\n"
            f"Target type: {ttype}\n"
            f"Scope: Full penetration test of {ttype} environment\n\n"
            f"Generate an ordered methodology checklist for this phase and target type."
        )

        assistant_content = json.dumps({
            "phase": phase,
            "target_type": ttype,
            "steps": steps,
        }, ensure_ascii=False)

        records.append({
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPTS["methodology_checklist"]},
                {"role": "user", "content": user_content},
                {"role": "assistant", "content": assistant_content},
            ],
            "metadata": {
                "task": "methodology_checklist",
                "source": "argus_internal",
                "license": "internal",
                "argus_phase": phase,
                "argus_tool_ids": tools_used,
                "argus_payload_families": [],
                "cwe_ids": [],
            },
        })
    return records


def generate_remediation_example(payload: dict) -> Optional[dict]:
    family_id = payload.get("family_id", "")
    cwe_ids = payload.get("cwe_ids", [])
    risk_level = payload.get("risk_level", "low")

    vuln_type = FINDING_DESCRIPTIONS.get(family_id, f"{family_id} vulnerability")

    remediation_map = {
        "sqli": [
            {"order": 1, "action": "Use parameterized queries / prepared statements", "detail": "Replace all string concatenation in SQL with parameterized inputs"},
            {"order": 2, "action": "Implement input validation", "detail": "Whitelist allowed characters, reject SQL metacharacters"},
            {"order": 3, "action": "Apply least-privilege database accounts", "detail": "Restrict application DB user to SELECT/INSERT/UPDATE only"},
            {"order": 4, "action": "Deploy WAF rules", "detail": "Add SQLi detection rules as defense-in-depth"},
        ],
        "xss": [
            {"order": 1, "action": "Implement context-aware output encoding", "detail": "HTML-encode for HTML context, JS-escape for script context, CSS-escape for style context"},
            {"order": 2, "action": "Deploy Content Security Policy", "detail": "Set CSP header: default-src 'self'; script-src 'self'"},
            {"order": 3, "action": "Add input sanitization", "detail": "Whitelist allowed characters for user input fields"},
        ],
        "rce": [
            {"order": 1, "action": "Remove OS command execution from application logic", "detail": "Replace shell calls with language-native libraries"},
            {"order": 2, "action": "Implement strict input validation", "detail": "Whitelist allowed characters, reject shell metacharacters (; | & $ `)"},
            {"order": 3, "action": "Run application with minimal privileges", "detail": "Use non-root user, apply container security profiles"},
        ],
        "ssrf": [
            {"order": 1, "action": "Implement URL allowlist", "detail": "Only permit requests to explicitly allowed domains and IPs"},
            {"order": 2, "action": "Block internal network ranges", "detail": "Deny requests to 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 127.x.x.x, 169.254.x.x"},
            {"order": 3, "action": "Disable URL schemes", "detail": "Only allow http:// and https://, block file://, gopher://, dict://"},
        ],
    }

    default_remediation = [
        {"order": 1, "action": "Implement input validation and sanitization", "detail": "Validate all user inputs against strict allowlist patterns"},
        {"order": 2, "action": "Apply defense-in-depth security controls", "detail": "Add security headers, access controls, and monitoring"},
        {"order": 3, "action": "Update affected components", "detail": "Apply security patches to vulnerable software versions"},
    ]

    steps = remediation_map.get(family_id.replace("_safe", "").replace("_dom", "").replace("_stored", "").replace("_contextual", ""), default_remediation)

    cwe_str = ", ".join(f"CWE-{c}" for c in (cwe_ids if isinstance(cwe_ids, list) else []))

    user_content = (
        f"Finding: {vuln_type}\n"
        f"Severity: {risk_level}\n"
        f"CWE: {cwe_str}\n"
        f"Affected asset: target.example.com\n"
        f"Evidence: Tool output confirms {family_id} vulnerability"
    )

    assistant_content = json.dumps({
        "title": vuln_type.capitalize(),
        "severity": risk_level,
        "remediation_steps": steps,
        "verification": f"Re-run appropriate ARGUS payload family ({family_id}) and verify no vulnerability remains",
    }, ensure_ascii=False)

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPTS["finding_to_remediation"]},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ],
        "metadata": {
            "task": "finding_to_remediation",
            "source": "argus_payload_registry",
            "license": "internal",
            "argus_phase": "post_exploitation",
            "argus_tool_ids": [],
            "argus_payload_families": [family_id],
            "cwe_ids": cwe_ids if isinstance(cwe_ids, list) else [],
        },
    }


def generate_attack_chain_example(payloads: list[dict]) -> dict:
    chain_1 = {
        "name": "SQL Injection to Domain Admin",
        "likelihood": "high",
        "steps": [
            {"step": 1, "technique": "T1190", "description": "Exploit SQL injection in login form", "from_finding": "SQLi in authentication endpoint"},
            {"step": 2, "technique": "T1082", "description": "Extract database credentials and internal hostnames", "from_finding": "Database credential extraction via UNION injection"},
            {"step": 3, "technique": "T1075", "description": "Pass-the-hash to domain controller", "from_finding": "Reused credentials between database and AD"},
            {"step": 4, "technique": "T1484", "description": "Domain persistence via GPO modification", "from_finding": "AD misconfiguration allowing GPO edit"},
        ],
        "impact": "Full domain compromise — attacker achieves Domain Admin privileges",
    }

    chain_2 = {
        "name": "XSS to Account Takeover",
        "likelihood": "medium",
        "steps": [
            {"step": 1, "technique": "T1189", "description": "Exploit reflected XSS in search parameter", "from_finding": "Reflected XSS in search functionality"},
            {"step": 2, "technique": "T1539", "description": "Steal session cookie via XSS payload", "from_finding": "Session cookie not marked HttpOnly"},
            {"step": 3, "technique": "T1078", "description": "Session hijack and privilege escalation", "from_finding": "Admin session cookie theft"},
        ],
        "impact": "Account takeover — attacker gains authenticated access as admin user",
    }

    chain_3 = {
        "name": "SSRF to Cloud Metadata",
        "likelihood": "high",
        "steps": [
            {"step": 1, "technique": "T1190", "description": "Exploit SSRF in URL parameter to access cloud metadata", "from_finding": "SSRF in image processing endpoint"},
            {"step": 2, "technique": "T1552", "description": "Extract IAM credentials from cloud metadata service", "from_finding": "Cloud metadata at 169.254.169.254"},
            {"step": 3, "technique": "T1078", "description": "Use IAM credentials to access cloud resources", "from_finding": "Over-privileged IAM role"},
        ],
        "impact": "Cloud environment compromise — attacker accesses S3 buckets, EC2 instances, and potentially cross-account resources",
    }

    user_content = (
        "Findings:\n"
        "1. SQL injection in login form (sqli, CWE-89, high)\n"
        "2. Reflected XSS in search parameter (xss, CWE-79, medium)\n"
        "3. SSRF in image URL parameter (ssrf, CWE-918, medium)\n"
        "4. Weak TLS configuration (CWE-326, low)\n"
        "5. Missing security headers (CWE-693, low)\n"
        "6. SMB null session access (CWE-287, medium)\n\n"
        "Construct realistic attack chains showing TTPs and MITRE ATT&CK techniques."
    )

    assistant_content = json.dumps({
        "chains": [chain_1, chain_2, chain_3],
    }, ensure_ascii=False)

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPTS["attack_chain_summary"]},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ],
        "metadata": {
            "task": "attack_chain_summary",
            "source": "argus_internal",
            "license": "internal",
            "argus_phase": "exploitation",
            "argus_tool_ids": ["sqlmap_safe", "dalfox", "ffuf_param", "nmap_tcp_top"],
            "argus_payload_families": ["sqli", "xss", "ssrf"],
            "cwe_ids": [89, 79, 918, 326, 693, 287],
        },
    }


def generate_report_example() -> dict:
    user_content = (
        "Section: executive_summary\n"
        "Findings: [{\"title\": \"SQL injection in login\", \"severity\": \"high\", \"cwe\": 89}, "
        "{\"title\": \"Reflected XSS in search\", \"severity\": \"medium\", \"cwe\": 79}, "
        "{\"title\": \"Weak TLS configuration\", \"severity\": \"low\", \"cwe\": 326}]\n"
        "Scan context: Web application penetration test for target.example.com, Q1 2026\n\n"
        "Write the report section following ARGUS report format."
    )

    assistant_content = """## Executive Summary

The penetration test of target.example.com identified 3 findings across the target environment. One high-severity SQL injection vulnerability was confirmed in the authentication mechanism, enabling unauthenticated attackers to extract sensitive data from the application database. One medium-severity reflected XSS vulnerability was found in the search functionality, which could be leveraged for session hijacking. One low-severity finding relates to weak TLS configuration with outdated cipher suites.

### Risk Assessment

| Severity | Count | Key Finding |
|----------|-------|-------------|
| High     | 1     | SQL injection (CWE-89) in login form |
| Medium   | 1     | Reflected XSS (CWE-79) in search |
| Low      | 1     | Weak TLS (CWE-326) cipher suites |

All findings are evidence-grounded with tool output verification. No speculative vulnerabilities are reported.

### Immediate Actions Required

1. **SQL Injection (Critical)**: Deploy parameterized queries immediately. This finding allows unauthenticated data extraction.
2. **XSS (Moderate)**: Implement context-aware output encoding and Content Security Policy headers.
3. **TLS (Low)**: Update cipher configuration to reject TLS 1.0/1.1 and weak ciphers."""

    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPTS["report_section"]},
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ],
        "metadata": {
            "task": "report_section",
            "source": "argus_internal",
            "license": "internal",
            "argus_phase": "reporting",
            "argus_tool_ids": [],
            "argus_payload_families": ["sqli", "xss"],
            "cwe_ids": [89, 79, 326],
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Generate ARGUS-native training data")
    parser.add_argument("--tools-dir", type=str, default="backend/config/tools", help="Path to ARGUS tool YAML directory")
    parser.add_argument("--payloads-dir", type=str, default="backend/config/payloads", help="Path to ARGUS payload YAML directory")
    parser.add_argument("--output", type=str, default="training_data/argus_internal.jsonl", help="Output JSONL file")
    args = parser.parse_args()

    tools_dir = Path(args.tools_dir)
    payloads_dir = Path(args.payloads_dir)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        import yaml
    except ImportError:
        print("[error] PyYAML is required. Install with: pip install pyyaml")
        sys.exit(1)

    print("[1/8] Loading ARGUS tool descriptors...")
    tools = load_yaml_files(tools_dir)
    print(f"  Loaded {len(tools)} tool descriptors")

    print("[2/8] Loading ARGUS payload descriptors...")
    payloads = load_yaml_files(payloads_dir)
    print(f"  Loaded {len(payloads)} payload descriptors")

    records = []

    print("[3/8] Generating tool_command_generation examples...")
    for tool in tools:
        rec = generate_tool_command_example(tool)
        if rec:
            records.append(rec)

    print("[4/8] Generating payload_generation examples...")
    for payload in payloads:
        rec = generate_payload_example(payload)
        if rec:
            records.append(rec)

    print("[5/8] Generating payload_family_selection examples...")
    for payload in payloads:
        rec = generate_family_selection_example(payload)
        if rec:
            records.append(rec)

    print("[6/8] Generating tool_selection examples...")
    tool_sel_records = generate_tool_selection_examples(tools)
    records.extend(tool_sel_records)

    print("[7/8] Generating finding_triage, validation_plan, remediation, methodology, attack_chain, report examples...")
    for tool in tools:
        rec = generate_finding_triage_example(tool)
        if rec:
            records.append(rec)

    for payload in payloads:
        rec = generate_validation_plan_example(payload)
        if rec:
            records.append(rec)

    for payload in payloads:
        rec = generate_remediation_example(payload)
        if rec:
            records.append(rec)

    for phase in ["recon", "vuln_analysis", "exploitation", "post_exploitation"]:
        method_records = generate_methodology_example(phase)
        records.extend(method_records)

    records.append(generate_attack_chain_example(payloads))
    records.append(generate_report_example())

    with open(output_path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    task_counts = {}
    for r in records:
        task = r["metadata"]["task"]
        task_counts[task] = task_counts.get(task, 0) + 1

    print(f"\n[done] Wrote {len(records)} records to {output_path}")
    print(f"\nTask type distribution:")
    for task, count in sorted(task_counts.items()):
        print(f"  {task}: {count}")
    print(f"\nTotal: {len(records)} examples")


if __name__ == "__main__":
    main()