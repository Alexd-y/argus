"""
ARGUS WhiteRabbitNeo — Evaluation Benchmark Generator

Generates hand-crafted evaluation examples for all 6 evaluation categories:
  A. Tool Command Accuracy (target: 200)
  B. Payload Family Selection (target: 100)
  C. Offensive Payload Generation (target: 150)
  D. JSON Schema Compliance (target: 500)
  E. Functional Correctness (target: 200)
  F. Consistency (target: 150)

Uses ARGUS tool catalog and payload registry to generate structured examples.

Usage:
    python scripts/training/generate_eval_benchmark.py --tools-dir backend/config/tools --payloads-dir backend/config/payloads --output-dir training_data/eval_benchmark/
"""

import argparse
import json
import random
import sys
from pathlib import Path

import yaml

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

TOOL_TRIAGE = {
    "dalfox": {"stdout": '[{"type":"Vulnerable","param":"q","payload":"<script>alert(1)</script>","evidence":"reflected in HTML context"}]', "title": "XSS in search parameter", "vuln": "XSS", "conf": "likely", "sev": "medium"},
    "sqlmap_safe": {"stdout": "sqlmap identified: parameter 'id' appears to be injectable", "title": "SQL injection in id parameter", "vuln": "SQLi", "conf": "likely", "sev": "high"},
    "nmap_tcp_top": {"stdout": "PORT     STATE SERVICE\n22/tcp   open  ssh\n80/tcp   open  http\n443/tcp  open  https", "title": "Open ports discovered", "vuln": "Informational", "conf": "confirmed", "sev": "low"},
    "nuclei": {"stdout": "[CVE-2021-44228] [http] [high] https://target.example.com", "title": "Log4Shell vulnerability", "vuln": "RCE", "conf": "confirmed", "sev": "high"},
    "nikto": {"stdout": "OSVDB-0: Server leaks IPv4 addresses in headers", "title": "Information disclosure via headers", "vuln": "Info Leak", "conf": "likely", "sev": "low"},
    "ffuf_dir": {"stdout": "admin                    [Status: 200, Size: 4523]\n.backup                  [Status: 403, Size: 289]", "title": "Hidden directory discovered", "vuln": "Informational", "conf": "suspected", "sev": "low"},
    "hydra": {"stdout": "[22][ssh] host: 10.10.1.100   login: admin   password: password123", "title": "Weak SSH credentials", "vuln": "Auth Bypass", "conf": "confirmed", "sev": "high"},
    "crackmapexec": {"stdout": "SMB    10.10.1.100    445    DC01    domain.local    [*] Windows Server 2019", "title": "SMB domain enumeration", "vuln": "Info Collection", "conf": "confirmed", "sev": "low"},
    "sslscan": {"stdout": "TLS 1.0   enabled  (deprecated)\nTLS 1.1   enabled  (deprecated)\nWeak cipher: RC4-SHA", "title": "Weak TLS configuration", "vuln": "Weak TLS", "conf": "confirmed", "sev": "medium"},
    "bloodhound_python": {"stdout": "Session: admin@domain.local collected 1547 edges, 234 nodes", "title": "AD data collection successful", "vuln": "Info Collection", "conf": "confirmed", "sev": "low"},
}

FINDING_DESCRIPTIONS = {
    "sqli": "SQL injection vulnerability in login form parameter",
    "xss": "Reflected XSS in search parameter",
    "xss_dom": "DOM-based XSS in JavaScript event handler",
    "xss_stored": "Stored XSS in user profile field",
    "xss_contextual": "Contextual XSS in attribute value",
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
    "prototype_pollution": "Prototype pollution in JavaScript merge",
    "race_condition": "Race condition in coupon redemption",
    "mass_assignment": "Mass assignment in user registration",
    "cache_poisoning": "Web cache poisoning via unkeyed header",
    "buffer_overflow": "Buffer overflow in legacy C daemon",
    "type_juggling": "PHP type juggling in comparison",
    "format_string": "Format string vulnerability in logging",
    "smtp_injection": "SMTP header injection in contact form",
    "crlf": "CRLF injection in URL redirect",
    "ldap_injection": "LDAP injection in authentication",
    "xpath_injection": "XPath injection in XML search",
    "oauth_misconfig": "OAuth2 misconfiguration allowing token theft",
}

CONTEXT_VARIATIONS = [
    "external web application with multiple subdomains",
    "internal corporate network with Active Directory",
    "cloud-hosted API with Kubernetes infrastructure",
    "web application behind CDN with API endpoints",
    "SaaS platform with REST API and OAuth2 authentication",
    "e-commerce platform with payment processing",
    "WordPress site with plugins and user uploads",
    "internal web application behind authenticating proxy",
    "GraphQL API with introspection enabled",
    "legacy application with outdated stack",
]

TARGET_TYPES = ["web_app", "internal_network", "api", "cloud", "ad_environment"]

TOOL_PHASE_MAP = {
    "recon": ["subfinder", "amass_passive", "httpx", "nmap_tcp_top", "nmap_version", "feroxbuster", "ffuf_dir", "nikto", "nuclei", "whatweb", "gospider", "katana", "masscan", "dnsx", "dnsrecon", "sslscan"],
    "vuln_analysis": ["sqlmap_safe", "dalfox", "nuclei", "nikto", "tplmap", "nosqlmap", "ffuf_param", "graphql_cop", "jwt_tool", "kiterunner", "sslscan", "testssl", "wpscan", "trivy_image", "semgrep"],
    "exploitation": ["hydra", "crackmapexec", "smbmap", "evil_winrm", "responder", "ntlmrelayx", "kerbrute", "impacket_examples", "sqlmap_confirm", "commix"],
    "post_exploitation": ["hashcat", "john", "bloodhound_python", "ldapsearch", "enum4linux_ng", "impacket_secretsdump", "puppeteer_screens"],
}

VALIDATION_TOOL_MAP = {
    "sqli": "sqlmap_safe", "sqli_safe": "sqlmap_safe", "xss": "dalfox", "xss_dom": "dalfox", "xss_stored": "dalfox",
    "ssrf": "ffuf_param", "ssrf_oast_safe": "ffuf_param", "rce": "commix", "command_injection_safe": "commix",
    "lfi_rfi": "ffuf_dir", "xxe": "nuclei", "xxe_oast_safe": "nuclei", "ssti": "tplmap", "nosqli": "nosqlmap",
    "graphql": "graphql_cop", "jwt": "jwt_tool", "auth_bypass": "nuclei", "idor": "ffuf_param",
    "cors_misconfig": "cors_probe", "deserialization": "nuclei", "http_smuggling": "nuclei",
    "open_redirect": "ffuf_param", "path_traversal": "ffuf_dir", "race_condition": "nuclei",
    "mass_assignment": "nuclei", "cache_poisoning": "nuclei", "prototype_pollution": "nuclei",
    "sqli_safe": "sqlmap_safe", "xss_contextual": "dalfox", "nosqli_safe": "nosqlmap",
    "ssti_safe": "tplmap", "graphql_safe": "graphw00f", "jwt_none_alg": "jwt_tool",
    "jwt_safe": "jwt_tool", "ldapi": "ldapsearch", "ldapi_safe": "ldapsearch",
    "xpath_injection": "nuclei", "xpathi_safe": "nuclei", "rce": "commix",
    "buffer_overflow": "nuclei", "format_string": "nuclei", "integer_overflow": "nuclei",
    "type_juggling": "nuclei", "smtp_injection": "nuclei", "crlf": "nuclei",
    "crlf_safe": "nuclei", "traversal_safe": "ffuf_dir", "oauth": "nuclei",
    "oauth_misconfig": "nuclei", "csrf_safe": "nuclei", "csrf_token_bypass": "nuclei",
    "proto_smuggle": "nuclei",
}

FAMILY_ALTS = {
    "xss": ["xss", "xss_dom", "xss_stored", "xss_contextual"], "sqli": ["sqli", "sqli_safe"],
    "ssrf": ["ssrf", "ssrf_oast_safe"], "jwt": ["jwt", "jwt_none_alg", "jwt_safe"],
    "xxe": ["xxe", "xxe_oast_safe"], "crlf": ["crlf", "crlf_safe"], "ssti": ["ssti", "ssti_safe"],
    "ldapi": ["ldapi", "ldapi_safe", "ldap_injection"], "xpath": ["xpath_injection", "xpathi_safe"],
}

REMEDIATION_STEPS = {
    "sqli": "1. Use parameterized queries\n2. Implement input validation\n3. Apply least-privilege database accounts\n4. Deploy WAF rules",
    "xss": "1. Implement context-aware output encoding\n2. Deploy Content Security Policy\n3. Add input sanitization",
    "rce": "1. Remove OS command execution\n2. Implement strict input validation\n3. Run with minimal privileges",
    "ssrf": "1. Implement URL allowlist\n2. Block internal network ranges\n3. Disable unnecessary URL schemes",
    "lfi_rfi": "1. Implement path validation\n2. Use allowlist for permitted files\n3. Disable PHP wrappers",
    "xxe": "1. Disable external entity processing\n2. Disable DTD processing\n3. Use JSON instead of XML",
    "auth_bypass": "1. Implement proper authentication middleware\n2. Validate JWT signatures\n3. Use constant-time token comparison",
    "idor": "1. Implement server-side authorization\n2. Use UUIDs instead of sequential IDs\n3. Validate resource ownership",
    "ssti": "1. Use sandboxed template rendering\n2. Never render user input in templates\n3. Implement input sanitization",
    "cors_misconfig": "1. Set explicit allowed origins\n2. Remove null origin from CORS policy\n3. Validate Origin against allowlist",
}


def load_tool_yamls(tools_dir: Path) -> list[dict]:
    tools = []
    for f in sorted(tools_dir.glob("*.yaml")):
        if f.name == "SIGNATURES":
            continue
        try:
            with open(f, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if data and "tool_id" in data:
                tools.append(data)
        except Exception:
            pass
    return tools


def load_payload_yamls(payloads_dir: Path) -> list[dict]:
    payloads = []
    for f in sorted(payloads_dir.glob("*.yaml")):
        try:
            with open(f, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if data and "family_id" in data:
                payloads.append(data)
        except Exception:
            pass
    return payloads


def gen_tool_cmd_examples(tools, n=200):
    records = []
    phase_tools = {}
    for t in tools:
        phase = t.get("phase", "recon")
        if phase not in phase_tools:
            phase_tools[phase] = []
        phase_tools[phase].append(t)

    for i in range(n):
        phase = random.choice(list(phase_tools.keys()))
        tool = random.choice(phase_tools[phase])
        tool_id = tool.get("tool_id", "")
        cmd = " ".join(str(c) for c in tool.get("command_template", []))
        desc = tool.get("description", "")[:150]
        target = random.choice(CONTEXT_VARIATIONS)

        records.append({
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPTS["tool_command_generation"]},
                {"role": "user", "content": f"Plan ARGUS tool commands for Phase: {phase} on target {target} with scope: {desc}.\n\nAvailable tool: {tool_id} ({tool.get('category', '')}, risk: {tool.get('risk_level', 'low')})"},
                {"role": "assistant", "content": json.dumps({"phase": phase, "target": "target.example.com", "scope": desc[:100], "tools": [{"tool_id": tool_id, "command": cmd, "rationale": desc[:200], "risk_level": tool.get("risk_level", "low"), "approval_required": tool.get("requires_approval", False)}], "estimated_duration": "5-30 minutes"}, ensure_ascii=False)},
            ],
            "metadata": {"task": "tool_command_generation", "source": "eval_benchmark", "license": "internal", "argus_phase": phase, "argus_tool_ids": [tool_id], "argus_payload_families": [], "cwe_ids": tool.get("cwe_hints", []) if isinstance(tool.get("cwe_hints"), list) else []},
        })
    return records


def gen_payload_selection_examples(payloads, n=100):
    records = []
    for i in range(n):
        p = random.choice(payloads)
        fid = p.get("family_id", "")
        desc = FINDING_DESCRIPTIONS.get(fid, f"{fid} vulnerability")
        target = random.choice(CONTEXT_VARIATIONS)
        alts = FAMILY_ALTS.get(fid.replace("_safe", "").replace("_dom", "").replace("_stored", "").replace("_contextual", ""), [fid])
        tool = VALIDATION_TOOL_MAP.get(fid, "nuclei")
        oast = p.get("oast_required", False)
        approval = p.get("requires_approval", False)
        cwe = p.get("cwe_ids", [])
        owasp = p.get("owasp_top10", [])

        records.append({
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPTS["payload_family_selection"]},
                {"role": "user", "content": f"Finding: {desc}\nVulnerability type: {fid}\nEvidence: Tool output indicates {desc.lower()}\nTarget: {target}"},
                {"role": "assistant", "content": json.dumps({"family_id": fid, "alternative_families": [f for f in alts if f != fid], "risk_level": p.get("risk_level", "low"), "approval_required": approval, "oast_required": oast, "cwe_ids": cwe if isinstance(cwe, list) else [], "owasp": owasp if isinstance(owasp, list) else [], "validation_strategy": "oast_callback" if oast else "reflection_verification", "payload_count": len(p.get("payloads", [])), "rationale": f"Primary: {fid} for {desc[:100]}"}, ensure_ascii=False)},
            ],
            "metadata": {"task": "payload_family_selection", "source": "eval_benchmark", "license": "internal", "argus_phase": "vuln_analysis" if fid.endswith("_safe") else "exploitation", "argus_tool_ids": [tool], "argus_payload_families": [fid], "cwe_ids": cwe if isinstance(cwe, list) else []},
        })
    return records


def gen_payload_generation_examples(payloads, n=150):
    records = []
    for i in range(n):
        p = random.choice(payloads)
        fid = p.get("family_id", "")
        desc = FINDING_DESCRIPTIONS.get(fid, f"{fid} vulnerability")
        target = random.choice(CONTEXT_VARIATIONS)
        cwe = p.get("cwe_ids", [])
        owasp = p.get("owasp_top10", [])
        oast = p.get("oast_required", False)
        approval = p.get("requires_approval", False)
        seeds = p.get("payloads", [])
        enc = p.get("encodings", [])
        is_safe = fid.endswith("_safe")

        seeds_out = []
        for s in seeds:
            seeds_out.append({"id": s.get("id", ""), "template": s.get("template", ""), "confidence": s.get("confidence", "suspected"), "technique": s.get("notes", "")})

        records.append({
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPTS["payload_generation"]},
                {"role": "user", "content": f"Generate payload seeds for the '{fid}' family targeting a {desc}.\n\nContext: {desc} in {target}\nCWE: {cwe}\nOWASP: {owasp}"},
                {"role": "assistant", "content": json.dumps({"family_id": fid, "seeds": seeds_out, "encoding_pipeline": enc[0].get("name", "identity") if enc else "identity", "parameters_needed": ["url", "param"] + (["canary"] if oast else []), "risk_level": p.get("risk_level", "low"), "requires_approval": approval, "oast_required": oast, "cwe_ids": cwe if isinstance(cwe, list) else [], "owasp": owasp if isinstance(owasp, list) else [], "rationale": p.get("description", "")[:300] or f"{fid} payload family for {desc}"}, ensure_ascii=False)},
            ],
            "metadata": {"task": "payload_generation", "source": "eval_benchmark", "license": "internal", "argus_phase": "vuln_analysis" if is_safe else "exploitation", "argus_tool_ids": [], "argus_payload_families": [fid], "cwe_ids": cwe if isinstance(cwe, list) else []},
        })
    return records


def gen_json_compliance_examples(payloads, tools, n=500):
    records = gen_tool_cmd_examples(tools, n // 3)
    records += gen_payload_selection_examples(payloads, n // 3)
    records += gen_payload_generation_examples(payloads, n // 3)
    while len(records) < n:
        records.append(random.choice(gen_tool_cmd_examples(tools, 1)))
    return records[:n]


def gen_functional_correctness_examples(payloads, tools, n=200):
    records = gen_tool_cmd_examples(tools, n // 3)
    records += gen_payload_selection_examples(payloads, n // 3)
    records += gen_payload_generation_examples(payloads, n // 3)
    while len(records) < n:
        records.append(random.choice(gen_tool_cmd_examples(tools, 1)))
    return records[:n]


def gen_consistency_examples(payloads, tools, n=150):
    random.seed(42)
    records = gen_payload_selection_examples(payloads, 50)
    records += gen_tool_cmd_examples(tools, 50)
    records += gen_payload_generation_examples(payloads, 50)
    return records


def main():
    parser = argparse.ArgumentParser(description="Generate evaluation benchmark examples")
    parser.add_argument("--tools-dir", type=str, default="backend/config/tools")
    parser.add_argument("--payloads-dir", type=str, default="backend/config/payloads")
    parser.add_argument("--output-dir", type=str, default="training_data/eval_benchmark")
    args = parser.parse_args()

    tools_dir = Path(args.tools_dir)
    payloads_dir = Path(args.payloads_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        import yaml
    except ImportError:
        print("[error] PyYAML required")
        sys.exit(1)

    print("[1/4] Loading catalog data...")
    tools = load_tool_yamls(tools_dir)
    payloads = load_payload_yamls(payloads_dir)
    print(f"  Tools: {len(tools)}, Payloads: {len(payloads)}")

    random.seed(42)

    print("[2/4] Generating evaluation examples...")
    all_records = []

    print("  Category A: Tool Command Accuracy (200 examples)...")
    cat_a = gen_tool_cmd_examples(tools, 200)
    all_records.extend(cat_a)

    print("  Category B: Payload Family Selection (100 examples)...")
    cat_b = gen_payload_selection_examples(payloads, 100)
    all_records.extend(cat_b)

    print("  Category C: Offensive Payload Generation (150 examples)...")
    cat_c = gen_payload_generation_examples(payloads, 150)
    all_records.extend(cat_c)

    print("  Category D: JSON Schema Compliance (500 examples)...")
    cat_d = gen_json_compliance_examples(payloads, tools, 500)
    all_records.extend(cat_d)

    print("  Category E: Functional Correctness (200 examples)...")
    cat_e = gen_functional_correctness_examples(payloads, tools, 200)
    all_records.extend(cat_e)

    print("  Category F: Consistency (150 examples)...")
    cat_f = gen_consistency_examples(payloads, tools, 150)
    all_records.extend(cat_f)

    print(f"\n[3/4] Writing {len(all_records)} examples...")

    for category, records in [("A_tool_command", cat_a), ("B_payload_selection", cat_b), ("C_payload_generation", cat_c), ("D_json_compliance", cat_d), ("E_functional_correctness", cat_e), ("F_consistency", cat_f)]:
        path = output_dir / f"category_{category}.jsonl"
        with open(path, "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        print(f"  {path.name}: {len(records)} records")

    print(f"\n[4/4] Summary")
    print(f"  Total examples: {len(all_records)}")
    print(f"  Category A (Tool Command): {len(cat_a)}")
    print(f"  Category B (Payload Selection): {len(cat_b)}")
    print(f"  Category C (Payload Generation): {len(cat_c)}")
    print(f"  Category D (JSON Compliance): {len(cat_d)}")
    print(f"  Category E (Functional Correctness): {len(cat_e)}")
    print(f"  Category F (Consistency): {len(cat_f)}")
    print(f"\n  Target totals: A=200, B=100, C=150, D=500, E=200, F=150 = 1300")
    print(f"  Generated: {len(cat_a) + len(cat_b) + len(cat_c) + len(cat_d) + len(cat_e) + len(cat_f)}")


if __name__ == "__main__":
    main()