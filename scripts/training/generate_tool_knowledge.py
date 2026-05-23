"""
ARGUS WhiteRabbitNeo — Knowledge Base Generator

Generates per-tool YAML files from ARGUS tool descriptors, enriched with
scenarios, next_steps, and related_tools for RAG training.

Creates the directory structure:
  training_data/tool_knowledge/recon/<tool_id>.yaml
  training_data/tool_knowledge/vuln_analysis/<tool_id>.yaml
  training_data/tool_knowledge/exploitation/<tool_id>.yaml
  training_data/tool_knowledge/post_exploitation/<tool_id>.yaml
  training_data/tool_knowledge/cross_phase/<tool_id>.yaml

No sanitization — all real commands and flags preserved.

Usage:
    python scripts/training/generate_tool_knowledge.py --tools-dir backend/config/tools --output-dir training_data/tool_knowledge
"""

import argparse
import sys
from pathlib import Path

import yaml


PHASE_TO_DIR = {
    "recon": "recon",
    "vuln_analysis": "vuln_analysis",
    "exploitation": "exploitation",
    "post_exploitation": "post_exploitation",
    "network": "recon",
    "web_va": "vuln_analysis",
    "web": "vuln_analysis",
    "auth": "exploitation",
    "misc": "cross_phase",
    "iac": "cross_phase",
    "cloud": "cross_phase",
    "binary": "cross_phase",
    "browser": "cross_phase",
    "oast": "cross_phase",
}

SCENARIOS_DB = {
    "nmap_tcp_top": [
        {"description": "Quick port discovery on a single host", "example": "nmap -sS -Pn -T4 --top-ports 1000 -oX /out/nmap_tcp.xml 10.0.0.1", "output_type": "xml_nmap", "next_steps": ["nmap_version on discovered ports", "nmap_udp for UDP services"]},
        {"description": "Scan a subnet for live hosts and open ports", "example": "nmap -sS -Pn -T4 --top-ports 1000 -oX /out/nmap_tcp.xml 10.0.0.0/24", "output_type": "xml_nmap", "next_steps": ["httpx for live host verification", "nmap_version on interesting ports"]},
    ],
    "nmap_tcp_full": [
        {"description": "Full port scan on high-value target", "example": "nmap -sS -Pn -p- -T4 -oX /out/nmap_tcp_full.xml 10.0.0.1", "output_type": "xml_nmap", "next_steps": ["nmap_version on discovered ports"]},
    ],
    "nmap_udp": [
        {"description": "UDP scan for DNS, SNMP, NTP services", "example": "nmap -sU --top-ports 100 -oX /out/nmap_udp.xml 10.0.0.1", "output_type": "xml_nmap", "next_steps": ["snmp_check if SNMP found", "dig for DNS verification"]},
    ],
    "nmap_version": [
        {"description": "Service version detection on discovered ports", "example": "nmap -sV --version-intensity 5 -p 22,80,443,3306,8080 -oX /out/nmap_version.xml 10.0.0.1", "output_type": "xml_nmap", "next_steps": ["nmap_vuln for vulnerability detection"]},
    ],
    "nmap_vuln": [
        {"description": "NSE vulnerability scan on discovered services", "example": "nmap --script=vuln -p 80,443,3306 -oX /out/nmap_vuln.xml 10.0.0.1", "output_type": "xml_nmap", "next_steps": ["nuclei for comprehensive vulnerability scanning"]},
    ],
    "subfinder": [
        {"description": "Passive subdomain enumeration for a domain", "example": "subfinder -d example.com -all -silent -oJ", "output_type": "json_lines", "next_steps": ["httpx for live host verification", "katana for web crawling"]},
    ],
    "httpx": [
        {"description": "HTTP fingerprinting of subdomains from subfinder", "example": "subfinder -d example.com -silent | httpx -silent -title -tech-detect -oJ /out/httpx.json", "output_type": "json_lines", "next_steps": ["nuclei for vulnerability scanning", "ffuf_dir for directory fuzzing"]},
    ],
    "amass_passive": [
        {"description": "Deep passive subdomain enumeration", "example": "amass enum -passive -d example.com -oJ /out/amass.json", "output_type": "json_lines", "next_steps": ["httpx for live host verification"]},
    ],
    "nuclei": [
        {"description": "CVE and vulnerability scanning on discovered URLs", "example": "nuclei -l /in/urls.txt -t cves/ -t vulnerabilities/ -severity critical,high,medium -o /out/nuclei.txt", "output_type": "text", "next_steps": ["dalfox for XSS testing", "sqlmap_safe for SQL injection"]},
    ],
    "sqlmap_safe": [
        {"description": "Conservative SQL injection testing on URL parameter", "example": "sqlmap -u 'https://target.example.com/page?id=1' --batch --level 2 --risk 1 --technique=BT --safe-url=https://target.example.com/ --flush-session --random-agent --timeout=30 --retries=2 --threads=2 --disable-coloring --output-dir=/out/sqlmap", "output_type": "text_lines", "next_steps": ["sqlmap_confirm if injection found", "dalfox for XSS on same parameters"]},
    ],
    "sqlmap_confirm": [
        {"description": "Full SQL injection exploitation after confirmation", "example": "sqlmap -u 'https://target.example.com/page?id=1' --batch --level 3 --risk 2 --technique=BEUSTQ --dbs", "output_type": "text_lines", "next_steps": ["hashcat for credential cracking if hashes found"]},
    ],
    "dalfox": [
        {"description": "XSS scanning with OAST callback", "example": "dalfox url https://target.example.com/search?q=test --mining-dom --mining-dict --deep-domxss --skip-bav --no-color --format json --output /out/dalfox.json --worker 10", "output_type": "json", "next_steps": ["playwright_xss_verify for browser confirmation", "nuclei for additional findings"]},
    ],
    "hydra": [
        {"description": "SSH credential bruteforce", "example": "hydra -L /in/users.txt -P /in/pass.txt -t 4 -I -f -o /out/hydra.txt ssh://10.0.0.1", "output_type": "text", "next_steps": ["evil_winrm for WinRM access", "crackmapexec for SMB validation"]},
    ],
    "crackmapexec": [
        {"description": "SMB credential validation across network", "example": "crackmapexec smb 10.0.0.0/24 -u /in/users.txt -p /in/pass.txt --continue-on-success", "output_type": "text", "next_steps": ["smbmap for share enumeration", "bloodhound_python for AD analysis"]},
    ],
    "hashcat": [
        {"description": "Crack NTLM hashes from credential dump", "example": "hashcat -m 1000 /in/ntlm_hashes.txt /usr/share/seclists/Passwords/rockyou.txt", "output_type": "text", "next_steps": ["crackmapexec for credential validation across network"]},
    ],
    "bloodhound_python": [
        {"description": "Collect AD data for attack path analysis", "example": "bloodhound-python -d domain.local -u admin -p password123 -ns 10.0.0.1 -c All", "output_type": "json", "next_steps": ["ldapsearch for detailed user enumeration"]},
    ],
    "ffuf_dir": [
        {"description": "Directory fuzzing with common extensions", "example": "ffuf -u https://target.example.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,txt -mc 200,301,302,403 -o /out/ffuf_dir.json", "output_type": "json", "next_steps": ["paramspider for parameter discovery", "dalfox for XSS testing"]},
    ],
    "feroxbuster": [
        {"description": "Recursive directory brute-forcing", "example": "feroxbuster -u https://target.example.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x html,php,txt -o /out/ferox.json", "output_type": "json", "next_steps": ["ffuf_param for parameter fuzzing"]},
    ],
    "gobuster_dir": [
        {"description": "Directory enumeration", "example": "gobuster dir -u https://target.example.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,html,txt -o /out/gobuster_dir.txt", "output_type": "text", "next_steps": ["ffuf_param for parameter fuzzing"]},
    ],
    "nikto": [
        {"description": "Web server vulnerability scan", "example": "nikto -h https://target.example.com -o /out/nikto.html -Format htm", "output_type": "html", "next_steps": ["nuclei for deeper vulnerability scanning"]},
    ],
    "masscan": [
        {"description": "Fast port scan of large network range", "example": "masscan -p1-65535 --rate=10000 -oX /out/masscan.xml 10.0.0.0/24", "output_type": "xml", "next_steps": ["nmap_version for service detection on found ports"]},
    ],
    "responder": [
        {"description": "LLMNR/NBT-NS poisoning for credential harvesting", "example": "responder -I eth0 -wrf", "output_type": "text", "next_steps": ["hashcat for cracking captured hashes", "ntlmrelayx for relay attacks"]},
    ],
    "ntlmrelayx": [
        {"description": "NTLM relay attack to SMB", "example": "ntlmrelayx -t smb://10.0.0.1 -smb2support", "output_type": "text", "next_steps": ["impacket_secretsdump for credential extraction"]},
    ],
    "kerbrute": [
        {"description": "Kerberos username enumeration", "example": "kerbrute userenum -d domain.local --dc 10.0.0.1 /in/users.txt", "output_type": "text", "next_steps": ["hydra for password spraying"]},
    ],
    "impacket_examples": [
        {"description": "AD exploitation via Impacket suite", "example": "impacket-psexec domain.local/admin:password123@10.0.0.1", "output_type": "text", "next_steps": ["bloodhound_python for AD topology mapping"]},
    ],
    "impacket_secretsdump": [
        {"description": "Extract secrets from Windows target remotely", "example": "impacket-secretsdump domain.local/admin:password123@10.0.0.1", "output_type": "text", "next_steps": ["hashcat for credential cracking"]},
    ],
    "evil_winrm": [
        {"description": "WinRM shell for post-exploitation", "example": "evil-winrm -i 10.0.0.1 -u admin -p password123", "output_type": "text", "next_steps": ["bloodhound_python for AD data collection"]},
    ],
    "gospider": [
        {"description": "Web crawling for URL and endpoint discovery", "example": "gospider -S /in/urls.txt -d 3 -t 10 -o /out/gospider/", "output_type": "text", "next_steps": ["ffuf_dir for directory fuzzing", "paramspider for parameter mining"]},
    ],
    "katana": [
        {"description": "Modern web crawler with JS parsing", "example": "katana -u https://target.example.com -d 3 -js-crawl -o /out/katana.txt", "output_type": "text", "next_steps": ["ffuf_dir for directory fuzzing", "nuclei for vulnerability scanning"]},
    ],
    "paramspider": [
        {"description": "Parameter mining from wayback/gau data", "example": "paramspider -d example.com -o /out/params.txt", "output_type": "text", "next_steps": ["arjun for hidden parameter discovery", "dalfox for XSS testing"]},
    ],
    "arjun": [
        {"description": "Hidden parameter discovery", "example": "arjun -u https://target.example.com/page -o /out/arjun.json", "output_type": "json", "next_steps": ["sqlmap_safe for injection testing", "dalfox for XSS"]},
    ],
    "sslscan": [
        {"description": "SSL/TLS cipher and certificate analysis", "example": "sslscan target.example.com", "output_type": "text", "next_steps": ["testssl for comprehensive TLS testing"]},
    ],
    "testssl": [
        {"description": "Comprehensive TLS vulnerability testing", "example": "testssl.sh --full --json /out/testssl.json https://target.example.com", "output_type": "json", "next_steps": ["nuclei for additional vulnerability scanning"]},
    ],
    "trivy_image": [
        {"description": "Container image vulnerability scanning", "example": "trivy image --format json --output /out/trivy_image.json nginx:latest", "output_type": "json", "next_steps": ["grype for vulnerability matching", "syft for SBOM generation"]},
    ],
    "semgrep": [
        {"description": "Static analysis for source code vulnerabilities", "example": "semgrep --config=auto /src/", "output_type": "text", "next_steps": ["bandit for Python-specific analysis"]},
    ],
}

RELATED_TOOLS_DB = {
    "nmap_tcp_top": ["nmap_tcp_full", "nmap_udp", "nmap_version", "nmap_vuln", "naabu", "masscan"],
    "nmap_tcp_full": ["nmap_tcp_top", "nmap_version", "nmap_udp"],
    "nmap_udp": ["nmap_tcp_top", "snmp_check", "onesixtyone"],
    "nmap_version": ["nmap_tcp_top", "nmap_vuln", "whatweb"],
    "nmap_vuln": ["nmap_version", "nuclei", "nikto"],
    "subfinder": ["amass_passive", "httpx", "crt_sh", "chaos", "findomain"],
    "httpx": ["subfinder", "amass_passive", "whatweb", "nuclei"],
    "amass_passive": ["subfinder", "httpx"],
    "nuclei": ["httpx", "nikto", "dalfox", "sqlmap_safe"],
    "dalfox": ["xsstrike", "xsser", "playwright_xss_verify", "nuclei"],
    "sqlmap_safe": ["sqlmap_confirm", "ghauri", "dalfox"],
    "sqlmap_confirm": ["sqlmap_safe", "hashcat"],
    "hydra": ["medusa", "ncrack", "crackmapexec"],
    "crackmapexec": ["smbmap", "smbclient", "evil_winrm", "bloodhound_python"],
    "hashcat": ["john", "hashid", "hash_analyzer", "crackmapexec"],
    "bloodhound_python": ["ldapsearch", "enum4linux_ng", "crackmapexec", "kerbrute"],
    "ffuf_dir": ["feroxbuster", "gobuster_dir", "paramspider", "arjun"],
    "feroxbuster": ["ffuf_dir", "ffuf_param", "gobuster_dir"],
    "nikto": ["nuclei", "sslscan", "testssl"],
    "sslscan": ["testssl", "tlsx", "jarm"],
    "testssl": ["sslscan", "nuclei"],
    "gospider": ["katana", "hakrawler", "paramspider"],
    "katana": ["gospider", "hakrawler", "nuclei"],
    "responder": ["ntlmrelayx", "crackmapexec"],
    "ntlmrelayx": ["responder", "impacket_secretsdump"],
    "kerbrute": ["impacket_examples", "crackmapexec", "bloodhound_python"],
    "trivy_image": ["trivy_fs", "grype", "syft", "checkov"],
    "semgrep": ["bandit", "gitleaks", "trivy_fs"],
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
                data["_source_file"] = f.name
                tools.append(data)
        except Exception:
            pass
    return tools


def get_phase_dir(phase: str) -> str:
    return PHASE_TO_DIR.get(phase, "cross_phase")


def generate_tool_yaml(tool: dict) -> dict:
    tool_id = tool.get("tool_id", "")
    phase = tool.get("phase", "recon")
    category = tool.get("category", "")
    risk_level = tool.get("risk_level", "low")
    requires_approval = tool.get("requires_approval", False)
    description = tool.get("description", "")
    command_template = tool.get("command_template", [])
    cwe_hints = tool.get("cwe_hints", [])
    owasp_wstg = tool.get("owasp_wstg", [])
    default_timeout_s = tool.get("default_timeout_s", 600)
    network_policy = tool.get("network_policy", {})
    image = tool.get("image", "")
    evidence_artifacts = tool.get("evidence_artifacts", [])
    parse_strategy = tool.get("parse_strategy", "")

    cmd_parts = []
    for part in command_template:
        if isinstance(part, str) and part.startswith("{") and part.endswith("}"):
            cmd_parts.append(part)
        else:
            cmd_parts.append(str(part))
    command_str = " ".join(cmd_parts)

    placeholders = {}
    for part in command_template:
        if isinstance(part, str) and "{" in part and "}" in part:
            var_name = part.strip("{}")
            if var_name in ("out_dir", "in_dir"):
                placeholders[var_name] = "/tmp/argus/" + tool_id
            elif var_name == "url":
                placeholders[var_name] = "https://target.example.com"
            elif var_name == "ip":
                placeholders[var_name] = "10.10.1.100"
            elif var_name == "host":
                placeholders[var_name] = "target.example.com"
            elif var_name == "port":
                placeholders[var_name] = "443"
            elif var_name == "safe":
                placeholders[var_name] = "https://target.example.com/"
            elif var_name == "target_proto":
                placeholders[var_name] = "ssh"
            else:
                placeholders[var_name] = f"<{var_name}>"

    scenarios = SCENARIOS_DB.get(tool_id, [
        {
            "description": f"Run {tool_id} against target",
            "example": command_str if command_str else f"{tool_id} <target>",
            "output_type": parse_strategy or "text",
            "next_steps": ["Follow up with related ARGUS tools based on findings"],
        }
    ])

    related = RELATED_TOOLS_DB.get(tool_id, [])

    phase_descs = {
        "recon": "Information gathering and discovery phase",
        "vuln_analysis": "Vulnerability identification and analysis phase",
        "exploitation": "Exploitation and credential attack phase",
        "post_exploitation": "Post-exploitation and evidence collection phase",
    }

    return {
        "tool_id": tool_id,
        "version": tool.get("version", "1.0.0"),
        "phase": phase,
        "category": category,
        "risk_level": risk_level,
        "requires_approval": requires_approval,
        "default_timeout_s": default_timeout_s,
        "description": description,
        "command_template": command_template,
        "command_string": command_str,
        "placeholders": placeholders,
        "output_format": parse_strategy,
        "evidence_artifacts": evidence_artifacts,
        "cwe_ids": cwe_hints if isinstance(cwe_hints, list) else [],
        "owasp_wstg": owasp_wstg if isinstance(owasp_wstg, list) else [],
        "image": image,
        "network_policy_name": network_policy.get("name", ""),
        "scenarios": scenarios,
        "related_tools": related,
        "when_to_use": f"{phase_descs.get(phase, 'ARGUS pipeline phase')}. {description[:200]}",
        "key_outputs": evidence_artifacts if evidence_artifacts else ["tool_output"],
        "tips": [f"Start with default flags, then add aggressive options for thorough scanning"],
    }


def main():
    parser = argparse.ArgumentParser(description="Generate per-tool YAML knowledge base from ARGUS tool descriptors")
    parser.add_argument("--tools-dir", type=str, default="backend/config/tools", help="Path to ARGUS tool YAML descriptors")
    parser.add_argument("--output-dir", type=str, default="training_data/tool_knowledge", help="Output directory for per-tool YAML files")
    args = parser.parse_args()

    tools_dir = Path(args.tools_dir)
    output_dir = Path(args.output_dir)

    try:
        import yaml
    except ImportError:
        print("[error] PyYAML required. Install: pip install pyyaml")
        sys.exit(1)

    print("[1/3] Loading ARGUS tool descriptors...")
    tools = load_tool_yamls(tools_dir)
    print(f"  Loaded {len(tools)} tool descriptors")

    phase_dirs = {}
    for phase_name in set(PHASE_TO_DIR.values()):
        phase_dir = output_dir / phase_name
        phase_dir.mkdir(parents=True, exist_ok=True)
        phase_dirs[phase_name] = phase_dir

    print("[2/3] Generating per-tool YAML files...")
    written = 0
    missing_scenarios = 0
    for tool in tools:
        enriched = generate_tool_yaml(tool)
        tool_id = enriched["tool_id"]
        phase = enriched["phase"]
        phase_dir_name = get_phase_dir(phase)
        phase_dir = phase_dirs.get(phase_dir_name, phase_dirs.get("cross_phase"))

        scenarios_list = enriched.get("scenarios", [])
        is_generic = False
        if len(scenarios_list) == 1:
            first_next = scenarios_list[0].get("next_steps", [""])[0] if scenarios_list[0].get("next_steps") else ""
            if "Follow up" in first_next:
                is_generic = True
        if len(scenarios_list) == 0 or is_generic:
            missing_scenarios += 1

        output_file = phase_dir / f"{tool_id}.yaml"
        with open(output_file, "w", encoding="utf-8") as f:
            yaml.dump(enriched, f, default_flow_style=False, allow_unicode=True, sort_keys=False)

        written += 1

    print(f"  Wrote {written} per-tool YAML files")
    print(f"  Tools with auto-generated scenarios (missing specific): {missing_scenarios}")
    print(f"  Tools with known scenarios: {len(SCENARIOS_DB)}")

    print("[3/3] Summary...")
    for phase_name, phase_dir in sorted(phase_dirs.items()):
        count = len(list(phase_dir.glob("*.yaml")))
        print(f"  {phase_name}: {count} tools")

    print(f"\n[done] Per-tool knowledge base written to {output_dir}/")


if __name__ == "__main__":
    main()