"""
ARGUS WhiteRabbitNeo Training Data — Repository Extractor

Clones all 6 pentest repositories and extracts structured content
(markdown, code blocks, command examples) into raw JSONL format.

No sanitization — all original content preserved as-is.

Usage:
    python scripts/training/extract_repos.py --output training_data/raw_repos.jsonl
    python scripts/training/extract_repos.py --output training_data/raw_repos.jsonl --cache-dir .cache/repos
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional


REPOS = [
    {
        "id": "zha0_pentest_playbook",
        "url": "https://github.com/zha0/pentest-playbook.git",
        "source": "zha0/pentest-playbook",
        "license": "MIT",
        "argus_phases": ["recon", "vuln_analysis", "exploitation"],
        "content_globs": ["**/*.md"],
    },
    {
        "id": "dievus_internal_pentest_playbook",
        "url": "https://github.com/dievus/Internal-Pentest-Playbook.git",
        "source": "dievus/Internal-Pentest-Playbook",
        "license": "MIT",
        "argus_phases": ["recon", "exploitation", "post_exploitation"],
        "content_globs": ["**/*.md"],
    },
    {
        "id": "ag_rodriguez_penetration_testing_playbook",
        "url": "https://github.com/ag-rodriguez/Penetration-Testing-Playbook.git",
        "source": "ag-rodriguez/Penetration-Testing-Playbook",
        "license": "MIT",
        "argus_phases": ["recon", "vuln_analysis", "exploitation", "post_exploitation"],
        "content_globs": ["**/*.md", "**/*.sh"],
    },
    {
        "id": "enaqx_awesome_pentest",
        "url": "https://github.com/enaqx/awesome-pentest.git",
        "source": "enaqx/awesome-pentest",
        "license": "CC-BY-4.0",
        "argus_phases": ["cross_phase"],
        "content_globs": ["**/*.md"],
    },
    {
        "id": "ianonymous3000_awesome_pentest_checklist",
        "url": "https://github.com/iAnonymous3000/awesome-pentest-checklist.git",
        "source": "iAnonymous3000/awesome-pentest-checklist",
        "license": "CC-BY-SA-4.0",
        "argus_phases": ["cross_phase"],
        "content_globs": ["**/*.md"],
    },
    {
        "id": "hackedbyagirl_offensive_kali_ansible",
        "url": "https://github.com/hackedbyagirl/offensive-kali-ansible.git",
        "source": "hackedbyagirl/offensive-kali-ansible",
        "license": "AGPL-3.0",
        "argus_phases": ["cross_phase"],
        "content_globs": ["**/*.md", "**/*.yml", "**/*.yaml"],
    },
]

TOOL_KEYWORDS = {
    "nmap": "nmap_tcp_top", "nmap_tcp_full": "nmap_tcp_full", "nmap_tcp": "nmap_tcp_top",
    "nmap_udp": "nmap_udp", "nmap_version": "nmap_version", "nmap_vuln": "nmap_vuln",
    "amass": "amass_passive", "subfinder": "subfinder", "httpx": "httpx",
    "ffuf": "ffuf_dir", "feroxbuster": "feroxbuster", "gobuster": "gobuster_dir",
    "nikto": "nikto", "nuclei": "nuclei", "sqlmap": "sqlmap_safe",
    "dalfox": "dalfox", "xsstrike": "xsstrike", "xsser": "xsser",
    "wapiti": "wapiti", "gospider": "gospider", "katana": "katana",
    "whatweb": "whatweb", "wappalyzer": "wappalyzer_cli", "webanalyze": "webanalyze",
    "masscan": "masscan", "naabu": "naabu", "rustscan": "rustscan",
    "hydra": "hydra", "medusa": "medusa", "ncrack": "ncrack",
    "john": "john", "hashcat": "hashcat", "john the ripper": "john",
    "crackmapexec": "crackmapexec", "smbmap": "smbmap", "smbclient": "smbclient",
    "bloodhound": "bloodhound_python", "evil-winrm": "evil_winrm",
    "dirsearch": "dirsearch", "dnsrecon": "dnsrecon", "dnsx": "dnsx",
    "gau": "gau", "waybackurls": "waybackurls", "paramspider": "paramspider",
    "wpscan": "wpscan", "joomscan": "joomscan", "droopescan": "droopescan",
    "sslscan": "sslscan", "sslyze": "sslyze", "testssl": "testssl",
    "trivy": "trivy_image", "grype": "grype", "syft": "syft",
    "checkov": "checkov", "tfsec": "tfsec", "terrascan": "terrascan",
    "kics": "kics", "semgrep": "semgrep", "bandit": "bandit",
    "gitleaks": "gitleaks", "trufflehog": "trufflehog",
    "zap": "zap_baseline", "arachni": "arachni", "skipfish": "skipfish",
    "w3af": "w3af_console", "responder": "responder", "kerbrute": "kerbrute",
    "impacket": "impacket_examples", "secretsdump": "impacket_secretsdump",
    "ntlmrelayx": "ntlmrelayx", "patator": "patator", "tplmap": "tplmap",
    "nosqlmap": "nosqlmap", "ghauri": "ghauri",
    "burpsuite": None, "burp": None,
    "metasploit": None, "msfconsole": None,
}

PAYLOAD_KEYWORDS = {
    "xss": ["xss", "xss_dom", "xss_stored", "xss_contextual"],
    "sql injection": ["sqli", "sqli_safe", "nosqli", "nosqli_safe"],
    "sqli": ["sqli", "sqli_safe"],
    "nosql": ["nosqli", "nosqli_safe"],
    "ssti": ["ssti", "ssti_safe"],
    "template injection": ["ssti", "ssti_safe"],
    "lfi": ["lfi_rfi", "path_traversal", "traversal_safe"],
    "rfi": ["lfi_rfi"],
    "path traversal": ["path_traversal", "traversal_safe"],
    "command injection": ["rce", "command_injection_safe"],
    "rce": ["rce"],
    "ssrf": ["ssrf", "ssrf_oast_safe"],
    "xxe": ["xxe", "xxe_oast_safe"],
    "deserialization": ["deserialization"],
    "jwt": ["jwt", "jwt_none_alg", "jwt_safe"],
    "oauth": ["oauth", "oauth_misconfig"],
    "csrf": ["csrf_safe", "csrf_token_bypass"],
    "idor": ["idor"],
    "auth bypass": ["auth_bypass"],
    "cors": ["cors_misconfig"],
    "ldap": ["ldapi", "ldapi_safe", "ldap_injection"],
    "xpath": ["xpath_injection", "xpathi_safe"],
    "graphql": ["graphql", "graphql_safe"],
    "race condition": ["race_condition"],
    "http smuggling": ["http_smuggling"],
    "cache poisoning": ["cache_poisoning"],
    "mass assignment": ["mass_assignment", "mass_assignment_safe"],
    "prototype pollution": ["prototype_pollution", "prototype_pollution_safe"],
    "type juggling": ["type_juggling"],
    "buffer overflow": ["buffer_overflow"],
    "format string": ["format_string"],
    "integer overflow": ["integer_overflow"],
    "smtp injection": ["smtp_injection"],
    "crlf": ["crlf", "crlf_safe"],
    "open redirect": ["open_redirect", "open_redirect_safe"],
}


def clone_repo(repo: dict, cache_dir: Path) -> Path:
    repo_dir = cache_dir / repo["id"]
    if repo_dir.exists():
        print(f"  [cache] {repo['id']} already cloned")
        return repo_dir
    print(f"  [clone] {repo['url']}")
    subprocess.run(
        ["git", "clone", "--depth", "1", repo["url"], str(repo_dir)],
        check=True,
        capture_output=True,
    )
    return repo_dir


def extract_markdown_content(file_path: Path) -> dict:
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None

    sections = re.split(r"^#{1,6}\s+", content, flags=re.MULTILINE)

    code_blocks = re.findall(r"```[\w]*\n(.*?)```", content, re.DOTALL)

    commands = []
    for block in code_blocks:
        lines = block.strip().split("\n")
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and not stripped.startswith("//"):
                if any(c in stripped for c in ["-", "--", "/", "|", ";", "$", ">", "<"]):
                    if len(stripped) > 5:
                        commands.append(stripped)

    return {
        "file": str(file_path.name),
        "content": content,
        "sections": [s.strip() for s in sections if s.strip()],
        "code_blocks": code_blocks,
        "commands": commands,
    }


def extract_yaml_content(file_path: Path) -> dict:
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None

    return {
        "file": str(file_path.name),
        "content": content,
        "type": "yaml",
    }


def detect_tools_in_text(text: str) -> list[str]:
    found = []
    text_lower = text.lower()
    for keyword, tool_id in TOOL_KEYWORDS.items():
        if keyword in text_lower and tool_id is not None:
            found.append(tool_id)
    return list(set(found))


def detect_payload_families_in_text(text: str) -> list[str]:
    found = []
    text_lower = text.lower()
    for keyword, families in PAYLOAD_KEYWORDS.items():
        if keyword in text_lower:
            found.extend(families)
    return list(set(found))


def process_repo(repo: dict, cache_dir: Path) -> list[dict]:
    repo_dir = clone_repo(repo, cache_dir)
    records = []

    for glob_pattern in repo["content_globs"]:
        for file_path in repo_dir.glob(glob_pattern):
            if file_path.is_dir():
                continue

            if file_path.suffix == ".md":
                extracted = extract_markdown_content(file_path)
            elif file_path.suffix in (".yml", ".yaml"):
                extracted = extract_yaml_content(file_path)
            else:
                continue

            if extracted is None:
                continue

            content = extracted.get("content", "")
            if len(content.strip()) < 50:
                continue

            tool_ids = detect_tools_in_text(content)
            payload_families = detect_payload_families_in_text(content)

            record = {
                "messages": [
                    {
                        "role": "system",
                        "content": f"ARGUS training data extracted from pentest repository.",
                    },
                    {"role": "user", "content": f"Content from {repo['source']}: {file_path.name}"},
                    {"role": "assistant", "content": content[:8000]},
                ],
                "metadata": {
                    "task": "raw_extraction",
                    "source": repo["source"],
                    "license": repo["license"],
                    "argus_phase": repo["argus_phases"],
                    "argus_tool_ids": tool_ids,
                    "argus_payload_families": payload_families,
                    "cwe_ids": [],
                    "file_path": str(file_path.relative_to(repo_dir)),
                    "file_type": file_path.suffix,
                    "content_length": len(content),
                    "command_count": len(extracted.get("commands", [])),
                    "code_block_count": len(extracted.get("code_blocks", [])),
                },
            }
            records.append(record)

    print(f"  [extract] {repo['id']}: {len(records)} records")
    return records


def main():
    parser = argparse.ArgumentParser(
        description="Extract training data from pentest repositories"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="training_data/raw_repos.jsonl",
        help="Output JSONL file path",
    )
    parser.add_argument(
        "--cache-dir",
        type=str,
        default=".cache/repos",
        help="Directory to cache cloned repos",
    )
    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    cache_dir = Path(args.cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)

    all_records = []

    for repo in REPOS:
        print(f"\n[repo] Processing {repo['source']}...")
        try:
            records = process_repo(repo, cache_dir)
            all_records.extend(records)
        except Exception as e:
            print(f"  [error] Failed to process {repo['source']}: {e}")
            continue

    with open(output_path, "w", encoding="utf-8") as f:
        for record in all_records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"\n[done] Wrote {len(all_records)} records to {output_path}")
    print(f"  Total tool references: {sum(len(r['metadata']['argus_tool_ids']) for r in all_records)}")
    print(f"  Total payload families: {sum(len(r['metadata']['argus_payload_families']) for r in all_records)}")


if __name__ == "__main__":
    main()