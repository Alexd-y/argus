# ARGUS WhiteRabbitNeo — Repository-to-Architecture Mapping

**Created:** 2026-05-23
**Task:** TRN-002

---

## 1. Tool Catalog Gap Analysis

### 1.1 Tools in Both ARGUS and Repos

| Category | ARGUS tool_id | Repo Source | Notes |
|----------|---------------|-------------|-------|
| **Recon** | nmap_tcp_top, nmap_tcp_full, nmap_udp, nmap_version | Repo 1 (nmap.md), Repo 3 (readme) | Extensive nmap flag coverage in repos |
| **Recon** | subfinder | Repo 1, Repo 6 (common role) | Subdomain enum methodology |
| **Recon** | httpx | Repo 1, Repo 3 | HTTP fingerprinting |
| **Recon** | amass_passive | Repo 1 (amass.md), Repo 6 | Passive subdomain enum |
| **Recon** | gospider | Repo 1 | Web crawling |
| **Recon** | hakrawler | Repo 1 | Subdomain + endpoint crawler |
| **Recon** | katana | — | No direct repo coverage, but similar to gospider |
| **Recon** | feroxbuster | Repo 1 (ffuf.md mentions it), Repo 3 | Dir fuzzing |
| **Recon** | ffuf_dir, ffuf_param, ffuf_vhost | Repo 1 (ffuf.md) | Comprehensive ffuf coverage |
| **Recon** | whatweb | Repo 3 | Tech fingerprinting |
| **Recon** | whois_rdap | — | No direct repo coverage |
| **Recon** | masscan | Repo 3 | Port scanning |
| **Recon** | naabu | — | Similar to nmap, no direct coverage |
| **Recon** | dnsx, dnsrecon | — | DNS enumeration |
| **Recon** | gau, waybackurls | — | URL history |
| **Recon** | wappalyzer_cli, webanalyze | — | Tech detection |
| **Recon** | gowitness, eyewitness | — | Screenshot recon |
| **Recon** | paramspider | — | Parameter mining |
| **Recon** | subjs | — | JS URL discovery |
| **Recon** | linkfinder | — | JS endpoint extraction |
| **Recon** | crt_sh, chaos, findomain | — | Certificate/enumeration |
| **Recon** | shodan_cli, censys, securitytrails, otx_alienvault | — | OSINT sources |
| **Recon** | theharvester | — | OSINT aggregation |
| **Recon** | urlscan | — | URL scan submission |
| **VA** | nuclei | Repo 1 (mentioned), Repo 3 | Template scanner |
| **VA** | nikto | Repo 1, Repo 3 | Web server scanner |
| **VA** | sqlmap_safe, sqlmap_confirm | Repo 1 (sqli.md), Repo 3 | SQL injection |
| **VA** | dalfox | Repo 1 (xss.md), Repo 3 | XSS scanner |
| **VA** | xsstrike | Repo 1 (xss.md) | XSS scanner |
| **VA** | xsser | — | XSS scanner |
| **VA** | wapiti | — | Web vulnerability scanner |
| **VA** | zap_baseline | — | ZAP proxy |
| **VA** | gobuster_dir, gobuster_auth | Repo 3 | Directory brute |
| **VA** | dirsearch | Repo 3 | Directory brute |
| **VA** | arjun | — | Parameter discovery |
| **VA** | ghauri | — | SQLi detector |
| **VA** | wpscan | — | WordPress scanner |
| **VA** | joomscan | — | Joomla scanner |
| **VA** | droopescan | — | CMS scanner |
| **VA** | cmsmap | — | CMS scanner |
| **VA** | magescan | — | Magento scanner |
| **VA** | sslscan, sslyze, testssl | — | TLS scanning |
| **VA** | nmap_vuln | Repo 3 (nmap vuln scripts) | NSE vuln scripts |
| **VA** | ffuf_dir (VA context) | — | Dir fuzzing for VA |
| **VA** | checkov, tfsec, terrascan, kics | — | IaC scanning |
| **VA** | trivy_fs, trivy_image, grype, syft | — | Container/SBOM |
| **VA** | semgrep, bandit | — | SAST |
| **VA** | gitleaks, detect_secrets, trufflehog | — | Secret scanning |
| **VA** | arachni, skipfish, w3af_console | — | Heavy web scanners |
| **Exploit** | hydra | Repo 3 (hydra), Repo 6 (external role) | Credential bruteforce |
| **Exploit** | crackmapexec | Repo 2, Repo 3 | SMB/AD enumeration |
| **Exploit** | medusa | Repo 3 | Credential bruteforce |
| **Exploit** | ncrack | — | Network auth cracker |
| **Exploit** | smbclient | Repo 2, Repo 3 | SMB client |
| **Exploit** | responder | Repo 2 | LLMNR/NBT-NS poisoner |
| **Exploit** | ntlmrelayx | Repo 2 | NTLM relay |
| **Exploit** | kerbrute | Repo 2 (Kerberoasting) | Kerberos enum |
| **Exploit** | impacket_examples | Repo 2 (impacket) | AD exploitation |
| **Exploit** | cloud_metadata_check | — | SSRF probe |
| **Exploit** | sqlmap_confirm | — | SQLi confirmation |
| **Exploit** | patator | — | Multi-module brute |
| **Post-Expl** | hashcat | Repo 1 (password-cracking.md), Repo 2 | Hash cracking |
| **Post-Expl** | john | Repo 1 | Hash cracking |
| **Post-Expl** | evil_winrm | — | WinRM shell |
| **Post-Expl** | bloodhound_python | Repo 2, Repo 3 | AD data collector |
| **Post-Expl** | hashid, hash_analyzer | — | Hash identification |
| **Post-Expl** | impacket_secretsdump | Repo 2 | AD secret extraction |
| **Post-Expl** | ophcrack | — | Rainbow table cracking |

### 1.2 Tools in Repos BUT NOT in ARGUS Catalog (Extension Candidates)

| Tool | Repo | Category | Rationale for Adding |
|------|------|----------|---------------------|
| mimikatz | Repo 2, 3 | post_exploitation | Credential harvesting — critical for AD pentest |
| powerview / PowerView | Repo 2, 3 | post_exploitation | AD enumeration — most used AD tool |
| bloodhound (GUI) | Repo 2, 3 | post_exploitation | AD visualization (we have bloodhound_python CLI) |
| netcat/nc | Repo 2 | exploitation | Reverse shells, file transfer |
| gobuster vhost | Repo 3 | recon | Vhost enum (different from dir mode) |
| impacket-psexec | Repo 2 | exploitation | Remote command execution |
| impacket-wmiexec | Repo 2 | exploitation | WMI remote execution |
| impacket-getTGT | Repo 2 | exploitation | Kerberos ticket management |
| impacket-getUserSPNs | Repo 2 | exploitation | Kerberoasting (we have impacket_examples) |
| certutil | Repo 2 | exploitation | File transfer on Windows |
| powershell_empire | Repo 2 | exploitation | Post-exploitation framework |
| ligolo | Repo 2 | post_exploitation | Pivoting tunneling |
| chisel | Repo 2 | post_exploitation | Tunneling |
| evil-winrm | Repo 2 | post_exploitation | We already have this! ✓ |
| linpeas / winpeas | Repo 2 | post_exploitation | Privesc automated enumeration |
| pspy | Repo 2 | post_exploitation | Process monitoring for privesc |
| burpsuite | Repo 1 (burp.md) | va | Intercepting proxy (heavyweight) |
| metasploit | Repo 4 (awesome-pentest) | exploitation | Multi-paradigm framework |
| arjun | Repo 1 | va | Parameter discovery (already in ARGUS) ✓ |
| jwt_tool | Repo 1 | va | JWT testing — NOT in ARGUS |
| graphql-cop | — | va | GraphQL testing (already in ARGUS) ✓ |
| ferox | Repo 3 | va | Already in ARGUS as feroxbuster ✓ |
| massdns | Repo 3 | recon | Fast DNS resolution |
| sublist3r | Repo 3 | recon | Subdomain enum (similar to subfinder) |
| eyewitness | — | recon | Already in ARGUS ✓ |
| seclists | Repo 6 | recon | Wordlists (infrastructure, not a tool) |
| peass-ng | Repo 2 | post_exploitation | Privesc scripts |
| pth-toolkit | Repo 2 | exploitation | Pass-the-hash |

### 1.3 Tools in ARGUS Catalog NOT Mentioned in Any Repo

| tool_id | Category | Notes |
|---------|----------|-------|
| puppeteer_screens | browser | New in catalog, not in repos |
| playwright_xss_verify | browser | Verification tool, not in repos |
| playwright_runner | browser | General runner, not in repos |
| cookie_probe | browser | Cookie auditor, not in repos |
| cors_probe | browser | CORS tester, not in repos |
| chrome_csp_probe | browser | CSP tester, not in repos |
| graphw00f | web_va | GraphQL fingerprinter |
| clairvoyance | web_va | GraphQL schema recon |
| openapi_scanner | web_va | OpenAPI walker |
| postman_newman | web_va | API collection runner |
| kiterunner | web_va | API route discovery |
| gopherus | web_va | SSRF payload generator |
| nosqlmap | web_va | NoSQL injection |
| tplmap | web_va | SSTI probe |
| jsql | web_va | Java SQLi |
| magescan | web_va | Magento scanner |
| cloudsploit | cloud | Cloud posture |
| dockle | cloud | Container best-practices |
| kube_bench | cloud | CIS Kubernetes benchmark |
| kube_hunter | cloud | Kubernetes attack surface |
| prowler | cloud | AWS posture |
| scoutsuite | cloud | Multi-cloud audit |
| syft | cloud | SBOM generator |
| binwalk | binary | Firmware analysis |
| apktool | binary | Android APK reverse |
| jadx | binary | DEX decompiler |
| mobsf_api | binary | Mobile security |
| radare2_info | binary | Binary triage |
| detect_secrets | misc | Secret scanner |
| gitleaks | misc | Git secret scanner |
| trufflehog | misc | Git secret scanner |
| semgrep | misc | SAST scanner |
| bandit | misc | Python SAST |
| checkov | iac | IaC scanner |
| kics | iac | KICS scanner |
| tfsec | iac | Terraform scanner |
| terrascan | iac | IaC scanner |
| ike_scan | network | IKE scanner |
| onesixtyone | network | SNMP scanner |
| snmp_check | network | SNMP checker |
| oast_dns_probe | oast | OAST DNS probe |
| oastify_client | oast | OAST client |
| interactsh_client | oast | OAST interaction |
| cloud_metadata_check | oast | Cloud SSRF |

---

## 2. Payload Family Coverage Mapping

### Repo 1 → ARGUS Payload Families

| Repo Content | ARGUS Family | Training Value |
|-------------|--------------|----------------|
| XSS methodology | xss, xss_dom, xss_stored, xss_contextual | Full XSS vectors: reflected, DOM, stored, polyglot, filter evasion |
| XSS filter evasion | xss (specifically filter bypass techniques) | Browser-specific evasion, encoding chains |
| SQL injection | sqli, sqli_safe | Boolean, error, UNION, time-based, stacked queries |
| Advanced web exploitation | lfi_rfi, path_traversal, ssrf, rce, auth_bypass | Multi-vectors per vulnerability |
| API security | idor, mass_assignment, cors_misconfig, xxe | OWASP API Top 10 |
| Password cracking | (maps to post_exploitation hash tools) | Hash identification, cracking strategies |
| Reverse shells | rce | Shell generation patterns for multiple languages |

### Repo 2 → ARGUS Payload Families

| Repo Content | ARGUS Family | Training Value |
|-------------|--------------|----------------|
| AD enumeration | auth_bypass, idor | AD-specific auth bypass techniques |
| Credential harvesting | jwt, jwt_none_alg | Token theft and manipulation |
| SMB exploitation | auth_bypass | SMB relay, pass-the-hash |
| Lateral movement | deserialization, xxe | AD-forest lateral movement payloads |
| Privilege escalation | rce, command_injection_safe | Privesc command chains |

### Repo 3 → ARGUS Payload Families

| Repo Content | ARGUS Family | Training Value |
|-------------|--------------|----------------|
| Nmap scanning | (recon tools, not payload families) | Port/service discovery |
| SMB enumeration | auth_bypass | SMB null sessions, share access |
| CrackMapExec | auth_bypass, idor | AD credential validation |
| MSSQL xp_cmdshell | rce | SQL command execution |
| PowerView/BloodHound | (post_exploitation tools) | AD data collection |
| Mimikatz/SAM | jwt, jwt_none_alg | Token/credential theft |

### Repos 4-6 → Indirect payload coverage

| Repo | Value | Family |
|------|-------|--------|
| awesome-pentest | Tool taxonomy, no direct payloads | General tool-knowledge |
| pentest-checklist | Methodology, no direct payloads | Decision-making patterns |
| offensive-kali-ansible | Tool installation, no payloads | Environment knowledge |

---

## 3. Prompt Enhancement Opportunities

### 3.1 Phase Prompt Enrichments

| ARGUS Prompt | Content Source | Enhancement |
|-------------|---------------|------------|
| recon phase | Repo 1 (methodology.md, tips.md), Repo 2 (Recon.md), Repo 3 (readme), Repo 5 (info gathering section) | Expand tool selection rationale, add BBOT methodology, add nmap flag examples |
| threat_modeling phase | Repo 2 (OSINT, Recon), Repo 5 (vulnerability analysis section) | Enrich STRIDE categories with concrete examples |
| vuln_analysis phase | Repo 1 (advanced.md, sqli.md, xss.md), Repo 2 (Exploitation.md, Scanning.md), Repo 3 (service enum) | Add vulnerability-specific verification steps |
| exploitation phase | Repo 1 (xss.md, sqli.md, advanced.md), Repo 2 (Exploitation.md) | Expand tool+payload combination rationale |
| post_exploitation phase | Repo 2 (Lateral Movement, Privilege Escalation, Post-Exploitation), Repo 3 (AD section) | Expand lateral movement and persistence patterns |
| reporting phase | Repo 5 (reporting section) | Add report structure templates |

### 3.2 YAML Agent Prompt Enrichments

| Agent | Content Source | Enhancement |
|-------|---------------|------------|
| planner_v1 | Repo 5 (all checklists), Repo 2 (phase methodology) | More concrete validation strategy selections per vuln type |
| critic_v1 | Repo 5 (pre-engagement, scope definition) | Better scope violation detection patterns |
| verifier_v1 | Repo 1 (BB tips, advanced techniques), Repo 2 (evidence sections) | Better finding classification with evidence thresholds |
| reporter_v1 | Repo 5 (reporting section) | Report section structure and language patterns |
| fixer_v1 | — | No specific repo content needed |

### 3.3 MCP Prompt Enrichments

| MCP Prompt | Content Source | Enhancement |
|-----------|---------------|------------|
| remediation.advisor | Repo 5 (remediation verification) | Concrete remediation steps per vulnerability class |
| vulnerability.explainer | Repo 1 (all technique docs) | Better plain-language vulnerability explanations |
| severity.normalizer | Repo 5 (risk ratings) | More consistent severity mapping examples |

---

## 4. Training Data Extraction Points

### Repo 1: zha0/pentest-playbook

| File | Content Type | Training Task Types | Quality |
|------|-------------|---------------------|---------|
| `web/methodology.md` | Methodology checklist | methodology_checklist, tool_selection | High |
| `web/tips.md` | Bug bounty tips | finding_triage, tool_selection | High |
| `web/xss.md` | XSS vectors and filter evasion | payload_generation (xss families), tool_command_generation | Very High |
| `web/sqli.md` | SQL injection techniques | payload_generation (sqli families), tool_command_generation | Very High |
| `web/advanced.md` | Advanced exploitation | payload_generation (rce, lfi_rfi, ssrf, auth_bypass), attack_chain_summary | Very High |
| `web/api.md` | OWASP API security | payload_generation (idor, mass_assignment, cors_misconfig) | High |
| `pwn/linux-privesc.md` | Linux privesc methodology | attack_chain_summary, methodology_checklist | High |
| `pwn/password-cracking.md` | Hash cracking | tool_command_generation (hashcat, john) | High |
| `pwn/shells.md` | Reverse shells | payload_generation (rce family), tool_command_generation | Very High |
| `tools/nmap.md` | Nmap comprehensive guide | tool_command_generation (nmap_*) | Very High |
| `tools/ffuf.md` | FFUF comprehensive guide | tool_command_generation (ffuf_*) | Very High |
| `tools/burp.md` | Burp Suite usage | tool_selection, methodology | Medium |
| `tools/amass.md` | Amass guide | tool_command_generation (amass_passive) | High |

### Repo 2: dievus/Internal-Pentest-Playbook

| File | Content Type | Training Task Types | Quality |
|------|-------------|---------------------|---------|
| `1 - Kickoff Call.md` | Engagement setup | methodology_checklist, report_section | Medium |
| `2 - OSINT.md` | OSINT methodology | tool_selection, methodology_checklist | High |
| `3 - Recon.md` | Reconnaissance | tool_command_generation, tool_selection | High |
| `4 - Scanning-and-Enumeration.md` | Scanning/enumeration | tool_command_generation, finding_triage | Very High |
| `5 - Exploitation.md` | Exploitation techniques | payload_generation, tool_command_generation, attack_chain_summary | Very High |
| `6 - Lateral-Movement-and-Privilege-Escalation.md` | Lateral movement | attack_chain_summary, payload_generation | Very High |
| `7 - Local-Privilege-Escalation.md` | Local privesc | attack_chain_summary, finding_to_remediation | High |
| `8 - Post-Exploitation-Loot.md` | Post-exploitation | tool_command_generation, finding_triage | High |
| `File-Transfer.md` | File transfer methods | tool_command_generation | Medium |
| `SSH-Pivoting.md` | SSH pivoting | tool_command_generation, methodology_checklist | High |
| `Logging.md` | Logging best practices | methodology_checklist | Medium |

### Repo 3: ag-rodriguez/Penetration-Testing-Playbook

| Section | Content Type | Training Task Types | Quality |
|---------|-------------|---------------------|---------|
| Nmap Discovery Scan | Command examples | tool_command_generation (nmap_*) | Very High |
| Nmap Targeted Scan | Advanced nmap flags | tool_command_generation (nmap_*) | Very High |
| BBOT | Subdomain enumeration | tool_command_generation | High |
| SMB Enumeration | CrackMapExec, smbmap, smbclient | tool_command_generation (smbmap, smbclient, crackmapexec) | Very High |
| HTTP(S) Service Analysis | curl headers | tool_command_generation | Medium |
| Gobuster | Directory brute | tool_command_generation (gobuster_dir) | High |
| FTP | FTP connection patterns | tool_command_generation | Medium |
| SSH | SSH connection | tool_command_generation | Medium |
| RDP | RDP connection | tool_command_generation | Medium |
| MSSQL/MYSQL | Database connection | tool_command_generation (impacket), payload_generation (sqli) | High |
| Active Directory | PowerView, BloodHound | tool_command_generation (bloodhound_python), attack_chain_summary | Very High |
| Credential Harvesting | Mimikatz, SAM | tool_command_generation, payload_generation | High |

### Repos 4-6: Indirect Value

| Repo | Extraction Focus | Training Task Types |
|------|-------------------|---------------------|
| awesome-pentest | Tool taxonomy, categories, descriptions | tool_selection (200+ tool descriptions for LLM to learn from) |
| pentest-checklist | Phase methodology, checklists | methodology_checklist, validation_plan, report_section |
| offensive-kali-ansible | Tool installation, package lists | tool_command_generation (environment setup knowledge) |