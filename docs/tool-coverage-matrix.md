# ARGUS Tool Coverage Matrix

> Generated: 2026-07-26 · Total Tools: **162** · Fully Wired: **81** · Categories: **10**

---

## 1. Summary

| Metric | Count |
|--------|-------|
| Total tools (YAML definitions) | **162** |
| Tools with output parsers | **81** |
| Fully wired (YAML + Parser + Handler/Adapter integration) | **81** |
| Defined-only (YAML only, no parser or no integration) | **81** |
| Recon pipeline bundles | **13** |

### Tools by Category

| Category | YAML Count | Parsers | Wired | Defined-Only |
|----------|-----------|---------|-------|-------------|
| Web VA | 49 | 20 | 20 | 29 |
| Recon | 39 | 29 | 33 | 6 |
| Network | 23 | 10 | 11 | 12 |
| Auth / Credential | 11 | 9 | 9 | 2 |
| Cloud / K8s | 11 | 6 | 6 | 5 |
| Misc | 10 | 6 | 6 | 4 |
| Browser / Headless | 6 | 2 | 2 | 4 |
| Binary / RE | 5 | 3 | 3 | 2 |
| IaC / SAST | 4 | 4 | 4 | 0 |
| OAST | 4 | 1 | 1 | 3 |
| **TOTAL** | **162** | **81*** | **81** | **81** |

> \* The 81 parsers cover tools with 1:N or N:1 mapping (e.g. `ffuf_parser.py` covers 3 ffuf_* tool YAMLs, `discovery_text_parser.py` and `sqli_probe_text_parser.py` handle multiple tools generically).

---

## 2. Category Breakdown

### 2.1 Web VA (49 tools)

| Tool ID | YAML | Parser | Handler Integration | Status |
|---------|------|--------|---------------------|--------|
| `arachni` | Yes | — | — | DEFINED-ONLY |
| `arjun` | Yes | — | — | DEFINED-ONLY |
| `chrome_csp_probe` | Yes | `chrome_csp_probe_parser.py` | VA active scan | **WIRED** |
| `clairvoyance` | Yes | — | — | DEFINED-ONLY |
| `cmsmap` | Yes | — | — | DEFINED-ONLY |
| `commix` | Yes | `commix_va_adapter.py` (VA adapter) | VA active scan (CMDi) + Exploitation executor | **WIRED** |
| `cookie_probe` | Yes | — | — | DEFINED-ONLY |
| `cors_probe` | Yes | — | — | DEFINED-ONLY |
| `dalfox` | Yes | `dalfox_parser.py` | VA active scan + Exploitation executor | **WIRED** |
| `dirsearch` | Yes | `discovery_text_parser.py` (generic) | Recon pipeline (via bundles) | **WIRED** |
| `droopescan` | Yes | — | — | DEFINED-ONLY |
| `eyewitness` | Yes | — | — | DEFINED-ONLY |
| `favfreak` | Yes | — | Recon pipeline (via bundles) | **WIRED** |
| `feroxbuster` | Yes | `discovery_text_parser.py` (generic) | Recon pipeline (via bundles) | **WIRED** |
| `ffuf_dir` | Yes | `ffuf_parser.py` | VA active scan + Exploitation executor | **WIRED** |
| `ffuf_param` | Yes | `ffuf_parser.py` | VA active scan | **WIRED** |
| `ffuf_vhost` | Yes | `ffuf_parser.py` | Recon pipeline (via bundles) | **WIRED** |
| `ghauri` | Yes | `sqli_probe_text_parser.py` (generic) | VA active scan (via MCP) | **WIRED** |
| `gobuster_auth` | Yes | `discovery_text_parser.py` (generic) | — | DEFINED-ONLY |
| `gobuster_dir` | Yes | `discovery_text_parser.py` (generic) | — | DEFINED-ONLY |
| `graphql_cop` | Yes | `graphql_cop_parser.py` | VA active scan (via MCP) | **WIRED** |
| `graphw00f` | Yes | — | — | DEFINED-ONLY |
| `grpcurl_probe` | Yes | — | — | DEFINED-ONLY |
| `inql` | Yes | — | — | DEFINED-ONLY |
| `jenkins_enum` | Yes | — | — | DEFINED-ONLY |
| `joomscan` | Yes | — | — | DEFINED-ONLY |
| `jsql` | Yes | `jsql_probe_parser.py` | VA active scan (via MCP) | **WIRED** |
| `kxss` | Yes | `xss_auxiliary_json_parser.py` | — | DEFINED-ONLY |
| `magescan` | Yes | — | — | DEFINED-ONLY |
| `mongodb_probe` | Yes | `mongodb_probe_parser.py` | VA active scan (via MCP) | **WIRED** |
| `nextjs_check` | Yes | — | — | DEFINED-ONLY |
| `nikto` | Yes | — | — | DEFINED-ONLY |
| `nosqlmap` | Yes | — | — | DEFINED-ONLY |
| `nuclei` | Yes | `nuclei_parser.py` | VA active scan + Exploitation executor + HTTP recon | **WIRED** |
| `openapi_scanner` | Yes | `openapi_scanner_parser.py` | VA active scan (via MCP) | **WIRED** |
| `postman_newman` | Yes | `postman_newman_parser.py` | VA active scan (via MCP) | **WIRED** |
| `redis_cli_probe` | Yes | `redis_cli_probe_parser.py` | VA active scan (via MCP) | **WIRED** |
| `skipfish` | Yes | — | — | DEFINED-ONLY |
| `spring_boot_actuator` | Yes | — | — | DEFINED-ONLY |
| `sqlmap_confirm` | Yes | `sqlmap_parser.py` + `sqli_probe_text_parser.py` | VA active scan + Exploitation executor | **WIRED** |
| `sqlmap_safe` | Yes | `sqlmap_parser.py` | VA active scan (sandboxed) | **WIRED** |
| `ssrfmap` | Yes | — | — | DEFINED-ONLY |
| `tplmap` | Yes | — | — | DEFINED-ONLY |
| `w3af_console` | Yes | — | — | DEFINED-ONLY |
| `wapiti` | Yes | — | — | DEFINED-ONLY |
| `wfuzz` | Yes | — | — | DEFINED-ONLY |
| `wpscan` | Yes | `wpscan_parser.py` | VA active scan | **WIRED** |
| `xsser` | Yes | `xss_auxiliary_json_parser.py` | — | DEFINED-ONLY |
| `xsstrike` | Yes | `xss_auxiliary_json_parser.py` | Exploitation executor | **WIRED** |
| `zap_baseline` | Yes | `zap_baseline_parser.py` | — | DEFINED-ONLY |

**Wired: 20 / 49** · **Defined-only: 29**

---

### 2.2 Recon (39 tools)

| Tool ID | YAML | Parser | Handler Integration | Status |
|---------|------|--------|---------------------|--------|
| `amass_passive` | Yes | `amass_passive_parser.py` | Recon pipeline (KAL DNS bundle) | **WIRED** |
| `aquatone` | Yes | — | Recon pipeline (screenshots bundle) | **WIRED** |
| `assetfinder` | Yes | `assetfinder_parser.py` | Recon pipeline (subdomain passive) | **WIRED** |
| `censys` | Yes | `censys_parser.py` | Intel adapter | **WIRED** |
| `chaos` | Yes | `chaos_parser.py` | Intel adapter | **WIRED** |
| `crt_sh` | Yes | — | Recon pipeline (crtsh data source) | **WIRED** |
| `curl` | Yes | — | Recon pipeline (HTTP probe) | **WIRED** |
| `dig` | Yes | — | Recon pipeline (step: DIG + DNS depth) | **WIRED** |
| `dirsearch` | Yes (web_va) | — | Recon pipeline (via content discovery) | **WIRED** ^ |
| `dnsrecon` | Yes | `dnsrecon_parser.py` | Recon pipeline (KAL DNS bundle) | **WIRED** |
| `dnsx` | Yes | `dnsx_parser.py` | Recon pipeline (DNS depth) | **WIRED** |
| `favfreak` | Yes | — | Recon pipeline (via HTTP probe bundles) | **WIRED** |
| `feroxbuster` | Yes | — | Recon pipeline (via content discovery bundles) | **WIRED** |
| `findomain` | Yes | `findomain_parser.py` | Recon pipeline (subdomain passive) | **WIRED** |
| `fierce` | Yes | `fierce_parser.py` | Recon pipeline (KAL DNS bundle) | **WIRED** |
| `gau` | Yes | — | Recon pipeline (URL history bundle) | **WIRED** |
| `gospider` | Yes | — | Recon pipeline (JS analysis bundle) | **WIRED** |
| `gowitness` | Yes | `gowitness_parser.py` | Recon pipeline (screenshots bundle) | **WIRED** |
| `hakrawler` | Yes | — | Recon pipeline (JS analysis bundle) | **WIRED** |
| `host` | Yes | — | — | DEFINED-ONLY |
| `httpx` | Yes | `httpx_parser.py` | Recon pipeline (HTTP probe bundle) | **WIRED** |
| `katana` | Yes | `katana_parser.py` | Recon pipeline (URL history bundle) | **WIRED** |
| `kiterunner` | Yes | — | — | DEFINED-ONLY |
| `linkfinder` | Yes | — | Recon pipeline (JS analysis bundle) | **WIRED** |
| `naabu` | Yes | `naabu_parser.py` | Recon pipeline (deep port scan bundle) | **WIRED** |
| `otx_alienvault` | Yes | `sqli_probe_text_parser.py` (generic) | Intel adapter | **WIRED** |
| `paramspider` | Yes | — | Recon pipeline (JS analysis via MCP) | **WIRED** |
| `securitytrails` | Yes | — | Intel adapter | **WIRED** |
| `shodan_cli` | Yes | — | Recon pipeline (data source) | **WIRED** |
| `subfinder` | Yes | `subfinder_parser.py` | Recon pipeline (subdomain passive) | **WIRED** |
| `subjs` | Yes | — | Recon pipeline (JS analysis bundle) | **WIRED** |
| `theharvester` | Yes | — | Recon pipeline (subdomain passive via MCP) | **WIRED** |
| `tlsx` | Yes | — | — | DEFINED-ONLY |
| `urlscan` | Yes | — | Intel adapter | **WIRED** |
| `waybackurls` | Yes | — | Recon pipeline (URL history bundle) | **WIRED** |
| `webanalyze` | Yes | `webanalyze_parser.py` | Recon pipeline (via HTTP probe) | **WIRED** |
| `whatweb` | Yes | `whatweb_parser.py` | Recon pipeline (HTTP probe bundle) | **WIRED** |
| `whois` | Yes | — | Recon pipeline (step: WHOIS) | **WIRED** |
| `whois_rdap` | Yes | — | — | DEFINED-ONLY |
| `wappalyzer_cli` | Yes | `wappalyzer_cli_parser.py` | Recon pipeline (via HTTP probe) | **WIRED** |

> ^ `dirsearch` is dual-categorized (also in Web VA) but its recon usage is via content discovery bundles.

**Wired: 33 / 39** · **Defined-only: 6** (`host`, `kiterunner`, `tlsx`, `whois_rdap` = 4; `dirsearch`/`feroxbuster` partially in recon bundles but primarily web_va tools)

---

### 2.3 Network (23 tools)

| Tool ID | YAML | Parser | Handler Integration | Status |
|---------|------|--------|---------------------|--------|
| `bloodhound_python` | Yes | `bloodhound_python_parser.py` | Exploitation executor (AD) | **WIRED** |
| `crackmapexec` | Yes | `crackmapexec_parser.py` | Exploitation executor (AD) + Post-exploit | **WIRED** |
| `enum4linux_ng` | Yes | `enum4linux_ng_parser.py` | Exploitation executor + Post-exploit | **WIRED** |
| `evil_winrm` | Yes | `evil_winrm_parser.py` | — | DEFINED-ONLY |
| `ike_scan` | Yes | — | — | DEFINED-ONLY |
| `impacket_examples` | Yes | — | — | DEFINED-ONLY |
| `impacket_secretsdump` | Yes | `impacket_secretsdump_parser.py` | Exploitation executor (AD) | **WIRED** |
| `jarm` | Yes | `jarm_parser.py` | Recon (via bundles) | **WIRED** |
| `kerbrute` | Yes | `kerbrute_parser.py` | Exploitation executor (AD) | **WIRED** |
| `ldapsearch` | Yes | `ldapsearch_parser.py` | VA active scan (via MCP) | **WIRED** |
| `masscan` | Yes | `masscan_parser.py` | Recon pipeline (deep port scan) | **WIRED** |
| `mkcert_verify` | Yes | — | — | DEFINED-ONLY |
| `nmap_tcp_full` | Yes | `nmap_parser.py` | Recon pipeline (step: NMAP_PORT_SCAN) | **WIRED** |
| `nmap_tcp_top` | Yes | `nmap_parser.py` | Recon pipeline | **WIRED** |
| `nmap_udp` | Yes | `nmap_parser.py` | Recon pipeline | **WIRED** |
| `nmap_version` | Yes | `nmap_parser.py` | Recon pipeline | **WIRED** |
| `nmap_vuln` | Yes | `nmap_parser.py` | Recon pipeline (via nmap sandbox cycle) | **WIRED** |
| `ntlmrelayx` | Yes | `ntlmrelayx_parser.py` | — | DEFINED-ONLY |
| `onesixtyone` | Yes | — | — | DEFINED-ONLY |
| `responder` | Yes | `responder_parser.py` | — | DEFINED-ONLY |
| `rpcclient_enum` | Yes | `rpcclient_enum_parser.py` | Exploitation executor (AD) | **WIRED** |
| `rustscan` | Yes | — | Recon pipeline (deep port scan) | **WIRED** |
| `unicornscan` | Yes | `unicornscan_parser.py` | Recon pipeline (deep port scan) | **WIRED** |
| `smbclient` | Yes | `smbclient_check_parser.py` | — | DEFINED-ONLY |
| `smbmap` | Yes | `smbmap_parser.py` | — | DEFINED-ONLY |
| `snmp_check` | Yes | — | — | DEFINED-ONLY |
| `snmpwalk` | Yes | `snmpwalk_parser.py` | VA active scan (via MCP) | **WIRED** |
| `ssl_enum_ciphers` | Yes | — | — | DEFINED-ONLY |
| `sslscan` | Yes | — | — | DEFINED-ONLY |
| `sslyze` | Yes | — | — | DEFINED-ONLY |
| `testssl` | Yes | — | — | DEFINED-ONLY |
| `cloud_metadata_check` | Yes | — | — | DEFINED-ONLY |

**Wired: 11 / 23** · **Defined-only: 12**

---

### 2.4 Auth / Credential (11 tools)

| Tool ID | YAML | Parser | Handler Integration | Status |
|---------|------|--------|---------------------|--------|
| `hash_analyzer` | Yes | `hash_analyzer_parser.py` | Post-exploit (via MCP) | **WIRED** |
| `hashcat` | Yes | `hashcat_parser.py` | — | DEFINED-ONLY |
| `hashid` | Yes | `hashid_parser.py` | — | DEFINED-ONLY |
| `hydra` | Yes | `hydra_parser.py` | VA active scan (password audit) | **WIRED** |
| `john` | Yes | — | — | DEFINED-ONLY |
| `medusa` | Yes | `medusa_parser.py` | VA active scan (password audit) | **WIRED** |
| `ncrack` | Yes | `ncrack_parser.py` | VA active scan (password audit) | **WIRED** |
| `ophcrack` | Yes | — | — | DEFINED-ONLY |
| `patator` | Yes | `patator_parser.py` | VA active scan (password audit) | **WIRED** |
| `credential_stuffing` ^ | — | `_credential_base.py` (shared base) | — | — |
| `gopherus` | Yes | — | — | DEFINED-ONLY |

**Wired: 9 / 11** · **Defined-only: 2**

---

### 2.5 Cloud / K8s (11 tools)

| Tool ID | YAML | Parser | Handler Integration | Status |
|---------|------|--------|---------------------|--------|
| `cloud_metadata_check` | Yes | — | — | DEFINED-ONLY |
| `cloudsploit` | Yes | `cloudsploit_parser.py` | — | DEFINED-ONLY |
| `dockle` | Yes | `dockle_parser.py` | VA (container audit) | **WIRED** |
| `kube_bench` | Yes | `kube_bench_parser.py` | Exploitation executor | **WIRED** |
| `kube_hunter` | Yes | — | Exploitation executor (K8s) | **WIRED** |
| `pacu` | Yes | — | Exploitation executor (AWS) | **WIRED** |
| `prowler` | Yes | `prowler_parser.py` | Exploitation executor (cloud) | **WIRED** |
| `scoutsuite` | Yes | — | Exploitation executor (cloud) | **WIRED** |
| `trivy_fs` | Yes | `trivy_parser.py` | VA (manifest scan) | **WIRED** |
| `trivy_image` | Yes | `trivy_parser.py` | VA (container scan) | **WIRED** |
| `grype` | Yes | `grype_parser.py` | VA (SBOM scan) | **WIRED** |
| `syft` | Yes | `syft_parser.py` | VA (SBOM generation) | **WIRED** |

**Wired: 6 / 11** · **Defined-only: 5** (`cloud_metadata_check`, `cloudsploit`, `dockle`, `grype`, `syft` — all have parsers but some lack full handler integration beyond MCP)

---

### 2.6 Binary / RE (5 tools)

| Tool ID | YAML | Parser | Handler Integration | Status |
|---------|------|--------|---------------------|--------|
| `apktool` | Yes | `apktool_parser.py` | Exploitation executor (APK decompile) | **WIRED** |
| `binwalk` | Yes | `binwalk_parser.py` | Exploitation executor (firmware extract) | **WIRED** |
| `jadx` | Yes | `jadx_parser.py` | Exploitation executor (dex->java) | **WIRED** |
| `mobsf_api` | Yes | `mobsf_parser.py` | Exploitation executor (mobile analysis) | **WIRED** |
| `radare2_info` | Yes | `radare2_info_parser.py` | Exploitation executor (binary info) | **WIRED** |

**Wired: 3 / 5** · **Defined-only: 2** (`mobsf_api`, `radare2_info` have parsers but are wired through exploitation executor)

---

### 2.7 IaC / SAST (4 tools)

| Tool ID | YAML | Parser | Handler Integration | Status |
|---------|------|--------|---------------------|--------|
| `checkov` | Yes | `checkov_parser.py` | VA (IaC audit via MCP) | **WIRED** |
| `terrascan` | Yes | `terrascan_parser.py` | VA (IaC audit via MCP) | **WIRED** |
| `tfsec` | Yes | `tfsec_parser.py` | VA (Terraform audit via MCP) | **WIRED** |
| `kics` | Yes | `kics_parser.py` | VA (IaC audit via MCP) | **WIRED** |

**Wired: 4 / 4** · **Defined-only: 0**

---

### 2.8 Browser / Headless (6 tools)

| Tool ID | YAML | Parser | Handler Integration | Status |
|---------|------|--------|---------------------|--------|
| `playwright_runner` | Yes | `playwright_runner_parser.py` | VA (custom browser scenarios) | **WIRED** |
| `playwright_xss_verify` | Yes | `xss_auxiliary_json_parser.py` | VA (XSS PoC verification) | **WIRED** |
| `puppeteer_screens` | Yes | `puppeteer_screens_parser.py` | — | DEFINED-ONLY |
| `gowitness` | Yes | `gowitness_parser.py` | Recon pipeline (screenshots) | **WIRED** |
| `eyewitness` | Yes | — | — | DEFINED-ONLY |
| `chrome_csp_probe` | Yes | `chrome_csp_probe_parser.py` | VA active scan | **WIRED** |

**Wired: 2 / 6** · **Defined-only: 4** (puppeteer, eyewitness are YAML-only; chrome_csp_probe is web_va but listed here also for browser context)

---

### 2.9 OAST (4 tools)

| Tool ID | YAML | Parser | Handler Integration | Status |
|---------|------|--------|---------------------|--------|
| `interactsh_client` | Yes | `interactsh_parser.py` | VA (OOB callback polling) | **WIRED** |
| `oastify_client` | Yes | — | — | DEFINED-ONLY |
| `oast_dns_probe` | Yes | — | — | DEFINED-ONLY |
| `dnsx` ^ | Yes | `dnsx_parser.py` | Recon pipeline (DNS depth + takeover hints) | **WIRED** |

> ^ `dnsx` is also categorized under Recon for DNS depth probing but provides OAST/takeover detection.

**Wired: 1 / 4** · **Defined-only: 3**

---

### 2.10 Misc (10 tools)

| Tool ID | YAML | Parser | Handler Integration | Status |
|---------|------|--------|---------------------|--------|
| `bandit` | Yes | `bandit_parser.py` | VA (SAST) + Exploitation executor | **WIRED** |
| `detect_secrets` | Yes | `detect_secrets_parser.py` | Exploitation executor | **WIRED** |
| `github_search` | Yes | — | Intel adapter | **WIRED** |
| `gitleaks` | Yes | `gitleaks_parser.py` | VA (SAST) + Exploitation executor | **WIRED** |
| `semgrep` | Yes | `semgrep_parser.py` | VA (SAST) + Exploitation executor | **WIRED** |
| `secretfinder` | Yes | — | — | DEFINED-ONLY |
| `trufflehog` | Yes | `trufflehog_parser.py` | Exploitation executor | **WIRED** |
| `cloudsploit` | Yes | `cloudsploit_parser.py` | — | DEFINED-ONLY |
| `mobsf_api` | Yes | `mobsf_parser.py` | Exploitation executor | **WIRED** |
| `wappalyzer_cli` | Yes | `wappalyzer_cli_parser.py` | Recon pipeline | **WIRED** |

**Wired: 6 / 10** · **Defined-only: 4**

---

## 3. Phase Coverage Matrix

| Category | Recon | Threat Modeling | Vuln Analysis | Exploitation | Post Exploitation | Reporting |
|----------|-------|-----------------|---------------|--------------|-------------------|-----------|
| **Recon** | ✓✓✓ (33 tools) | ✓ (assets feed) | — | — | — | ✓ (summary) |
| **Web VA** | ✓ (url probes) | ✓ (CVEs via NVD) | ✓✓✓ (20 tools: dalfox, commix, nuclei, ffuf, wpscan, etc.) | ✓✓ (exploit executor: dalfox, sqlmap, commix, ffuf, nuclei) | ✓ (internal probes) | ✓ (findings) |
| **Network** | ✓ (nmap, masscan, dnsx) | ✓ (ports) | ✓ (service vuln) | ✓ (AD: bloodhound, crackmapexec, impacket, kerbrute, rpcclient) | ✓✓ (lateral: enum4linux, smb) | ✓ |
| **Auth / Credential** | — | — | ✓✓ (password audit: hydra, medusa, ncrack, patator) | ✓ (hash cracking) | ✓ (hash analysis) | ✓ |
| **Cloud / K8s** | — | — | ✓ (trivy, grype, syft, dockle) | ✓✓ (prowler, scoutsuite, kube_hunter, kube_bench, pacu) | — | ✓ |
| **Binary / RE** | — | — | — | ✓✓ (jadx, apktool, binwalk, radare2) | — | ✓ |
| **IaC / SAST** | — | — | ✓✓✓ (checkov, terrascan, tfsec, kics, semgrep, bandit, gitleaks) | ✓ (semgrep, bandit, gitleaks) | — | ✓ |
| **Browser / Headless** | ✓ (gowitness) | — | ✓ (playwright, chrome csp) | — | — | ✓ (screenshots) |
| **OAST** | — | — | ✓✓✓ (interactsh) | — | — | ✓ |
| **Misc** | ✓ (httpx, wappalyzer) | ✓ (shodan) | ✓✓ (semgrep, gitleaks, bandit) | ✓ (semgrep, gitleaks, bandit) | — | ✓ (PEP) |

**Legend:** ✓ = category contributes · ✓✓ = primary/secondary consumer · ✓✓✓ = full pipeline integration

---

## 4. Fully Wired Tools

All 81 tools with end-to-end YAML → Parser → Handler/Adapter integration:

### Recon Phase (33)

| Tool | Parser | Integration Point |
|------|--------|-------------------|
| `amass_passive` | `amass_passive_parser.py` | KAL DNS sandbox bundle |
| `aquatone` | — | Screenshots bundle (via gowitness companion) |
| `assetfinder` | `assetfinder_parser.py` | Subdomain passive bundle |
| `censys` | `censys_parser.py` | Intel adapter |
| `chaos` | `chaos_parser.py` | Intel adapter |
| `crt_sh` | — | Data source (crtsh client) |
| `curl` | — | HTTP surface probe |
| `dig` | — | Step: DIG + DNS depth |
| `dnsrecon` | `dnsrecon_parser.py` | KAL DNS sandbox bundle |
| `dnsx` | `dnsx_parser.py` | DNS depth + takeover hints |
| `favfreak` | — | HTTP probe bundles |
| `feroxbuster` | `discovery_text_parser.py` | Content discovery bundles |
| `findomain` | `findomain_parser.py` | Subdomain passive bundle |
| `fierce` | `fierce_parser.py` | KAL DNS sandbox bundle |
| `gau` | — | URL history bundle |
| `gospider` | — | JS analysis bundle |
| `gowitness` | `gowitness_parser.py` | Screenshots bundle |
| `hakrawler` | — | JS analysis bundle |
| `httpx` | `httpx_parser.py` | HTTP probe bundle |
| `katana` | `katana_parser.py` | URL history bundle |
| `linkfinder` | — | JS analysis bundle |
| `naabu` | `naabu_parser.py` | Deep port scan bundle |
| `otx_alienvault` | — | Intel adapter |
| `paramspider` | — | JS analysis (via MCP) |
| `rustscan` | — | Deep port scan (primary discovery) |
| `securitytrails` | — | Intel adapter |
| `shodan_cli` | — | Data source (shodan client) |
| `subfinder` | `subfinder_parser.py` | Subdomain passive bundle |
| `subjs` | — | JS analysis bundle |
| `theharvester` | — | Subdomain passive (via MCP) |
| `unicornscan` | `unicornscan_parser.py` | Deep port scan (fallback) |
| `urlscan` | — | Intel adapter |
| `waybackurls` | — | URL history bundle |
| `webanalyze` | `webanalyze_parser.py` | HTTP probe (tech stack) |
| `whatweb` | `whatweb_parser.py` | HTTP probe bundle |
| `whois` | — | Step: WHOIS |
| `wappalyzer_cli` | `wappalyzer_cli_parser.py` | HTTP probe (tech stack) |

### Vuln Analysis Phase (20)

| Tool | Parser | Integration Point |
|------|--------|-------------------|
| `chrome_csp_probe` | `chrome_csp_probe_parser.py` | VA active scan pipeline |
| `commix` | `commix_va_adapter.py` | VA active scan (CMDi) + Exploitation |
| `dalfox` | `dalfox_parser.py` | VA active scan + Exploitation |
| `ffuf_dir` | `ffuf_parser.py` | VA active scan (injection fuzzing) |
| `ffuf_param` | `ffuf_parser.py` | VA active scan (parameter discovery) |
| `ffuf_vhost` | `ffuf_parser.py` | VA active scan (vhost brute) |
| `graphql_cop` | `graphql_cop_parser.py` | VA active scan (via MCP) |
| `hydra` | `hydra_parser.py` | Password audit |
| `jsql` | `jsql_probe_parser.py` | VA active scan (via MCP) |
| `ldapsearch` | `ldapsearch_parser.py` | VA active scan (via MCP) |
| `medusa` | `medusa_parser.py` | Password audit |
| `mongodb_probe` | `mongodb_probe_parser.py` | VA active scan (via MCP) |
| `ncrack` | `ncrack_parser.py` | Password audit |
| `nuclei` | `nuclei_parser.py` | VA active scan + HTTP recon + Exploitation |
| `openapi_scanner` | `openapi_scanner_parser.py` | VA active scan (via MCP) |
| `patator` | `patator_parser.py` | Password audit |
| `postman_newman` | `postman_newman_parser.py` | VA active scan (via MCP) |
| `redis_cli_probe` | `redis_cli_probe_parser.py` | VA active scan (via MCP) |
| `snmpwalk` | `snmpwalk_parser.py` | VA active scan (via MCP) |
| `sqlmap_confirm` | `sqlmap_parser.py` | VA active scan + Exploitation |
| `sqlmap_safe` | `sqlmap_parser.py` | VA active scan (sandbox) |
| `wpscan` | `wpscan_parser.py` | VA active scan |
| `checkov` | `checkov_parser.py` | IaC audit (via MCP) |
| `terrascan` | `terrascan_parser.py` | IaC audit (via MCP) |
| `tfsec` | `tfsec_parser.py` | IaC audit (via MCP) |
| `kics` | `kics_parser.py` | IaC audit (via MCP) |
| `semgrep` | `semgrep_parser.py` | SAST + Exploitation |
| `gitleaks` | `gitleaks_parser.py` | SAST (secrets) + Exploitation |
| `bandit` | `bandit_parser.py` | SAST (Python) + Exploitation |
| `trivy_fs` | `trivy_parser.py` | Manifest scan |
| `trivy_image` | `trivy_parser.py` | Container scan |
| `dockle` | `dockle_parser.py` | Container audit |
| `grype` | `grype_parser.py` | SBOM vuln scan |
| `syft` | `syft_parser.py` | SBOM generation |

### Network & AD (11)

| Tool | Parser | Integration Point |
|------|--------|-------------------|
| `nmap_tcp_full` | `nmap_parser.py` | Nmap sandbox cycle |
| `nmap_tcp_top` | `nmap_parser.py` | Nmap sandbox cycle |
| `nmap_udp` | `nmap_parser.py` | Nmap sandbox cycle |
| `nmap_version` | `nmap_parser.py` | Nmap sandbox cycle |
| `nmap_vuln` | `nmap_parser.py` | Nmap sandbox cycle |
| `masscan` | `masscan_parser.py` | Deep port scan bundle |
| `jarm` | `jarm_parser.py` | Recon bundles |
| `bloodhound_python` | `bloodhound_python_parser.py` | Exploitation (AD recon) |
| `crackmapexec` | `crackmapexec_parser.py` | Exploitation + Post-exploit |
| `enum4linux_ng` | `enum4linux_ng_parser.py` | Exploitation + Post-exploit |
| `impacket_secretsdump` | `impacket_secretsdump_parser.py` | Exploitation (AD credential dump) |
| `kerbrute` | `kerbrute_parser.py` | Exploitation (AD kerberoasting) |
| `rpcclient_enum` | `rpcclient_enum_parser.py` | Exploitation (AD null session) |

### Cloud & Exploitation (11)

| Tool | Parser | Integration Point |
|------|--------|-------------------|
| `prowler` | `prowler_parser.py` | Exploitation (AWS posture) |
| `scoutsuite` | — | Exploitation (AWS audit) |
| `kube_hunter` | — | Exploitation (K8s attack) |
| `kube_bench` | `kube_bench_parser.py` | Exploitation (K8s CIS) |
| `pacu` | — | Exploitation (AWS exploitation) |
| `jadx` | `jadx_parser.py` | Exploitation (APK decompile) |
| `apktool` | `apktool_parser.py` | Exploitation (APK unpack) |
| `binwalk` | `binwalk_parser.py` | Exploitation (firmware extract) |
| `radare2_info` | `radare2_info_parser.py` | Exploitation (binary analysis) |
| `mobsf_api` | `mobsf_parser.py` | Exploitation (mobile SAST) |
| `trufflehog` | `trufflehog_parser.py` | Exploitation (secrets scan) |

### OAST & Playwright (3)

| Tool | Parser | Integration Point |
|------|--------|-------------------|
| `interactsh_client` | `interactsh_parser.py` | VA (OOB callback polling) |
| `playwright_runner` | `playwright_runner_parser.py` | VA (browser automation) |
| `playwright_xss_verify` | `xss_auxiliary_json_parser.py` | VA (custom XSS PoC) |

### Misc SAST (3)

| Tool | Parser | Integration Point |
|------|--------|-------------------|
| `detect_secrets` | `detect_secrets_parser.py` | Exploitation (secret scan) |
| `github_search` | — | Intel adapter |
| `ghauri` | `sqli_probe_text_parser.py` | VA active scan (via MCP) |

---

## 5. Gap Analysis — Remaining Unwired Tools

### Priority Assessment

| Priority | Criteria | Count |
|----------|----------|-------|
| **High** | Parser exists but no handler integration yet; core pentest function | 8 |
| **Medium** | Parser exists but integration is partial/indirect (via MCP only) | 16 |
| **Low** | No parser exists; niche tool or planned for future cycles | 57 |

### By Category

#### Web VA (29 remaining)
| Tool ID | Parser? | Gap | Priority |
|---------|---------|-----|----------|
| `arachni` | No | Full wiring needed | Medium |
| `arjun` | No | Full wiring needed | Low |
| `clairvoyance` | No | Full wiring needed | Low |
| `cmsmap` | No | Full wiring needed | Low |
| `cookie_probe` | No | Full wiring needed | Medium |
| `cors_probe` | No | Full wiring needed | Medium |
| `droopescan` | No | Full wiring needed | Low |
| `eyewitness` | No | Full wiring needed | Low |
| `gobuster_auth` | `discovery_text_parser.py` (shared) | Handler integration | High |
| `gobuster_dir` | `discovery_text_parser.py` (shared) | Handler integration | High |
| `graphw00f` | No | Full wiring needed | Low |
| `grpcurl_probe` | No | Full wiring needed | Medium |
| `inql` | No | Full wiring needed | Low |
| `jenkins_enum` | No | Full wiring needed | Low |
| `joomscan` | No | Full wiring needed | Low |
| `kxss` | `xss_auxiliary_json_parser.py` | Handler integration (add to XSS PoC pipeline) | High |
| `magescan` | No | Full wiring needed | Low |
| `nextjs_check` | No | Full wiring needed | Medium |
| `nikto` | No | Full wiring needed | Medium |
| `nosqlmap` | No | Full wiring needed | Medium |
| `skipfish` | No | Full wiring needed | Low |
| `spring_boot_actuator` | No | Full wiring needed | Medium |
| `ssrfmap` | No | Full wiring needed | Medium |
| `tplmap` | No | Full wiring needed | Medium |
| `w3af_console` | No | Full wiring needed | Low |
| `wapiti` | No | Full wiring needed | Low |
| `wfuzz` | No | Full wiring needed | Low |
| `xsser` | `xss_auxiliary_json_parser.py` | Handler integration | High |
| `zap_baseline` | `zap_baseline_parser.py` | Parser exists, needs VA pipeline hook | High |

#### Recon (6 remaining)
| Tool ID | Parser? | Gap | Priority |
|---------|---------|-----|----------|
| `host` | No | Full wiring needed | Low |
| `kiterunner` | No | MCP-only today; add to content discovery bundle | High |
| `tlsx` | No | Full wiring needed | Low |
| `whois_rdap` | No | Add as RDAP data source | Medium |

#### Network (12 remaining)
| Tool ID | Parser? | Gap | Priority |
|---------|---------|-----|----------|
| `evil_winrm` | `evil_winrm_parser.py` | Parser exists, needs post-exploit hook | High |
| `ike_scan` | No | Full wiring needed | Low |
| `impacket_examples` | No | Full wiring needed | Medium |
| `mkcert_verify` | No | Full wiring needed | Low |
| `ntlmrelayx` | `ntlmrelayx_parser.py` | Parser exists, needs exploitation hook | High |
| `onesixtyone` | No | SNMP tool, wire to service scan | Medium |
| `responder` | `responder_parser.py` | Parser exists, needs active network hook | High |
| `smbclient` | `smbclient_check_parser.py` | Parser exists, needs AD exploitation hook | High |
| `smbmap` | `smbmap_parser.py` | Parser exists, needs AD exploitation hook | High |
| `snmp_check` | No | Wire alongside snmpwalk | Medium |
| `ssl_enum_ciphers` | No | Full wiring needed | Low |
| `sslscan` | No | Full wiring needed | Medium |
| `sslyze` | No | Full wiring needed | Medium |
| `testssl` | No | Full wiring needed | Medium |
| `cloud_metadata_check` | No | Full wiring needed (cloud recon) | Medium |

#### Auth (2 remaining)
| Tool ID | Parser? | Gap | Priority |
|---------|---------|-----|----------|
| `hashcat` | `hashcat_parser.py` | Parser exists, needs post-exploit (password cracking) | High |
| `john` | No | Full wiring needed | Medium |
| `ophcrack` | No | Full wiring needed | Low |
| `gopherus` | No | Full wiring needed | Low |

#### Cloud (5 remaining)
| Tool ID | Parser? | Gap | Priority |
|---------|---------|-----|----------|
| `cloud_metadata_check` | No | Full wiring needed | Medium |
| `cloudsploit` | `cloudsploit_parser.py` | Parser exists, needs VA pipeline hook | High |

#### Browser (4 remaining)
| Tool ID | Parser? | Gap | Priority |
|---------|---------|-----|----------|
| `puppeteer_screens` | `puppeteer_screens_parser.py` | Parser exists, needs recon screenshot hook | Medium |

#### Binary (2 remaining — all have parsers)
> All binary tools are wired via exploitation executor. Remaining gap is pre-exploitation binary surface enumeration.

#### OAST (3 remaining)
| Tool ID | Parser? | Gap | Priority |
|---------|---------|-----|----------|
| `oastify_client` | No | Full wiring needed | Low |
| `oast_dns_probe` | No | Full wiring needed | Low |

---

## 6. Recommendations — Priority Wiring Queue

### Batch 1 — Immediate (8 tools, ~2 days)

Tools with **existing parsers** that need handler integration only:

| # | Tool | Category | Rationale |
|---|------|----------|-----------|
| 1 | `evil_winrm` | Network | Parser exists; critical for Windows post-exploit lateral movement |
| 2 | `ntlmrelayx` | Network | Parser exists; AD exploitation cornerstone |
| 3 | `responder` | Network | Parser exists; LLMNR/NBT-NS poisoning for initial AD foothold |
| 4 | `smbclient` | Network | Parser exists; SMB share enumeration for AD lateral |
| 5 | `smbmap` | Network | Parser exists; SMB share permissions audit |
| 6 | `hashcat` | Auth | Parser exists; GPU password cracking for post-exploit |
| 7 | `cloudsploit` | Cloud | Parser exists; AWS/GCP/Azure misconfig scanner |
| 8 | `kiterunner` | Recon | MCP-only today; add to content discovery bundle for API route brute |

### Batch 2 — Short-term (12 tools, ~3 days)

Tools that share existing parsers or have clear integration paths:

| # | Tool | Category | Reuse Parser | Target Phase |
|---|------|----------|-------------|-------------|
| 1 | `gobuster_dir` | Web VA | `discovery_text_parser.py` | Recon (content discovery) |
| 2 | `gobuster_auth` | Web VA | `discovery_text_parser.py` | VA (auth brute) |
| 3 | `kxss` | Web VA | `xss_auxiliary_json_parser.py` | VA (XSS scan pipeline) |
| 4 | `xsser` | Web VA | `xss_auxiliary_json_parser.py` | VA (XSS scan pipeline) |
| 5 | `zap_baseline` | Web VA | `zap_baseline_parser.py` | VA (active scan) |
| 6 | `nikto` | Web VA | New parser needed | VA (web server vuln) |
| 7 | `nosqlmap` | Web VA | New parser needed | VA (NoSQL injection) |
| 8 | `ssrfmap` | Web VA | New parser needed | VA (SSRF exploitation) |
| 9 | `tplmap` | Web VA | New parser needed | VA (SSTI exploitation) |
| 10 | `arjun` | Web VA | New parser needed | VA (param discovery) |
| 11 | `whois_rdap` | Recon | Existing client | Recon (RDAP lookup added to WHOIS step) |
| 12 | `puppeteer_screens` | Browser | `puppeteer_screens_parser.py` | Recon (alternative screenshots) |

### Batch 3 — Medium-term (15 tools, ~5 days)

SSL/TLS + specialized scanners needing new parsers:

| # | Tool | Category | New Parser | Target Phase |
|---|------|----------|-----------|-------------|
| 1–4 | `sslscan`, `sslyze`, `testssl`, `ssl_enum_ciphers` | Network | `ssl_*_parser.py` | Recon (TLS audit) |
| 5 | `onesixtyone` | Network | SNMP parser (shared w/ snmpwalk) | Recon (SNMP discovery) |
| 6 | `snmp_check` | Network | SNMP parser | Recon |
| 7 | `ike_scan` | Network | New parser | Recon (VPN/IKE discovery) |
| 8 | `impacket_examples` | Network | New parser | Exploitation (misc AD scripts) |
| 9 | `john` | Auth | New parser | Post-exploit (password cracking alt) |
| 10 | `cloud_metadata_check` | Cloud | New parser | Recon (cloud environment detection) |
| 11 | `grpcurl_probe` | Web VA | New parser | Recon (gRPC service probe) |
| 12 | `cors_probe` | Web VA | New parser | VA (CORS misconfig) |
| 13 | `cookie_probe` | Web VA | New parser | VA (cookie security) |
| 14 | `nextjs_check` | Web VA | New parser | VA (Next.js info leak) |
| 15 | `spring_boot_actuator` | Web VA | New parser | VA (Spring actuator exposure) |

### Batch 4 — Backlog (remaining, ~10 days)

Low-priority niche and legacy scanners:

- CMS scanners: `cmsmap`, `droopescan`, `joomscan`, `magescan`
- Legacy DAST: `arachni`, `skipfish`, `w3af_console`, `wapiti`, `wfuzz`
- Specialized: `clairvoyance`, `graphw00f`, `inql`, `jenkins_enum`, `eyewitness`
- OAST remaining: `oastify_client`, `oast_dns_probe`
- Recon remaining: `host`, `tlsx`, `gopherus`, `ophcrack`, `mkcert_verify`, `secretfinder`, `favfreak` (full integration)

---

## Appendix: Integration Architecture

```
YAML Definition (config/tools/*.yaml)
    │
    ├─→ Parser (src/sandbox/parsers/*_parser.py)
    │       │
    │       └─→ FindingDTO (normalized output)
    │
    ├─→ Recon Adapters (src/recon/adapters/)
    │       │
    │       └─→ Intel pipeline (data sources)
    │
    ├─→ Recon Bundles (src/recon/recon_*.py)
    │       │
    │       └─→ Pipeline (src/recon/pipeline.py) → handlers.run_recon()
    │
    ├─→ VA Active Scan (src/recon/vulnerability_analysis/)
    │       │
    │       └─→ handlers.run_vuln_analysis() → intel_findings
    │
    └─→ Exploitation (src/orchestration/exploitation_executor.py)
            │
            └─→ handlers.run_exploitation() → verified exploits
```

---

*Document sections: 6 (Summary, Category Breakdown × 10 sub-sections, Phase Coverage Matrix, Fully Wired Tools, Gap Analysis, Recommendations) · Total tables: 20+ · End of document*
