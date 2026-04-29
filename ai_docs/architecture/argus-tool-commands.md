# ARGUS — Командный справочник по инструментам

> Дополнение к [`argus-pentest-process-overview.md`](./argus-pentest-process-overview.md).
> Здесь собраны все CLI-команды/argv, которые ARGUS реально запускает в sandbox-контейнере
> или напрямую (host) при сканировании. Источники: `mcp-server/argus_mcp.py`,
> `mcp-server/tools/kali_registry.py`, `backend/src/api/routers/tools.py`,
> `backend/src/tools/executor.py`, `backend/src/recon/vulnerability_analysis/active_scan/*`,
> `backend/src/recon/recon_*`, `backend/src/recon/mcp/policy.py`, `backend/src/tasks/tools.py`.

`<target>` / `<url>` / `<domain>` / `<host>` / `<wordlist>` / `<extra>` — подставляемые
значения. Все argv запускаются **без shell** (`subprocess.run(list)` или sandbox docker exec),
shell metacharacters блокируются.

---

## 1. Recon-фаза (orchestration/handlers.py + recon/pipeline.py)

```bash
# Внутри run_recon — параллельный gather (asyncio):

# nmap (recon/nmap_recon_cycle.py — multi-phase sandbox cycle, KAL-003):
nmap <target>            # phase 1: -sV -Pn -T4 -p <ports>  (по умолчанию 1-1000)
nmap -sC -sV <target>    # phase 2: NSE базовые скрипты на найденных портах
nmap --script vuln <target>  # phase 3: vuln NSE (если deep)

# DNS / WHOIS:
dig <domain> ANY +noall +answer
whois <domain>

# Сертификаты + Shodan:
GET https://crt.sh/?q=%.<domain>&output=json     # asyncio httpx
GET https://api.shodan.io/shodan/host/<ip>       # ShodanClient

# HTTP-сюрфинг:
GET <target>                # _extract_url_params_and_forms — формы, query, redirects
GET <target>/requirements.txt    # для Trivy fs (если найдено)
GET <target>/package.json
```

Дальнейшие bundle-функции (выполняются по `plan_recon_steps(cfg)` → `STUB_STEPS`):

```bash
# subdomain inventory (recon/recon_subdomain_passive.py):
subfinder -d <domain>
assetfinder --subs-only <domain>
findomain -t <domain>
theHarvester -d <domain> -b crtsh,otx,urlscan,...   # из THEHARVESTER_RECON_B_SOURCES_CAP

# DNS sandbox (recon/recon_dns_sandbox.py):
dig +short <domain>
dnsx -d <domain>
amass enum -d <domain>           # только enum allowed (KAL_AMASS_ALLOWED_SUBCOMMANDS)
host <domain>
nslookup <domain>
dnsrecon -d <domain>
fierce --domain <domain>

# DNS depth (recon/recon_dns_depth.py):
dnsx -d <domain> -resp -a -aaaa -cname -mx -ns -txt
massdns -r <resolvers> <wordlist>
shuffledns -d <domain> -w <wordlist>

# ASN map (recon/recon_asn_screenshots.py):
asnmap -d <domain>
gowitness scan -f <urls.txt> -o /tmp/screenshots

# URL history / content discovery (recon/recon_url_history.py):
gau <domain>
waybackurls <domain>
katana -u <target> -d 3

# JS analysis (recon/recon_js_analysis.py):
linkfinder -i <local.js> -o cli         # KAL: только локальный файл
unfurl --json <url>

# Deep port scan (recon/recon_deep_port_scan.py):
masscan <target> -p 1-65535 --rate 1000
naabu -host <target> -p <ports>

# HTTP probe (recon/recon_http_probe.py):
httpx -u <target> -tech-detect -title -status-code -tls-grab -follow-redirects -silent
whatweb <target>

# Security headers (recon/recon_http_headers.py):
GET <target>  # внутренний async-httpx, парсит CSP/HSTS/X-Frame-Options и т.д.
```

---

## 2. Vulnerability Analysis (active_scan adapters + Celery)

Все argv ниже строятся в `backend/src/recon/vulnerability_analysis/active_scan/*_adapter.py`.
Запускаются в sandbox-контейнере через `mcp_runner.run_va_active_scan_sync(tool_name,
target, argv, timeout_sec, use_sandbox=True, sandbox_workdir="/home/argus")`.

```bash
# dalfox (build_dalfox_argv) — XSS:
dalfox url <url>

# xsstrike (xsstrike_adapter):
python3 /opt/XSStrike/xsstrike.py -u <url> --skip --skip-dom

# ffuf (build_ffuf_argv) — fuzzer (FUZZ injected в query value или path-suffix):
ffuf -u <url-with-FUZZ> -w <wordlist> -t 2 -rate 5

# sqlmap (build_sqlmap_va_argv) — only conservative VA-mode:
sqlmap -u <url> --batch --level 1 --risk 1 --random-agent
sqlmap -u <url> --batch --level 1 --risk 1 --random-agent --data "<post>"

# nuclei (build_nuclei_va_argv):
nuclei -u <url> -jsonl -duc -ni -rate-limit 12 -silent

# whatweb (build_whatweb_va_argv):
whatweb --log-json=- -q <url>

# nikto (build_nikto_va_argv):
nikto -h <url> -Format json -maxtime <30..600> -o -

# testssl (build_testssl_va_argv):
testssl.sh --color 0 --openssl-timeout 15 --connect-timeout 15 --quiet \
           --warnings off --jsonfile-pretty /dev/stdout <url>

# sslscan fallback (build_sslscan_va_argv):
sslscan --json <host:port>

# commix (allowlisted by VA_ACTIVE_SCAN_ALLOWED_TOOLS):
commix --url=<url> --batch

# wfuzz (allowlisted):
wfuzz -u <url-with-FUZZ> -w <wordlist>

# feroxbuster:
feroxbuster -u <url> -w <wordlist>

# gobuster (KAL bruteforce_testing):
gobuster dir -u <url> -w /usr/share/wordlists/dirb/common.txt

# password audit (только при двойном opt-in):
hydra -L <users.txt> -P <pass.txt> <target> <service>
medusa -h <target> -U <users.txt> -P <pass.txt> -M <module>

# OSINT / shallow crawl (VDF-005/008):
theharvester -d <domain> -b crtsh
gospider -s <url>
parsero -u <url>

# Network capture (gated):
mitmdump -p 8080 --mode reverse:<url>
tcpdump -i any -w /tmp/cap.pcap

# Vuln intel (KAL-006):
searchsploit <product>
```

Custom XSS PoC (`recon/exploitation/custom_xss_poc.py:run_custom_xss_poc`) — ARGUS
формирует HTTP-запросы из `xss_payload_manager.py` и стреляет httpx-ом
(NOT через dalfox), параметризовано:

```python
run_custom_xss_poc(target, params_inv, forms_inv,
                   timeout=20.0,
                   max_payloads=80 if aggressive else 50,
                   max_total_requests=200,
                   aggressive=settings.va_aggressive_scan)
```

Trivy fs scan (KAL-008, `recon/trivy_recon_manifest_scan.py`):
```bash
trivy fs --format json --quiet --no-progress <local-manifest-dir>
```

---

## 3. Sandbox `/api/v1/sandbox/execute` (общий generic-runner)

`backend/src/api/routers/sandbox.py` принимает любую команду из allowlist
(`ALLOWED_TOOLS` в `tools/guardrails/command_parser.py`), запускает через
`execute_command_with_recovery()` (recovery alternatives ≤ 3 раза). MCP-tool
`execute_security_tool(tool, target, args_json, timeout_sec, scan_id)` собирает
команду через `_tool_to_shell_command` (`mcp-server/argus_mcp.py`):

```bash
# Поддерживаемые "build_command_for_tool" билдеры:
dig <target>
whois <target>
host <target>
curl <target>
whatweb <target>
dnsx -d <target>
naabu -host <target>
theHarvester -d <target>
dnsrecon -d <target>
fierce --domain <target>
assetfinder <target>
findomain -d <target>
gau <target>
waybackurls <target>
sublist3r -d <target>
gitleaks detect [--source <target>]
semgrep scan --config auto <target|.>
trufflehog filesystem <target|.>
prowler [-p <target>]
checkov -d <target|.>
terrascan scan -d <target|.>

# Кроме того, через _tool_to_shell_command:
nmap -sV [-p <ports>] <target> [<extra>]
nuclei -u <target> [<extra>]
gobuster dir -u <url> -w <wordlist> [<extra>]
nikto -h <target> [<extra>]
sqlmap -u <url> --batch [<extra>]
```

---

## 4. Per-tool API endpoints (`/api/v1/tools/<name>`)

`backend/src/api/routers/tools.py`. Каждый endpoint билдит свою команду:

```bash
# POST /api/v1/tools/nmap            (NmapRequest: target, scan_type=-sV, ports, additional_args=-T4 -Pn)
nmap <scan_type> [-p <ports>] <extra> <target>

# POST /api/v1/tools/nuclei
nuclei -u <target> [-severity <s>] [-tags <t>] [-t <template>] <extra>

# POST /api/v1/tools/gobuster        (mode: dir|dns|fuzz|vhost)
gobuster <mode> -u <url> -w <wordlist> <extra>

# POST /api/v1/tools/nikto
nikto -h <target> <extra>

# POST /api/v1/tools/sqlmap          (--batch always, optional --data)
sqlmap -u <url> --batch [--data <data>] <extra>

# POST /api/v1/tools/dirb
dirb <url> <wordlist> <extra>

# POST /api/v1/tools/ffuf
ffuf -u <url> -w <wordlist> <extra>

# POST /api/v1/tools/subfinder
subfinder -d <domain> <extra>

# POST /api/v1/tools/hydra
hydra [-l <user> | -L <user_file>] [-p <pass> | -P <pass_file>] <target> <service> <extra>

# POST /api/v1/tools/wpscan
wpscan --url <url> <extra>

# POST /api/v1/tools/httpx
httpx -u <targets> <extra>

# POST /api/v1/tools/amass
amass enum -d <domain> <extra>

# POST /api/v1/tools/feroxbuster
feroxbuster -u <url> -w <wordlist> <extra>

# POST /api/v1/tools/dirsearch
dirsearch -u <url> -w <wordlist> <extra>

# POST /api/v1/tools/wfuzz
wfuzz -u <url> -w <wordlist> <extra>

# POST /api/v1/tools/rustscan
rustscan -a <target> [-- -p <ports>] <extra>

# POST /api/v1/tools/masscan
masscan <target> -p <ports> --rate <rate> <extra>          # default rate=1000, ports=1-65535

# POST /api/v1/tools/trivy           (scan_type: image|fs|repo|config)
trivy <scan_type> <target> <extra>

# POST /api/v1/tools/execute         (generic command, allowlist enforced)
<command_string>                                            # rate-limit 30/min/IP

# POST /api/v1/tools/kal/run         (KAL-002 categorized argv)
{ "category": "<cat>", "argv": ["<bin>", ...], "target": "<t>",
  "tenant_id": "<tid>", "scan_id": "<sid>", "password_audit_opt_in": false }
```

---

## 5. KAL MCP categorized runner (`run_kal_mcp_tool`)

Из `mcp-server/argus_mcp.py:_register_kal_mcp_tools` идёт в backend
`POST /api/v1/tools/kal/run`. Категории и собираемые argv (примеры из MCP-обёрток):

```bash
# run_network_scan(tool=nmap|rustscan|masscan):
nmap <extra_args="-sV -Pn -T4"> <target>
rustscan -a <target> <extra>
masscan <target> -p 1-1000 --rate 1000

# run_web_scan(tool=httpx|whatweb|wpscan|nikto):
httpx -u <target> -silent
whatweb <target>
wpscan --url <target>
nikto -h <target>

# run_ssl_test:
openssl s_client -connect <host:port> -servername <host>

# run_dns_enum(tool=dig|subfinder|amass|dnsx|host|nslookup):
dig +short <target>
subfinder -d <target>
amass enum -d <target>
dnsx -d <target>
host <target>
nslookup <target>

# run_bruteforce(tool=gobuster|feroxbuster|dirsearch|ffuf|wfuzz|dirb):
gobuster dir -u <target> -w /usr/share/wordlists/dirb/common.txt
feroxbuster -u <target> -w /usr/share/wordlists/dirb/common.txt
dirsearch -u <target> -w /usr/share/wordlists/dirb/common.txt
ffuf -u <target> -w /usr/share/wordlists/dirb/common.txt
wfuzz -u <target> -w /usr/share/wordlists/dirb/common.txt
dirb <target> /usr/share/wordlists/dirb/common.txt
```

Argv-injection блокируется патерном `[\`$]|\$\(|;\s*|\|\s*|&&\s*|\n|\r|<\(|>\(`.

Hydra/medusa блокируется везде, кроме `password_audit` категории + двойного opt-in:

```bash
# run_tool(category="password_audit", argv=["hydra", ...], password_audit_opt_in=True)
# и server-flag KAL_ALLOW_PASSWORD_AUDIT=true; иначе POLICY_DENY.
```

---

## 6. Internal VA enqueue (`/api/v1/internal/va-tools/enqueue` → Celery)

`backend/src/api/routers/internal_va.py` ставит Celery таски с именами
`argus.va.run_<tool>` (`backend/src/tasks/tools.py`). Принимаемые tool-имена:
`dalfox, xsstrike, ffuf, sqlmap, nuclei, whatweb, nikto, testssl`.

```python
celery_app.send_task("argus.va.run_dalfox",  args=[tenant_id, scan_id, target, args])
celery_app.send_task("argus.va.run_xsstrike", args=[tenant_id, scan_id, target, args])
celery_app.send_task("argus.va.run_ffuf",     args=[tenant_id, scan_id, target, args])
celery_app.send_task("argus.va.run_sqlmap",   args=[tenant_id, scan_id, target, args])
celery_app.send_task("argus.va.run_nuclei",   args=[tenant_id, scan_id, target, args])
celery_app.send_task("argus.va.run_whatweb",  args=[tenant_id, scan_id, target, args])
celery_app.send_task("argus.va.run_nikto",    args=[tenant_id, scan_id, target, args])
celery_app.send_task("argus.va.run_testssl",  args=[tenant_id, scan_id, target, args])
```

Внутри таска `_resolve_argv(tool, target, args)` либо собирает default-argv
из соответствующего адаптера, либо валидирует custom argv-prefix (executable должен
совпасть). `run_va_active_scan_sync` запускает в sandbox-контейнере с timeout (по
умолчанию `settings.va_ssl_probe_timeout_sec`/`va_nikto_timeout_sec` для
SSL/Nikto). Stdout/stderr/meta пишутся в MinIO как `tool_<name>_celery_<runid>_<suffix>`.

---

## 7. Kali registry tools (мульти-tool MCP layer)

Все ~140 инструментов из `mcp-server/tools/kali_registry.py` регистрируются как
MCP tools `kali_<name>` и попадают либо в dedicated-endpoint (см. § 4 — nmap/nuclei/...),
либо в generic `/api/v1/tools/execute` через `_build_command_for_tool` (см. § 3).

### 7.1 recon (25)
```
subfinder, amass, httpx, whatweb, dnsx, naabu, theharvester, dnsrecon, fierce,
assetfinder, findomain, gau, waybackurls, sublist3r, dig, whois, host, nslookup,
dnsenum, altdns, shuffledns, massdns, knockpy, crt, curl
```

### 7.2 vuln_scan (20)
```
nuclei, nikto, nmap, openvas, lynis, sslyze, testssl, wapiti, zap, retire, safety,
npm_audit, pip_audit, grype, trivy, clair, cvedb, searchsploit, vulners
```

### 7.3 web (25)
```
gobuster, ffuf, dirsearch, wfuzz, sqlmap, dirb, feroxbuster, wpscan, joomscan,
droopescan, arjun, paramspider, commix, xsstrike, dalfox, nuclei_web, httpx_tech,
katana, gau_web, hakrawler, gospider, burpsuite, cewl, crunch
```

### 7.4 network (20)
```
masscan, rustscan, zmap, unicornscan, hping3, netcat, ncat, snmpwalk, onesixtyone,
enum4linux, smbclient, nbtscan, rpcclient, ldapsearch, traceroute, ping, arp-scan,
ike-scan, responder, crackmapexec
```

### 7.5 cloud (15)
```
prowler, scoutsuite, cloudsplaining, steampipe, tfsec, cfn_nag, kics, cloudsploit,
azucar, gcp_scanner, kubeaudit, kubescape, polaris, kube_score
```

### 7.6 code / SAST (20)
```
semgrep, gitleaks, trufflehog, bandit, brakeman, spotbugs, gosec, flawfinder,
cppcheck, eslint, npm_audit_code, yarn_audit, detect_secrets, git_secrets,
repo_supervisor, codeql, sonarscanner, insidersec, bearer
```

### 7.7 IaC (15)
```
checkov, terrascan, tfsec_terraform, infracost, conftest, opa, regula, policies,
docker_bench, cis_docker, ansible_lint, puppet_parser, helm_lint
```

### 7.8 misc / forensics (10)
```
binwalk, strings, exiftool, foremost, volatility, bulk_extractor, hashcat, john,
pdfid, pev
```

Поведение: MCP-handler формирует args = `{primary_arg: target, additional_args: extra}`,
backend конвертирует в shell-команду из § 3/4.

---

## 8. Exploitation phase (нет деструктивного исполнения)

`run_exploit_attempt` — **только LLM**, не запускает CLI.
`run_exploit_verify` — `httpx.AsyncClient` GET с `timeout=10.0,
follow_redirects=True, verify=False`. Никакого shell.

`maybe_run_aggressive_exploit_tools` — единственное исключение, когда findings
указывают на SQLi и `VA_EXPLOIT_AGGRESSIVE_ENABLED=true`:

```python
# Целево ставит Celery task argus.va.run_sqlmap  (ENV + per-tool approval policy)
run_sqlmap.delay(tenant_id, scan_id, target, None)
# default argv из build_sqlmap_va_argv(target, None) =
# sqlmap -u <target> --batch --level 1 --risk 1 --random-agent
```

Stage-4 `EXPLOITATION_BLOCKED_PATTERNS` блокирует на уровне MCP policy:
`--drop`, `--delete`, `rm -rf`, `format `, `mkfs`, `DROP TABLE`, `DELETE FROM`,
`TRUNCATE`, `ALTER TABLE`, `--os-pwn`, `--os-bof`.

---

## 9. Reporting (Celery-bundle)

```python
# run_reporting → ai_reporting (LLM) → ReportingOutput
# bundle_enqueue.enqueue_generate_all_bundle()  → отдельные Celery таски:
generate_report_task(scan_id, format)            # pdf|html|json|csv|sarif|junit
generate_all_reports_task(scan_id, formats)      # batch
```

HTML/PDF — Jinja + WeasyPrint (см. `src/reports/`), SARIF — `src/reports/sarif_generator.py`,
JUnit — `src/reports/junit_generator.py`. Скачивание через
`GET /api/v1/reports/{report_id}/download?format=...&redirect=true` — отдаёт base64
или 302 на presigned MinIO URL.

---

## 10. Wordlists и пути по умолчанию

```bash
/usr/share/wordlists/dirb/common.txt           # gobuster, ffuf, dirsearch, wfuzz, dirb, feroxbuster
backend/src/recon/vulnerability_analysis/active_scan/data/va_ffuf_wordlist.txt  # VA ffuf default
                                                # (можно переопределить settings.ffuf_va_wordlist_path)
```

---

## 11. Кеш и rate limit

* `tool_cache_*` (Redis): per-tool TTL (`ttl_for_tool` в `cache/tool_cache.py`).
* `/tools/execute`: `RateLimiter(30/min/IP)` (`tools/guardrails/rate_limiter.py`).
* `/tools/kal/run`: тот же rate-limiter (`kal_run:<ip>` ключ).
* `cache/scan_knowledge_base.py`: skills/tools per OWASP/CWE, прогрев через POST
  `/api/v1/cache/warm` (admin), флаш — DELETE `/api/v1/cache` (паттерны должны
  начинаться с `argus:`).

---

## 12. Минимальный пример: scan от MCP до отчёта

```bash
# 1. MCP create_scan → POST /api/v1/scans:
{ "target": "https://example.com",
  "email": "x@y.z",
  "scan_mode": "standard",
  "options": { "scanType": "standard", "vulnerabilities":
    {"xss":true,"sqli":true,"csrf":true,"ssrf":false,"lfi":false,"rce":false},
    "scope": {"maxDepth":3,"includeSubs":false,"excludePatterns":""},
    "kal":{"password_audit_opt_in":false,
           "recon_dns_enumeration_opt_in":true,
           "va_network_capture_opt_in":false}
  }
}
# → 201 { "scan_id": "...", "status": "queued" }

# 2. Backend → Celery scan_phase_task → ScanStateMachine:
#    Phase RECON
nmap -sV -Pn -T4 -p 1-1000 example.com
dig example.com ANY +noall +answer
whois example.com
GET https://crt.sh/?q=%.example.com&output=json
subfinder -d example.com
httpx -u https://example.com -tech-detect -silent
gowitness scan -f urls.txt -o /tmp/screenshots
asnmap -d example.com
gau example.com
katana -u https://example.com -d 3
# → ai_recon (LLM ORCHESTRATION) → ReconOutput

#    Phase THREAT_MODELING
# NVD CVE keyword search per tech keyword (top 5)
GET https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=<kw>&resultsPerPage=5
# → ai_threat_modeling (LLM THREAT_MODELING) → ThreatModelOutput (STRIDE)

#    Phase VULN_ANALYSIS  (sandbox + multi-agent)
dalfox url https://example.com/?q=test
nuclei -u https://example.com -jsonl -duc -ni -rate-limit 12 -silent
ffuf -u https://example.com/?q=FUZZ -w wordlist.txt -t 2 -rate 5
sqlmap -u https://example.com/?id=1 --batch --level 1 --risk 1 --random-agent
whatweb --log-json=- -q https://example.com
nikto -h https://example.com -Format json -maxtime 120 -o -
testssl.sh --jsonfile-pretty /dev/stdout https://example.com
# → web_vuln_heuristics (header / cookie / CORS analysis)
# → searchsploit <product>
# → trivy fs --format json <manifest-dir>
# → ai_vuln_analysis (LLM ZERO_DAY_ANALYSIS) + VAMultiAgentOrchestrator (parallel)

#    Phase EXPLOITATION
# ai_exploitation (LLM EXPLOIT_GENERATION) — proposed exploits
# verify_exploit_poc_async — httpx GET only
# (опционально) maybe_run_aggressive_exploit_tools → argus.va.run_sqlmap

#    Phase POST_EXPLOITATION  (LLM only)
# ai_post_exploitation (LLM REMEDIATION_PLAN) → lateral / persistence proposals

#    Phase REPORTING
# HIBP enrichment
# ai_reporting (LLM REPORT_SECTION)
# enqueue_generate_all_bundle (pdf/html/json/csv/sarif/junit Celery tasks)

# 3. MCP get_report → GET /api/v1/reports/{report_id}/download?format=pdf&redirect=true
# → 302 на presigned MinIO URL (или base64 если redirect=false)
```
