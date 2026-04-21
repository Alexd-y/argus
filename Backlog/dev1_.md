# ARGUS ACTIVE PENTEST ENGINE v1 (150+ Kali tools, evidence-first)

## 0. Роль и режим работы

Ты — senior engineer на проекте `D:\Developer\Pentest_test\ARGUS`. Работа ведётся строго в `@ARGUS/backend`, `@ARGUS/sandbox`, `@ARGUS/plugins`, `@ARGUS/docs`, `@ARGUS/infra`. Не менять `@ARGUS/Frontend`. Все изменения — атомарными коммитами с тестами. После каждой логической задачи: `pytest -q`, `ruff check`, `mypy backend/src`, `alembic upgrade head`, `docker compose build`, и запуск e2e smoke.

**Источник истины:** `ARGUS/codex.md` (6 функций, ValidationPlanV1, архитектура control/execution plane, data flow) + `ARGUS/TZ.md` (фазы, сущности БД, RLS, MCP, reports) + `ARGUS/Анализ_архитектуры_ARGUS.md` (текущая база). Главная цель — ARGUS должен проводить **активный пентест** с применением **150+ Kali-инструментов**, каждый из которых вызывается по конкретной команде, результат нормализуется в `Finding`, все подтверждения и evidence попадают в отчёты HTML/PDF/JSON/CSV.

## 1. Глобальные архитектурные правила

1. Разделить **Control Plane** (FastAPI + Celery beat + Policy Engine + AI Orchestrator + Report Service) и **Execution Plane** (Kali sandbox runners). Взаимодействие только через очередь с типизированными `ToolJob`/`ValidationJob`/`ExploitJob`.
2. Убрать любые `docker.sock`, `docker exec host`, `shell=True`. Запуск инструментов — через `SandboxAdapter`, создающий **ephemeral Kubernetes Job** (`infra/k8s/sandbox-job.yaml`) или **Firecracker microVM** (fallback `infra/firecracker/*.json`). Политики: `seccomp=runtime/default`, `AppArmor`, `readOnlyRootFilesystem=true`, `runAsNonRoot=true`, `NET_RAW` только для инструментов, где явно объявлено, egress allowlist per-job.
3. LLM **никогда** не исполняет shell. LLM выбирает `tool_id`, `registry_family`, `payload_template_id`, `mutation_classes` — всё из подписанного `payload_registry` (Ed25519). Материализация команд — в `PayloadBuilder` (`backend/src/payloads/builder.py`).
4. Scope Engine обязателен: перед любым активным действием `ScopeEngine.assert_in_scope(target, tenant_id)` + `OwnershipProof.verified_at < 30d` (DNS TXT `_argus-verify=<token>`, HTTP `/.well-known/argus-verify.txt`, cloud IAM proof, signed authorization letter PDF хэш в БД).
5. Все активные/destructive действия — через **Approval Gate** с ed25519-подписью tenant admin (`ApprovalService.request` → SSE → UI → `/api/v1/approvals/{id}/sign`).
6. Все tool-запуски идут через **единый contract** `ToolAdapter` (см. §3). Ни одна команда не выполняется в обход реестра.
7. Каждый запуск инструмента порождает `tool_runs` row + объект в S3 `argus-stage{N}/` + `evidence` row + `scan_events` SSE-событие.
8. Каждое `Finding` обязано иметь минимум одно `Evidence` (raw output + parsed + reproducer + screenshot при UI-векторах).

## 2. 6-фазовая state machine — распределение инструментов

Реализуй в `backend/src/pipeline/state_machine.py` следующее распределение (каждая фаза — отдельная Celery-очередь):

- **Phase 1 — recon** (`recon` queue): passive OSINT + ownership verification + active port/service discovery.
- **Phase 2 — threat_modeling** (`analysis` queue): STRIDE/kill-chain, OWASP WSTG/ASVS, CWE/CAPEC/ATT&CK маппинг, next-step planner.
- **Phase 3 — vuln_analysis** (`va` queue): rule-based сканеры, fingerprinting, низкорисковые probes.
- **Phase 4 — exploitation** (`exploit` queue): только после approval, safe validators → confirmed exploits.
- **Phase 5 — post_exploitation** (`post` queue): доказательство impact без вредоносных действий (list privileges, enumerate reachable services, harmless marker write).
- **Phase 6 — reporting** (`reports` queue): 3 уровня (Midgard/Asgard/Valhalla) × 4 формата (HTML/PDF/JSON/CSV) + SARIF/JUnit.

Между фазами — `PhaseInput`/`PhaseOutput` с JSON Schema в `backend/src/pipeline/contracts/`.

## 3. Единый контракт `ToolAdapter`

Создай `backend/src/sandbox/adapter_base.py`:

```python
class ToolAdapter(Protocol):
    tool_id: str                      # "nmap", "nuclei", ...
    category: ToolCategory            # RECON, WEB_VA, CLOUD, ...
    phase: ScanPhase                  # recon | vuln_analysis | exploitation
    risk_level: RiskLevel             # passive | low | medium | high | destructive
    requires_approval: bool
    network_policy: NetworkPolicyRef  # egress allowlist template
    seccomp_profile: str
    default_timeout_s: int
    cpu_limit: str
    memory_limit: str

    def build_command(self, job: ToolJob) -> list[str]: ...
    def parse_output(self, raw_stdout: bytes, raw_stderr: bytes,
                     artifacts_dir: Path) -> list[Finding]: ...
    def collect_evidence(self, job: ToolJob, workdir: Path) -> list[Evidence]: ...
```

Реестр: `backend/src/sandbox/tool_registry.py` (pydantic-валидируемый YAML `backend/config/tools/*.yaml` + Ed25519 подпись в `backend/config/tools/SIGNATURES`). Приложение на старте валидирует подписи; при несовпадении — fail-closed.

## 4. КАТАЛОГ 150+ ИНСТРУМЕНТОВ С КОНКРЕТНЫМИ КОМАНДАМИ

Создай `backend/config/tools/*.yaml` по одному файлу на инструмент. Для каждого: `tool_id`, `phase`, `risk_level`, `requires_approval`, `command_template`, `parse_strategy`, `evidence_artifacts`, `cwe_hints`, `owasp_wstg`, `network_policy`. Ниже — исчерпывающий перечень. **Все инструменты обязаны использоваться**; ни один не может быть «задекларирован, но не вызван». CI-тест `tests/test_tool_catalog_coverage.py` падает, если `tool_id` не имеет ни одного интеграционного теста.

### 4.1 Passive recon / OSINT (17)
| tool_id | Команда (шаблон) | Phase |
|---|---|---|
| `amass_passive` | `amass enum -passive -d {domain} -json /out/amass.jsonl -timeout 20` | recon |
| `subfinder` | `subfinder -d {domain} -all -silent -oJ -o /out/subfinder.json` | recon |
| `assetfinder` | `assetfinder --subs-only {domain} > /out/assetfinder.txt` | recon |
| `findomain` | `findomain -t {domain} -u /out/findomain.txt` | recon |
| `chaos` | `chaos -d {domain} -o /out/chaos.txt -silent` (если есть `CHAOS_API_KEY`) | recon |
| `theharvester` | `theHarvester -d {domain} -b all -f /out/theharvester.json` | recon |
| `crt_sh` | `curl -s "https://crt.sh/?q=%25.{domain}&output=json" > /out/crtsh.json` | recon |
| `shodan_cli` | `shodan search --fields ip_str,port,org,hostnames 'hostname:{domain}' > /out/shodan.csv` | recon |
| `censys` | `censys search 'services.tls.certificates.leaf_data.names:{domain}' -o /out/censys.json` | recon |
| `securitytrails` | HTTP `GET /v1/domain/{domain}/subdomains` → `/out/securitytrails.json` | recon |
| `whois_rdap` | `whois {domain} > /out/whois.txt; curl -s https://rdap.org/domain/{domain} > /out/rdap.json` | recon |
| `dnsx` | `dnsx -l /in/subs.txt -a -aaaa -cname -mx -ns -txt -resp -json -o /out/dnsx.json` | recon |
| `dnsrecon` | `dnsrecon -d {domain} -t std,brt,srv,axfr -j /out/dnsrecon.json` | recon |
| `fierce` | `fierce --domain {domain} --json /out/fierce.json` | recon |
| `github_search` | via `gh api`: code/secret leak lookup for `{org}` | recon |
| `urlscan` | HTTP `POST /api/v1/scan/` `{url:{target}}` → poll → `/out/urlscan.json` | recon |
| `otx_alienvault` | HTTP `GET /api/v1/indicators/domain/{domain}/*` | recon |

### 4.2 Active recon / port & service (12)
| tool_id | Команда | Phase |
|---|---|---|
| `nmap_tcp_top` | `nmap -sS -Pn -T4 --top-ports 1000 -oX /out/nmap_tcp.xml {ip}` | recon |
| `nmap_tcp_full` | `nmap -sS -Pn -p- -T4 --min-rate 2000 -oX /out/nmap_full.xml {ip}` | recon |
| `nmap_udp` | `nmap -sU --top-ports 100 -oX /out/nmap_udp.xml {ip}` | recon |
| `nmap_version` | `nmap -sV -sC -p{ports} --script=default,safe -oX /out/nmap_v.xml {ip}` | recon |
| `nmap_vuln` | `nmap --script vuln -p{ports} -oX /out/nmap_vuln.xml {ip}` | vuln_analysis |
| `masscan` | `masscan -p1-65535 --rate 10000 -oJ /out/masscan.json {cidr}` | recon |
| `rustscan` | `rustscan -a {ip} --ulimit 5000 -- -sC -sV -oX /out/rustscan.xml` | recon |
| `naabu` | `naabu -host {ip} -p - -json -o /out/naabu.json` | recon |
| `unicornscan` | `unicornscan -mT {ip}:a -I -l /out/unicornscan.txt` | recon |
| `smbmap` | `smbmap -H {ip} -R -q > /out/smbmap.txt` | recon |
| `enum4linux_ng` | `enum4linux-ng -A -oJ /out/enum4linux.json {ip}` | recon |
| `rpcclient_enum` | `rpcclient -U "" -N {ip} -c "enumdomusers; enumdomgroups; querydominfo" > /out/rpc.txt` | recon |

### 4.3 TLS/SSL (6)
| tool_id | Команда | Phase |
|---|---|---|
| `testssl` | `testssl.sh --jsonfile /out/testssl.json --severity LOW {host}:{port}` | vuln_analysis |
| `sslyze` | `sslyze --json_out=/out/sslyze.json {host}:{port}` | vuln_analysis |
| `sslscan` | `sslscan --xml=/out/sslscan.xml {host}:{port}` | vuln_analysis |
| `ssl_enum_ciphers` (nmap) | `nmap --script ssl-enum-ciphers -p {port} {host} -oX /out/ssl_ciphers.xml` | vuln_analysis |
| `tlsx` | `tlsx -host {host} -port {port} -json -o /out/tlsx.json` | vuln_analysis |
| `mkcert_verify` | локальная проверка цепочки | vuln_analysis |

### 4.4 HTTP fingerprinting / tech stack (9)
| tool_id | Команда | Phase |
|---|---|---|
| `httpx` | `httpx -l /in/urls.txt -json -title -tech-detect -status-code -tls-probe -favicon -jarm -o /out/httpx.json` | recon |
| `whatweb` | `whatweb -a 3 --log-json /out/whatweb.json {url}` | recon |
| `wappalyzer_cli` | `wappalyzer {url} --pretty > /out/wappalyzer.json` | recon |
| `webanalyze` | `webanalyze -host {host} -output json > /out/webanalyze.json` | recon |
| `aquatone` | `cat /in/urls.txt \| aquatone -out /out/aquatone` (screens) | recon |
| `gowitness` | `gowitness file -f /in/urls.txt --destination /out/screens` | recon |
| `eyewitness` | `eyewitness -f /in/urls.txt -d /out/eyewitness --no-prompt --web` | recon |
| `favfreak` | favicon hash lookup → `/out/favfreak.json` | recon |
| `jarm` | `jarm -i /in/urls.txt -j /out/jarm.json` | recon |

### 4.5 Content/path discovery & fuzzing (10)
| tool_id | Команда | Phase |
|---|---|---|
| `ffuf_dir` | `ffuf -u {url}/FUZZ -w /wordlists/raft-large.txt -mc 200,204,301,302,307,401,403 -recursion -recursion-depth 2 -o /out/ffuf_dir.json -of json` | vuln_analysis |
| `ffuf_vhost` | `ffuf -u https://{ip} -H "Host: FUZZ.{domain}" -w /wordlists/subdomains-top1m.txt -mc all -fs {size} -o /out/ffuf_vhost.json -of json` | recon |
| `ffuf_param` | `ffuf -u "{url}?FUZZ=test" -w /wordlists/burp-parameter-names.txt -mc all -fs {size} -o /out/ffuf_param.json -of json` | vuln_analysis |
| `feroxbuster` | `feroxbuster -u {url} -w /wordlists/raft.txt -d 3 -x php,aspx,js,txt --json -o /out/ferox.json` | vuln_analysis |
| `gobuster_dir` | `gobuster dir -u {url} -w /wordlists/dirb-common.txt -x php,txt,html -o /out/gobuster.txt` | vuln_analysis |
| `dirsearch` | `dirsearch -u {url} -e php,aspx,js,html -o /out/dirsearch.json --format json` | vuln_analysis |
| `kiterunner` | `kr scan {url} -w /wordlists/routes-large.kite -o /out/kr.json` | vuln_analysis |
| `arjun` | `arjun -u {url} -oJ /out/arjun.json -m GET,POST` | vuln_analysis |
| `paramspider` | `paramspider -d {domain} -o /out/paramspider.txt` | recon |
| `wfuzz` | `wfuzz -c -z file,/wordlists/common.txt --hc 404 -o json {url}/FUZZ > /out/wfuzz.json` | vuln_analysis |

### 4.6 Crawler / JS / endpoint extraction (8)
| tool_id | Команда | Phase |
|---|---|---|
| `katana` | `katana -u {url} -jc -d 3 -rl 50 -json -o /out/katana.json` | recon |
| `gospider` | `gospider -s {url} -c 10 -d 3 --js --sitemap --robots -o /out/gospider --json` | recon |
| `hakrawler` | `echo {url} \| hakrawler -d 3 -subs > /out/hakrawler.txt` | recon |
| `waybackurls` | `echo {domain} \| waybackurls > /out/wayback.txt` | recon |
| `gau` | `gau --threads 5 --json {domain} > /out/gau.json` | recon |
| `linkfinder` | `linkfinder -i {url} -o cli > /out/linkfinder.txt` | recon |
| `subjs` | `subjs -i /in/urls.txt > /out/subjs.txt` | recon |
| `secretfinder` | `SecretFinder -i /in/js.txt -o /out/secretfinder.html` | vuln_analysis |

### 4.7 CMS / platform-specific (8)
| tool_id | Команда | Phase |
|---|---|---|
| `wpscan` | `wpscan --url {url} --api-token $WPVULN_TOKEN --enumerate vp,vt,tt,cb,dbe --format json --output /out/wpscan.json` | vuln_analysis |
| `joomscan` | `joomscan -u {url} -ec -o /out/joomscan.txt` | vuln_analysis |
| `droopescan` | `droopescan scan drupal -u {url} -o json > /out/droopescan.json` | vuln_analysis |
| `cmsmap` | `cmsmap {url} -o /out/cmsmap.txt` | vuln_analysis |
| `magescan` | `magescan scan:all {url} --format=json > /out/magescan.json` | vuln_analysis |
| `nextjs_check` | nuclei template `technologies/nextjs-*` | vuln_analysis |
| `spring_boot_actuator` | nuclei `exposures/configs/springboot-*` | vuln_analysis |
| `jenkins_enum` | nuclei `exposures/configs/jenkins-*` + `jenkins-cli` probe | vuln_analysis |

### 4.8 Web vulnerability scanners (7)
| tool_id | Команда | Phase |
|---|---|---|
| `nuclei` | `nuclei -l /in/urls.txt -severity low,medium,high,critical -t /nuclei-templates -jsonl -o /out/nuclei.jsonl -stats-json /out/nuclei_stats.json -rl 100` | vuln_analysis |
| `nikto` | `nikto -h {url} -Format json -o /out/nikto.json` | vuln_analysis |
| `wapiti` | `wapiti -u {url} -f json -o /out/wapiti.json --flush-session` | vuln_analysis |
| `arachni` | `arachni {url} --output-only-positives --report-save-path=/out/arachni.afr && arachni_reporter /out/arachni.afr --reporter=json:outfile=/out/arachni.json` | vuln_analysis |
| `skipfish` | `skipfish -o /out/skipfish -S /wordlists/skipfish/complete.wl {url}` | vuln_analysis |
| `w3af_console` | `w3af_console -s /scripts/full_audit.w3af` | vuln_analysis |
| `zap_baseline` | `zap-baseline.py -t {url} -J /out/zap.json -r /out/zap.html` | vuln_analysis |

### 4.9 SQL injection (6)
| tool_id | Команда | Phase |
|---|---|---|
| `sqlmap_safe` | `sqlmap -u "{url}" --batch --level 2 --risk 1 --technique=BT --safe-url={safe} --flush-session --output-dir=/out/sqlmap` | vuln_analysis |
| `sqlmap_confirm` | `sqlmap -u "{url}" --batch --technique=E --dbs --count --output-dir=/out/sqlmap_confirm` (approval) | exploitation |
| `ghauri` | `ghauri -u "{url}" --batch --level 2 --dbs -o /out/ghauri.txt` | vuln_analysis |
| `jsql` | `java -jar jsql.jar -u "{url}" --get-data --json > /out/jsql.json` | vuln_analysis |
| `tplmap` | `tplmap -u "{url}" --os-cmd=id --level 3 > /out/tplmap.txt` | vuln_analysis |
| `nosqlmap` | `nosqlmap --attack 2 -u {url} > /out/nosqlmap.txt` | vuln_analysis |

### 4.10 XSS (5)
| tool_id | Команда | Phase |
|---|---|---|
| `dalfox` | `dalfox url {url} --mining-dom --mining-dict --deep-domxss -o /out/dalfox.json -F json` | vuln_analysis |
| `xsstrike` | `xsstrike -u "{url}" --crawl --json-out /out/xsstrike.json` | vuln_analysis |
| `kxss` | `echo {url} \| kxss > /out/kxss.txt` | vuln_analysis |
| `xsser` | `xsser -u "{url}" --auto --Json /out/xsser.json` | vuln_analysis |
| `playwright_xss_verify` | headless Playwright → triggers canary `ARGUS_CANARY_{scan_id}` → `/out/playwright.json` + screenshot | validation |

### 4.11 SSRF / OAST / OOB (5)
| tool_id | Команда | Phase |
|---|---|---|
| `interactsh_client` | `interactsh-client -server https://oast.argus.local -json -o /out/interactsh.jsonl -v` | validation |
| `ssrfmap` | `ssrfmap -r /in/req.txt -p {param} -m readfiles,portscan -o /out/ssrfmap.txt` | vuln_analysis |
| `gopherus` | `gopherus --exploit mysql -o /out/gopher.txt` (template gen, dry) | vuln_analysis |
| `oast_dns_probe` | inject `{rand}.oast.argus.local` и корреляция callbacks | validation |
| `cloud_metadata_check` | целевой probe 169.254.169.254, gce, azure IMDS (только если scope permits + approval) | exploitation |

### 4.12 Auth / bruteforce / credential (10)
| tool_id | Команда | Phase |
|---|---|---|
| `hydra` | `hydra -L /in/users.txt -P /in/pass.txt -t 4 -I -f -o /out/hydra.txt {proto}://{host}:{port}` | exploitation (approval) |
| `medusa` | `medusa -h {host} -U /in/u.txt -P /in/p.txt -M {mod} -O /out/medusa.txt` | exploitation |
| `patator` | `patator {module} host={host} user=FILE0 password=FILE1 0=/in/u.txt 1=/in/p.txt -x ignore:code=401 > /out/patator.log` | exploitation |
| `ncrack` | `ncrack -U /in/u.txt -P /in/p.txt -oN /out/ncrack.txt {host}:{port}` | exploitation |
| `crackmapexec` | `crackmapexec smb {host} -u /in/u.txt -p /in/p.txt --shares --continue-on-success > /out/cme.txt` | exploitation |
| `kerbrute` | `kerbrute userenum --dc {dc} -d {domain} /in/u.txt -o /out/kerbrute.txt` | exploitation |
| `gobuster_auth` | `gobuster fuzz -u {url} -b 401 -w /in/u.txt -o /out/gbauth.txt` | vuln_analysis |
| `evil-winrm` (post) | `evil-winrm -i {host} -u {u} -p {p} -s /scripts/harmless.ps1` (post-exploitation, approval) | post_exploitation |
| `smbclient_check` | `smbclient -L \\\\{host} -U '{u}%{p}' > /out/smbclient.txt` | exploitation |
| `snmp-check` | `snmp-check -c {community} {host} > /out/snmp.txt` | vuln_analysis |

### 4.13 Password hashing/analysis (5)
| tool_id | Команда | Phase |
|---|---|---|
| `hashid` | `hashid -m /in/hashes.txt > /out/hashid.txt` | analysis |
| `hashcat` (dictionary only) | `hashcat -m {mode} -a 0 /in/hashes.txt /wordlists/rockyou.txt --status --outfile /out/hashcat.txt` | post (approval + offline) |
| `john` | `john --wordlist=/wordlists/rockyou.txt --format={fmt} /in/hashes.txt --pot=/out/john.pot` | post (approval) |
| `ophcrack` | rainbow-table lookup (offline) | post |
| `hash_analyzer` | internal entropy/policy checker | analysis |

### 4.14 API / GraphQL / gRPC (7)
| tool_id | Команда | Phase |
|---|---|---|
| `openapi_scanner` | внутренний Semgrep-like обход OpenAPI → nuclei api-templates | vuln_analysis |
| `graphw00f` | `graphw00f -d -t {url} -o /out/graphw00f.json` | recon |
| `clairvoyance` | `clairvoyance {url}/graphql -o /out/clairvoyance.json` | vuln_analysis |
| `inql` | `inql -t {url}/graphql -o /out/inql.json` | vuln_analysis |
| `graphql-cop` | `graphql-cop -t {url}/graphql -o json > /out/graphqlcop.json` | vuln_analysis |
| `grpcurl_probe` | `grpcurl -plaintext {host}:{port} list > /out/grpc.txt` | recon |
| `postman_newman` | `newman run /in/collection.json -r json --reporter-json-export /out/newman.json` | vuln_analysis |

### 4.15 Cloud / IaC / container (12)
| tool_id | Команда | Phase |
|---|---|---|
| `prowler` | `prowler aws -M json -o /out/prowler.json --profile {profile}` | vuln_analysis |
| `scoutsuite` | `scout aws --report-dir /out/scoutsuite --no-browser` | vuln_analysis |
| `cloudsploit` | `cloudsploit scan --config /in/aws.js --json /out/cloudsploit.json` | vuln_analysis |
| `pacu` | `pacu --session {s} --module iam__enum_permissions` (approval) | exploitation |
| `trivy_image` | `trivy image --format json -o /out/trivy.json {image}` | vuln_analysis |
| `trivy_fs` | `trivy fs --format json -o /out/trivy_fs.json /in/repo` | vuln_analysis |
| `grype` | `grype {image} -o json > /out/grype.json` | vuln_analysis |
| `syft` | `syft {image} -o cyclonedx-json > /out/sbom.json` | vuln_analysis |
| `dockle` | `dockle -f json -o /out/dockle.json {image}` | vuln_analysis |
| `kube-bench` | `kube-bench --json > /out/kubebench.json` | vuln_analysis |
| `kube-hunter` | `kube-hunter --remote {host} --report json --log none > /out/kubehunter.json` | vuln_analysis |
| `checkov` | `checkov -d /in/iac -o json > /out/checkov.json` | vuln_analysis |

### 4.16 IaC / code / secrets (8)
| tool_id | Команда | Phase |
|---|---|---|
| `terrascan` | `terrascan scan -i terraform -d /in/iac -o json > /out/terrascan.json` | vuln_analysis |
| `tfsec` | `tfsec /in/iac --format json > /out/tfsec.json` | vuln_analysis |
| `kics` | `kics scan -p /in/iac -o /out --report-formats json` | vuln_analysis |
| `semgrep` | `semgrep ci --config=p/ci --config=p/owasp-top-ten --json -o /out/semgrep.json` | vuln_analysis |
| `bandit` | `bandit -r /in/src -f json -o /out/bandit.json` | vuln_analysis |
| `gitleaks` | `gitleaks detect -s /in/repo -r /out/gitleaks.json -f json` | vuln_analysis |
| `trufflehog` | `trufflehog filesystem /in/repo --json > /out/trufflehog.json` | vuln_analysis |
| `detect-secrets` | `detect-secrets scan /in/repo > /out/detect-secrets.json` | vuln_analysis |

### 4.17 Network / protocol-specific (10)
| tool_id | Команда | Phase |
|---|---|---|
| `responder` (dry-run) | `responder -I eth0 -A` (ловушка, только если segment в scope + approval) | exploitation |
| `impacket_secretsdump` | `impacket-secretsdump {dom}/{u}:{p}@{host} -just-dc-user {u} > /out/sd.txt` | post (approval) |
| `ntlmrelayx` | `ntlmrelayx.py -tf /in/targets.txt -smb2support` (approval) | exploitation |
| `bloodhound_python` | `bloodhound-python -u {u} -p {p} -d {domain} -c all -ns {dc} --zip` | post (approval) |
| `ldapsearch` | `ldapsearch -x -H ldap://{host} -b "dc={d}" > /out/ldap.txt` | recon |
| `snmpwalk` | `snmpwalk -v2c -c {community} {host} > /out/snmp.txt` | recon |
| `onesixtyone` | `onesixtyone -c /wordlists/snmp.txt {host} > /out/o161.txt` | recon |
| `ike-scan` | `ike-scan -M {host} > /out/ike.txt` | recon |
| `redis-cli_probe` | `redis-cli -h {host} -p {port} --no-auth-warning INFO > /out/redis.txt` | recon |
| `mongodb_probe` | `mongo {host}:{port}/admin --eval "db.runCommand({buildinfo:1})" > /out/mongo.txt` | recon |

### 4.18 Binary / mobile / misc (5)
| tool_id | Команда | Phase |
|---|---|---|
| `mobsf_api` | HTTP `POST /api/v1/upload` + `/scan` → `/report_json` → `/out/mobsf.json` | vuln_analysis |
| `apktool` | `apktool d /in/app.apk -o /out/apk` | vuln_analysis |
| `jadx` | `jadx -d /out/jadx /in/app.apk` | vuln_analysis |
| `binwalk` | `binwalk -e -M /in/firmware.bin --directory=/out/bw` | vuln_analysis |
| `radare2_info` | `r2 -q -c "iI~canary,pic,nx" /in/bin > /out/r2.txt` | vuln_analysis |

### 4.19 Browser-based & OAST verifiers (5)
| tool_id | Команда | Phase |
|---|---|---|
| `playwright_runner` | Node runner запускает `/scripts/verify_xss.js`, `/verify_csrf.js`, `/verify_clickjack.js` | validation |
| `puppeteer_screens` | headless screenshot on confirmed finding | validation |
| `chrome_csp_probe` | внутренняя проверка CSP bypass через DOM injection + canary | validation |
| `cors_probe` | `curl -H "Origin: https://evil.{rand}.oast" ...` → корреляция | vuln_analysis |
| `cookie_probe` | парсер Set-Cookie, флаги Secure/HttpOnly/SameSite | vuln_analysis |

**Итого ≥ 150 tool_id.** Каталог расширяем: добавление нового — PR в `backend/config/tools/*.yaml` + подпись + тест.

## 5. Payload Registry + PayloadBuilder

`backend/config/payloads/*.yaml` — подписанные семейства:
`sqli.boolean.diff.v3`, `sqli.time.blind.v2`, `sqli.error.mysql.v2`, `sqli.error.mssql.v2`, `xss.reflected.canary.v3`, `xss.dom.canary.v2`, `xss.stored.canary.v1`, `ssrf.oast.redirect.v1`, `ssrf.oast.gopher.v1`, `rce.oast.dns.v1`, `rce.oast.http.v1`, `lfi.sentinel.etc.v1`, `lfi.sentinel.wrapper.v1`, `xxe.oast.v1`, `ssti.marker.v1`, `nosqli.bool.v1`, `ldapi.bool.v1`, `cmdi.oast.v1`, `xxe.dtd.v1`, `cors.origin.v1`, `openredirect.canary.v1`, `csrf.marker.v1`, `prototype_pollution.v1`.

`PayloadBuilder.materialize(family, mutation_classes, canary_token, context)` возвращает финальный payload **внутри sandbox**. LLM не видит финальный payload; он выбирает `family` и `mutation_classes` ∈ {`canonicalization`, `context_encoding`, `length_variation`, `case_normalization`, `charset_shift`, `waf_detour_lite`}.

## 6. AI Orchestrator + ValidationPlanV1

`backend/src/orchestrator/`: `planner.py`, `critic.py`, `verifier.py`, `reporter.py`. Цикл:

```
ingest normalized findings
 → planner.select_next_actions()        # LLM: strict JSON (ValidationPlanV1)
 → policy_engine.check(plan)            # scope, risk, approval, rate
 → dispatcher.enqueue(tool_jobs/validation_jobs)
 → sandbox runners execute
 → critic.evaluate(evidence)            # FP detection, confidence score
 → verifier.reproduce()                 # replay from canary + PoC
 → reporter.enrich(findings)            # remediation, prioritization
```

**ValidationPlanV1 JSON Schema** (`backend/src/orchestrator/schemas/validation_plan_v1.json`):

```json
{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "type":"object",
  "required":["hypothesis","risk","payload_strategy","validator","approval_required","evidence_to_collect","remediation_focus"],
  "properties":{
    "hypothesis":{"type":"string","minLength":8,"maxLength":500},
    "risk":{"enum":["low","medium","high","critical"]},
    "payload_strategy":{
      "type":"object",
      "required":["registry_family","mutation_classes","raw_payloads_allowed"],
      "properties":{
        "registry_family":{"type":"string","pattern":"^[a-z_]+\\.[a-z_]+(\\.[a-z0-9_]+)+\\.v[0-9]+$"},
        "mutation_classes":{"type":"array","items":{"enum":["canonicalization","context_encoding","length_variation","case_normalization","charset_shift","waf_detour_lite"]}},
        "raw_payloads_allowed":{"const":false}
      }
    },
    "validator":{
      "type":"object",
      "required":["tool","inputs","success_signals","stop_conditions"],
      "properties":{
        "tool":{"enum":["safe_validator","browser_validator","oast_canary","payload_registry"]},
        "inputs":{"type":"object"},
        "success_signals":{"type":"array","items":{"type":"string"}},
        "stop_conditions":{"type":"array","items":{"type":"string"}}
      }
    },
    "approval_required":{"type":"boolean"},
    "evidence_to_collect":{"type":"array","items":{"type":"string"}},
    "remediation_focus":{"type":"array","items":{"type":"string"}}
  }
}
```

**Prompt Registry** (`backend/src/prompts/registry/`): файлы `system.yaml`, `developer.yaml`, и по каждому типу уязвимости: `sqli.yaml`, `xss.yaml`, `rce.yaml`, `lfi.yaml`, `ssrf.yaml`, `ssti.yaml`, `xxe.yaml`, `nosqli.yaml`, `ldapi.yaml`, `cmdi.yaml`, `openredirect.yaml`, `csrf.yaml`, `cors.yaml`, `auth.yaml`, `idor.yaml`, `jwt.yaml`. Каждый prompt содержит `system`/`developer`/`context_template` + `retry_fixer` + `schema_ref: validation_plan_v1`. Используй тексты prompt'ов из `codex.md` §3 (SQLi/XSS/RCE/LFI/SSRF) дословно, остальные — по той же структуре.

**Fallback/retry**: при невалидном JSON → `retry_fixer_prompt` + provider rotation (openai → deepseek → openrouter → gemini → kimi → perplexity) по `backend/src/llm/router.py`.

## 7. OAST/Canary infrastructure

`@ARGUS/infra/oast/` — deployment `interactsh-server` (DNS/HTTP/SMTP listeners) под субдомен `oast.argus.local` (prod: `oast.<tenant>.argus.cloud`). Каждому scan выдаётся `canary_token = hex(16) + tenant_hash8`. `OastCorrelator` (`backend/src/oast/correlator.py`) сопоставляет callbacks с `ToolRun.id`, пишет `Evidence(type=oast_callback)` и триггерит `finding.confidence = confirmed`.

Используй `interactsh_client` для SSRF/RCE/Blind-XSS/DNS-probe. Fallback — собственный `ArgusCanaryServer` (FastAPI endpoint `/c/{token}`) для HTTP-only callbacks.

## 8. Policy Engine + Approval Gate

`backend/src/policy/engine.py`:

```python
class PolicyDecision(BaseModel):
    allow: bool
    reason: str
    requires_approval: bool
    approvers_required: int
    max_rps: int
    maintenance_window_ok: bool
```

Правила (YAML `backend/config/policy/*.yaml`):
- `risk_level in {high, destructive}` → `requires_approval=true, approvers_required >= 1 tenant_admin`.
- `target` должен пройти `ScopeEngine.assert(target, tenant_id)`. Out-of-scope → hard deny + `audit_logs`.
- `rate_limit`: per-target RPS, per-tenant scans concurrency.
- `maintenance_window`: cron-выражение на tenant.
- `kill_switch`: tenant admin может остановить все scans одним вызовом.

`ApprovalService` (`backend/src/approvals/service.py`) создаёт `ApprovalRequest` с JSON diff планируемых действий, отправляет SSE + email + webhook, принимает Ed25519 подпись (`/api/v1/approvals/{id}/sign` body: `{signature, public_key_id}`), хранит в `approvals` table, проверяет против tenant public keys.

## 9. Sandbox runtime

`@ARGUS/sandbox/`:
- `sandbox/images/argus-kali-full/Dockerfile` — базовый образ с 150+ инструментами (multi-stage, pinned versions, SBOM `syft -o cyclonedx-json`).
- `sandbox/images/argus-kali-web/Dockerfile` — slim (web-only инструменты).
- `sandbox/images/argus-kali-cloud/Dockerfile` — только cloud/IaC.
- `sandbox/images/argus-browser/Dockerfile` — Playwright + Chromium.
- `infra/k8s/sandbox-job.yaml` — Job template с `runtimeClassName: kata-clh` (Kata Containers) + resource limits + NetworkPolicy per-tool-category.
- `backend/src/sandbox/k8s_driver.py` — driver, создаёт Job, стримит logs, собирает `/out`, загружает в S3 `argus-stage3/<scan_id>/<tool_run_id>/`.
- `backend/src/sandbox/firecracker_driver.py` — fallback.
- **Нет** `docker.sock`, **нет** privileged, **нет** hostPath кроме read-only `/wordlists` из CSI.

## 10. Evidence & Finding model

`backend/src/models/finding.py`:

```python
class Finding(Base):
    id: UUID
    tenant_id: UUID
    scan_id: UUID
    asset_id: UUID
    tool_run_id: UUID
    category: FindingCategory           # sqli/xss/rce/...
    cwe: list[int]
    cvss_v3_vector: str
    cvss_v3_score: float
    epss_score: float | None
    kev_listed: bool
    ssvc_decision: SSVCDecision
    owasp_wstg: list[str]
    mitre_attack: list[str]
    confidence: ConfidenceLevel          # suspected|likely|confirmed|exploitable
    status: FindingStatus                # new|validated|false_positive|accepted_risk|fixed
    evidence_ids: list[UUID]
    reproducer: ReproducerSpec           # strict non-destructive
    remediation: Remediation
    first_seen: datetime
    last_seen: datetime
```

`Evidence`:
```python
class Evidence(Base):
    id: UUID
    finding_id: UUID
    tool_run_id: UUID
    kind: EvidenceKind                   # raw_output|parsed|screenshot|pcap|oast_callback|video|har|diff
    s3_key: str
    sha256: str
    redactions: list[RedactionSpec]      # secrets, tokens, cookies
    created_at: datetime
```

**Normalizer** (`backend/src/findings/normalizer.py`): на каждый tool output → 0..N Findings с дедупликацией по `(asset, endpoint, parameter, category, root_cause_hash)`. Correlator связывает в цепочки (kill-chain).

**Prioritizer** (`backend/src/findings/prioritizer.py`): CVSS + EPSS + KEV + SSVC → `priority_score`. Для приоритизации подтяни EPSS (`https://epss.cyentia.com`) и KEV (`https://www.cisa.gov/known-exploited-vulnerabilities-catalog`) с кэшированием 24h.

## 11. Reporting

`backend/src/reports/`:
- `generators/html.py`, `pdf.py` (WeasyPrint), `json.py`, `csv.py`, `sarif.py`, `junit.py`.
- Шаблоны `backend/templates/reports/midgard/`, `asgard/`, `valhalla/`.
- **Каждая находка** обязана иметь в отчёте:
  1. Summary + CWE/CVSS/EPSS/KEV/SSVC.
  2. Affected asset + endpoint.
  3. **Reproducer**: безопасная команда/HTTP-запрос с canary, без вредоносной нагрузки.
  4. **Evidence block**: presigned URL на raw output, parsed JSON, screenshot, OAST callback trace, HAR, diff.
  5. **Remediation**: конкретные code/config fixes + ссылки OWASP/WSTG/ASVS.
  6. **Timeline**: какие tools её нашли и в какой последовательности.
- `ReportService.generate(scan_id, tier, format)` → `reports` row + S3 object + presigned URL (SSE event `report.ready`).
- `replay_command_sanitizer.py` — выбрасывает secrets/реверс-шеллы/destructive flags, прежде чем положить в отчёт.

## 12. SSE события (не менять контракт с Frontend)

`/api/v1/scans/{id}/events`:
- `scan.phase.started` / `scan.phase.completed`
- `tool.run.started` / `tool.run.completed` / `tool.run.failed`
- `finding.new` / `finding.updated` / `finding.confirmed`
- `approval.requested` / `approval.granted` / `approval.denied`
- `oast.callback.received`
- `report.generating` / `report.ready`

## 13. MCP server

`@ARGUS/backend/src/mcp/server.py` (FastMCP, stdio + optional SSE/HTTP) — tools:
- `scan.create`, `scan.status`, `scan.cancel`
- `findings.list`, `findings.get`, `findings.mark_false_positive`
- `approvals.list`, `approvals.sign`
- `tool.catalog.list`, `tool.run.trigger`, `tool.run.status`
- `report.generate`, `report.download`
- `scope.verify`, `policy.evaluate`

Все — typed Pydantic schemas, tenant-scoped, audit-logged.

## 14. Admin Frontend

`@ARGUS/admin-frontend/` (Next.js) — страницы: tenants, users, subscriptions, providers (API keys health), policies, audit logs, usage metering, queue/storage/provider health, tool catalog coverage, approval inbox. Только чтение/управление метаданными. Не трогает `@ARGUS/Frontend`.

## 15. Observability

- OpenTelemetry: spans на каждый tool_run, LLM-call, policy-decision, approval.
- Prometheus: `argus_tool_runs_total{tool,category,status}`, `argus_findings_total{category,confidence}`, `argus_oast_callbacks_total`, `argus_llm_tokens_total{provider}`, `argus_scan_duration_seconds`, `argus_queue_depth`.
- Structured JSON logs с `scan_id`, `tool_run_id`, `tenant_id`, `correlation_id`.
- `/health`, `/ready`, `/metrics`, `/providers/health`, `/queues/health`.

## 16. Порядок реализации (строго по шагам)

1. **Контракты**: `backend/src/pipeline/contracts/*.py`, JSON Schemas, `validation_plan_v1.json`.
2. **Tool registry & YAMLs**: все 150+ файлов `backend/config/tools/*.yaml` с командами из §4 + Ed25519 signer/verifier.
3. **SandboxAdapter (k8s + firecracker)** + ephemeral Job template.
4. **ToolAdapter реализации** — по группам §4.1-§4.19, по адаптеру на tool_id, общий `ShellToolAdapter` + специфичные парсеры.
5. **PayloadRegistry + PayloadBuilder**.
6. **OAST infra + correlator**.
7. **PolicyEngine + ScopeEngine + OwnershipProof + ApprovalService**.
8. **AI Orchestrator**: planner/critic/verifier/reporter + prompt registry + provider router + retry/fixer.
9. **Findings normalizer + correlator + prioritizer** (EPSS/KEV/SSVC).
10. **Evidence pipeline + redaction**.
11. **ReportService** (Midgard/Asgard/Valhalla × HTML/PDF/JSON/CSV + SARIF/JUnit).
12. **SSE events + API endpoints** (без изменений контракта с Frontend).
13. **MCP server**.
14. **Admin frontend**.
15. **Observability (OTel/Prom/logs/health)**.
16. **Docs**: обнови все файлы из `@ARGUS/docs/` (frontend-api-contract, backend-architecture, erd, scan-state-machine, prompt-registry, provider-adapters, security-model, deployment) + добавь `@ARGUS/docs/tool-catalog.md` с таблицей всех 150+ tool_id, команд, категорий, approvals.

## 17. Тесты (обязательны, без них PR не мержить)

- `tests/unit/` — unit для каждого парсера, PolicyEngine правил, PayloadBuilder mutations, Normalizer дедупликации.
- `tests/contract/` — соответствие API Frontend-у (golden JSON).
- `tests/integration/tool_runs/` — по одному smoke-тесту на каждый tool_id с мок-таргетом (vulhub контейнеры, OWASP Juice Shop, DVWA, WebGoat, HackMe CMS). CI-matrix.
- `tests/integration/oast/` — end-to-end SSRF blind + XSS blind + RCE DNS callback.
- `tests/integration/approval_flow.py` — full cycle: plan → policy → approval → signed → execute → evidence → report.
- `tests/integration/reports/` — все 12 комбинаций (3 tier × 4 format), snapshot-тесты HTML/JSON/CSV, structural PDF check.
- `tests/rls/` — cross-tenant изоляция (каждая таблица).
- `tests/security/` — фаззинг командных шаблонов, проверка отсутствия `shell=True`, отсутствие docker.sock, seccomp validation.
- `tests/test_tool_catalog_coverage.py` — каждый `tool_id` имеет: yaml + adapter + unit test + integration test + упоминание в `docs/tool-catalog.md` + подпись валидна.

## 18. Critical guardrails

- LLM генерирует shell, видит secrets, видит сырой payload.
- Ни один destructive инструмент не запускается без approval и без `ScopeEngine` allow.
- `shell=True`, конкатенации строк в команду — только `list[str]` + `argparse`-safe templating (`backend/src/sandbox/templating.py` с allowlist placeholders `{url}`, `{host}`, `{port}`, `{domain}`, `{ip}`, `{cidr}`, `{params}`, `{wordlist}`, `{canary}`, `{out_dir}`, `{in_dir}`; любое другое — reject).
- Все secrets через K8s `Secret` + CSI mount, в env процесса LLM.
- Rate limiter per-target + per-tenant + global kill-switch.
- Audit log append-only (PostgreSQL + hash chain: `prev_hash || row_hash`).

## 19. Definition of Done

Фича считается готовой только если:
1. `pytest -q` зелёный, coverage ≥ 85% для `backend/src/sandbox`, `backend/src/policy`, `backend/src/findings`, `backend/src/reports`.
2. `ruff`, `mypy --strict`, `bandit -q -r backend/src` — без ошибок.
3. `alembic upgrade head && alembic downgrade -1 && alembic upgrade head` проходит.
4. `docker compose -f infra/docker-compose.yml up -d` поднимает стек; smoke e2e `scripts/e2e_full_scan.sh http://juice-shop:3000` завершается успешно и создаёт все 12 отчётов с хотя бы одной confirmed-находкой с OAST evidence.
5. `@ARGUS/Frontend` без изменений получает SSE и отображает прогресс/отчёты.
6. `docs/tool-catalog.md` содержит **≥ 150** строк, все `tool_id` подписаны и протестированы.
7. Ни одного упоминания hexstrike/legacy в коде/логах/UI/env/docs.

---

## 20. Формат ответа Cursor на каждом шаге

Cursor должен:
1. Вывести список файлов, которые собирается создать/изменить.
2. Сделать изменения атомарными коммитами `feat(sandbox): ...`, `feat(tools): add nmap adapter`, `feat(oast): ...`.
3. После каждого коммита — прогнать соответствующие тесты и показать вывод.
4. В конце раунда — обновить `docs/tool-catalog.md` и `CHANGELOG.md`, показать diff.

Начни прямо сейчас с шага **16.1 (контракты)** и **16.2 (tool registry + YAMLs первых 30 инструментов из §4.1, §4.2, §4.3)**. Дальше — по плану §16 до полного закрытия каталога и DoD §19.

---

## ЗАПРЕЩЕНО
1. Менять frontend
2. Нарушать существующие API-контракты для frontend