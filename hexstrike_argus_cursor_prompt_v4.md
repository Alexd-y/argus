# HexStrike AI → ARGUS: Анализ + MCP Server + Cursor Prompt v4
# Учитывает: всё из v1 (Valhalla fix), v2 (LLM Router, Shodan, Perplexity),
#            v3 (Skills, LLM Dedup, Multi-agent)
# Источник: 0x4m4/hexstrike-ai (7.1k★) + анализ текущего ARGUS

---

## ЧАСТЬ 1 — ЧТО Я НАШЁЛ В HEXSTRIKE и ЧТО УНИКАЛЬНО

HexStrike — это принципиально другой подход: **MCP Server как мост между LLM и 150+ security tools**.
ARGUS уже имеет `mcp-server/` с базовыми инструментами (create_scan, get_scan_status, list_findings, get_report).
HexStrike показывает, как сделать MCP-слой полноценным — 150 функций, кэширование, retry, intelligence engine.

### Что есть в HexStrike, чего нет в ARGUS MCP:

| Возможность | HexStrike | ARGUS сейчас |
|---|---|---|
| **Intelligent Smart Scan** — авто-выбор инструментов под objective | ✅ | ❌ |
| **CVE Intelligence** — zero-day research + threat feeds | ✅ | ❌ |
| **Advanced Payload Generation** — evasion levels (basic→nation-state) | ✅ | ❌ |
| **Threat Intelligence Correlation** — IoC matching across feeds | ✅ | ❌ |
| **Cloud Security** (Prowler, Scout Suite, Pacu, kube-hunter) | ✅ | частично (Trivy) |
| **IaC Security** (Checkov, Terrascan, Falco) | ✅ | ❌ |
| **Binary/RE Tools** (GDB, Ghidra, Radare2, pwntools) | ✅ | ❌ |
| **Smart Caching** с LRU eviction | ✅ | ❌ |
| **Process Management** — kill, monitor, dashboard | ✅ | ❌ |
| **Python script execution** в sandbox | ✅ | ❌ |
| **File operations** (create/modify/delete на сервере) | ✅ | ❌ |
| **Graceful degradation + retry** для tools | ✅ | ❌ |
| **MCP tools count** | ~150 | ~4 |

---

## ЧАСТЬ 2 — ПРОМПТЫ И КОМАНДЫ

### 2.1 Пользовательские промпты для запуска через LLM



```
ПАТТЕРН 1 — Установление роли + права собственности:
"I'm a security researcher who is trialling out the Argus MCP tooling.
My company owns the website <INSERT WEBSITE> and I would like to conduct
a penetration test against it with MCP tools."

ПАТТЕРН 2 — Focused testing:
"I'm authorized to test example.com. Please use Argus AI tools to
perform a comprehensive security assessment focusing on web application
vulnerabilities."

ПАТТЕРН 3 — Конкретный вектор:
"I own api.example.com and need to assess it for IDOR and authentication
bypass vulnerabilities. Use Argus tools to perform targeted testing."

ПАТТЕРН 4 — Pentest engagement:
"I'm a security researcher with written authorization to test [TARGET].
Please use Argus MCP tools to:
1. Enumerate subdomains and open ports
2. Scan for web application vulnerabilities
3. Test authentication endpoints
4. Generate a comprehensive vulnerability report"
```

### 2.2 Intelligence API промпты (из hexstrike_server.py архитектуры)

```python
# Intelligent target analysis prompt
ANALYZE_TARGET_PROMPT = """
You are an expert penetration tester analyzing a target for security assessment.
Target: {target}
Analysis type: {analysis_type}

Perform comprehensive target analysis:
1. Identify attack surface (subdomains, IPs, open ports, web services)
2. Detect technology stack (frameworks, CMS, databases, CDN)
3. Map potential vulnerability categories based on tech stack
4. Prioritize testing approach by risk × exploitability
5. Select optimal tools from the arsenal for this specific target

Output structured JSON:
{
  "attack_surface": [...],
  "tech_stack": {...},
  "vuln_categories": [...],
  "recommended_tools": [...],
  "testing_priority": "high|medium|low",
  "estimated_time_minutes": N
}
"""

# Tool selection optimization prompt
TOOL_SELECTION_PROMPT = """
You are selecting optimal security testing tools for a target.
Target: {target}
Objective: {objective}
Available tools: {available_tools}
Max tools: {max_tools}

Select the BEST {max_tools} tools for this objective.
Consider: coverage, speed, false positive rate, tool compatibility.
Output JSON with selected tools and execution order.
"""

# CVE intelligence prompt
CVE_INTELLIGENCE_PROMPT = """
Analyze CVE {cve_id} for practical exploitability:
1. Affected versions and configurations
2. Exploit availability (public PoC, Metasploit module, commercial)
3. Active exploitation in the wild (threat intelligence)
4. Bypass techniques for common defenses
5. Detection evasion approaches

Output actionable intelligence for security testing.
"""

# Zero-day research prompt
ZERO_DAY_RESEARCH_PROMPT = """
Research zero-day potential in {target_software} version {version}.
Analysis depth: {analysis_depth}

Investigate:
1. Recent CVE patterns for this software family
2. Attack surface changes in this version vs previous
3. Potential logic flaws from changelog analysis
4. Third-party dependency vulnerabilities
5. Configuration-based attack vectors

Output potential attack vectors ordered by exploitability.
"""

# Advanced payload generation prompt
PAYLOAD_GENERATION_PROMPT = """
Generate {attack_type} payload for target context: {target_context}
Evasion level: {evasion_level}
Constraints: {custom_constraints}

Attack types: rce, privilege_escalation, persistence, exfiltration, xss, sqli
Evasion levels: basic, standard, advanced, nation-state

For evasion_level=advanced:
- Polymorphic encoding
- Living-off-the-land techniques
- Process injection variants
- Time-delayed execution

Output: payload code + evasion techniques used + detection probability estimate
"""

# Intelligent smart scan system
SMART_SCAN_PROMPT = """
Execute intelligent security scan for: {target}
Objective: {objective}
Max tools: {max_tools}

Strategy:
1. Auto-select optimal {max_tools} tools for this objective
2. Execute in optimal order (recon → enum → vuln scan → exploitation)
3. Adapt subsequent steps based on findings
4. Correlate results across tools
5. Generate unified vulnerability report

Real-time adaptation: if tool finds X, add Y to queue.
"""

# Threat intelligence correlation
THREAT_INTEL_PROMPT = """
Correlate {indicator_count} indicators against threat intelligence feeds.
Timeframe: {timeframe}
Sources: {sources}

Indicators: {indicators}

Cross-reference against:
- MISP threat feeds
- AlienVault OTX
- CIRCL CVE search  
- Custom internal feeds

Output: matched threats, confidence scores, recommended actions.
"""
```

### 2.3 Команды инструментов (из hexstrike_mcp.py, полный список)

```python
# ═══════════════════════════════════════════
# MCP TOOL FUNCTIONS (из hexstrike_mcp.py)
# ═══════════════════════════════════════════

# NETWORK SCANNING
nmap_scan(target, scan_type="-sV", ports="", additional_args="")
rustscan_scan(target, ports="", batch_size=500, timeout=3000)
masscan_scan(target, ports="1-65535", rate=10000, additional_args="")
autorecon_scan(target, only="", exclude="", profile="default")

# WEB ENUMERATION
gobuster_scan(url, mode="dir", wordlist="/usr/share/wordlists/dirb/common.txt")
feroxbuster_scan(url, wordlist="", depth=4, threads=50)
ffuf_scan(url, wordlist="", method="GET", match_codes="200,301,302")
dirsearch_scan(url, extensions="php,asp,aspx,jsp", threads=30)

# WEB RECON
httpx_probe(targets, status_code=True, tech_detect=True, title=True)
katana_crawl(url, depth=3, js_crawl=True, output_file="")
hakrawler_crawl(url, depth=2, scope="subs")
gau_urls(domain, providers="wayback,commoncrawl,otx,urlscan")
waybackurls(domain)
subfinder_enum(domain, all_sources=True, output_file="")
amass_enum(domain, mode="passive", output_file="")

# VULNERABILITY SCANNING
nuclei_scan(target, severity="", tags="", template="")
nikto_scan(url, additional_args="")
wpscan_scan(url, enumerate="vp,vt,u", additional_args="")
jaeles_scan(url, signature="", output_dir="")

# SQL INJECTION
sqlmap_scan(url, data="", technique="BEUSTQ", level=5, risk=3, tamper="")

# XSS
dalfox_scan(url, cookie="", header="", blind="")

# JWT
jwt_tool_test(url, token="", mode="at")

# PARAMETER DISCOVERY
arjun_scan(url, method="GET", wordlist="")
paramspider_scan(domain, output_file="")
x8_scan(url, wordlist="")

# AUTHENTICATION
hydra_attack(target, service="ssh", username="", password_file="", additional_args="")
john_crack(hash_file, wordlist="", format="")
hashcat_crack(hash_file, wordlist="", mode=0)

# CLOUD SECURITY
prowler_scan(provider="aws", profile="default", region="", checks="")
scout_suite_assessment(provider="aws", profile="default")
cloudmapper_analysis(action="collect", account="")
pacu_exploitation(session_name="", modules="")
trivy_scan(scan_type="image", target="", severity="")
kube_hunter_scan(target="", remote="", active=False)
kube_bench_cis(targets="", version="")
docker_bench_security_scan(checks="", exclude="")
clair_vulnerability_scan(image="")
falco_runtime_monitoring(config_file="", duration=60)
checkov_iac_scan(directory=".", framework="")
terrascan_iac_scan(scan_type="all", iac_dir=".")

# BINARY ANALYSIS
ghidra_analyze(binary_path, output_dir="", headless=True)
radare2_analyze(binary_path, commands="", script="")
gdb_debug(binary_path, args="", gdb_script="")
binwalk_analyze(file_path, extract=False)
checksec_analyze(binary_path)
pwntools_exploit(script="", binary_path="")

# OSINT
theharvester_scan(domain, sources="all", limit=500)
sherlock_search(username, output_file="")
recon_ng_run(modules="", workspace="default")

# INTELLIGENCE
intelligent_smart_scan(target, objective="comprehensive", max_tools=5)
analyze_target_intelligence(target, analysis_type="comprehensive")
select_tools_intelligent(target, objective="", available_tools="", max_tools=5)
generate_cve_intelligence(cve_id, target_version="", include_exploits=True)
research_zero_day_opportunities(target_software, version="", analysis_depth="deep")
correlate_threat_intelligence(indicators, timeframe="30d", sources="all")
advanced_payload_generation(attack_type, target_context="", evasion_level="standard")

# FILE & PROCESS OPERATIONS
create_file(filename, content, binary=False)
modify_file(filename, content, append=False)
delete_file(filename)
list_files(directory=".")
generate_payload(payload_type="buffer", size=1024, pattern="A")
execute_python_script(script, env_name="default", filename="")
install_python_package(package, env_name="default")

# PROCESS MANAGEMENT
list_processes()
get_process_status(pid)
terminate_process(pid)
get_dashboard()

# SYSTEM
check_health()
get_telemetry()
get_cache_stats()
clear_cache()
execute_command(command, use_cache=True)
```

---

## ЧАСТЬ 3 — АНАЛИЗ ТЕКУЩЕГО ARGUS MCP

Из `argus-mcp.json` видно что ARGUS MCP сейчас имеет только 4 инструмента:
- `create_scan` — создать скан
- `get_scan_status` — статус
- `list_findings` — findings
- `get_report` — отчёт

Это минимальный read-only интерфейс. HexStrike показывает, что MCP-слой может быть полноценным оркестратором.

---

## ЧАСТЬ 4 — CURSOR PROMPT v4 (только НОВОЕ, не повторяет v1-v3)

> Этот промпт — дополнение к предыдущим.
> УЖЕ реализовано из предыдущих промптов:
> - Valhalla report fixes (Markdown render, personas, dedup)
> - MultiProviderLLMRouter (DeepSeek, OpenAI, OpenRouter, Kimi, Perplexity)
> - ShoданEnricher, PerplexityIntelEnricher
> - ExploitabilityValidator (5-stage pipeline)
> - AdversarialScore
> - PocGenerator (с Playwright)
> - ScanCostTracker
> - Skills-система (backend/app/skills/)
> - LLM Deduplication (XML-based)
> - VAMultiAgentOrchestrator

---

```
Ты старший Python-разработчик в проекте ARGUS (AI-powered pentest platform).
Backend: FastAPI + Celery, infra: Docker Compose, MCP: mcp-server/argus_mcp.py.



═══════════════════════════════════════════════════════════════
УЛУЧШЕНИЕ 1: РАСШИРЕНИЕ MCP СЕРВЕРА (150+ инструментов → ARGUS)
═══════════════════════════════════════════════════════════════

Найди mcp-server/argus_mcp.py. Сейчас там 4 инструмента.
Расширь до полноценного security MCP сервера по паттерну HexStrike.

Структура нового MCP:

```python
# mcp-server/argus_mcp.py — полная переработка

from mcp.server.fastmcp import FastMCP
import httpx
import asyncio
import json
import os
from typing import Any

ARGUS_SERVER = os.getenv("ARGUS_SERVER_URL", "http://127.0.0.1:8000")
TENANT_ID = os.getenv("ARGUS_TENANT_ID", "00000000-0000-0000-0000-000000000001")

mcp = FastMCP("argus-security")
client = httpx.AsyncClient(base_url=ARGUS_SERVER, timeout=300)

# ─── SCAN MANAGEMENT ──────────────────────────────────────────

@mcp.tool()
async def create_scan(target: str, scan_mode: str = "standard",
                      instruction: str = "") -> dict:
    """
    Create and start a security scan.
    scan_mode: quick | standard | deep
    instruction: Custom testing focus (e.g. "focus on authentication and IDOR")
    """
    resp = await client.post("/api/v1/scans", json={
        "target_url": target,
        "scan_mode": scan_mode,
        "custom_instruction": instruction,
        "tenant_id": TENANT_ID,
    })
    return resp.json()

@mcp.tool()
async def get_scan_status(scan_id: str) -> dict:
    """Get real-time scan status including current phase and progress."""
    resp = await client.get(f"/api/v1/scans/{scan_id}")
    return resp.json()

@mcp.tool()
async def list_scans(status: str = "", limit: int = 20) -> dict:
    """List all scans, optionally filtered by status."""
    resp = await client.get("/api/v1/scans",
                            params={"status": status, "limit": limit,
                                    "tenant_id": TENANT_ID})
    return resp.json()

@mcp.tool()
async def cancel_scan(scan_id: str) -> dict:
    """Cancel a running scan."""
    resp = await client.post(f"/api/v1/scans/{scan_id}/cancel")
    return resp.json()

# ─── FINDINGS & INTELLIGENCE ──────────────────────────────────

@mcp.tool()
async def list_findings(scan_id: str, severity: str = "",
                        validated_only: bool = False) -> dict:
    """
    List findings for a scan.
    severity: critical|high|medium|low|info (filter)
    validated_only: only confirmed exploitable findings
    """
    params = {"severity": severity, "validated_only": validated_only}
    resp = await client.get(f"/api/v1/scans/{scan_id}/findings", params=params)
    return resp.json()

@mcp.tool()
async def get_finding_detail(finding_id: str) -> dict:
    """Get detailed finding info including PoC code, adversarial score, validation status."""
    resp = await client.get(f"/api/v1/findings/{finding_id}")
    return resp.json()

@mcp.tool()
async def get_adversarial_top(scan_id: str, top_n: int = 5) -> dict:
    """Get top N findings by adversarial score (Impact × Exploitability / Detection_Time)."""
    resp = await client.get(f"/api/v1/scans/{scan_id}/findings/top",
                            params={"top_n": top_n, "sort_by": "adversarial_score"})
    return resp.json()

@mcp.tool()
async def get_poc_code(finding_id: str) -> dict:
    """Get proof-of-concept exploit code for a confirmed finding."""
    resp = await client.get(f"/api/v1/findings/{finding_id}/poc")
    return resp.json()

# ─── REPORTS ──────────────────────────────────────────────────

@mcp.tool()
async def get_report(scan_id: str, format: str = "html",
                     tier: str = "valhalla") -> dict:
    """
    Get security report.
    format: html | json | pdf
    tier: valhalla (leadership_technical) | svalbard (technical)
    """
    resp = await client.get(f"/api/v1/scans/{scan_id}/report",
                            params={"format": format, "tier": tier})
    return resp.json()

@mcp.tool()
async def get_scan_cost(scan_id: str) -> dict:
    """Get LLM cost breakdown for a scan (total cost, cost per phase, model usage)."""
    resp = await client.get(f"/api/v1/scans/{scan_id}/cost")
    return resp.json()

# ─── INTELLIGENCE ─────────────────────────────────────────────

@mcp.tool()
async def analyze_target_intelligence(target: str,
                                       analysis_type: str = "comprehensive") -> dict:
    """
    AI-powered target analysis: attack surface, tech stack, recommended tools.
    analysis_type: comprehensive | quick | passive
    Returns: attack_surface, tech_stack, vuln_categories, recommended_tools
    """
    resp = await client.post("/api/v1/intelligence/analyze-target", json={
        "target": target,
        "analysis_type": analysis_type,
    })
    return resp.json()

@mcp.tool()
async def get_cve_intelligence(cve_id: str, product: str = "") -> dict:
    """
    Get CVE intelligence via Perplexity web search:
    exploit availability, active exploitation, patch status.
    """
    resp = await client.post("/api/v1/intelligence/cve", json={
        "cve_id": cve_id,
        "product": product,
    })
    return resp.json()

@mcp.tool()
async def osint_domain(domain: str) -> dict:
    """
    OSINT lookup: data breaches, tech stack, subdomains, public security disclosures.
    Uses Perplexity web search + Shodan.
    """
    resp = await client.post("/api/v1/intelligence/osint-domain", json={
        "domain": domain,
    })
    return resp.json()

@mcp.tool()
async def get_shodan_intel(target_ip: str) -> dict:
    """Get Shodan data for target: open ports, services, known CVEs."""
    resp = await client.get("/api/v1/intelligence/shodan",
                            params={"ip": target_ip})
    return resp.json()

# ─── SMART SCAN ORCHESTRATION ─────────────────────────────────

@mcp.tool()
async def intelligent_smart_scan(target: str,
                                   objective: str = "comprehensive",
                                   max_phases: int = 5) -> dict:
    """
    AI-orchestrated smart scan: auto-selects tools and phases based on objective.
    objective: comprehensive | web_app | api | auth | business_logic | cloud
    Real-time adaptation: findings from phase N inform phase N+1.
    Returns scan_id for tracking.
    """
    resp = await client.post("/api/v1/scans/smart", json={
        "target": target,
        "objective": objective,
        "max_phases": max_phases,
        "tenant_id": TENANT_ID,
    })
    return resp.json()

@mcp.tool()
async def run_skill_scan(target: str, skill: str) -> dict:
    """
    Run focused scan using a specific security skill.
    skill: sql_injection | xss | ssrf | idor | authentication_jwt |
           business_logic | race_conditions | path_traversal |
           cloud_aws | cloud_gcp | iac_security
    """
    resp = await client.post("/api/v1/scans/skill", json={
        "target": target,
        "skill": skill,
        "tenant_id": TENANT_ID,
    })
    return resp.json()

# ─── SANDBOX TOOL EXECUTION ───────────────────────────────────

@mcp.tool()
async def execute_security_tool(tool: str, target: str,
                                  args: dict = {}) -> dict:
    """
    Execute a security tool directly in ARGUS sandbox.
    tool: nmap | nuclei | sqlmap | dalfox | ffuf | katana | subfinder |
          jwt_tool | trivy | nikto | wpscan | gobuster | amass | httpx
    Returns stdout, stderr, findings extracted from output.
    """
    resp = await client.post("/api/v1/sandbox/execute", json={
        "tool": tool,
        "target": target,
        "args": args,
        "tenant_id": TENANT_ID,
    })
    return resp.json()

@mcp.tool()
async def execute_python_in_sandbox(script: str, timeout: int = 60) -> dict:
    """
    Execute Python script in ARGUS sandbox for custom exploitation/analysis.
    Returns stdout, stderr, execution_time.
    """
    resp = await client.post("/api/v1/sandbox/python", json={
        "script": script,
        "timeout": timeout,
    })
    return resp.json()

# ─── VALIDATION ───────────────────────────────────────────────

@mcp.tool()
async def validate_finding(finding_id: str) -> dict:
    """
    Run exploitability validation pipeline on a specific finding.
    5-stage: Inventory → OneShot → Process → Sanity → Ruling
    Returns: validation_status, confidence, poc_code
    """
    resp = await client.post(f"/api/v1/findings/{finding_id}/validate")
    return resp.json()

@mcp.tool()
async def generate_poc(finding_id: str) -> dict:
    """
    Generate proof-of-concept exploit code for a finding using DeepSeek.
    Returns: poc_code (Python/bash), playwright_script (for XSS).
    """
    resp = await client.post(f"/api/v1/findings/{finding_id}/poc/generate")
    return resp.json()
```

Добавь также:
- `get_available_skills()` — список доступных skill-файлов
- `get_scan_memory_summary(scan_id)` — сжатый контекст скана
- `get_process_list()` — активные процессы в sandbox
- `kill_process(pid)` — убить процесс

Обнови `argus-mcp.json`:
```json
{
  "mcpServers": {
    "argus": {
      "command": "python",
      "args": ["mcp-server/argus_mcp.py", "--server", "http://127.0.0.1:8000"],
      "env": {
        "ARGUS_SERVER_URL": "http://127.0.0.1:8000",
        "ARGUS_TENANT_ID": ""
      },
      "description": "ARGUS MCP — AI security scanner. 30+ tools: create_scan, intelligent_smart_scan, list_findings, validate_finding, generate_poc, get_adversarial_top, execute_security_tool, analyze_target_intelligence, get_cve_intelligence, osint_domain, run_skill_scan",
      "timeout": 300,
      "alwaysAllow": ["get_scan_status", "list_findings", "get_adversarial_top", "get_available_skills"]
    }
  }
}
```


═══════════════════════════════════════════════════════════════
УЛУЧШЕНИЕ 2: INTELLIGENCE ENGINE API ENDPOINTS
═══════════════════════════════════════════════════════════════

Создай backend/app/api/intelligence.py — новый router для intelligence endpoints.
Эти endpoints используются как MCP Tools через новый MCP-сервер.

```python
from fastapi import APIRouter, Depends
router = APIRouter(prefix="/api/v1/intelligence", tags=["intelligence"])

@router.post("/analyze-target")
async def analyze_target(request: AnalyzeTargetRequest):
    """
    AI-powered target analysis (used by MCP Tool: analyze_target_intelligence).
    Orchestrates: Shodan lookup → Perplexity OSINT → LLM analysis → tool selection.
    """
    # 1. Shodan для IP info
    shodan_data = await shodan_enricher.enrich_target(request.target)
    
    # 2. Perplexity OSINT для домена
    osint_data = await perplexity_enricher.osint_domain(request.target)
    
    # 3. LLM analysis + tool selection
    analysis = await llm_router.complete(
        task=LLMTask.THREAT_MODELING,
        system_prompt=ANALYZE_TARGET_SYSTEM,
        user_prompt=ANALYZE_TARGET_USER.format(
            target=request.target,
            shodan=json.dumps(shodan_data),
            osint=json.dumps(osint_data),
        ),
    )
    return parse_json_response(analysis.text)

@router.post("/cve")
async def cve_intelligence(cve_id: str, product: str = ""):
    """CVE intelligence via Perplexity web search."""
    return await perplexity_enricher.enrich_cve(cve_id, product)

@router.post("/osint-domain")
async def osint_domain_endpoint(domain: str):
    """Full OSINT lookup via Perplexity + Shodan."""
    shodan = await shodan_enricher.enrich_target(domain)
    osint = await perplexity_enricher.osint_domain(domain)
    return {"shodan": shodan, "osint": osint}

@router.get("/shodan")
async def shodan_intel(ip: str):
    """Direct Shodan lookup for IP."""
    return await shodan_enricher.enrich_target(ip)
```

Также добавь:

```python
@router.post("/smart-scan")  # POST /api/v1/scans/smart
async def smart_scan(request: SmartScanRequest):
    """
    Intelligent scan — определяет objective и создаёт скан с правильными настройками.
    objective → scan_mode + instructions + initial_skills
    """
    OBJECTIVE_MAP = {
        "comprehensive": {"scan_mode": "deep", "skills": None},
        "web_app": {"scan_mode": "standard", "skills": ["xss", "sqli", "ssrf", "idor"]},
        "api": {"scan_mode": "standard", "skills": ["idor", "authentication_jwt", "mass_assignment"]},
        "auth": {"scan_mode": "quick", "skills": ["authentication_jwt", "business_logic"]},
        "business_logic": {"scan_mode": "standard", "skills": ["business_logic", "race_conditions", "idor"]},
        "cloud": {"scan_mode": "standard", "skills": ["cloud_aws", "iac_security"]},
    }
    config = OBJECTIVE_MAP.get(request.objective, OBJECTIVE_MAP["comprehensive"])
    
    # Создать скан с enriched инструкциями
    instruction = f"Focus on {request.objective} vulnerabilities. " \
                  f"Think like a bug bounty hunter — only report $500+ findings."
    
    scan = await create_scan_internal(
        target=request.target,
        scan_mode=config["scan_mode"],
        custom_instruction=instruction,
        initial_skills=config["skills"],
        tenant_id=request.tenant_id,
    )
    return scan
```


═══════════════════════════════════════════════════════════════
УЛУЧШЕНИЕ 3: SANDBOX TOOL EXECUTION API
═══════════════════════════════════════════════════════════════

Расширь backend/app/api/sandbox.py (или создай если нет).
Добавь endpoint для прямого вызова инструментов через MCP:

```python
# POST /api/v1/sandbox/execute
@router.post("/execute")
async def execute_tool(request: SandboxExecuteRequest):
    """
    Direct tool execution in sandbox.
    Used by MCP Tool: execute_security_tool
    
    Supported tools и их параметры:
    """
    TOOL_MAP = {
        "nmap": {
            "cmd_template": "nmap {scan_type} {ports_arg} {target} {additional}",
            "output_parser": "parse_nmap_output",
            "timeout": 300,
        },
        "nuclei": {
            "cmd_template": "nuclei -u {target} {severity_arg} {tags_arg} -json",
            "output_parser": "parse_nuclei_output",
            "timeout": 600,
        },
        "sqlmap": {
            "cmd_template": "sqlmap -u {target} {data_arg} --batch --level=5 --risk=3 {tamper_arg} --output-dir=/tmp/sqlmap/{scan_id}",
            "output_parser": "parse_sqlmap_output",
            "timeout": 900,
        },
        "dalfox": {
            "cmd_template": "dalfox url {target} {cookie_arg} {header_arg} --output /tmp/dalfox/{scan_id}.txt",
            "output_parser": "parse_dalfox_output",
            "timeout": 300,
        },
        "ffuf": {
            "cmd_template": "ffuf -u {target}/FUZZ -w {wordlist} -mc {match_codes} -json -o /tmp/ffuf/{scan_id}.json",
            "output_parser": "parse_ffuf_output",
            "timeout": 300,
        },
        "katana": {
            "cmd_template": "katana -u {target} -d {depth} -jc -jsl -o /tmp/katana/{scan_id}.txt",
            "output_parser": "parse_katana_output",
            "timeout": 300,
        },
        "subfinder": {
            "cmd_template": "subfinder -d {target} -all -json -o /tmp/subfinder/{scan_id}.json",
            "output_parser": "parse_subfinder_output",
            "timeout": 300,
        },
        "jwt_tool": {
            "cmd_template": "jwt_tool {token} -t {target} -rh {header} -M at",
            "output_parser": "parse_jwt_tool_output",
            "timeout": 120,
        },
        "trivy": {
            "cmd_template": "trivy {scan_type} {target} --format json -o /tmp/trivy/{scan_id}.json",
            "output_parser": "parse_trivy_output",
            "timeout": 300,
        },
        "nikto": {
            "cmd_template": "nikto -h {target} -output /tmp/nikto/{scan_id}.json -Format json",
            "output_parser": "parse_nikto_output",
            "timeout": 600,
        },
        "gobuster": {
            "cmd_template": "gobuster dir -u {target} -w {wordlist} -o /tmp/gobuster/{scan_id}.txt",
            "output_parser": "parse_gobuster_output",
            "timeout": 300,
        },
        "httpx": {
            "cmd_template": "httpx -u {target} -status-code -tech-detect -title -json -o /tmp/httpx/{scan_id}.json",
            "output_parser": "parse_httpx_output",
            "timeout": 120,
        },
        "amass": {
            "cmd_template": "amass enum -d {target} -json /tmp/amass/{scan_id}.json",
            "output_parser": "parse_amass_output",
            "timeout": 600,
        },
    }
    
    tool_config = TOOL_MAP.get(request.tool)
    if not tool_config:
        return {"error": f"Unknown tool: {request.tool}. Available: {list(TOOL_MAP.keys())}"}
    
    # Build command from template + args
    cmd = build_tool_command(tool_config, request.target, request.args, scan_id=str(uuid4()))
    
    # Execute in sandbox with timeout
    result = await sandbox_executor.run(cmd, timeout=tool_config["timeout"])
    
    # Parse output into structured findings
    findings = await parse_tool_output(tool_config["output_parser"], result.stdout)
    
    # Store artifacts in MinIO
    artifact_url = await store_artifact(result, request.tool, scan_id=None)
    
    return {
        "success": result.returncode == 0,
        "stdout": result.stdout[:5000],  # truncate
        "stderr": result.stderr[:1000],
        "findings": findings,
        "artifact_url": artifact_url,
        "execution_time_sec": result.duration,
    }

# POST /api/v1/sandbox/python
@router.post("/python")
async def execute_python(request: PythonExecuteRequest):
    """Execute Python script in sandbox. Used for custom exploit development."""
    # Validate script (basic safety check)
    if any(dangerous in request.script for dangerous in ["os.system", "subprocess.call", "__import__"]):
        return {"error": "Potentially dangerous operations detected in script"}
    
    result = await sandbox_executor.run_python(request.script, timeout=request.timeout)
    return {
        "success": result.returncode == 0,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "execution_time_sec": result.duration,
    }
```


═══════════════════════════════════════════════════════════════
УЛУЧШЕНИЕ 4: SMART CACHING ДЛЯ SANDBOX TOOLS
═══════════════════════════════════════════════════════════════

HexStrike реализует LRU-кэш для результатов инструментов.
Создай backend/app/cache/tool_cache.py

```python
from functools import lru_cache
from datetime import datetime, timedelta
import hashlib
import json

class ToolResultCache:
    """
    LRU cache for security tool results.
    Cache key: hash(tool + target + normalized_args)
    TTL: configurable per tool type
    """
    
    TOOL_TTL = {
        "nmap": 3600,        # 1 hour — ports change rarely
        "subfinder": 7200,   # 2 hours — subdomains stable
        "amass": 7200,
        "nuclei": 1800,      # 30 min — templates update
        "sqlmap": 0,         # no cache — stateful
        "hydra": 0,          # no cache — stateful
        "dalfox": 900,       # 15 min
        "ffuf": 1800,        # 30 min
        "httpx": 600,        # 10 min — fast changes
        "shodan": 86400,     # 24 hours — via Redis
    }
    
    def __init__(self, redis_client):
        self.redis = redis_client
    
    def _make_key(self, tool: str, target: str, args: dict) -> str:
        normalized = json.dumps({"tool": tool, "target": target, "args": args},
                               sort_keys=True)
        return f"tool_cache:{hashlib.md5(normalized.encode()).hexdigest()}"
    
    async def get(self, tool: str, target: str, args: dict) -> dict | None:
        ttl = self.TOOL_TTL.get(tool, 1800)
        if ttl == 0:
            return None  # no cache for stateful tools
        
        key = self._make_key(tool, target, args)
        cached = await self.redis.get(key)
        if cached:
            data = json.loads(cached)
            data["from_cache"] = True
            return data
        return None
    
    async def set(self, tool: str, target: str, args: dict, result: dict):
        ttl = self.TOOL_TTL.get(tool, 1800)
        if ttl == 0:
            return
        
        key = self._make_key(tool, target, args)
        result["cached_at"] = datetime.utcnow().isoformat()
        await self.redis.setex(key, ttl, json.dumps(result))
    
    async def get_stats(self) -> dict:
        """Cache hit/miss statistics."""
        # implemented via Redis INFO
        ...
```

Интегрируй `ToolResultCache` в `execute_security_tool` endpoint.
До выполнения инструмента: check cache → если hit, возвращай cached result.
После выполнения: save to cache.
Добавь поле `from_cache: bool` в ответ.
Добавь endpoint `GET /api/v1/cache/stats` и `DELETE /api/v1/cache` (clear all).


═══════════════════════════════════════════════════════════════
УЛУЧШЕНИЕ 5: GRACEFUL DEGRADATION + RETRY ДЛЯ TOOLS
═══════════════════════════════════════════════════════════════

HexStrike реализует retry с альтернативными инструментами.
Создай backend/app/sandbox/recovery.py

```python
class ToolRecoverySystem:
    """
    When a security tool fails, try alternative tools.
    Pattern from Argus: FailureRecoverySystem.
    """
    
    TOOL_ALTERNATIVES = {
        "gobuster": ["feroxbuster", "dirsearch", "ffuf"],
        "subfinder": ["amass", "assetfinder", "findomain"],
        "nmap": ["rustscan", "masscan", "naabu"],
        "sqlmap": ["nosqlmap", "ghauri"],
        "dalfox": ["xsstrike", "kxss"],
        "nuclei": ["jaeles", "nikto"],
        "katana": ["gospider", "hakrawler", "gau"],
    }
    
    MAX_ATTEMPTS = 3
    
    async def execute_with_recovery(
        self,
        tool: str,
        target: str,
        args: dict,
        executor,
    ) -> ToolResult:
        """
        Try primary tool, then alternatives on failure.
        Returns result with recovery_info metadata.
        """
        tools_to_try = [tool] + self.TOOL_ALTERNATIVES.get(tool, [])
        
        for attempt, current_tool in enumerate(tools_to_try[:self.MAX_ATTEMPTS]):
            try:
                result = await executor.execute(current_tool, target, args)
                if result.success:
                    result.recovery_info = {
                        "recovery_applied": attempt > 0,
                        "original_tool": tool,
                        "used_tool": current_tool,
                        "attempts_made": attempt + 1,
                    }
                    return result
            except Exception as e:
                logger.warning(f"Tool {current_tool} failed: {e}, trying next")
                continue
        
        # All tools failed
        return ToolResult(
            success=False,
            error=f"All {len(tools_to_try[:self.MAX_ATTEMPTS])} tools failed",
            recovery_info={"all_failed": True, "tools_tried": tools_to_try[:self.MAX_ATTEMPTS]},
        )
```

Интегрируй `ToolRecoverySystem` в `execute_security_tool`.
Добавь поле `recovery_info` к ответу endpoint.


═══════════════════════════════════════════════════════════════
УЛУЧШЕНИЕ 6: SCAN HISTORY + KNOWLEDGE BASE
═══════════════════════════════════════════════════════════════

HexStrike кэширует и переиспользует результаты. ARGUS должен строить knowledge base.

Создай backend/app/knowledge/scan_kb.py

```python
class ScanKnowledgeBase:
    """
    Cross-scan knowledge: if target X had vulnerability Y before,
    suggest testing Y first in new scans of X or similar targets.
    """
    
    async def record_finding(self, finding: Finding, scan: Scan):
        """Store finding in KB with target fingerprint."""
        fingerprint = await self._fingerprint_target(scan.target_url)
        await self.redis.lpush(
            f"kb:target:{fingerprint}",
            json.dumps({
                "cwe": finding.cwe,
                "owasp": finding.owasp_category,
                "severity": finding.severity,
                "confirmed": finding.validation_status == "confirmed",
            })
        )
    
    async def get_suggested_skills(self, target_url: str) -> list[str]:
        """
        Based on historical findings for similar targets,
        suggest which skills to prioritize.
        Returns sorted list of skill names by historical frequency.
        """
        fingerprint = await self._fingerprint_target(target_url)
        history = await self.redis.lrange(f"kb:target:{fingerprint}", 0, 50)
        
        if not history:
            return []  # no history, use defaults
        
        # Count CWE/OWASP frequencies
        from collections import Counter
        owasp_counts = Counter()
        for h in history:
            data = json.loads(h)
            owasp_counts[data["owasp"]] += 1
        
        # Map OWASP to skill names
        OWASP_TO_SKILL = {
            "A01": "idor", "A03": "sql_injection",
            "A05": "xss", "A07": "authentication_jwt",
            "A10": "ssrf",
        }
        
        top_categories = [k for k, _ in owasp_counts.most_common(5)]
        return [OWASP_TO_SKILL[c] for c in top_categories if c in OWASP_TO_SKILL]
    
    async def _fingerprint_target(self, url: str) -> str:
        """Create target fingerprint from domain (not full URL)."""
        from urllib.parse import urlparse
        domain = urlparse(url).netloc or url
        return hashlib.md5(domain.encode()).hexdigest()
```

Интегрируй в VAMultiAgentOrchestrator:
- При определении categories: `suggested = await kb.get_suggested_skills(target)`
- Приоритизируй suggested skills в категориях скана
- После скана: `await kb.record_finding(f, scan)` для каждого confirmed finding


═══════════════════════════════════════════════════════════════
ОБНОВЛЕНИЕ .cursor/rules
═══════════════════════════════════════════════════════════════

Добавь или обнови `.cursor/rules/` файлы с правилами разработки ARGUS.
Создай `.cursor/rules/argus-mcp.md`:

```markdown
# ARGUS MCP Development Rules

## MCP Tool Design
- Every new backend capability MUST be exposed as MCP tool
- MCP tools use async/await (httpx.AsyncClient)
- All tools return Dict with success/error fields
- MCP description must be actionable: list what tool returns

## Tool Naming Convention
- scan management: create_scan, get_scan_*, list_scans, cancel_scan
- findings: list_findings, get_finding_*, validate_finding, generate_poc
- intelligence: analyze_target_intelligence, get_cve_intelligence, osint_*
- sandbox: execute_security_tool, execute_python_in_sandbox
- smart: intelligent_smart_scan, run_skill_scan

## argus-mcp.json description field
Must list top 10 tools so Claude/Cursor understand capabilities.

## API endpoints for MCP
Each MCP tool maps to one backend endpoint:
MCP Tool → POST /api/v1/{resource}/{action}
Status: GET /api/v1/{resource}/{id}
```


═══════════════════════════════════════════════════════════════
ПОРЯДОК РЕАЛИЗАЦИИ
═══════════════════════════════════════════════════════════════

1. Улучшение 1 (MCP расширение)       — 4-6 ч, максимальный эффект для Cursor/Claude
2. Улучшение 2 (Intelligence API)     — 3-4 ч, зависит от v2 (уже есть Shodan/Perplexity)
3. Улучшение 3 (Sandbox Tool API)     — 6-8 ч, ключевое для прямого tool execution
4. Улучшение 4 (Smart Caching)        — 2-3 ч, performance
5. Улучшение 5 (Graceful Degradation) — 2-3 ч, reliability
6. Улучшение 6 (Knowledge Base)       — 3-4 ч, long-term value

Тесты:
- test_mcp_tools.py — mock httpx, проверить все 30+ tool функций
- test_intelligence_api.py — mock Shodan + Perplexity
- test_sandbox_execute.py — mock sandbox executor
- test_tool_cache.py — mock Redis
- test_recovery_system.py — simulate tool failures

pytest tests/ -v && ruff check backend/ && ruff check mcp-server/
```

---

## ЧАСТЬ 5 — СВОДНАЯ МАТРИЦА: ЧТО ГДЕ ВЗЯТО

| Фича | Источник | Файл в ARGUS |
|---|---|---|
| MCP расширение (30+ tools) | HexStrike `hexstrike_mcp.py` | `mcp-server/argus_mcp.py` |
| Intelligence API endpoints | HexStrike `hexstrike_server.py` | `backend/app/api/intelligence.py` |
| Smart Scan (objective-based) | HexStrike `intelligent_smart_scan` | `backend/app/api/sandbox.py` |
| Direct tool execution via MCP | HexStrike tool functions | `backend/app/api/sandbox.py` |
| Smart Caching LRU | HexStrike Smart Caching System | `backend/app/cache/tool_cache.py` |
| Graceful degradation + retry | HexStrike FailureRecoverySystem | `backend/app/sandbox/recovery.py` |
| Knowledge Base | HexStrike (new for ARGUS) | `backend/app/knowledge/scan_kb.py` |
| Analyze target prompt | HexStrike intelligence prompts | `backend/app/api/intelligence.py` |
| Python execution in sandbox | HexStrike `execute_python_script` | `backend/app/api/sandbox.py` |
| Cursor rules for MCP | собственный | `.cursor/rules/argus-mcp.md` |
| Skills system | Strix ✅ v3 | `backend/app/skills/` |
| LLM Dedup | Strix ✅ v3 | `backend/app/validation/llm_dedup.py` |
| Multi-agent orchestrator | Strix ✅ v3 | `backend/app/agents/va_orchestrator.py` |
| Exploitability validator | RAPTOR ✅ v2 | `backend/app/validation/exploitability.py` |
| Adversarial score | RAPTOR ✅ v2 | `backend/app/scoring/adversarial.py` |
| LLM Router | .env ✅ v2 | `backend/app/llm/router.py` |
| Shodan enricher | .env ✅ v2 | `backend/app/intel/shodan_enricher.py` |
| Perplexity OSINT | .env ✅ v2 | `backend/app/intel/perplexity_enricher.py` |
| Valhalla fixes | report ✅ v1 | `backend/app/reports/` |


**Запрещено:**
- Менять frontend.
- Нарушать существующие API‑контракты.