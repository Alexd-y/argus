# ARGUS Implementation Prompt v5 — Zero Stubs, Full Production Code

## КОНТЕКСТ ПРОЕКТА

ARGUS — AI-powered penetration testing platform.
- **Backend**: FastAPI + Celery + PostgreSQL + Redis (`backend/`)
- **MCP Server**: FastMCP, stdio/HTTP transport (`mcp-server/`)
- **Sandbox**: Kali tools, Docker isolated (`sandbox/`)
- **Infra**: Docker Compose, MinIO S3, Nginx (`infra/`)
- **Frontend**: Next.js + Vercel (`Frontend/`)
- **Tests**: pytest (`backend/tests/`, `tests/`)

**Текущее состояние кодовой базы:**
- 31 `@mcp.tool()` в `mcp-server/argus_mcp.py` + 150 kali tools из registry
- 16 alembic миграций (001–016)
- эндпоинты с 501 (исторически): `sandbox/processes`, `sandbox/processes/{pid}/kill`, `sandbox/python` (disabled), `scans/{id}/memory-summary`, `findings/{id}/poc` (no data), `findings/{id}/validate` (exception), `findings/{id}/poc/generate` (exception), `scans/{id}/report` (no report row)
- Redis client есть (`src/core/redis_client.py`) — lazy-init, sync
- Tool cache есть (`src/cache/tool_cache.py`) — SHA-256 key, TTL per tool
- legacy `recovery_info_*` в cache module (заменить на ToolRecoverySystem)
- VA orchestrator (`src/agents/va_orchestrator.py`) — `VAMultiAgentOrchestrator` с parallel agents
- Skills system: 21 `.md` файлов, `_CATEGORY_SKILL_MAP` маппинг
- OWASP Top 10:2025 в `src/owasp_top10_2025.py` (A01–A10)
- Guardrails: `ALLOWED_TOOLS` = 18 инструментов
- Config: 200+ settings через pydantic-settings

**ПРАВИЛА:**
1. **Никаких noop-реализаций** — каждый endpoint, каждая функция, каждый tool должен быть полностью реализован
2. **Контракт-first** — Backend реализуется по `docs/api-contracts.md`, Frontend — источник истины
3. **Existing code** — не ломать работающие endpoints, расширять; все imports должны разрешаться
4. **Type safety** — Pydantic v2 schemas, typed returns, no `Any` без необходимости
5. **Tests** — каждый блок сопровождается тестами в `backend/tests/`

---

## БЛОК 1 — ScanKnowledgeBase (Redis OWASP→skill + CWE→skill)

### Что есть сейчас
- `src/skills/__init__.py` — `_CATEGORY_SKILL_MAP` (sqli→[sql_injection], xss→[xss], ...)
- `src/owasp_top10_2025.py` — `OWASP_TOP10_2025_CATEGORY_IDS` (A01–A10)
- `src/agents/va_orchestrator.py` — `CATEGORY_SKILL_MAP`, `TOOLS_BY_CATEGORY`
- `src/core/redis_client.py` — `get_redis()`, `redis_ping()`

### Что реализовать

**Файл: `backend/src/cache/scan_knowledge_base.py`**

```python
"""
ScanKnowledgeBase — Redis-backed knowledge mapping for intelligent scan planning.

Maps OWASP categories and CWE IDs to skills, tools, and scan strategies.
TTL 30 days. Falls back to in-memory dict when Redis unavailable.
"""
```

**Полная реализация должна содержать:**

1. **Класс `ScanKnowledgeBase`:**
   - `__init__(self)` — подключение к Redis через `get_redis()`, fallback на `dict`
   - `_build_owasp_skill_map()` — статическая таблица OWASP A01–A10 → skills:
     ```
     A01 (Broken Access Control) → ["idor", "authentication_jwt", "business_logic"]
     A02 (Security Misconfiguration) → ["information_disclosure"]
     A03 (Supply Chain) → [] (trivy scan)
     A04 (Cryptographic Failures) → ["authentication_jwt"]
     A05 (Injection) → ["sql_injection", "xss", "rce", "path_traversal"]
     A06 (Insecure Design) → ["business_logic", "race_conditions"]
     A07 (Authentication Failures) → ["authentication_jwt", "csrf"]
     A08 (Integrity Failures) → ["mass_assignment", "file_upload"]
     A09 (Logging Failures) → ["information_disclosure"]
     A10 (Exceptional Conditions) → ["ssrf", "xxe"]
     ```
   - `_build_cwe_skill_map()` — 50+ CWE → skill маппингов:
     ```
     CWE-79  → ["xss"]
     CWE-89  → ["sql_injection"]
     CWE-22  → ["path_traversal"]
     CWE-352 → ["csrf"]
     CWE-918 → ["ssrf"]
     CWE-611 → ["xxe"]
     CWE-502 → ["mass_assignment"]
     CWE-434 → ["file_upload"]
     CWE-287 → ["authentication_jwt"]
     CWE-639 → ["idor"]
     CWE-362 → ["race_conditions"]
     CWE-601 → ["open_redirect"]
     CWE-78  → ["rce"]
     CWE-94  → ["rce"]
     CWE-77  → ["rce"]
     CWE-863 → ["idor", "business_logic"]
     CWE-284 → ["idor", "authentication_jwt"]
     CWE-798 → ["authentication_jwt"]
     CWE-306 → ["authentication_jwt"]
     CWE-862 → ["idor"]
     CWE-200 → ["information_disclosure"]
     CWE-209 → ["information_disclosure"]
     CWE-532 → ["information_disclosure"]
     CWE-312 → ["authentication_jwt", "information_disclosure"]
     CWE-327 → ["authentication_jwt"]
     CWE-328 → ["authentication_jwt"]
     CWE-330 → ["authentication_jwt"]
     CWE-347 → ["authentication_jwt"]
     CWE-384 → ["authentication_jwt"]
     CWE-613 → ["authentication_jwt"]
     CWE-521 → ["authentication_jwt"]
     CWE-307 → ["authentication_jwt"]
     CWE-640 → ["authentication_jwt"]
     CWE-1321 → ["mass_assignment"]
     CWE-915 → ["mass_assignment"]
     CWE-285 → ["idor"]
     CWE-943 → ["sql_injection"]
     CWE-564 → ["sql_injection"]
     CWE-113 → ["ssrf"]
     CWE-116 → ["xss"]
     CWE-346 → ["csrf"]
     CWE-1275 → ["csrf"]
     CWE-538 → ["information_disclosure"]
     CWE-548 → ["information_disclosure"]
     CWE-1004 → ["authentication_jwt"]
     CWE-614 → ["authentication_jwt"]
     CWE-942 → ["information_disclosure"]
     CWE-829 → ["rce", "file_upload"]
     CWE-426 → ["rce"]
     CWE-427 → ["rce"]
     ```
   - `_build_owasp_tools_map()` — OWASP → recommended tools:
     ```
     A01 → ["ffuf", "nuclei", "burp-intruder"]
     A02 → ["nikto", "nuclei", "trivy", "testssl"]
     A03 → ["trivy", "gitleaks", "semgrep"]
     A04 → ["testssl", "openssl", "nuclei"]
     A05 → ["sqlmap", "dalfox", "nuclei", "semgrep", "ffuf"]
     A06 → ["ffuf", "nuclei", "custom-python-asyncio"]
     A07 → ["hydra", "jwt_tool", "ffuf", "nuclei"]
     A08 → ["nuclei", "semgrep", "trufflehog"]
     A09 → ["nuclei", "nikto"]
     A10 → ["nuclei", "ffuf"]
     ```
   - `get_skills_for_owasp(owasp_id: str) -> list[str]` — lookup с кэшированием в Redis, key = `argus:kb:owasp:{id}`, TTL 30 дней
   - `get_skills_for_cwe(cwe_id: str) -> list[str]` — lookup, key = `argus:kb:cwe:{id}`, TTL 30 дней
   - `get_tools_for_owasp(owasp_id: str) -> list[str]` — recommended tools
   - `get_scan_strategy(owasp_ids: list[str], cwe_ids: list[str]) -> dict` — merge skills + tools + priority
   - `warm_cache()` — preload all mappings into Redis at startup
   - `invalidate(pattern: str)` — delete keys by pattern (e.g. `argus:kb:*`)
   - `stats() -> dict` — hit/miss counters, key count, memory usage estimate

2. **Redis key schema:**
   - `argus:kb:owasp:{A01..A10}` → JSON list of skill names
   - `argus:kb:cwe:{CWE-XX}` → JSON list of skill names
   - `argus:kb:tools:owasp:{A01..A10}` → JSON list of tool names
   - `argus:kb:stats:hits` → integer counter
   - `argus:kb:stats:misses` → integer counter
   - TTL: 30 дней (2_592_000 секунд)

3. **Интеграция в `VAMultiAgentOrchestrator`:**
   В `src/agents/va_orchestrator.py` метод `determine_categories()` должен использовать `ScanKnowledgeBase` для обогащения:
   - При наличии OWASP/CWE из предыдущих stage-ов (recon findings), подгружать skills и tools динамически
   - Добавить метод `enrich_from_recon(recon_findings: list[dict]) -> dict` — принимает findings из Stage 1, извлекает CWE/OWASP, возвращает обогащённый план

4. **Singleton:**
   ```python
   _kb_instance: ScanKnowledgeBase | None = None

   def get_knowledge_base() -> ScanKnowledgeBase:
       global _kb_instance
       if _kb_instance is None:
           _kb_instance = ScanKnowledgeBase()
       return _kb_instance
   ```

5. **Startup hook в `backend/main.py`:**
   В lifespan добавить `get_knowledge_base().warm_cache()` после alembic migrations.

---

## БЛОК 2 — ToolRecoverySystem (полный цикл)

### Что есть сейчас
- `src/cache/tool_cache.py` — legacy helper возвращает `{"source": "cache", "recovery_tier": "none"}`
- `src/api/routers/sandbox.py` — передаёт `recovery_info=...` из legacy helper в response
- `SandboxExecuteResponse` schema имеет `recovery_info: dict | None`

### Что реализовать

**Файл: `backend/src/cache/tool_recovery.py`**

```python
"""
ToolRecoverySystem — automatic fallback to alternative tools when primary fails.

When a tool execution fails (non-zero exit, timeout, permission denied), the system
consults TOOL_ALTERNATIVES to find equivalent tools, retries up to MAX_RECOVERY_ATTEMPTS=3,
and returns structured recovery_info in every response.

Stateful tools (sqlmap, hydra, metasploit, burpsuite) have NO alternatives — they manage
their own sessions and cannot be transparently replaced.
"""
```

**Полная реализация:**

1. **Таблица `TOOL_ALTERNATIVES`** — dict[str, list[str]], 150+ записей. Группы:
   ```python
   TOOL_ALTERNATIVES: dict[str, list[str]] = {
       # --- Port Scanning ---
       "nmap": ["rustscan", "masscan", "naabu"],
       "rustscan": ["nmap", "masscan", "naabu"],
       "masscan": ["nmap", "rustscan", "naabu"],
       "naabu": ["rustscan", "nmap", "masscan"],

       # --- Subdomain Enumeration ---
       "subfinder": ["amass", "assetfinder", "findomain", "sublist3r"],
       "amass": ["subfinder", "assetfinder", "findomain", "sublist3r"],
       "assetfinder": ["subfinder", "amass", "findomain"],
       "findomain": ["subfinder", "amass", "assetfinder"],
       "sublist3r": ["subfinder", "amass", "assetfinder"],

       # --- DNS Enumeration ---
       "dig": ["host", "nslookup", "dnsx", "dnsrecon"],
       "host": ["dig", "nslookup", "dnsx"],
       "nslookup": ["dig", "host", "dnsx"],
       "dnsx": ["dig", "host", "dnsrecon"],
       "dnsrecon": ["dig", "dnsx", "fierce"],
       "fierce": ["dnsrecon", "dnsx", "dig"],

       # --- Web Fingerprinting ---
       "whatweb": ["httpx", "wappalyzer", "webanalyze"],
       "httpx": ["whatweb", "curl"],
       "wappalyzer": ["whatweb", "httpx"],
       "webanalyze": ["whatweb", "httpx"],

       # --- Directory Bruteforce ---
       "gobuster": ["feroxbuster", "dirsearch", "dirb", "ffuf", "wfuzz"],
       "feroxbuster": ["gobuster", "dirsearch", "dirb", "ffuf"],
       "dirsearch": ["gobuster", "feroxbuster", "dirb", "ffuf"],
       "dirb": ["gobuster", "feroxbuster", "dirsearch", "ffuf"],
       "ffuf": ["gobuster", "feroxbuster", "dirsearch", "wfuzz"],
       "wfuzz": ["ffuf", "gobuster", "feroxbuster"],

       # --- Web Vulnerability Scanners ---
       "nikto": ["nuclei", "wpscan"],
       "nuclei": ["nikto"],
       "wpscan": ["nikto", "nuclei"],

       # --- XSS ---
       "dalfox": ["xsstrike", "nuclei"],
       "xsstrike": ["dalfox", "nuclei"],

       # --- SSL/TLS ---
       "testssl": ["sslyze", "openssl"],
       "sslyze": ["testssl", "openssl"],
       "openssl": ["testssl", "sslyze"],

       # --- OSINT / Recon ---
       "theharvester": ["recon-ng", "spiderfoot"],
       "recon-ng": ["theharvester", "spiderfoot"],
       "spiderfoot": ["theharvester", "recon-ng"],
       "whois": ["curl"],
       "gau": ["waybackurls", "waymore"],
       "waybackurls": ["gau", "waymore"],
       "waymore": ["gau", "waybackurls"],

       # --- Code / Secret Scanning ---
       "gitleaks": ["trufflehog", "semgrep"],
       "trufflehog": ["gitleaks", "semgrep"],
       "semgrep": ["gitleaks", "trufflehog"],

       # --- IaC / Cloud ---
       "trivy": ["checkov", "terrascan"],
       "checkov": ["trivy", "terrascan"],
       "terrascan": ["trivy", "checkov"],
       "prowler": ["scout"],
       "scout": ["prowler"],

       # --- Container ---
       "trivy": ["grype", "syft"],
       "grype": ["trivy"],
       "syft": ["trivy"],

       # --- CMS ---
       "joomscan": ["droopescan"],
       "droopescan": ["joomscan"],
       "wpscan": ["nuclei"],

       # --- API ---
       "arjun": ["paramspider", "ffuf"],
       "paramspider": ["arjun", "gau"],

       # --- Screenshot ---
       "gowitness": ["eyewitness", "aquatone"],
       "eyewitness": ["gowitness", "aquatone"],
       "aquatone": ["gowitness", "eyewitness"],

       # --- Wireless (no alternatives typically) ---
       "aircrack-ng": [],
       "bettercap": [],

       # --- Binary/RE (no alternatives) ---
       "gdb": [],
       "radare2": ["ghidra"],
       "ghidra": ["radare2"],
   }

   # Stateful tools — NEVER auto-replace, they manage sessions/state
   STATEFUL_TOOLS: frozenset[str] = frozenset({
       "sqlmap",       # manages DB fingerprint state, session files
       "hydra",        # tracks credential attempts, avoids re-testing
       "medusa",       # same as hydra — credential session state
       "metasploit",   # session/meterpreter state
       "burpsuite",    # project state, sitemap, findings
       "zaproxy",      # session state, spider state
       "beef-xss",     # hooked browser state
       "empire",       # agent/listener state
       "cobaltstrike", # beacon state
       "msfconsole",   # same as metasploit
       "responder",    # network listener state
       "mitmdump",     # proxy session state
       "bettercap",    # session state
   })
   ```

2. **Класс `ToolRecoverySystem`:**
   ```python
   MAX_RECOVERY_ATTEMPTS = 3

   class ToolRecoverySystem:
       def __init__(self):
           self._attempt_log: list[dict] = []

       def get_alternatives(self, tool_name: str) -> list[str]:
           """Return alternatives for a tool. Empty for stateful tools."""
           if tool_name.lower() in STATEFUL_TOOLS:
               return []
           return TOOL_ALTERNATIVES.get(tool_name.lower(), [])

       def is_stateful(self, tool_name: str) -> bool:
           return tool_name.lower() in STATEFUL_TOOLS

       def should_retry(self, tool_name: str, attempt: int) -> bool:
           if attempt >= MAX_RECOVERY_ATTEMPTS:
               return False
           if self.is_stateful(tool_name):
               return False
           return len(self.get_alternatives(tool_name)) > 0

       def next_alternative(self, tool_name: str, attempt: int) -> str | None:
           alts = self.get_alternatives(tool_name)
           if attempt - 1 < len(alts):
               return alts[attempt - 1]
           return None

       def build_recovery_info(
           self,
           original_tool: str,
           final_tool: str,
           attempts: list[dict],  # [{tool, exit_code, error_type, duration_sec}]
           from_cache: bool = False,
       ) -> dict:
           return {
               "original_tool": original_tool,
               "final_tool": final_tool,
               "recovery_used": original_tool != final_tool,
               "attempts": attempts,
               "total_attempts": len(attempts),
               "is_stateful": self.is_stateful(original_tool),
               "from_cache": from_cache,
               "alternatives_available": self.get_alternatives(original_tool),
           }
   ```

3. **Интеграция в `src/api/routers/sandbox.py` и `src/tools/executor.py`:**
   - В `sandbox_execute()`: если `execute_command()` возвращает `success=False` и tool не stateful, итеративно пробовать alternatives (подменяя tool name в command через `_replace_tool_in_command()`)
   - Каждая попытка логируется в `attempts[]`
   - Финальный response содержит полный `recovery_info` вместо legacy cache helper

4. **Удалить legacy recovery helper** из `src/cache/tool_cache.py` — заменить на import из `tool_recovery.py`.

5. **Функция `_replace_tool_in_command(command: str, old_tool: str, new_tool: str) -> str`** — безопасная замена первого токена в команде.

---

## БЛОК 3 — Cache Stats API (полный набор endpoint'ов для Argus)

### Что есть сейчас
- `src/cache/tool_cache.py` — `ToolResultCache` с Redis get/set/enabled
- `src/core/redis_client.py` — `get_redis()`, `redis_ping()`
- Нет API endpoints для мониторинга кэша

### Что реализовать

**Файл: `backend/src/api/routers/cache.py`** — новый router

Для проекта Argus нужен полный cache management API. Два endpoint'а мало — вот полный набор:

```python
router = APIRouter(prefix="/cache", tags=["cache"])
```

**Endpoint'ы (10 штук):**

1. **`GET /api/v1/cache/stats`** — общая статистика
   - Response: `{ hit_rate: float, hits: int, misses: int, total_keys: int, memory_used_bytes: int, memory_human: str, uptime_seconds: int, connected: bool, tool_breakdown: { "nmap": { keys: int, avg_ttl_sec: int }, ... } }`
   - Реализация: `redis.info("memory")`, `redis.info("stats")`, scan by `argus:*` prefix

2. **`DELETE /api/v1/cache`** — flush с allowlist паттернов
   - Body: `{ patterns: ["argus:sandbox:exec:*", "argus:kb:*"], confirm: true }`
   - Allowlist: только паттерны начинающиеся с `argus:` — нельзя удалить Redis системные ключи
   - Response: `{ deleted_count: int, patterns_matched: list[str] }`

3. **`GET /api/v1/cache/keys`** — list keys by pattern
   - Query: `?pattern=argus:sandbox:exec:*&limit=100&cursor=0`
   - Response: `{ keys: list[str], count: int, next_cursor: str | null, pattern: str }`
   - Использует `SCAN` а не `KEYS` (production-safe)

4. **`GET /api/v1/cache/key/{key}`** — get single cached value
   - Response: `{ key: str, value: any, ttl_remaining_sec: int, size_bytes: int, type: str }`
   - Только для ключей с prefix `argus:` (безопасность)

5. **`DELETE /api/v1/cache/key/{key}`** — delete single key
   - Только для ключей с prefix `argus:`
   - Response: `{ key: str, deleted: bool }`

6. **`GET /api/v1/cache/tool-ttls`** — текущие TTL настройки per tool
   - Response: `{ ttls: { "nmap": 3600, "nuclei": 1800, ... }, default_ttl: 300 }`
   - Из `_TOOL_TTL_SEC` в `tool_cache.py`

7. **`PUT /api/v1/cache/tool-ttls`** — обновить TTL per tool (runtime, не persistent)
   - Body: `{ tool: str, ttl_sec: int }` (min 0, max 604800 = 7 days)
   - Response: `{ tool: str, old_ttl: int, new_ttl: int }`

8. **`GET /api/v1/cache/health`** — Redis health check
   - Response: `{ connected: bool, latency_ms: float, version: str, used_memory_human: str, maxmemory_human: str, eviction_policy: str }`

9. **`POST /api/v1/cache/warm`** — trigger warmup (knowledge base + tool cache preload)
   - Response: `{ warmed_keys: int, duration_ms: float, source: str }`
   - Вызывает `get_knowledge_base().warm_cache()`

10. **`GET /api/v1/cache/scan/{scan_id}`** — cached results for a specific scan's tools
    - Response: `{ scan_id: str, cached_results: list[{ tool: str, key: str, ttl_remaining: int, size_bytes: int }] }`
    - Scan по паттерну, пересечение с scan_id artifacts

**Регистрация в `backend/main.py`:**
```python
from src.api.routers import cache as cache_router
app.include_router(cache_router.router, prefix="/api/v1")
```

**Защита:** все endpoints требуют admin key (`Depends(require_admin)` из `src/api/routers/admin.py` или отдельный dependency).

---

## БЛОК 4 — MCP расширение + Cursor Rules

### Что есть сейчас
- 31 `@mcp.tool()` в `argus_mcp.py` (create_scan, get_scan_status, list_scans, cancel_scan, list_findings, get_finding_detail, get_adversarial_top, get_poc_code, get_report, get_scan_cost, analyze_target_intelligence, get_cve_intelligence, osint_domain, get_shodan_intel, intelligent_smart_scan, run_skill_scan, execute_security_tool, execute_python_in_sandbox, validate_finding, generate_poc, get_available_skills, get_scan_memory_summary, get_process_list, kill_process, run_network_scan, run_web_scan, run_ssl_test, run_dns_enum, run_bruteforce, run_tool, va_enqueue_sandbox_scanner)
- 150 kali tools зарегистрированы через `_register_kali_tools()` (формально 150 но через один handler с dynamic naming)
- `argus-mcp.json` — минимальный description

### Что реализовать

**Довести до 150+ ЯВНЫХ `@mcp.tool()` функций** (не через dynamic registry, а explicit).
Каждый tool должен иметь:
- Чёткое имя (snake_case, prefix по домену)
- Полный docstring с Args/Returns
- Типизированные параметры

**Новые категории MCP tools для добавления (120+ новых):**

#### Категория: Scan Management (существует, дополнить)
Добавить:
- `pause_scan(scan_id: str)` → POST `/scans/{id}/pause`
- `resume_scan(scan_id: str)` → POST `/scans/{id}/resume`
- `retry_scan(scan_id: str)` → POST `/scans/{id}/retry`
- `get_scan_phases(scan_id: str)` → GET `/scans/{id}/phases`
- `get_scan_artifacts(scan_id: str)` → GET `/scans/{id}/artifacts`
- `get_scan_events(scan_id: str, limit: int)` → GET `/scans/{id}/events` (SSE snapshot)
- `get_scan_timeline(scan_id: str)` → GET `/scans/{id}/timeline`
- `compare_scans(scan_id_a: str, scan_id_b: str)` → GET `/scans/compare`
- `clone_scan(scan_id: str)` → POST `/scans/{id}/clone`
- `export_scan(scan_id: str, format: str)` → GET `/scans/{id}/export`

#### Категория: Finding Management (существует, дополнить)
Добавить:
- `update_finding_severity(finding_id: str, severity: str)` → PATCH `/findings/{id}`
- `add_finding_note(finding_id: str, note: str)` → POST `/findings/{id}/notes`
- `get_finding_notes(finding_id: str)` → GET `/findings/{id}/notes`
- `mark_finding_false_positive(finding_id: str, reason: str)` → POST `/findings/{id}/false-positive`
- `get_finding_remediation(finding_id: str)` → GET `/findings/{id}/remediation`
- `get_finding_references(finding_id: str)` → GET `/findings/{id}/references`
- `bulk_validate_findings(scan_id: str, finding_ids: list[str])` → POST `/findings/bulk-validate`
- `get_findings_by_cwe(scan_id: str, cwe: str)` → GET `/scans/{id}/findings?cwe=`
- `get_findings_by_owasp(scan_id: str, owasp: str)` → GET `/scans/{id}/findings?owasp=`
- `get_findings_statistics(scan_id: str)` → GET `/scans/{id}/findings/statistics`

#### Категория: Report Management (существует, дополнить)
Добавить:
- `generate_report(scan_id: str, tier: str, formats: list[str])` → POST `/scans/{id}/reports/generate`
- `generate_all_reports(scan_id: str)` → POST `/scans/{id}/reports/generate-all`
- `get_report_status(report_id: str)` → GET `/reports/{id}/status`
- `download_report(report_id: str, format: str)` → GET `/reports/{id}/download`
- `list_report_formats()` → GET `/reports/formats`
- `get_report_preview(report_id: str)` → GET `/reports/{id}/preview`
- `compare_reports(report_id_a: str, report_id_b: str)` → GET `/reports/compare`
- `delete_report(report_id: str)` → DELETE `/reports/{id}`

#### Категория: Intelligence (существует, дополнить)
Добавить:
- `search_cve(query: str, severity: str, year: int)` → GET `/intelligence/cve/search`
- `get_exploit_db(cve_id: str)` → GET `/intelligence/exploitdb`
- `get_threat_feeds(target: str)` → GET `/intelligence/threat-feeds`
- `get_technology_vulns(technology: str, version: str)` → POST `/intelligence/tech-vulns`
- `get_waf_detection(target: str)` → POST `/intelligence/waf-detect`
- `get_cdn_detection(target: str)` → POST `/intelligence/cdn-detect`
- `whois_lookup(domain: str)` → GET `/intelligence/whois`
- `reverse_dns(ip: str)` → GET `/intelligence/rdns`
- `ip_geolocation(ip: str)` → GET `/intelligence/geoip`
- `certificate_transparency(domain: str)` → GET `/intelligence/ct-logs`

#### Категория: Recon (новая)
- `start_recon(target: str, mode: str)` → POST `/recon/engagements`
- `get_recon_status(engagement_id: str)` → GET `/recon/engagements/{id}`
- `list_recon_engagements(target: str)` → GET `/recon/engagements`
- `get_recon_subdomains(engagement_id: str)` → GET `/recon/engagements/{id}/subdomains`
- `get_recon_ports(engagement_id: str)` → GET `/recon/engagements/{id}/ports`
- `get_recon_technologies(engagement_id: str)` → GET `/recon/engagements/{id}/technologies`
- `get_recon_urls(engagement_id: str)` → GET `/recon/engagements/{id}/urls`
- `get_recon_dns(engagement_id: str)` → GET `/recon/engagements/{id}/dns`
- `get_recon_screenshots(engagement_id: str)` → GET `/recon/engagements/{id}/screenshots`
- `get_recon_js_findings(engagement_id: str)` → GET `/recon/engagements/{id}/js-findings`

#### Категория: Threat Modeling (новая)
- `start_threat_model(engagement_id: str)` → POST `/recon/threat-modeling/{id}/start`
- `get_threat_model_status(engagement_id: str)` → GET `/recon/threat-modeling/{id}/status`
- `get_threat_model_artifacts(engagement_id: str)` → GET `/recon/threat-modeling/{id}/artifacts`
- `get_attack_surface(engagement_id: str)` → GET `/recon/threat-modeling/{id}/attack-surface`
- `get_threat_matrix(engagement_id: str)` → GET `/recon/threat-modeling/{id}/matrix`

#### Категория: Vulnerability Analysis (новая)
- `start_va(engagement_id: str, categories: list[str])` → POST `/recon/vulnerability-analysis/{id}/start`
- `get_va_status(engagement_id: str)` → GET `/recon/vulnerability-analysis/{id}/status`
- `get_va_findings(engagement_id: str)` → GET `/recon/vulnerability-analysis/{id}/findings`
- `get_va_active_scan_results(engagement_id: str)` → GET `/recon/vulnerability-analysis/{id}/active-scan`
- `get_va_passive_results(engagement_id: str)` → GET `/recon/vulnerability-analysis/{id}/passive`

#### Категория: Exploitation (новая)
- `start_exploitation(engagement_id: str)` → POST `/recon/exploitation/{id}/start`
- `get_exploitation_status(engagement_id: str)` → GET `/recon/exploitation/{id}/status`
- `get_exploitation_results(engagement_id: str)` → GET `/recon/exploitation/{id}/results`
- `get_poc_scripts(engagement_id: str)` → GET `/recon/exploitation/{id}/poc-scripts`

#### Категория: Cache & System (новая)
- `get_cache_stats()` → GET `/cache/stats`
- `flush_cache(patterns: list[str])` → DELETE `/cache`
- `get_cache_health()` → GET `/cache/health`
- `warm_cache()` → POST `/cache/warm`
- `get_system_health()` → GET `/health`
- `get_system_metrics()` → GET `/metrics`
- `get_available_tools()` → GET `/tools/available`
- `get_tool_status(tool: str)` → GET `/tools/{tool}/status`

#### Категория: Sandbox Management (существует, заменить минимальные ответы)
- `get_sandbox_processes()` → GET `/sandbox/processes` (полная реализация)
- `kill_sandbox_process(pid: int)` → POST `/sandbox/processes/{pid}/kill` (РЕАЛИЗОВАТЬ)
- `get_sandbox_status()` → GET `/sandbox/status`
- `run_python_script(code: str, timeout: int)` → POST `/sandbox/python` (РЕАЛИЗОВАТЬ)

#### Категория: Knowledge Base (новая)
- `get_skills_for_owasp(owasp_id: str)` → из ScanKnowledgeBase
- `get_skills_for_cwe(cwe_id: str)` → из ScanKnowledgeBase
- `get_scan_strategy(owasp_ids: list[str], cwe_ids: list[str])` → strategy planner
- `list_all_skills()` → все available skills
- `get_skill_content(skill_name: str)` → содержимое skill MD file
- `search_skills(query: str)` → поиск по skill content

#### Категория: Admin (новая)
- `get_admin_stats()` → GET `/admin/stats`
- `get_tenant_info()` → GET `/admin/tenant`
- `list_all_scans_admin(limit: int)` → GET `/admin/scans`
- `get_llm_usage()` → GET `/admin/llm-usage`

**Каждый tool в `argus_mcp.py`** должен быть явной функцией с `@mcp.tool()`, типизированными параметрами, полным docstring. НЕ через dynamic registration для новых tools (kali tools можно оставить через registry).

**ArgusClient расширить** соответствующими методами для каждого нового tool (по аналогии с существующими `create_scan`, `get_scan_status` etc.).

### `argus-mcp.json` — обновить:

```json
{
  "mcpServers": {
    "argus": {
      "command": "python",
      "args": ["ARGUS/mcp-server/argus_mcp.py", "--server", "http://127.0.0.1:8000"],
      "env": {
        "ARGUS_SERVER_URL": "http://127.0.0.1:8000",
        "ARGUS_TENANT_ID": "",
        "ARGUS_API_KEY": "",
        "ARGUS_ADMIN_KEY": "",
        "MCP_TRANSPORT": "stdio"
      },
      "description": "ARGUS MCP — AI-powered pentesting orchestration. 150+ tools: scan lifecycle (create/pause/resume/cancel/clone/compare), finding management (validate/poc/remediation/false-positive/bulk), reports (generate/download/preview/compare), intelligence (CVE/OSINT/Shodan/WAF/CDN/CT-logs/whois/geoip), recon pipeline (subdomains/ports/tech/URLs/DNS/screenshots/JS), threat modeling, vulnerability analysis, exploitation, 150+ Kali tools via KAL framework, sandbox management, cache control, knowledge base, admin.",
      "timeout": 300,
      "alwaysAllow": [
        "get_scan_status", "list_scans", "list_findings", "get_finding_detail",
        "get_adversarial_top", "get_poc_code", "get_report", "get_scan_cost",
        "get_available_skills", "get_scan_memory_summary", "get_process_list",
        "get_cache_stats", "get_cache_health", "get_system_health",
        "get_recon_status", "list_recon_engagements", "get_va_status",
        "get_threat_model_status", "get_exploitation_status",
        "get_findings_statistics", "list_report_formats",
        "get_skills_for_owasp", "get_skills_for_cwe", "list_all_skills",
        "get_tool_status", "get_available_tools",
        "get_admin_stats", "get_tenant_info", "get_llm_usage"
      ]
    }
  }
}
```

### `.cursor/rules/argus-mcp.md` — создать:

```markdown
---
description: ARGUS MCP Tool Naming & Usage Conventions
globs: mcp-server/**/*.py, backend/src/api/routers/**/*.py
alwaysApply: true
---

# ARGUS MCP Conventions

## Tool Naming
- snake_case, English
- Prefix by domain: `get_`, `list_`, `create_`, `start_`, `run_`, `delete_`, `update_`
- Scan tools: `create_scan`, `get_scan_status`, `cancel_scan`, `pause_scan`, `resume_scan`
- Finding tools: `get_finding_detail`, `validate_finding`, `mark_finding_false_positive`
- Report tools: `generate_report`, `download_report`, `get_report_status`
- Intel tools: `get_cve_intelligence`, `osint_domain`, `get_shodan_intel`, `whois_lookup`
- Recon tools: `start_recon`, `get_recon_subdomains`, `get_recon_ports`
- Kali tools: `kali_{tool_name}` (auto-registered from registry)
- KAL tools: `run_network_scan`, `run_web_scan`, `run_dns_enum`, `run_bruteforce`
- Cache tools: `get_cache_stats`, `flush_cache`, `warm_cache`
- KB tools: `get_skills_for_owasp`, `get_skills_for_cwe`, `get_scan_strategy`

## Parameter Conventions
- `scan_id`, `finding_id`, `report_id`, `engagement_id` — always `str` (UUID)
- `target` — URL or domain, `str`
- `tenant_id` — from env or explicit, `str`
- `severity` — `"critical" | "high" | "medium" | "low" | "info"`
- `scan_mode` — `"quick" | "standard" | "deep"`
- `tier` — `"midgard" | "asgard" | "valhalla"`
- `format` / `report_format` — `"html" | "json" | "pdf" | "csv"`

## Return Contract
All tools return `dict[str, Any]`. On error: `{"error": str, ...}`.
On success: domain-specific keys per endpoint contract.
Never raise exceptions — always return error dict.

## Backend API Mapping
Every MCP tool maps 1:1 to a backend API endpoint.
MCP tools NEVER execute commands directly — always via ArgusClient HTTP calls.
```

---

## БЛОК 5 — Адаптер create_scan: `_build_scan_request()`

### Что есть сейчас
- MCP `create_scan()` отправляет `{"target", "email", "scan_mode", "options": {"scanType": ...}}`
- Backend `ScanCreateRequest` ожидает `{"target", "email", "options": ScanOptions(scanType, reportFormat, rateLimit, ports, ...)}` и `scan_mode` как отдельное поле в Scan model
- Несоответствие: MCP передаёт плоский `scan_mode`, backend ожидает nested `options.scanType`

### Что реализовать

**В `mcp-server/argus_mcp.py` — добавить `_build_scan_request()`:**

```python
def _build_scan_request(
    target: str,
    email: str = "mcp@argus.local",
    scan_mode: str = "standard",
    ports: str = "80,443,8080,8443",
    report_format: str = "html",
    rate_limit: str = "normal",
    follow_redirects: bool = True,
    max_depth: int = 3,
    include_subs: bool = False,
    vulnerabilities: dict[str, bool] | None = None,
    auth_enabled: bool = False,
    auth_type: str = "basic",
    auth_username: str = "",
    auth_password: str = "",
    auth_token: str = "",
    kal_password_audit: bool = False,
    kal_dns_enum: bool = False,
    kal_network_capture: bool = False,
) -> dict[str, Any]:
    """
    Build a scan request payload matching backend ScanCreateRequest exactly.
    Resolves the contract mismatch between MCP's flat params and backend's nested schema.
    """
    sm = _scan_mode_from_alias(scan_mode)

    vuln_defaults = {"xss": True, "sqli": True, "csrf": True, "ssrf": False, "lfi": False, "rce": False}
    if vulnerabilities:
        vuln_defaults.update(vulnerabilities)

    return {
        "target": target.strip(),
        "email": email.strip() or "mcp@argus.local",
        "scan_mode": sm,
        "options": {
            "scanType": sm,
            "reportFormat": report_format,
            "rateLimit": rate_limit,
            "ports": ports,
            "followRedirects": follow_redirects,
            "vulnerabilities": vuln_defaults,
            "authentication": {
                "enabled": auth_enabled,
                "type": auth_type,
                "username": auth_username,
                "password": auth_password,
                "token": auth_token,
            },
            "scope": {
                "maxDepth": max_depth,
                "includeSubs": include_subs,
                "excludePatterns": "",
            },
            "advanced": {
                "timeout": 30,
                "userAgent": "chrome",
                "proxy": "",
                "customHeaders": "",
            },
            "kal": {
                "password_audit_opt_in": kal_password_audit,
                "recon_dns_enumeration_opt_in": kal_dns_enum,
                "va_network_capture_opt_in": kal_network_capture,
            },
        },
    }
```

**Обновить `ArgusClient.create_scan()`:**
```python
def create_scan(self, **kwargs) -> dict[str, Any]:
    payload = _build_scan_request(**kwargs)
    return self._post_json("/api/v1/scans", payload)
```

**Обновить `@mcp.tool() create_scan`** — расширить параметры:
```python
@mcp.tool()
def create_scan(
    target: str,
    email: str = "mcp@argus.local",
    scan_mode: str = "standard",
    ports: str = "80,443,8080,8443",
    report_format: str = "html",
    include_subs: bool = False,
    max_depth: int = 3,
    kal_password_audit: bool = False,
) -> dict[str, Any]:
    """Create a new security scan with full options control."""
    return client.create_scan(
        target=target, email=email, scan_mode=scan_mode,
        ports=ports, report_format=report_format,
        include_subs=include_subs, max_depth=max_depth,
        kal_password_audit=kal_password_audit,
    )
```

**Дополнительно для Argus — `_build_smart_scan_request()`:**
```python
def _build_smart_scan_request(
    target: str,
    objective: str = "comprehensive",
    max_phases: int = 5,
    focus_categories: list[str] | None = None,
    skip_categories: list[str] | None = None,
    budget_usd: float | None = None,
) -> dict[str, Any]:
    """Build smart scan request with AI objective and phase budget."""
    body: dict[str, Any] = {
        "target": target.strip(),
        "objective": objective,
        "max_phases": max_phases,
    }
    if focus_categories:
        body["focus_categories"] = focus_categories
    if skip_categories:
        body["skip_categories"] = skip_categories
    if budget_usd is not None:
        body["budget_usd"] = budget_usd
    return body
```

---

## БЛОК 6 — Замена всех ответов 501

### Полный список 501 endpoints и решение для каждого:

#### 1. `GET /sandbox/processes` → **РЕАЛИЗОВАТЬ**
**Решение:** Docker API через `docker.from_env()` или `subprocess` к `docker exec argus-sandbox ps aux`.

```python
@router.get("/processes")
async def sandbox_process_list() -> JSONResponse:
    """List running processes in sandbox container."""
    import subprocess as sp
    container = settings.sandbox_container_name
    try:
        result = sp.run(
            ["docker", "exec", container, "ps", "aux", "--sort=-%cpu"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return JSONResponse(content={
                "success": False, "processes": [],
                "error": f"ps failed: {result.stderr[:500]}",
            })
        lines = result.stdout.strip().split("\n")
        header = lines[0] if lines else ""
        processes = []
        for line in lines[1:]:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                processes.append({
                    "user": parts[0], "pid": int(parts[1]),
                    "cpu": float(parts[2]), "mem": float(parts[3]),
                    "vsz": parts[4], "rss": parts[5],
                    "stat": parts[7], "start": parts[8],
                    "time": parts[9], "command": parts[10],
                })
        return JSONResponse(content={
            "success": True, "processes": processes,
            "count": len(processes), "container": container,
        })
    except sp.TimeoutExpired:
        return JSONResponse(content={"success": False, "processes": [], "error": "timeout"})
    except FileNotFoundError:
        return JSONResponse(content={
            "success": False, "processes": [],
            "error": "docker CLI not available",
        })
```

#### 2. `POST /sandbox/processes/{pid}/kill` → **РЕАЛИЗОВАТЬ**
```python
@router.post("/processes/{pid}/kill")
async def sandbox_kill_process(pid: int) -> JSONResponse:
    """Kill a process in sandbox container by PID."""
    if pid <= 1:
        return JSONResponse(status_code=400, content={"success": False, "error": "Cannot kill PID <= 1"})
    import subprocess as sp
    container = settings.sandbox_container_name
    try:
        result = sp.run(
            ["docker", "exec", container, "kill", "-9", str(pid)],
            capture_output=True, text=True, timeout=10,
        )
        return JSONResponse(content={
            "success": result.returncode == 0,
            "pid": pid, "container": container,
            "error": result.stderr.strip()[:500] if result.returncode != 0 else None,
        })
    except Exception as e:
        return JSONResponse(content={"success": False, "pid": pid, "error": str(e)})
```

#### 3. `POST /sandbox/python` (disabled) → **РЕАЛИЗОВАТЬ** (feature-flagged)
Уже реализован — убрать 501, оставить feature flag `ARGUS_SANDBOX_PYTHON_ENABLED`. Вместо 501 возвращать 403 с объяснением:
```python
if not settings.argus_sandbox_python_enabled:
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"success": False, "error": "Python sandbox disabled. Set ARGUS_SANDBOX_PYTHON_ENABLED=true"},
    )
```

#### 4. `GET /scans/{id}/memory-summary` → **РЕАЛИЗОВАТЬ**
```python
@router.get("/{scan_id}/memory-summary")
async def get_scan_memory_summary(scan_id: str, tenant_id: str = Depends(get_current_tenant_id)):
    """Compressed scan context: findings summary, technologies, phases, progress."""
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        # Load scan
        result = await session.execute(
            select(Scan).where(cast(Scan.id, String) == scan_id, cast(Scan.tenant_id, String) == tenant_id)
        )
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        # Load findings
        fr = await session.execute(
            select(FindingModel).where(cast(FindingModel.scan_id, String) == scan_id)
        )
        findings = fr.scalars().all()
        # Load events
        er = await session.execute(
            select(ScanEvent).where(cast(ScanEvent.scan_id, String) == scan_id).order_by(ScanEvent.created_at)
        )
        events = er.scalars().all()

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    owasp_categories = set()
    cwe_ids = set()
    for f in findings:
        sev = (f.severity or "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        if f.owasp_category:
            owasp_categories.add(f.owasp_category)
        if f.cwe:
            cwe_ids.add(f.cwe)

    phases = []
    for ev in events:
        phases.append({
            "phase": ev.phase if hasattr(ev, "phase") else "unknown",
            "status": ev.status if hasattr(ev, "status") else "unknown",
            "timestamp": ev.created_at.isoformat() if ev.created_at else None,
            "message": (ev.message or "")[:200] if hasattr(ev, "message") else "",
        })

    return JSONResponse(content={
        "scan_id": scan_id,
        "target": scan.target_url,
        "status": scan.status,
        "progress": scan.progress or 0,
        "scan_mode": getattr(scan, "scan_mode", "standard"),
        "findings_summary": {
            "total": len(findings),
            "by_severity": severity_counts,
            "owasp_categories": sorted(owasp_categories),
            "cwe_ids": sorted(cwe_ids),
        },
        "phases": phases[-20:],  # last 20 events
        "technologies": scan.technologies if hasattr(scan, "technologies") else [],
        "cost_summary": scan.cost_summary if isinstance(scan.cost_summary, dict) else {},
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
    })
```

#### 5. `GET /findings/{id}/poc` (no PoC stored) → **УЛУЧШИТЬ**
Вместо 501 — попробовать auto-generate:
```python
@router.get("/{finding_id}/poc")
async def get_finding_poc(finding_id: str, tenant_id: str = Depends(get_current_tenant_id)):
    loaded = await _load_finding_for_tenant(finding_id, tenant_id)
    if not loaded:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding, target_url = loaded
    poc = finding.proof_of_concept if isinstance(finding.proof_of_concept, dict) else None
    if poc:
        return FindingPocBodyResponse(finding_id=finding_id, poc=poc)
    # Auto-generate minimal PoC hint from finding data
    return FindingPocBodyResponse(
        finding_id=finding_id,
        poc=None,
        poc_hint=f"No stored PoC. Use generate_poc({finding_id}) to create one via LLM.",
        can_generate=True,
    )
```

#### 6. `POST /findings/{id}/validate` (exception → 501) → **УЛУЧШИТЬ**
Вместо 501 при exception — возвращать partial result:
```python
except Exception as exc:
    logger.exception("finding_validate_failed", extra={"finding_id": finding_id})
    return FindingValidationApiResponse(
        finding_id=finding_id,
        status="error",
        confidence="unknown",
        reasoning=f"Validation pipeline error: {type(exc).__name__}. Check LLM provider configuration.",
        poc_command=None,
        actual_impact=None,
        preconditions=[],
        reject_reason=str(exc)[:200],
        exploit_public=False,
        exploit_sources=[],
        stages_passed=[],
    )
```

#### 7. `POST /findings/{id}/poc/generate` (exception → 501) → **УЛУЧШИТЬ**
Аналогично — возвращать error response вместо 501:
```python
except Exception as exc:
    logger.exception("finding_poc_generate_failed", extra={"finding_id": finding_id})
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "finding_id": finding_id,
            "error": f"PoC generation failed: {type(exc).__name__}",
            "detail": str(exc)[:200],
            "suggestion": "Ensure LLM provider keys are configured in .env",
        },
    )
```

#### 8. `GET /scans/{id}/report` (no report row → 501) → **УЛУЧШИТЬ**
Вместо 501 — auto-trigger report generation:
```python
if not report:
    # Auto-generate instead of 501
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "error": "no_report",
            "scan_id": scan_id,
            "tier": tier,
            "message": "No report generated yet. Use POST /scans/{scan_id}/reports/generate to create one.",
            "auto_generate_url": f"/api/v1/scans/{scan_id}/reports/generate",
        },
    )
```

### Дополнительные endpoint'ы для Argus (новые, не из 501 списка):

#### 9. `GET /api/v1/sandbox/status` — состояние sandbox контейнера
```python
@router.get("/status")
async def sandbox_status():
    """Check sandbox container health."""
    import subprocess as sp
    container = settings.sandbox_container_name
    try:
        result = sp.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", container],
            capture_output=True, text=True, timeout=5,
        )
        container_status = result.stdout.strip() if result.returncode == 0 else "not_found"
    except Exception:
        container_status = "docker_unavailable"

    return {
        "container": container,
        "status": container_status,
        "sandbox_enabled": settings.sandbox_enabled,
        "python_enabled": settings.argus_sandbox_python_enabled,
        "tools_timeout": settings.recon_tools_timeout,
    }
```

#### 10. `GET /api/v1/tools/available` — полный список доступных инструментов
```python
@router.get("/available")
async def list_available_tools():
    """List all allowlisted tools with their status."""
    from src.tools.guardrails.command_parser import ALLOWED_TOOLS
    tools = []
    for tool in sorted(ALLOWED_TOOLS):
        import shutil
        available = shutil.which(tool) is not None
        tools.append({"name": tool, "available": available, "path": shutil.which(tool)})
    return {"tools": tools, "count": len(tools)}
```

#### 11. `GET /api/v1/scans/{id}/timeline` — хронология событий скана
Агрегация ScanEvent'ов в human-readable timeline.

#### 12. `POST /api/v1/findings/{id}/false-positive` — отметить как false positive
Обновить `dedup_status` на `"false_positive"`, записать reason в `applicability_notes`.

#### 13. `GET /api/v1/findings/{id}/remediation` — рекомендации по исправлению
LLM-powered remediation advice на основе finding data + skill content.

#### 14. `GET /api/v1/scans/{id}/findings/statistics` — агрегированная статистика
```json
{
  "scan_id": "...",
  "total": 42,
  "by_severity": {"critical": 2, "high": 8, "medium": 15, "low": 12, "info": 5},
  "by_owasp": {"A01": 5, "A05": 12, ...},
  "by_confidence": {"confirmed": 10, "likely": 20, "possible": 12},
  "validated": 10,
  "false_positives": 3,
  "unique_cwes": ["CWE-79", "CWE-89", ...],
  "risk_score": 7.8
}
```

---

## БЛОК 7 — Миграция 017

**Файл: `backend/alembic/versions/017_knowledge_base_and_finding_notes.py`**

```python
"""
Add knowledge_base_cache table, finding_notes table, finding false_positive fields.

Revision ID: 017
Revises: 016
"""

revision: str = "017"
down_revision: str | None = "016"

def upgrade() -> None:
    # Finding notes
    op.execute("""
        CREATE TABLE IF NOT EXISTS finding_notes (
            id VARCHAR(36) PRIMARY KEY DEFAULT gen_random_uuid()::text,
            finding_id VARCHAR(36) NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
            tenant_id VARCHAR(36) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
            author VARCHAR(255) NOT NULL DEFAULT 'system',
            note TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS ix_finding_notes_finding_id ON finding_notes(finding_id)")

    # Finding false_positive tracking
    op.execute(
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS false_positive BOOLEAN DEFAULT FALSE"
    )
    op.execute(
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS false_positive_reason TEXT DEFAULT NULL"
    )

    # Scan timeline / phase tracking improvement
    op.execute(
        "ALTER TABLE scan_events ADD COLUMN IF NOT EXISTS duration_sec FLOAT DEFAULT NULL"
    )

def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS finding_notes")
    op.execute("ALTER TABLE findings DROP COLUMN IF EXISTS false_positive")
    op.execute("ALTER TABLE findings DROP COLUMN IF EXISTS false_positive_reason")
    op.execute("ALTER TABLE scan_events DROP COLUMN IF EXISTS duration_sec")
```

---

## БЛОК 8 — Чеклист POST-003/004/005

### POST-003: Все ответы 501 заменены
- [ ] `GET /sandbox/processes` — реализован через docker exec ps
- [ ] `POST /sandbox/processes/{pid}/kill` — реализован через docker exec kill
- [ ] `POST /sandbox/python` — 501→403 (feature-flagged, без noop-ответов)
- [ ] `GET /scans/{id}/memory-summary` — реализован (findings summary + phases + costs)
- [ ] `GET /findings/{id}/poc` — 501→200 с poc_hint + can_generate
- [ ] `POST /findings/{id}/validate` — exception→error response (503)
- [ ] `POST /findings/{id}/poc/generate` — exception→error response (503)
- [ ] `GET /scans/{id}/report` — 501→404 с auto_generate hint

### POST-004: MCP tools
- [ ] 150+ explicit `@mcp.tool()` functions registered
- [ ] Each tool has typed parameters + docstring
- [ ] ArgusClient extended with all new methods
- [ ] `argus-mcp.json` updated with full description + alwaysAllow
- [ ] `.cursor/rules/argus-mcp.md` created

### POST-005: Subsystems
- [ ] `ScanKnowledgeBase` with Redis + OWASP/CWE maps + warm_cache()
- [ ] `ToolRecoverySystem` with 150+ TOOL_ALTERNATIVES + MAX_RECOVERY_ATTEMPTS=3
- [ ] Cache API router with 10 endpoints
- [ ] `_build_scan_request()` adapter in MCP
- [ ] Migration 017 applied
- [ ] All new endpoints tested

---

## БЛОК 9 — Тесты

### `backend/tests/test_mcp_tools.py`

```python
"""
Tests for MCP tools — verify all registered tools, parameter contracts, response shapes.
Covers: scan management, findings, reports, intelligence, recon, cache, knowledge base.
"""
```

**Структура тестов:**

1. **test_scan_management_tools** — для каждого scan tool: mock ArgusClient, вызвать tool, проверить response shape
2. **test_finding_management_tools** — validate_finding, generate_poc, mark_false_positive, get_remediation
3. **test_report_tools** — generate_report, download_report, list_report_formats
4. **test_intelligence_tools** — cve search, osint, shodan, whois, geoip, ct-logs
5. **test_recon_tools** — start_recon, get_recon_subdomains, get_recon_ports
6. **test_cache_tools** — get_cache_stats, flush_cache, warm_cache
7. **test_knowledge_base_tools** — get_skills_for_owasp, get_skills_for_cwe, get_scan_strategy
8. **test_kali_tools_registration** — verify all 150 kali tools registered
9. **test_tool_naming_conventions** — all tool names are snake_case, no duplicates
10. **test_recovery_system** — TOOL_ALTERNATIVES completeness, stateful tools have no alts, MAX_RECOVERY_ATTEMPTS

### `backend/tests/test_scan_knowledge_base.py`

```python
"""Tests for ScanKnowledgeBase — OWASP/CWE mapping, Redis caching, warm_cache."""
```

1. test_owasp_to_skills_mapping — all A01-A10 return non-empty lists (except A03/A09)
2. test_cwe_to_skills_mapping — top 30 CWEs return correct skills
3. test_redis_caching — warm, get, verify TTL
4. test_fallback_without_redis — in-memory dict works when Redis unavailable
5. test_get_scan_strategy — merge OWASP + CWE → unique skills + tools
6. test_invalidate — keys deleted after invalidate
7. test_stats — hit/miss counters increment

### `backend/tests/test_tool_recovery.py`

```python
"""Tests for ToolRecoverySystem — alternatives, stateful tools, retry logic."""
```

1. test_alternatives_completeness — every tool in ALLOWED_TOOLS has entry
2. test_stateful_no_alternatives — sqlmap, hydra etc return []
3. test_should_retry — attempt 0..2 returns True, attempt 3 returns False
4. test_next_alternative — returns correct alt per attempt
5. test_build_recovery_info — correct structure
6. test_replace_tool_in_command — "nmap -sV target" → "rustscan -sV target"

### `backend/tests/test_cache_router.py`

```python
"""Tests for Cache API router — stats, flush, keys, health."""
```

1. test_get_cache_stats — returns hit_rate, memory, keys
2. test_flush_cache_allowlist — only argus: prefixed patterns allowed
3. test_list_keys — SCAN pagination
4. test_cache_health — Redis connectivity check
5. test_warm_cache — triggers KB warm
6. test_tool_ttls — returns correct per-tool TTL config
7. test_admin_auth_required — all endpoints require admin key

---

## ПОРЯДОК ВЫПОЛНЕНИЯ

1. **Блок 1** — `scan_knowledge_base.py` + тесты
2. **Блок 2** — `tool_recovery.py` + интеграция в sandbox router + тесты
3. **Блок 6** — замена всех ответов 501 + новые endpoints
4. **Блок 3** — `cache.py` router + тесты
5. **Блок 7** — миграция 017
6. **Блок 5** — `_build_scan_request()` в MCP
7. **Блок 4** — 150+ MCP tools + ArgusClient extension + argus-mcp.json + cursor rules
8. **Блок 9** — полный `test_mcp_tools.py`
9. **Блок 8** — проверка чеклиста POST-003/004/005

**После каждого блока:**
- `ruff check` PASS
- `pytest` для нового кода PASS
- Не сломаны существующие тесты

---

## ЗАПРЕЩЕНО

1. `raise HTTPException(status_code=501)` — нигде в финальном коде
2. Legacy recovery helper в tool_cache — удалить, заменить на `ToolRecoverySystem.build_recovery_info()`
3. Маркеры незавершённой работы в комментариях или `pass` без реализации
4. `**kwargs` без типизации
5. `Any` returns без cause
6. Dynamic tool registration для новых MCP tools (kali registry — исключение)
7. Менять frontend.
8. Нарушать существующие API‑контракты.
