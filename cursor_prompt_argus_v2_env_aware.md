# ARGUS Enhancement — Cursor Agent Prompt (v2, env-aware)

## КОНТЕКСТ ДЛЯ CURSOR

Проект ARGUS — AI-powered penetration testing platform.
- Backend: FastAPI + Celery + Python (backend/)
- Отчёты: Python + Jinja2 (tier "valhalla")
- Инфра: Docker Compose, MinIO, PostgreSQL, Redis
- Sandbox: расширенный (Kali tools + MSF установлен)

**Активные LLM провайдеры** (ключи есть в .env):
- OpenRouter (OPENROUTER_API_KEY) — агрегатор, даёт доступ к claude-3.5, gpt-4o, deepseek и др.
- OpenAI (OPENAI_API_KEY) — gpt-4o, gpt-4o-mini
- DeepSeek (DEEPSEEK_API_KEY) — deepseek-chat, deepseek-reasoner (сильный и дешёвый)
- Kimi/Moonshot (KIMI_API_KEY) — moonshot-v1-8k/32k/128k
- Perplexity (PERPLEXITY_API_KEY) — с веб-поиском (llama-3.1-sonar-huge-online)
- Google (GOOGLE_API_KEY) — пустой, пропустить

**Активные intel-ключи:**
- Shodan (SHODAN_API_KEY) — уже установлен, использовать в recon
- NVD, ExploitDB, VirusTotal, UrlScan, GreyNoise, OTX — пустые, но структуру заложить

**Уже работает в .env:**
- VA_AI_PLAN_ENABLED=true
- VA_EXPLOIT_AGGRESSIVE_ENABLED=true
- VA_POC_PLAYWRIGHT_SCREENSHOT_ENABLED=true
- SQLMAP_VA_ENABLED=true
- SANDBOX_PROFILE=extended + INSTALL_MSF=true
- XSS_BROWSER_VERIFICATION_ENABLED=true
- AI_TEXT_EXECUTIVE_FACT_CHECK_REPLACE=true
- SEARCHSPLOIT_ENABLED=true
- TRIVY_ENABLED=true
- HIBP_PASSWORD_CHECK_OPT_IN=true
- RECON_MODE=full (все инструменты активны)

Изучи структуру backend/ и найди:
1. LLM-клиент / провайдер-абстракцию (скорее всего backend/app/llm/ или core/)
2. AI-промпты для секций отчёта Valhalla
3. Finding модель (Pydantic)
4. Pipeline фаз скана

Реализуй следующие улучшения:

═══════════════════════════════════════════════════════════════
УЛУЧШЕНИЕ 0: MULTI-PROVIDER LLM ROUTER (ФУНДАМЕНТ ДЛЯ ВСЕГО)
═══════════════════════════════════════════════════════════════

Найди существующий LLM-клиент в backend/. Если уже есть абстракция провайдеров —
расширь её. Если нет — создай backend/app/llm/router.py

Цель: разные задачи используют разные провайдеры оптимально по cost/quality.

```python
# backend/app/llm/router.py

from enum import Enum
from typing import Literal
import os

class LLMTask(Enum):
    """Task types mapped to optimal provider/model."""
    EXECUTIVE_SUMMARY    = "executive_summary"     # требует: высокое качество текста
    THREAT_MODELING      = "threat_modeling"       # требует: reasoning + creativity
    EXPLOIT_GENERATION   = "exploit_generation"    # требует: code quality, accuracy
    VALIDATION_ONESHOT   = "validation_oneshot"    # требует: reasoning, cheap per call
    REMEDIATION_PLAN     = "remediation_plan"      # требует: technical depth
    ZERO_DAY_ANALYSIS    = "zero_day_analysis"     # требует: deep reasoning
    DEDUP_ANALYSIS       = "dedup_analysis"        # требует: fast + cheap
    SHODAN_ENRICHMENT    = "shodan_enrichment"     # не LLM — Shodan API
    PERPLEXITY_OSINT     = "perplexity_osint"      # требует: web search

# Routing table: task → (provider, model, fallback_model)
# Логика: DeepSeek дёшев и силён для reasoning/code; OpenAI для текста; OpenRouter как fallback
ROUTING_TABLE = {
    LLMTask.EXECUTIVE_SUMMARY: {
        "provider": "openrouter",
        "model": "anthropic/claude-3.5-sonnet",         # лучший для executive prose
        "fallback": "openai/gpt-4o",
        "max_tokens": 1500,
        "temperature": 0.3,
    },
    LLMTask.THREAT_MODELING: {
        "provider": "deepseek",
        "model": "deepseek-reasoner",                    # R1 — отличный для reasoning chains
        "fallback": "openrouter/anthropic/claude-3.5-sonnet",
        "max_tokens": 2000,
        "temperature": 0.4,
    },
    LLMTask.EXPLOIT_GENERATION: {
        "provider": "deepseek",
        "model": "deepseek-chat",                        # сильный код, дёшево
        "fallback": "openai/gpt-4o",
        "max_tokens": 2000,
        "temperature": 0.1,                             # code needs low temp
    },
    LLMTask.VALIDATION_ONESHOT: {
        "provider": "deepseek",
        "model": "deepseek-chat",                        # ~$0.001/call, достаточно для validation
        "fallback": "openrouter/meta-llama/llama-3.1-70b-instruct",
        "max_tokens": 800,
        "temperature": 0.1,
    },
    LLMTask.REMEDIATION_PLAN: {
        "provider": "openai",
        "model": "gpt-4o-mini",                          # дёшево, достаточно для патчей
        "fallback": "deepseek/deepseek-chat",
        "max_tokens": 2000,
        "temperature": 0.2,
    },
    LLMTask.ZERO_DAY_ANALYSIS: {
        "provider": "deepseek",
        "model": "deepseek-reasoner",                    # deep reasoning для novel attacks
        "fallback": "openrouter/anthropic/claude-3.5-sonnet",
        "max_tokens": 1500,
        "temperature": 0.5,
    },
    LLMTask.DEDUP_ANALYSIS: {
        "provider": "deepseek",
        "model": "deepseek-chat",                        # самый дешёвый вариант
        "fallback": "openai/gpt-4o-mini",
        "max_tokens": 500,
        "temperature": 0.0,                             # deterministic dedup
    },
    LLMTask.PERPLEXITY_OSINT: {
        "provider": "perplexity",
        "model": "llama-3.1-sonar-huge-online",          # web search enabled
        "fallback": "llama-3.1-sonar-large-32k-online",
        "max_tokens": 1000,
        "temperature": 0.2,
    },
}

class MultiProviderLLMRouter:
    """
    Routes LLM calls to optimal provider based on task type.
    Falls back automatically if primary provider fails or key missing.
    Tracks cost per call.
    """
    
    def __init__(self, settings):
        self.settings = settings
        self._clients = {}  # lazy init
    
    def _get_available_providers(self) -> list[str]:
        """Return list of providers with valid (non-empty) API keys."""
        providers = []
        if os.getenv("OPENROUTER_API_KEY"):
            providers.append("openrouter")
        if os.getenv("OPENAI_API_KEY"):
            providers.append("openai")
        if os.getenv("DEEPSEEK_API_KEY"):
            providers.append("deepseek")
        if os.getenv("KIMI_API_KEY"):
            providers.append("kimi")
        if os.getenv("PERPLEXITY_API_KEY"):
            providers.append("perplexity")
        return providers
    
    async def complete(
        self,
        task: LLMTask,
        system_prompt: str,
        user_prompt: str,
        scan_id: str | None = None,
    ) -> LLMResponse:
        """
        Execute LLM call with automatic provider routing and fallback.
        Records cost to ScanCostTracker if scan_id provided.
        """
        route = ROUTING_TABLE[task]
        available = self._get_available_providers()
        
        # Try primary, then fallback
        for provider_model in [f"{route['provider']}/{route['model']}", route.get("fallback", "")]:
            if not provider_model:
                continue
            provider = provider_model.split("/")[0]
            if provider not in available:
                continue
            try:
                response = await self._call_provider(
                    provider=provider,
                    model=provider_model,
                    system=system_prompt,
                    user=user_prompt,
                    max_tokens=route["max_tokens"],
                    temperature=route["temperature"],
                )
                if scan_id:
                    await self._record_cost(scan_id, task, response)
                return response
            except Exception as e:
                logger.warning(f"LLM provider {provider} failed for {task}: {e}, trying fallback")
        
        raise LLMAllProvidersFailedError(f"All providers failed for task {task}")
    
    async def _call_provider(self, provider: str, model: str, **kwargs) -> LLMResponse:
        """Dispatch to provider-specific client."""
        if provider == "openrouter":
            return await self._call_openrouter(model, **kwargs)
        elif provider == "openai":
            return await self._call_openai(model, **kwargs)
        elif provider == "deepseek":
            return await self._call_deepseek(model, **kwargs)
        elif provider == "perplexity":
            return await self._call_perplexity(model, **kwargs)
        elif provider == "kimi":
            return await self._call_kimi(model, **kwargs)
        raise ValueError(f"Unknown provider: {provider}")
    
    async def _call_openrouter(self, model: str, system: str, user: str, 
                                max_tokens: int, temperature: float) -> LLMResponse:
        """OpenRouter uses OpenAI-compatible API."""
        import openai
        client = openai.AsyncOpenAI(
            api_key=os.getenv("OPENROUTER_API_KEY"),
            base_url="https://openrouter.ai/api/v1",
            default_headers={
                "HTTP-Referer": "https://argus-security.io",
                "X-Title": "ARGUS Security Scanner",
            }
        )
        # model в OpenRouter: "anthropic/claude-3.5-sonnet" или убрать prefix "openrouter/"
        clean_model = model.replace("openrouter/", "")
        resp = await client.chat.completions.create(
            model=clean_model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            max_tokens=max_tokens,
            temperature=temperature,
        )
        return LLMResponse(
            text=resp.choices[0].message.content,
            provider="openrouter",
            model=clean_model,
            prompt_tokens=resp.usage.prompt_tokens,
            completion_tokens=resp.usage.completion_tokens,
        )
    
    async def _call_deepseek(self, model: str, system: str, user: str,
                              max_tokens: int, temperature: float) -> LLMResponse:
        """DeepSeek uses OpenAI-compatible API."""
        import openai
        client = openai.AsyncOpenAI(
            api_key=os.getenv("DEEPSEEK_API_KEY"),
            base_url="https://api.deepseek.com/v1",
        )
        clean_model = model.replace("deepseek/", "")
        resp = await client.chat.completions.create(
            model=clean_model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            max_tokens=max_tokens,
            temperature=temperature,
        )
        return LLMResponse(
            text=resp.choices[0].message.content,
            provider="deepseek",
            model=clean_model,
            prompt_tokens=resp.usage.prompt_tokens,
            completion_tokens=resp.usage.completion_tokens,
        )
    
    async def _call_perplexity(self, model: str, system: str, user: str,
                                max_tokens: int, temperature: float) -> LLMResponse:
        """Perplexity — web-search enabled, useful for CVE/OSINT enrichment."""
        import openai
        client = openai.AsyncOpenAI(
            api_key=os.getenv("PERPLEXITY_API_KEY"),
            base_url="https://api.perplexity.ai",
        )
        clean_model = model.replace("perplexity/", "")
        resp = await client.chat.completions.create(
            model=clean_model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            max_tokens=max_tokens,
            temperature=temperature,
        )
        return LLMResponse(
            text=resp.choices[0].message.content,
            provider="perplexity",
            model=clean_model,
            prompt_tokens=resp.usage.prompt_tokens,
            completion_tokens=resp.usage.completion_tokens,
        )
    
    async def _call_kimi(self, model: str, system: str, user: str,
                          max_tokens: int, temperature: float) -> LLMResponse:
        """Kimi/Moonshot — OpenAI-compatible, good for long context."""
        import openai
        client = openai.AsyncOpenAI(
            api_key=os.getenv("KIMI_API_KEY"),
            base_url="https://api.moonshot.cn/v1",
        )
        clean_model = model.replace("kimi/", "")
        resp = await client.chat.completions.create(
            model=clean_model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
            max_tokens=max_tokens,
            temperature=temperature,
        )
        return LLMResponse(
            text=resp.choices[0].message.content,
            provider="kimi",
            model=clean_model,
            prompt_tokens=resp.usage.prompt_tokens,
            completion_tokens=resp.usage.completion_tokens,
        )

# Cost constants (USD per 1K tokens, input/output)
PROVIDER_COSTS = {
    "deepseek-chat":               {"input": 0.00014, "output": 0.00028},   # дешевле всех
    "deepseek-reasoner":           {"input": 0.00055, "output": 0.00219},   # R1
    "gpt-4o":                      {"input": 0.0025,  "output": 0.010},
    "gpt-4o-mini":                 {"input": 0.00015, "output": 0.0006},
    "anthropic/claude-3.5-sonnet": {"input": 0.003,   "output": 0.015},     # via openrouter
    "llama-3.1-sonar-huge-online": {"input": 0.005,   "output": 0.005},
    "moonshot-v1-8k":              {"input": 0.001,   "output": 0.003},
}
```

Интегрируй MultiProviderLLMRouter как синглтон в FastAPI app (lifespan).
Внедри через DI во все сервисы, которые сейчас вызывают LLM напрямую.
Добавь env var LLM_PRIMARY_PROVIDER (default: "deepseek") как глобальный override.


═══════════════════════════════════════════════════════════════
УЛУЧШЕНИЕ 1: SHODAN ENRICHMENT ДЛЯ FINDINGS
═══════════════════════════════════════════════════════════════

SHODAN_API_KEY уже установлен. Используй его для обогащения findings.
Создай backend/app/intel/shodan_enricher.py

```python
import shodan  # pip install shodan
import os

class ShodanEnricher:
    """
    Enrich scan findings with Shodan intelligence.
    Uses SHODAN_API_KEY from env.
    """
    
    def __init__(self):
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            raise ValueError("SHODAN_API_KEY not set")
        self.api = shodan.Shodan(api_key)
    
    async def enrich_target(self, target_host: str) -> ShodanResult:
        """
        Query Shodan for target host info.
        Returns: open ports, services, CVEs from Shodan, banners, ISP, ASN.
        Cache result in Redis (TTL=24h) to avoid repeated API calls.
        """
        try:
            host = self.api.host(target_host)
            return ShodanResult(
                ip=host.get("ip_str"),
                hostnames=host.get("hostnames", []),
                org=host.get("org"),
                isp=host.get("isp"),
                asn=host.get("asn"),
                country=host.get("country_name"),
                open_ports=[item["port"] for item in host.get("data", [])],
                services=[
                    ShodanService(
                        port=item["port"],
                        transport=item.get("transport", "tcp"),
                        product=item.get("product"),
                        version=item.get("version"),
                        cpe=item.get("cpe", []),
                        banner=item.get("data", "")[:500],  # truncate
                    )
                    for item in host.get("data", [])
                ],
                vulns=list(host.get("vulns", {}).keys()),  # CVE IDs from Shodan
                tags=host.get("tags", []),
            )
        except shodan.APIError as e:
            logger.warning(f"Shodan lookup failed for {target_host}: {e}")
            return None
    
    async def cross_reference_vulns(
        self, shodan_result: ShodanResult, findings: list[Finding]
    ) -> list[Finding]:
        """
        Cross-reference findings with Shodan CVEs.
        If Shodan reports CVE on the same port/service as a finding — 
        mark finding as shodan_confirmed=True and add shodan_cves list.
        """
        if not shodan_result or not shodan_result.vulns:
            return findings
        
        enriched = []
        for finding in findings:
            # Match by CVE if finding has CVE
            if finding.cve_ids:
                matching = set(finding.cve_ids) & set(shodan_result.vulns)
                if matching:
                    finding.shodan_confirmed = True
                    finding.shodan_cves = list(matching)
                    finding.confidence = "confirmed"  # upgrade confidence
            # Match by service/port
            if finding.affected_port:
                for svc in shodan_result.services:
                    if svc.port == finding.affected_port and svc.product:
                        finding.shodan_service_info = f"{svc.product} {svc.version or ''}".strip()
            enriched.append(finding)
        
        return enriched
```

Вызывай ShodanEnricher в начале recon-фазы для основного IP таргета.
Результат Shodan:
1. Добавляй в секцию "Технологический стек" отчёта Valhalla
2. Используй open_ports для VA-фазы (расширить список портов для сканирования)
3. Shodan CVEs → автоматически создавай findings с confidence="confirmed"
4. Если Shodan.vulns пересекается с нашими findings → повышай их severity

Добавь SHODAN_ENRICHMENT_ENABLED=true в .env.example с описанием.


═══════════════════════════════════════════════════════════════
УЛУЧШЕНИЕ 2: PERPLEXITY ДЛЯ CVE/OSINT ОБОГАЩЕНИЯ
═══════════════════════════════════════════════════════════════

PERPLEXITY_API_KEY есть. Perplexity имеет доступ к интернету — идеально для:
- Поиска эксплойтов к найденным CVE
- OSINT по домену/организации
- Получения актуальных PoC из GitHub

Создай backend/app/intel/perplexity_enricher.py

```python
class PerplexityIntelEnricher:
    """
    Uses Perplexity (web-search LLM) for real-time CVE and OSINT enrichment.
    """
    
    async def enrich_cve(self, cve_id: str, product: str = "") -> CVEIntel:
        """
        Search for latest CVE exploit info, public PoC, patch status.
        Prompt:
        
        SYSTEM: You are a vulnerability intelligence analyst. 
        Search for current information and respond in JSON only.
        
        USER: Research CVE {cve_id} affecting {product}.
        Return JSON with:
        {
          "cvss_v3": float,
          "severity": "critical/high/medium/low",
          "description": "one sentence",
          "exploit_available": true/false,
          "exploit_sources": ["github url", "exploit-db url"],
          "patch_available": true/false,
          "patch_url": "url or null",
          "actively_exploited": true/false,
          "affected_versions": ["version range"],
          "remediation": "one sentence action"
        }
        """
    
    async def osint_domain(self, domain: str) -> DomainOSINT:
        """
        OSINT lookup for target domain.
        Finds: data breaches, leaked credentials, related domains, 
        technology stack from public sources, known vulnerabilities.
        
        SYSTEM: You are an OSINT analyst. Search for public information only.
        Do not include private or sensitive data. Respond in JSON.
        
        USER: Research this domain for a security assessment: {domain}
        Find:
        1. Known data breaches or leaks (cite sources)
        2. Technology stack (from public job listings, cert transparency, etc.)
        3. Related subdomains or infrastructure
        4. Any public security disclosures or bug bounty reports
        5. Company/org background relevant to attack surface
        
        Return JSON: {"breaches": [], "tech_stack": [], "subdomains": [],
                     "public_vulns": [], "org_info": {}}
        """
    
    async def find_public_exploits(self, findings: list[Finding]) -> list[Finding]:
        """
        For each finding with CVE, search for public exploit/PoC.
        Only run if NVD_API_KEY or EXPLOITDB_API_KEY not set (prefer those if available).
        """
```

Вызывай после recon-фазы:
- osint_domain() → данные в секцию "Контекст цели" Valhalla
- enrich_cve() → для каждого finding с CVE, добавляй exploit_available в таблицу findings
- Если exploit_available=True → автоматически повышай severity на один уровень
- Добавь флаг: PERPLEXITY_INTEL_ENABLED (default: true если ключ есть)


═══════════════════════════════════════════════════════════════
УЛУЧШЕНИЕ 3: EXPLOITABILITY VALIDATION PIPELINE
═══════════════════════════════════════════════════════════════

Используй DeepSeek Reasoner (R1) для validation — он лучший для reasoning-цепочек.
Создай backend/app/validation/exploitability.py

Промпт для Stage A (One-Shot Validation) — адаптирован под DeepSeek R1:

```python
STAGE_A_SYSTEM = """
You are a senior penetration tester with 15 years of experience.
Your task: validate whether a security finding is REAL and EXPLOITABLE.

Critical rules:
- REJECT findings that only affect test/mock/example code
- REJECT findings that require physical access or unrealistic conditions  
- REJECT findings described with hedging language ("might", "could possibly")
- CONFIRM only if you can construct a concrete, realistic attack path

Respond ONLY in valid JSON, no markdown, no explanation outside the JSON.
"""

STAGE_A_USER = """
Validate this security finding:

Title: {title}
Description: {description}
Evidence: {evidence}
Affected URL/Component: {affected_url}
CWE: {cwe}
OWASP: {owasp}
CVSS: {cvss}
Scan tool output: {tool_evidence}

Required JSON response:
{{
  "exploitable": true/false,
  "confidence": "high/medium/low",
  "reasoning": "2-3 sentences explaining your decision",
  "poc_command": "curl command or python snippet demonstrating the vulnerability",
  "actual_impact": "what an attacker actually gains",
  "preconditions": ["list of required conditions"],
  "reject_reason": "null or reason if not exploitable"
}}
"""

STAGE_C_SANITY_SYSTEM = """
You are a code reviewer performing a sanity check on vulnerability analysis.
Your task: verify that the LLM's analysis matches the actual evidence.

Check:
1. Is the affected URL/file real (not hallucinated)?
2. Is the code path reachable (not dead code)?
3. Does the PoC actually demonstrate the claimed vulnerability?
4. Are CVSS score and severity consistent?

Respond in JSON only.
"""

STAGE_D_RULING_SYSTEM = """
You are a final arbiter for security findings.
Apply strict filtering:

AUTOMATICALLY REJECT if finding:
- Is from test/, mock/, example/, __tests__/ directory
- Has title "unknown finding" or empty description
- Requires conditions that no real attacker would have
- Is a duplicate of another finding (same CWE + same URL)
- Has CVSS > 6.9 but severity = "low" (scoring conflict)

AUTOMATICALLY CONFIRM if finding:
- Has Shodan CVE cross-reference (shodan_confirmed=True)
- Has working PoC from Stage A
- Is exploitable from the internet with no authentication

Respond in JSON: {"decision": "confirm/reject", "reason": "..."}
"""
```

Stage E добавь использование Perplexity для поиска public exploit:
```python
async def stage_e_self_review(self, findings: list[ValidatedFinding]) -> list[ValidatedFinding]:
    """
    Final review + Perplexity public exploit search for confirmed findings.
    If public exploit exists for CVE — mark exploit_public=True.
    """
    if os.getenv("PERPLEXITY_API_KEY"):
        enricher = PerplexityIntelEnricher()
        for f in findings:
            if f.status == "confirmed" and f.cve_ids:
                intel = await enricher.enrich_cve(f.cve_ids[0])
                f.exploit_public = intel.exploit_available
                f.exploit_sources = intel.exploit_sources
    return findings
```


═══════════════════════════════════════════════════════════════
УЛУЧШЕНИЕ 4: ADVERSARIAL PRIORITIZATION SCORE
═══════════════════════════════════════════════════════════════

Создай backend/app/scoring/adversarial.py

```python
def compute_adversarial_score(finding: Finding) -> float:
    """
    RAPTOR-inspired formula: Impact × Exploitability / Detection_Time
    
    Учитывает данные из Shodan и Perplexity если доступны.
    """
    impact = _impact_score(finding)
    exploitability = _exploitability_score(finding)
    detection = _detection_time_score(finding)
    
    base_score = (impact * exploitability) / max(detection, 1)
    
    # Boost modifiers
    if finding.shodan_confirmed:
        base_score *= 1.5          # Shodan подтвердил — реальнее
    if getattr(finding, 'exploit_public', False):
        base_score *= 2.0          # Public exploit существует — критично
    if finding.poc_code:
        base_score *= 1.3          # Есть рабочий PoC
    
    return round(min(base_score, 10.0), 2)

def _impact_score(f: Finding) -> float:
    """Business impact 1-10."""
    severity_map = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 0.5}
    base = severity_map.get(f.severity.lower(), 3)
    # CVSS override if more precise
    if f.cvss:
        base = f.cvss
    # Boost for specific high-impact categories
    if f.owasp_category in ("A01", "A02", "A07"):  # access control, auth
        base = min(base * 1.2, 10)
    return base

def _exploitability_score(f: Finding) -> float:
    """Ease of exploitation 1-10."""
    score = 5.0  # default
    confidence_map = {"confirmed": 9, "likely": 7, "possible": 4, "theoretical": 1}
    score = confidence_map.get(f.confidence, 5)
    # No auth required → easier
    if f.cvss_vector and "AV:N/AC:L/PR:N" in f.cvss_vector:
        score = min(score + 2, 10)
    return score

def _detection_time_score(f: Finding) -> float:
    """
    How long before defenders notice (higher = harder to detect = dangerous).
    Used as DIVISOR — high detection_time means lower urgency to defenders.
    """
    # Categories that are silent (no obvious logs)
    silent_categories = {"A01", "A04", "A10"}  # access control, crypto, SSRF
    if f.owasp_category in silent_categories:
        return 8.0
    # Categories that trigger alerts
    noisy_categories = {"A03", "A05"}  # injection (SQLi triggers WAF)
    if f.owasp_category in noisy_categories:
        return 3.0
    return 5.0  # default medium detectability
```

Добавь поле `adversarial_score: float` к Finding модели.
Используй как первичный ключ сортировки в Valhalla findings таблице.
В секции "Критически важные уязвимости" показывай findings с adversarial_score >= 4.0.


═══════════════════════════════════════════════════════════════
УЛУЧШЕНИЕ 5: ЭКСПЕРТ-ПЕРСОНЫ + MARKDOWN FIX (КРИТИЧНО)
═══════════════════════════════════════════════════════════════

КРИТИЧЕСКИЙ БАГ: ai-slot-body рендерит сырой Markdown.
Исправить в двух местах:

1. Python: конвертировать Markdown → HTML перед записью в шаблон:
```python
# pip install markdown
import markdown as md_lib
from markupsafe import Markup

def md_to_html(text: str) -> str:
    """Convert AI-generated markdown to safe HTML."""
    if not text or not text.strip():
        return ""
    return Markup(md_lib.markdown(
        text,
        extensions=["extra", "nl2br", "sane_lists"],
        output_format="html",
    ))
```

2. Jinja2: убрать white-space: pre-wrap из .ai-slot-body CSS.
   Заменить `{{ ai_text }}` на `{{ ai_text | md_to_html | safe }}`.

Персоны — полные system prompts (на языке отчёта через переменную {lang}):

```python
VALHALLA_PERSONAS = {

"executive_summary": """
You are a Chief Information Security Officer (CISO) writing an executive summary 
for a board-level audience. Write in {lang}. 
CRITICAL: Do NOT use Markdown formatting. No asterisks, no hashes, no bullet dashes.
Write only plain prose paragraphs.

Structure (4 paragraphs):
1. Overall security verdict in one clear sentence. Then overall posture.
2. Most significant risks and their business consequences (not technical details).
3. What the assessment covered and what was NOT found (scope confirmation).
4. Three immediate priority actions with estimated business value.

The audience is non-technical executives. Translate every finding to business impact.
Example: not "missing CSP header" but "users can be tricked into performing 
unintended actions on our platform, enabling fraud".
""",

"threat_modeling": """
You are a red team lead with expertise in STRIDE threat modeling.
Write in {lang}. CRITICAL: No Markdown formatting. Plain prose only.

Your task: build ATTACK CHAINS, not individual vulnerability descriptions.
The reader already has the findings table — do not repeat it.

For each of 2-3 scenarios describe:
- Attacker persona (opportunistic script kiddie / targeted nation-state / insider threat)  
- Entry point and initial access method
- Step-by-step attack progression (how findings combine)
- What the attacker achieves at the end
- Estimated time to execute: hours / days / weeks
- Likelihood: Low / Medium / High with one-sentence justification

If the threat_model_context is empty {{}}, acknowledge limited recon data 
and base scenarios on confirmed findings only.
Never invent findings not in the provided list.
""",

"zero_day_potential": """
You are a vulnerability researcher specializing in novel attack techniques.
Write in {lang}. CRITICAL: No Markdown formatting. Plain prose only.

Analyze the provided findings for NON-OBVIOUS exploitation potential:
1. Can low-severity findings be CHAINED to achieve critical impact?
2. Are there logic flaws that automated scanners typically miss?
3. What manual testing areas would be highest-value given this attack surface?
4. Assign: Zero-Day Potential Rating: None / Low / Medium / High
   One sentence justification for the rating.

Be honest. If findings are standard web misconfigurations with no novel angle, 
say so explicitly. Do NOT inflate findings to appear more impressive.
Do NOT list individual findings — synthesize.
""",

"remediation_plan": """
You are a DevSecOps engineer and secure coding expert.
Write in {lang}. CRITICAL: No Markdown formatting. Plain prose only.

Write a CONCRETE, ACTIONABLE remediation plan grouped by effort tier:

Tier 1 — Fix within 48 hours (confirmed exploitable, CVSS >= 7.0 or adversarial_score >= 5):
For each: what to change, where (specific config/file location), 
exact value or code snippet, how to verify the fix.

Tier 2 — Fix within 2 weeks (medium priority):
For each: same structure as Tier 1.

Tier 3 — Architectural / SDLC improvements (> 1 month):
Structural issues that require design changes, not just config updates.

Reference finding IDs. Do NOT invent fixes for findings not in the list.
If Shodan data is available, mention specific versions to patch.
""",

"cost_summary": """
You are a security program manager summarizing the scan economics.
Write in {lang}. CRITICAL: No Markdown formatting. Plain prose only.

Summarize the scan in 2 short paragraphs:
1. What was scanned, how many findings, noise reduction from validation pipeline.
2. LLM cost breakdown: total cost, cost per confirmed finding, most expensive phase.

Keep it factual and brief. This is a metadata section, not analysis.
""",

}
```

Добавь к каждому вызову LLM соответствующую персону из VALHALLA_PERSONAS.
Передавай `lang` из параметра скана (default: "ru" для русского вывода).


═══════════════════════════════════════════════════════════════
УЛУЧШЕНИЕ 6: POC GENERATION С ПОДДЕРЖКОЙ PLAYWRIGHT
═══════════════════════════════════════════════════════════════

VA_POC_PLAYWRIGHT_SCREENSHOT_ENABLED=true уже в .env.
MSF (Metasploit) установлен (INSTALL_MSF=true).
Расширь логику PoC generation с учётом этих возможностей.

Создай backend/app/exploit/generator.py

```python
POC_GENERATION_SYSTEM = """
You are an expert penetration tester writing minimal proof-of-concept exploit code.
Write ONLY valid, runnable code. No markdown formatting. No explanations outside comments.

Rules:
- Code must be HARMLESS (read-only operations, no destructive payloads)
- Include assertion that confirms successful exploitation
- Prefer Python + requests for web vulnerabilities
- For XSS: generate Playwright-compatible verification script (the platform has Playwright)
- For auth bypass: show the unauthorized access, then stop
- For rate limiting: show the missing 429 response, then stop
- For header issues: show missing header via curl
"""

POC_GENERATION_USER = """
Generate a PoC for:
Title: {title}
Type: {cwe} / {owasp}
Target: {affected_url}
Description: {description}
Evidence from scanner: {evidence}
Shodan context: {shodan_context}

Output format: Python script or bash commands.
Start with:
#!/usr/bin/env python3
# PoC: {title}
# Target: {affected_url}
# Severity: {severity} | CVSS: {cvss} | A-Score: {adversarial_score}
# Finding ID: {finding_id}
"""

class PocGenerator:
    
    async def generate(self, finding: Finding, target: str) -> PocResult:
        """
        Generate PoC. For XSS findings with Playwright enabled,
        generate both curl and Playwright script.
        """
        # Use DeepSeek for code generation (best code quality / cost ratio)
        poc_code = await self.llm_router.complete(
            task=LLMTask.EXPLOIT_GENERATION,
            system_prompt=POC_GENERATION_SYSTEM,
            user_prompt=POC_GENERATION_USER.format(
                title=finding.title,
                cwe=finding.cwe or "N/A",
                owasp=finding.owasp_category or "N/A",
                affected_url=finding.affected_url or target,
                description=finding.description,
                evidence=finding.evidence or "",
                shodan_context=getattr(finding, 'shodan_service_info', 'N/A'),
                severity=finding.severity,
                cvss=finding.cvss or "N/A",
                adversarial_score=getattr(finding, 'adversarial_score', 'N/A'),
                finding_id=str(finding.id),
            ),
            scan_id=str(finding.scan_id),
        )
        
        # For XSS: also generate Playwright verification script
        playwright_script = None
        if finding.cwe in ("CWE-79", "CWE-80") and os.getenv("VA_POC_PLAYWRIGHT_SCREENSHOT_ENABLED") == "true":
            playwright_script = await self._generate_playwright_xss_verifier(finding)
        
        return PocResult(
            finding_id=finding.id,
            poc_code=poc_code.text,
            playwright_script=playwright_script,
            generator_model=poc_code.model,
            generated_at=datetime.utcnow(),
        )
    
    async def _generate_playwright_xss_verifier(self, finding: Finding) -> str:
        """Generate Playwright script that takes screenshot of XSS execution."""
        # Minimal template — Playwright already configured on worker
        return f"""
from playwright.sync_api import sync_playwright

def verify_xss():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        
        dialog_fired = []
        page.on("dialog", lambda d: (dialog_fired.append(d.message), d.dismiss()))
        
        page.goto("{finding.affected_url}")
        # Insert XSS payload from finding evidence
        # {finding.evidence or 'Add payload here'}
        
        page.wait_for_timeout(2000)
        if dialog_fired:
            print(f"[+] XSS CONFIRMED: alert fired with: {{dialog_fired[0]}}")
            page.screenshot(path="xss_proof_{finding.id}.png")
        else:
            print("[-] XSS not triggered in this context")
        browser.close()

if __name__ == "__main__":
    verify_xss()
"""
```

Сохраняй PoC в MinIO как артефакт (path: .../poc/{finding_id}_poc.py).
Отображай в Valhalla finding detail блок с syntax highlighting (class="finding-poc-block").
Генерируй PoC только для findings с validation_status="confirmed".


═══════════════════════════════════════════════════════════════
УЛУЧШЕНИЕ 7: COST TRACKING (с учётом реальных провайдеров)
═══════════════════════════════════════════════════════════════

Создай backend/app/llm/cost_tracker.py

```python
# Актуальные цены на апрель 2026 (проверь и обнови при изменении)
COST_PER_1K_TOKENS = {
    "deepseek-chat":               {"input": 0.00014, "output": 0.00028},
    "deepseek-reasoner":           {"input": 0.00055, "output": 0.00219},
    "gpt-4o":                      {"input": 0.0025,  "output": 0.010},
    "gpt-4o-mini":                 {"input": 0.00015, "output": 0.0006},
    "anthropic/claude-3.5-sonnet": {"input": 0.003,   "output": 0.015},
    "anthropic/claude-3-haiku":    {"input": 0.00025, "output": 0.00125},
    "llama-3.1-sonar-huge-online": {"input": 0.005,   "output": 0.005},
    "moonshot-v1-8k":              {"input": 0.001,   "output": 0.003},
    "moonshot-v1-128k":            {"input": 0.008,   "output": 0.008},
}

class ScanCostTracker:
    
    def __init__(self, scan_id: str, max_cost_usd: float | None = None):
        self.scan_id = scan_id
        self.max_cost_usd = max_cost_usd or float(os.getenv("MAX_COST_PER_SCAN_USD", "10.0"))
        self.calls: list[LLMCallRecord] = []
    
    def record(self, phase: str, task: str, model: str, 
               prompt_tokens: int, completion_tokens: int):
        cost = self._calc_cost(model, prompt_tokens, completion_tokens)
        self.calls.append(LLMCallRecord(
            phase=phase, task=task, model=model,
            prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
            cost_usd=cost, timestamp=datetime.utcnow(),
        ))
        total = self.total_cost_usd
        if total > self.max_cost_usd:
            raise ScanBudgetExceededError(
                f"Scan {self.scan_id} exceeded budget: ${total:.4f} > ${self.max_cost_usd}"
            )
    
    @property
    def total_cost_usd(self) -> float:
        return sum(c.cost_usd for c in self.calls)
    
    def breakdown(self) -> dict:
        by_phase = {}
        for c in self.calls:
            by_phase.setdefault(c.phase, {"cost": 0.0, "tokens": 0, "calls": 0})
            by_phase[c.phase]["cost"] += c.cost_usd
            by_phase[c.phase]["tokens"] += c.prompt_tokens + c.completion_tokens
            by_phase[c.phase]["calls"] += 1
        return {
            "scan_id": self.scan_id,
            "total_cost_usd": round(self.total_cost_usd, 5),
            "total_tokens": sum(c.prompt_tokens + c.completion_tokens for c in self.calls),
            "by_phase": by_phase,
            "cheapest_call": min(self.calls, key=lambda c: c.cost_usd, default=None),
            "most_expensive_call": max(self.calls, key=lambda c: c.cost_usd, default=None),
        }
    
    def _calc_cost(self, model: str, in_tokens: int, out_tokens: int) -> float:
        rates = COST_PER_1K_TOKENS.get(model, {"input": 0.002, "output": 0.008})
        return (in_tokens * rates["input"] + out_tokens * rates["output"]) / 1000
```

Добавь в .env.example:
```
# LLM Cost Management
MAX_COST_PER_SCAN_USD=10.0
LLM_PRIMARY_PROVIDER=deepseek
SHODAN_ENRICHMENT_ENABLED=true
PERPLEXITY_INTEL_ENABLED=true
ADVERSARIAL_SCORE_ENABLED=true
EXPLOITABILITY_VALIDATION_ENABLED=true
POC_GENERATION_ENABLED=true
```

Добавь cost_summary в Scan модель БД и в GET /api/v1/scans/{id} response.
Отображай в Valhalla метаданных: "Стоимость скана: $X.XXXX".


═══════════════════════════════════════════════════════════════
ПОРЯДОК РЕАЛИЗАЦИИ
═══════════════════════════════════════════════════════════════

1. Улучшение 5 (Markdown fix + персоны)          
2. Улучшение 0 (LLM Router)                      
3. Улучшение 4 (Adversarial Score)              
4. Улучшение 1 (Shodan)                          
5. Улучшение 3 (Validation Pipeline)             
6. Улучшение 2 (Perplexity OSINT)                
7. Улучшение 6 (PoC Generation)                 
8. Улучшение 7 (Cost Tracking)                  

Тесты для каждого модуля в tests/:
- Все LLM вызовы мокировать через pytest-mock
- Shodan тесты использовать fixtures с сохранёнными ответами
- pytest tests/ -v && ruff check backend/

