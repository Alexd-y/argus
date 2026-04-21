

**Что взять из ARGUS**
По `TZ.md` и `Анализ_архитектуры_ARGUS.md` текущая база уже правильная: 6-фазный lifecycle `recon → threat_modeling → vuln_analysis → exploitation → post_exploitation → reporting`, FastAPI + Celery + PostgreSQL RLS + Redis + MinIO/S3, sandbox с Kali-инструментами, SSE, MCP-server, prompt registry, LLM provider adapters, approval gate перед exploitation и отчёты HTML/PDF/JSON/CSV.

Главное развитие для SaaS: отделить **control plane** от **execution plane**, заменить небезопасный `docker exec`/docker.sock-модель на ephemeral sandbox jobs или microVM, сделать ownership verification целей, строгий scope enforcement, evidence-first validation, OAST/canary-инфраструктуру и risk prioritization по CVSS + EPSS/KEV + SSVC-подходу.
Должен использоваться MCP server и Tools более 150+ Tools из Kali Linux, можо дополнить дополнительными Tools

**1. Ключевые Функции**
1. **Разведка**
   - Проверка владения целью: DNS TXT, HTTP well-known token, cloud/account proof, signed authorization letter.
   - Passive recon: DNS, RDAP/WHOIS, crt.sh, SecurityTrails, Censys/Shodan, GitHub leaks, urlscan, OTX, GreyNoise.
   - Active recon: fingerprinting, port/service discovery, TLS, tech stack, API discovery, JS endpoint extraction, screenshotting.
   - Attack surface graph: domains, subdomains, IPs, services, APIs, auth zones, cloud assets, repos, exposed buckets.

2. **Threat modeling**
   - Автоматическая STRIDE/kill-chain модель по найденной поверхности.
   - Маппинг на OWASP WSTG/ASVS, CWE, CAPEC, MITRE ATT&CK.
   - Определение “куда идти дальше”: auth bypass, injection, SSRF, exposed admin, outdated component, secret exposure.

3. **Сканирование уязвимостей**
   - Комбинация rule-based scanners и context-aware probes: nuclei, nmap, httpx, ffuf, dalfox/xsstrike-like validators, Semgrep, Trivy, Checkov, Prowler.
   - Нормализация результатов в единую Finding-модель: asset, vector, evidence, confidence, reproducibility, impact, remediation.
   - Дедупликация и корреляция: один root cause вместо 20 похожих scanner findings.

4. **Валидация**
   - Безопасная проверка exploitability без разрушительных действий.
   - Canary/OAST для blind SSRF/XSS/RCE callbacks.
   - Differential validation: сравнение baseline/variant responses, timing only within allowed thresholds, browser-based verification для XSS.
   - Confidence scoring: suspected → likely → confirmed → exploitable-with-approval.

5. **Эксплуатация**
   - Только после policy gate: explicit tenant approval, scope check, risk level, rate limits, maintenance window.
   - LLM не выполняет команды и не генерирует произвольный shell. Он выбирает стратегию, tool adapter и payload template ID. LLM генерирует команды и генерирует произвольный shell, которые должны попасть в отчеты.
   - Payload Builder материализует тестовые payloads из allowlist registry внутри sandbox и пишет полную audit trail.

6. **Отчётность**
   - Executive summary, technical appendix, validated vectors, evidence, screenshots, timeline, affected assets, business impact, remediation.
   - Форматы: HTML, PDF, JSON, CSV, SARIF/JUnit для CI/CD.
   - “Replayable evidence”: безопасный reproduction recipe без вредоносных строк, с redaction секретов.

Отличие от Nessus/OpenVAS: продукт не просто запускает сигнатуры. Он строит граф атаки, выбирает следующий шаг по результатам предыдущего, валидирует exploitability, связывает находки в цепочки, требует approvals для опасных действий, учитывает бизнес-контекст и генерирует отчёт с доказательствами, а не просто список CVE.

**2. AI Как Оркестратор**
AI работает как planner/critic/verifier/reporter и как “исполнитель команд”.

Цикл принятия решений:

```text
Scan State Machine
  → ingest normalized tool results
  → AI Planner выбирает next actions
  → Policy Engine проверяет scope/risk/approval
  → Queue ставит sandbox jobs
  → Validators возвращают structured evidence
  → AI Critic оценивает confidence и false positives
  → Reporter формирует выводы и remediation
```

Пример решения:

```text
Найден SQLi-сигнал:
  1. AI видит: параметр, endpoint, auth context, response diff, scanner evidence.
  2. Проверяет scope и rate policy.
  3. Выбирает safe SQLi validator, а не arbitrary exploit.
  4. Запрашивает Payload Registry: boolean/time/error-based validation families.
  5. Если confirmed: повышает severity, создаёт approval request для deeper exploitation.
  6. После approval запускает ограниченную non-destructive validation, без data dumping.
  7. Сохраняет evidence и remediation: parameterized queries, ORM binding, WAF не как primary fix.
```

**3. Prompt-Механизм Для Уязвимостей**
Базовая структура prompt registry:

```json
{
  "system": "You are ARGUS Pentest Orchestrator. Operate only on verified in-scope assets. Never output raw destructive payloads, credential theft logic, reverse shells, data exfiltration steps, or WAF bypass recipes. Return strict JSON only.",
  "developer": {
    "allowed_tools": ["safe_validator", "browser_validator", "oast_canary", "payload_registry"],
    "constraints": ["non_destructive", "rate_limited", "tenant_scoped", "approval_required_for_exploitation"],
    "output_schema": "ValidationPlanV1"
  },
  "context": {
    "finding_type": "...",
    "asset": "...",
    "endpoint": "...",
    "parameter": "...",
    "auth_context": "...",
    "observed_evidence": "...",
    "server_responses": "...",
    "waf_or_filter_signals": "...",
    "previous_attempts": "...",
    "scope_policy": "..."
  }
}
```

Выход LLM:

```json
{
  "hypothesis": "string",
  "risk": "low|medium|high|critical",
  "payload_strategy": {
    "registry_family": "string",
    "mutation_classes": ["canonicalization", "context_encoding", "length_variation"],
    "raw_payloads_allowed": false
  },
  "validator": {
    "tool": "safe_validator|browser_validator|oast_canary",
    "inputs": {},
    "success_signals": [],
    "stop_conditions": []
  },
  "approval_required": true,
  "evidence_to_collect": [],
  "remediation_focus": []
}
```

**SQLi prompt**

```text
Finding type: SQL injection candidate.
Given endpoint, parameter, method, auth context, baseline response, variant response, DB error hints, and rate limits.
Return a non-destructive validation plan. Select payload registry families for boolean/error/time differential checks without dumping data or modifying records. Include success signals, stop conditions, and whether approval is required for deeper validation.
Output strict ValidationPlanV1 JSON only.
```

**XSS prompt**

```text
Finding type: XSS candidate.
Given sink/source context, reflected/stored/DOM evidence, CSP headers, encoding behavior, browser trace, and user role.
Return a browser-safe validation plan using a tenant canary marker. Do not generate credential theft, session exfiltration, or phishing logic. Select context-aware payload template families from registry and define Playwright verification signals.
Output strict ValidationPlanV1 JSON only.
```

**RCE prompt**

```text
Finding type: command/code execution candidate.
Given injection point, runtime hints, observed errors, sandbox policy, and OAST availability.
Return a non-destructive canary validation plan. Do not generate shell commands, reverse shells, persistence, file writes, or lateral movement. Use only approved harmless marker strategies and require explicit approval before any active execution validation.
Output strict ValidationPlanV1 JSON only.
```

**LFI prompt**

```text
Finding type: local file inclusion/path traversal candidate.
Given parameter, path normalization behavior, response deltas, framework hints, and target policy.
Return a validation plan that uses approved sentinel resources or benign differential checks. Do not request sensitive system files, secrets, environment files, keys, or credentials. Include evidence signals and stop conditions.
Output strict ValidationPlanV1 JSON only.
```

**SSRF prompt**

```text
Finding type: SSRF candidate.
Given URL parameter, callback telemetry availability, egress policy, response behavior, and cloud metadata restrictions.
Return an OAST/canary-based validation plan. Do not target internal metadata services, private networks, admin panels, or third-party hosts unless explicitly included in scope and approved. Include callback correlation, redirect handling, and blocklist-respectful stop conditions.
Output strict ValidationPlanV1 JSON only.
```

Как генерировать payloads:
- LLM выбирает **payload family**, печатает raw payload.
- Payload Builder берёт шаблон из signed registry: `sqli.boolean.diff.v3`, `xss.dom.canary.v2`, `ssrf.oast.redirect.v1`.
- Mutator применяет преобразования: encoding/context adaptation/length variation/case normalization.
- Validator сравнивает ответы сервера и callback telemetry.
- Если фильтр/WAF мешает, AI “обходит любой ценой”, классифицирует причину блокировки и предлагает варианты проверки: другой endpoint, reduced intensity, manual approval, или marking as protected/unconfirmed.


**4. Архитектура SaaS**

```text
[Web UI / Public API / CI API / MCP API]
        |
        v
[API Gateway]
  - auth/RBAC/tenant
  - target ownership verification
  - rate limit / quota
  - OpenAPI / SSE / webhooks
        |
        v
[ARGUS Control Plane]
  - Scan State Machine
  - AI Orchestrator
  - Prompt Registry + JSON Schemas
  - Policy Engine / Approval Gates
  - Scope Engine
  - Finding Correlator
        |
        +--> [PostgreSQL + RLS]
        |      tenants, scans, assets, findings, evidence, reports, audit_logs
        |
        +--> [Object Storage S3/MinIO]
        |      raw outputs, screenshots, reports, canary artifacts
        |
        +--> [Queue Layer: Redis/NATS/Kafka]
               scan jobs, tool jobs, report jobs, validation jobs
                    |
                    v
        [Execution Plane / Worker Pools]
          - recon workers
          - web validation workers
          - browser workers
          - cloud/repo/IaC workers
          - report workers
          - OAST/canary workers
                    |
                    v
        [Sandbox Runtime]
          - ephemeral Kubernetes Jobs or Firecracker microVMs
          - no shared docker.sock
          - seccomp/AppArmor/gVisor
          - per-job network policy
          - egress allowlist
          - CPU/memory/time limits
          - secretless execution
```

Monitoring:

```text
OpenTelemetry traces
Prometheus metrics
Structured JSON logs
SIEM export
Audit append-only log
Provider health checks
Queue depth dashboards
Cost metering per tenant/scan/provider/tool
```

**5. Пример Потока Данных**
1. Пользователь создаёт tenant/project и добавляет target.
2. Scope Engine проверяет владение: DNS/HTTP token или cloud/repo proof.
3. `POST /scans` создаёт scan со статусом `queued`; событие уходит в SSE.
4. Recon workers собирают DNS, TLS, ports, web fingerprints, screenshots, JS/API endpoints.
5. AI строит attack surface graph и threat model.
6. Vulnerability workers запускают allowlisted scanners и validators.
7. Findings нормализуются: CWE/CVSS/ASVS/WSTG, asset, endpoint, evidence, confidence.
8. AI выбирает все кандидаты для подтверждения.
9. Safe validators запускают payload templates из registry в sandbox; OAST фиксирует callbacks.
10. Для опасной эксплуатации scan переходит в активный режим с approval выполняется destructive validation.
11. После approval exploitation worker делает проверку, сохраняет evidence, redacts secrets.
12. AI Reporter создаёт executive summary, technical appendix, remediation plan, risk prioritization и отчёты HTML/PDF/JSON/CSV.
13. Frontend получает live progress по SSE и ссылки на отчёты через presigned URLs.

Итоговая модель: ARGUS должен стать не “LLM вокруг Kali”, а **policy-driven PTaaS control plane**, где AI принимает решения, но каждое действие проходит через scope, approval, sandbox, typed tool adapters, evidence model и audit trail.

Источники для актуальных ориентиров: [OWASP WSTG](https://owasp.org/www-project-web-security-testing-guide/latest/), [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/), [NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final), [CISA SSVC](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc).