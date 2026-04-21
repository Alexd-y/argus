Теперь у меня есть вся необходимая информация. Составляю финальный структурированный отчёт.

---

# Архитектурный анализ проекта **ARGUS**

> Корень репозитория: `d:\Developer\Pentest_test\ARGUS`
> Артефакт-первоисточник: `README.md`, `docs/INDEX.md`, `CHANGELOG.md`, `infra/docker-compose.yml`, `backend/main.py`, `backend/src/orchestration/state_machine.py`.

---

## 1. Что делает проект

**ARGUS** — это **автоматизированная платформа пентеста (Automated Penetration Testing as a Service)**, объединяющая классический инструментарий Kali Linux с LLM-оркестрацией. Принимает URL цели и/или скоуп — на выходе даёт мульти-форматный отчёт об уязвимостях (HTML / PDF / JSON / CSV).

### Бизнес-логика и целевая аудитория

| Аудитория | Использование |
|-----------|---------------|
| **Внутренние Red/AppSec-команды** | Запуск скана по своему скоупу через Web UI / API, получение Valhalla/Asgard/Midgard tier-отчётов |
| **MSSP / SOC** | Multi-tenant платформа с Row-Level Security (RLS) на PostgreSQL — каждый клиент изолирован |
| **CI/CD-интеграции** | REST API + SSE стрим прогресса; можно дёргать из пайплайна на каждый pre-prod деплой |
| **AI-агенты внешних систем** | Отдельный **MCP-сервер** (`mcp-server/`) экспонирует тулзы Kali через Model Context Protocol для Claude/Cursor и т.п. |

### Ключевые фичи

- **6-фазный конвейер скана** (`PHASE_ORDER` в `backend/src/orchestration/phases.py:42-49`):
   `recon → threat_modeling → vuln_analysis → exploitation → post_exploitation → reporting`.
- **Multi-tenant с RLS** на уровне Postgres (`infra/postgres/init.sql:20`, `backend/src/db/session.py:65-74`).
- **Мульти-провайдер LLM-фасад** (OpenAI, DeepSeek, OpenRouter, Google Gemini, Kimi/Moonshot, Perplexity; модели Anthropic — через OpenRouter) с per-task маршрутизацией и cost tracker'ом.
- **Sandbox с Kali + 100+ тулз** (nmap, dalfox, ffuf, sqlmap, nuclei, xsstrike, hydra, testssl, …) — изолированный контейнер, вызовы через `docker exec`.
- **MCP-сервер** на FastMCP — позволяет внешним AI-агентам напрямую дёргать инструменты пентеста (`docs/mcp-server.md`, `mcp-server/argus_mcp.py`).
- **3 tier-отчёта** (Midgard / Asgard / Valhalla) с AI-генерацией секций (executive summary, vulnerability description, remediation step, business risk, attack scenarios, exploit chains, zero-day potential).
- **Server-Sent Events** на `/api/v1/scans/{id}/events` — live прогресс в UI.
- **MinIO-бакеты** для артефактов на каждой фазе (raw tool outputs, скриншоты, PoC).
- **Approval gate** перед эксплуатацией — деструктивные тулзы (sqlmap, commix, hydra/medusa) требуют явного одобрения по политике (`evaluate_tool_approval_policy()`).

### Интерфейсы

| Тип | Где | Описание |
|-----|-----|----------|
| **REST API** | `backend/main.py:103-117` (FastAPI), префикс `/api/v1` | OpenAPI на `/api/v1/docs` |
| **SSE** | `GET /api/v1/scans/{scan_id}/events` | Live стрим событий скана |
| **Web UI (основной)** | `Frontend/` — Next.js 16 + React 19 + Tailwind v4 (бренд «RAGNAROK») | Запуск сканов, дашборд, отчёты |
| **Admin UI** | `admin-frontend/` — Next.js 16 (порт 3001) | Управление tenants/users/policies/providers |
| **MCP server** | `mcp-server/argus_mcp.py` (порт 8765, FastMCP) | Tool API для внешних AI-агентов |
| **CLI (recon)** | `backend/src/recon/cli/main.py` + `cli/commands/*.py` | Локальный запуск recon/VA/export |

---

## 2. Инструменты под капотом (стек)

### 2.1 Языки и рантаймы

| Компонент | Версия / источник |
|-----------|-------------------|
| **Python (backend, worker, MCP)** | 3.12 — `infra/backend/Dockerfile` (`FROM python:3.12-slim`), `backend/ruff.toml` (`target-version = "py312"`) |
| **Node.js (Frontend, CI)** | 20 — `.github/workflows/ci.yml` job `npm-audit` |
| **TypeScript** | 5.9.3 (оба фронта) |
| **React** | 19.2.3 |
| **Next.js** | 16.1.6 |
| **Bash + sh** для entrypoint-ов nginx/cloudflared |

### 2.2 Backend (Python)

Из `backend/requirements.txt`:

| Категория | Пакеты |
|-----------|--------|
| **Web/API** | `fastapi>=0.109`, `uvicorn[standard]>=0.27`, `gunicorn>=21`, `sse-starlette>=2.0` |
| **ORM/DB** | `sqlalchemy[asyncio]>=2.0`, `asyncpg>=0.29`, `alembic>=1.13` |
| **Очередь** | `celery[redis]>=5.3`, `redis>=5.0` |
| **HTTP-клиент** | `httpx>=0.27` |
| **Auth/валидация** | `python-jose[cryptography]`, `passlib[bcrypt]`, `python-multipart`, `pydantic>=2.5`, `pydantic-settings`, `email-validator` |
| **Отчёты** | `weasyprint>=62`, `Jinja2>=3.1` |
| **Observability** | `prometheus-client`, `python-json-logger`, `opentelemetry-api/sdk`, `opentelemetry-instrumentation-fastapi` |
| **LLM** | `openai>=1.0`, `tiktoken>=0.7` |
| **Recon-утилиты** | `markdown`, `nh3` (HTML sanitization) |
| **Cloud** | `boto3>=1.34` (для MinIO/S3) |

### 2.3 Frontend (оба клиента)

`Frontend/package.json` и `admin-frontend/package.json`:

- **Next.js 16.1.6** (App Router, RSC)
- **React 19.2.3** + **TypeScript 5.9.3**
- **Tailwind CSS v4** через `@tailwindcss/postcss`
- **ESLint 9** + `eslint-config-next@16.1.6`
- **Vitest 3** (только в основном `Frontend/`)
- Без отдельного state-менеджера (Redux/Zustand) — собственный React state + RSC
- `Frontend/next.config.ts:6-14`: rewrite `/api/v1/*` → `NEXT_PUBLIC_BACKEND_URL` (по умолчанию `http://localhost:8000`)

### 2.4 Базы данных, кеш, объектное хранилище

| Сервис | Образ / версия | Назначение |
|--------|----------------|------------|
| **PostgreSQL** | `pgvector/pgvector:pg15` | Основное хранилище (26 сущностей: scans, findings, reports, tenants, …); расширение **`vector`** для эмбеддингов; **RLS включён** на уровне БД (`infra/postgres/init.sql:20`) |
| **Redis** | `redis:7-alpine` | Celery broker + result backend + кеш AI-текста отчётов + tool_cache |
| **MinIO** | `minio/minio:RELEASE.2025-09-07T16-13-09Z` | S3-совместимое хранилище артефактов и отчётов |
| **Alembic** | 17 миграций в `backend/alembic/versions/` (от `001_initial_schema.py` до `017_finding_notes_false_positive_scan_event_duration.py`) |

### 2.5 Оркестрация / контейнеризация

`infra/docker-compose.yml` (10 сервисов):

| Сервис | Образ / Build | Сети | Особенности |
|--------|---------------|------|-------------|
| `postgres` | pgvector/pgvector:pg15 | `data` | Healthcheck `pg_isready` |
| `redis` | redis:7-alpine | `data` | Опц. `requirepass` |
| `minio` | minio:RELEASE.2025-09-07 | `data` | Console на 9001 |
| `minio-init` | minio/mc | `data` | One-shot создание bucket'ов: `argus`, `argus-reports`, `stage1-4-artifacts`, `argus-recon` |
| `backend` | build `infra/backend/Dockerfile` | `backend`, `data` | Лимиты `2 CPU / 2 GB`, монтирование `/var/run/docker.sock:ro` для VA sandbox |
| `worker` | build `infra/worker/Dockerfile` | `backend`, `data` | Celery, лимиты `4 CPU / 4 GB`, `user: 1000:${DOCKER_GID}` |
| `sandbox` | build `sandbox/Dockerfile` (Kali rolling) | `data` | Пайплайн VA-инструментов |
| `nginx` | nginx:1.27-alpine | `frontend`, `backend` | Reverse proxy + CORS map + SSE для `/scans/` |
| `cloudflared` | build `infra/cloudflared/Dockerfile` | `frontend` | Profile `tunnel` (опц. Cloudflare Tunnel) |

Сети: `frontend`, `backend`, `data` (все bridge). Volumes: `postgres_data`, `redis_data`, `minio_data`, `sandbox_tmp`.

Override-файлы:
- `infra/docker-compose.override.yml` — dev: проброс портов PG/Redis/MinIO, `uvicorn --reload`, code mount `../backend:/app`.
- `infra/docker-compose.dev.yml` — аналог с дополнительным sandbox volume.

### 2.6 Sandbox (Kali) — список тулз

`sandbox/Dockerfile` — база `kalilinux/kali-rolling`, два профиля (`SANDBOX_PROFILE=standard|extended`):

- **Metapackages:** `kali-linux-headless`, `kali-tools-top10`, `kali-tools-web`, `kali-tools-information-gathering`, `kali-tools-vulnerability` (+ `kali-tools-passwords` в extended).
- **Сетевые сканеры:** `nmap`, `masscan`, `tcpdump`, `tshark`.
- **Web/VA:** `nuclei`, `ffuf`, `gobuster`, `wfuzz`, `sqlmap`, `commix`, `nikto`, `whatweb`, `sslscan`, `feroxbuster`, `dirb`, `wpscan`, `joomscan`, `dirsearch` (pip), `dalfox` (бинарь с GitHub releases), **XSStrike** (`/opt/xsstrike`).
- **DNS/recon:** `dnsrecon`, `fierce`, `amass`, `subfinder`, `theharvester`, `gospider`, `parsero`, `testssl.sh`.
- **Brute-force (gated):** `hydra`, `medusa`, `john`, `hashcat`.
- **Прочее:** `mitmproxy`, `exploitdb`, `dirbuster`, `trivy`, **Playwright + Chromium** (для XSS-верификации в браузере), опционально **Metasploit** (`INSTALL_MSF=true`).

### 2.7 MCP-сервер

| Файл | Назначение |
|------|------------|
| `mcp-server/argus_mcp.py` | FastMCP-сервер на порту 8765, HTTP-транспорт, прокси к ARGUS backend (`ARGUS_SERVER_URL`) |
| `mcp-server/tools/kali_registry.py` | `KALI_TOOL_REGISTRY` — категории `network_scanning`, `web_fingerprinting`, `bruteforce_testing`, `ssl_analysis`, `dns_enumeration`, `password_audit` |
| `mcp-server/tools/va_sandbox_tools.py` | Allowlist `run_*` для sandbox: dalfox, xsstrike, ffuf, sqlmap, nuclei, whatweb, nikto, testssl |
| `mcp-server/Dockerfile` | Python 3.12-slim |
| `mcp-server/requirements.txt` | `fastmcp>=2.0,<3.0`, `httpx>=0.27,<1.0` |

Внутри backend есть свой клиент к MCP/HTTP fetch: `backend/src/recon/mcp/client.py:88-91` (приоритет httpx, опционально stdio MCP SDK + `mcp-server-fetch`); политики в `backend/src/recon/mcp/policy.py`.

### 2.8 Очереди / Celery

`backend/src/celery_app.py:7-43` — броккер и backend = Redis. Очереди (роутинг по `task_routes`):

| Очередь | Задачи |
|---------|--------|
| `argus.scans` | `argus.scan_phase` — full pipeline state machine |
| `argus.reports` | `argus.generate_report`, `argus.generate_all_reports`, `argus.report_generation`, `argus.ai_text_generation` |
| `argus.tools` | `argus.tool_run`, `argus.va_active_scan_tool`, `argus.va.run_dalfox`, `argus.va.run_xsstrike`, `argus.va.run_ffuf`, `argus.va.run_sqlmap`, `argus.va.run_nuclei`, … |
| `argus.recon` | `argus.recon_job` — engagement recon job |
| `argus.exploitation` | `argus.exploitation` — Stage 4 экзекьютор |
| `argus.default` | fallback |

Worker запускается так: `celery -A src.celery_app worker -l INFO -Q argus.scans,argus.reports,argus.tools,argus.recon,argus.exploitation,argus.default` (`infra/worker/Dockerfile:15`).

### 2.9 CI/CD — `.github/workflows/ci.yml`

| Job | Действия |
|-----|----------|
| **lint** | Python 3.12, install deps, `ruff check` + `ruff format --check` |
| **test** | Сервисы PG + Redis, `alembic upgrade head`, `pytest tests` |
| **security** | `bandit -r src -ll`, `safety check --ignore 51457` |
| **npm-audit** | matrix `Frontend`, `admin-frontend`, Node 20, `npm audit --audit-level=high` |
| **helm-lint** | Условный (нет Chart.yaml — пропускается) |
| **build** | `needs: [lint, test, security, npm-audit]`, `docker compose build backend worker` |

Нет `.pre-commit-config.yaml`, нет корневого `Makefile`.

### 2.10 Observability

| Слой | Файл | Что |
|------|------|-----|
| **Prometheus метрики** | `backend/src/core/observability.py:45-73` | Counters/Histograms: `argus_scans_total`, `argus_phase_duration_seconds`, `argus_tool_runs_total`, … |
| **Эндпоинт** | `backend/src/api/routers/metrics.py:16-42` | `/metrics` под Bearer-токеном; **404, если `METRICS_TOKEN` не задан** |
| **OpenTelemetry** | `observability.py` — context-manager `trace_phase`; `opentelemetry-instrumentation-fastapi` в зависимостях |
| **Логи** | `backend/src/core/logging_config.py:9-25` | Structured JSON (`python-json-logger`) с полями `event_type`, `phase`, `scan_id`; secret redaction в `memory_compressor` (regex по `bearer/api_key/token/password/cookie`) |

> **Замечание (потенциальный баг):** `observability.get_metrics_content()` возвращает `(body, content_type, status_code)` — **3 значения**, а в `metrics.py` распаковывается в **2** (`body, content_type`). Может выкинуть `ValueError` при вызове.

### 2.11 Сторонние API / интеграции

Из `backend/src/core/config.py`, compose env и `backend/src/data_sources/`:

- **LLM-провайдеры** (см. раздел 3): OpenAI, DeepSeek, OpenRouter, Google Gemini, Kimi (Moonshot), Perplexity.
- **Threat Intelligence:** **Shodan** (`SHODAN_API_KEY`), **NVD** (CVE база), **Censys**, **SecurityTrails**, **VirusTotal**, **HIBP** (Have I Been Pwned), **Exploit-DB / SearchSploit**, **urlscan**, **AbuseIPDB**, **GreyNoise**, **OTX**, **GitHub** (для OSINT).
- **Pipeline обогащения:** `backend/src/intel/enrichment_pipeline.py` — Shodan → adversarial score → LLM dedup → Perplexity → validation → PoC.
- **Cloud:** **Cloudflare** (опциональный туннель), **Vercel** (фронт-хостинг — `VERCEL_FRONTEND_URL`).
- **MinIO/S3** через boto3.

### 2.12 Линтеры, форматтеры, тесты

| Слой | Инструменты |
|------|-------------|
| **Python** | Ruff (lint+format в CI), Black (в `requirements-dev.txt`), Bandit (SAST), Safety (SCA) |
| **Тесты Python** | pytest + pytest-asyncio (`backend/pytest.ini`: `asyncio_mode = auto`, маркеры `storage_contract`, `integration`) |
| **Frontend** | ESLint 9 + `eslint-config-next` 16.1.6, Vitest (только основной фронт) |
| **Node SCA** | `npm audit --audit-level=high` |

---

## 3. Промты, используемые для AI

### 3.1 LLM-провайдеры (адаптеры)

`backend/src/llm/adapters.py:12-18` — список OpenAI-совместимых провайдеров (единый формат `/v1/chat/completions`, `temperature=0.3`, таймаут 120с):

```12:18:backend/src/llm/adapters.py
_PROVIDERS: list[tuple[str, str, str]] = [
    ("OPENAI_API_KEY", "https://api.openai.com", "gpt-4o-mini"),
    ("DEEPSEEK_API_KEY", "https://api.deepseek.com", "deepseek-chat"),
    ("OPENROUTER_API_KEY", "https://openrouter.ai/api", "openai/gpt-4o-mini"),
    ("KIMI_API_KEY", "https://api.moonshot.cn", "moonshot-v1-8k"),
    ("PERPLEXITY_API_KEY", "https://api.perplexity.ai", "sonar"),
]
```

**Google Gemini** — отдельный `GeminiAdapter` (`adapters.py:75-105`), модель по умолчанию `gemini-1.5-flash`, REST `generativelanguage.googleapis.com`. Системный промт конкатенируется с пользовательским.

**Anthropic** прямого SDK **нет** — модели Claude 3.5 Sonnet попадают через **OpenRouter** в `task_router.ROUTING_TABLE`.

### 3.2 Маршрутизация по задачам (`backend/src/llm/task_router.py`)

13 типов задач (`LLMTask` enum, строки 17-31):

```17:31:backend/src/llm/task_router.py
class LLMTask(Enum):
    EXECUTIVE_SUMMARY = "executive_summary"
    THREAT_MODELING = "threat_modeling"
    EXPLOIT_GENERATION = "exploit_generation"
    VALIDATION_ONESHOT = "validation_oneshot"
    REMEDIATION_PLAN = "remediation_plan"
    ZERO_DAY_ANALYSIS = "zero_day_analysis"
    DEDUP_ANALYSIS = "dedup_analysis"
    PERPLEXITY_OSINT = "perplexity_osint"
    REPORT_SECTION = "report_section"
    ORCHESTRATION = "orchestration"
    POC_GENERATION = "poc_generation"
    COST_SUMMARY = "cost_summary"
    INTELLIGENCE_SUMMARY = "intelligence_summary"
```

`ROUTING_TABLE` (строки ~62-193) задаёт для каждой задачи: provider env key, base URL, model, **fallback**, `max_tokens`, `temperature`. Примеры моделей: DeepSeek `deepseek-reasoner` / `deepseek-chat`, OpenRouter `anthropic/claude-3.5-sonnet`, OpenAI `gpt-4o` / `gpt-4o-mini`, Perplexity `sonar-pro` / `sonar`.

`LLM_PRIMARY_PROVIDER` (env) переопределяет первую попытку (`task_router.py:54-60, 246-262`).

### 3.3 Реестры промтов — где хранятся

| Назначение | Файл |
|------------|------|
| **Главный реестр оркестрации + JSON-схемы + санитизация** | `backend/src/orchestration/prompt_registry.py` (~920 строк) |
| **Вызов LLM по фазам state machine + retry/fixer** | `backend/src/orchestration/ai_prompts.py` |
| **Шаблоны для Stage 2 TM pipeline (9 задач)** | `backend/src/prompts/threat_modeling_prompts.py` |
| **Шаблоны для Stage 3 VA pipeline (8 задач)** | `backend/src/prompts/vulnerability_analysis_prompts.py` |
| **AI-генерация секций отчётов** | `backend/src/reports/ai_text_generation.py` |
| **Memory compressor** | `backend/src/agents/memory_compressor.py:19-41` |
| **Dedup (XML output)** | `backend/src/dedup/llm_dedup.py:19-50` |
| **PoC generator** | `backend/src/exploit/generator.py:17-29` |
| **Multi-agent VA discovery** | `backend/src/agents/va_orchestrator.py:98-126` |
| **Validation exploitability (3-stage)** | `backend/src/validation/exploitability.py` |
| **Perplexity CVE/OSINT enricher** | `backend/src/intel/perplexity_enricher.py:46-50, 102-147` |
| **API findings remediation bullets** | `backend/src/api/routers/findings.py:401-405` |
| **API intelligence analyze-target** | `backend/src/api/routers/intelligence.py:38-41, 223-227` |
| **AI registry для TM pipeline** | `backend/src/recon/threat_modeling/ai_task_registry.py:21-31` |
| **AI registry для VA pipeline** | `backend/src/recon/vulnerability_analysis/ai_task_registry.py:19-52` |
| **Документация** | `docs/prompt-registry.md` |

### 3.4 Версионирование промтов

- `ORCHESTRATION_PROMPT_VERSION = "kal008-20250327"` (`prompt_registry.py:76`) — общий тег для системных промтов оркестрации.
- `VA_ACTIVE_SCAN_PLANNING_PROMPT_VERSION = "va-plan-kal008-20250327"` (`prompt_registry.py:77`) — для планировщика active scan.
- `REPORT_AI_PROMPT_VERSIONS["..."] = "vhq012-20260405"` (`prompt_registry.py:525-538`) — единая версия для всех ключей AI-секций отчёта; используется в Redis-кеше `ai_text_generation`.

### 3.5 Защита от prompt injection

`prompt_registry.py:13-64`:

- Лимиты: `MAX_PROMPT_STRING_LENGTH = 4096`, `MAX_PROMPT_OBJECT_LENGTH = 65536`.
- `_SUSPICIOUS_PATTERNS` (regex) — обрезает промт при первом совпадении: `ignore previous instructions`, `you are now`, `system:`, `jailbreak`, `<|im_end|>` и т.п.
- `_sanitize_for_prompt`/`_sanitize_kwargs_for_prompt` — нормализуют пробелы, обрезают newline'ы, проверяют паттерны.

### 3.6 Pipeline-by-pipeline список AI-задач

**Stage 1 (Recon)** — `RECON` в `PHASE_PROMPTS` (`prompt_registry.py:130-145`) → `LLMTask.ORCHESTRATION`. Дополнительно в recon-reporting:
- `stage2_builder._enrich_with_llm` (`backend/src/recon/reporting/stage2_builder.py:274`) — обогащение для Stage 2.
- `anomaly_builder` (`backend/src/recon/reporting/anomaly_builder.py:231`) — поиск аномалий.

**Stage 2 (Threat Modeling)** — 9 задач в `THREAT_MODELING_AI_TASKS`:
`critical_assets` → `trust_boundaries` → `attacker_profiles` → `entry_points` → `application_flows` → `threat_scenarios` → `scenario_scoring` → `testing_roadmap` → `report_summary`.

**Stage 3 (Vulnerability Analysis)** — `VA_AI_TASKS` (`vulnerability_analysis/ai_task_registry.py:19-52`):

Active-scan блок:
- `active_scan_planning`, `web_scan_planning`, `xss_analysis`, `sqli_analysis`, `nuclei_analysis`, `generic_web_finding`.

Legacy-блок:
- `validation_target_planning`, `evidence_bundle`, `contradiction_analysis`, `evidence_sufficiency`, `confirmation_policy`, `scenario_mapping`, `next_phase_gate`, `exploitation_candidates`, `duplicate_correlation`, `remediation_generation`, `stage3_confirmation_summary`.

**Stage 4 (Exploitation / Post-exploitation)** — `EXPLOITATION` / `POST_EXPLOITATION` в `PHASE_PROMPTS` → `LLMTask.EXPLOIT_GENERATION`; `POC_GENERATION` через `exploit/generator.py`.

**Reporting (RPT-004 AI секции)** — ключи `REPORT_AI_SECTION_*`:
- `executive_summary`, `vulnerability_description`, `remediation_step`, `business_risk`, `attack_scenarios`, `exploit_chains`, `remediation_stages`, `zero_day_potential`, `cost_summary` — все идут через **один** `LLMTask.REPORT_SECTION`.

### 3.7 Примеры конкретных промтов

**Базовый системный промт оркестрации** (`prompt_registry.py:115-120`):

```115:120:backend/src/orchestration/prompt_registry.py
SYSTEM_PROMPT_BASE = (
    "You are an expert penetration tester and security analyst. "
    "You analyze REAL tool output (nmap, dig, whois, crt.sh, Shodan, NVD). "
    "Respond ONLY with valid JSON. No markdown, no explanation, only the JSON object. "
    f"[orchestration_prompt_version={ORCHESTRATION_PROMPT_VERSION}]"
)
```

**JSON repair fixer** (`prompt_registry.py:122-126`) — вызывается, если LLM вернул кривой JSON.

**Recon user-промт** (`prompt_registry.py:130-145`):

Включает блок `KALI_MCP_ORCHESTRATION_BLOCK` (`prompt_registry.py:80-105`), описывающий категории/allowlist бинарей (`network_scanning: nmap, rustscan, masscan`; `bruteforce_testing: gobuster, ffuf, …`; `password_audit: hydra, medusa — GATED`).

**Threat Modeling** (`prompt_registry.py:147-180`) — STRIDE-анализ + NVD CVE-маппинг с явной структурой выходного JSON (`attack_surface`, `threats`, `cves`, `mitigations`).

**Vulnerability Analysis** (`prompt_registry.py:182-213`) — для каждой уязвимости требуются: `severity`, `title`, `cwe`, `cvss`, `affected_asset`, `remediation`, `confidence`, `evidence_type`, `evidence_refs`.

**REPORT_AI_SYSTEM** для генерации секций отчёта (`prompt_registry.py:541-591`) — длинный (50 строк) системный промт со строгими правилами:
- запрет фабрикации CVE/систем
- использование точных integer'ов из `severity_counts`, `executive_severity_totals`, `pwned_count`
- использование `valhalla_context.xss_structured` дословно для XSS-секций
- запрет дубликации между секциями (`section_id` + `ALREADY WRITTEN SECTIONS`)
- требование привязки кода-примеров к detected stack (Next.js → middleware, Nginx → config)

**Active scan planning** (`prompt_registry.py:851-866`) — выход только JSON-array с объектами `{"tool": "...", "args": [...]}`, ограничен allowlist'ом (`dalfox, xsstrike, ffuf, sqlmap, nuclei, gobuster, feroxbuster, wfuzz, commix`).

**Memory compression** (`memory_compressor.py:19-41`) — сжатие истории сканов с **обязательной редакцией секретов** (`<REDACTED:api_key>`, `<REDACTED:bearer_token>`).

**Dedup** (`llm_dedup.py:19-50`) — XML-output с критериями same root cause / same component / same exploitation method.

**PoC generator** (`exploit/generator.py:17-29`):

```17:29:backend/src/exploit/generator.py
POC_SYSTEM = (
    "You are an expert penetration tester writing minimal proof-of-concept exploit code.\n"
    "Write ONLY valid, runnable code. No markdown formatting. No explanations outside comments.\n\n"
    "Rules:\n"
    "- Code must be HARMLESS (read-only operations, no destructive payloads)\n"
    "- Include assertion that confirms successful exploitation\n"
    "- Prefer Python + requests for web vulnerabilities\n"
    "- For XSS: generate Playwright-compatible verification script\n"
    "- For auth bypass: show the unauthorized access, then stop\n"
    "- For rate limiting: show the missing 429 response, then stop\n"
    "- For header issues: show missing header via curl\n"
    "- Start with #!/usr/bin/env python3 for Python scripts"
)
```

### 3.8 Cost tracking

`backend/src/llm/cost_tracker.py`:

- `ScanCostTracker` — singleton по `scan_id`. На каждый вызов `record(phase, task, model, prompt_tokens, completion_tokens)`.
- `COST_PER_1K_TOKENS` — таблица цен по модели; иначе `DEFAULT_COST`.
- При превышении `max_cost_usd` (по умолчанию **10 USD/scan**, `config.py:113-116`) — `ScanBudgetExceededError`.
- Подсчёт токенов: `usage` из ответа LLM, иначе fallback **tiktoken `cl100k_base`** (`facade.py:99-114`).
- Финал: `state_machine.py:843-861` — `pop_tracker(scan_id)` → сериализация в `Scan.cost_summary` JSON-колонку.

### 3.9 Все call-sites LLM в коде

| Слой | Файл:строка |
|------|-------------|
| **Ядро** | `backend/src/llm/router.py:16-40`, `backend/src/llm/task_router.py:196-243, 265-312`, `backend/src/llm/facade.py:64-135, 138-173`, `backend/src/core/llm_config.py:92-111` |
| **Оркестрация фаз** | `backend/src/orchestration/ai_prompts.py:87-88, 111-112`; `backend/src/orchestration/handlers.py:593, 686, 1163, 1190, 1243, 1275` |
| **Агенты** | `backend/src/agents/memory_compressor.py:115-121`; `backend/src/agents/va_orchestrator.py:449-455` |
| **API роутеры** | `backend/src/api/routers/findings.py:401-405`; `backend/src/api/routers/intelligence.py:223-227` |
| **Отчёты / recon reporting** | `backend/src/reports/ai_text_generation.py:333-338`; `stage2_builder.py:274`; `anomaly_builder.py:231`; `stage1_report_generator.py:330` |
| **TM/VA пайплайны** | `recon/threat_modeling/pipeline.py:499`; `recon/vulnerability_analysis/pipeline.py:962`; `recon/vulnerability_analysis/active_scan_planner.py:255, 290` |
| **Утилиты** | `dedup/llm_dedup.py:146-150`; `exploit/generator.py:79-80`; `intel/perplexity_enricher.py:102-106, 143-147`; `validation/exploitability.py:208, 241-242, 281-285` |

---

## 4. Схема потоков данных

### 4.1 Точки входа (откуда данные приходят в систему)

| Канал | Где |
|-------|-----|
| **HTTP REST (FastAPI)** | `backend/main.py:103-117` — все роутеры под `/api/v1` |
| **SSE (стрим прогресса)** | `GET /api/v1/scans/{scan_id}/events` |
| **Celery очереди (Redis)** | `argus.scans`, `argus.reports`, `argus.tools`, `argus.recon`, `argus.exploitation`, `argus.default` |
| **MCP-сервер (порт 8765)** | Внешние AI-агенты дёргают тулзы через FastMCP |
| **CLI** | `backend/src/recon/cli/main.py` — локальный запуск |

### 4.2 Основные API-эндпоинты

`scans` (`/api/v1/scans` — `backend/src/api/routers/scans.py`):

| Метод | Путь | Действие |
|-------|------|----------|
| POST | `/scans` | **Главная точка входа: создаёт скан + ставит state machine в очередь** (`scans.py:289-293`) |
| POST | `/scans/smart` | Скан по objective + max_phases |
| POST | `/scans/skill` | Скан с skill_focus |
| GET | `/scans` / `/scans/{id}` | Список / детали |
| POST | `/scans/{id}/cancel` | Отмена + `celery_app.control.revoke(scan_id)` |
| GET | `/scans/{id}/findings` / `/top` / `/statistics` | Findings |
| GET | `/scans/{id}/artifacts` | MinIO-артефакты |
| GET | `/scans/{id}/cost` / `/memory-summary` / `/timeline` | Метрики |
| POST | `/scans/{id}/reports/generate-all` | Запуск пакетной генерации отчётов |
| GET | `/scans/{id}/events` | SSE стрим |

Прочие роутеры (через `main.py:103-117`): `auth`, `findings`, `reports`, `sandbox`, `tools` (включая `kal/run`), `admin` (tenants/users/policies), `cache`, `internal_va`, `recon_router` (агрегатор `engagements`/`jobs`/`threat_modeling`/`vulnerability_analysis`/`exploitation`/`artifacts`/`targets`), `intelligence` (`/analyze-target`), `skills_public`, `knowledge`, `health`, `metrics`.

### 4.3 Хранение данных

**PostgreSQL** (см. `docs/erd.md` — 26 сущностей, RLS):
`tenants`, `users`, `policies`, `targets`, `scans`, `scan_steps`, `scan_events`, `scan_timeline`, `phase_inputs`, `phase_outputs`, `findings`, `evidence`, `reports`, `report_objects`, `screenshots`, плюс engagement-модели в `db/models_recon`.

RLS — обязательный `set_session_tenant` перед любой операцией:

```65:74:backend/src/db/session.py
async def set_session_tenant(session: AsyncSession, tenant_id: str) -> None:
    """
    Set app.current_tenant_id for RLS policies.
    Must be called at start of each DB operation when RLS is enabled.
    ...
    """
    _validate_tenant_id(tenant_id)
    ...
    await session.execute(text(f"SET LOCAL app.current_tenant_id = '{escaped}'"))
```

**MinIO бакеты** (паттерны в `backend/src/storage/s3.py:5-16`):

| Bucket | Назначение | Ключи |
|--------|------------|-------|
| `argus` (основной) | Per-scan raw artifacts | `{tenant}/{scan_id}/raw/...`, `{tenant}/{scan_id}/{phase}/raw/{ts}_{type}.{ext}`, `{tenant}/{scan_id}/poc/{finding_id}.json`, screenshots |
| `argus-reports` | Готовые отчёты | `{tenant}/{scan_id}/reports/{tier}/{report_id}.{fmt}` |
| `stage1-artifacts` | Stage 1 (engagement) | `{scan_id}/recon_results.json`, `tech_profile.json`, `raw_tool_outputs/*` |
| `stage2-artifacts` | Stage 2 (engagement) | `{scan_id}/threat_model.json`, `stage2_inputs.json`, … |
| `stage3-artifacts` | Stage 3 (engagement) | `ai_va_*_normalized.json`, `exploitation_candidates.json`, … |
| `stage4-artifacts` | Stage 4 (engagement) | `exploitation_plan.json`, `stage4_results.json`, … |
| `argus-recon` | Recon engagement | jobs |

**Redis** — broker Celery (queues), result backend, кеш AI-текста отчётов (TTL по `prompt_version`), `tool_cache`.

### 4.4 Текстовая диаграмма потока

```
                    ┌──────────────────────────────────────────────┐
                    │  Frontend (Next.js, RAGNAROK UI / Admin UI)  │
                    │  — POST /api/v1/scans                        │
                    │  — SSE GET /api/v1/scans/{id}/events         │
                    └───────────────┬──────────────────────────────┘
                                    │ HTTPS
                              ┌─────▼─────┐
                              │   nginx   │ (TLS, CORS map, rate limit)
                              └─────┬─────┘
                                    │
                       ┌────────────▼─────────────┐
                       │   FastAPI (backend)      │
                       │   - JWT/API-key auth     │
                       │   - get_current_tenant   │
                       │   - INSERT Tenant?,      │
                       │     Target, Scan         │
                       │     (status=queued,      │
                       │      phase=init)         │
                       │   - apply_async to       │
                       │     argus.scans          │
                       │     (task_id=scan_id)    │
                       └────────────┬─────────────┘
                                    │
        ┌───────────────────────────▼─────────────────────────────┐
        │   Redis  (Celery broker + result backend + cache)       │
        └───────────────────────────┬─────────────────────────────┘
                                    │
            ┌───────────────────────▼────────────────────────┐
            │   Celery Worker → scan_phase_task              │
            │   → run_scan_state_machine(scan_id, tenant_id) │
            └────────────────────────┬───────────────────────┘
                                     │
        ┌────────────────────────────▼────────────────────────────┐
        │  STATE MACHINE (PHASE_ORDER, 6 фаз, gates)              │
        │                                                          │
        │  recon (15%) ──► threat_modeling (25%) ──► vuln_analysis │
        │       │                  │                       │       │
        │       │ ┌────────────────┴───┐  ┌────────────────┴───┐   │
        │       │ │ NVD CVE lookup     │  │ run_va_active_scan │   │
        │       │ │ ai_threat_modeling │  │ _phase (Sandbox)   │   │
        │       │ │  (LLM)             │  │ + heuristics       │   │
        │       │ └────────────────────┘  │ + ai_vuln_analysis │   │
        │       │                         │  (LLM)             │   │
        │       ▼                         └─────────┬──────────┘   │
        │  Sandbox (Kali docker exec):              │              │
        │  nmap, dig, crt.sh, httpx, whatweb, etc.  │              │
        │       │                                   │              │
        │       │                                   ▼              │
        │       │              ┌──── exploitation (65%) ◄── APPROVAL GATE
        │       │              │     (run_exploit_attempt          │
        │       │              │      + run_exploit_verify)        │
        │       │              ▼                                   │
        │       │     post_exploitation (85%)                      │
        │       │              │                                   │
        │       │              ▼                                   │
        │       │     reporting (100%) → ai_reporting (LLM)        │
        │       │              │                                   │
        │       └──────────────┴────► RawPhaseSink → MinIO         │
        │                             phase_inputs/outputs → DB    │
        │                                                          │
        │  Финал: _persist_report_and_findings + cost_summary      │
        │  + auto enqueue_generate_all_bundle (Midgard/Asgard/     │
        │    Valhalla × HTML/PDF/JSON/CSV) → argus.reports         │
        └──────────────────────────┬──────────────────────────────┘
                                   │
              ┌────────────────────▼────────────────────┐
              │ Celery: generate_all_reports_task       │
              │ → run_generate_report_pipeline          │
              │   - data_collector (DB + stage MinIO)   │
              │   - AI-секции (REPORT_AI_*) — кеш Redis │
              │   - Jinja2 templates                    │
              │   - WeasyPrint (PDF)                    │
              └────────────────────┬────────────────────┘
                                   │
                                   ▼
              MinIO: argus-reports/{tenant}/{scan_id}/reports/{tier}/{id}.{fmt}
              DB: ReportObject rows
                                   │
                                   ▼
              Frontend ◄── presigned URLs из GET /api/v1/scans/{id}/artifacts
                          live SSE прогресс на /events

  Параллельно (внешние AI-агенты):
  ┌─────────────────────┐    HTTP   ┌─────────────────────┐
  │ Claude/Cursor LLM   │ ─────────►│ MCP Server (FastMCP)│
  │ (через MCP)         │           │ port 8765           │
  └─────────────────────┘           │ tools/kali_registry │──► backend
                                    │ + va_sandbox_tools  │
                                    └─────────────────────┘
```

### 4.5 LLM-вызовы как поток

```
handlers.run_recon  →  ai_recon  →  ai_prompts.call_llm_unified
                                       │
                                       ▼
                                   prompt_registry.get_prompt("recon")
                                   → SYSTEM_PROMPT_BASE + KALI_MCP_BLOCK + tool_results
                                       │
                                       ▼
                                   facade.call_llm_unified(task=ORCHESTRATION)
                                       │
                                       ▼
                                   task_router._build_attempts
                                   (LLM_PRIMARY_PROVIDER override?)
                                       │
                              ┌────────┴────────┐
                              ▼                 ▼
                         primary route    fallback route
                              │                 │
                              ▼                 ▼
                       OpenAICompatibleAdapter (httpx → /v1/chat/completions)
                              │
                              ▼
                       ScanCostTracker.record(phase, task, model, tokens)
                              │   (если budget exceeded → ScanBudgetExceededError)
                              ▼
                       JSON response → orchestration retry/fixer
                              │
                              ▼
                       handlers writes ReconOutput → phase_outputs (DB)
```

---

## 5. Фазы / этапы выполнения

### 5.1 Инициализация приложения (lifespan)

`backend/main.py:39-75`:

1. `configure_logging()` — JSON-логи через `python-json-logger`.
2. `subprocess.run(["alembic", "upgrade", "head"], timeout=60)` — авто-миграции; в prod при failure → `RuntimeError`.
3. `get_knowledge_base().warm_cache()` — прогрев кеша знаний.
4. Регистрация exception handlers (`register_exception_handlers`).
5. SecurityHeadersMiddleware + CORSMiddleware.
6. Включение всех роутеров под `/api/v1`.

### 5.2 Жизненный цикл одного скана

```
[T0] HTTP POST /api/v1/scans           → INSERT Scan(status=queued, phase=init)
                                       → apply_async("argus.scan_phase",
                                                     args=[scan_id, tenant_id, target, options],
                                                     task_id=scan_id)

[T1] Celery worker picks up task       → set_session_tenant(RLS)
                                       → run_scan_state_machine(...)

[T2] for phase in PHASE_ORDER:         (recon → threat_modeling → vuln_analysis →
                                        exploitation → post_exploitation → reporting)

  [phase_start]   UPDATE Scan SET phase=<phase>, status=running, progress=<%>
                  INSERT ScanStep(name, status=running)
                  INSERT ScanEvent(type=phase_start)

  [build input]   input_data = build_phase_input(phase, prev outputs)
                  INSERT PhaseInput(scan_id, phase, payload)

  [exploitation gate] if phase == EXPLOITATION:
                       if policy.exploit_approval and scan.status != "approved":
                           UPDATE Scan SET status=awaiting_approval
                           raise ExploitationApprovalRequiredError
                       (Celery task returns {"status":"awaiting_approval"})

  [run handler]   output = await handlers.run_<phase>(input_data, ...)
                  - LLM-вызовы через ai_<phase> (cost_tracker.record)
                  - Tool calls в Sandbox (docker exec, политика, audit log)
                  - Raw artifacts → RawPhaseSink → MinIO

  [persist out]   INSERT PhaseOutput(scan_id, phase, payload)
                  UPDATE ScanStep SET status=completed
                  INSERT ScanEvent(type=phase_end)

[T3] After last phase (reporting):
     _persist_report_and_findings:
       INSERT Report
       INSERT Finding[*]
       INSERT Evidence[*] (если есть PoC)
     UPDATE Scan SET status=completed, progress=100, cost_summary=<json>

[T4] enqueue_generate_all_bundle:
     INSERT Report(tier=midgard|asgard|valhalla, format=html|pdf|json|csv) — 12 строк
     schedule_generate_all_reports_task_safe → argus.reports

[T5] generate_all_reports_task:
     for report_id in reports:
       run_generate_report_pipeline:
         data_collector.collect(scan_id) → DB + MinIO stage1-4 + raw phases
         AI-секции через REPORT_AI_SECTION_* (кеш по prompt_version в Redis)
         Jinja2 → HTML/JSON/CSV
         WeasyPrint(HTML) → PDF
       upload_to_minio(report_id, file)
       INSERT ReportObject(report_id, format, key, size, sha256)

[T6] Frontend polls/SSE:
     GET /api/v1/scans/{id} → status=completed
     GET /api/v1/scans/{id}/artifacts → presigned URLs на отчёты
```

### 5.3 Pipeline по каждой фазе (краткая сводка)

**Stage 1 — Recon** (`backend/src/orchestration/handlers.py:530-595`):
- `plan_recon_steps(cfg)` (`step_registry.py:39-103`) — passive / active / full + фильтр `tool_selection`.
- `run_recon_planned_tool_gather` — параллельный сбор: `dig`, `dns_depth`, `whois`, `crt.sh`, `subdomain_passive`, `httpx_probe`, опционально `nmap`, `http_surface`, `js_analysis`, `screenshots`.
- `build_recon_summary_document` — сводка.
- `ai_recon` (LLM) — извлекает `assets`, `subdomains`, `ports` из tool output.

**Stage 2 — Threat Modeling**:
- В state machine: облегчённый путь — `handlers.run_threat_modeling` (recon context + NVD CVE lookup + LLM).
- В engagement-API: полный pipeline `recon/threat_modeling/pipeline.py` — 9 AI-задач (`THREAT_MODELING_AI_TASKS`), 12 артефактов в bucket `stage2-artifacts`.

**Stage 3 — Vulnerability Analysis**:
- При `SANDBOX_ENABLED=true` и наличии target — `run_va_active_scan_phase` (`handlers.py:986-1030`).
- `DEFAULT_TOOL_SEQUENCE` (`active_scan/planner.py`): dalfox → xsstrike → ffuf → sqlmap (gated) → nuclei → gobuster → wfuzz → commix → fingerprint (whatweb/nikto) → testssl.
- AI-планер опционально (`VA_AI_PLAN_ENABLED`).
- Custom XSS PoC через Playwright (`VA_CUSTOM_XSS_POC_ENABLED=true`).
- Эвристики `run_web_vuln_heuristics` (SSRF/CSRF/IDOR/open redirect).
- `searchsploit` для CVE → exploit маппинга.
- `ai_vuln_analysis` (LLM) — финальная агрегация.
- В engagement-API: полный pipeline с 15 AI-задачами и 17 артефактами в `stage3-artifacts`.

**Stage 4 — Exploitation**:
- **Approval gate** (`state_machine.py:569-591`) — если `policy.exploit_approval` требует одобрения, скан замораживается в `awaiting_approval`.
- `maybe_run_aggressive_exploit_tools` — опционально enqueue `run_sqlmap.delay` (если есть SQLi-сигнал, approval, `SQLMAP_VA_ENABLED`).
- `run_exploit_attempt` → `run_exploit_verify`.
- В engagement-API: полный pipeline с 5 адаптерами (Metasploit, SQLMap, Nuclei, Hydra, Custom Script), 4 артефакта в `stage4-artifacts`.

**Stage 5 — Post-exploitation**: lateral movement / persistence сценарии (LLM-only, теоретический анализ).

**Stage 6 — Reporting**:
- `ai_reporting` — JSON отчёт.
- `_persist_report_and_findings` — сохранение в DB.
- Авто-enqueue `enqueue_generate_all_bundle` для 3 tier × 4 format = 12 файлов.

### 5.4 Асинхронные задачи и воркеры

| Задача | Очередь | Назначение |
|--------|---------|------------|
| `argus.scan_phase` | `argus.scans` | Полный state machine скана |
| `argus.generate_report` / `generate_all_reports` | `argus.reports` | Генерация одного / всех форматов отчётов |
| `argus.report_generation` | `argus.reports` | Низкоуровневый рендер |
| `argus.ai_text_generation` | `argus.reports` | Генерация AI-секции с Redis-кешем по `prompt_version` |
| `argus.tool_run` | `argus.tools` | Вызов произвольного тула с политикой + audit log |
| `argus.va_active_scan_tool` | `argus.tools` | Async-обёртка `run_va_active_scan_sync` |
| `argus.va.run_*` | `argus.tools` | Именованные VA-инструменты (dalfox, xsstrike, ffuf, sqlmap, nuclei, whatweb, nikto, testssl) |
| `argus.recon_job` | `argus.recon` | Engagement recon job + нормализация артефактов |
| `argus.exploitation` | `argus.exploitation` | `execute_exploitation_run` для Stage 4 engagement |

Шедулеров (Celery beat) в коде не найдено — все задачи on-demand.

### 5.5 Завершение / graceful shutdown

- Celery: per-task — на ошибке `update Scan SET status=failed, phase=failed` (`tasks/__init__.py:49-62`), затем re-raise.
- Cancel API (`POST /scans/{id}/cancel`) — `celery_app.control.revoke(scan_id)` (task_id == scan_id) + `UPDATE Scan SET status=cancelled`.
- FastAPI lifespan завершается стандартно; SQLAlchemy engine — pool close on shutdown.
- В docker-compose нет явных `stop_grace_period` — используются дефолты Docker (10s).
- Healthcheck'и есть для всех сервисов; backend — `urllib.request /api/v1/health`, worker — `celery inspect ping`.

---

## 6. Чего не хватает / куда добавить

| Пробел | Где должно жить | Приоритет |
|--------|-----------------|-----------|
| **Несоответствие сигнатур `metrics`** | `observability.get_metrics_content` возвращает 3 значения, в `metrics.py:42` распаковывается 2. Может выкинуть `ValueError`. | High — потенциальный 500 на `/metrics` |
| **`docs/prompt-registry.md` устарел** | Нужно регенерить из `prompt_registry.py` (старые цитаты `SYSTEM_PROMPT_BASE`). | Medium |
| **Нет схемы ERD как изображения** | `docs/erd.md` — есть текстовое описание; сгенерировать визуальный ERD (например, mermaid в README или SVG из `dbml`). | Low |
| **Нет `.pre-commit-config.yaml`** | Корень проекта — добавить ruff, black, bandit pre-commit hooks. | Medium (security policy) |
| **Нет API contract в OpenAPI YAML** | `docs/frontend-api-contract.md` — markdown, но машинно-читаемого OpenAPI export'а вне `/api/v1/openapi.json` нет. | Medium |
| **Нет изображения архитектуры** | Вся диаграмма — текст. Mermaid / Excalidraw в `docs/backend-architecture.md`. | Low |
| **`backend/Dockerfile` помечен deleted в git status** | Используется `infra/backend/Dockerfile`. Стоит явно упомянуть в `README.md` и `docs/RUNNING.md`. | Low |
| **Anthropic SDK напрямую отсутствует** | Если хочется убрать зависимость от OpenRouter — добавить `anthropic` в `requirements.txt` + `AnthropicAdapter` в `llm/adapters.py`. | Low (опционально) |
| **Celery beat / scheduler** | Нет периодических задач — если нужны (например, авто-cleanup MinIO старше N дней) — добавить `celery-beat-schedule`. | Low |
| **Helm-чарты** | CI содержит job `helm-lint` под условием `hashFiles('**/Chart.yaml')`, но самих чартов нет. Добавить `helm/argus/` для k8s-деплоя. | Medium (если планируется k8s) |
| **`Frontend.rar` в корне (140 MB)** | `git status` показывает большой бинарь в корне. Нужно вынести в release-assets / .gitignore. | High (репозиторий пухнет) |
| **`infra/.env` в `git status` как modified** | Файл с секретами не должен быть в репозитории — проверить, что `.env` в `.gitignore` (см. `.gitignore` modified). | **Critical** (security) |
| **Кеш-инвалидация AI-секций** | `REPORT_AI_PROMPT_VERSIONS` единая для всех — при изменении одной секции инвалидируется весь кеш. Можно сделать per-section версии. | Low |
| **Документация по MCP-серверу** | `mcp-server/README.md` отсутствует — есть только `docs/mcp-server.md`. Добавить локальный README с инструкциями запуска. | Medium |

---

## Резюме одной строкой

**ARGUS** — production-grade multi-tenant пентест-платформа на FastAPI + Celery + Postgres-RLS, оркеструющая 6-фазный конвейер (recon → TM → VA → exploitation → post-exploitation → reporting) с **мульти-провайдер LLM-фасадом** (6 моделей через адаптер-роутер с cost tracker'ом и prompt-injection защитой), **Kali-sandbox** на 100+ инструментах, **3 tier-отчётами** (Midgard/Asgard/Valhalla × HTML/PDF/JSON/CSV), **MCP-сервером** для внешних AI-агентов, **MinIO** для артефактов, **SSE** для live-прогресса, **двумя Next.js 16 фронтами** и **CI с lint/test/SAST/SCA/build**.

[Анализ архитектуры ARGUS](47fb6c19-1c75-43d5-a9c5-83a52c70bda7)