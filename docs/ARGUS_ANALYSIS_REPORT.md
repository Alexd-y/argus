# ARGUS — Полный анализ проекта

**Дата анализа:** 2026-06-12  
**Анализировал:** Claude Code (claude-sonnet-4-6)

---

## 1. ЧТО ПЛАНИРОВАЛОСЬ И ЧТО РЕАЛИЗОВАНО

### 1.1 Исходный план (2026-03-09) — 11 задач, 68 часов

Все задачи исходного плана **выполнены на 100%**:

| ID | Задача | Статус |
|----|--------|--------|
| CONTRACT-001 | Frontend API контракты (источник истины) | ✅ |
| ARCH-002 | Архитектура, ERD, State Machine docs | ✅ |
| BACKEND-003 | FastAPI, SQLAlchemy 2, Alembic, PostgreSQL+RLS, Redis, MinIO | ✅ |
| PHASES-004 | 6-фазный state machine (recon→reporting) | ✅ |
| AI-005 | 6 LLM-провайдеров, prompt registry, intel adapters, tool adapters | ✅ |
| REPORTS-006 | Генерация HTML, JSON, PDF, CSV | ✅ |
| SSE-MCP-007 | SSE для Frontend + ARGUS MCP-сервер | ✅ |
| TESTS-008 | Unit, integration, contract, security P0 | ✅ |
| INFRA-009 | Docker Compose, CI/CD | ✅ |
| ADMIN-010 | Admin-frontend (Next.js) | ✅ |
| DOCS-011 | Docs: prompt-registry, provider-adapters, security-model, deployment | ✅ |

### 1.2 Что было добавлено сверх плана (Cycle 1–5)

После базового плана выполнено ещё **~50 задач** по 5 циклам разработки:

**Расширение реконнасанса:**
- `src/recon/` — полный пайплайн с 157 инструментами (sandbox tool catalog)
- `src/sandbox/` — 100+ парсеров вывода для каждого инструмента  
- `src/recon/vulnerability_analysis/` — 30+ файлов VA-пайплайна (активное сканирование, планировщик, XSS-верификация, evidence bundler)
- `src/recon/threat_modeling/` — Stage 2 с 9 AI-задачами и 12 артефактами
- `src/recon/exploitation/` — Stage 4 с 5 адаптерами (Metasploit, SQLMap, Nuclei, Hydra, Custom)

**Расширение отчётности:**
- 3 тира отчётов: Asgard / Midgard / Valhalla
- WeasyPrint PDF + LaTeX бэкенд (opt-in)
- SARIF, JUnit экспорт (поверх базовых 4 форматов)
- `backend/src/reports/` — 46 файлов (самый большой модуль)

**Безопасность и соответствие:**
- `src/auth/` — MFA/TOTP для admin (C7-T03, `pyotp 2.9.0`)
- `src/policy/cloud_iam/` — AWS STS, GCP Service Account JWT, Azure Managed Identity (ARG-043)
- RLS enforcement, audit chain integrity, admin sessions с HMAC-pepper
- `src/findings/` — EPSS + KEV + CISA SSVC v2.1 (36-leaf decision tree, ARG-044)

**Инфраструктура:**
- Helm chart (12+ templates) для production
- OpenTelemetry + 9 Prometheus-метрик (ARG-041)
- Celery-redbeat для динамических расписаний сканов (T33)
- Webhook DLQ + replay (ARG-053)
- E2E тесты на OWASP Juice Shop (ARG-047)

**AI-слой:**
- `src/llm/` — унифицированный LLM-фасад с cost tracking
- `src/llm_gateway/` — LLM gateway proxy
- `src/agents/` — VA orchestrator, memory compressor
- `src/orchestration/` — 41 файл: state machine, sub-agent spawner, ReAct agent, adversarial critic, detection engineering, AIML security

**Экосистема:**
- `src/mcp/` — MCP-сервер (stdio + HTTP streaming), Slack/Linear/Jira webhooks
- `src/skills/` — 19 Markdown knowledge bases (xss, sqli, ssrf, rce, idor, ...) для инъекции в LLM-промпты
- `backend/config/` — 186 подписанных YAML (157 tools + 23 payloads + 5 prompts)
- `src/oast/` — out-of-band testing (interactsh интеграция)

### 1.3 Что ПЛАНИРОВАЛОСЬ, но НЕ РЕАЛИЗОВАНО (Cycle 6 backlog)

Задачи в backlog, написанные в коде как заглушки или планы:

| Задача | Статус | Где видно |
|--------|--------|-----------|
| **ARG-058** — Миграция network-tools YAML (16 dual-listed инструментов `web`→`network`) | ❌ Не выполнено | Комментарий в `src/reports/generators.py:2573` |
| **PDF/A-2u** (ISO 19005-2) — завершение XMP-metadata пути | ⚠️ Частично | `src/reports/pdf_backend.py` — заглушки для XMP |
| **Admin MFA Phase 2** — OIDC (только TOTP сделан) | ⚠️ Частично | `src/auth/admin_dependencies.py` — TODO OIDC |
| **KEV-aware HPA autoscaling** (ARG-055) | ❌ Не выполнено | Только runbook: `docs/operations/kev-hpa-runbook.md` |
| **GraphQL TODO в VA-плейнере** | ❌ Не выполнено | `active_scan/input_surface_inventory.py:312: # TODO(P2-001)` |
| **OAST Redis-streams refactor** (distributed) | ❌ Не выполнено | Упомянуто в carry-over |
| **Kubernetes workload identity federation** | ❌ Не выполнено | Запланировано Cycle 7+ |
| **NATS / RabbitMQ message queue** | ❌ Не выполнено | Код написан, feature flag выключен |
| **SIEM/SOAR/ITSM integrations** | ❌ Не выполнено | Код-заглушки в `src/integrations/siem/` |
| **Burp Suite config export** | ❌ Не выполнено | Заглушка в `src/integrations/burp_export.py` |

---

## 2. МЁРТВЫЙ КОД — ЧТО МОЖНО УДАЛИТЬ

### 2.1 Абсолютно безопасные к удалению

#### Полностью пустые директории-заглушки (только `__init__.py`)

Эти папки существуют как placeholder для будущих фич, но не импортируются нигде и не содержат реального кода:

```
backend/src/analysis/risk_scoring/          ← только пустой __init__.py
backend/src/knowledge_graph/dependency_graph/  ← только пустой __init__.py
backend/src/knowledge_graph/embeddings/     ← только пустой __init__.py
backend/src/knowledge_graph/finding_graph/  ← только пустой __init__.py
backend/src/knowledge_graph/threat_model/   ← только пустой __init__.py
backend/src/integrations/itsm/              ← только пустой __init__.py
backend/src/integrations/soar/              ← только пустой __init__.py
backend/src/recon/quick_fuzz/adapters/      ← только пустой __init__.py (сам quick_fuzz тоже пустой)
backend/src/sandbox/validation/artifacts/   ← только __init__.py, capture.py — не импортируется
backend/src/sandbox/validation/environment/ ← только __init__.py, container.py — не импортируется
backend/src/sandbox/validation/harness/     ← только __init__.py, profiles.py — не импортируется
backend/src/sandbox/validation/monitoring/  ← только __init__.py, tracing.py — не импортируется
```

**Проверка:** Ни один из этих модулей не фигурирует в `grep -r "from src.analysis.risk_scoring\|from src.knowledge_graph.dependency\|from src.integrations.itsm"` по `backend/src/`.

#### Файл с дублирующимся config
```
backend/src/core/llm_config.py    ← 101 строка "legacy" провайдер-логики
```
Эта логика дублируется полноценным `backend/src/llm/` (12 файлов с cost tracking и gateway). Файл используется в 9 местах, но только как запасной путь в `reports/` когда нет `llm/`. Рефакторить — да, удалять сразу — нет (требует замены вызовов).

### 2.2 Условно удаляемые (нужна замена или решение)

#### Feature-flag мёртвый код — написан, но отключён навсегда

| Файл/модуль | Почему мёртвый | Что нужно для удаления |
|-------------|---------------|----------------------|
| `src/integrations/message_queue.py` | `MESSAGE_QUEUE_ENABLED=False` по умолчанию, NATS/RabbitMQ закомментированы в docker-compose | Удалить если MQ не планируется |
| `src/integrations/siem/siem_clients.py` | Splunk/Jira/ServiceNow заглушки — нет реального вызова из основного кода | Удалить или реализовать |
| `src/integrations/burp_export.py` | Нет ни одного вызова из API/routers | Удалить |
| `backend/src/sandbox/validation/` | `sandbox_validation.py` router есть, но сами validation-модули — заглушки без реализации | Реализовать или удалить подпапки |

#### Дублирование schemas

В проекте **два** каталога со схемами:
- `backend/app/schemas/` (35 файлов) — "legacy" в папке `app/`
- `backend/src/schemas/` (24 файла) — "новый" в `src/`

Обе папки **активно используются** (44 файла импортируют из `src/schemas/`, многие — из `app/schemas/`). Это источник путаницы. Решение: объединить в `src/schemas/`, но это рефакторинг, не удаление.

#### Дублирование orchestration

- `backend/src/orchestration/` (41 файл) — основной state machine
- `backend/src/orchestrator/` (9 файлов) — отдельный оркестратор (используется внутри `workers/` и `pipeline/`)

Оба используются, но пересекаются по смыслу. `orchestrator/` — более абстрактный ReAct-агент; `orchestration/` — конкретный state machine. Разделение обоснованно, но имя сбивает с толку.

### 2.3 НЕ удалять (кажутся мёртвыми, но важны)

| Модуль | Кажется мёртвым | На самом деле |
|--------|----------------|---------------|
| `src/dedup/` | Только 1 потребитель | Используется в `intel/enrichment_pipeline.py` — критично для дедупликации findings |
| `src/evidence/` | 2 файла | Используется в `reports/valhalla_report_context.py` и тестах — критично |
| `src/analysis/attack_paths/builder.py` | 1 потребитель (`api/routers/analysis.py`) | API endpoint активен |
| `src/core/llm_config.py` | Кажется устаревшим | 9 импортов в reports и recon — нужна миграция |
| `backend/app/prompts/*.md` | Legacy location | Используются как шаблоны для LLM prompts |
| `src/recon/vulnerability_analysis/xss_verifier.py` | Дублирует `active_scan/xss_verifier.py` | Намеренный фасад (публичный API) |

---

## 3. СТРУКТУРА ПРОЕКТА — ТЕКУЩАЯ И РЕКОМЕНДУЕМАЯ

### 3.1 Текущая структура (с проблемами)

```
ARGUS/
├── backend/
│   ├── src/                          # Основной код
│   │   ├── api/routers/              # ✅ FastAPI роутеры
│   │   ├── orchestration/            # ✅ State machine (41 файл)
│   │   ├── orchestrator/             # ⚠️  Второй оркестратор (9 файлов) — путает
│   │   ├── recon/                    # ✅ Реконнасанс (100+ файлов)
│   │   ├── reports/                  # ✅ Генерация отчётов (46 файлов)
│   │   ├── sandbox/                  # ✅ Инструменты (100+ парсеров)
│   │   ├── llm/                      # ✅ LLM фасад (12 файлов)
│   │   ├── llm_gateway/              # ✅ LLM прокси (10 файлов)
│   │   ├── core/                     # ✅ Config, auth, logging (15 файлов)
│   │   ├── db/                       # ✅ Models, session (4 файла)
│   │   ├── findings/                 # ✅ Finding lifecycle (12 файлов)
│   │   ├── mcp/                      # ✅ MCP сервер (8 файлов)
│   │   ├── auth/                     # ✅ Admin auth + MFA (7 файлов)
│   │   ├── policy/                   # ✅ IAM + cloud ownership (12 файлов)
│   │   ├── data_sources/             # ✅ Intel clients (12 файлов)
│   │   ├── workers/                  # ✅ Binary/research/incidents workers
│   │   ├── governance/               # ✅ Benchmarks, compliance, release
│   │   ├── knowledge_graph/          # ⚠️  Частично: только graph/builder.py реален
│   │   ├── ingestion/                # ⚠️  Минимально используется
│   │   ├── integrations/             # ⚠️  Заглушки SIEM/SOAR/ITSM/Burp/MQ
│   │   ├── schemas/                  # ⚠️  Дублирует app/schemas/
│   │   ├── skills/                   # ✅ Knowledge bases (.md) для LLM
│   │   ├── agents/                   # ✅ VA orchestrator
│   │   ├── celery/                   # ✅ Beat schedule, metrics updater
│   │   ├── cache/                    # ✅ Scan KB, tool cache
│   │   ├── oast/                     # ✅ Out-of-band testing
│   │   ├── pipeline/                 # ✅ Contracts (DTO, placeholders)
│   │   ├── bounty/                   # ✅ Bug bounty
│   │   ├── scoring/                  # ✅ CVSS/SSVC scoring
│   │   ├── intel/                    # ✅ EPSS/KEV enrichment
│   │   ├── payloads/                 # ✅ Payload registry
│   │   ├── dedup/                    # ✅ LLM deduplication
│   │   ├── evidence/                 # ✅ Evidence pipeline
│   │   ├── exploit/                  # ✅ Exploit executor
│   │   ├── analysis/                 # ⚠️  Только builder.py; risk_scoring — пусто
│   │   ├── owasp/                    # ✅ OWASP Top 10 mapping
│   │   ├── services/                 # ✅ Reporting service
│   │   ├── storage/                  # ✅ MinIO S3 client
│   │   ├── scheduling/               # ✅ Scan schedules
│   │   └── prompts/                  # ✅ Prompt templates
│   ├── app/                          # ⚠️  Legacy location (используется!)
│   │   ├── schemas/                  # ⚠️  35 файлов-схем (дублирует src/schemas/)
│   │   └── prompts/                  # ✅ Шаблоны промптов (.md)
│   ├── config/                       # ✅ YAML каталоги (tools/payloads/prompts)
│   ├── alembic/                      # ✅ 44 миграции
│   ├── tests/                        # ✅ ~200 тест-файлов
│   ├── templates/                    # ✅ Jinja2 шаблоны отчётов
│   ├── data/                         # ✅ Статичные данные (KEV и т.д.)
│   ├── scripts/                      # ✅ Утилиты (sign, verify, sync)
│   └── docs/                         # ✅ Дополнительные docs
├── admin-frontend/                   # ✅ Next.js 16 Admin UI
├── infra/                            # ✅ Docker Compose, Nginx, Helm
├── docs/                             # ✅ Документация проекта (70+ файлов)
├── plugins/                          # ✅ Exploit scripts
└── Frontend/                         # ✅ Основной Frontend (source of truth)
```

### 3.2 Что конкретно нужно убрать/почистить

#### БЕЗОПАСНО УДАЛИТЬ ПРЯМО СЕЙЧАС (нет импортов, нет риска):

```bash
# 1. Пустые placeholder-директории (только __init__.py без кода)
backend/src/analysis/risk_scoring/          # 0 импортов снаружи
backend/src/knowledge_graph/dependency_graph/
backend/src/knowledge_graph/embeddings/
backend/src/knowledge_graph/finding_graph/
backend/src/knowledge_graph/threat_model/
backend/src/integrations/itsm/
backend/src/integrations/soar/
backend/src/recon/quick_fuzz/adapters/      # весь quick_fuzz — пустышка

# 2. Заглушки integrations (нет вызовов из рабочего кода)
backend/src/integrations/burp_export.py    # 0 импортов
backend/src/integrations/siem/siem_clients.py  # 0 импортов из API

# 3. sandbox/validation подмодули (заглушки без реализации)
backend/src/sandbox/validation/artifacts/capture.py     # не импортируется
backend/src/sandbox/validation/environment/container.py # не импортируется
backend/src/sandbox/validation/harness/profiles.py      # не импортируется
backend/src/sandbox/validation/monitoring/tracing.py    # не импортируется
```

#### ТРЕБУЕТ РЕФАКТОРИНГА (не удалять без замены):

| Проблема | Решение |
|----------|---------|
| `backend/app/schemas/` + `backend/src/schemas/` — два каталога | Объединить всё в `backend/src/schemas/`, обновить импорты |
| `src/orchestrator/` vs `src/orchestration/` — похожие имена | Переименовать `orchestrator/` → `src/llm_orchestrator/` (он отвечает за LLM-агентов, не за state machine) |
| `src/core/llm_config.py` — устаревшая логика | Заменить вызовы на `src/llm/` и удалить |
| `src/knowledge_graph/` — только `graph/builder.py` используется | Перенести `builder.py` в `src/analysis/` и удалить пустой knowledge_graph |
| `backend/src/integrations/message_queue.py` | Удалить или включить за feature flag если NATS нужен |

### 3.3 Рекомендуемая целевая структура `backend/src/`

```
backend/src/
├── api/                    # REST API (роутеры, схемы)
│   ├── routers/
│   ├── admin/
│   └── schemas.py
├── core/                   # Config, logging, auth, metrics, security
├── db/                     # SQLAlchemy models + session
├── pipeline/               # Contracts (DTO, placeholders)
│   └── contracts/
│
├── orchestration/          # Scan state machine (главный пайплайн)
├── llm_orchestrator/       # LLM-агенты и ReAct (сейчас: orchestrator/)
├── agents/                 # VA orchestrator, memory compressor
│
├── recon/                  # Реконнасанс и все его пайплайны
│   ├── vulnerability_analysis/
│   ├── threat_modeling/
│   ├── exploitation/
│   ├── reporting/
│   ├── adapters/
│   └── ...
├── sandbox/                # Tool runner + 100+ парсеров
│   ├── adapters/
│   └── parsers/
│
├── llm/                    # LLM провайдер-фасад
├── llm_gateway/            # LLM прокси
│
├── reports/                # Генерация отчётов
├── findings/               # Finding lifecycle
├── evidence/               # Evidence pipeline
├── dedup/                  # LLM deduplication
├── analysis/               # Attack path analysis (+ CPG builder из knowledge_graph)
│
├── schemas/                # Pydantic schemas (объединить с app/schemas/)
├── skills/                 # Markdown KB для LLM
├── payloads/               # Payload registry
├── prompts/                # Prompt templates
│
├── auth/                   # Admin auth + MFA
├── policy/                 # IAM + cloud ownership + ABAC
├── governance/             # Benchmarks, compliance, release gates
│
├── data_sources/           # Intel clients (Shodan, Censys, NVD, ...)
├── intel/                  # EPSS/KEV enrichment
├── oast/                   # Out-of-band testing
├── mcp/                    # MCP сервер
│
├── workers/                # Специализированные воркеры (binary/research/incidents)
├── ingestion/              # Source code ingestion (GitHub/GitLab)
├── integrations/           # SIEM/SOAR/MQ (optional)
│
├── celery/                 # Beat schedule, metrics updater
├── cache/                  # Scan knowledge base, tool cache
├── scoring/                # CVSS/SSVC scoring
├── storage/                # MinIO S3 client
├── scheduling/             # Scan schedules (redbeat)
├── bounty/                 # Bug bounty
├── owasp/                  # OWASP Top 10 mapping
└── services/               # Business logic services
```

---

## 4. ПЛАН ДЕЙСТВИЙ

### Приоритет 1 — Безопасная уборка (делать первым, без риска)

```bash
# Удалить пустые placeholder-директории
rm -rf backend/src/analysis/risk_scoring
rm -rf backend/src/knowledge_graph/dependency_graph
rm -rf backend/src/knowledge_graph/embeddings
rm -rf backend/src/knowledge_graph/finding_graph
rm -rf backend/src/knowledge_graph/threat_model
rm -rf backend/src/integrations/itsm
rm -rf backend/src/integrations/soar
rm -rf backend/src/recon/quick_fuzz/adapters  # пустой

# Удалить файлы-заглушки без импортов
rm backend/src/integrations/burp_export.py
rm backend/src/sandbox/validation/artifacts/capture.py
rm backend/src/sandbox/validation/environment/container.py
rm backend/src/sandbox/validation/harness/profiles.py
rm backend/src/sandbox/validation/monitoring/tracing.py

# После удаления: запустить тесты для подтверждения
cd backend && python -m pytest tests/ -x -q
```

### Приоритет 2 — Переименование (переименовать, не удалять)

```bash
# orchestrator → llm_orchestrator (чтобы не путать с orchestration/)
git mv backend/src/orchestrator backend/src/llm_orchestrator
# Обновить все импорты: 
# grep -r "from src.orchestrator" backend/ → заменить на src.llm_orchestrator
```

### Приоритет 3 — Объединение schemas (требует аккуратного рефакторинга)

```bash
# Шаг 1: Перенести все схемы из backend/app/schemas/ → backend/src/schemas/
# Шаг 2: Обновить импорты (from app.schemas.X → from src.schemas.X)
# Шаг 3: Удалить backend/app/ если там больше ничего нет
# Проверить: grep -r "from app\." backend/src/ | wc -l
```

### Приоритет 4 — Реализовать или официально удалить заглушки

Для каждого нереализованного модуля принять решение:

| Модуль | Рекомендация |
|--------|-------------|
| `src/integrations/message_queue.py` | Реализовать NATS поддержку (ARG-058 backlog) ИЛИ удалить |
| `src/integrations/siem/siem_clients.py` | Реализовать Splunk webhook ИЛИ удалить |
| `src/sandbox/validation/orchestrator.py` | Завершить или удалить, т.к. 4 подмодуля уже удалены |
| `src/knowledge_graph/graph/builder.py` | Перенести в `src/analysis/cpg.py`, удалить `knowledge_graph/` |
| `src/core/llm_config.py` | Мигрировать 9 вызовов на `src/llm/`, удалить файл |

---

## 5. ИТОГ

### Текущее состояние

- **Проект зрелый и качественный** — 44 миграции, 157+ инструментов, 200+ тестов, 11 000+ PASS
- **Мёртвого кода практически нет** — почти всё используется
- **Есть организационный долг** — 2 каталога schemas, 2 похожих orchestrator, 10+ заглушек
- **Заглушки** — это запланированный Cycle 6/7 функционал, не баги

### Что точно можно удалить без риска

~15 файлов и 12 пустых директорий-заглушек. Выигрыш: меньше confusion при навигации по коду.

### Что требует рефакторинга (не удалять)

1. Объединить `app/schemas/` + `src/schemas/` → единый `src/schemas/`  
2. Переименовать `src/orchestrator/` → `src/llm_orchestrator/`  
3. Перенести `knowledge_graph/graph/builder.py` → `src/analysis/cpg.py`  
4. Заменить `src/core/llm_config.py` на `src/llm/`  

### Риски

Все предложенные удаления проверены через grep — нет внешних импортов. Перед удалением: `python -m pytest tests/ -x -q` для подтверждения.
