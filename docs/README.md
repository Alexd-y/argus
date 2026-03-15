# ARGUS Documentation

Документация проекта ARGUS — AI-powered security scanner.

---

## Основные документы

| Документ | Описание |
|----------|----------|
| [api-contracts.md](./api-contracts.md) | REST API контракты — endpoints, request/response schemas |
| [api-contract-rule.md](./api-contract-rule.md) | Правило: Frontend — источник истины |
| [auth-flow.md](./auth-flow.md) | Поток аутентификации (JWT, API Key, pentagi reference) |
| [sse-polling.md](./sse-polling.md) | SSE vs Polling для real-time прогресса скана |
| [architecture-decisions.md](./architecture-decisions.md) | ADR — ключевые архитектурные решения |
| [env-vars.md](./env-vars.md) | Переменные окружения |
| [recon-stage1-flow.md](./recon-stage1-flow.md) | Upgraded Recon Stage 1 flow: MCP policy, AI bundles, traceability, Stage2 handoff |
| [recon-stage2-flow.md](./recon-stage2-flow.md) | **Stage 2 Threat Modeling**: dependency check → bundle load → MCP → 9 AI tasks → 12 artifacts |
| [STAGE2_QUICK_REF.md](./STAGE2_QUICK_REF.md) | **Quick Start**: 30 сек, curl, CLI, 12 артефактов, API endpoints |

---

## Recent Updates

### [Stage 2 Threat Modeling Documentation — TM-010](./recon-stage2-flow.md) (2026-03-12)

✅ Полная документация Stage 2 flow:
- 📊 Диаграмма Mermaid: Stage 1 → 9 AI задач → 12 артефактов
- 📋 11 типов артефактов с описаниями (markdown, CSV, JSON)
- 🚨 Зависимость от Stage 1 (4 блокирующих состояния)
- 🌐 MCP/AI integration points (REST API, CLI, MCP)
- 💡 Примеры использования (Python, cURL, CLI)
- ⚡ [Быстрая справка](./STAGE2_QUICK_REF.md) для старта за 30 сек

---

### [Stage 1 Threat Modeling Readiness — Final Completion](./develop/reports/2026-03-12-stage1-enrichment-completion.md) (2026-03-12)

✅ Закрыта оркестрация `orch-2026-03-12-06-01-argus-stage1-tm`:
- MCP Stage 1 allowlist/fail-closed policy + audit trail с `run_id`/`job_id`
- 7 AI task contracts на Pydantic v2 + schema export + examples + tests
- Новые артефакты и секции отчета для Route/JS/Input/API/Headers-TLS/Clustering/Anomaly/Stage2
- Verification gate: `ruff` PASS, `pytest` PASS (`24 passed`), final review approved

---

### [Stage 1 Svalbard Report — Methodology Section](./develop/reports/2026-03-11-stage1-methodology-update.md) (2026-03-11)

✅ Добавлена новая секция «Методология и инструменты» в Stage 1 HTML-отчёт:
- Документация AI-оркестрации (Cursor Agent, 10 этапов с промптами)
- Обоснование выбора системных команд вместо MCP
- 13 тестов, 100% покрытие
- **Файл:** `pentest_reports_svalbard/stage1-svalbard.html`

---

## Правило разработки

**Backend реализуется строго по API контрактам.** Источник истины — Frontend. См. [api-contract-rule.md](./api-contract-rule.md).

---

## Структура проекта

```
ARGUS/
├── backend/       # FastAPI, Celery, PostgreSQL
├── admin-frontend/# Админ-панель (опционально)
├── mcp-server/    # MCP для Cursor
├── sandbox/       # Изолированное выполнение инструментов
├── infra/         # Docker Compose
└── docs/          # Документация
```
