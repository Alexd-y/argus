# ARGUS Architecture Decisions

Ключевые архитектурные решения проекта ARGUS.

---

## ADR-001: Frontend — источник истины

**Статус:** Принято

**Контекст:** Backend и Frontend разрабатываются параллельно. Нужен единый источник истины для API.

**Решение:** Frontend (ARGUS/Frontend) — источник истины для API контрактов. Backend реализуется строго по контрактам. Изменения names, paths, status codes, payload shape — только после обновления Frontend или явного согласования.

**Следствия:**
- [api-contracts.md](./api-contracts.md) — каноническое описание REST API
- Contract tests проверяют совместимость backend с ожиданиями Frontend
- Референс: test/pentagi/frontend при пустом ARGUS/Frontend

---

## ADR-002: REST API (не GraphQL)

**Статус:** Принято

**Контекст:** pentagi использует GraphQL. ARGUS — сканер с простыми CRUD и потоком событий.

**Решение:** REST API для всех операций. SSE для real-time прогресса скана. GraphQL не используется.

**Следствия:**
- Простая интеграция с любым клиентом
- OpenAPI/Swagger для документации
- SSE — односторонний поток, проще WebSocket

---

## ADR-003: PostgreSQL + Redis + MinIO

**Статус:** Принято

**Контекст:** Нужны: персистентное хранилище, очереди, object storage для отчётов.

**Решение:**
- **PostgreSQL** — scans, reports, findings, events, users, tenants. pgvector для будущего RAG.
- **Redis** — Celery broker, rate limiting, кэш.
- **MinIO** — S3-совместимое хранилище отчётов (PDF, HTML, JSON, CSV).

**Следствия:**
- Docker Compose для локальной разработки
- Миграции через Alembic

---

## ADR-004: Celery для фоновых сканов

**Статус:** Принято

**Контекст:** Сканирование — долгий процесс (минуты). HTTP request не должен блокироваться.

**Решение:** Celery worker выполняет scan_phase_task. API возвращает scan_id сразу, клиент подписывается на SSE или polling.

**Следствия:**
- Redis как broker
- Профиль `tools` для celery-worker в docker-compose

---

## ADR-005: SSE для прогресса скана

**Статус:** Принято

**Контекст:** Клиенту нужен real-time прогресс (phase, progress, findings).

**Решение:** `GET /scans/:id/events` — Server-Sent Events. События пишутся в ScanEvent (PostgreSQL), backend читает и стримит. Polling `GET /scans/:id` — fallback.

**Следствия:**
- sse-starlette для FastAPI
- Фильтрация phase_complete (ARGUS-010): не передавать findings/exploits/evidence в SSE

---

## ADR-006: JWT + API Key для auth

**Статус:** Принято

**Контекст:** Admin-frontend и CI/CD требуют аутентификации.

**Решение:** JWT access token (15m) для admin-frontend. X-API-Key для programmatic access. Scans/Reports — публичные в текущей модели доступа.

**Следствия:**
- JWT_SECRET обязателен для auth endpoints
- POST /auth/login — упрощённый путь (любые credentials при JWT_SECRET в dev)
- GET /auth/me — protected

---

## ADR-007: Tools Guardrails

**Статус:** Принято

**Контекст:** Инструменты (nmap, nuclei, sqlmap и др.) выполняют команды. Риск: injection, сканирование неразрешённых целей.

**Решение:**
- Allowlist команд (nmap, nuclei, nikto, gobuster, sqlmap для /execute)
- Валидация target: домен или IP (whitelist)
- Rate limiting (30 req/min на IP)
- Sandbox (опционально) для изоляции

**Следствия:**
- parse_execute_command, validate_target_for_tool
- SANDBOX_ENABLED в config

---

## ADR-008: Multi-tenant через RLS

**Статус:** Принято (частично)

**Контекст:** Изоляция данных между tenants.

**Решение:** tenant_id во всех таблицах. RLS (Row Level Security) — `SET LOCAL app.current_tenant_id` перед запросами. Default tenant для публичного сканера.

**Следствия:**
- Alembic migration 002_rls_and_audit_immutable
- AuthContext.tenant_id для JWT/API key

---

## ADR-009: Отчёты — генерация on-demand и кэш

**Статус:** Принято

**Контекст:** PDF/HTML/JSON/CSV генерируются из данных Report + Findings.

**Решение:** При download — проверка MinIO. Если есть кэш — отдать. Иначе — сгенерировать, загрузить в MinIO, отдать.

**Следствия:**
- reports/generators.py — weasyprint (PDF), jinja2 (HTML)
- reports/storage.py — upload/download

---

## ADR-010: Observability

**Статус:** Принято

**Контекст:** Мониторинг в production.

**Решение:** Prometheus metrics (`/metrics`), structured JSON logging, OpenTelemetry-ready (OTEL_EXPORTER_OTLP_ENDPOINT).

**Следствия:**
- core/observability.py — scan_started, phase_duration, tool_run
- LOG_LEVEL, OTEL_* env vars

---

## Связанные документы

- [api-contracts.md](./api-contracts.md)
- [api-contract-rule.md](./api-contract-rule.md)
- [auth-flow.md](./auth-flow.md)
- [sse-polling.md](./sse-polling.md)
- [env-vars.md](./env-vars.md)
