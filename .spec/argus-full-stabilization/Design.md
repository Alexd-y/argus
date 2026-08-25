# ARGUS — Полная стабилизация (Design)

## Текущая архитектура (существующая, не переписывается)

- Backend: Python 3.12 / FastAPI; Celery (9 очередей); SQLAlchemy async (asyncpg).
- Данные: PostgreSQL + pgvector; Redis (broker/cache); MinIO (S3-совместимо).
- Sandbox: Kali-контейнер, инструменты через `docker exec`.
- Frontend: Next.js (публичный + admin).
- Миграции: Alembic (`backend/alembic/versions`, 001…059), env через
  `async_engine_from_config`; smoke-тест допускает `aiosqlite`.

## Контейнерный validation environment

Файл: `infra/docker-compose.validation.yml`, проект `argus-validation`.

| Сервис | Образ | Хост-порт | Том (disposable) |
|--------|-------|-----------|------------------|
| postgres | pgvector/pgvector:pg15 | 55432 | argus_validation_pg |
| redis | redis:7-alpine | 56379 | (без тома) |
| minio | minio/minio | 59000/59001 | argus_validation_minio |
| minio-init | minio/mc | — | — |

Клиентские строки (в тестах через env):
```
DATABASE_URL=postgresql+asyncpg://argus:argus_validation@localhost:55432/argus_test
REDIS_URL=redis://localhost:56379/0
MINIO_ENDPOINT=localhost:59000
```
Изоляция: собственные имена/тома/порты; продакшн-`argus-*` не затрагивается;
`down -v` удаляет только тома этого проекта. Секреты — только в
`infra/.env.validation` (gitignored), с dev-fallback в compose.

## DB / migration strategy

- Драйверы: runtime — asyncpg; тесты миграций дополнительно используют sync
  `psycopg2-binary` (объявлен dev-only в `pyproject.toml`) для интроспекции.
- Round-trip: тесты гонят `command.upgrade(head)` и в teardown
  `command.downgrade(base)` — поэтому корректность downgrade всей цепочки
  критична для изоляции (иначе «грязная» БД каскадит в следующий тест).
- Найденный дефект: `031_drop_legacy_admin_session_id.downgrade` на PostgreSQL
  выполнял `ALTER COLUMN session_token_hash DROP NOT NULL` до снятия PK →
  `column ... is in a primary key`. Исправлено: снятие PK перед демоцией.

## State isolation

- Общая тестовая БД возвращается к `base` через teardown downgrade (после фикса
  031 это снова работает детерминированно).
- Sandbox parser / registry тесты, зависящие от порядка, лечатся сбросом/
  переинициализацией глобального реестра в фикстуре либо в lifecycle —
  по факту root cause (диагностика в `test-failures.md`).

## tool / payload / prompt registries

- Signed tool registry (`backend/config/tools/*.yaml`) — источник истины;
  сверяется с `expected_executables`, planner, Celery tasks, MCP, парсерами.
- Prompt-каталог верифицируется на старте (Ed25519); путь резолвится
  module-relative (исправлено ранее в `737c3b9`).

## Quick / Light / Deep

| UI profile | scan_mode | execution_mode | runtime | lease |
|------------|-----------|----------------|---------|-------|
| quick | quick | quick | Quick balanced | нет |
| light | standard | production | safe active | нет |
| deep | lab | lab_unrestricted | LAB scope | обязателен |

Резолвинг — `backend/src/profiles/resolver.py`; конфликт профиля/legacy → 422.

## Report pipeline

Единый immutable snapshot `ReportDocumentV1` → JSON/Markdown/XML/HTML→PDF
рендереры; evidence-gate понижает findings без доказательств; parity-тесты
сверяют число findings, severity, evidence IDs, coverage, snapshot hash.

## AWS portability

- Endpoints/креды — из env/role chain; нет hardcoded localhost в рантайме.
- S3: endpoint/region/path-style конфигурируемы (MinIO ↔ S3).
- Backend/worker stateless; health/readiness; graceful SIGTERM; Celery
  visibility timeout; идемпотентные retries; DLQ.
- Документация готовности — `docs/aws-readiness.md` (без создания ресурсов).

## Error handling

- Единый machine-readable контракт ошибок с кодами и correlation_id.
- Нет утечки stack trace/секретов наружу; structured logging.

## Test matrix (см. TASK.md §10)

compileall → ruff (CI select) → pytest (unit/api/db/integration/security/mcp/
quick/payloads/nuclei/orchestration/reports/e2e) → повтор полного прогона →
randomized/order → frontend (vitest/eslint/tsc/build) → контейнерный smoke.

## Compatibility / rollout

- Изменения аддитивны; продакшн-миграции не переписывают семантику; исправление
  031 меняет только ПОРЯДОК DDL в downgrade (конечная схема идентична), апгрейд
  не затронут.
- Validation-стенд опционален и не влияет на прод-конфигурацию.
