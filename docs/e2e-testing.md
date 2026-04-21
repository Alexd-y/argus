# ARGUS — Полное e2e-тестирование (ARG-047)

> Капстоун-тест полного стека ARGUS на боевой мишени **OWASP Juice Shop v17.0.0**.
> Доказывает работоспособность всей цепочки: **Backend → Celery → MCP → Sandboxes →
> Reports → OAST → Prometheus**. Запускается ежедневно (cron) и вручную (workflow_dispatch).

Документ — оперативный runbook для дежурного инженера / SRE / релиз-менеджера.
Если ночной прогон упал — начните с раздела **«Что делать, если тест упал»**.

---

## 1. Что включено в e2e-стек

| Сервис             | Образ                                            | Порт (host) | Назначение                                                |
| ------------------ | ------------------------------------------------ | ----------- | --------------------------------------------------------- |
| `juice-shop`       | `bkimminich/juice-shop:v17.0.0`                  | 3000        | Мишень для активного скана                                |
| `argus-backend`    | `argus-backend:e2e` (или `${ARGUS_BACKEND_IMAGE}`) | 8000        | FastAPI, /health, /ready, /metrics, /api/v1/*             |
| `argus-celery`     | (тот же образ, другая команда)                   | —           | Воркер очередей `argus.scans|reports|tools|recon|...`     |
| `argus-mcp`        | (тот же образ)                                    | 8765        | MCP-сервер инструментов                                    |
| `postgres`         | `postgres:16-alpine`                             | 5432        | Каталог сканов / находок / отчётов                         |
| `redis`            | `redis:7-alpine`                                 | 6379        | Брокер Celery + Pub/Sub                                    |
| `minio`            | `minio/minio:RELEASE.2024-09-13T20-26-02Z`       | 9000/9001   | S3-совместимое хранилище отчётов                          |
| `prometheus`       | `prom/prometheus:v2.54.1`                        | 9090        | Сбор метрик `argus_*` каждые 5 секунд                      |

> ⚠️ Все образы запинены по тегу/версии. Не меняйте теги «по дороге» — это
> единственный способ удержать **CI flake rate < 5%** (Backlog §17).

Сетевая модель: общий bridge-network `argus-e2e`. Только `juice-shop` и
`argus-backend` экспозированы наружу; остальные сервисы общаются по DNS-именам.

---

## 2. Предусловия

* **Docker Desktop ≥ 25** или Docker Engine + Compose v2 на Linux.
* ≥ 8 ГБ свободной оперативной памяти; ≥ 10 ГБ свободного места на диске.
* На Windows-хостах: PowerShell 5.1 или 7.x; репозиторий клонирован в путь
  без пробелов (Compose volume mounts не любят пробелы).
* Опционально: `cosign ≥ 2.4` в PATH — без него Phase 08 деградирует до
  `status='cosign_unavailable'` и не валит весь прогон.

Переменные окружения (см. `.env.e2e.example`):

| Переменная               | Дефолт                              | Описание                                  |
| ------------------------ | ----------------------------------- | ----------------------------------------- |
| `E2E_TARGET`             | `http://juice-shop:3000`            | URL мишени, передаётся в API при создании |
| `E2E_SCAN_MODE`          | `standard`                          | `quick \| standard \| deep`               |
| `E2E_MIN_FINDINGS`       | `50`                                | Минимум находок для зелёного прогона      |
| `E2E_EXPECTED_REPORTS`   | `12`                                | Сколько отчётов считается «полным набором» (3 уровня × 4 формата API) |
| `E2E_BACKEND_URL`        | `http://localhost:8000`             | URL для curl/python из обёртки            |
| `E2E_PROM_URL`           | `http://localhost:9090`             | URL Prometheus                            |
| `E2E_TOKEN`              | `e2e-api-key-not-for-production`    | API-ключ из `ARGUS_API_KEYS`              |
| `E2E_KEEP_STACK`         | `0`                                 | `1` — не сносить стек после прогона       |
| `E2E_RESULTS_DIR`        | `./e2e-results-<utc-stamp>`         | Куда складывать артефакты                 |

---

## 3. Локальный запуск

### Linux / macOS / WSL

```bash
chmod +x scripts/e2e_full_scan.sh scripts/e2e/verify_cosign.sh scripts/e2e/archive_results.sh
bash scripts/e2e_full_scan.sh
```

### Windows (PowerShell 5.1+)

```powershell
pwsh -File .\scripts\e2e_full_scan.ps1
# или: powershell.exe -ExecutionPolicy Bypass -File .\scripts\e2e_full_scan.ps1
```

Прогон занимает **30–60 минут** (большая часть — активный скан Juice Shop).

В обоих случаях:

1. Скрипт поднимает `infra/docker-compose.e2e.yml`.
2. Дожидается `GET /ready` от backend (deadline 5 минут).
3. Создаёт скан через `POST /api/v1/scans`.
4. Поллит `GET /api/v1/scans/<id>` пока статус не станет `completed`.
5. Запускает `POST /api/v1/scans/<id>/reports/generate-all`.
6. Дожидается, пока все отчёты получат `generation_status='ready'`.
7. Прогоняет хелперы из `scripts/e2e/`: `verify_reports.py`, `verify_oast.py`,
   `verify_cosign.sh`, `verify_prometheus.py`.
8. Складывает результаты в `${E2E_RESULTS_DIR}` и сжимает в `.tar.gz`.
9. Сносит стек (`docker compose down -v`), если `E2E_KEEP_STACK=0`.

---

## 4. Структура артефактов

```
e2e-results-2026-04-19T02-00-00Z/
├── summary.json              ← агрегат: статус, длительности фаз, IDs
├── scan_create.json          ← Phase 03 — POST /api/v1/scans
├── scan_status_final.json    ← Phase 04 — финальное состояние скана
├── reports_generate.json     ← Phase 05 — POST /generate-all
├── verify_reports.json       ← Phase 06 — verify_reports.py
├── verify_oast.json          ← Phase 07 — verify_oast.py (м.б. no_oast_in_scope)
├── verify_cosign.json        ← Phase 08 — verify_cosign.sh
├── verify_prometheus.json    ← Phase 09 — verify_prometheus.py
├── findings.json             ← Phase 10 — снимок /findings
├── archive.json              ← Phase 12 — манифест архива
└── diagnostics/
    ├── ps.txt                ← docker compose ps
    ├── argus-backend.log     ← последние 500 строк
    ├── argus-celery.log
    ├── argus-mcp.log
    ├── juice-shop.log
    ├── postgres.log
    ├── redis.log
    ├── minio.log
    └── prometheus.log
```

`summary.json` — корневой документ. Если поле `status='failed'`, поле
`failed_phase` указывает, какая фаза провалилась, а `failure_detail` содержит
короткое сообщение **без stack trace** (правило безопасности — наружу
никогда не уходят внутренние детали).

---

## 5. Что делать, если тест упал

1. **Откройте `summary.json`** — найдите `failed_phase` и `failure_detail`.
2. **Сопоставьте с таблицей фаз ниже** — каждая фаза имеет typical-failure-mode.
3. **Проверьте `diagnostics/*.log`** — ARGUS пишет structured-JSON, ищите
   `level=ERROR` или `event=exception`.
4. Если есть подозрение на регрессию — **сравните с предыдущим прогоном**
   (артефакты CI хранятся 30 дней).

| Phase | Тест проверяет                            | Типичная причина падения                          | Куда смотреть                            |
| ----- | ----------------------------------------- | ------------------------------------------------- | ---------------------------------------- |
| 01    | `docker compose up --wait`                | Образ не запинен / реестр недоступен              | Сетевые логи Docker                      |
| 02    | `GET /ready` всё OK                       | Postgres/Redis не поднялись; миграции упали       | `argus-backend.log`, `postgres.log`      |
| 03    | `POST /api/v1/scans` → 201                | API-ключ не принят; Pydantic валидация            | `argus-backend.log`                      |
| 04    | Скан → `completed`                        | Таймаут (увеличить `E2E_SCAN_TIMEOUT_SECONDS`); упал в `failed` | `argus-celery.log`            |
| 05    | `POST /generate-all` → 202                | Бэкенд не нашёл скан                              | `argus-backend.log`                      |
| 06    | `verify_reports.py` — N отчётов в `ready` | Воркер не справился с генерацией; шаблон сломан   | `argus-celery.log`, `verify_reports.json` |
| 07    | `verify_oast.py`                          | Если `status='no_oast_in_scope'` — это НЕ ошибка  | `verify_oast.json`                       |
| 08    | `verify_cosign.sh`                        | Cosign не установлен (skip); подпись недействительна | `verify_cosign.json`                  |
| 09    | `verify_prometheus.py`                    | Метрики не экспортированы; Prometheus не скрейпит | `prometheus.log`, `verify_prometheus.json` |
| 10    | Финальные ассерты findings ≥ MIN          | Juice Shop недоступен; активный сканер заблокирован | `juice-shop.log`, `argus-celery.log`   |
| 11    | `docker compose down`                     | Стек завис; volume locked                         | `docker ps -a`                           |
| 12    | `archive_results.sh` создал `.tar.gz`     | Нет места на диске                                | `df -h`                                  |

---

## 6. Pytest-режим (опционально, для разработчиков)

Файлы `backend/tests/integration/e2e/test_e2e_*.py` дублируют контракт
обёртки на уровне тестов. По умолчанию они **скипаются** (auto-classifier
помечает их `requires_docker`). Чтобы запустить только e2e-сюиту — стек
должен быть уже поднят:

```bash
bash scripts/e2e_full_scan.sh   # в одном терминале (или E2E_KEEP_STACK=1)
# в другом терминале:
cd backend
E2E_BACKEND_URL=http://localhost:8000 \
E2E_TARGET=http://juice-shop:3000 \
E2E_TOKEN=e2e-api-key-not-for-production \
pytest -m requires_docker_e2e tests/integration/e2e -v
```

Все тесты sharing-fixture-aware: сканы создаются один раз на модуль.

---

## 7. CI-интеграция

Workflow: `.github/workflows/e2e-full-scan.yml`.

Триггеры:
* `schedule: cron "0 2 * * *"` — ежедневно 02:00 UTC.
* `workflow_dispatch` — ручной запуск с инпутами (`target`, `scan_mode`,
  `min_findings`, `expected_reports`, `keep_stack`).
* `push` на `main`, если изменились `infra/docker-compose.e2e.yml`,
  `scripts/e2e_full_scan.*`, `scripts/e2e/**`, или сам workflow.

Артефакт `e2e-results-<run_id>` хранится 30 дней. Если прогон упал —
job summary автоматически содержит `summary.json` и хвосты логов
проблемных сервисов (для быстрой триажа без скачивания архива).

---

## 8. Ограничения и известные TODO

* **18 vs 12 отчётов.** Бэлог требует 18 отчётов (3 уровня × 6 форматов).
  API сейчас генерирует 12 (3 × 4). SARIF и JUNIT-генераторы существуют, но
  не выведены в `POST /generate-all`. До закрытия задачи на API мы выставляем
  `E2E_EXPECTED_REPORTS=12` по умолчанию. Поднимите до `18` после
  соответствующего PR.
* **OAST в Juice Shop.** Juice Shop не делает out-of-band callbacks по
  умолчанию. Phase 07 по умолчанию завершается со `status='no_oast_in_scope'`,
  что **не считается падением**. Для строгой проверки направьте сканер на
  свой собственный stage с искусственным OAST-эндпоинтом и установите
  `E2E_REQUIRE_OAST=1`.
* **Cosign-проверка sandbox-образов.** Требует, чтобы образы были подписаны
  через GitHub OIDC + Sigstore. Если запускаете локально вне CI и образы
  не подписаны — Phase 08 завершится со `status='no_signatures_found'`
  (предупреждение, не ошибка).

---

## 9. Безопасность

* Все логи и артефакты **не содержат PII**, секретов или stack trace —
  ARGUS использует structured logging (`backend/src/core/logging.py`) с
  redacted-фильтрами.
* `E2E_TOKEN` — выделенный CI-only ключ, не использовать в продакшене.
* Volume-маунты `postgres-data`, `redis-data`, `minio-data` — локальные
  Docker volumes, удаляются `docker compose down -v` в Phase 11.
* Сетевой контур замкнут: `juice-shop` доступен только из network
  `argus-e2e` и наружу через port-mapping для удобства ручной отладки.

---

## 10. Контакты

Изменения в e2e-инфраструктуре требуют ревью владельца **ARG-047**
(см. `.claude/state/orchestration_status.json`). При каскадных падениях
ночного прогона — открыть incident в трекере с тегом `arg-047/flake`
и приложить артефакт `e2e-results-<run_id>`.

---

## 11. Мишени для быстрого Playwright-smoke (multi-target matrix)

Полный капстоун ARG-047 по-прежнему использует только **OWASP Juice Shop** внутри
`infra/docker-compose.e2e.yml`. Отдельно доступен **лёгкий матричный прогон**
против трёх изолированных lab-контейнеров (Juice Shop, DVWA, WebGoat) без ARGUS-стека:

| Файл | Назначение |
|------|------------|
| `infra/docker-compose.vuln-targets.yml` | Профили `juice-shop`, `dvwa`, `webgoat`; образы с pin `tag@sha256`; по одному профилю за раз (порты на localhost не конфликтуют). |
| `infra/e2e-vuln-targets.md` | Краткий runbook (локальный запуск и env-переменные). |
| `Frontend/tests/e2e/vuln-targets/` | Playwright smoke: главная/login в зависимости от `E2E_VULN_TARGET`. |
| `.github/workflows/e2e-vuln-target-smoke.yml` | Matrix `target: [juice-shop, dvwa, webgoat]`; для `dvwa` и `webgoat` включён **continue-on-error** (возможные флаки сторонних образов), для `juice-shop` — строгий gate. |

Переменные для локального/CI запуска smoke:

| Переменная | Пример | Описание |
|------------|--------|----------|
| `E2E_VULN_TARGET` | `juice-shop` \| `dvwa` \| `webgoat` | Выбор сценария в спеке. |
| `E2E_VULN_BASE_URL` | `http://127.0.0.1:40080` | Базовый URL поднятого контейнера. |
| `PLAYWRIGHT_NO_SERVER` | `1` | Не поднимать Next dev server при прогоне только vuln-smoke. |
| `E2E_WEBGOAT_USERNAME` / `E2E_WEBGOAT_PASSWORD` | из CI env | Только для шага логина WebGoat; не класть в репозиторий. |

Команда в каталоге `Frontend`: `npm run test:e2e:vuln-smoke` (требуется `E2E_VULN_BASE_URL` — см. `Frontend/playwright.config.ts`, проект `vuln-smoke`).

---

## 12. Admin console E2E

Playwright-спека админки Next.js: навигация, запреты для роли operator, страницы tenants/scans/scopes, LLM-gate. Конфиг и дефолты dev-сервера для прогона — в [`Frontend/playwright.config.ts`](../Frontend/playwright.config.ts).

### Команда

```bash
cd Frontend && npx playwright test tests/e2e/admin-console.spec.ts
```

(Windows PowerShell: `cd Frontend; npx playwright test tests/e2e/admin-console.spec.ts`.)

### Переменные окружения

| Переменная | Назначение |
|------------|------------|
| `ADMIN_API_KEY` | **Рекомендуется для admin E2E:** должен совпадать с `ADMIN_API_KEY` бэкенда. Задайте в `Frontend/.env.local` (или в shell перед запуском). Конфиг Playwright подмешивает `.env` / `.env.local` в `process.env` до старта `webServer`, иначе Server Actions логируют «Admin service is temporarily unavailable» при каждом вызове `listTenants` / LLM summary. |
| `BACKEND_URL` / `NEXT_PUBLIC_BACKEND_URL` | База FastAPI для admin server actions (см. `Frontend/.env.example`). |
| `NEXT_PUBLIC_ADMIN_DEV_ROLE` | Роль по умолчанию при старте dev-сервера через `webServer` Playwright (дефолт в конфиге — `admin`, чтобы guards пропускали tenants/LLM). Переопределяйте в CI при необходимости. |
| (в тестах) `sessionStorage` | Сценарии **operator** выставляют ключ `argus.admin.role` в `sessionStorage` до навигации (см. `AdminAuthContext` и комментарий в спеке). |
| `E2E_TENANT_ID` | Опциональный UUID для сценария `/admin/tenants/{id}/scopes`; если не задан — соответствующий тест пропускается. См. также `Frontend/.env.example`. |

### Бэкенд и CRUD

При **поднятом** API и заданных `ADMIN_API_KEY` + `BACKEND_URL` пропадают ошибки в логах dev-сервера от admin server actions; тесты по-прежнему могут проходить и без бэкенда (пустые состояния / сообщения в UI), но шум и лишние stack traces в консоли лучше убрать через `.env.local`.

Полный **CRUD / данные tenants & scans** требует согласованных **`ADMIN_API_KEY`** и **`BACKEND_URL`** с реальным инстансом API.

### Файлы

| Файл | Описание |
|------|----------|
| `Frontend/tests/e2e/admin-console.spec.ts` | Спека админ-консоли. |
| `Frontend/playwright.config.ts` | `webServer`, `NEXT_PUBLIC_ADMIN_DEV_ROLE`, базовый URL. |
