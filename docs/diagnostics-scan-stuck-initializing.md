# Диагностика: Скан застрял на "Initializing" (0%)

## Симптомы

- Frontend: "Scan in Progress", 0%, "Initializing"
- В консоли браузера: `SES Removing unpermitted intrinsics` (moz-extension / lockdown-install.js) — это **расширение браузера** (Kaspersky/безопасность), **не код приложения**

---

## Архитектура flow

```
POST /api/v1/scans
    → Backend создаёт Scan (status=queued, phase=init, progress=0)
    → scan_phase_task.delay(...) — задача в Redis
    → Celery worker подхватывает задачу
    → run_scan_state_machine() обновляет phase/progress в БД
    → Frontend: SSE /scans/:id/events или polling GET /scans/:id
```

**Если Celery worker не запущен** — задача остаётся в очереди, скан навсегда в `init`/0%.

---

## Шаг 1: Проверка Backend

```powershell
# Health (базовый)
curl http://localhost:5000/api/v1/health

# Ожидаемо: {"status":"ok","version":"0.1.0"}

# Readiness (DB, Redis, MinIO)
curl http://localhost:5000/api/v1/ready
```

Если backend не отвечает — запустить backend и проверить порт (по умолчанию 5000).

---

## Шаг 2: Проверка Celery worker

**Это наиболее вероятная причина.**

```powershell
# Проверить, запущен ли процесс celery
Get-Process -Name celery -ErrorAction SilentlyContinue

# Или через Docker (если используете compose)
docker ps | findstr celery
```

**Запуск Celery worker (локально):**

```powershell
cd ARGUS\backend
$env:REDIS_URL = "redis://localhost:6379/0"
$env:CELERY_BROKER_URL = "redis://localhost:6379/0"
celery -A src.celery_app worker -l INFO -Q argus.scans,argus.reports,argus.tools,argus.default
```

**Через Docker Compose (с profile tools):**

```powershell
docker compose -f infra/docker-compose.yml --profile tools up -d celery-worker
```

---

## Шаг 3: Проверка Redis

```powershell
# Локально
redis-cli ping
# Ожидаемо: PONG

# Через Docker
docker exec argus-redis redis-cli ping
```

---

## Шаг 4: Проверка flow (после создания скана)

1. Создать скан через UI.
2. В DevTools → Network найти запрос `POST .../scans` — должен вернуть `201` и `scan_id`.
3. Проверить статус:
   ```powershell
   curl "http://localhost:5000/api/v1/scans/<SCAN_ID>"
   ```
   Если `phase` остаётся `init` и `progress` 0 — Celery не обрабатывает задачу.

---

## Шаг 5: Расширение браузера (Kaspersky / SES)

- `SES Removing unpermitted intrinsics` — от **расширения**, не от ARGUS.
- В редких случаях расширения могут ломать `EventSource` или `fetch`.
- **Рекомендация:** отключить расширение для `localhost` или использовать **чистый профиль** браузера для тестов.

Frontend при падении SSE переключается на **polling** (GET /scans/:id каждые 3 с). Если polling работает — данные должны обновляться. Если Celery не запущен — polling всё равно покажет 0%, т.к. backend возвращает реальные данные из БД.

---

## Итоговая таблица причин

| Причина | Симптом | Решение |
|---------|---------|---------|
| **Celery worker не запущен** | Скан в init, 0% | Запустить `celery -A src.celery_app worker ...` |
| Redis недоступен | Backend может падать, задачи не доходят | Запустить Redis, проверить `REDIS_URL` |
| Backend не запущен | Нет ответа на /health | Запустить uvicorn |
| Расширение браузера | SSE может падать, polling обычно работает | Отключить для localhost / чистый профиль |

---

## Нужен ли рефакторинг?

**Скорее нет.** Архитектура корректна:

- POST → Celery → state machine → БД → SSE/polling
- Frontend при ошибке SSE переключается на polling
- Проблема обычно в **инфраструктуре** (Celery/Redis не запущены) или **расширении браузера**

**Опциональные улучшения** (не обязательны для исправления):

1. **Индикатор "Worker offline"** — если скан >N минут в init, показать подсказку "Проверьте, что Celery worker запущен".
2. **Логирование в backend** — при `scan_phase_task.delay()` логировать, что задача поставлена в очередь (для отладки).

---

## Конкретные шаги для пользователя

1. **Проверить backend:** `curl http://localhost:5000/api/v1/health`
2. **Проверить Redis:** `redis-cli ping`
3. **Запустить Celery worker** (если не запущен):
   ```powershell
   cd d:\Developer\Pentest_test\ARGUS\backend
   celery -A src.celery_app worker -l INFO -Q argus.scans,argus.reports,argus.tools,argus.default
   ```
4. **Повторить скан** — прогресс должен пойти (recon → threat_modeling → ...).
5. При необходимости — отключить Kaspersky/другие расширения для localhost или использовать чистый профиль браузера.
