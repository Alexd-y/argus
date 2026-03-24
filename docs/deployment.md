# ARGUS Deployment

**Version:** 0.1  
**Source:** `infra/docker-compose.yml`, `backend/Dockerfile`, `.env.example`, `.github/workflows/ci.yml`

---

## 1. Overview

ARGUS разворачивается через Docker Compose. Backend, PostgreSQL, Redis, MinIO и опционально Celery worker и sandbox объединены в единый стек.

**Публичный hostname и ingress:** указывайте как целевой сервис только внутренние адреса стека — `http://nginx:80` (предпочтительно) или `http://backend:8000` в сети Compose. Не задавайте произвольные внешние URL как destination туннеля или обратного прокси: клиент должен подключаться к процессу внутри compose. **Nginx** удобнее как единая точка входа (маршрутизация, заголовки, **rate limiting**).

---

## 2. Docker Compose

**Файл:** `infra/docker-compose.yml`

**Запуск:**

```bash
docker compose -f infra/docker-compose.yml up
```

### 2.1 Сервисы

| Сервис | Образ/сборка | Порт | Назначение |
|--------|--------------|------|------------|
| postgres | pgvector/pgvector:pg15 | 5432 | PostgreSQL с pgvector |
| minio | minio/minio:latest | 9000, 9001 | Object storage (S3-совместимый) |
| redis | redis:7-alpine | 6379 | Redis (кеш, Celery broker) |
| backend | build: backend | 8000 | FastAPI приложение |
| sandbox | build: sandbox | — | Контейнер для выполнения инструментов (profile: tools) |
| celery-worker | build: backend | — | Celery worker (profile: tools) |

### 2.2 Volumes

| Volume | Сервис | Назначение |
|--------|--------|------------|
| argus_postgres_data | postgres | Данные PostgreSQL |
| argus_minio_data | minio | Данные MinIO |
| argus_redis_data | redis | Данные Redis (appendonly) |

### 2.3 Profiles

- **По умолчанию:** postgres, minio, redis, backend
- **`--profile tools`:** дополнительно sandbox, celery-worker

```bash
docker compose -f infra/docker-compose.yml --profile tools up
```

---

## 3. Переменные окружения

### 3.1 Backend

| Переменная | Описание | По умолчанию |
|------------|----------|--------------|
| DATABASE_URL | PostgreSQL (asyncpg) | `postgresql://argus:argus@postgres:5432/argus` |
| REDIS_URL | Redis | `redis://redis:6379/0` |
| MINIO_ENDPOINT | MinIO endpoint | `minio:9000` |
| MINIO_ACCESS_KEY | MinIO access key | `argus` |
| MINIO_SECRET_KEY | MinIO secret key | `argussecret` |
| MINIO_BUCKET | Основной bucket (артефакты, не отчёты) | `argus` |
| MINIO_REPORTS_BUCKET | Bucket для экспортов отчётов (presigned/download) | `argus-reports` |
| JWT_SECRET | Секрет для JWT | — (обязательно в prod) |
| LOG_LEVEL | Уровень логирования | `INFO` |

### 3.2 PostgreSQL

| Переменная | По умолчанию |
|------------|--------------|
| POSTGRES_USER | argus |
| POSTGRES_PASSWORD | argus |
| POSTGRES_DB | argus |
| POSTGRES_PORT | 5432 |

### 3.3 MinIO

| Переменная | По умолчанию |
|------------|--------------|
| MINIO_ACCESS_KEY | argus |
| MINIO_SECRET_KEY | argussecret |
| MINIO_PORT | 9000 |
| MINIO_CONSOLE_PORT | 9001 |

### 3.4 Redis

| Переменная | По умолчанию |
|------------|--------------|
| REDIS_PORT | 6379 |

### 3.5 LLM-провайдеры (опционально)

| Переменная | Провайдер |
|------------|-----------|
| OPENAI_API_KEY | OpenAI |
| DEEPSEEK_API_KEY | DeepSeek |
| OPENROUTER_API_KEY | OpenRouter |
| GOOGLE_API_KEY | Gemini |
| KIMI_API_KEY | Kimi |
| PERPLEXITY_API_KEY | Perplexity |

### 3.6 Пример .env

Скопировать `backend/.env.example` в `.env` и задать значения:

```bash
# Database
DATABASE_URL=postgresql+asyncpg://argus:argus@localhost:5432/argus

# Tenant
DEFAULT_TENANT_ID=00000000-0000-0000-0000-000000000001

# Auth (prod)
JWT_SECRET=<secure-random-string>
JWT_EXPIRY=15m
JWT_ALGORITHM=HS256

# LLM (хотя бы один для AI)
OPENAI_API_KEY=sk-...

# Redis & Celery
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=

# MinIO
MINIO_ENDPOINT=localhost:9000
MINIO_ACCESS_KEY=argus
MINIO_SECRET_KEY=argussecret
MINIO_BUCKET=argus
MINIO_REPORTS_BUCKET=argus-reports
```

### 3.7 CORS и фронтенд

| Переменная | Назначение |
|------------|------------|
| `CORS_ORIGINS` | Список через запятую допустимых origin для браузера |
| `VERCEL_FRONTEND_URL` | URL приложения на Vercel (без завершающего `/`), добавляется к списку CORS вместе с localhost для разработки |

Бэкенд разрешает методы `GET`, `POST`, `OPTIONS` и заголовки `Content-Type`, `Authorization`; `allow_credentials=True` для совместимости с будущей cookie-сессией.

---

## 4. Cloudflare Tunnel (опционально)

Публичный HTTPS-доступ к стеку за NAT без открытия портов на роутере: трафик идёт из Cloudflare в контейнер **cloudflared**, который подключается к **nginx** (или напрямую к backend) во внутренней сети Compose.

### 4.1 Запуск

В `infra/docker-compose.yml` сервис `cloudflared` включён в **profile `tunnel`**:

```bash
cd infra
docker compose --profile tunnel up -d
```

В `infra/.env` задайте `CLOUDFLARE_TUNNEL_TOKEN` (см. ниже).

### 4.2 Получение `CLOUDFLARE_TUNNEL_TOKEN` (Cloudflare Zero Trust)

Токен — это JWT из вашей панели Zero Trust; подставлять «выдуманный» токен нельзя.

1. Откройте [Cloudflare Zero Trust](https://one.dash.cloudflare.com/).
2. Перейдите в **Networks** → **Tunnels**.
3. Создайте туннель (**Create a tunnel**) или выберите существующий.
4. Для типа **Cloudflared** задайте имя туннеля и продолжите мастер установки.
5. На шаге установки коннектора выберите **Docker** (или **Install connector**) и найдите команду вида `cloudflared tunnel run --token <JWT>`.
6. Скопируйте только значение JWT после `--token` (длинная строка) в `CLOUDFLARE_TUNNEL_TOKEN` в файле `infra/.env` (файл в `.gitignore`, секреты в репозиторий не коммитить).
7. Запускайте стек с профилем только после того, как переменная задана: `docker compose --profile tunnel up` из каталога `infra/`.
8. В настройках туннеля добавьте **Public Hostname**: **Service type** HTTP, **URL** `http://nginx:80` (или `http://backend:8000` при прямом доступе к API).

Если запустить профиль `tunnel` с пустым токеном, `cloudflared` завершится с сообщением вроде: `"cloudflared tunnel run" requires the ID or name of the tunnel`.

### 4.3 Связка с Vercel

- В проекте Next.js задайте **`NEXT_PUBLIC_BACKEND_URL`** на публичный URL бэкенда — тот же hostname, что настроен в туннеле (например `https://api.example.com`), либо URL корня, если nginx проксирует `/api/v1` на backend.
- **`VERCEL_FRONTEND_URL`** на бэкенде должен совпадать с URL приложения Vercel (например `https://your-app.vercel.app`), чтобы CORS пропускал запросы браузера с прод-фронта.

**Без своего домена в Cloudflare** (нет зоны DNS / недоступен Public hostname): используйте временный публичный URL — **Quick Tunnel** (`cloudflared tunnel --url …`) или **ngrok**. Пошагово: [`docs/vercel-local-backend.md`](vercel-local-backend.md).

Локальная разработка: `NEXT_PUBLIC_BACKEND_URL=http://localhost:8000` и фронт на `localhost:5000` — localhost уже входит в список CORS по умолчанию.

---

## 5. Backend Dockerfile

**Путь:** `backend/Dockerfile`

```dockerfile
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Сборка:**

```bash
docker build -t argus-backend backend
```

---

## 6. CI/CD

**Файл:** `.github/workflows/ci.yml`

### 6.1 Триггеры

- Push в `main`, `develop`
- Pull request в `main`, `develop`

### 6.2 Jobs

| Job | Назначение |
|-----|------------|
| lint | Ruff, Black (backend) |
| test | pytest с PostgreSQL и Redis (services) |
| security | Bandit, Safety |
| build | Docker build backend (после lint, test, security) |

### 6.3 Переменные CI

- `DATABASE_URL`, `REDIS_URL`, `CELERY_BROKER_URL` — для тестов
- `JWT_SECRET`, `DEFAULT_TENANT_ID` — для прогона приложения

### 6.4 Тесты

```yaml
- alembic upgrade head
- pytest tests -v --tb=short
```

### 6.5 Сборка образа

- `docker/build-push-action` с `push: false`, `load: true`
- Тег: `argus-backend:ci`
- Кэш: GitHub Actions cache

---

## 7. Миграции БД

Перед первым запуском или обновлением:

```bash
cd backend
alembic upgrade head
```

В Docker Compose backend зависит от `postgres` (condition: service_healthy), миграции выполняются при старте приложения или вручную в контейнере.

---

## 8. Health Checks

- **PostgreSQL:** `pg_isready -U $POSTGRES_USER -d $POSTGRES_DB`
- **Redis:** `redis-cli ping`
- **Backend:** `GET /api/v1/health`, `GET /api/v1/ready`

---

## 9. See Also

For complete startup instructions including all 3 deployment scenarios, environment setup, and API key placement, see **[RUNNING.md](./RUNNING.md)** — the definitive guide for:
- Docker full stack setup
- Local development setup (backend + frontend)
- Docker backend + local frontend
- Troubleshooting common issues
