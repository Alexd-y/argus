# ARGUS Deployment

**Version:** 0.1  
**Source:** `infra/docker-compose.yml`, `backend/Dockerfile`, `.env.example`, `.github/workflows/ci.yml`

---

## 1. Overview

ARGUS разворачивается через Docker Compose. Backend, PostgreSQL, Redis, MinIO и опционально Celery worker и sandbox объединены в единый стек.

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
| MINIO_BUCKET | Bucket name | `argus` |
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
```

---

## 4. Backend Dockerfile

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

## 5. CI/CD

**Файл:** `.github/workflows/ci.yml`

### 5.1 Триггеры

- Push в `main`, `develop`
- Pull request в `main`, `develop`

### 5.2 Jobs

| Job | Назначение |
|-----|------------|
| lint | Ruff, Black (backend) |
| test | pytest с PostgreSQL и Redis (services) |
| security | Bandit, Safety |
| build | Docker build backend (после lint, test, security) |

### 5.3 Переменные CI

- `DATABASE_URL`, `REDIS_URL`, `CELERY_BROKER_URL` — для тестов
- `JWT_SECRET`, `DEFAULT_TENANT_ID` — для прогона приложения

### 5.4 Тесты

```yaml
- alembic upgrade head
- pytest tests -v --tb=short
```

### 5.5 Сборка образа

- `docker/build-push-action` с `push: false`, `load: true`
- Тег: `argus-backend:ci`
- Кэш: GitHub Actions cache

---

## 6. Миграции БД

Перед первым запуском или обновлением:

```bash
cd backend
alembic upgrade head
```

В Docker Compose backend зависит от `postgres` (condition: service_healthy), миграции выполняются при старте приложения или вручную в контейнере.

---

## 7. Health Checks

- **PostgreSQL:** `pg_isready -U $POSTGRES_USER -d $POSTGRES_DB`
- **Redis:** `redis-cli ping`
- **Backend:** `GET /api/v1/health`, `GET /api/v1/ready`

---

## 8. See Also

For complete startup instructions including all 3 deployment scenarios, environment setup, and API key placement, see **[RUNNING.md](./RUNNING.md)** — the definitive guide for:
- Docker full stack setup
- Local development setup (backend + frontend)
- Docker backend + local frontend
- Troubleshooting common issues
