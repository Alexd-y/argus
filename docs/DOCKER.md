# ARGUS Docker Configuration & Build

**Версия:** 0.2  
**Последнее обновление:** 2026-03-19  
**Статус:** ✅ Stable (fixed COPY app/, verified with tests)

---

## 📋 Содержание

1. [Обзор](#обзор)
2. [Структура Docker](#структура-docker)
3. [Backend Dockerfile (Multi-stage)](#backend-dockerfile-multi-stage)
4. [Worker Dockerfile](#worker-dockerfile)
5. [Docker Compose Configuration](#docker-compose-configuration)
6. [Сборка и запуск](#сборка-и-запуск)
7. [Исправления и обновления (v0.2)](#исправления-и-обновления-v02)
8. [Проверка конфигурации](#проверка-конфигурации)
9. [Troubleshooting](#troubleshooting)

---

## Обзор

ARGUS использует **многоэтапную сборку Docker** для оптимизации размера образов и безопасности:

| Компонент | Тип | Назначение |
|-----------|-----|-----------|
| **Backend** | Multi-stage (builder + runtime) | FastAPI приложение (uvicorn + gunicorn) |
| **Worker** | From backend image | Celery worker для асинхронных задач |
| **Infrastructure** | docker-compose | PostgreSQL, Redis, MinIO, Backend, Worker |

**Ключевое улучшение в v0.2:** Добавлена инструкция `COPY app/ ./app/` для копирования директорий **schemas** и **prompts**, которые требуются для работы LLM интеграции и обработки данных.

---

## Структура Docker

### Иерархия файлов

```
ARGUS/
├── infra/
│   ├── docker-compose.yml          # Основная конфигурация
│   ├── docker-compose.dev.yml      # Overrides для разработки
│   ├── .env.example                # Шаблон переменных
│   ├── backend/
│   │   └── Dockerfile              # Backend multi-stage build ✅ UPDATED
│   └── worker/
│       └── Dockerfile              # Worker (FROM backend)
└── backend/
    ├── main.py                     # Точка входа
    ├── requirements.txt            # Python зависимости
    ├── src/                        # Backend код
    ├── app/                        # ✅ Schemas & Prompts (обязательно!)
    │   ├── schemas/
    │   │   ├── recon/
    │   │   ├── threat_modeling/
    │   │   └── vulnerability_analysis/
    │   └── prompts/
    │       ├── threat_modeling_prompts.py
    │       └── vulnerability_analysis_prompts.py
    ├── alembic/                    # Database migrations
    ├── alembic.ini
    └── tests/
        └── test_docker_build.py    # ✅ NEW: Docker config verification
```

---

## Backend Dockerfile (Multi-stage)

**Файл:** `infra/backend/Dockerfile`

```dockerfile
# ARGUS Backend — production multi-stage build
# Builder: install deps | Runtime: minimal image, gunicorn+uvicorn workers
# Build context: ARGUS/backend (set in docker-compose)

# --- Builder stage ---
FROM python:3.12-slim AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Runtime stage ---
FROM python:3.12-slim AS runtime

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Runtime deps (nmap, dnsutils, etc. for recon)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap dnsutils whois curl net-tools \
    && rm -rf /var/lib/apt/lists/*

# Copy application
COPY main.py .
COPY src/ ./src/
COPY app/ ./app/
COPY alembic.ini .
COPY alembic/ ./alembic/

# Non-root user
RUN adduser --system --group --no-create-home appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Gunicorn + Uvicorn workers (worker overrides with celery in compose)
CMD ["gunicorn", "main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "-b", "0.0.0.0:8000"]
```

### Особенности

| Этап | Описание | Зачем |
|------|---------|-------|
| **Builder** | Installs `requirements.txt` | Разделение зависимостей от кода |
| **Copy from builder** | `/usr/local/lib/python3.12/site-packages` | Переиспользование установленных пакетов |
| **Runtime deps** | `nmap`, `dnsutils`, `whois`, `curl`, `net-tools` | Для реконнекции и сканирования сервисов |
| **COPY app/** | ✅ Schemas & Prompts | **Обязательно! Используется LLM и обработкой данных** |
| **Non-root user** | `appuser` | Security best practice |

---

## Worker Dockerfile

**Файл:** `infra/worker/Dockerfile`

```dockerfile
# ARGUS Celery Worker — inherits from backend image
FROM argus-backend:latest

# Override entrypoint with celery worker
CMD ["celery", "-A", "src.celery_app", "worker", "-l", "info", "--concurrency=2"]
```

**Назначение:** Асинхронная обработка задач (сканирование, анализ, отчёты).

---

## Docker Compose Configuration

**Файл:** `infra/docker-compose.yml`

```yaml
version: "3.9"

services:
  postgres:
    image: pgvector/pgvector:pg15-latest
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-argus}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-argus}
      POSTGRES_DB: ${POSTGRES_DB:-argus}
    ports:
      - "${POSTGRES_PORT:-5432}:5432"
    volumes:
      - argus_postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U argus"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "${REDIS_PORT:-6379}:6379"
    volumes:
      - argus_redis_data:/data
    command: redis-server --appendonly yes
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  minio:
    image: minio/minio:latest
    environment:
      MINIO_ROOT_USER: ${MINIO_ACCESS_KEY:-argus}
      MINIO_ROOT_PASSWORD: ${MINIO_SECRET_KEY:-argussecret}
    ports:
      - "${MINIO_PORT:-9000}:9000"
      - "${MINIO_CONSOLE_PORT:-9001}:9001"
    volumes:
      - argus_minio_data:/data
    command: server /data --console-address ":9001"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
      interval: 10s
      timeout: 5s
      retries: 5

  backend:
    build:
      context: ../backend
      dockerfile: ../infra/backend/Dockerfile
    image: argus-backend:${VERSION:-latest}
    container_name: argus-backend
    environment:
      DATABASE_URL: postgresql://argus:argus@postgres:5432/argus
      REDIS_URL: redis://redis:6379/0
      MINIO_ENDPOINT: minio:9000
      MINIO_ACCESS_KEY: ${MINIO_ACCESS_KEY:-argus}
      MINIO_SECRET_KEY: ${MINIO_SECRET_KEY:-argussecret}
      PYTHONPATH: /app
    ports:
      - "8000:8000"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
      minio:
        condition: service_healthy
    volumes:
      - ../backend:/app  # Dev only; remove in production
    restart: unless-stopped

  worker:
    build:
      context: ../backend
      dockerfile: ../infra/worker/Dockerfile
    image: argus-worker:${VERSION:-latest}
    container_name: argus-worker
    environment:
      DATABASE_URL: postgresql://argus:argus@postgres:5432/argus
      REDIS_URL: redis://redis:6379/0
      CELERY_BROKER_URL: redis://redis:6379/1
    depends_on:
      - backend
    profiles:
      - tools
    restart: unless-stopped

volumes:
  argus_postgres_data:
    driver: local
  argus_redis_data:
    driver: local
  argus_minio_data:
    driver: local
```

### Сервисы

| Сервис | Порт (Dev) | Профиль | Назначение |
|--------|-----------|---------|-----------|
| **postgres** | 5432 | default | PostgreSQL с pgvector |
| **redis** | 6379 | default | Кеш, Celery broker |
| **minio** | 9000, 9001 | default | S3-совместимое хранилище |
| **backend** | 8000 | default | FastAPI (8 workers) |
| **worker** | — | `tools` | Celery worker для async tasks |

### Profiles

```bash
# Базовый стек (postgres, redis, minio, backend)
docker compose -f infra/docker-compose.yml up

# С worker'ом для async обработки
docker compose -f infra/docker-compose.yml --profile tools up
```

---

## Сборка и запуск

### Подготовка

```powershell
cd ARGUS
```

Опционально, скопировать `.env`:

```powershell
copy infra\.env.example infra\.env
```

### Build Backend

```bash
# Сборка backend образа
docker build -f infra/backend/Dockerfile -t argus-backend:latest backend/

# Или через docker-compose
docker compose -f infra/docker-compose.yml build backend
```

**Проверка:**

```bash
docker images | grep argus-backend
```

### Запуск

**Production (minimal):**

```bash
docker compose -f infra/docker-compose.yml up -d
```

**Development (с пробросом портов):**

```bash
docker compose -f infra/docker-compose.yml -f infra/docker-compose.dev.yml up -d
```

**With Celery Worker:**

```bash
docker compose -f infra/docker-compose.yml --profile tools up -d
```

### Проверка сервисов

```bash
# Backend health check
curl http://localhost:8000/api/v1/health

# MinIO Console
open http://localhost:9001

# Docker stats
docker stats
```

### Остановка

```bash
docker compose -f infra/docker-compose.yml down

# С удалением volume'ов
docker compose -f infra/docker-compose.yml down -v
```

---

## Исправления и обновления (v0.2)

### ✅ Добавлено: `COPY app/ ./app/`

**Проблема (v0.1):** Backend Dockerfile не копировал директорию `backend/app/`, содержащую:
- **Schemas** для AI интеграции (vulnerability analysis, threat modeling, recon)
- **Prompts** для LLM обработки

**Решение (v0.2):**

```dockerfile
# Line 37 in infra/backend/Dockerfile
COPY app/ ./app/
```

**Структура `backend/app/`:**

```
backend/app/
├── schemas/
│   ├── __init__.py
│   ├── recon/
│   │   ├── __init__.py
│   │   ├── stage1.py
│   │   └── stage3_readiness.py
│   ├── threat_modeling/
│   │   ├── __init__.py
│   │   ├── ai_tasks.py
│   │   └── schemas.py
│   └── vulnerability_analysis/
│       ├── __init__.py
│       ├── ai_tasks.py
│       ├── exploitation_candidates.py
│       └── ... (8+ more files)
└── prompts/
    ├── __init__.py
    ├── threat_modeling_prompts.py
    └── vulnerability_analysis_prompts.py
```

### Тестирование новой конфигурации

**Новый тестовый файл:** `backend/tests/test_docker_build.py`

```bash
pytest backend/tests/test_docker_build.py -v
```

**Результаты (19 tests passed ✅):**

- ✅ Dockerfile exists and valid
- ✅ COPY main.py
- ✅ COPY src/
- ✅ **COPY app/** (schemas, prompts)
- ✅ COPY alembic
- ✅ COPY requirements.txt
- ✅ backend/app/ directory exists
- ✅ backend/src/ directory exists
- ✅ backend/main.py exists
- ✅ backend/requirements.txt exists
- ✅ worker Dockerfile exists
- ✅ worker FROM backend image
- ✅ worker runs celery
- ✅ docker-compose.yml exists
- ✅ docker-compose.yml is valid YAML
- ✅ backend has build section
- ✅ backend build context points to backend
- ✅ worker has build section
- ✅ backend and worker images defined

---

## Проверка конфигурации

### 1. Validate Dockerfile

```bash
# Использовать Hadolint (если установлен)
hadolint infra/backend/Dockerfile

# Или build и посмотреть ошибки
docker build -f infra/backend/Dockerfile backend/ 2>&1 | grep -i "error\|warning"
```

### 2. Validate docker-compose.yml

```bash
docker compose -f infra/docker-compose.yml config
```

### 3. Run Tests

```bash
cd backend
pytest tests/test_docker_build.py -v --tb=short
```

### 4. Build & Inspect

```bash
# Сборка
docker build -f infra/backend/Dockerfile -t argus-backend:test backend/

# Inspect layers
docker history argus-backend:test

# Inspect filesystem
docker run --rm argus-backend:test ls -la /app/

# Check PYTHONPATH
docker run --rm argus-backend:test python -c "import sys; print('\\n'.join(sys.path))"
```

### 5. Runtime Check

```bash
# Запуск backend
docker run -it --rm \
  -e PYTHONPATH=/app \
  -p 8000:8000 \
  argus-backend:test \
  python -c "import app.schemas; import app.prompts; print('✅ app module is accessible')"
```

---

## Troubleshooting

### ❌ `COPY app/ ./app/` fails: directory not found

**Причина:** Backend build context некорректный или `app/` нет в нём.

**Решение:**

```bash
# Проверить, что app/ существует в backend/
ls -la ARGUS/backend/app/

# Проверить build context в docker-compose.yml
grep -A 3 "build:" infra/docker-compose.yml | grep -A 2 "backend"

# Должно быть:
# context: ../backend  (relative to infra/)
# или абсолютный путь
```

### ❌ Backend не может импортировать `app.schemas`

**Причина:** `PYTHONPATH` не установлен или `app/` не скопирован.

**Решение:**

1. Проверить `PYTHONPATH=/app` в Dockerfile (строка 23)
2. Проверить `COPY app/ ./app/` присутствует (строка 37)
3. Пересоздать образ:

```bash
docker compose -f infra/docker-compose.yml build --no-cache backend
```

### ❌ Docker Compose build fails: requirements not found

**Причина:** `requirements.txt` не в контексте.

**Решение:**

```bash
# Проверить наличие
ls backend/requirements.txt

# Проверить контекст в compose
cat infra/docker-compose.yml | grep -A 5 "backend:"
```

### ⚠️ Build очень медленный

**Решение:**

```bash
# Use BuildKit (faster)
export DOCKER_BUILDKIT=1
docker build -f infra/backend/Dockerfile -t argus-backend:latest backend/

# Или в docker-compose
DOCKER_BUILDKIT=1 docker compose -f infra/docker-compose.yml build
```

### ⚠️ Образ слишком большой

**Проверить:**

```bash
docker images | grep argus

# Посмотреть слои
docker history argus-backend:latest --no-trunc --human | head -20
```

**Оптимизация:**

- Объединить RUN команды: `RUN ... && apt-get clean`
- Удалить pip cache: `pip install --no-cache-dir`
- Использовать `.dockerignore`

---

## Итоги (v0.2)

| Категория | Статус |
|-----------|--------|
| **Backend Dockerfile** | ✅ Multi-stage, optimized |
| **COPY app/ (schemas, prompts)** | ✅ Fixed & verified |
| **Worker Dockerfile** | ✅ FROM backend |
| **docker-compose.yml** | ✅ Valid, tested |
| **Tests** | ✅ 19 passed |
| **CI/CD** | ✅ Integrated |

**Следующие шаги:**

1. Deploy в staging/production
2. Мониторить логи backend и worker
3. Оптимизировать образы по размеру (если нужно)
4. Настроить secrets management для prod переменных

---

## Ссылки

- [RUNNING.md](./RUNNING.md) — Полный гайд по запуску
- [deployment.md](./deployment.md) — Детали развёртывания
- [backend/tests/test_docker_build.py](../backend/tests/test_docker_build.py) — Тесты конфигурации
- [infra/docker-compose.yml](../infra/docker-compose.yml) — Compose конфигурация
- [infra/backend/Dockerfile](../infra/backend/Dockerfile) — Backend Dockerfile

