# ARGUS Deployment

**Version:** 0.1  
**Source:** `infra/docker-compose.yml`, `infra/backend/Dockerfile`, `.env.example`, `.github/workflows/ci.yml`

---

## 1. Overview

ARGUS is deployed via Docker Compose. All services — backend, PostgreSQL, Redis, MinIO, worker, sandbox, nginx reverse proxy, MCP server, and optionally a Cloudflare tunnel — are part of a single stack.

**Public hostname / ingress:** always point tunnel or reverse proxy destinations to internal stack addresses — `http://nginx:80` (preferred) or `http://backend:8000` inside the Compose network. Do not set arbitrary external URLs as the tunnel destination; the client must connect to a process running inside the Compose stack. **Nginx** is the recommended single entry point (routing, security headers, rate limiting).

---

## 2. Docker Compose

**File:** `infra/docker-compose.yml`

**Start:**

```bash
docker compose -f infra/docker-compose.yml up
```

### 2.1 Services

| Service | Image / Build | Port (host default) | Purpose |
|---------|---------------|---------------------|---------|
| postgres | pgvector/pgvector:pg15 | 5432 (internal only) | PostgreSQL with pgvector extension |
| redis | redis:7-alpine | 6379 (internal only) | Cache and Celery broker |
| minio | minio/minio:RELEASE.* | 9000, 9001 (internal only) | S3-compatible object storage |
| backend | build: `infra/backend/Dockerfile` | 8000 (internal) | FastAPI application |
| worker | build: `infra/worker/Dockerfile` | — | Celery worker for scan tasks |
| sandbox | build: `sandbox/Dockerfile` | — | Kali-based container for pentest tool execution |
| nginx | nginx:alpine | 8080 (HTTP), 8443 (HTTPS) | Reverse proxy, rate limiting, security headers |
| mcp | MCP server container | 8765 | ARGUS MCP server (HTTP transport) |
| cloudflared | argus-cloudflared | — | Cloudflare tunnel (profile: tunnel) |

**Building the sandbox image:** build time depends heavily on Kali mirrors and CPU; the first build often takes **tens of minutes** (metapackages `kali-tools-*`, nuclei templates, dalfox/xsstrike). **`SANDBOX_PROFILE=extended`** adds **`kali-tools-passwords`** and typically increases image size by **1–3+ GB** compared to `standard` (see comments in `sandbox/Dockerfile`). Subsequent builds benefit from Docker layer caching.

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
| VA_AGGRESSIVE_SCAN | Подмешивать `aggressive_args` из `backend/data/tool_configs.json` в argv dalfox/ffuf/xsstrike/sqlmap/nuclei; **дополнительно** расширяет worker `custom_xss_poc` (больше payloads, cap 80) для script-context / alf.nu-style целей | `false` (в prod для XSS/SQLi можно `true`) |
| VA_CUSTOM_XSS_POC_ENABLED | После VA active scan запускать httpx reflected-XSS probe (встроенные script-context payloads + `data/payloads/xss_custom.txt` / `data/xss_payloads.txt` в образе; sandbox mirror `/opt/argus-payloads/`) | `true` |
| KAL_ALLOW_PASSWORD_AUDIT | Разрешить на сервере **hydra/medusa** через `POST /api/v1/tools/kal/run` при `category=password_audit` и `password_audit_opt_in=true` в теле запроса (двойной opt-in) | `false` |
| NMAP_RECON_CYCLE | Многофазный nmap в песочнице на recon (см. [scan-state-machine.md](./scan-state-machine.md)) при `SANDBOX_ENABLED=true` | `true` |
| NMAP_FULL_TCP | Добавить фазу `-p- -sV -O` (долго) | `false` |
| NMAP_UDP_TOP50 | Добавить UDP top-50 | `false` |
| NMAP_RECON_PHASE_TIMEOUT_SEC | Таймаут одной фазы nmap-цикла (сек) | `600` |
| SEARCHSPLOIT_ENABLED | Intel: searchsploit по строкам версий из recon | `true` |
| SEARCHSPLOIT_MAX_QUERIES | Лимит запросов searchsploit за прогон | `8` |
| TRIVY_ENABLED | Опциональный trivy fs-scan по собранным manifest'ам | `false` |
| HIBP_PASSWORD_CHECK_OPT_IN | Отчётность: проверка паролей через k-anonymity HIBP Pwned Passwords (без логирования plaintext) | `false` |
| VA_WHATWEB_TIMEOUT_SEC | Таймаут whatweb в VA active scan | `90` |
| VA_NIKTO_TIMEOUT_SEC | Таймаут nikto в VA active scan | `180` |
| VA_SSL_PROBE_TIMEOUT_SEC | Таймаут testssl/ssl probe в VA | `300` |
| VA_FEROX_TIME_LIMIT_SEC | Лимит времени feroxbuster (сек) | `90` |
| VA_FEROX_WORDLIST_MAX_LINES | Макс. строк словаря ferox в sandbox | `5000` |
| KAL_RECON_DNS_MAX_DOMAINS | Сколько apex-доменов обрабатывать в DNS recon sandbox | `1` |
| KAL_RECON_DNS_MAX_LINES | Верхняя граница строк subdomain-intel | `200` |

### 3.1a Профиль образа sandbox (`SANDBOX_PROFILE`)

Передаётся **build-arg** сервиса `sandbox` в `infra/docker-compose.yml` (по умолчанию `standard`).

| Значение | Состав (обзор) |
|----------|----------------|
| **standard** | `kali-linux-headless` + `kali-tools-top10`, `kali-tools-web`, `kali-tools-information-gathering`, `kali-tools-vulnerability` + явный список пакетов (nmap, nuclei, feroxbuster, testssl.sh, …) — см. `sandbox/Dockerfile` |
| **extended** | То же + метапакет **`kali-tools-passwords`** (тяжёлый граф зависимостей: john/hashcat и др.; больше размер образа и время сборки) |

Переменная **`INSTALL_MSF`** (опционально `true`) — отдельно подтягивает Metasploit (~1.5 GB+).

### 3.1b Recon pipeline (`RECON_*`)

Полный перечень с комментариями — **[`infra/.env.example`](../infra/.env.example)** (блок RECON-001 … RECON-008). Краткая таблица для Compose/backend/worker:

| Переменная | Назначение | Типичное значение |
|------------|------------|-------------------|
| `RECON_MODE` | `passive` \| `active` \| `full` | `full` |
| `RECON_PASSIVE_ONLY` | Принудительный passive | `false` |
| `RECON_ACTIVE_DEPTH` | Зарезервировано (глубина active) | `1` |
| `RECON_ENABLE_CONTENT_DISCOVERY` | gau / waybackurls / katana (только `full`) | `false` |
| `RECON_JS_ANALYSIS` | Query params + JS / linkfinder / unfurl (только `full`) | `false` |
| `RECON_SCREENSHOTS` | gowitness (только `full`) | `false` |
| `RECON_DEEP_PORT_SCAN` | naabu + nmap -sV (только `full`) | `false` |
| `RECON_ASNMAP_ENABLED` | asnmap apex ASN (только `full`) | `true` |
| `RECON_TOOL_SELECTION` | Подмножество шагов (csv id) | пусто = все по режиму |
| `RECON_WORDLIST_PATH` | Резерв под future dir busting | пусто |
| `RECON_RATE_LIMIT` / `RECON_RATE_LIMIT_PER_SECOND` | RPS throttle пайплайна | вторичный / `10` |
| `RECON_PASSIVE_SUBDOMAIN_TIMEOUT_SEC` | Таймаут passive subdomain bundle | fallback `RECON_TOOLS_TIMEOUT` |
| `RECON_THEHARVESTER_*` | Источники / лимит / включение theHarvester | см. example |
| `RECON_DNS_DEPTH_*`, `RECON_DNSX_*` | dnsx, dig, takeover hints | см. example |
| `RECON_NUCLEI_TECH_*` | nuclei tech-only в http_surface | см. example |
| `RECON_DEEP_*` | Лимиты deep port scan | см. example |
| `RECON_JS_*` | Лимиты JS-анализа, linkfinder, unfurl | см. example |
| `RECON_GOWITNESS_*` | Лимиты скриншотов | см. example |

Поведение фаз и шагов: **[scan-state-machine.md](./scan-state-machine.md)** § 4.1 (recon pipeline). Операции: **[recon-guide.md](./recon-guide.md)**.

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

### 3.5a Чеклист: active scan + AI + отчёты (Compose)

Используйте `infra/.env` (копия с `infra/.env.example`). **Backend** и **worker** в `infra/docker-compose.yml` должны получать одинаковые критичные переменные для VA/AI.

**Active scan (песочница):**

- [ ] `SANDBOX_ENABLED=true` — без этого активные инструменты VA не запускаются (`handlers.run_vuln_analysis`).
- [ ] `VA_AI_PLAN_ENABLED` — при `true` нужен хотя бы один LLM-ключ для `plan_active_scan_with_ai`.
- [ ] `SQLMAP_VA_ENABLED`, `VA_EXPLOIT_AGGRESSIVE_ENABLED` — включать осознанно (политика/approval).
- [ ] `VA_AGGRESSIVE_SCAN`, `VA_CUSTOM_XSS_POC_ENABLED` — агрессивные argv и reflected XSS probe после active scan.
- [ ] `ACTIVE_SCAN_MAX_CONCURRENT_JOBS`, `ACTIVE_SCAN_MAX_CAPTURE_BYTES`, `VA_ACTIVE_SCAN_TOOL_TIMEOUT_SEC` — лимиты нагрузки.
- [ ] `SANDBOX_PROFILE` — `standard` vs `extended` (сборка образа sandbox); первая сборка может занять долго.
- [ ] `NMAP_RECON_CYCLE`, `NMAP_FULL_TCP`, `NMAP_UDP_TOP50`, `NMAP_RECON_PHASE_TIMEOUT_SEC` — цикл nmap в recon.
- [ ] `RECON_MODE`, `RECON_PASSIVE_ONLY`, opt-in шаги (`RECON_ENABLE_CONTENT_DISCOVERY`, `RECON_JS_ANALYSIS`, `RECON_SCREENSHOTS`, `RECON_DEEP_PORT_SCAN`) и прочие **`RECON_*`** — см. § 3.1b и [`infra/.env.example`](../infra/.env.example).
- [ ] `KAL_ALLOW_PASSWORD_AUDIT` — только если нужен серверный gate для hydra/medusa через KAL API/MCP.
- [ ] `SEARCHSPLOIT_*`, `TRIVY_ENABLED`, `HIBP_PASSWORD_CHECK_OPT_IN` — intel и отчётность (см. § 3.1).

**LLM (анализ, VA-план, RPT-004 текст отчёта):**

- [ ] Хотя бы один из: `OPENROUTER_API_KEY`, `OPENAI_API_KEY`, `DEEPSEEK_API_KEY`, `KIMI_API_KEY`, `PERPLEXITY_API_KEY`, `GOOGLE_API_KEY`.
- [ ] Без ключей отчётные секции получают запасной текст вида «AI generation skipped: no LLM provider available» (шаблоны остаются валидными).

**Отчёты / MinIO:**

- [ ] `MINIO_REPORTS_BUCKET`, `MINIO_*` — выгрузка отчётов; post-scan hook создаёт **12** строк отчёта (3 tier × 4 формата по умолчанию), объекты в `{tenant}/{scan}/reports/{tier}/{report_id}.{fmt}`.

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

### 3.8 Active web scanning & AI reports (чеклист)

Перед включением активного VA по вебу и AI-плана отчётов проверьте:

- **`SANDBOX_ENABLED=true`** — без песочницы активные инструменты (dalfox, xsstrike и др.) не выполняются в штатном pipeline.
- **Celery worker и backend** получают **те же переменные окружения**, что и API-процесс (в том же `docker-compose` это обычно один и тот же env-файл / одинаковые `environment:` для `backend` и `worker`), в том числе **`SANDBOX_ENABLED`**.
- **Ключи LLM** (например `OPENAI_API_KEY`, `DEEPSEEK_API_KEY`, см. § 3.5) — нужны для AI-фаз отчётов и опционально для AI-плана активного сканирования.
- **`SQLMAP_VA_ENABLED`** — держите `false`, если не требуется sqlmap в фазе VA; включайте только осознанно (политика/approval).
- **`VA_AI_PLAN_ENABLED`** — при `true` после детерминированного плана подмешиваются шаги от LLM (нужны LLM-ключи).

Полный перечень переменных для compose: **[`infra/.env.example`](../infra/.env.example)** (скопируйте в `infra/.env` и заполните секреты).

#### 3.8.1 Активное веб-сканирование (docker exec → sandbox)

Фаза VA и задачи Celery (`scan_phase_task` и др.) вызывают инструменты через **`docker exec`** в контейнер песочницы (**имя по умолчанию: `argus-sandbox`**, задаётся `settings.sandbox_container_name`). Песочница должна быть в **том же compose-проекте**, что и worker/backend, чтобы DNS/имя контейнера совпадали.

- **Worker и backend** должны иметь доступ к **Docker API хоста**: в `infra/docker-compose.yml` смонтирован сокет **`/var/run/docker.sock:/var/run/docker.sock:ro`**. Без сокета `docker exec` из контейнера worker не выполняется — активные сканеры не стартуют, артефактов dalfox/xsstrike не будет.
- Переменная **`DOCKER_HOST`** на Linux обычно **не нужна** (используется дефолтный unix-socket). На **Windows + Docker Desktop** compose часто запускают из WSL или с Linux-VM; путь сокета в override должен соответствовать среде, где выполняется `docker compose` (см. документацию Docker Desktop для bind-mount сокета).
- Убедитесь, что **`SANDBOX_ENABLED=true`** и для **worker**, и для **backend** (одинаковое значение в `environment` / `.env`).
- После изменений в **`sandbox/Dockerfile`** пересоберите образ песочницы (`docker compose build sandbox` или полный rebuild стека с `--profile tools`), иначе в контейнере останутся старые бинарники (dalfox / xsstrike / ffuf и др.).

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

**Path:** `infra/backend/Dockerfile`

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

**Build:**

```bash
docker compose -f infra/docker-compose.yml build backend
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

- **[mcp-server.md](./mcp-server.md)** — MCP-инструменты KAL и `POST /api/v1/tools/kal/run`.

For complete startup instructions including all 3 deployment scenarios, environment setup, and API key placement, see **[RUNNING.md](./RUNNING.md)** — the definitive guide for:
- Docker full stack setup
- Local development setup (backend + frontend)
- Docker backend + local frontend
- Troubleshooting common issues
