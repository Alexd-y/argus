# ARGUS Environment Variables

Переменные окружения для Frontend и Backend.

---

## 1. Frontend (ARGUS)

| Variable | Default | Описание |
|----------|---------|----------|
| `NEXT_PUBLIC_API_URL` | `/api/v1` | Base URL для REST API |

---

## 2. Frontend (pentagi reference)

| Variable | Default | Описание |
|----------|---------|----------|
| `VITE_API_URL` | — | Backend host:port (без схемы, напр. `localhost:8080`) |
| `VITE_USE_HTTPS` | `false` | SSL для dev-сервера |
| `VITE_PORT` | `8000` | Порт Vite dev server |
| `VITE_HOST` | `0.0.0.0` | Host Vite |
| `VITE_SSL_KEY_PATH` | `ssl/server.key` | Путь к SSL ключу |
| `VITE_SSL_CERT_PATH` | `ssl/server.crt` | Путь к SSL сертификату |
| `VITE_APP_NAME` | — | Название приложения |
| `VITE_APP_API_ROOT` | — | API root (типы) |
| `VITE_APP_LOG_LEVEL` | — | `DEBUG` \| `INFO` \| `WARN` \| `ERROR` |
| `VITE_APP_SESSION_KEY` | — | Ключ сессии |

---

## 3. Backend (ARGUS)

### 3.1 Основные

| Variable | Default | Описание |
|---------|---------|----------|
| `ARGUS_SERVER_URL` | — | URL MCP-сервера (для оркестрации) |
| `DATABASE_URL` | — | PostgreSQL connection string |
| `REDIS_URL` | — | Redis для очередей |
| `MINIO_ENDPOINT` | — | S3-compatible storage |
| `MINIO_ACCESS_KEY` | — | MinIO access key |
| `MINIO_SECRET_KEY` | — | MinIO secret key |
| `MINIO_BUCKET` | — | Bucket для отчётов и артефактов |

### 3.2 LLM Providers (Phase 6)

| Variable | Описание |
|----------|----------|
| `OPENAI_API_KEY` | OpenAI (gpt-4o-mini) |
| `DEEPSEEK_API_KEY` | DeepSeek |
| `OPENROUTER_API_KEY` | OpenRouter |
| `GOOGLE_API_KEY` | Gemini |
| `KIMI_API_KEY` | Kimi (Moonshot) |
| `PERPLEXITY_API_KEY` | Perplexity |

Минимум один валидный ключ для AI-orchestration. Роутер вызывает первый доступный провайдер.

### 3.3 Data Sources (опционально)

| Variable | Описание |
|----------|----------|
| `CENSYS_API_KEY` | Censys |
| `SECURITYTRAILS_API_KEY` | SecurityTrails |
| `VIRUSTOTAL_API_KEY` | VirusTotal |
| `HIBP_API_KEY` | Have I Been Pwned |

NVD, Exploit-DB — публичные, без ключей.

### 3.4 Auth & Security

| Variable | Default | Описание |
|----------|---------|----------|
| `JWT_SECRET` | — | Секрет для JWT (admin-frontend) |
| `JWT_EXPIRY` | `15m` | Время жизни access token |
| `REFRESH_TOKEN_EXPIRY` | `7d` | Время жизни refresh token |
| `COOKIE_SIGNING_SALT` | — | Соль для подписи cookies (если используется) |
| `CORS_ORIGINS` | — | Разрешённые origins |

### 3.5 Observability

| Variable | Описание |
|----------|----------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry endpoint |
| `OTEL_SERVICE_NAME` | Имя сервиса |
| `LOG_LEVEL` | `INFO` \| `DEBUG` \| `WARN` \| `ERROR` |

---

## 4. pentagi Backend (reference)

Основные группы: LLM (OPEN_AI_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY, OLLAMA_*, …), OAuth (OAUTH_GOOGLE_*, OAUTH_GITHUB_*), Postgres (PENTAGI_POSTGRES_*), Docker, Scraper, Langfuse, Observability.  
Полный список — `test/pentagi/.env`.

---

## 5. .gitignore

Файлы `.env`, `.env.local`, `.env.*.local` должны быть в `.gitignore`. Секреты — только через env или secret manager.
