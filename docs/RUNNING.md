# ARGUS — полный гайд по запуску

**Версия:** 0.2  
**Источники:** `infra/docker-compose.yml`, `backend/.env.example`, `docs/deployment.md`, `docs/DOCKER.md`, `Frontend/package.json`, `admin-frontend/package.json`

> **ℹ️ Обновление v0.2 (2026-03-19):** Добавлена полная документация Docker-конфигурации в [DOCKER.md](./DOCKER.md). Backend Dockerfile теперь корректно копирует директорию `app/` (schemas, prompts). Смотрите [DOCKER.md](./DOCKER.md) для деталей конфигурации, сборки, проверки и troubleshooting.

---

## 1. Предварительные требования

| Компонент | Версия | Назначение |
|-----------|--------|------------|
| **Docker** | 20.10+ | Контейнеры (PostgreSQL, Redis, MinIO, Backend, Celery) |
| **Docker Compose** | v2+ | Оркестрация стека |
| **Node.js** | 18+ | Frontend, admin-frontend (Next.js) |
| **Python** | 3.12 | Backend (локальный запуск) |
| **pnpm / npm / yarn** | — | Установка зависимостей Frontend |

---

## 2. Вариант A: Всё через Docker

Полный стек в контейнерах.

### 2.1 Подготовка

```powershell
cd ARGUS
```

Скопировать env для infra (опционально, для переопределения портов и паролей):

```powershell
copy infra\.env.example infra\.env
```

### 2.2 Запуск

**Production** (порты postgres/redis/minio не пробрасываются):

```powershell
docker compose -f infra/docker-compose.yml up -d
```

**Dev** (с пробросом портов для локальных инструментов — pgAdmin, Redis CLI, MinIO Console):

```powershell
docker compose -f infra/docker-compose.yml -f infra/docker-compose.dev.yml up -d
```

С Celery worker и sandbox (для сканирования и отчётов):

```powershell
docker compose -f infra/docker-compose.yml --profile tools up -d
```

### 2.3 Сервисы

| Сервис | Порт (dev) | Назначение |
|--------|------|------------|
| postgres | 5432 | PostgreSQL + pgvector |
| redis | 6379 | Redis (кеш, Celery broker) |
| minio | 9000, 9001 | S3-совместимое хранилище |
| backend | 8000 | FastAPI API |
| celery-worker | — | Celery worker (profile: tools) |
| sandbox | — | Sandbox для инструментов (profile: tools) |
| mcp-server | 8001 | HTTP in Docker; stdio locally |

### 2.4 Проверка

- Backend: http://localhost:8000/api/v1/health
- MinIO Console: http://localhost:9001 — **только если** в `docker ps` у `argus-minio` есть проброс `0.0.0.0:9001->9001/tcp` (см. ниже).

**MinIO Console не открывается (`connection refused` на 9001):**

1. Вы запустили **только** `infra/docker-compose.yml` — в нём **нет** `ports` у MinIO (by design). Нужен второй файл:
   ```powershell
   docker compose -f infra/docker-compose.yml -f infra/docker-compose.dev.yml up -d
   ```
   или из каталога `infra/` (подхватится `docker-compose.override.yml`):
   ```powershell
   cd infra
   docker compose up -d
   ```
2. Убедитесь, что контейнер пересоздан после обновления образа: в `docker-compose.yml` для MinIO задана консоль на **9001** (`--console-address ":9001"`).

---

## 3. Вариант B: Backend локально + Frontend локально

Для разработки без Docker backend и frontend.

### 3.1 Инфраструктура (Docker)

Запустить только БД, Redis и MinIO (с пробросом портов для локального backend):

```powershell
cd ARGUS
docker compose -f infra/docker-compose.yml -f infra/docker-compose.dev.yml up -d postgres redis minio
```

### 3.2 Backend

```powershell
cd ARGUS/backend
```

Создать `.env`:

```powershell
copy .env.example .env
```

Заполнить `.env` (см. секцию «Куда вставлять API ключи»). Для локального запуска:

```env
DATABASE_URL=postgresql+asyncpg://argus:argus@localhost:5432/argus
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
MINIO_ENDPOINT=localhost:9000
MINIO_ACCESS_KEY=argus
MINIO_SECRET_KEY=argussecret
MINIO_BUCKET=argus
MINIO_REPORTS_BUCKET=argus-reports
MINIO_SECURE=false
```

Миграции:

```powershell
alembic upgrade head
```

Запуск:

```powershell
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### 3.3 Celery worker (опционально)

В отдельном терминале:

```powershell
cd ARGUS/backend
celery -A src.celery_app worker -l INFO -Q argus.scans,argus.reports,argus.tools,argus.exploitation,argus.default
```


### 3.3.1 Sandbox контейнер (Stage 4 Exploitation)

**Требуется для Stage 4 (Exploitation).** Sandbox — изолированный Docker контейнер с инструментами пентестирования.

**Инструменты в песочнице:**

| Инструмент | Назначение | Stage |
|-----------|-----------|-------|
| **nmap** | Сканирование портов, сервисов | 1-3 |
| **dnsutils** | DNS reconnaissance | 1-3 |
| **whois** | WHOIS lookup | 1-3 |
| **sqlmap** | SQL injection testing & exploitation | 4 |
| **hydra** | Brute force, default credentials | 4 |
| **nuclei** | CVE verification, vulnerability scanning | 4 |
| **metasploit-framework** | CVE exploitation (RCE, LFI, etc.) | 4 (опционально) |
| **Python 3** | Custom exploit scripts | 4 |

**Сборка контейнера:**

```powershell
# Базовая сборка (без Metasploit)
cd ARGUS
docker build -f sandbox/Dockerfile -t argus-exploits:latest .

# С Metasploit (~1.5 GB, опционально)
docker build -f sandbox/Dockerfile --build-arg INSTALL_MSF=true -t argus-exploits:latest .
```

**Запуск с Docker Compose:**

Sandbox автоматически запускается когда используется `--profile tools`:

```powershell
docker compose -f infra/docker-compose.yml --profile tools up -d
```

**Health check:**

```powershell
# Проверить, что контейнер запущен
docker ps | findstr argus-exploit-sandbox

# Проверить инструменты
docker exec argus-exploit-sandbox sqlmap --version
docker exec argus-exploit-sandbox nuclei -version
```

### 3.3.2 Пересборка образа sandbox для VA active-scan (dalfox, ffuf, sqlmap, …)

Фаза **vulnerability analysis → active scan** запускает allowlisted-инструменты внутри sandbox через `docker exec` (см. `sandbox/Dockerfile`: **ffuf**, **gobuster**, **wfuzz**, **sqlmap** из apt; **dalfox** и **nuclei** — pinned binary; **commix**, **XSStrike** — git + pip). Если вы меняли Dockerfile, build-args или версии инструментов — пересоберите образ и пересоздайте контейнер, иначе worker продолжит использовать старый слой.

**Через Compose (рекомендуется, образ `argus-sandbox`, контейнер `argus-sandbox`):**

```powershell
cd ARGUS
docker compose -f infra/docker-compose.yml build sandbox --no-cache
docker compose -f infra/docker-compose.yml up -d sandbox
```

С dev-оверлеем (порты БД/Redis и т.д.):

```powershell
docker compose -f infra/docker-compose.yml -f infra/docker-compose.dev.yml build sandbox --no-cache
docker compose -f infra/docker-compose.yml -f infra/docker-compose.dev.yml up -d sandbox
```

**Вручную (тот же контекст, что и в compose):**

```powershell
cd ARGUS
docker build -f sandbox/Dockerfile -t argus-sandbox:latest .
```

Опциональные аргументы образа (см. комментарии в `sandbox/Dockerfile`): `DALFOX_VERSION`, `NUCLEI_VERSION`, `INSTALL_MSF=true` для Metasploit.

**Проверка бинарников после пересборки:**

```powershell
docker exec argus-sandbox dalfox version
docker exec argus-sandbox ffuf -V
docker exec argus-sandbox sqlmap --version
docker exec argus-sandbox nuclei -version
```

**Переменные `backend/.env`, относящиеся к VA active-scan и sandbox:**

| Переменная | Назначение |
|------------|------------|
| `SANDBOX_ENABLED` | Включить выполнение через sandbox (`docker exec`); без этого фаза active-scan пропускается. |
| `SANDBOX_CONTAINER_NAME` | Имя контейнера (по умолчанию `argus-sandbox` — должно совпадать с `container_name` в compose). |
| `VA_ACTIVE_SCAN_TOOL_TIMEOUT_SEC` | Таймаут одного вызова инструмента (сек). |
| `FFUF_VA_WORDLIST_PATH` | Путь к wordlist для **ffuf** на стороне процесса backend/worker (при необходимости смонтируйте том или положите файл туда, откуда worker читает путь). |
| `SQLMAP_VA_ENABLED` | Включить **sqlmap** в плане VA (по умолчанию выкл.; политика/approval могут дополнительно ограничивать запуск). |
| `ACTIVE_SCAN_MAX_CONCURRENT_JOBS` | Максимум параллельных async-задач active-scan. |
| `ACTIVE_SCAN_MAX_CAPTURE_BYTES` | Верхний предел размера stdout/stderr на поток. |

**Ресурсные ограничения:**

```yaml
# Из docker-compose.yml
cpus: "2"           # 2 CPU cores
memory: 2gb            # 2 GB RAM
memory_swap: 2gb       # No swap
```

**Custom exploit scripts:**

Поместите пользовательские скрипты в `plugins/exploit_scripts/`:

```
plugins/exploit_scripts/
├── sqli/              # SQL injection payloads
├── xss/               # XSS verification
├── rce/               # Remote code execution chains
├── auth_bypass/       # Authentication bypass
└── custom/            # Other custom exploits
```

Скрипты монтируются read-only в `/opt/exploit_scripts/` внутри контейнера.

**Требования к скриптам:**

- Язык: Python 3 или Bash
- Exit code: `0` = успех, non-zero = ошибка
- Output: JSON предпочтительно
- Безопасность: запускаются в изолированном контейнере с ограничениями ресурсов

**Сервис `minio-init` — зачем и почему «падает»**

- **Назначение:** контейнер с `minio/mc` подключается к MinIO и выполняет **`mc mb --ignore-existing`** — создаёт нужные **buckets**, если их ещё нет. Без этого backend/worker могут получать ошибки при записи в S3.
- **Поведение:** это **не** долгоживущий сервис. Скрипт отрабатывает и процесс **завершается с кодом 0**. В списке контейнеров статус **Exited (0)** — это **норма**, а не авария. Постоянно «Running» он быть не должен.
- **Логи (успех или ошибка):**
  ```powershell
  docker logs argus-minio-init
  ```
  В конце при успехе должна быть строка `MinIO buckets ready`. Если **Exited (1)** — смотри логи: чаще всего неверные `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY` относительно уже существующего volume MinIO (учётка задаётся при первом старте тома).
- **Повторно создать buckets вручную:**
  ```powershell
  docker compose -f infra/docker-compose.yml run --rm minio-init
  ```

**Логин и пароль MinIO (Web Console `http://127.0.0.1:9001` при пробросе портов)**

| Поле в форме входа | Что вводить |
|--------------------|-------------|
| **User** / Access Key | Значение **`MINIO_ACCESS_KEY`** из **`infra/.env`** |
| **Password** / Secret Key | Значение **`MINIO_SECRET_KEY`** из **`infra/.env`** |

Если переменных нет в `.env`, в `docker-compose.yml` подставляются дефолты **`argus`** / **`argussecret`**.

**Не путать:** логин MinIO **не** `POSTGRES_USER` / **не** пароль БД.

**Вводишь верные ключи из `.env`, но «Invalid login»:** MinIO один раз зафиксировал root при **первом** запуске тома. Смена `MINIO_SECRET_KEY` в `.env` **не** меняет пароль в уже существующем volume — либо верни старый пароль, либо удалить volume `minio_data` (потеря объектов в MinIO) и поднять заново.

**MinIO buckets (создаёт `minio-init`):**

| Bucket | Назначение |
|--------|-----------|
| `argus` (или `MINIO_BUCKET`) | Основной bucket: raw, screenshots, evidence, attachments и т.п. |
| `argus-reports` (или `MINIO_REPORTS_BUCKET`) | Кэш экспортов отчётов (PDF/HTML/JSON/CSV), presigned/download |
| `stage1-artifacts` … `stage4-artifacts` | Артефакты по стадиям recon/exploitation |
| `argus-recon` | Recon-модуль |

### 3.4 Frontend

```powershell
cd ARGUS/Frontend
```

Создать `.env.local`:

```powershell
copy .env.example .env.local
```

Указать API backend:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
```

Установка и запуск:

```powershell
npm install
npm run dev
```

Frontend: http://localhost:5000

### 3.5 Admin-frontend

```powershell
cd ARGUS/admin-frontend
copy .env.example .env.local
```

В `.env.local`:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_ADMIN_KEY=<ваш ADMIN_API_KEY из backend>
```

```powershell
npm install
npm run dev
```

Admin-frontend: http://localhost:3001

---

## 4. Вариант C: Docker backend + локальный Frontend

Backend в Docker, frontend локально.

### 4.1 Запуск backend-стека

```powershell
cd ARGUS
docker compose -f infra/docker-compose.yml up -d

Сборка и запуск
cd d:\Developer\Pentest_test\ARGUS
docker compose -f infra/docker-compose.yml build backend worker
docker compose -f infra/docker-compose.yml up -d
Для dev с пробросом портов postgres/redis/minio:

docker compose -f infra/docker-compose.yml -f infra/docker-compose.dev.yml up -d
Замечания
Frontend и admin-frontend не в Docker — запускаются локально (см. docs/RUNNING.md).
Перед production: скопировать infra/.env.example → infra/.env и задать секреты.
```

Запуск туннеля

cd d:\Developer\Pentest_test\ARGUS
# В infra/.env задать CLOUDFLARE_TUNNEL_TOKEN и VERCEL_FRONTEND_URL
docker compose -f infra/docker-compose.yml --profile tunnel up -d

На Vercel в переменных окружения фронта указать URL бэкенда через туннель (например NEXT_PUBLIC_BACKEND_URL=https://argus-tunnel.your-domain.com), как описано в docs/deployment.md.

задать токен: vercel.com → Account → Tokens → VERCEL_TOKEN в окружении и снова vercel deploy --prod --yes
cloudflared tunnel --url http://127.0.0.1:80

### 4.2 Frontend

```powershell
cd ARGUS/Frontend
copy .env.example .env.local
```

В `.env.local`:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
```

```powershell
npm install
npm run dev
```

### 4.3 Admin-frontend

```powershell
cd ARGUS/admin-frontend
copy .env.example .env.local
```

В `.env.local`:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_ADMIN_KEY=<ADMIN_API_KEY из backend/infra .env>
```

```powershell
npm run dev
```

---

## 5. AI Orchestrator — LLM Integration

**Когда используется AI:**
- Если в `backend/.env` установлен **хотя бы один** LLM ключ (OPENAI_API_KEY, DEEPSEEK_API_KEY, OPENROUTER_API_KEY, GOOGLE_API_KEY, KIMI_API_KEY, PERPLEXITY_API_KEY) — система использует AI для:
  - Анализа аномалий в данных сканирования
  - Генерации гипотез о уязвимостях
  - Оркестрации многошаговых сценариев разведки
  - Автоматической классификации угроз

**Если ключи не установлены:**
- Система переходит в режим **rule-based analysis** (правила без AI)
- Функциональность остаётся полной, но без интеллектуального анализа

**LLM Providers:**

| Provider | Env Variable | Примечание |
|----------|--------------|-----------|
| OpenAI (GPT-4, GPT-3.5) | OPENAI_API_KEY | Сбалансированная цена/качество |
| DeepSeek | DEEPSEEK_API_KEY | Быстрая обработка |
| OpenRouter | OPENROUTER_API_KEY | Агрегатор моделей (гибкость) |
| Google Gemini | GOOGLE_API_KEY | Встроенная контекстная информация |
| Kimi (Moonshot) | KIMI_API_KEY | Оптимизирована для длинного контекста |
| Perplexity | PERPLEXITY_API_KEY | Специализирована на поиске и синтезе |

**Рекомендуемая настройка для разработки:**
```env
# Использовать одного провайдера или оставить пусто для rule-based mode
OPENROUTER_API_KEY=sk-or-v1-...  # (включен в .env.example)
```

---

## 6. MCP Server — Model Context Protocol

**Разделение ролей MCP в ARGUS:**

| Компонент | Назначение | Транспорт |
|-----------|------------|-----------|
| **mcp-server-fetch** (pip) | Endpoint discovery для Stage 1: robots.txt, sitemap.xml, security.txt, favicon.ico, manifest.json | stdio (backend spawn) |
| **ARGUS MCP** (argus_mcp.py) | Инструменты для Cursor/агента: create_scan, get_scan_status, subfinder, httpx и др. | stdio (Cursor IDE) |

**Stage 1 pipeline** использует mcp-server-fetch для HTTP-запросов к целям. ARGUS MCP контейнер предоставляет инструменты оркестрации сканирований для Cursor — backend не подключается к ARGUS MCP напрямую (stdio-only).

### 6.1 Запуск MCP сервера

**Локально (рекомендуется):**
```powershell
cd ARGUS/mcp-server
python argus_mcp.py --server http://localhost:8000
```

**Через Docker (по умолчанию):** MCP сервер запускается вместе с основным стеком (`docker compose up -d`).
```powershell
cd ARGUS
docker compose -f infra/docker-compose.yml up -d
```

**Проверка:** MCP использует stdio-транспорт; для Cursor настройте `.cursor/mcp.json` (см. ниже).

### 6.2 Интеграция с Cursor IDE

Добавьте в `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "argus": {
      "command": "python",
      "args": [
        "/absolute/path/to/ARGUS/mcp-server/argus_mcp.py",
        "--server",
        "http://localhost:8000"
      ],
      "env": {
        "ARGUS_SERVER_URL": "http://localhost:8000"
      },
      "description": "ARGUS MCP — Security scan orchestration",
      "timeout": 300
    }
  }
}
```

**MCP Tools:**
- `create_scan(target, scan_type)` — запуск сканирования
- `get_scan_status(scan_id)` — статус сканирования
- `list_findings(scan_id)` — получить находки
- `get_report(scan_id)` — полный отчёт

### 6.3 Автоматическое обеспечение MCP доступности

Скрипт `scripts/ensure_mcp_server.ps1` проверяет доступность MCP и может запустить его:

```powershell
& .\scripts\ensure_mcp_server.ps1
```

**Что делает:**
1. Проверяет наличие `mcp-server-fetch` (pip) — используется для endpoint discovery (robots.txt, sitemap и т.д.)
2. Проверяет/запускает контейнер `argus-mcp` через `docker compose up -d mcp-server`
3. ARGUS MCP работает по stdio (без HTTP-порта); Cursor подключается через `.cursor/mcp.json`

---

## 7. Intel Adapters — External Intelligence

**Intel адаптеры** собирают passive intelligence из 3rd-party API без активного сканирования целей.

### 7.1 Поддерживаемые сервисы

| Сервис | Env Key | Назначение | Обязательно |
|--------|---------|-----------|------------|
| **Shodan** | SHODAN_API_KEY | IP/port/service enumeration, CVE by banner | опционально |
| **GitHub** | GITHUB_TOKEN | Public repos, code leaks, exposed credentials | опционально |
| **Censys** | CENSYS_API_KEY | SSL certs, host enumeration, internet scanning | опционально |
| **SecurityTrails** | SECURITYTRAILS_API_KEY | DNS history, domain/subdomain enumeration | опционально |
| **VirusTotal** | VIRUSTOTAL_API_KEY | URL/file reputation, malware analysis | опционально |
| **AbuseIPDB** | ABUSEIPDB_API_KEY | IP reputation, malicious activity reports | опционально |
| **GreyNoise** | GREYNOISE_API_KEY | Sensor network, internet background noise | опционально |
| **OTX** | OTX_API_KEY | Open threat exchange, IoCs | опционально |
| **URLscan.io** | URLSCAN_API_KEY | Website screenshot, DOM, security indicators | опционально |
| **ExploitDB** | EXPLOITDB_API_KEY | Public exploits, vulnerability database | опционально |

### 7.2 Применение

В конфиге сканирования (или скрипте) установите `use_intel=True`:

```python
# Пример в run_stage1_report.py
scan = create_scan(
    target="svalbard.ca",
    scan_type="reconnaissance",
    use_intel=True,  # ← Включить Intel адаптеры
    ai_analysis=True  # ← Включить AI анализ (если LLM ключ есть)
)
```

**Поведение:**
- Если ключ для сервиса установлен — адаптер активирован и выполняет запросы
- Если ключ не установлен — сервис пропускается (graceful degradation)
- Результаты объединяются в финальный отчёт

---

## 8. Stage 1 Reconnaissance Resources

**Stage 1** использует passive, безопасные источники (не отправляет трафик на цель):

### 8.1 Бесплатные/встроенные ресурсы

| Ресурс | Назначение | Примечание |
|--------|-----------|-----------|
| **Shodan** | IP/port/service enumeration | Требует API key (опционально) |
| **NVD (NIST)** | CVE lookup by version | Бесплатно, встроено |
| **crt.sh** | SSL certificate enumeration | Бесплатно, публичная база |
| **RDAP** | IP ownership, ASN, WHOIS | Бесплатно, встроено (RFC 7482) |
| **DNS** (public resolvers) | A/AAAA/MX/TXT records | Бесплатно, встроено |
| **Google Search** | Dorking (optional, AI-powered) | Требует OPENAI_API_KEY |
| **GitHub API** | Public repos, code leaks | GITHUB_TOKEN ускоряет rate limits |

### 8.2 Flow Stage 1 Reconnaissance

```
1. Инициализация
   ├── Загрузка env и конфига
   ├── Инициализация логирования
   └── Проверка доступности AI/MCP

2. Domain Enumeration
   ├── DNS A/AAAA/MX/TXT records (встроено)
   ├── SSL certificate enumeration via crt.sh (встроено)
   ├── Subdomain hints from SecurityTrails (если SECURITYTRAILS_API_KEY)
   └── GitHub repo scan (если GITHUB_TOKEN)

3. IP & ASN Profiling
   ├── IP ownership via RDAP (встроено)
   ├── ASN/CIDR lookup (встроено)
   ├── Shodan IP enumeration (если SHODAN_API_KEY)
   └── GreyNoise context (если GREYNOISE_API_KEY)

4. Service Enumeration
   ├── HTTP probing на common ports (80, 443, 8000, 8443, ...)
   ├── Banner grabbing (безопасно, HTTP только)
   ├── WAF detection (headers analysis)
   └── Technology stack inference (Wappalyzer-like)

5. Vulnerability Intelligence
   ├── CVE lookup by version (NVD + vendor advisories)
   ├── ExploitDB public exploits (если EXPLOITDB_API_KEY)
   ├── Shodan CVE scoring (если SHODAN_API_KEY)
   └── VirusTotal URL/domain reputation (если VIRUSTOTAL_API_KEY)

6. Threat & Reputation
   ├── AbuseIPDB IP reputation (если ABUSEIPDB_API_KEY)
   ├── GreyNoise classification (если GREYNOISE_API_KEY)
   ├── OTX IoC lookup (если OTX_API_KEY)
   └── URLscan.io website analysis (если URLSCAN_API_KEY)

7. AI Analysis (если LLM ключ установлен)
   ├── Anomaly detection (unusual ports, versions, etc.)
   ├── Threat hypothesis generation
   ├── Attack surface prioritization
   └── Remediation recommendations

8. Report Generation
   ├── HTML report (assets, findings, risk score)
   ├── JSON findings export
   └── PDF (опционально, requires browser)
```

### 8.3 Скрипт Stage 1 в деталях

**Команда:**
```powershell
.\scripts\run-stage1-recon-svalbard.ps1
```

**Шаги:**
1. **Docker containers check** — запуск ARGUS stack, если не запущен
2. **Backend health** — проверка `/api/v1/health`
3. **MCP availability** — ensure_mcp_server.ps1 проверяет mcp-server-fetch (endpoint discovery) и argus-mcp (опционально для Cursor)
4. **Report generation** — вызов `run_stage1_report.py` с параметром `use_mcp=True`; endpoint discovery использует mcp-server-fetch
5. **HTML output** — копирование отчёта в `pentest_reports_svalbard/`
6. **PDF generation** — опциональное создание PDF

**Переменные окружения (из backend/.env):**
```env
# Stage 1 будет использовать эти ключи при наличии:
OPENAI_API_KEY          # AI orchestrator
SHODAN_API_KEY          # IP/port enum
GITHUB_TOKEN            # Repo scan
CENSYS_API_KEY          # SSL enum
SECURITYTRAILS_API_KEY  # DNS history
VIRUSTOTAL_API_KEY      # URL reputation
ABUSEIPDB_API_KEY       # IP reputation
GREYNOISE_API_KEY       # Sensor network
OTX_API_KEY             # Threat intel
URLSCAN_API_KEY         # Website analysis
EXPLOITDB_API_KEY       # Exploits
```

---

## 9. Куда вставлять API ключи

| Файл/место | Переменная | Назначение | Обязательность |
|------------|------------|------------|----------------|
| backend/.env | OPENAI_API_KEY | LLM (OpenAI) | опционально* |
| backend/.env | DEEPSEEK_API_KEY | LLM (DeepSeek) | опционально* |
| backend/.env | OPENROUTER_API_KEY | LLM (OpenRouter) | опционально |
| backend/.env | GOOGLE_API_KEY | LLM (Gemini) | опционально |
| backend/.env | KIMI_API_KEY | LLM (Kimi) | опционально |
| backend/.env | PERPLEXITY_API_KEY | LLM (Perplexity) | опционально |
| backend/.env | SHODAN_API_KEY | Intel (Shodan) | опционально |
| backend/.env | GITHUB_TOKEN | Intel (GitHub) | опционально |
| backend/.env | CENSYS_API_KEY | Intel (Censys) | опционально |
| backend/.env | JWT_SECRET | Auth (JWT подпись) | обязательно в prod |
| backend/.env | ADMIN_API_KEY | Admin API (X-Admin-Key) | опционально |
| Frontend/.env.local | NEXT_PUBLIC_API_URL | API base URL | обязательно |
| admin-frontend/.env.local | NEXT_PUBLIC_API_URL | API base URL | обязательно |
| admin-frontend/.env.local | NEXT_PUBLIC_ADMIN_KEY | Admin API key для UI | опционально |
| backend/.env | SANDBOX_ENABLED | Enable sandbox execution for Stage 4 / VA active-scan | обязательно в Docker |
| backend/.env | SANDBOX_CONTAINER_NAME | Docker container name (compose: `argus-sandbox`) | опционально |
| backend/.env | VA_ACTIVE_SCAN_TOOL_TIMEOUT_SEC | Таймаут одного VA active-scan инструмента (сек) | опционально |
| backend/.env | FFUF_VA_WORDLIST_PATH | Wordlist для ffuf в VA | опционально |
| backend/.env | SQLMAP_VA_ENABLED | Включить sqlmap в VA active-scan | опционально |
| backend/.env | ACTIVE_SCAN_MAX_CONCURRENT_JOBS | Параллельность VA active-scan | опционально |
| backend/.env | ACTIVE_SCAN_MAX_CAPTURE_BYTES | Лимит захвата stdout/stderr | опционально |
| backend/.env | EXPLOIT_TIMEOUT_SECONDS | Timeout per exploit (default 600) | опционально |
| backend/.env | EXPLOIT_MAX_CONCURRENT | Max concurrent exploits (default 5) | опционально |
| backend/.env | APPROVAL_TIMEOUT_MINUTES | Approval request timeout (default 60) | опционально |
| backend/.env | STAGE4_ARTIFACTS_BUCKET | MinIO bucket for Stage 4 results | обязательно |
## 10. Куда вставлять API ключи

| Файл/место | Переменная | Назначение | Обязательность |
|------------|------------|-----------|----------------|
|| **LLM Providers** (AI Orchestrator) ||||
|| backend/.env | OPENAI_API_KEY | LLM (OpenAI GPT-4/3.5) | опционально* |
|| backend/.env | DEEPSEEK_API_KEY | LLM (DeepSeek) | опционально* |
|| backend/.env | OPENROUTER_API_KEY | LLM (OpenRouter multimodel) | опционально* |
|| backend/.env | GOOGLE_API_KEY | LLM (Google Gemini) | опционально* |
|| backend/.env | KIMI_API_KEY | LLM (Kimi/Moonshot) | опционально* |
|| backend/.env | PERPLEXITY_API_KEY | LLM (Perplexity) | опционально* |
|| **Intel Adapters** (Stage 1 Reconnaissance) ||||
|| backend/.env | SHODAN_API_KEY | Intel (Shodan IP enum) | опционально |
|| backend/.env | GITHUB_TOKEN | Intel (GitHub repos, leaks) | опционально |
|| backend/.env | CENSYS_API_KEY | Intel (Censys SSL, hosts) | опционально |
|| backend/.env | SECURITYTRAILS_API_KEY | Intel (SecurityTrails DNS) | опционально |
|| backend/.env | VIRUSTOTAL_API_KEY | Intel (VirusTotal URL reputation) | опционально |
|| backend/.env | ABUSEIPDB_API_KEY | Intel (AbuseIPDB IP reputation) | опционально |
|| backend/.env | GREYNOISE_API_KEY | Intel (GreyNoise sensor network) | опционально |
|| backend/.env | OTX_API_KEY | Intel (OTX threat intel) | опционально |
|| backend/.env | URLSCAN_API_KEY | Intel (URLscan.io analysis) | опционально |
|| backend/.env | EXPLOITDB_API_KEY | Intel (ExploitDB exploits) | опционально |
|| **Authentication & Admin** ||||
|| backend/.env | JWT_SECRET | Auth (JWT подпись) | обязательно в prod |
|| backend/.env | ADMIN_API_KEY | Admin API (X-Admin-Key header) | опционально |
|| **Storage & Infrastructure** ||||
|| backend/.env | DATABASE_URL | PostgreSQL connection | обязательно |
|| backend/.env | REDIS_URL | Redis connection | обязательно |
|| backend/.env | CELERY_BROKER_URL | Celery broker (обычно Redis) | обязательно |
|| backend/.env | MINIO_ENDPOINT | S3-compatible storage | обязательно |
|| backend/.env | MINIO_ACCESS_KEY | MinIO access key | обязательно |
|| backend/.env | MINIO_SECRET_KEY | MinIO secret key | обязательно |
|| **Frontend** ||||
|| Frontend/.env.local | NEXT_PUBLIC_API_URL | API base URL | обязательно |
|| admin-frontend/.env.local | NEXT_PUBLIC_API_URL | API base URL | обязательно |
|| admin-frontend/.env.local | NEXT_PUBLIC_ADMIN_KEY | Admin API key для UI | опционально |

\* Хотя бы один LLM-ключ нужен для AI-функций (анализ аномалий, гипотезы, оркестрация). Если ключей нет — система работает в режиме rule-based analysis.

### 9.1 Генерация JWT_SECRET

```powershell
openssl rand -hex 32
```

**Windows без openssl:** если `openssl` недоступен, используйте PowerShell:

```powershell
[Convert]::ToBase64String((1..32|%{Get-Random -Maximum 256})).Substring(0,32)
```

Либо установите Git for Windows — в комплекте идёт openssl.

---

## 10. Troubleshooting

### 10.1 Порты заняты

| Порт | Сервис | Решение |
|------|--------|---------|
| 5432 | PostgreSQL | Изменить `POSTGRES_PORT` в `infra/.env` |
| 6379 | Redis | Изменить `REDIS_PORT` |
| 9000, 9001 | MinIO | Изменить `MINIO_PORT`, `_CONSOLE_PORT` |
| 8000 | Backend | Изменить `BACKEND_PORT` |
| 5000 | Frontend | Уже в `package.json` (`next dev -p 5000`) |
| 3001 | admin-frontend | Уже в `package.json` (`next dev -p 3001`) |

### 10.2 EACCES: permission denied на портах 3000/3002 (Windows)

На Windows порты 3000 и 3002 могут попадать в **excluded port range** (резерв Hyper-V/WSL). При `EACCES: permission denied`:

1. **Проверить исключённые диапазоны:**
   ```powershell
   netsh interface ipv4 show excludedportrange protocol=tcp
   ```

2. **Проверить занятость портов:**
   ```powershell
   netstat -ano | findstr ":3000 :3002"
   ```

3. **Использовать порт вне диапазонов** — по умолчанию Frontend настроен на **5000** (вне excluded ranges). Если EACCES сохраняется, попробуйте 4400, 4500 или другой порт выше 4377 и ниже 50000.

4. **Изменить порт в `Frontend/package.json`:**
   ```json
   "dev": "next dev -H 127.0.0.1 -p 5000"
   ```

Сервис доступен по `http://localhost:5000` или `http://127.0.0.1:5000`.

### 10.3 Миграции не применяются

```powershell
cd ARGUS/backend
alembic upgrade head
```

Если ошибка подключения к БД — проверить `DATABASE_URL` и что PostgreSQL запущен.

### 10.4 Health check backend

```powershell
curl http://localhost:8000/api/v1/health
curl http://localhost:8000/api/v1/ready
```

### 10.5 Frontend не видит API

- Убедиться, что `NEXT_PUBLIC_API_URL` указывает на backend (например `http://localhost:8000/api/v1`).
- При изменении `.env.local` перезапустить `npm run dev`.

### 10.6 CORS

При `allow_credentials=True` браузер не принимает `Access-Control-Allow-Origin: *`. Backend при `CORS_ORIGINS=*` или пустом значении использует явный список: localhost/127.0.0.1 на портах 5000, 5800, 8000, 3001.

**Рекомендация:** используйте относительный `NEXT_PUBLIC_API_URL=/api/v1` в Frontend — запросы идут на same-origin (например `localhost:5800/api/v1`), Next.js проксирует их на backend. CORS не требуется.

Если frontend на нестандартном порту (например 5800 из-за excluded port range на Windows), добавьте его в `CORS_ORIGINS` или используйте относительный `/api/v1`:

```env
CORS_ORIGINS=http://localhost:5000,http://127.0.0.1:5000,http://localhost:5800,http://127.0.0.1:5800,http://localhost:3001
```

При ошибках 500 CORS-заголовки добавляются в exception handler — браузер не блокирует ответ.

### 10.7 Celery не обрабатывает задачи

- Проверить `REDIS_URL` и `CELERY_BROKER_URL`.
- Запускать с `--profile tools` при Docker.
- Локально — отдельно запустить `celery -A src.celery_app worker ...`.

### 10.8 Docker build ошибка: `chown: invalid group`

Если при `docker build` выскакивает `chown: invalid group: 'appuser:appuser'`, это значит adduser создал пользователя без группы. **Решение:** используйте `adduser --group` перед `chown`:

```dockerfile
RUN adduser --system --group --no-create-home appuser && chown -R appuser:appuser /app
```

Флаг `--group` гарантирует создание group с тем же именем. Это особенно важно в slim образах с минимальным toolset.

### 10.9 React hydration mismatch на `<html>`: `suppressHydrationWarning`

**Симптом:** при загрузке Frontend в браузере с расширениями (Password Manager, ad-blocker и т.д.) консоль выдаёт ошибку `Hydration mismatch on <html>` — расширение добавило атрибут (например `data-lt-installed`), и серверный HTML не совпадает с клиентским.

**Решение:** добавлена директива `suppressHydrationWarning` на тег `<html>` в `Frontend/src/app/layout.tsx`. Это безопасно, так как мы контролируем содержимое, и ошибка вызвана сторонним кодом. Подробнее: [React Hydration Docs](https://react.dev/reference/react-dom/client/hydrateRoot).

### 10.10 Docker: "network not found" при compose start

**Проблема:** `failed to set up container networking: network <id> not found` при запуске `docker compose up`.

**Причина:** Orphaned контейнер (остаток от старой конфигурации, напр. `argus-mcp-server`) ссылается на удалённую сеть.

**Решение:**
```powershell
docker rm -f argus-mcp-server
docker compose -f infra/docker-compose.yml down --remove-orphans
docker compose -f infra/docker-compose.yml up -d
```

**Примечание:** MCP-сервер входит в стек по умолчанию; при проблемах с сетью можно запустить локально (раздел 6).

### 10.11 Scan Failed (404): Frontend не видит Backend

**Симптом:** Сканирование падает с ошибкой `Request failed (404)`, хотя backend работает.

**Причина:** `NEXT_PUBLIC_API_URL` в `Frontend/.env.local` указывает на относительный путь (например `/api/v1`) или неправильный URL. Next.js интерпретирует это как запрос к себе, а не к backend.

**Решение:** В `Frontend/.env.local` установите полный абсолютный URL:
```env
NEXT_PUBLIC_API_URL=http://localhost:8000/api/v1
```
Затем перезапустите frontend: `npm run dev`.

### 10.12 Scan Failed (NetworkError / 500)

**Симптом:** Сканирование падает с `NetworkError` или `500 Internal Server Error` в backend.

**Предусловие:** Убедиться, что в `backend/.env` установлены **обязательные** переменные:
- `JWT_SECRET` (сгенерировать: `openssl rand -hex 32`)
- `CELERY_BROKER_URL=redis://localhost:6379/0` (или соответствующий Redis URL)

Проверить, что **Celery worker запущен** (локально или в Docker с `--profile tools`).

**Решение:**
1. Применить миграции БД:
   ```powershell
   cd ARGUS/backend && alembic upgrade head
   ```
2. При Docker запустить с tools-профилем (Celery + sandbox):
   ```powershell
   docker compose -f infra/docker-compose.yml --profile tools up -d
   ```
3. Проверить логи backend (`docker logs argus-backend`) и Celery worker.

### 10.13 Scan застрял на Initializing

**Симптом:** Сканирование останавливается на статусе `Initializing` и не прогрессирует.

**Предусловие:** Убедиться, что **Celery worker запущен** — для Docker использовать `--profile tools`:
```powershell
docker compose -f infra/docker-compose.yml --profile tools up -d
```

**Если проблема сохраняется:** Проверить логи Celery worker на `ProgrammingError`:
```powershell
docker logs argus-celery-worker
```

**Общее решение:** Пересобрать backend и celery-worker контейнеры после изменений кода:
```powershell
docker compose -f infra/docker-compose.yml --profile tools down
docker compose -f infra/docker-compose.yml --profile tools build --no-cache backend celery-worker
docker compose -f infra/docker-compose.yml --profile tools up -d
```

### 10.14 PDF-отчёты (RPT-009, WeasyPrint)

Backend формирует **PDF из того же HTML**, что и веб-отчёт, через **WeasyPrint**. В `ARGUS/backend/Dockerfile` установлены системные библиотеки (**Pango, Cairo, GDK-Pixbuf**, `shared-mime-info`).

**Локально без этих библиотек** импорт WeasyPrint может вызвать `OSError` — используйте Docker или установите зависимости ОС ([WeasyPrint — Install](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation)).

**CI / pytest без нативных зависимостей:** задайте переменную и пропускайте интеграционные тесты PDF (юнит-тест с моком WeasyPrint выполняется всегда):

```powershell
$env:ARGUS_SKIP_WEASYPRINT_PDF = "1"
pytest tests/ -v
```

```bash
export ARGUS_SKIP_WEASYPRINT_PDF=1
pytest tests/ -v
```

Тесты с маркером `weasyprint_pdf` получат **skip** с явной причиной.

---

## 11. Краткая шпаргалка

| Действие | Команда |
|----------|---------|
| Всё в Docker | `docker compose -f infra/docker-compose.yml up -d` |
| Docker + Celery | `docker compose -f infra/docker-compose.yml --profile tools up -d` |
| Миграции | `cd backend && alembic upgrade head` |
| Backend локально | `cd backend && uvicorn main:app --reload --port 8000` |
| Frontend | `cd Frontend && npm run dev` |
| Admin-frontend | `cd admin-frontend && npm run dev` |
