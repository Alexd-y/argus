# ARGUS Scripts — Stage 1 Reconnaissance

Документация для утилит и скриптов автоматизации разведки (Stage 1) в ARGUS.

---

## Обзор

| Скрипт | Язык | Назначение | Входные данные |
|--------|------|-----------|-----------------|
| `run-stage1-recon-svalbard.ps1` | PowerShell | Оркестрация полного цикла Stage 1 разведки | Конфиг, env-переменные |
| `run_stage1_report.py` | Python | Генерация Stage 1 отчёта (core logic) | Target, scan type, flags |
| `run_stage1_argus_mcp.py` | Python | MCP-обёртка для запуска через LLM agents | MCP protocol |
| `ensure_mcp_server.ps1` | PowerShell | Проверка и запуск MCP сервера | None (standalone) |
| `diagnose-scan-stuck.ps1` | PowerShell | Диагностика застывших сканирований | Scan ID (optional) |
| `start-cloudflare-tunnel.ps1` | PowerShell | Quick Tunnel к локальному nginx для Vercel → `NEXT_PUBLIC_BACKEND_URL` | `cloudflared` в PATH; опционально `-Port` |

---

## 1. `run-stage1-recon-svalbard.ps1`

**Назначение:** Оркестрация полного цикла Stage 1 разведки с проверками инфраструктуры, AI, MCP.

**Использование:**
```powershell
cd d:\Developer\Pentest_test\ARGUS
.\scripts\run-stage1-recon-svalbard.ps1
```

### Поток выполнения

```
[1/6] Docker containers check
      ├── Проверка: работает ли argus-backend контейнер?
      └── Если нет → запуск docker compose -f infra/docker-compose.yml up -d
          └── Ожидание 30 сек

[2/6] Backend health check
      ├── GET http://localhost:8000/api/v1/health
      └── Если недоступен → warning (отчёт генерируется локально)

[3/6] MCP availability check
      ├── Вызов .\scripts\ensure_mcp_server.ps1
      ├── Проверка: слушает ли localhost:8001?
      └── Если нет → попытка запустить argus_mcp.py
          └── Если всё ещё нет → warning (fallback к httpx)

[4/6] Stage 1 report generation
      ├── Вызов python .\scripts\run_stage1_report.py
      ├── Параметры: use_mcp=True (предпочитать MCP для fetch)
      └── Выход: JSON findings + HTML report

[5/6] Copy HTML report
      ├── Источник: pentest_reports_svalbard/recon/svalbard-stage1/stage1_report.html
      └── Целевая папка: pentest_reports_svalbard/stage1-svalbard.html

[6/6] PDF generation (опционально)
      ├── Если существует .\pentest_reports_svalbard\generate-pdf.ps1
      ├── Вызов: & $pdfScript -baseName "stage1-svalbard"
      └── Выход: pentest_reports_svalbard/stage1-svalbard.pdf
```

### Окружение

Скрипт использует переменные из `backend/.env`:
- **LLM keys** (OPENAI_API_KEY, DEEPSEEK_API_KEY, etc.) — включают AI анализ
- **Intel keys** (SHODAN_API_KEY, GITHUB_TOKEN, CENSYS_API_KEY, etc.) — включают доп. источники
- **Infra** (DATABASE_URL, REDIS_URL, etc.) — для подключения к backend

### Обработка ошибок

| Ошибка | Действие |
|--------|----------|
| Docker недоступен | Warning, пропуск контейнеров |
| Backend недоступен | Warning, отчёт генерируется локально |
| MCP недоступен | Warning, fallback к встроенным httpx запросам |
| Report generation failed | Exit 1 (критическая ошибка) |

---

## 2. `run_stage1_report.py`

**Назначение:** Core logic для генерации Stage 1 разведочного отчёта.

**Использование:**
```powershell
python .\scripts\run_stage1_report.py [--target TARGET] [--use-mcp] [--use-ai]
```

### Параметры

```
--target TARGET         : Целевой домен/IP (по умолчанию: svalbard.ca)
--use-mcp              : Использовать MCP для сетевых запросов (по умолчанию: False)
--use-ai               : Включить AI анализ (по умолчанию: если OPENAI_API_KEY установлен)
--use-intel            : Включить Intel адаптеры (по умолчанию: True)
--output-dir DIR       : Папка для output (по умолчанию: pentest_reports_svalbard/recon/svalbard-stage1)
```

### Логика

```python
1. Инициализация
   ├── Загрузка backend/.env
   ├── Инициализация логирования (JSON формат)
   └── Проверка доступности LLM и Intel API

2. Domain Enumeration
   ├── DNS A/AAAA/MX/TXT records (встроено)
   ├── WHOIS/RDAP lookup (встроено)
   ├── SSL certificate enumeration via crt.sh (встроено)
   ├── [опционально] SecurityTrails DNS history (если SECURITYTRAILS_API_KEY)
   └── [опционально] GitHub repo scan (если GITHUB_TOKEN)

3. IP & ASN Profiling
   ├── IP ownership via RDAP (встроено)
   ├── ASN/CIDR lookup (встроено)
   ├── [опционально] Shodan IP enum (если SHODAN_API_KEY)
   └── [опционально] GreyNoise context (если GREYNOISE_API_KEY)

4. Service Enumeration
   ├── HTTP probing на common ports (80, 443, 8000, 8443, ...)
   ├── TLS/SSL certificate parsing
   ├── Wappalyzer-like tech detection
   └── WAF detection (headers analysis)

5. Vulnerability Intelligence
   ├── CVE lookup by version (NVD API + vendor advisories)
   ├── [опционально] ExploitDB (если EXPLOITDB_API_KEY)
   ├── [опционально] Shodan CVE scoring (если SHODAN_API_KEY)
   └── [опционально] VirusTotal (если VIRUSTOTAL_API_KEY)

6. Threat & Reputation
   ├── [опционально] AbuseIPDB (если ABUSEIPDB_API_KEY)
   ├── [опционально] GreyNoise (если GREYNOISE_API_KEY)
   ├── [опционально] OTX IoCs (если OTX_API_KEY)
   └── [опционально] URLscan.io (если URLSCAN_API_KEY)

7. AI Analysis (если --use-ai и LLM ключ)
   ├── Anomaly detection (unusual ports, versions, etc.)
   ├── Threat hypothesis generation
   ├── Attack surface prioritization
   └── Remediation recommendations

8. Report Generation
   ├── JSON findings export
   └── HTML report (assets, findings, risk score)
```

### Выход

```
└── pentest_reports_svalbard/recon/svalbard-stage1/
    ├── stage1_report.html          # Визуальный отчёт
    ├── findings.json               # Структурированные находки
    ├── targets.json                # Метаданные целей
    └── stage1.log                  # Лог выполнения (JSON lines)
```

### Примеры вызовов

**Базовый (без AI, без MCP):**
```powershell
python .\scripts\run_stage1_report.py --target "example.com"
```

**С AI (требует OPENAI_API_KEY):**
```powershell
python .\scripts\run_stage1_report.py --target "example.com" --use-ai
```

**С MCP (для интеграции с agents/Cursor):**
```powershell
python .\scripts\run_stage1_report.py --target "example.com" --use-mcp --use-ai
```

---

## 3. `run_stage1_argus_mcp.py`

**Назначение:** MCP (Model Context Protocol) сервер для интеграции Stage 1 с LLM агентами (Cursor, Claude).

**Использование:**
```powershell
cd .\scripts
python run_stage1_argus_mcp.py --port 8002 --server http://localhost:8000
```

### Параметры

```
--port PORT            : Порт для MCP сервера (по умолчанию: 8002)
--server URL           : Backend API URL (по умолчанию: http://localhost:8000)
--log-level LEVEL      : Уровень логирования (DEBUG, INFO, WARNING, ERROR)
```

### MCP Tools

#### `stage1_scan(target, options)`
Запуск Stage 1 разведки на целевой домен/IP.

**Параметры:**
```json
{
  "target": "example.com",
  "options": {
    "use_ai": true,
    "use_intel": true,
    "use_mcp": true
  }
}
```

**Возврат:**
```json
{
  "status": "success",
  "scan_id": "uuid",
  "findings": [...],
  "risk_score": 7.5
}
```

#### `stage1_status(scan_id)`
Получить статус выполняющейся разведки.

#### `stage1_report(scan_id, format)`
Получить финальный отчёт (JSON или HTML).

### Интеграция с Cursor

В `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "argus-recon": {
      "command": "python",
      "args": [
        "d:/Developer/Pentest_test/ARGUS/scripts/run_stage1_argus_mcp.py",
        "--port", "8002",
        "--server", "http://localhost:8000"
      ],
      "env": {
        "ARGUS_SERVER_URL": "http://localhost:8000"
      },
      "description": "ARGUS Stage 1 Reconnaissance",
      "timeout": 600
    }
  }
}
```

Затем в Cursor можно использовать:
```
@stage1_scan target="svalbard.ca" use_ai=true
```

---

## 4. `ensure_mcp_server.ps1`

**Назначение:** Проверка доступности MCP сервера; запуск при необходимости.

**Использование:**
```powershell
.\scripts\ensure_mcp_server.ps1
```

### Поток

```
1. Проверка: слушает ли localhost:8001?
   ├── Если ДА → успех (MCP доступен)
   └── Если НЕТ → перейти к шагу 2

2. Попытка запуска argus_mcp.py
   ├── Проверка: существует ли ARGUS/mcp-server/argus_mcp.py?
   ├── Если ДА → Start-Process для запуска в фоне
   └── Если НЕТ → error (файл не найден)

3. Ожидание запуска (max 10 сек)
   ├── Проверка каждые 1 сек: слушает ли localhost:8001?
   ├── Если ДА → успех
   └── Если timeout → warning (MCP недоступен, используется fallback)
```

### Выход

```powershell
# Успех
[INFO] MCP server is available at http://localhost:8001

# Warning (MCP недоступен)
[WARN] MCP server is not available. Stage 1 will use built-in httpx for HTTP requests.
```

---

## 5. `diagnose-scan-stuck.ps1`

**Назначение:** Диагностика и логирование застревших сканирований.

**Использование:**
```powershell
# Диагностика всех сканирований
.\scripts\diagnose-scan-stuck.ps1

# Диагностика конкретного сканирования
.\scripts\diagnose-scan-stuck.ps1 -ScanId "uuid-of-scan"
```

### Логика

```
1. Получить список всех сканирований со статусом "Initializing"
   └── Фильтр: created_at > (now - 1 hour)

2. Для каждого сканирования:
   ├── Получить метаданные (target, scan_type, created_at)
   ├── Проверить статус Celery задачи
   ├── Проверить логи backend
   ├── Вывести стек вызовов (если доступно)
   └── Предложить решение

3. Общие причины и решения:
   ├── Celery worker не запущен → docker compose --profile tools up -d
   ├── ProgrammingError в Celery → пересборка контейнеров
   ├── Timeout в HTTP запросах → проверить целевой сервис
   └── Out of memory → рестарт worker
```

---

## Полный Flow: Stage 1 Reconnaissance

```
┌─────────────────────────────────────────────────────────────┐
│ User: .\scripts\run-stage1-recon-svalbard.ps1               │
└────────────────────────────────┬──────────────────────────────┘
                                 │
                                 ▼
    ┌──────────────────────────────────────────────────┐
    │ 1. Docker check: argus-backend up?              │
    │    NO → docker compose up -d (wait 30s)         │
    └────────────────┬─────────────────────────────────┘
                     │
                     ▼
    ┌──────────────────────────────────────────────────┐
    │ 2. Backend health: /api/v1/health               │
    │    FAIL → WARNING (report local-only)           │
    └────────────────┬─────────────────────────────────┘
                     │
                     ▼
    ┌──────────────────────────────────────────────────┐
    │ 3. MCP availability: localhost:8001?            │
    │    NO → ensure_mcp_server.ps1 (try to start)    │
    │    FAIL → WARNING (fallback to httpx)           │
    └────────────────┬─────────────────────────────────┘
                     │
                     ▼
    ┌──────────────────────────────────────────────────┐
    │ 4. Call: python run_stage1_report.py             │
    │    Params: use_mcp=True, use_ai=True (if key)   │
    │    Output: JSON + HTML                          │
    │    FAIL → EXIT 1 (error)                        │
    └────────────────┬─────────────────────────────────┘
                     │
                     ▼
    ┌──────────────────────────────────────────────────┐
    │ 5. Copy HTML to pentest_reports_svalbard/       │
    │    stage1-svalbard.html                         │
    └────────────────┬─────────────────────────────────┘
                     │
                     ▼
    ┌──────────────────────────────────────────────────┐
    │ 6. Generate PDF (if generate-pdf.ps1 exists)    │
    │    stage1-svalbard.pdf                          │
    │    (fallback: user opens HTML → Print as PDF)   │
    └──────────────────────────────────────────────────┘
```

---

## Переменные окружения

Все скрипты читают из `backend/.env`:

### LLM Providers (AI Orchestrator)
```env
OPENAI_API_KEY=
DEEPSEEK_API_KEY=
OPENROUTER_API_KEY=
GOOGLE_API_KEY=
KIMI_API_KEY=
PERPLEXITY_API_KEY=
```

### Intel Adapters (Stage 1 Intelligence)
```env
SHODAN_API_KEY=
GITHUB_TOKEN=
CENSYS_API_KEY=
SECURITYTRAILS_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
GREYNOISE_API_KEY=
OTX_API_KEY=
URLSCAN_API_KEY=
EXPLOITDB_API_KEY=
```

### Infrastructure
```env
DATABASE_URL=postgresql+asyncpg://...
REDIS_URL=redis://localhost:6379/0
CELERY_BROKER_URL=redis://localhost:6379/0
```

---

## Troubleshooting

### Проблема: Stage 1 зависает на "Initializing"

**Проверить:**
1. Запущен ли Celery worker?
   ```powershell
   docker logs argus-celery-worker
   ```

2. Есть ли ошибки в базе?
   ```powershell
   docker exec argus-postgres psql -U argus -c "SELECT * FROM scans WHERE status='Initializing' LIMIT 1;"
   ```

3. Используйте диагностику:
   ```powershell
   .\scripts\diagnose-scan-stuck.ps1
   ```

### Проблема: MCP сервер недоступен

**Решение:**
```powershell
# Вручную запустить MCP
cd ..\mcp-server
python argus_mcp.py --server http://localhost:8000

# Или через Docker (mcp-server входит в стек по умолчанию)
docker compose -f ../infra/docker-compose.yml up -d
```

### Проблема: Intel адаптеры не работают

**Проверить:**
1. Установлены ли ключи в `backend/.env`?
2. Доступны ли API сервисы (не заблокированы ли)?
3. Лимиты на API (rate limiting)?

Используйте:
```powershell
# Просмотреть логи backend
docker logs argus-backend | grep -i "intel\|adapter\|shodan\|github"
```

---

## Разработка и расширение

### Добавить новый Intel адаптер

1. Создать класс в `backend/src/recon/adapters/`
2. Зарегистрировать в `backend/src/recon/intel_manager.py`
3. Добавить env переменную в `.env.example`
4. Обновить таблицу сервисов выше

### Добавить новый Stage

1. Создать новый скрипт: `run-stage2-active-recon-*.ps1`
2. Добавить в `scripts/README.md` новый раздел
3. Обновить `docs/RUNNING.md` с информацией о новом Stage

---

## Конвенции

- **Логирование:** JSON format (парсируется машиной и человеком)
- **Ошибки:** Никогда не выводим stack traces пользователю (информационная утечка)
- **Пути:** Абсолютные для скриптов (проще отладка)
- **API ключи:** Не храним в кодах, только в .env и переменных окружения
- **Timeouts:** 30 сек для Docker start, 10 сек для MCP check, 300 сек для HTTP requests

