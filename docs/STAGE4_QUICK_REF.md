# Stage 4 Exploitation — Quick Reference

**Дата:** 2026-03-19  
**Статус:** ✅ Production-Ready  
**Полная документация:** [recon-stage4-flow.md](./recon-stage4-flow.md)

---

## Быстрый старт (30 сек)

### 1. REST API — Запустить эксплуатацию

```bash
curl -X POST http://localhost:8000/api/v1/recon/engagements/eng-123/exploitation/run \
  -H "Content-Type: application/json" \
  -d '{}'

# Результат:
{
  "run_id": "exp-run-789",
  "status": "pending",
  "job_id": "job-789",
  "created_at": "2026-03-19T10:00:00Z"
}
```

### 2. REST API — Проверить статус

```bash
curl http://localhost:8000/api/v1/recon/engagements/eng-123/exploitation/status?run_id=exp-run-789

# Результат:
{
  "run_id": "exp-run-789",
  "status": "running",
  "progress": { "total": 10, "completed": 3, "successful": 2 }
}
```

### 3. REST API — Получить результаты

```bash
curl http://localhost:8000/api/v1/recon/engagements/eng-123/exploitation/results?run_id=exp-run-789

# Результат:
{
  "run_id": "exp-run-789",
  "status": "completed",
  "stage4_results": { /* full results */ },
  "shells": { /* shell sessions */ },
  "artifact_refs": [ /* 4 artifacts */ ]
}
```

### 4. REST API — Скачать артефакт

```bash
# Скачать exploitation plan
curl http://localhost:8000/api/v1/recon/engagements/eng-123/exploitation/artifacts/exploitation_plan \
  ?run_id=exp-run-789 \
  -o exploitation_plan.json

# Скачать results
curl http://localhost:8000/api/v1/recon/engagements/eng-123/exploitation/artifacts/stage4_results \
  ?run_id=exp-run-789 \
  -o stage4_results.json
```

---

## Flow в 4 шага

```
1. Load Candidates      2. Exploit Planner    3. Policy Engine       4. Execute & Collect
   (Stage 3 output)        (sort & tools)       (scope, rules)          (docker sandbox)
        ↓                        ↓                      ↓                      ↓
exploitation_candidates. AttackPlans      Allowed/Blocked/  → Async Tasks (Celery)
json (10 vulns)          (prioritized)    NeedsApproval        ↓
                                                             Tool Adapters:
                                                             - Metasploit (CVE)
                                                             - SQLMap (SQLi)
                                                             - Nuclei (CVE verify)
                                                             - Hydra (brute force)
                                                             - Custom (IDOR, etc.)
                                                             ↓
                                                         4 Artifacts
                                                         (plans, results,
                                                          shells, summary)
```

---

## Артефакты Stage 4 (4 типа)

| # | Артефакт | Формат | Содержание |
|---|----------|--------|-----------|
| 1️⃣ | `exploitation_plan.json` | JSON | Все AttackPlans (после приоритизации & политик) |
| 2️⃣ | `stage4_results.json` | JSON | Результаты: статус, доказательства, данные для каждого кандидата |
| 3️⃣ | `shells.json` | JSON | Активные shell-сеансы, полученные во время эксплуатации |
| 4️⃣ | `ai_exploitation_summary.json` | JSON | AI-сгенерированный summary + recommendations |

### stage4_results.json — schema

```json
{
  "scan_id": "scan-123",
  "total_candidates": 10,
  "successful": 3,
  "failed": 5,
  "blocked": 2,
  "results": [
    {
      "candidate_id": "cand-001",
      "target_url": "https://example.com/api/users/{id}",
      "vulnerability_type": "idor",
      "tool_used": "custom_script",
      "status": "success|failed|timeout|blocked|pending_approval",
      "proof": "User IDs 1-100 accessible without auth",
      "evidence_refs": ["screenshot.png", "request.txt"],
      "shell_info": null,
      "extracted_data": { "user_ids": [1,2,3,...] },
      "error_message": null
    }
  ]
}
```

### shells.json — schema

```json
{
  "shells": [
    {
      "type": "reverse|bind",
      "protocol": "tcp",
      "address": "192.168.1.100:4444",
      "session_id": "meterpreter_session_1"
    }
  ]
}
```

---

## Блокирующие состояния

| Состояние | Проблема | Решение |
|-----------|----------|---------|
| `blocked_missing_stage3` | Stage 3 не запущена | Запустить Stage 3 первым |
| `blocked_no_candidates` | `exploitation_candidates.json` пуста | Stage 3 не обнаружила уязвимости |
| `blocked_invalid_candidates` | Кандидаты не проходят валидацию | Переиспользовать Stage 3 |

---

## 5 Tool Adapters

| Адаптер | Инструмент | Типы уязвимостей | Описание |
|---------|-----------|------------------|----------|
| **MetasploitAdapter** | Metasploit | `cve` | Эксплуатация известных CVE (RCE, LFI, etc.) |
| **SQLMapAdapter** | SQLMap | `sql_injection` | SQL injection testing & exploitation |
| **NucleiAdapter** | Nuclei | `cve`, `xss`, `ssrf`, `misconfiguration` | CVE verification, web vulnerability scanning |
| **HydraAdapter** | Hydra | `weak_password` | Brute force, default credentials |
| **CustomScriptAdapter** | Python scripts | `idor`, `business_logic`, `other` | Custom exploits (IDOR enumeration, etc.) |

---

## Policy Engine — 3 проверки

### 1. Scope Check

```python
# Проверяет: находится ли целевой URL в scope?
allowed_domains = ["example.com", "*.example.com"]
target_url = "https://api.example.com/users"
# ✅ Allowed (in scope)

target_url = "https://evil.com/users"
# ❌ Blocked (out of scope)
```

### 2. Destructive Commands Check

```python
# Блокирует опасные паттерны:
BLOCKED_PATTERNS = [
    "--drop",           # SQLMap
    "rm -rf",           # Shell
    "DROP TABLE",       # SQL
    "shutdown",
    "reboot",
    ":(){",             # Fork bomb
]
```

### 3. DoS Risk Check

```python
# Флаги DoS для brute-force инструментов:
DOS_RISK_TOOLS = ["hydra", "medusa", "hping3"]
DOS_RISK_FLAGS = ["--flood", "-t 64", "--threads 64"]

# Пример: hydra с --threads 64 → needs_approval
```

---

## Approval Workflow

```
1. Высокорисковая атака обнаружена
   ├─ Risk level: critical или high
   └─ Tool: в HIGH_RISK_TYPES (cve, sql_injection, ssrf)

2. Создать ApprovalRequest
   ├─ candidate_id, target_url, proposed_command
   └─ status: "pending"

3. Оператор проверяет
   └─ GET /exploitation/approvals → список pending

4. Оператор действует
   ├─ POST /approvals/{id}/approve → execute immediately
   └─ POST /approvals/{id}/reject → skip execution

5. Timeout (1 час)
   └─ Auto-reject if no response
```

### API — Ожидающие одобрения

```bash
GET /api/v1/recon/engagements/eng-123/exploitation/approvals

{
  "pending": [
    {
      "id": "approval-123",
      "candidate_id": "cand-001",
      "target_url": "https://example.com/vulnerable",
      "attack_type": "CVE-XXXX-XXXXX",
      "risk_level": "critical",
      "proposed_command": "msfconsole -d /tmp/msf.db ...",
      "created_at": "2026-03-19T10:00:00Z"
    }
  ]
}
```

### API — Одобрить атаку

```bash
POST /api/v1/recon/engagements/eng-123/exploitation/approvals/approval-123/approve

{
  "approved_by": "operator@example.com",
  "notes": "Proceed"
}
```

### API — Отклонить атаку

```bash
POST /api/v1/recon/engagements/eng-123/exploitation/approvals/approval-123/reject

{
  "rejected_by": "operator@example.com",
  "reason": "Out of scope"
}
```

---

## API Endpoints (полный список)

### Launch Exploitation

```
POST /api/v1/recon/engagements/{engagement_id}/exploitation/run
```

**Request:**
```json
{
  "candidate_filter": "high_confidence",  // optional
  "auto_approve_high_risk": false,        // optional
  "max_concurrent": 5,                    // optional
  "timeout_minutes": 10                   // optional
}
```

**Response 202:**
```json
{
  "run_id": "exp-run-789",
  "status": "pending",
  "job_id": "job-789"
}
```

### Check Status

```
GET /api/v1/recon/engagements/{engagement_id}/exploitation/status?run_id=exp-run-789
```

**Response 200:**
```json
{
  "run_id": "exp-run-789",
  "status": "running",
  "progress": { "total": 10, "completed": 3, "successful": 2, "failed": 1 }
}
```

### Get Results

```
GET /api/v1/recon/engagements/{engagement_id}/exploitation/results?run_id=exp-run-789
```

**Response 200:**
```json
{
  "run_id": "exp-run-789",
  "status": "completed",
  "stage4_results": { /* full results */ },
  "shells": { /* shell sessions */ },
  "artifact_refs": [ /* 4 artifacts */ ]
}
```

### List Pending Approvals

```
GET /api/v1/recon/engagements/{engagement_id}/exploitation/approvals
```

### Approve Exploitation

```
POST /api/v1/recon/engagements/{engagement_id}/exploitation/approvals/{approval_id}/approve
```

### Reject Exploitation

```
POST /api/v1/recon/engagements/{engagement_id}/exploitation/approvals/{approval_id}/reject
```

### Download Artifact

```
GET /api/v1/recon/engagements/{engagement_id}/exploitation/artifacts/{artifact_type}?run_id=exp-run-789
```

**Artifact types:**
- `exploitation_plan`
- `stage4_results`
- `shells`
- `ai_exploitation_summary`

---

## CLI Commands

### Запустить эксплуатацию (Python CLI)

```bash
# Простейший запуск
python -m src.recon.cli exploitation run --engagement eng-123

# С фильтром кандидатов
python -m src.recon.cli exploitation run --engagement eng-123 --filter high_confidence

# С явным recon-dir
python -m src.recon.cli exploitation run \
  --engagement eng-123 \
  --recon-dir ./pentest_reports_svalbard/recon

# Результат:
Created run exp-run-789 (job_id=job-789)
Exploitation started.
  Status: running
  Progress: 3/10 completed
```

---

## Sandbox & Docker

### Docker Container

**Сборка образа:**

```powershell
# Базовая сборка (без Metasploit)
cd ARGUS
docker build -f sandbox/Dockerfile -t argus-exploits:latest .

# С Metasploit (~1.5 GB, опционально)
docker build -f sandbox/Dockerfile --build-arg INSTALL_MSF=true -t argus-exploits:latest .
```

**Запуск:**

```powershell
# С Docker Compose (рекомендуется)
docker compose -f infra/docker-compose.yml --profile tools up -d

# Или отдельно
docker run -d --name argus-exploit-sandbox \
  -v ./plugins/exploit_scripts:/opt/exploit_scripts:ro \
  -e ARGUS_SANDBOX=true \
  --cpus 2 --memory 2gb \
  argus-exploits:latest tail -f /dev/null
```

**Проверка и healthcheck:**

```powershell
# Проверить, что контейнер запущен
docker ps | grep argus-exploit-sandbox

# Выполнить healthcheck
docker exec argus-exploit-sandbox sqlmap --version
docker exec argus-exploit-sandbox nuclei -version
docker exec argus-exploit-sandbox hydra -version

# Проверить логи
docker logs argus-exploit-sandbox
```

**Информация о контейнере:**

```
Container name: argus-exploit-sandbox
Image: argus-exploits:latest
CPU limits: 2 cores
Memory limits: 2 GB

Установленные инструменты (Stage 4):
- SQLMap — SQL injection testing
- Nuclei — CVE verification, web scanning
- Hydra — Brute force, weak passwords
- Metasploit Framework (опционально)
- Python 3 + custom exploit scripts

MinIO buckets:
- stage4-artifacts — exploitation results
```

### Execution Flow

```
┌─────────────────────────────────────┐
│ 1. Celery Worker picks up task      │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│ 2. Select Tool Adapter              │
│    (Metasploit, SQLMap, etc.)       │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│ 3. Build Command                    │
│    (add flags, urls, params)        │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│ 4. Execute in Docker                │
│    docker exec argus-exploit-...    │
│    [command]                        │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│ 5. Parse Output                     │
│    (extract results, evidence)      │
└──────────────┬──────────────────────┘
               ↓
┌─────────────────────────────────────┐
│ 6. Store Result                     │
│    (status, proof, shells, data)    │
└─────────────────────────────────────┘
```

**Timeout:** 600 сек (10 минут) per command

---

## Хранилища артефактов

### MinIO (Production)

```
Bucket: stage4-artifacts

s3://stage4-artifacts/
  └── {scan_id}/
      ├── exploitation_plan.json
      ├── stage4_results.json
      ├── shells.json
      ├── ai_exploitation_summary.json
      └── evidence/
          ├── screenshot_001.png
          ├── request_001.txt
          └── ...
```

### File System (Dev)

```
pentest_reports_{engagement_id}/recon/exploitation/{run_id}/
├── exploitation_plan.json
├── stage4_results.json
├── shells.json
├── ai_exploitation_summary.json
└── evidence/
    └── ...
```

---

## Configuration

### Environment Variables

```bash
# Sandbox
SANDBOX_ENABLED=true
SANDBOX_CONTAINER_NAME=argus-exploit-sandbox

# Timeouts
EXPLOIT_TIMEOUT_SECONDS=600
EXPLOIT_MAX_CONCURRENT=5

# Approval
APPROVAL_TIMEOUT_MINUTES=60
AUTO_APPROVE_LOW_RISK=false

# Storage
STAGE4_ARTIFACTS_BUCKET=stage4-artifacts
MINIO_ENDPOINT=http://localhost:9000
```

---

## Troubleshooting

### Статус: `pending` → `running` → `completed`?

```bash
# Проверить статус
curl http://localhost:8000/.../exploitation/status?run_id=exp-run-789

# Если зависает в "running":
# 1. Проверить Celery worker логи
docker logs argus-celery-worker

# 2. Проверить Docker контейнер песочницы
docker ps | grep argus-exploit-sandbox
docker logs argus-exploit-sandbox

# 3. Увеличить timeout
POST /exploitation/run
{
  "timeout_minutes": 30
}
```

### Ошибка: `blocked_missing_stage3`

```bash
# Stage 3 не запущена
# Решение:
argus-recon vulnerability-analysis run --engagement eng-123
```

### Ошибка: `blocked_no_candidates`

```bash
# Stage 3 завершилась, но кандидатов не обнаружила
# Причины:
# - Все уязвимости были отфильтрованы
# - Недостаточный coverage в Stage 1
# Решение:
argus-recon vulnerability-analysis run --engagement eng-123 --extend-scope
```

### Approval Request Timeout

```bash
# Если одобрение ожидается > 1 часа, запрос истекает (статус: "expired")
# Решение:
# 1. Создать новый запрос
# 2. Или переиспользовать Stage 4 с auto_approve_low_risk=false

POST /exploitation/run
{
  "auto_approve_high_risk": true  # (осторожно!)
}
```

### Sandbox Container Not Running

```bash
# Проверить:
docker ps | grep argus-exploit-sandbox

# Если контейнер не запущен, запустить:
docker run -d --name argus-exploit-sandbox -v /pentests:/pentests argus-exploits:latest

# Или перезапустить:
docker restart argus-exploit-sandbox
```

### Tool Adapter Error

```bash
# Пример: SQLMap adapter не может подключиться к целевому URL
# Логи:
docker logs argus-exploit-sandbox | grep sqlmap

# Решение:
# 1. Проверить, что целевой URL доступен с точки зрения Docker контейнера
# 2. Проверить network connectivity
# 3. Проверить scope (Policy Engine может заблокировать)
```

---

## Примеры

### Python (Programmatic)

```python
from src.recon.exploitation.pipeline import execute_exploitation_run
from src.db.session import async_session_factory

async def run_stage4():
    async with async_session_factory() as db:
        result = await execute_exploitation_run(
            engagement_id="eng-123",
            run_id="exp-run-789",
            job_id="job-789",
            db=db,
            max_concurrent=5,
            timeout_minutes=10
        )
        print(f"Status: {result.status}")
        print(f"Successful: {result.successful}/{result.total_candidates}")
        for artifact_ref in result.artifact_refs:
            print(f"  - {artifact_ref.artifact_type}: {artifact_ref.filename}")
```

### cURL

```bash
# 1. Launch
curl -X POST http://localhost:8000/api/v1/recon/engagements/eng-123/exploitation/run \
  -H "Content-Type: application/json" -d '{}'

# 2. Poll status
curl http://localhost:8000/api/v1/recon/engagements/eng-123/exploitation/status?run_id=exp-run-789

# 3. Get results
curl http://localhost:8000/api/v1/recon/engagements/eng-123/exploitation/results?run_id=exp-run-789 \
  | jq '.stage4_results'

# 4. Download artifacts
curl http://localhost:8000/api/v1/recon/engagements/eng-123/exploitation/artifacts/stage4_results?run_id=exp-run-789 \
  -o stage4_results.json
```

---

## Отслеживание (Traceability)

Каждый run получает:

- **run_id**: уникальный ID (e.g., `exp-run-789`)
- **job_id**: связь со Stage 3 (e.g., `job-789`)
- **trace_id**: корреляция логов (e.g., `trace-xyz123`)

Все артефакты содержат эти ID для отслеживания:

```json
{
  "scan_id": "scan-123",
  "run_id": "exp-run-789",
  "job_id": "job-789",
  "trace_id": "trace-xyz123",
  ...
}
```

---

## Что дальше (Stage 5+)

После Stage 4:

- ✅ Recon завершен (Stage 1)
- ✅ Threat Modeling завершен (Stage 2)
- ✅ Vulnerability Analysis завершен (Stage 3)
- ✅ Exploitation завершен (Stage 4, 4 артефакта)
- ⬜ Post-Exploitation (Stage 5) — дальнейшее расширение доступа
- ⬜ Reporting (Stage 6) — финальный отчет

---

## Структура файлов

```
backend/
├── src/recon/exploitation/
│   ├── __init__.py
│   ├── dependency_check.py       # Stage 3 readiness
│   ├── input_loader.py           # Load candidates
│   ├── planner.py                # Exploit planner
│   ├── policy_engine.py          # Policy checks
│   ├── executor.py               # Sandbox execution
│   ├── pipeline.py               # Main orchestration
│   ├── artifacts.py              # Generate artifacts
│   └── adapters/
│       ├── __init__.py
│       ├── base.py               # Base adapter
│       ├── metasploit_adapter.py # Metasploit
│       ├── sqlmap_adapter.py     # SQLMap
│       ├── nuclei_adapter.py     # Nuclei
│       ├── hydra_adapter.py      # Hydra
│       └── custom_script_adapter.py  # Custom
├── app/schemas/exploitation/
│   ├── __init__.py
│   ├── models.py                 # AttackPlan, ExploitationResult, etc.
│   └── requests.py               # API request schemas
├── src/api/routers/recon/
│   └── exploitation.py           # REST endpoints (7 endpoints)
└── alembic/versions/
    └── 008_add_exploitation_models.py  # DB migration
```

---

**Полная документация:** [recon-stage4-flow.md](./recon-stage4-flow.md)
