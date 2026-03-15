# Stage 3 Vulnerability Analysis — Quick Reference

**Дата:** 2026-03-13  
**Статус:** ✅ Production-Ready  
**Полная документация:** [recon-stage3-flow.md](./recon-stage3-flow.md)

---

## Быстрый старт (30 сек)

### 1. REST API Trigger

```bash
curl -X POST http://localhost:8000/recon/engagements/eng-123/vulnerability-analysis/trigger \
  -H "Content-Type: application/json" \
  -d '{"target_id": "target-456"}'
```

**Результат:**
```json
{
  "run_id": "va-run-789",
  "status": "completed",
  "artifact_refs": [
    {"artifact_type": "vulnerability_analysis", "filename": "vulnerability_analysis.md"},
    {"artifact_type": "validation_targets", "filename": "validation_targets.csv"},
    ...
  ]
}
```

### 2. CLI Trigger

```bash
argus-recon vulnerability-analysis run --engagement eng-123 [--target t-1] [--recon-dir ./recon]
```

**Результат:**
```
Created run va-run-789 (job_id=job-456)
Vulnerability analysis completed.
  Status: completed
  Artifacts: 17
```

### 3. Download Artifacts

```bash
# Скачать vulnerability analysis report
curl http://localhost:8000/recon/engagements/eng-123/vulnerability-analysis/runs/va-run-789/artifacts/vulnerability_analysis/download \
  -o vulnerability_analysis.md

# Скачать validation targets (CSV)
curl http://localhost:8000/recon/engagements/eng-123/vulnerability-analysis/runs/va-run-789/artifacts/validation_targets/download \
  -o validation_targets.csv
```

---

## Flow в 3 шага

```
1. Input Bundle           2. 15 AI Tasks        3. 17 Artifacts
   (Stage 1+2 data)       (Sequential)          (Human + JSON)
        ↓                      ↓                    ↓
 - Threat scenarios   - validation_targets   - vulnerability_analysis.md
 - Entry points       - auth_surfaces        - validation_targets.csv
 - Critical assets    - authorization_checks - auth_surfaces.csv
 - Trust boundaries   - input_surface_checks - finding_candidates.csv
 - Testing roadmap    - route_workflows      - (15 normalized AI outputs)
 - Route inventory    - api_surface_checks   - ai_reasoning_traces.json
 - API surface        - resource_access      - mcp_trace.json
                      - frontend_logic
                      - security_controls
                      - anomalous_hosts
                      - trust_boundary_validation
                      - business_logic
                      - finding_correlation
                      - remediation_notes
                      - stage3_report_summary
```

---

## 17 Типов артефактов

| # | Артефакт | Формат | Назначение |
|----|----------|--------|-----------|
| 1️⃣ | `vulnerability_analysis.md` | Markdown | Интегрированный отчет |
| 2️⃣ | `validation_targets.csv` | CSV | Цели валидации |
| 3️⃣ | `auth_surfaces.csv` | CSV | Auth endpoints |
| 4️⃣ | `finding_candidates.csv` | CSV | Кандидаты на findings |
| 5️⃣-1️⃣9️⃣ | `ai_va_*_normalized.json` | JSON | 15 нормализованных AI выходов |
| 🔟 | `ai_reasoning_traces.json` | JSON | Все AI выходы |
| 1️⃣1️⃣ | `mcp_trace.json` | JSON | MCP audit log |

---

## Блокирующие состояния

| Состояние | Что не так | Решение |
|-----------|-----------|---------|
| `blocked_missing_stage1` | Stage 1 не запущена | `argus-recon run --engagement <id>` |
| `blocked_missing_stage2` | Stage 2 не запущена | `argus-recon threat-modeling run --engagement <id>` |
| `blocked_unlinked_stage_artifacts` | Нет связи между Stage 1/2 артефактами | Переиспользовать Stage 1/2 |
| `blocked_stage3_not_ready` | Coverage score < 0.3 (Stage 3 readiness) | Расширить Stage 1 recon |

---

## 15 AI-задач (последовательно)

```
1. validation_target_planning       — Планировать цели валидации
2. auth_surface_analysis            — Анализировать auth endpoints
3. authorization_analysis           — Проверить авторизацию
4. input_surface_analysis           — Анализировать input surfaces
5. route_and_workflow_analysis      — Анализировать маршруты/workflows
6. api_surface_analysis             — Анализировать API surface
7. resource_access_analysis         — Проверить доступ к ресурсам
8. frontend_logic_analysis          — Анализировать клиентскую логику
9. security_controls_analysis       — Оценить security controls
10. anomalous_host_analysis         — Анализировать аномальные hosts
11. trust_boundary_validation_analysis — Валидировать границы доверия
12. business_logic_analysis         — Анализировать business logic
13. finding_correlation             — Коррелировать findings
14. remediation_note_generation     — Генерировать заметки по remediation
15. stage3_report_summary           — Генерировать итоговый отчет
```

Каждая задача может использовать выходы предыдущих.

---

## API Endpoints (полный список)

### Create Run (без выполнения)
```
POST /recon/engagements/{engagement_id}/vulnerability-analysis/runs
```

### Trigger (create + execute)
```
POST /recon/engagements/{engagement_id}/vulnerability-analysis/trigger
```

### Execute (для существующего run)
```
POST /recon/engagements/{engagement_id}/vulnerability-analysis/runs/{run_id}/execute
```

### Get Readiness
```
GET /recon/engagements/{engagement_id}/vulnerability-analysis/readiness
```

### Get Input Bundle
```
GET /recon/engagements/{engagement_id}/vulnerability-analysis/runs/{run_id}/input-bundle
```

### Get AI Traces
```
GET /recon/engagements/{engagement_id}/vulnerability-analysis/runs/{run_id}/ai-traces
```

### Get MCP Traces
```
GET /recon/engagements/{engagement_id}/vulnerability-analysis/runs/{run_id}/mcp-traces
```

### Download Artifact
```
GET /recon/engagements/{engagement_id}/vulnerability-analysis/runs/{run_id}/artifacts/{artifact_type}/download
```

---

## Хранилища артефактов

### MinIO (Production)
```
s3://argus-reports/vulnerability_analysis/{engagement_id}/{run_id}/
├── vulnerability_analysis.md
├── validation_targets.csv
├── ai_va_validation_target_planning_normalized.json
├── ai_reasoning_traces.json
└── ...
```

### File System (Dev)
```
pentest_reports_{engagement_id}/recon/vulnerability_analysis/{run_id}/
├── vulnerability_analysis.md
├── validation_targets.csv
├── ai_va_validation_target_planning_normalized.json
├── ai_reasoning_traces.json
└── ...
```

---

## Примеры кода

### Python (asyncio)

```python
from src.recon.vulnerability_analysis.pipeline import execute_vulnerability_analysis_run

result = await execute_vulnerability_analysis_run(
    engagement_id="eng-123",
    run_id="va-run-789",
    job_id="job-456",
    db=db
)
print(f"Status: {result.status}")
```

### Python (sync via subprocess)

```bash
python -m src.recon.cli vulnerability-analysis run --engagement eng-123
```

### cURL (all endpoints)

```bash
# Trigger Stage 3
curl -X POST http://localhost:8000/recon/engagements/eng-123/vulnerability-analysis/trigger

# Get readiness
curl http://localhost:8000/recon/engagements/eng-123/vulnerability-analysis/readiness

# Get input bundle
curl http://localhost:8000/recon/engagements/eng-123/vulnerability-analysis/runs/va-run-789/input-bundle

# Download artifact
curl http://localhost:8000/.../artifacts/vulnerability_analysis/download -o report.md
```

---

## Отслеживание (Traceability)

Каждый run получает:
- **run_id**: уникальный ID (e.g., `va-run-789`)
- **job_id**: связь с Stage 2 (e.g., `job-456`)
- **trace_id**: корреляция логов (e.g., `trace-xyz123`)

Все артефакты содержат метаданные с этими ID для отслеживания.

---

## MCP Операции (если используется MCP enrichment)

| Операция | Назначение |
|----------|-----------|
| `fetch_url` | Получить содержимое страницы (timeout=5s) |
| `get_headers` | Получить headers сервера |
| `dns_query` | DNS resolve hostname |
| `check_service` | Проверить сервис (ping, port scan) |

**Policy:** fail-closed (денай по умолчанию, audit все вызовы)

---

## Fallback & Resilience

- **LLM недоступен**: используется rule-based fallback (генерирует артефакты из bundle)
- **Timeout задачи**: 60 сек per task, если превышено → fallback
- **Повторный запуск**: система пропускает уже завершенные задачи

---

## Что дальше (Stage 4+)

После Stage 3:
- ✅ Recon завершен (Stage 1)
- ✅ Threat Modeling завершен (Stage 2, 12 артефактов)
- ✅ Vulnerability Analysis завершен (Stage 3, 17 артефактов)
- ⬜ Exploitation (Stage 4)
- ⬜ Post-Exploitation (Stage 5)
- ⬜ Reporting (Stage 6)

---

## Структура файлов для разработки

```
backend/
├── src/recon/vulnerability_analysis/
│   ├── pipeline.py                 # Main orchestration
│   ├── dependency_check.py          # Stage 1/2 readiness check
│   ├── input_loader.py              # Load input bundle from Stage 1/2
│   ├── mcp_enrichment.py            # MCP operations
│   ├── artifacts.py                 # Generate artifacts
│   ├── ai_task_registry.py          # 15 task definitions
│   └── __init__.py
├── app/schemas/vulnerability_analysis/
│   ├── schemas.py                   # Main schemas
│   ├── ai_tasks.py                  # AI task input/output models
│   └── __init__.py
├── app/prompts/
│   └── vulnerability_analysis_prompts.py  # 15 prompt templates
├── api/routers/recon/
│   └── vulnerability_analysis.py    # REST endpoints
└── cli/commands/
    └── vulnerability_analysis.py    # CLI command
```

---

**Полная документация:** [recon-stage3-flow.md](./recon-stage3-flow.md)
