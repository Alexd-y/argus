# Stage 2 Threat Modeling — Quick Reference

**Дата:** 2026-03-12  
**Статус:** ✅ Production-Ready  
**Полная документация:** [recon-stage2-flow.md](./recon-stage2-flow.md)

---

## Быстрый старт (30 сек)

### 1. REST API Trigger

```bash
curl -X POST http://localhost:8000/recon/engagements/eng-123/threat-modeling/trigger \
  -H "Content-Type: application/json" \
  -d '{"target_id": "target-456"}'
```

**Результат:**
```json
{
  "run_id": "tm-run-789",
  "status": "completed",
  "artifact_refs": [
    {"artifact_type": "threat_model", "filename": "threat_model.md"},
    {"artifact_type": "critical_assets", "filename": "critical_assets.csv"},
    ...
  ]
}
```

### 2. CLI Trigger

```bash
argus-recon threat-modeling run --engagement eng-123 --recon-dir ./pentest_reports_svalbard/recon
```

**Результат:**
```
Created run tm-run-789 (job_id=job-456)
Threat modeling completed.
  Status: completed
  Artifacts: 12
```

### 3. Download Artifacts

```bash
# Скачать threat model
curl http://localhost:8000/recon/engagements/eng-123/threat-modeling/runs/tm-run-789/artifacts/threat_model/download \
  -o threat_model.md

# Скачать CSV
curl http://localhost:8000/recon/engagements/eng-123/threat-modeling/runs/tm-run-789/artifacts/critical_assets/download \
  -o critical_assets.csv
```

---

## Flow в 3 шага

```
1. Input Bundle        2. 9 AI Tasks        3. 12 Artifacts
   (Stage 1 data)      (Sequential)         (Human + JSON)
        ↓                   ↓                    ↓
 - Critical Assets    - critical_assets     - threat_model.md
 - Trust Boundaries   - trust_boundaries    - critical_assets.csv
 - Entry Points       - attacker_profiles   - entry_points.csv
 - URLs/Hostnames     - entry_points       - trust_boundaries.md
                      - app_flows          - attacker_profiles.csv
                      - threat_scenarios   - application_flows.md
                      - scenario_scoring   - threat_scenarios.csv
                      - testing_roadmap    - testing_priorities.md
                      - report_summary     - evidence_gaps.md
                                           - ai_reasoning_traces.json
                                           - mcp_trace.json
```

---

## 12 Типов артефактов

| # | Артефакт | Формат | Назначение |
|----|----------|--------|-----------|
| 1️⃣ | `threat_model.md` | Markdown | Интегрированный отчет |
| 2️⃣ | `critical_assets.csv` | CSV | Критичные активы |
| 3️⃣ | `entry_points.csv` | CSV | Точки входа |
| 4️⃣ | `trust_boundaries.md` | Markdown | Границы доверия |
| 5️⃣ | `attacker_profiles.csv` | CSV | Профили атакующих |
| 6️⃣ | `application_flows.md` | Markdown | Потоки приложения |
| 7️⃣ | `threat_scenarios.csv` | CSV | Сценарии угроз |
| 8️⃣ | `testing_priorities.md` | Markdown | Приоритеты тестирования |
| 9️⃣ | `evidence_gaps.md` | Markdown | Пробелы в доказательствах |
| 🔟 | `ai_reasoning_traces.json` | JSON | Все AI выходы |
| 1️⃣1️⃣ | `mcp_trace.json` | JSON | MCP audit log |
| 1️⃣2️⃣ | (reserved) | - | - |

---

## Блокирующие состояния

| Состояние | Что не так | Решение |
|-----------|-----------|---------|
| `missing_recon` | Stage 1 не запущена | `argus-recon run --engagement <id>` |
| `missing_stage1_artifacts` | Нет выходов Stage 1 | Переиспользовать Stage 1 |
| `insufficient_entry_points` | Слишком мало точек входа | Расширить scope в Stage 1 |
| `insufficient_critical_assets` | Нет активов | Уточнить цели в Stage 1 |

---

## 9 AI-задач (последовательно)

```
1. critical_assets        — Выявить критичные активы
2. trust_boundaries       — Нарисовать границы доверия
3. attacker_profiles      — Описать типы атакующих
4. entry_points          — Найти точки входа (с приоритетом)
5. application_flows     — Нарисовать потоки данных
6. threat_scenarios      — Построить сценарии угроз
7. scenario_scoring      — Оценить риск каждого сценария
8. testing_roadmap       — Создать план тестирования
9. report_summary        — Генерировать итоговый отчет
```

Каждая задача может использовать выходы предыдущих.

---

## API Endpoints (полный список)

### Create Run (без выполнения)
```
POST /recon/engagements/{engagement_id}/threat-modeling/runs
```

### Trigger (create + execute)
```
POST /recon/engagements/{engagement_id}/threat-modeling/trigger
```

### Execute (для существующего run)
```
POST /recon/engagements/{engagement_id}/threat-modeling/runs/{run_id}/execute
```

### Get Input Bundle
```
GET /recon/engagements/{engagement_id}/threat-modeling/runs/{run_id}/input-bundle
```

### Get AI Traces
```
GET /recon/engagements/{engagement_id}/threat-modeling/runs/{run_id}/ai-traces
```

### Get MCP Traces
```
GET /recon/engagements/{engagement_id}/threat-modeling/runs/{run_id}/mcp-traces
```

### Download Artifact
```
GET /recon/engagements/{engagement_id}/threat-modeling/runs/{run_id}/artifacts/{artifact_type}/download
```

---

## Hранилища артефактов

### MinIO (Production)
```
s3://argus-reports/threat_modeling/{engagement_id}/{run_id}/
├── threat_model.md
├── critical_assets.csv
├── ai_tm_critical_assets_normalized.json
└── ...
```

### File System (Dev)
```
pentest_reports_{engagement_id}/recon/threat_modeling/{run_id}/
├── threat_model.md
├── critical_assets.csv
├── ai_tm_critical_assets_normalized.json
└── ...
```

---

## Примеры кода

### Python (asyncio)

```python
from src.recon.threat_modeling.pipeline import execute_threat_modeling_run

result = await execute_threat_modeling_run(
    engagement_id="eng-123",
    run_id="tm-run-789",
    job_id="job-456",
    db=db
)
print(f"Status: {result.status}")
```

### Python (sync via subprocess)

```bash
python -m src.recon.cli threat-modeling run --engagement eng-123
```

### cURL (all endpoints)

```bash
# Trigger
curl -X POST http://localhost:8000/recon/engagements/eng-123/threat-modeling/trigger

# Get input bundle
curl http://localhost:8000/recon/engagements/eng-123/threat-modeling/runs/tm-run-789/input-bundle

# Download artifact
curl http://localhost:8000/.../artifacts/threat_model/download -o threat_model.md
```

---

## Отслеживание (Traceability)

Каждый run получает:
- **run_id**: уникальный ID (e.g., `tm-run-789`)
- **job_id**: связь со Stage 1 (e.g., `job-456`)
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

## Что дальше (Stage 3+)

После Stage 2:
- ✅ Threat Modeling завершен (12 артефактов)
- ⬜ Vulnerability Analysis (Stage 3)
- ⬜ Exploitation (Stage 4)
- ⬜ Post-Exploitation (Stage 5)
- ⬜ Reporting (Stage 6)

---

## Структура файлов для разработки

```
backend/
├── src/recon/threat_modeling/
│   ├── pipeline.py              # Main orchestration
│   ├── dependency_check.py       # Stage 1 readiness check
│   ├── input_loader.py           # Load input bundle
│   ├── mcp_enrichment.py         # MCP operations
│   ├── artifacts.py              # Generate artifacts
│   ├── ai_task_registry.py       # Task definitions
│   └── __init__.py
├── api/routers/recon/
│   └── threat_modeling.py        # REST endpoints
└── cli/commands/
    └── threat_modeling.py        # CLI command
```

---

**Полная документация:** [recon-stage2-flow.md](./recon-stage2-flow.md)
