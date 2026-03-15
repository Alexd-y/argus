# Recon Stage 1 Flow (Upgraded)

Документ фиксирует фактический Stage 1 flow в `backend/src/recon/**` после REC-108/REC-109.

## 1) Где работает MCP allowlist policy

Policy и fail-closed контроль реализованы в:

- `backend/src/recon/mcp/policy.py`
  - `RECON_STAGE1_ALLOWED_TOOLS`
  - `RECON_STAGE1_ALLOWED_OPERATIONS`
  - `evaluate_recon_stage1_policy(...)`
  - `sanitize_args(...)`
- `backend/src/recon/mcp/client.py`
  - `fetch_url_mcp(...)` всегда проверяет policy до вызова MCP
  - deny/failure возвращаются без утечки внутренних деталей (`notes`: `mcp_operation_denied_by_policy` / `mcp_fetch_failed`)
- `backend/src/recon/mcp/audit.py`
  - `record_mcp_invocation(...)` пишет структурированный audit event (JSONL) с `run_id/job_id/trace_id`
  - `write_mcp_audit_meta(...)` пишет linkage meta

Файлы аудита, ожидаемые контрактом Stage 1:

- `mcp_invocation_audit.jsonl`
- `mcp_invocation_audit_meta.json`

## 2) Какие AI tasks выполняются и какие артефакты пишутся

Реестр 7 задач:

- `backend/app/schemas/ai/schema_export.py` (`RECON_AI_TASKS`)

Схемы и linkage primitives:

- `backend/app/schemas/ai/common.py`
  - `ReconAiTask`
  - `ReportSectionId`
  - `StatementType`
  - `TaskRunMetadata`

Запуск Stage 1 enrichment и persistence:

- `backend/src/recon/reporting/stage1_enrichment_builder.py`
  - `build_stage1_enrichment_artifacts(...)`
  - `_persist_ai_task(...)`

Для каждой из 7 задач пишется полный bundle:

- `ai_<task>_raw.json`
- `ai_<task>_normalized.json`
- `ai_<task>_input_bundle.json`
- `ai_<task>_validation.json`
- `ai_<task>_rendered_prompt.md`

Манифест по всем AI bundle артефактам:

- `ai_persistence_manifest.json`

Экспорт JSON schema реестра:

- `export_recon_ai_schemas(...)` -> `recon_ai_tasks.schemas.json`

## 3) Evidence model (Evidence / Observation / Inference / Hypothesis)

Источник истины по типам утверждений:

- `backend/app/schemas/ai/common.py` -> `StatementType`
  - `observation`
  - `inference`
  - `hypothesis`

Практика в Stage 1 markdown/AI outputs:

- Evidence: ссылки `evidence_ref` / `evidence_refs` на Stage 1 артефакты
- Observation/Inference/Hypothesis: классифицированные statements в AI normalized outputs
- Для non-hypothesis statements `evidence_refs` обязательны (валидация схемами)

Где это используется в отчете:

- `backend/src/recon/reporting/html_report_builder.py` (badge taxonomy)
- `backend/src/recon/reporting/stage1_enrichment_builder.py` (формирование markdown и AI outputs)

## 4) Traceability model (run/job/trace + MCP traces + AI bundles)

Базовая связка:

- `run_id`
- `job_id`
- `run_link` = `recon://runs/<run_id>`
- `job_link` = `recon://jobs/<job_id>`
- `trace_id`

Где фиксируется:

- `stage1_contract_baseline.json` (contract snapshot)
- `mcp_invocation_audit_meta.json` и `mcp_invocation_audit.jsonl` (MCP invocation trace)
- каждый `ai_<task>_{raw|normalized|input_bundle|validation}.json`
- `ai_persistence_manifest.json`

Правило линковки:

- для AI bundle trace расширяется до task-уровня (`<trace_id>:<task_name>`)
- `evidence_trace.mcp_trace_refs` содержит ссылки на MCP audit artifacts

## 5) Как Stage 1 готовит Stage 2 Threat Modeling

Генерация Stage 1 выполняется в:

- `backend/src/recon/reporting/stage1_report_generator.py` -> `generate_stage1_report(...)`

Ключевые Stage 2-ready outputs:

- `stage2_preparation.md` (из `stage1_enrichment_builder.py`)
- `ai_stage2_preparation_summary_*` (полный AI bundle для секции Stage 2 prep)
- `anomaly_validation.md`, `anomaly_validation.csv`
- `content_clusters.csv`, `redirect_clusters.csv`, `hostname_behavior_matrix.csv`
- `frontend_backend_boundaries.md`, `app_flow_hints.md`
- `stage2_inputs.md`, `stage2_structured.json` (из `backend/src/recon/reporting/stage2_builder.py`)

Важно по порядку генерации:

- `stage2_preparation.md` и AI stage2 summary формируются в enrichment шаге.
- `stage2_inputs.md` формируется отдельным шагом `stage2_builder` в том же пайплайне.
- При повторном запуске Stage 1 enrichment `stage2_inputs.md` может включаться в source artifacts AI task `stage2_preparation_summary`.

## 6) Контрактные файлы Stage 1

Source of truth по Stage 1 contract:

- `backend/src/recon/reporting/stage1_contract.py`
  - `STAGE1_BASELINE_ARTIFACTS`
  - `STAGE1_REPORT_SECTIONS`
  - `build_stage1_contract_snapshot(...)`

Синхронизация на уровне пайплайна:

- `backend/src/recon/reporting/stage1_report_generator.py`
  - `STAGE1_OUTPUTS = list(STAGE1_BASELINE_ARTIFACTS)`

