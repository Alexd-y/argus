# Recon Stage 1 Flow (Upgraded)

Документ фиксирует фактический Stage 1 flow в `backend/src/recon/**` после REC-108/REC-109 и REC-002..REC-010.

## 1) Новые артефакты (REC-002..REC-008)

Машиночитаемые артефакты для Stage 2 (Threat Modeling) и MinIO:

| Артефакт | Описание | Источник |
|----------|----------|----------|
| **recon_results.json** | Унифицированный JSON: DNS (A, AAAA, CNAME, MX, TXT, NS) для domain + subdomains; WHOIS; SSL certs (CN, SANs, Issuer, Validity) для HTTPS hosts; tech stack (Wappalyzer/Server headers); HTTP headers analysis | `backend/src/recon/reporting/recon_results_builder.py` |
| **mcp_trace.jsonl** | Audit log: timestamp, tool_name, input_parameters (incl target), output_summary (или error status), run_id, job_id. Post-process из `mcp_invocation_audit.jsonl` | `backend/src/recon/mcp/audit.py` → `build_mcp_trace_from_audit()` |
| **raw_tool_outputs/** | subfinder_output.json/txt, httpx_output.json, nuclei_output_initial.json — копии из 02_subdomains, 04_live_hosts, 14_content | `backend/src/recon/reporting/raw_outputs_builder.py` → `aggregate_raw_tool_outputs()` |
| **tech_profile.json** | JSON-версия tech_profile.csv (httpx + wappalyzer) | `backend/src/recon/reporting/tech_builder.py` → `build_tech_profile_json()` |

## 2) Layout `artifacts/stage1/{scan_id}/` (REC-008)

При вызове `generate_stage1_report(..., artifacts_base=Path)` артефакты копируются в:

```
artifacts_base/
  stage1/
    {scan_id}/
      recon_results.json
      tech_profile.json
      mcp_trace.jsonl
      anomalies_structured.json
      raw_tool_outputs/
        subfinder_output.json  (или .txt)
        httpx_output.json
        nuclei_output_initial.json  (если есть)
```

- `scan_id` = `run_id` = `recon_dir.name` (например `svalbard-stage1`)
- CLI: `argus report stage1 <recon_dir> --artifacts-base <path>`

## 3) MinIO bucket `stage1-artifacts` (REC-007)

- **Bucket:** `stage1-artifacts` (конфиг: `settings.stage1_artifacts_bucket`)
- **Object key pattern:** `{scan_id}/{filename}` или `{scan_id}/raw_tool_outputs/{filename}`

| Object Key | Описание |
|------------|----------|
| `{scan_id}/recon_results.json` | ReconResults schema |
| `{scan_id}/tech_profile.json` | Tech profile JSON |
| `{scan_id}/mcp_trace.jsonl` | MCP trace (McpTraceEvent schema) |
| `{scan_id}/anomalies_structured.json` | Anomalies structured |
| `{scan_id}/raw_tool_outputs/subfinder_output.*` | Subfinder raw output |
| `{scan_id}/raw_tool_outputs/httpx_output.json` | Httpx raw output |
| `{scan_id}/raw_tool_outputs/nuclei_output_initial.json` | Nuclei output (если safe mode) |

Metadata объектов: `scan_id`, `run_id`, `job_id`, `generated_at`.

Реализация: `backend/src/recon/stage1_storage.py` → `upload_stage1_artifacts()`.

## 4) Где работает MCP allowlist policy

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

## 5) Какие AI tasks выполняются и какие артефакты пишутся

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

## 6) Evidence model (Evidence / Observation / Inference / Hypothesis)

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

## 7) Traceability model (run/job/trace + MCP traces + AI bundles)

Базовая связка:

- `run_id`
- `job_id`
- `run_link` = `recon://runs/<run_id>`
- `job_link` = `recon://jobs/<job_id>`
- `trace_id`

Где фиксируется:

- `stage1_contract_baseline.json` (contract snapshot)
- `mcp_invocation_audit_meta.json` и `mcp_invocation_audit.jsonl` (MCP invocation trace)
- `mcp_trace.jsonl` (post-processed MCP trace для evidence_trace.mcp_trace_refs)
- `recon_results.json`, `tech_profile.json` (в metadata MinIO: run_id, job_id)
- каждый `ai_<task>_{raw|normalized|input_bundle|validation}.json`
- `ai_persistence_manifest.json`

Правило линковки:

- для AI bundle trace расширяется до task-уровня (`<trace_id>:<task_name>`)
- `evidence_trace.mcp_trace_refs` содержит ссылки на `mcp_trace.jsonl` и MCP audit artifacts

## 8) Как Stage 1 готовит Stage 2 Threat Modeling

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

## 9) Контрактные файлы Stage 1

Source of truth по Stage 1 contract:

- `backend/src/recon/reporting/stage1_contract.py`
  - `STAGE1_BASELINE_ARTIFACTS`
  - `STAGE1_REPORT_SECTIONS`
  - `build_stage1_contract_snapshot(...)`

Синхронизация на уровне пайплайна:

- `backend/src/recon/reporting/stage1_report_generator.py`
  - `STAGE1_OUTPUTS = list(STAGE1_BASELINE_ARTIFACTS)`

