# Reporting (ARGUS) — RPT-010

End-to-end **stage 5 — `reporting` phase** in the [6-phase scan lifecycle](./scan-state-machine.md): recon → threat_modeling → vuln_analysis → exploitation → post_exploitation → **reporting**. Tracks **RPT-003 … RPT-010** (data collection, AI sections, Celery, templates, PDF, API, docs).

**Code root:** `ARGUS/backend/` — Python modules below are `backend/src/...`.

---

## Architecture overview

```mermaid
flowchart LR
  API["POST /api/v1/scans/{id}/reports/generate"]
  T["Celery: argus.generate_report"]
  DC["ReportDataCollector → ScanReportData"]
  RG["ReportGenerator"]
  AI["run_ai_text_generation / argus.ai_text_generation"]
  GEN["generate_html | pdf | json | csv"]
  S3["MinIO: MINIO_REPORTS_BUCKET"]
  API --> T
  T --> DC
  DC --> RG
  RG --> AI
  RG --> GEN
  GEN --> S3
```

| Component | Module | Role |
|-----------|--------|------|
| **ReportDataCollector** | `src/reports/data_collector.py` | Async load: scan, optional report row, timeline, phase I/O, findings; optional MinIO stage1–4 artifacts into `ScanReportData`. |
| **ScanReportData** | `src/reports/data_collector.py` | Pydantic aggregate: DB slices + `StageArtifactsBundle` per stage (no raw secrets in public API responses). |
| **ReportGenerator** | `src/services/reporting.py` | Orchestrates collect → AI sections by tier → Jinja context → `ReportData` for byte generators. |
| **Report pipeline** | `src/reports/report_pipeline.py` | `run_generate_report_pipeline`: `generation_status` `processing` → render → upload → `ReportObject` rows → `ready` / `failed`. |
| **Generators** | `src/reports/generators.py` | `generate_html`, `generate_pdf`, `generate_json`, `generate_csv`; `build_report_data_from_scan_report` bridges RPT-003 → export model. |
| **Jinja** | `src/reports/jinja_minimal_context.py`, `template_env.py` | Tiered templates (RPT-008); minimal context when only `ReportData` is available (e.g. download regenerate path). |

---

## Celery tasks

| Task name | Queue | Definition | Purpose |
|-----------|-------|------------|---------|
| **`argus.generate_report`** | `argus.reports` | `src/tasks.py` → `generate_report_task` | Full pipeline: `run_generate_report_pipeline` (sync AI, configured formats, MinIO upload). |
| **`argus.generate_all_reports`** | `argus.reports` | `src/tasks.py` → `generate_all_reports_task` | Bulk generate: one DB row per **tier × format** (default **3 tiers × 4 formats = 12** rows). Runs `run_generate_report_pipeline` once per `report_id` (bounded concurrency). If the client supplies `formats` with length **M**, there are **3×M** rows and the HTTP response’s `report_ids` / `count` match that total. |
| **`argus.ai_text_generation`** | `argus.reports` | `src/tasks.py` → `ai_text_generation_task` | One RPT-004 section; used when `ReportGenerator.build_context(..., sync_ai=False)` enqueues per-section work (or future parallel AI). |

Routes: `src/celery_app.py` (`task_routes`). Legacy alias `generate_report` may still map to the same handler — see `tasks.py`.

**Parallelism note** (`argus.generate_all_reports`): The API enqueues **one** Celery task with the full `report_ids` list; inside the task, `run_generate_report_pipeline` runs for each id with bounded concurrency (semaphore, e.g. 4 at a time).

### Automatic generate-all after a full scan (RPT-001–RPT-004)

When the scan state machine finishes **successfully** (all phases through `reporting`, scan status `completed`), the backend enqueues the same bundle as `POST /scans/{scan_id}/reports/generate-all` with **default formats** (3 tiers × 4 formats = **12** `Report` rows) without a separate API call.

- **Hook:** `src/orchestration/state_machine.py` — immediately before the final `commit` that marks the scan complete, `enqueue_generate_all_bundle(..., set_post_scan_idempotency_flag=True)` creates the rows and sets `Scan.options["_argus_post_scan_generate_all_bundle_id"]` to the new `bundle_id`. After `commit`, `schedule_generate_all_reports_task_safe` calls `generate_all_reports_task.delay(...)`.
- **Shared logic:** `src/reports/bundle_enqueue.py` — used by both the HTTP endpoint (`src/api/routers/scans.py`) and the completion hook so row shape, metadata (`bundle_id`, `generate_all`, optional `source: post_scan_complete`), and Celery payload stay aligned.
- **Idempotency:** If `_argus_post_scan_generate_all_bundle_id` is already set (e.g. retry or duplicate completion path), a second bundle is **not** created and the task is **not** scheduled again.
- **MinIO keys:** Unchanged — `{tenant_id}/{scan_id}/reports/{tier}/{report_id}.{fmt}` via `build_report_object_key` / `upload_report_artifact` inside `run_generate_report_pipeline`.

---

## Tiers: Midgard / Asgard / Valhalla

Defined in `src/services/reporting.py`: `REPORT_TIERS`, `report_tier_sections`, `normalize_report_tier`. API: `POST .../reports/generate` body field **`type`**: `midgard` \| `asgard` \| `valhalla`.

| Tier | Section keys (prompt registry) | Focus |
|------|-------------------------------|--------|
| **Midgard** | `executive_summary`, `vulnerability_description` | Short executive + vuln narrative. |
| **Asgard** | Midgard + `remediation_step`, `business_risk`, `compliance_check` | Technical depth + risk/compliance. |
| **Valhalla** | 11 ключей AI — см. подраздел **Valhalla — полная структура** и таблицу промптов ниже | Эталонное оглавление `Report Valhalla.md` + `valhalla_context` + экспорт `valhalla_report` / `valhalla_sections.csv`. |

`prepare_template_context` exposes `jinja.{tier}.slots` and `tier_stubs` (Valhalla: `focus: leadership_technical`).

### Valhalla — полная структура (`Report Valhalla.md`)

Эталонное оглавление заказчика: **`Report Valhalla.md`** в корне рабочей копии репозитория (рядом с каталогом `ARGUS/`). Ниже — логические разделы шаблона и как они закрываются в ARGUS.

| № | Раздел эталона | Роль в ARGUS |
|---|----------------|--------------|
| 1 | Титульный лист | Метаданные скана / цель / шапка отчёта в tier-шаблоне (`valhalla.html.j2`). |
| 2 | Резюме для руководства (Executive Summary) | AI `executive_summary_valhalla` + таблица критичностей из `recon_summary.summary_counts` / `ReportSummary`; блок **OWASP Top 10:2025** (Asgard/Valhalla) из `owasp_compliance_rows`. |
| 3 | Объект, цели и задачи | Контекст цели/скоупа из данных скана и шаблона. |
| 4 | Объём работ и ограничения | Текстовые/метаданные поля отчёта по мере заполнения контекста. |
| 5 | Методология и стандарты | Статический блок методологии в шаблоне + фактические артефакты фаз. |
| 6 | Обзор результатов и матрица рисков | `valhalla_context`: robots/sitemap, tech stack, устаревшие компоненты, email (маскирование), SSL/TLS, security headers, зависимости; **матрица рисков** `risk_matrix` и **critical_vulns** из находок (`valhalla_report_context.py`). |
| 7 | Моделирование угроз и сценарии атак | AI `attack_scenarios` + ссылка/выдержка `threat_model` / `threat_model_excerpt` / `threat_model_phase_link`. |
| 8 | Детализированное описание уязвимостей | Таблица находок (в т.ч. PoC, OWASP) как в Asgard/Valhalla. |
| 9 | Анализ цепочек эксплуатации | AI `exploit_chains` → в JSON/CSV как `exploit_chains_text`. |
| 10 | Рекомендации и приоритизация | AI `remediation_stages`, `prioritization_roadmap`, `hardening_recommendations`, `zero_day_potential`; этапы устранения → `remediation_stages_text`; заключение собирается из roadmap + hardening → `conclusion_text` в payload. |
| 11 | Заключение | См. `conclusion_text` (объединение `prioritization_roadmap` + `hardening_recommendations`). |
| 12 | Приложения | `appendices` в `valhalla_report`: сводки recon, exploitation, scan_artifacts, raw_artifacts, прочие AI-секции (`ai_sections_supplemental`); приложение А — список инструментов `appendix_tools` в `valhalla_context`; выдержки nmap/timeline — поля шаблона (`valhalla_appendix_*` в Jinja). |

**Модули:** сбор контекста `build_valhalla_report_context` → `ValhallaReportContext` (`src/reports/valhalla_report_context.py`); в Jinja — `valhalla_context` (+ tier `valhalla`).

#### Экспорт: объект `valhalla_report` (JSON)

При генерации JSON для tier **`valhalla`** (`generate_json`, `src/reports/generators.py`) в корень документа добавляется ключ **`valhalla_report`** — зеркало секций для машинной обработки. Построение: `build_valhalla_report_payload(jinja_context, ReportData)`.

Топ-уровневые ключи `valhalla_report` (порядок совпадает с CSV-строками ниже):

| Ключ | Содержание |
|------|------------|
| `title_meta` | `report_id`, `target`, `scan_id`, `tenant_id`, `created_at`, `tier` (= `valhalla`). |
| `executive_summary_counts` | Счётчики по severity (из `recon_summary.summary_counts` или fallback из `ReportSummary`). |
| `owasp_compliance` | Строки таблицы OWASP Top 10:2025 из контекста. |

**Связка с recon pipeline (RECON-009):** при сборе отчёта `ReportDataCollector` передаёт в `build_valhalla_report_context` словарь **`recon_results`** из stage1-артефакта **`recon_results.json`**. Если при завершении recon в этот JSON попало поле **`recon_pipeline_summary`**, оно же доступно как стабильный объект **`{tenant_id}/{scan_id}/recon/raw/recon_summary.json`** в основном bucket (`upload_recon_summary_json`). Документ строится `build_recon_summary_document` (`src/recon/summary_builder.py`, `_schema_version`). **`ValhallaReportContext.recon_pipeline_summary`** и fallback tech-stack (`technologies_combined` и др. в `_apply_recon_fallbacks_to_structured`) используют этот слой поверх WhatWeb/legacy `tech_stack`, чтобы таблица технологий и приложения в JSON **`valhalla_report`** отражали агрегат CLI-пайплайна, а не только LLM-выжимку. См. **[scan-state-machine.md](./scan-state-machine.md)** § 4.1 (recon pipeline).
| `robots_sitemap` | `robots_txt_analysis`, `sitemap_analysis` из `valhalla_context`. |
| `tech_stack` | `tech_stack_table`. |
| `outdated_components` | `outdated_components`. |
| `emails` | `leaked_emails` (маскированные). |
| `ssl_tls` | `ssl_tls_analysis`. |
| `headers` | `security_headers_analysis`. |
| `dependencies` | `dependency_analysis`. |
| `risk_matrix` | `risk_matrix` (вариант `matrix` или `distribution`). |
| `critical_vulns` | Критические/высокие находки (краткие ссылки). |
| `threat_modeling_ref` | `threat_model`, `threat_model_excerpt`, `threat_model_phase_link`, `exploitation_post_excerpt`. |
| `findings` | Канонизированные строки находок из Jinja-контекста. |
| `exploit_chains_text` | Текст AI-секции `exploit_chains`. |
| `remediation_stages_text` | Текст AI-секции `remediation_stages`. |
| `zero_day_text` | Текст AI-секции `zero_day_potential`. |
| `conclusion_text` | Склейка `prioritization_roadmap` + `hardening_recommendations`. |
| `appendices` | JSON-объект: `recon_summary`, `exploitation`, `scan_artifacts`, `raw_artifacts`, `ai_sections_supplemental` (все прочие ключи `ai_sections`, кроме пяти, вынесенных в отдельные текстовые поля выше). |

Остальная схема JSON-отчёта (findings, timeline, `ai_sections`, и т.д.) без изменений; `valhalla_report` — **дополнительный** агрегат для Valhalla.

Пример сокращённого фрагмента (поля структурированных секций опущены или пусты):

```json
{
  "valhalla_report": {
    "title_meta": {
      "report_id": "…",
      "target": "https://example.com",
      "scan_id": "…",
      "tenant_id": "…",
      "created_at": "2026-03-27T12:00:00Z",
      "tier": "valhalla"
    },
    "executive_summary_counts": { "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0 },
    "exploit_chains_text": "…",
    "remediation_stages_text": "…",
    "zero_day_text": "…",
    "conclusion_text": "…"
  }
}
```

Полный набор ключей верхнего уровня `valhalla_report` — в таблице выше; тест-референс: `backend/tests/test_rpt009_pdf.py` (`test_vhl005_valhalla_json_includes_valhalla_report`, `test_vhl005_valhalla_sections_csv_roundtrip`).

#### Экспорт: `valhalla_sections.csv` (VHL-005)

Дополнительный артефакт **только для tier Valhalla**, если в пайплайне запрошен формат **`csv`**:

- **Константа формата:** `valhalla_sections.csv` (`VALHALLA_SECTIONS_CSV_FORMAT` в `generators.py`).
- **MinIO key:** `{tenant_id}/{scan_id}/reports/valhalla/{report_id}.valhalla_sections.csv` (тот же префикс, что и у `report_id.csv`; «расширение» файла — полная строка `valhalla_sections.csv`).
- **Содержимое:** UTF-8 CSV с заголовком `section,content_markdown_or_json`.
- **Порядок строк** (поле `section`):  
  `title_meta`, `executive_summary_counts`, `owasp_compliance`, `robots_sitemap`, `tech_stack`, `outdated_components`, `emails`, `ssl_tls`, `headers`, `dependencies`, `risk_matrix`, `critical_vulns`, `threat_modeling_ref`, `findings`, `exploit_chains_text`, `remediation_stages_text`, `zero_day_text`, `conclusion_text`, `appendices`.
- **Вторая колонка:** для `exploit_chains_text`, `remediation_stages_text`, `zero_day_text`, `conclusion_text` — **plain text**; для остальных секций — **одна ячейка JSON** (тот же объект, что в `valhalla_report`).

**БД:** значение `report_objects.format` для этой строки длиннее 20 символов → см. миграцию **012** ниже.

#### Миграция `012_report_objects_format_length`

Alembic **`012_report_objects_format_length`**: колонка **`report_objects.format`** расширена с **`VARCHAR(20)`** до **`VARCHAR(48)`**, чтобы сохранять формат артефакта **`valhalla_sections.csv`** без усечения (VHL-005).

### Proof of Concept (PoC) in findings

- **DB:** nullable JSONB `findings.proof_of_concept` (Alembic `010_findings_proof_of_concept`) — структурированный словарь с ключами из `active_scan/poc_schema.py` (`tool`, `parameter`, `payload`, `request`, `response`, `response_snippet`, `curl_command`, `javascript_code`, `screenshot_key`). Поле **дополнительное**; публичные ключи ответа API без переименований. `build_proof_of_concept` усечёт `response` до 1024 и `response_snippet` до 500 символов; `merge_proof_of_concept` мержит два dict по известным ключам, для строк выбирая более длинное значение.
- **MinIO (primary bucket):** идемпотентный объект `{tenant_id}/{scan_id}/poc/{finding_id}.json` — зеркало PoC при сохранении finding в фазе `reporting` (`upload_finding_poc_json` в `src/storage/s3.py`). Скриншоты PoC (Playwright, если включено в VA) — отдельные объекты под ключом `screenshot_key` в том же bucket; presigned ссылка в Jinja через `get_finding_poc_screenshot_presigned_url` (`findings_rows_for_jinja`). Отчётный bucket для PDF/HTML/JSON не используется. Таблица **`evidence`** не расширялась (`poc_data` не добавлялся): канонический JSON PoC — MinIO + колонка finding.

**Скриншоты PoC в MinIO (не `…/raw/`):** bucket тот же, что и у сырых артефактов фаз — **`MINIO_BUCKET`** / `settings.minio_bucket`, не `MINIO_REPORTS_BUCKET`. Канонический префикс объектов: **`{tenant_id}/{scan_id}/poc/screenshots/{slug}.png`** (`build_finding_poc_screenshot_object_key`, `upload_finding_poc_screenshot_png`). Это отличается от шаблона stage raw `{tenant_id}/{scan_id}/{phase}/raw/{filename}`: скриншоты лежат под **`poc/screenshots/`**, рядом с JSON PoC **`…/poc/{finding_id}.json`**. Имя файла — логический `slug`: для XSS-верификации **`xss_verify_{sha256(url|param|payload)[:40]}.png`** (`xss_verifier._screenshot_slug`); для POC-003 визуального обогащения VA — **`va_poc_{sha40}.png`** (`poc_visual_enrichment._poc_upload_finding_slug`). Полный ключ попадает в `proof_of_concept.screenshot_key` и далее в отчёт.
- **HTML:** `partials/findings_table.html.j2` — блок `finding-poc` для **asgard** и **valhalla** (payload, JS, cURL, request/response, **Response snippet**, ссылка **Screenshot** при `screenshot_key`); **midgard** — одна строка-заглушка (полные детали только в старших tier). По умолчанию скриншот — ссылка `<a>`; при **`REPORT_POC_EMBED_SCREENSHOT_INLINE=true`** (`settings.report_poc_embed_screenshot_inline`) в шаблон передаётся `embed_poc_screenshot_inline` и рендерится миниатюра `<img>` (увеличивает размер HTML/PDF). Для tier **valhalla** `prepare_template_context` по умолчанию задаёт **`embed_poc_screenshot_inline=true`**, даже если глобальный env false; переопределение — поле **`embed_poc_screenshot_inline`** в аргументе `extra`.
- **JSON отчёт:** `generate_json` включает `proof_of_concept` в каждом finding при наличии.
- **AI (RPT-004):** `ReportGenerator.build_ai_input_payload` добавляет в срез findings поля `poc_curl`, `poc_javascript`, `poc_request` при наличии в PoC. Для **`tier=valhalla`** в каждый элемент findings дополнительно попадают **`finding_id`**, усечённое **`description`** (~400 символов), список **`cve_ids`** (из title/description/CWE/PoC-ключи `cve` / `cve_id` / `cve_ids`), флаг **`exploit_available`** (`derive_exploit_available_flag`); в компактном **`valhalla_context`** для LLM — **`risk_matrix`** (ячейки: impact, likelihood, count, finding_ids до 24 на ячейку) и **`critical_vulns`** (`vuln_id`, title, cvss, description, exploit_available). Дополнительно в payload Valhalla: плоские **`tech_stack_structured`**, **`ssl_tls_analysis`**, **`security_headers_analysis`**, **`outdated_components_table`**, **`robots_sitemap_analysis`** (срезы из компактного контекста) и объект **`valhalla_fallback_messages_ru`**: по ключам `tech_stack`, `ssl_tls`, `security_headers`, `outdated_components`, `robots_sitemap`, `leaked_emails` — краткие пояснения на русском, когда соответствующий блок в данных скана пуст или недоступен (см. `build_valhalla_report_context` в `valhalla_report_context.py`). Версия промптов отчёта: **`REPORT_AI_PROMPT_VERSIONS`** → сегмент **`vhq005-20250328`** (`prompt_registry.py`).

### Valhalla — блок XSS (структурированный контекст, HTML, PoC-ключи)

- **Критерий попадания в XSS-блок:** [`finding_qualifies_for_xss_structured_context`](../backend/src/reports/valhalla_report_context.py) — CWE-79 / XSS в заголовке / наличие в PoC сигнальных полей (`reflection_context`, `verified_via_browser`, `verification_method`, `browser_alert_text`, `payload_entered`, `payload_used`, `screenshot_key`, `poc_screenshot_url`, …).
- **Строки для AI (`valhalla_context.xss_structured`):** [`build_xss_structured_rows_from_findings`](../backend/src/reports/valhalla_report_context.py) → модель `ValhallaXssStructuredRowModel`: `finding_id`, `title`, `parameter`, `payload_entered`, `payload_reflected`, `payload_used`, `reflection_context`, `verification_method`, `verified_via_browser`, `browser_alert_text`, `artifact_keys` (в т.ч. MinIO object keys), `artifact_urls` (presigned/прямые URL из PoC). Лимиты: до 48 строк, усечение полей (~600 символов). Сериализация для вложений: `serialize_xss_structured_for_ai`. Промпты: [`prompt_registry.py`](../backend/src/orchestration/prompt_registry.py) (ссылки на `valhalla_context.xss_structured`).
- **HTML (таблица находок Valhalla):** для каждой строки, прошедшей квалификатор, [`findings_rows_for_jinja`](../backend/src/services/reporting.py) заполняет `row.xss_poc_detail` через [`_build_xss_poc_detail_for_jinja`](../backend/src/services/reporting.py). Шаблон секции: [`finding_xss_poc_detail.html.j2`](../backend/src/reports/templates/reports/partials/valhalla/finding_xss_poc_detail.html.j2) — поля **`payload_entered`**, **`payload_reflected`**, **`payload_used`**, **`reflection_context`**, **`verification_line`** (человекочитаемая сводка: `verification_method`, `verified_via_browser`, наличие `screenshot_key` / `poc_screenshot_url`, curl), **`poc_narrative`** (из PoC или автогенерация), **`poc_screenshot_url`** (presigned GET, см. ниже).
- **Канонические ключи `proof_of_concept` (XSS и общий PoC):** [`poc_schema.py`](../backend/src/recon/vulnerability_analysis/active_scan/poc_schema.py) — `PROOF_OF_CONCEPT_KEYS`, в т.ч. `verified_via_browser`, `verification_method`, `browser_alert_text`, `browser_dialog_type`, `payload_entered`, `payload_used`, `payload_reflected`, `reflection_context`, `escape_technique`, `curl_command`, `screenshot_key`, `response_snippet`, `tool`, `parameter`, `payload`, …
- **MinIO и скриншоты:** primary bucket **`MINIO_BUCKET`** ([`s3.py`](../backend/src/storage/s3.py)): JSON PoC находки `{tenant_id}/{scan_id}/poc/{finding_id}.json` (`upload_finding_poc_json`); PNG PoC `{tenant_id}/{scan_id}/poc/screenshots/{finding_id}.png` (`build_finding_poc_screenshot_object_key`, `upload_finding_poc_screenshot_png`, presigned — `get_finding_poc_screenshot_presigned_url`). Headless XSS-верификатор пишет PNG с id вида `xss_verify_<hash>` (см. [`xss_verifier.py`](../backend/src/recon/vulnerability_analysis/active_scan/xss_verifier.py)). Отдельно: bucket отчётов **`MINIO_REPORTS_BUCKET`** для готовых HTML/PDF/JSON/CSV ([раздел MinIO ниже](#minio--s3)). Доп. скриншоты VA PoC — `VA_POC_PLAYWRIGHT_SCREENSHOT_ENABLED` и [`poc_visual_enrichment.py`](../backend/src/recon/vulnerability_analysis/active_scan/poc_visual_enrichment.py).

### Valhalla: VA, fallback-тексты и recon robots/sitemap (VDF / datafill)

- **WhatWeb / tech stack:** структурированный стек и таблица технологий в Valhalla собираются из выходов **whatweb** (VA active scan), `recon_results` и связанных сигналов. Если валидного отпечатка WhatWeb и достаточных рекон-сигналов нет, в контексте задаётся **`tech_stack_fallback_message`** (RU), а в AI payload то же значение попадает в **`valhalla_fallback_messages_ru.tech_stack`**.
- **testssl / SSL-TLS:** приоритет — JSON **testssl.sh** из сырых артефактов (`_latest_tls_blob_from_raw` → `_ssl_from_testssl_json`); при отсутствии blob остаются данные из recon-сертификатов. Celery-обёртка **`testssl`** в `src/tasks/tools.py` использует **`_run_testssl_va_celery_with_sslscan_fallback`**: при сбое или пустом результате допускается fallback **sslscan** для TLS-зонда. Если поверхность TLS для отчёта пуста, **`ssl_tls_fallback_message`** и **`valhalla_fallback_messages_ru.ssl_tls`** объясняют отсутствие данных (HTTP-цель, нет testssl/sslscan в sandbox и т.п.).
- **Security headers:** карта заголовков из `recon_results` и фаз recon/vuln_analysis; при пустой карте — **`security_headers_fallback_message`** / **`valhalla_fallback_messages_ru.security_headers`**.
- **HARVESTER_ENABLED:** env → `settings.harvester_enabled`; при **`true`** в VA может планироваться **theHarvester** (OSINT email), stdout/артефакты участвуют в маскированных email для Valhalla. Если индикаторов нет, в fallback для email указана связь с этим флагом.
- **VA_ROBOTS_EXTENDED_PIPELINE:** env → `settings.va_robots_extended_pipeline`; при **`true`** и **`SANDBOX_ENABLED`** после базового сбора robots/sitemap модуль **`src/recon/robots_sitemap_analyzer.py`** может запускать поверхностный **gospider** и **parsero** (best-effort, без тяжёлого fuzz по умолчанию).
- **robots_sitemap_analyzer:** фаза recon — HTTP-загрузка `robots.txt`, `sitemap.xml`, `sitemap_index.xml`, `.well-known/security.txt`; парсинг правил и `<loc>`, слияние в сводку, запись сырых текстов и JSON **`recon_robots_sitemap_summary`** в MinIO. Юнит-тесты парсеров без сети: `backend/tests/test_robots_sitemap_analyzer.py`.

### OWASP Top 10:2025 in HTML findings

- **Колонка находки:** для Asgard/Valhalla в таблице находок выводится код категории (`A01`…`A10`) и русская подпись (`owasp_title_ru` из JSON при наличии, иначе краткий EN title из `owasp_top10_2025.py`); источник кода — `findings.owasp_category` (см. `owasp_category_map.py`, миграция `011_findings_owasp_category`).
- **Сводка соответствия:** под таблицей находок (шаблон `partials/findings_table.html.j2`) секция **«OWASP Top 10:2025 Compliance»** с таблицей `owasp-compliance-table` (только Asgard/Valhalla; в **midgard** скрыта). Строки строит `build_owasp_compliance_rows` (`src/reports/generators.py`) из счётчиков находок и данных загрузчика `src/owasp/owasp_loader.py`.
- **Данные RU:** файл JSON по пути **`OWASP_JSON_PATH`** → настройка `settings.owasp_json_path` (по умолчанию `data/owasp_top_10_2025_ru.json` относительно корня backend — каталог с `src/`). Ключи на категорию: `title_ru`, `example_attack`, `how_to_find`, `how_to_fix`. При отсутствии/битом файле используются безопасные fallback из кода (см. `owasp_loader.py`).
- **Колонки таблицы соответствия (заголовки RU):** **Категория** — `<code>A0x</code>` + ` — ` + `title_ru`; **Описание** — краткий текст риска (из `example_attack`, иначе первое предложение `how_to_find`); **Наличие находок** — `Да` / `Нет`. Подсветка строк: `owasp-compliance-0` (нет находок), `owasp-compliance-warn` (1–2), `owasp-compliance-high` (3+).
- **Подсказка (tooltip):** у ячейки категории атрибут `title` заполняется усечённым `how_to_fix` из JSON (поле `description_hover` в строке compliance), если текст есть.
- **AI (RPT-004):** если в контексте есть сводка OWASP по находкам, `ReportGenerator.build_ai_input_payload` добавляет объект **`owasp_category_reference_ru`**: по категориям с ненулевым счётчиком или из `gap_categories` — компактные RU-поля `title_ru`, `example_attack`, `how_to_find`, `how_to_fix` (обрезка длины в `reporting.py`). Промпты в `prompt_registry.py` ссылаются на этот ключ для согласованности формулировок с отчётом.

---

## Prompts (RPT-004) — section keys

Constants in `src/orchestration/prompt_registry.py` (see also [prompt-registry.md](./prompt-registry.md)):

| Section key | Typical constant prefix | Tiers |
|-------------|-------------------------|--------|
| `executive_summary` | `REPORT_AI_SECTION_EXECUTIVE_SUMMARY` | Midgard, Asgard |
| `executive_summary_valhalla` | `REPORT_AI_SECTION_EXECUTIVE_SUMMARY_VALHALLA` | Valhalla (вместо `executive_summary`) |
| `vulnerability_description` | `REPORT_AI_SECTION_VULNERABILITY_DESCRIPTION` | Все |
| `attack_scenarios` | `REPORT_AI_SECTION_ATTACK_SCENARIOS` | **Valhalla only** |
| `exploit_chains` | `REPORT_AI_SECTION_EXPLOIT_CHAINS` | **Valhalla only** |
| `remediation_step` | `REPORT_AI_SECTION_REMEDIATION_STEP` | Asgard, Valhalla |
| `remediation_stages` | `REPORT_AI_SECTION_REMEDIATION_STAGES` | **Valhalla only** |
| `business_risk` | `REPORT_AI_SECTION_BUSINESS_RISK` | Asgard, Valhalla |
| `compliance_check` | `REPORT_AI_SECTION_COMPLIANCE_CHECK` | Asgard, Valhalla |
| `prioritization_roadmap` | `REPORT_AI_SECTION_PRIORITIZATION_ROADMAP` | Valhalla |
| `hardening_recommendations` | `REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS` | Valhalla |
| `zero_day_potential` | `REPORT_AI_SECTION_ZERO_DAY_POTENTIAL` | **Valhalla only** |

Порядок вызова AI для Valhalla задаётся `report_tier_sections("valhalla")` в `src/services/reporting.py`:  
`executive_summary_valhalla` → `vulnerability_description` → `attack_scenarios` → `exploit_chains` → `remediation_step` → `remediation_stages` → `business_risk` → `compliance_check` → `prioritization_roadmap` → `hardening_recommendations` → `zero_day_potential`.

Prompt bodies and versions: `REPORT_AI_PROMPT_VERSIONS`, `get_prompt` / reporting helpers in the same registry. Runtime: `run_ai_text_generation` (`src/reports/ai_text_generation.py`) resolves by section key and caches in Redis under prefix **`argus:ai_text:`** (see `build_ai_text_cache_key`).

---

## Export formats

| Format | Content-Type | Notes |
|--------|--------------|--------|
| `html` | `text/html; charset=utf-8` | Tiered Jinja (RPT-008), `template_env.render_tier_report_html`. |
| `pdf` | `application/pdf` | WeasyPrint (RPT-009); HTML → PDF. |
| `json` | `application/json; charset=utf-8` | Stable ordering in `generators.py`; для **valhalla** добавляется ключ **`valhalla_report`**. |
| `csv` | `text/csv; charset=utf-8` | Табличный экспорт находок + приложение `ai_sections` / `scan_artifacts`. |
| `valhalla_sections.csv` | `text/csv; charset=utf-8` | **Только Valhalla** и только при запросе `csv` в пайплайне: одна строка на логическую секцию эталона (см. выше). Скачивание: `GET .../download?format=valhalla_sections.csv` для Valhalla-отчёта. |

Default when explicit/requested list is empty after validation: `html`, `json`, `csv`, `pdf` (`report_pipeline.DEFAULT_REPORT_FORMATS`).

---

## HTTP API (prefix `/api/v1`)

| Method | Path | Status | Description |
|--------|------|--------|-------------|
| POST | `/scans/{scan_id}/reports/generate` | **202** | Body: `type` (tier), `formats[]`. Creates `Report` (`generation_status=pending`), enqueues `argus.generate_report`. Response: `report_id`, `task_id`. |
| POST | `/scans/{scan_id}/reports/generate-all` | **202** | Creates one `Report` per tier × requested format (default formats: `html`, `json`, `csv`, `pdf` → **12** rows). Optional body: `{ "formats": [...] }` (length **M** → **3×M** rows). Response: `bundle_id`, `report_ids[]` (**12** UUIDs by default), `task_id`, `count` (**12** by default, equals `len(report_ids)`). The same row + task pattern runs automatically once when a scan reaches **completed** (see *Automatic generate-all* above). |
| GET | `/reports` | 200 | List reports; optional `?target=`. Includes `generation_status`, `tier`, `requested_formats` for UI polling. |
| GET | `/reports/{report_id}` | 200 | Detail + same lifecycle fields. |
| GET | `/reports/{report_id}/download?format=pdf|html|json|csv` | 200 / 302 | Stream or presigned redirect (`redirect=true`). |
| GET | `/scans/{scan_id}/findings` | 200 | Findings (reporting UX). |

**Generate-all response example** (default formats — twelve report rows):
```json
{
  "bundle_id": "bundle_uuid_v4",
  "report_ids": [
    "uuid_tier0_fmt0", "uuid_tier0_fmt1", "uuid_tier0_fmt2", "uuid_tier0_fmt3",
    "uuid_tier1_fmt0", "uuid_tier1_fmt1", "uuid_tier1_fmt2", "uuid_tier1_fmt3",
    "uuid_tier2_fmt0", "uuid_tier2_fmt1", "uuid_tier2_fmt2", "uuid_tier2_fmt3"
  ],
  "task_id": "celery_task_uuid",
  "count": 12
}
```

Tenant: `X-Tenant-ID` / auth-derived tenant (`get_current_tenant_id`). See [frontend-api-contract.md](./frontend-api-contract.md).

---

## MinIO / S3

- **Reports bucket:** `settings.minio_reports_bucket` — env **`MINIO_REPORTS_BUCKET`** (default `argus-reports`). Distinct from stage artifacts **`MINIO_BUCKET`** (e.g. `argus`).
- **Object type:** `reports` → `OBJECT_TYPE_REPORTS` in `src/storage/s3.py`.
- **Key layout:** `{tenant_id}/{scan_id}/reports/{tier}/{report_id}.{fmt}` where `tier` ∈ {`midgard`, `asgard`, `valhalla`} and `fmt` — обычно `html`, `pdf`, `json`, `csv`; для Valhalla при генерации CSV дополнительно загружается **`{report_id}.valhalla_sections.csv`** (см. `VALHALLA_SECTIONS_CSV_FORMAT`).
  - Example: `tenant-123/scan-456/reports/asgard/report-789.pdf`
  - Valhalla + csv: `.../reports/valhalla/{report_id}.csv` и `.../reports/valhalla/{report_id}.valhalla_sections.csv`
  - Single-report key pattern (legacy/single generate): `{tenant_id}/{scan_id}/reports/{filename}` (e.g. `report.pdf`).
- **Helpers:** `src/reports/storage.py` — re-exports `upload`, `download`, `exists`, `get_presigned_url`, `ensure_bucket()`.

---

## Environment variables (reporting-relevant)

| Variable | Purpose |
|----------|---------|
| `MINIO_ENDPOINT`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `MINIO_SECURE` | S3-compatible client. |
| `MINIO_BUCKET` | Default bucket for stage scan artifacts, PoC JSON/PNG, XSS verifier screenshots (`.../poc/...`). |
| **`MINIO_REPORTS_BUCKET`** | Bucket for generated report files. |
| **`XSS_VERIFICATION_ENABLED`** | Влияет на заполнение PoC полей `verified_via_browser` / `verification_method` при генерации находок XSS engine (см. [scan-state-machine.md](./scan-state-machine.md) § 4.3a). |
| **`XSS_PLAYWRIGHT_TIMEOUT`** / **`XSS_PLAYWRIGHT_TIMEOUT_MS`** | Таймаут Playwright для XSS-верификатора (мс). |
| **`XSS_CONTEXT_DETECTION_ENABLED`** | Включение контекста отражения в XSS engine → `reflection_context` в PoC и в Valhalla XSS-блоке. |
| **`XSS_PAYLOAD_COLLECTION_URL`**, **`XSS_PAYLOAD_REPOS`**, **`XSS_MAX_PAYLOADS_PER_PARAM`** | Расширение набора payloads и лимиты XSS engine (см. [`config.py`](../backend/src/core/config.py)). |
| **`VA_POC_PLAYWRIGHT_SCREENSHOT_ENABLED`** (`settings.va_poc_playwright_screenshot_enabled`) | VA: опциональные PNG скриншоты + `response_snippet` вокруг payload (`poc_visual_enrichment.py`; нужны `playwright` + браузер). Принудительное отключение без смены settings: env **`VA_POC_PLAYWRIGHT_SCREENSHOT`** = `0` / `false` / `off` / `no`. |
| **`REPORT_POC_EMBED_SCREENSHOT_INLINE`** (`settings.report_poc_embed_screenshot_inline`) | Отчёт HTML/PDF: встраивать presigned URL скриншота PoC как `<img>` вместо только ссылки (по умолчанию `false`). |
| **`OWASP_JSON_PATH`** (`settings.owasp_json_path`) | Путь к JSON с русскими текстами OWASP Top 10:2025 для таблицы соответствия, tooltip и AI `owasp_category_reference_ru` (по умолчанию `data/owasp_top_10_2025_ru.json` относительно корня backend). |
| **`AI_TEXT_CACHE_TTL_SECONDS`** (`settings.ai_text_cache_ttl_seconds`) | Redis TTL for AI section text cache. |
| Redis URL (if configured) | Used by `run_ai_text_generation` for cache get/set. |
| `ARGUS_SKIP_WEASYPRINT_PDF` | Skip heavy PDF tests when set. |

---

## Valhalla — follow-up scan scheduling (stub / future)

**Not implemented** as a production API. Intent: Valhalla-tier output may suggest a **follow-up** scan (deeper scope or post-remediation re-test).

- **Option A (planned):** `POST /api/v1/scans/{scan_id}/follow-up` — body with scope/options → **202** + new `scan_id` / task id.
- **Option B:** Extend report metadata with `suggested_follow_up` and create scans via existing `POST /scans`.

Until then, UIs should treat follow-up as a **manual** new scan for the same target.

---

## Artifacts in HTML Reports

HTML reports include embedded artifact references and presigned download links for raw scan outputs from each phase.

### Artifact Section Structure

In tiered HTML reports (Midgard, Asgard, Valhalla), the **Artifacts** section:
- Lists raw artifacts by phase (recon, threat_modeling, vuln_analysis, exploitation, post_exploitation)
- Provides artifact metadata: filename, size, timestamp, phase
- Includes **presigned download links** for direct browser download (valid for 1 hour)
- Shows artifact type (log, JSON, CSV, binary)

### Example HTML Artifact Block

```html
<section class="artifacts">
  <h2>Scan Artifacts</h2>
  <div class="artifact-phase">
    <h3>Recon Phase</h3>
    <table>
      <tr>
        <th>Artifact</th>
        <th>Type</th>
        <th>Size</th>
        <th>Action</th>
      </tr>
      <tr>
        <td>nmap_output.xml</td>
        <td>XML</td>
        <td>245 KB</td>
        <td><a href="https://minio.../presigned-url?token=...">Download</a></td>
      </tr>
    </table>
  </div>
</section>
```

### Raw Artifacts API

Access raw artifacts programmatically via:

```
GET /api/v1/scans/{id}/artifacts
```

**Query Parameters:**

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `phase` | string | Filter by phase (optional) | `recon`, `threat_modeling`, `vuln_analysis`, `exploitation`, `post_exploitation` |
| `raw` | boolean | Include raw artifact data (default: false) | `true` / `false` |
| `presigned` | boolean | Generate presigned URLs (default: true) | `true` / `false` |

**Response Example** (with presigned URLs):

```json
{
  "scan_id": "scan-123",
  "tenant_id": "tenant-456",
  "artifacts": [
    {
      "phase": "recon",
      "filename": "nmap_output.xml",
      "type": "xml",
      "size": 245120,
      "created_at": "2026-03-23T10:15:32Z",
      "minio_key": "tenant-456/scan-123/recon/raw/nmap_output.xml",
      "download_url": "https://minio.../presigned-url?token=...",
      "download_expires_in_seconds": 3600
    },
    {
      "phase": "threat_modeling",
      "filename": "threat_model.json",
      "type": "json",
      "size": 18560,
      "created_at": "2026-03-23T10:22:15Z",
      "minio_key": "tenant-456/scan-123/threat_modeling/raw/threat_model.json",
      "download_url": "https://minio.../presigned-url?token=...",
      "download_expires_in_seconds": 3600
    }
  ],
  "total_artifacts": 2,
  "total_size_bytes": 263680
}
```

**Response Example** (raw=true, presigned=false):

```json
{
  "scan_id": "scan-123",
  "artifacts": [
    {
      "phase": "recon",
      "filename": "nmap_output.xml",
      "type": "xml",
      "size": 245120,
      "created_at": "2026-03-23T10:15:32Z",
      "minio_key": "tenant-456/scan-123/recon/raw/nmap_output.xml"
    }
  ]
}
```

**Error Responses:**

```json
{
  "error": "scan_not_found",
  "code": 404,
  "details": "Scan with ID 'scan-999' does not exist"
}
```

### Implementation Notes

- **MinIO key layout:** `{tenant_id}/{scan_id}/{phase}/raw/{filename}`
- **Presigned URL TTL:** Configurable via `ARTIFACT_PRESIGNED_URL_TTL_SECONDS` (default: 3600)
- **Tenant isolation:** All artifact access validated via `X-Tenant-ID` header / auth context
- **Raw data size limit:** Large artifacts (>100MB) streamed rather than buffered
- **Audit logging:** All artifact downloads logged via `GET /api/v1/scans/{id}/artifacts` access

---

## Артефакты этапов (Stage Artifacts)

Все 6 фаз сканирования сохраняют необработанные данные (raw artifacts) в MinIO для полного аудита, forensics и программного доступа. Артефакты организованы по фазам и содержат исходные выходы инструментов, logs, промежуточные анализы и JSON/CSV экспорты.

### Структура артефактов по фазам

| Фаза | MinIO path | Формат артефактов | Примеры |
|------|-----------|------------------|---------|
| **recon** | `{tenant}/{scan}/recon/raw/` | logs, XML, JSON | nmap_output.xml, subfinder_domains.txt, nuclei_results.json |
| **threat_modeling** | `{tenant}/{scan}/threat_modeling/raw/` | JSON, markdown | threat_model.json, ai_analysis.md, scenario_list.json |
| **vuln_analysis** | `{tenant}/{scan}/vuln_analysis/raw/` | JSON, CSV | evidence_bundles.json, finding_confirmation_matrix.csv, xss_payloads.json, sqlmap_output.json |
| **exploitation** | `{tenant}/{scan}/exploitation/raw/` | JSON, logs, binary | exploit_attempts.json, proof_of_concept.bin, post_exploit_logs.txt |
| **post_exploitation** | `{tenant}/{scan}/post_exploitation/raw/` | JSON, CSV | lateral_movement_map.json, persistence_mechanisms.csv, session_data.json |
| **reporting** | `{tenant}/{scan}/reports/{tier}/` | HTML, PDF, JSON, CSV | report_asgard.html, report_midgard.pdf, report_valhalla.json |

### Raw Tool Outputs (подсекция)

Каждый инструмент, запущенный во время скана, оставляет исходные выходы в `raw/` подпапке соответствующей фазы.

#### Сырые выводы инструментов (HTML-отчёт)

В шаблоне `partials/artifacts.html.j2` блок с заголовком **«Сырые выводы инструментов»** (якорь `id="raw-tool-outputs"`) показывает таблицу файлов из `scan_artifacts.phase_blocks[].tool_output_rows` — те же объекты, что в `ScanReportData.raw_artifacts` при сборе отчёта (`ReportDataCollector` / `build_scan_artifacts_section_context`). Смысл: **raw CLI / stdout** по фазам MinIO.

#### Примеры layout по фазам

##### recon phase
```
{tenant}/{scan}/recon/raw/
├── nmap_summary.xml         — Полный сканс портов (XML формат nmap)
├── nmap_service_scan.txt    — Описания сервисов (–sV output)
├── subfinder_discovered.txt — Перечень обнаруженных субдоменов
├── nikto_output.json        — Результаты веб-скана (JSON)
├── nuclei_templates.json    — Результаты template-based сканирования
├── crt_sh_certificates.json — Сертификаты из crt.sh (OSINT)
└── host_alive_validation.csv — Живые хосты (IP, hostname, timestamp)
```

##### threat_modeling phase
```
{tenant}/{scan}/threat_modeling/raw/
├── threat_model.json        — Структурированная модель (JSON)
├── ai_response_raw.txt      — Исходный ответ LLM (raw text)
├── threat_scenarios.json    — Сценарии атак (trust boundaries, actors)
├── asset_inventory.csv      — Активы и их критичность
└── risk_matrix.csv          — Matrix(asset, threat, impact)
```

##### vuln_analysis phase
```
{tenant}/{scan}/vuln_analysis/raw/
├── findings_raw.json        — Исходные findings (до AI анализа)
├── evidence_bundles.json    — Ссылки на доказательства per finding
├── evidence_sufficiency.json — Статус достаточности (sufficient|marginal|insufficient)
├── finding_confirmation_matrix.csv — Matrix (finding_id, status, evidence_count, confidence, contradictions)
├── contradiction_analysis.json — Conflicting evidence pairs
├── duplicate_finding_clusters.csv — Grouped & deduplicated findings
├── xss_payloads.json        — XSS payload templates & results (dalfox, xsstrike)
├── sqlmap_output.json       — SQL injection findings (policy-gated)
├── web_findings.csv         — Summary (endpoint, type, severity)
└── next_phase_gate.json     — Gate status + blocking conditions
```

##### exploitation phase
```
{tenant}/{scan}/exploitation/raw/
├── exploit_attempts.json    — Попытки эксплуатации (tool, params, result)
├── proof_of_concept.bin     — PoC файлы (executables, payloads)
├── post_exploit_logs.txt    — Shell output (стандартизированно)
└── evidence_collected.csv   — Proof-of-execution (files written, credentials, etc)
```

##### post_exploitation phase
```
{tenant}/{scan}/post_exploitation/raw/
├── lateral_movement_map.json — Сетевые пути к другим активам
├── persistence_mechanisms.csv — Установленные backdoors/agents
├── session_data.json        — Active sessions & credentials (redacted)
└── system_enumeration.txt   — System info, patches, users
```

### JSON / CSV Export Structures

#### ai_sections (структурированные AI output)

Для каждого tier × format (Midgard/Asgard/Valhalla × HTML/PDF/JSON/CSV) сохраняются JSON объекты AI-generated sections:

```json
{
  "scan_id": "scan-123",
  "tier": "asgard",
  "sections": [
    {
      "key": "executive_summary",
      "content": "Summary text...",
      "tokens_used": 450,
      "cache_hit": false,
      "generated_at": "2026-03-24T10:15:32Z"
    },
    {
      "key": "vulnerability_description",
      "content": "Description text...",
      "tokens_used": 820,
      "cache_hit": true,
      "generated_at": "2026-03-24T10:16:01Z"
    }
  ],
  "total_tokens": 1270,
  "redis_cache_key": "argus:ai_text:scan-123:asgard"
}
```

**Расположение:** `{tenant}/{scan}/reports/{tier}/ai_sections_{tier}.json`

#### scan_artifacts (метаданные + links)

Список всех артефактов с метаданными для UI и API:

```json
{
  "scan_id": "scan-123",
  "scan_status": "completed",
  "phases": [
    {
      "phase": "recon",
      "status": "completed",
      "artifacts": [
        {
          "filename": "nmap_summary.xml",
          "type": "xml",
          "size_bytes": 245120,
          "minio_key": "tenant-123/scan-123/recon/raw/nmap_summary.xml",
          "created_at": "2026-03-24T10:05:00Z",
          "presigned_url": "https://minio.../presigned-token",
          "presigned_expires_in_seconds": 3600,
          "tool": "nmap",
          "description": "Full port scan results"
        }
      ],
      "total_artifacts": 7,
      "total_size_bytes": 1847293
    }
  ],
  "total_artifacts": 32,
  "total_size_bytes": 8920184,
  "timestamp": "2026-03-24T11:30:00Z"
}
```

**Расположение:** `{tenant}/{scan}/artifacts/scan_artifacts.json` или доступно через API endpoint `GET /api/v1/scans/{id}/artifacts`

### CSV Export Структуры

Для табличного экспорта данных используются стандартизированные CSV форматы:

#### finding_confirmation_matrix.csv

```csv
finding_id,finding_title,cwe_id,severity,status,evidence_count,direct_evidence,confidence,contradictions,duplicate_of,scenario_linked,asset_linked,lineage_complete,remediation_priority
FND-001,SQL Injection in login form,CWE-89,High,confirmed,3,2,0.95,0,none,true,true,true,1
FND-002,XSS in comment field,CWE-79,Medium,partially_confirmed,1,1,0.72,0,FND-003,true,true,false,2
FND-003,Stored XSS in profile,CWE-79,Medium,confirmed,2,1,0.88,1,none,true,true,true,2
```

#### evidence_sufficiency.csv

```csv
finding_id,title,required_evidence,actual_evidence,min_direct,actual_direct,sufficiency_status,confidence_level
FND-001,SQL Injection,≥2,3,≥1,2,sufficient,high
FND-002,XSS,≥2,1,≥1,1,insufficient,low
FND-003,Authentication Bypass,≥2,2,≥1,1,sufficient,medium
```

#### web_findings.csv

```csv
endpoint,http_method,parameter,vulnerability_type,severity,payload_sample,response_code,confidence,tool,timestamp
/api/users,GET,id,SQL Injection,High,"1 UNION SELECT NULL--",200,0.95,sqlmap,2026-03-24T10:15:32Z
/comment,POST,text,XSS,Medium,"<img src=x onerror=alert(1)>",200,0.88,xsstrike,2026-03-24T10:20:15Z
```

---

## RPT-009 — PDF

- Engine: [WeasyPrint](https://weasyprint.org/) — tiered HTML → PDF (`src/reports/generators.py`, pipeline, download router).
- Docker: system libs in `Dockerfile`; Python package in requirements.
- Tests: `tests/test_rpt009_pdf.py`; integration marker `@pytest.mark.weasyprint_pdf`; skips via `tests/weasyprint_skips.py`.

---

## Phase Artifacts — Raw Data (Артефакты этапов)

Each scan phase stores raw tool outputs and AI traces in MinIO. Reports include an
**«Артефакты этапов / Phase Artifacts»** section with presigned download URLs (valid 1 hour).

### Artifact types

| Type | Description | Format |
|------|-------------|--------|
| Tool stdout/stderr | Raw output from security tools (nmap, dalfox, sqlmap, xsstrike, nuclei, etc.) | `.txt` |
| AI prompts/responses | LLM request/response pairs and reasoning traces | `.json` |
| HTTP stubs | Reconstructed HTTP request for reproducibility | `.txt` |
| Scan plans | JSON plans generated by the active scan planner | `.json` |
| Heuristic results | SSRF/CSRF/IDOR/open redirect heuristic output | `.json` |
| Active scan findings | Normalized findings from active scan tools | `.json` |

### Storage path format

```
{tenant_id}/{scan_id}/{phase}/raw/{timestamp}_{artifact_type}.{ext}
```

Example: `tenant-abc/scan-123/vuln_analysis/raw/20260324T120000_tool_dalfox_scan_0_stdout.txt`

### Report integration

All report tiers (Midgard, Asgard, Valhalla) include an artifacts section in the HTML/PDF output.
The `ScanReportData.raw_artifacts` field is populated during `ReportDataCollector.collect_async()`
when `include_minio=True`. Each artifact entry contains:

| Field | Description |
|-------|-------------|
| `key` | MinIO object key |
| `phase` | Scan phase (recon, vuln_analysis, etc.) |
| `artifact_type` | Parsed artifact type (tool name, trace type) |
| `size_bytes` | Object size |
| `url` | Presigned download URL (1h expiry) |

JSON report export also includes the `raw_artifacts` list.

### Implementation

- **Listing:** `list_raw_artifacts()` in `data_collector.py` — calls `list_scan_artifacts()` from `storage/s3.py`
- **Presigned URLs:** `get_presigned_url_by_key()` from `storage/s3.py`
- **Jinja context:** `_build_scan_artifacts_from_raw()` in `jinja_minimal_context.py`
- **Template:** `reports/partials/artifacts.html.j2`

---

## Related docs

- [frontend-api-contract.md](./frontend-api-contract.md) — generate / list / download for the Next.js client.
- [scan-state-machine.md](./scan-state-machine.md) — phase `reporting`.
- `backend/docs/reporting.md` — short pointer to this file.
