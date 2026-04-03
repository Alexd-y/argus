# Reporting (backend synopsis)

Canonical **RPT-010** architecture, API, env vars, Celery, MinIO, and Valhalla follow-up scheduling (deferred):

**[../../docs/reporting.md](../../docs/reporting.md)**

PDF (RPT-009) build notes and template paths remain relative to `ARGUS/backend/` (`src/reports/templates/reports/`, WeasyPrint in `Dockerfile`).

## Valhalla (VHL / эталон `Report Valhalla.md`)

- **Эталон оглавления:** файл **`Report Valhalla.md`** в корне репозитория; полная таблица соответствия разделов и реализации — в **[../../docs/reporting.md](../../docs/reporting.md)** (раздел *Valhalla — полная структура*).
- **Шаблон:** `src/reports/templates/reports/valhalla.html.j2`; структурированный контекст: `ValhallaReportContext` / `build_valhalla_report_context` → `src/reports/valhalla_report_context.py`; в Jinja — `valhalla_context` (см. `jinja_minimal_context.py`).
- **AI (Valhalla-only ключи):** `attack_scenarios`, `exploit_chains`, `remediation_stages`, `zero_day_potential`; плюс `executive_summary_valhalla`, остальные как у Asgard и roadmap/hardening. Реестр: `src/orchestration/prompt_registry.py`; порядок секций: `report_tier_sections("valhalla")` в `src/services/reporting.py`.
- **JSON:** при `tier=valhalla` `generate_json` добавляет **`valhalla_report`** (`build_valhalla_report_payload` в `src/reports/generators.py`).
- **CSV:** при генерации отчёта Valhalla с форматом `csv` дополнительно загружается **`valhalla_sections.csv`** (`generate_valhalla_sections_csv`, константа `VALHALLA_SECTIONS_CSV_FORMAT`) — см. пайплайн `src/reports/report_pipeline.py`. Скачивание: `GET .../download?format=valhalla_sections.csv` (`src/api/routers/reports.py`).
- **Миграция 012:** `alembic/versions/012_report_objects_format_length.py` — `report_objects.format` **VARCHAR(20) → VARCHAR(48)** под строку формата `valhalla_sections.csv`.

## Proof of concept (PoC) in HTML/PDF findings

- **Data:** Each finding may carry `proof_of_concept` (JSONB / dict) with additive fields from `poc_schema.PROOF_OF_CONCEPT_KEYS`: `tool`, `parameter`, `payload`, `request`, `response`, `response_snippet`, `curl_command`, `javascript_code`, `screenshot_key`. Length caps applied when building via `build_proof_of_concept` (e.g. `response` 1024, `response_snippet` 500).
- **Pipeline:** `ReportDataCollector` → `FindingRow.proof_of_concept` → `findings_rows_for_jinja()` copies the dict, may set `poc_screenshot_url` from MinIO presign when `screenshot_key` is present (`src/services/reporting.py`). Regenerated HTML uses the same Jinja env as tier reports (`render_findings_table_html`).
- **Tiers (`findings_table.html.j2`):**
  - **Asgard / Valhalla:** `finding-poc`: parameter, payload, JavaScript, cURL, request/response, **response snippet**, screenshot link (or inline `<img>` when `embed_poc_screenshot_inline` is true).
  - **Midgard:** Stub only; full PoC omitted.
  - PoC with only `tool` → “No PoC available”.
- **Env (reporting / VA):** `VA_POC_PLAYWRIGHT_SCREENSHOT_ENABLED` — worker-side Playwright screenshots + snippet enrichment; override off with `VA_POC_PLAYWRIGHT_SCREENSHOT=0|false|off|no`. `REPORT_POC_EMBED_SCREENSHOT_INLINE` — embed screenshot in HTML/PDF as image (default link-only). Для **valhalla** в `prepare_template_context` по умолчанию встраивание скриншота **включено**, если не передано иное в `extra["embed_poc_screenshot_inline"]`. Details: [../../docs/reporting.md](../../docs/reporting.md).
- **AI payload (Valhalla, VHQ-005):** `build_ai_input_payload` — в findings: `finding_id`, `description` (усечение), `cve_ids`, `exploit_available`; в `valhalla_context`: `risk_matrix`, `critical_vulns` (компактно для LLM). Промпты: `vhq005-20250328` в `prompt_registry.py`.
- **VDF / Valhalla datafill:** плоские поля `tech_stack_structured`, `ssl_tls_analysis`, `security_headers_analysis`, `outdated_components_table`, `robots_sitemap_analysis` и **`valhalla_fallback_messages_ru`** (ключи: `tech_stack`, `ssl_tls`, `security_headers`, `outdated_components`, `robots_sitemap`, `leaked_emails`) — см. `reporting.py` и `build_valhalla_report_context`. Fallback для tech/stack ссылается на **WhatWeb**; для SSL — на **testssl.sh** / **sslscan** (Celery: `_run_testssl_va_celery_with_sslscan_fallback` в `tasks/tools.py`). **`HARVESTER_ENABLED`** включает **theHarvester** в VA для сигналов email. **`VA_ROBOTS_EXTENDED_PIPELINE`** + sandbox — опционально **gospider/parsero** после `robots_sitemap_analyzer` (`src/recon/robots_sitemap_analyzer.py`). Тесты парсеров: `tests/test_robots_sitemap_analyzer.py`. Полная таблица — [../../docs/reporting.md](../../docs/reporting.md) (раздел *Valhalla: VA, fallback-тексты и recon robots/sitemap*).

## OWASP Top 10:2025 compliance block

- **Finding row:** `owasp_category` on `FindingRow` → Asgard/Valhalla: код `A01`…`A10` + русский `title_ru` (из JSON через `get_owasp_category_info`) или fallback EN title из `owasp_top10_2025.py`.
- **Summary:** **OWASP Top 10:2025 Compliance** (`owasp-compliance-table` в `findings_table.html.j2`) — строки `build_owasp_compliance_rows`; колонки RU: **Категория**, **Описание**, **Наличие находок**; tooltip на категории — усечённый `how_to_fix` (`description_hover`). Midgard — блок скрыт.
- **Config:** env **`OWASP_JSON_PATH`** → `settings.owasp_json_path` (default `data/owasp_top_10_2025_ru.json` under backend root). Loader: `src/owasp/owasp_loader.py`.
- **AI payload:** при наличии `owasp_summary` добавляется **`owasp_category_reference_ru`** (`src/services/reporting.py`) — см. [../../docs/reporting.md](../../docs/reporting.md) § OWASP.
- **Mapping:** `owasp_category_map.py` / DB `findings.owasp_category`. Полная таблица env и детали — в каноническом [../../docs/reporting.md](../../docs/reporting.md).
