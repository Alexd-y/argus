# VHL-PROVABLE-001 — Valhalla report from raw, provable data — Completion Report

**Дата:** 2026-06-10
**Статус:** ✅ Completed (реализация + тесты + ревью)
**Связанные компоненты:** `backend/src/reports/*`, `backend/src/services/reporting.py`, Valhalla HTML/PDF/JSON/CSV/Markdown.

---

## Executive summary

Отчёт Valhalla теперь собирается **только из сырых подтверждённых данных** и каждое попадающее в основной отчёт наблюдение **на 100% доказуемо из сырых артефактов** (raw HTTP request/response, сырой вывод инструмента, OAST/out-of-band callback, скриншот/браузерное подтверждение, command output, либо наблюдение заголовков/TLS, доказанное сырым ответом).

Решены две первопричины «в отчёт попадают не все данные»:

1. **Молчаливая потеря данных.** Findings с `evidence_type = threat_model_inference` ранее **молча удалялись** в `_normalize_one_finding`. Теперь они сохраняются и выносятся в отдельный явно помеченный раздел.
2. **Рассинхрон форматов.** HTML не применял evidence-gates, а JSON/MD применяли downgrade-гейты — форматы показывали разный набор данных. Введён **единый источник истины** (`evidence_partition`), который одинаково делит findings на «доказуемые» (основной отчёт) и «неподтверждённые — требуют ручной проверки» (отдельный раздел) во всех форматах (HTML, PDF, JSON, CSV, Markdown).

Ключевой инвариант: **ничего не удаляется молча**. Неподтверждённое не пропадает, а попадает в раздел *Unconfirmed Observations — Require Manual Verification* с указанием причины и исключается из заголовочных risk-счётчиков.

Изменение ограничено ярусом **Valhalla** — Midgard/Asgard сохраняют прежнее поведение (защита snapshot/parity контрактов).

---

## Принцип доказуемости (single source of truth)

`backend/src/reports/evidence_partition.py` (NEW) — единственное место, решающее «provable vs unconfirmed»:

- `is_provable_from_raw(finding) -> bool` — переиспользует существующий классификатор `classify_evidence` (одна таксономия силы доказательства). Provable ⇔ `evidence_classification ∈ {validated, observed}` **И** `evidence_type ≠ threat_model_inference`.
- `unconfirmed_reason(finding) -> str | None` — безопасный для заказчика текст причины (без секретов/стектрейсов).
- `partition_findings(findings, *, tag=True) -> (confirmed, unconfirmed)` — делит и проставляет на каждый finding флаги `is_provable` / `unconfirmed_reason`.

Маппинг классификаций:

| `evidence_classification` | Куда | Почему |
|---|---|---|
| `validated` | основной отчёт | полная цепочка PoC (raw req+resp, payload, impact, repro, …) |
| `observed` | основной отчёт | техническое наблюдение, доказанное сырым ответом (missing header, banner, 429) |
| `candidate` | unconfirmed | срабатывание сканера без доказанного воздействия |
| `inconclusive` | unconfirmed | инструмент/парсер не дал пригодного сырого артефакта |
| `threat_model_inference` (любой) | unconfirmed | гипотеза модели угроз — нет сырого подтверждения |

---

## Файлы

### Production code

| Файл | Тип | Назначение |
|---|---|---|
| `backend/src/reports/evidence_partition.py` | NEW | Единый предикат/причина/разбиение доказуемости. |
| `backend/src/reports/report_quality_gate.py` | MOD | `_normalize_one_finding`: убрано молчаливое удаление `threat_model_inference`; `evidence_classification` теперь вычисляется на **нормализованном** finding (исправлен латентный баг устаревшей классификации). |
| `backend/src/reports/data_collector.py` | MOD | `FindingRow` + поля `is_provable`/`unconfirmed_reason`; collector тегирует findings через `partition_findings` после нормализации (ничего не теряем). |
| `backend/src/api/schemas.py` | MOD | `Finding` + поля `is_provable`/`unconfirmed_reason` (additive, backward-compatible). |
| `backend/src/reports/generators.py` | MOD | `_finding_row_to_schema` пробрасывает флаги + заполняет `evidence_classification`; helpers `_effective_evidence_classification`, `_is_valhalla_context`; `_finding_to_dict` выдаёт флаги; `generate_json`/`generate_markdown` (Valhalla) разбивают на provable + `unconfirmed_findings`; `generate_csv` добавил колонки `is_provable`/`unconfirmed_reason`; **исправлен пред-существующий креш**: в `_build_valhalla_report_context` finding-dict передавался в `calculate_evidence_gate` (ожидает `EvidenceQuality`) — заменено на `_effective_evidence_classification`. |
| `backend/src/services/reporting.py` | MOD | `findings_rows_for_jinja` переносит флаги в строки шаблона; `prepare_template_context` (Valhalla) делит `findings` (provable) и `unconfirmed_findings`, считает заголовочные severity/OWASP по доказуемым, добавляет `unconfirmed_findings_count`/`total_findings_count`. |

### Templates

| Файл | Тип | Назначение |
|---|---|---|
| `…/partials/valhalla/section_unconfirmed_findings.html.j2` | NEW | Раздел «Unconfirmed Observations — Require Manual Verification»: таблица severity(claimed)/confidence/classification/ID/title/description/CWE/OWASP/причина; всё экранировано `| e`; пустое состояние при отсутствии неподтверждённых. |
| `…/partials/valhalla/sections_07_08_threat_findings.html.j2` | MOD | `{% include %}` нового раздела после таблицы findings. |

### Tests

| Файл | Тип | Назначение |
|---|---|---|
| `backend/tests/reports/test_evidence_partition_vhl_provable.py` | NEW (12 кейсов) | Юнит-тесты предиката/причины/разбиения; интеграция: `threat_model_inference` сохраняется; HTML-контекст и JSON-экспорт делят provable/unconfirmed одинаково; non-Valhalla не затронут. |
| `backend/tests/reports/test_mandatory_section_artifact_status.py` | MOD | `test_threat_model_inference_dropped_by_normalize` → `…_preserved_and_routed_to_unconfirmed` (отражает новый контракт). |

---

## Поток данных (после изменения)

```
collect_async: load findings → dedup → filter_valid → normalize_findings_for_report
   → normalize_severity → partition_findings(findings)  [tag is_provable + reason; nothing dropped]
        │
        ├── HTML/PDF: prepare_template_context (valhalla)
        │      findings = provable rows; unconfirmed_findings = rest
        │      severity/OWASP counts ← только provable
        │      template: основная таблица + раздел Unconfirmed Observations
        │
        └── JSON/CSV/MD: build_report_data_from_scan_report (_finding_row_to_schema несёт флаги+classification)
               generate_json/md (valhalla): partition_findings → "findings" (provable) + "unconfirmed_findings"
               generate_csv: колонки is_provable/unconfirmed_reason
```

Единый предикат `is_provable_from_raw` применяется в точке сборки каждого формата → наборы данных согласованы между форматами.

---

## Тесты и верификация

- Новые тесты: **12 PASS** (`tests/reports/test_evidence_partition_vhl_provable.py`).
- `tests/reports/` целиком: **211 passed, 1 skipped, 10 failed** — все 10 падений **пред-существующие** (подтверждено прогоном на HEAD до изменений; см. ниже), к данному изменению отношения не имеют.
- `tests/snapshots/test_report_snapshots.py` — PASS; `tests/integration/reports/test_valhalla_tier_all_formats.py` (non-docker) — PASS; `tests/test_rpt009_pdf.py`, `tests/test_report_valhalla_full.py` — PASS.
- Lint: новые/изменённые мной строки — **0 ошибок** (ruff/IDE). 8 ruff F841/F541 в затронутых файлах присутствуют и на HEAD (pre-existing, вне scope).

### Пред-существующие падения (НЕ регрессии — падают и на HEAD)

`test_active_injection_quality_gate` (×4), `test_apply_security_header_table_gap_to_findings`, `test_report_export_bundle_parity_rpt006[json]`, `test_val010::test_missing_headers_not_critical_without_exploit`, `test_val010::test_remediation_does_not_include_x_xss_protection`, `test_valhalla_vh010::test_tool_health_summary_respects_mandatory_section_status`, `test_valhalla_vh010::test_no_x_xss_protection_recommendation`, плюс 6 устаревших кейсов в `tests/test_report_quality_gate.py` (отражают убранную ранее «cap/downgrade» логику — комментарии `NO CVSS cap`, `NO rate limit cap` в production-коде на HEAD).

---

## Backward compatibility и контракты

- **Additive** изменения JSON: добавлен ключ `unconfirmed_findings` и поля `is_provable`/`unconfirmed_reason` в каждом finding. Существующий ключ `findings` для Valhalla теперь содержит только доказуемые findings (по требованию).
- ⚠️ **API-контракт (Frontend = источник истины).** Семантика `findings` для Valhalla сужена до provable + появился `unconfirmed_findings`. Это согласовано с явным требованием владельца продукта. Frontend следует обновить, чтобы рендерить раздел «Неподтверждённые» из `unconfirmed_findings`; обновить `docs/api-contracts.md`.
- Midgard/Asgard и не-Valhalla форматы — поведение не изменено (tier-scoped через `_is_valhalla_context`).

---

## Дальнейшие шаги (follow-up, вне текущего scope)

1. Обновить `ARGUS/Frontend` + `docs/api-contracts.md` под `unconfirmed_findings` / `is_provable`.
2. Опционально: распространить scope-filter единообразно и на HTML (сейчас scope-filter только в JSON/MD) для полного паритета out-of-scope findings.
3. Опционально: подгрузка таблицы `evidence` (MinIO object keys) в `ReportData.evidence` для расширенного provenance (сейчас провенанс обеспечен embedded PoC + `evidence_refs` + raw artifacts).
4. Привести в порядок пред-существующие устаревшие тесты quality-gate и pre-existing ruff F841/F541 (отдельной задачей).
