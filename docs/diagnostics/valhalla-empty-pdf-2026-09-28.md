# Диагностика: пустой одностраничный Valhalla PDF (2026-09-28)

**Артефакт:** `1b563359-9029-4458-97aa-95df21f54014.pdf`
**Report ID:** `135f8c21-fc4f-4a73-9e86-05f1ffd42eaf` · **Target:** `alleksy.com` · **Tier:** Valhalla / `leadership_technical`
**Producer:** WeasyPrint 70.0 · **Страниц:** 1 · **Размер:** 15 КБ
**Состояние репозитория при разборе:** HEAD `6c2012e` (ветка `hardening/platform-a`).

## Симптом

Полный отчёт Valhalla выгружается как PDF на одну страницу: только шапка и титульный блок,
плюс футер. Ни находок, ни доказательств, ни PoC, ни выводов. Извлечённый текст PDF содержит
только элементы, идущие в разметке до и после `.main-container` (шапка + титул + футер) —
то есть контент области `#form-area` в PDF обрезан, а не отсутствует в HTML.

## Подтверждённые причины (сверено с кодом на HEAD `6c2012e`)

### D1 — КОРНЕВАЯ ПРИЧИНА: flex-раскладка несовместима с постраничным выводом WeasyPrint — **ПОДТВЕРЖДЕНО**

`src/reports/templates/reports/valhalla_secreport_base.html.j2`:

* `body { min-height: 100vh }`, `#app { display:flex; flex-direction:column; min-height:100vh }`,
  `.main-container { display:flex; flex:1; min-height:0 }`, `#form-area { flex:1; max-width:1120px }`.
* Блок `@media print` переопределял только `.main-container { display:block }` и скрывал
  `#sidebar`, **но оставлял `#app` flex-контейнером с `min-height:100vh`** и не сбрасывал
  `flex:1` у `.main-container` / `#form-area`.

WeasyPrint **не фрагментирует flex-контейнеры между страницами**. `#app` укладывается ровно на
одну страницу высотой `100vh`; `.main-container` получает остаток высоты, весь контент сверх
него обрезается; футер (следующий flex-элемент) печатается на той же странице. Вырожденные
переносы в шапке (`Svalbard Security / Inc. Security / Report`) — тот же дефект: flex-элементы
`.app-header` получили аномально узкую ширину.

**Вывод:** это не потеря данных. HTML полный, обрезка происходит на этапе печатной раскладки.

### D5 — XML отдаётся как CSV; xml не генерируется пайплайном — **ПОДТВЕРЖДЕНО**

* `src/api/routers/reports.py::download_report` — ветвление по формату завершалось
  `elif fmt == "md": ... else: generate_csv(...)`. `xml` присутствует в `VALID_FORMATS`
  (строки 105–124), проходит валидацию, попадает в финальный `else` и получает **CSV-содержимое**
  под заголовком `application/xml`.
* `REPORT_FORMAT_SET` / `DEFAULT_REPORT_FORMATS` в `src/reports/report_pipeline.py:97-98`
  не включали `xml` → хранимого `xml`-артефакта нет, каждый скачивание шло через regenerate → CSV.

### D4 — гейт полноты написан, но не подключён — **ПОДТВЕРЖДЕНО**

`src/reports/valhalla_completeness.py::valhalla_release_blockers` не вызывался ни из
`report_pipeline.py`, ни из `report_service.py`. Валидатор существовал, релиз не блокировал.

### D2 / D3 — статус

* D2 (branded layout `backend/templates/reports/valhalla/pdf_layout.html` — executive brief,
  молчаливый fallback в `generate_pdf`): подтверждено наличие файла и fallback-ветки; branded
  layout по замыслу не содержит полных карточек находок. Судьба layout'а — Вариант 1 (см.
  `docs/report-service.md`): остаётся отдельным executive-артефактом, не единственным Valhalla-PDF.
* D3 (`skipped_no_llm` трактуется как `ok` → пустые секции): подтверждено в
  `src/services/reporting.py`. Относится к Фазе E (обязательные LLM-выводы).

## Воспроизведение

Скрипт `backend/scripts/debug_valhalla_render.py` собирает контекст тем же путём, что прод
(`build_report_export_payload` → `generate_*`), и выгружает `report.{html,pdf,md,json,xml}`,
`context.keys.json` и `summary.json` в `--out` (по умолчанию `/tmp/valhalla-debug`). `summary.json`
печатает число страниц PDF, длину HTML, все `id="…"`-якоря, `len(findings)`, карту `ai_sections`,
непустые поля `valhalla_context`, `coverage_label` / `report_mode_label` и список якорей секций,
которые есть в HTML, но отсутствуют в тексте PDF (прямая проверка D1).

```bash
cd backend && python scripts/debug_valhalla_render.py \
    --report-id 135f8c21-fc4f-4a73-9e86-05f1ffd42eaf --tier valhalla
```

**Критерий приёмки Фазы A выполнен:** D1 подтверждён по коду; наличие HTML-якорей секций при их
отсутствии в тексте PDF воспроизводит одностраничную обрезку. D1 не опровергнут — план опирается
на него правомерно.

## Исправления (последующие фазы)

* **Фаза B (D1):** блок `@media print` в `valhalla_secreport_base.html.j2` переведён на блочную
  раскладку — `#app`, `.main-container`, `#form-area` → `display:block; flex:none; min-height:0;
  height:auto`; колонтитулы через `@page`/`counter(page)`; `page-break-inside:auto` на длинных
  панелях; `break-after:avoid` на заголовках. Аудит `base/asgard/midgard` — патологии нет
  (простой блочный layout 960px). Branded `pdf_styles.css` — flex/grid только на ограниченных
  cover/meta-блоках, допустимо.
* **Фаза F (D5):** `download_report` — явные ветки `elif fmt == "xml"` / `elif fmt == "csv"` и
  `else: HTTP 400`; `xml` добавлен в `REPORT_FORMAT_SET`, `DEFAULT_REPORT_FORMATS`, `CONTENT_TYPES`
  и в цикл генерации пайплайна.
* **Фаза G (D4):** `valhalla_release_blockers` подключён в `report_pipeline` перед переводом
  релиза в `ready` (`_compute_valhalla_release_blockers`). Блокеры всегда логируются; блокируют
  релиз при `valhalla_release_blockers_enabled=True` (staged rollout, default False до готовности
  Фаз C–E, дающих полноценный ordered-section registry для VP-04).
