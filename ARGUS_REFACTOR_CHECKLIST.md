# ARGUS — чеклист рефакторинга backend (для разработчика)

**Дата аудита:** 2026-10-03 · **Ветка:** `hardening/platform-a` · **Объём:** `backend/src` =
1196 файлов, ~308k строк.

Аудит выполнен автоматическими анализаторами (`ruff`, `black`, `bandit`) + собственным
AST-сканером (длина функций, вложенность, арность, обработка исключений). На старте `ruff`,
`black --check` и `bandit -c pyproject.toml` были **зелёными** — поэтому находки лежат на уровне
семантики/структуры, а не стиля.

---

## ✅ Уже исправлено в этой сессии

| # | Находка | Было | Стало | Файлы |
|---|---------|------|-------|-------|
| F1 | «Тихое» подавление исключений — широкий `except Exception: pass`/`...` без пояснения, скрывал неожиданные ошибки | 55 мест | `logger.debug(..., exc_info=True)` (2 места → `logger.warning`, где терялось состояние) | 30 файлов |
| F1a | 6 из этих файлов не имели модульного `logger` | — | добавлен `logging.getLogger(__name__)` | `cve_platform_mitigations`, `censys_adapter`, `securitytrails_adapter`, `finding_normalizer`, `valhalla_finding_normalization`, `report_quality_gate` |
| P4 | Deprecated Pydantic `json_encoders` (удаляется в v3) | `ConfigDict(json_encoders={bytes:...})` | `@field_serializer(when_used="json")` — поведение идентично (round-trip проверен) | `evidence_collector.py` |
| P1+P2 | `_execute_tool_in_sandbox` — god-функция + вложенность 27 | 495 строк / nest 27 | **154 строки / nest 3**; argv-диспетч → `_build_sandbox_cmd_parts`, запуск → `_run_shared_sandbox_exec` | `exploitation_executor.py` |
| P1 #8 | `_dispatch_phase_handler` — диспетчер фаз | 563 строки | **62 строки**; 8 ветвей → `_dispatch_phase_<name>` (параметры по AST) | `state_machine.py` |
| P1 #4 | `_build_va_fallback_output` — fallback-диспетч по task | 741 строка | **83 строки**; 26 веток → `_va_fallback_<task>` | `vulnerability_analysis/pipeline.py` |

**Последовательные god-функции (dataflow-извлечение стадий, AST-инструмент `tmp/bx.py`):**

| # | Функция | Было → Стало | Верификация |
|---|---------|-------------|-------------|
| P1 | `_compute_mandatory_sections_and_coverage` | 518 → **181** (7 `_vh_section_*`) | reports 760 passed |
| P1 | `build_valhalla_report_context` | 735 → **479** (8 `_vh_build_*`) | reports 760 passed |
| P1 | `run_generate_report_pipeline` | 710 → **327** (3 `_rgp_*`) | reports 340 passed |
| P1 | `build_html_report` | 741 → **179** (7 `_html_*`) | smoke + stage1-report 31 passed |
| P1 | `run_vuln_analysis` | 857 → **546** (5 `_va_*`) | orchestration 467 passed |

**Коммиты (11):** логирование, json_encoders, exploitation, state_machine, va_fallback,
_compute_mandatory, build_valhalla, report_pipeline, build_html_report, run_vuln_analysis (+docs).
Каждый верифицирован: `ruff`/`black`/`bandit` зелёные, профильные тесты зелёные.

**`build_stage1_enrichment_artifacts` — СДЕЛАНО (2112 → 1169, −943):**
Запущены контейнеры (postgres/redis/minio/sandbox); выяснилось, что unit-тест
`test_stage1_enrichment_builder.py` на самом деле быстрый (auto-marked `requires_docker`
из-за localhost-URL в фикстурах, но исполняется за ~7s через `pytest -m ""`). Это дало
быструю страховку. Извлечено (dataflow-инструментом `tmp/bx.py`): 8 AI-блоков (`_s1ai_*`),
2 crawl-цикла (`_s1_crawl_*`), 2 row-группы (`_s1_rows_*`). Верификация: **33 passed**
(1 предсущ. fail — footer scan-mode, не связан). Остаток — литерал `output_files` (157)
и взаимозависимые temp-циклы — оставлены inline.

**`run_va_active_scan_phase` (1375 → 429) — СДЕЛАНО:**
7 взаимно-ссылающихся sink-замыканий (`_sink_tool_run`, `_sink_ssl_probe_step`,
`_sink_plan_step`, `_sink_va_tool_artifacts` + `_hook_timeout`, `_mark_*`, `_log_*`),
захватывавших до ~25 внешних переменных, подняты в класс **`_VaActiveScanSinks`**.
Метод: `symtable` даёт точные свободные переменные каждого замыкания; тело метода
копируется **дословно** + `self` + преамбула `X = self.X` (включая соседние sink'и как
bound-методы) — ни одна ссылка внутри ~900 строк не переписывается. Общее состояние
хранится один раз в `__init__` (25 полей); `_publish_active_injection_coverage` оставлен
вложенным (мутирует тот же dict). Верификация: **36 passed + 3 предсуществующих падения**
(environment-dependent severity на реальных инструментах) — те же, что на дорефакторном
baseline (проверено прогоном обеих версий). Инструмент: `tmp/lift_va.py`.

**Почему безопасно:** замена `pass` на `logger.debug(...)` не меняет control flow (логирование
не бросает исключений при штатной конфигурации) — best-effort семантика сохранена, но скрытые
сбои теперь наблюдаемы.

**Верификация пройдена:** `ruff` ✓, `black --check` ✓, `bandit` 0 issues ✓,
`pytest tests/reports tests/unit/llm tests/unit/orchestration tests/unit/recon` → **1076 passed**.

> **Важно:** НЕ все `except ...: pass` — проблема. 59 мест ловят **конкретный** тип
> (`json.JSONDecodeError`, `ValueError` при `urlparse`/`ip_address`) как идиоматичный fallback —
> они корректны и намеренно не трогались. 16 широких были уже документированы
> (`# noqa: BLE001 — defensive`). Исправлены только 55 **широких и недокументированных**.

---

## ⏳ Остаётся исправить (структурное — в `ARGUS_REFACTOR_FIX_PROMPT.md`)

Эти правки НЕ применялись автоматически: они меняют структуру кода в ядре pentest-pipeline и
требуют характеризующих тестов + ручной верификации, чтобы гарантировать неизменность поведения.

### P1 — God-функции топ-10: **10 из 10 сделаны** ✅

| Строк | Файл:функция | Статус |
|------:|--------------|--------|
| 2112 | `recon/reporting/stage1_enrichment_builder.py` → `build_stage1_enrichment_artifacts` | ✅ **сделано** 2112→1169 (8 `_s1ai_*` + 2 `_s1_crawl_*` + 2 `_s1_rows_*`) |
| 1375 | `.../active_scan/va_active_scan_phase.py` → `run_va_active_scan_phase` | ✅ **сделано** 1375→429 (7 замыканий → класс `_VaActiveScanSinks` через symtable-lifting) |
| 857 | `orchestration/handlers.py` → `run_vuln_analysis` | ✅ **сделано** 857→546 (5 `_va_*`) |
| 741 | `recon/vulnerability_analysis/pipeline.py` → `_build_va_fallback_output` | ✅ **сделано** 741→83 (26 хелперов) |
| 741 | `recon/reporting/html_report_builder.py` → `build_html_report` | ✅ **сделано** 741→179 (7 `_html_*`) |
| 735 | `reports/valhalla_report_context.py` → `build_valhalla_report_context` | ✅ **сделано** 735→479 (8 `_vh_build_*`) |
| 710 | `reports/report_pipeline.py` → `run_generate_report_pipeline` | ✅ **сделано** 710→327 (3 `_rgp_*`) |
| 563 | `orchestration/state_machine.py` → `_dispatch_phase_handler` | ✅ **сделано** 563→62 (8 хелперов) |
| 518 | `reports/valhalla_report_context.py` → `_compute_mandatory_sections_and_coverage` | ✅ **сделано** 518→181 (7 `_vh_section_*`) |
| 495 | `orchestration/exploitation_executor.py` → `_execute_tool_in_sandbox` | ✅ **сделано** 495→154, nest 27→3 |

Распределение по модулям: **recon 50, reports 33, orchestration 21**, api 7, llm 5, прочее 1–3.
Цель — каждая результирующая функция ≤80 строк, одна зона ответственности.

> **Классификация по структуре (важно для стратегии):** сделанные — *диспетчер-подобные*
> (независимые `if ... return` ветви: механически извлекаются со строгим сохранением поведения).
> Оставшиеся 7 из топ-10 — *последовательная сборка* (десятки `Assign`, один `return`, общие
> локальные переменные между блоками): механический слайсинг небезопасен, нужен ручной анализ
> «что читает/пишет каждый блок» + характеризующий тест на каждую. Делать по одной за коммит.

- [x] Диспетчер-подобные god-функции из топ-10 (3 шт.).
- [ ] Последовательные god-функции из топ-10 (7 шт.) — по одной за выделенную сессию.
- [ ] Остальные 128 функций ≥120 строк — по модулям (recon → reports → orchestration).
- [ ] Для функций в фазовых обработчиках / state machine — сперва характеризующий тест фазы.

> Побочно: ветвь `EXPLOITATION` внутри `state_machine.py`, вынесенная в
> `_dispatch_phase_exploitation` (334 строки), теперь изолирована и стала отдельной
> god-функцией-кандидатом — удобная следующая цель.

### P2 — Глубокая вложенность: 69 функций ≥6

| Глубина | Файл:функция |
|--------:|--------------|
| **27** | `orchestration/exploitation_executor.py` → `_execute_tool_in_sandbox` |
| 18 | `.../va_active_scan_phase.py` → `run_va_active_scan_phase` |
| 18 | `.../va_active_scan_phase.py` → `_sink_plan_step` |
| 17 | `.../va_active_scan_phase.py` → `_sink_tool_run` |
| 13 | `orchestration/state_machine.py` → `_dispatch_phase_handler` |

- [ ] Guard-clause / early-return, извлечение вложенных циклов и `try` в хелперы. Цель — ≤4.
- [ ] `_execute_tool_in_sandbox` — абсолютный приоритет (27 уровней, 495 строк).

### P3 — Слишком много аргументов: 80 функций ≥10

| Арг | Файл:функция | Действие |
|----:|--------------|----------|
| **43** | `reports/report_document.py` → `build_report_document` | ❌ **не цель**: все 43 — keyword-only (`*,`), 0 позиционных → критерий «≤6 позиционных» уже выполнен; spec-объект продублировал бы `ReportDocumentV1` и сломал ~25 вызовов в тестах. Оставить как есть. |
| 26 | `.../active_scan/poc_schema.py` → `build_proof_of_concept` | spec-объект |
| 22 | `reports/valhalla_report_context.py` → `_compute_mandatory_sections_and_coverage` | spec-объект |
| 21 | `reports/valhalla_report_context.py` → `build_valhalla_report_context` | spec-объект |
| 17 | `orchestration/state_machine.py` → `_execute_phase` | сгруппировать phase-контекст |
| 15 | `llm/facade.py` → `call_llm_unified` / `call_llm_sync` / `_call_llm_unified_impl` | опции в объект |

- [ ] Группировать связанные параметры в dataclass/Pydantic-модель; обновлять все вызовы в том же коммите.
- [ ] Реальная цель — функции с **позиционными** аргументами ≥7 (35 шт.), НЕ keyword-only.
      Исключить FastAPI-роуты (`admin_list_findings`, `admin_list_reports`, `list_webhook_dlq`
      и т.п.) — там параметры обязательны для DI/парсинга query; группировка меняет API-поверхность.
      Чистые внутренние цели: `state_machine._execute_phase` (17 поз.),
      `llm_gateway/usage_ledger._persist_to_db`/`record_usage` (15).

### P4 — Модернизация (низкий риск)

- [x] **Pydantic `json_encoders`** — `evidence_collector.py` переведён на
      `@field_serializer("screenshot_bytes", when_used="json")`. ✅ **сделано**

---

## Что проверено и оказалось в порядке (ложные/неактуальные сигналы)

- Голых `except:` — **0**. Мутабельных дефолтов (`def f(x=[])`) — **0**. `print()` в `src/` — **0**.
- `== None` / `type(x) ==` — по 1–2 (не трогаем). Логирование f-строками — 0.
- `datetime.utcnow()` — 2 совпадения, но оба внутри docstring/комментария (ложные срабатывания).
- `from X import *` — 1 (`knowledge_graph/graph/builder.py`) — намеренный backward-compat shim
  с `# noqa: F403`, не трогать.
- `bandit` — 0 issues (severity Low/Medium/High = 0), baseline документирован.

## Команды верификации

```bash
cd backend                       # venv: backend/.venv активен
ruff check src/
black --check src/
bandit -c pyproject.toml -r src/                 # ожидаем 0 issues
python -m pytest tests/ -q                       # полный прогон без docker-маркеров
```
