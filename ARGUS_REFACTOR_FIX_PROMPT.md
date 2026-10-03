# ARGUS — промт для агента по рефакторингу backend

> Назначение: отдать этот файл AI-агенту (Claude Code / Cursor) для **безопасного структурного
> рефакторинга** backend ARGUS. Промт самодостаточен: содержит контекст, жёсткие правила,
> приоритизированный список задач с точными целями (`файл:функция`), команды верификации и
> критерии приёмки.
>
> Дата аудита: 2026-10-03. Ветка: `hardening/platform-a`.
> Базовый размер: `backend/src` = 1196 файлов, ~308k строк.

---

## 0. Роль и контекст

Ты — старший Python-инженер, выполняющий рефакторинг кодовой базы **ARGUS** — платформы
автоматизированного пентеста (FastAPI + Celery + PostgreSQL/pgvector + Redis + MinIO).
Ядро — линейный 8-фазный pipeline (`source_analysis → recon → quick_fuzz → threat_modeling →
vuln_analysis → exploitation → post_exploitation → reporting`), управляемый
`ScanStateMachine`. Любая правка в фазовых обработчиках, state machine или sandbox-исполнении
напрямую влияет на результаты реальных сканирований — **поведение менять нельзя**.

Прочитай `CLAUDE.md` в корне репозитория перед началом — там команды, архитектура и границы
модулей.

## 1. Жёсткие правила (нарушение = откат)

1. **Поведение сохраняется байт-в-байт.** Рефакторинг — только реструктуризация: извлечение
   функций, уменьшение вложенности, группировка аргументов. Никаких изменений логики,
   порядка вызовов, значений по умолчанию или контрактов API/БД.
2. **Каждая задача — отдельный коммит.** Один коммит = одна функция/один файл. Не смешивай
   несвязанные правки.
3. **После каждой задачи прогоняй верификацию** (раздел 4). Красный тест/линтер → откат задачи,
   не продолжай.
4. **Не трогай сигнатуры публичных функций**, вызываемых из других модулей, без обновления всех
   вызовов в том же коммите. Сначала `grep` по имени, убедись в полноте.
5. **Извлечённые приватные функции** именуй с префиксом `_` и размещай рядом с исходной в том же
   модуле. Не создавай новые модули без явной необходимости.
6. **Не меняй сигнатуры/контракты, завязанные на сериализацию** (Pydantic-схемы, экспорт
   JSON Schema для LLM `response_format`, подписанные YAML-каталоги). Для каталогов — после
   правок пере-подписывай (`scripts/*_sign.py`).
7. **Типизацию сохраняй или усиливай.** Не удаляй аннотации. `from __future__ import annotations`
   уже включён в большинстве файлов.
8. Стиль: `black` (line-length 100) + `ruff`. Не добавляй `# noqa` для сокрытия проблем.

## 2. Что уже сделано (НЕ переделывать)

Автоматический проход уже устранил **55 «тихих» подавлений исключений** (широкий
`except Exception: pass` без пояснения) в 30 файлах — заменены на
`logger.debug(..., exc_info=True)` (а в `recon/jobs/runner.py` и
`orchestration/scan_events.py` — на `logger.warning`, т.к. там терялось важное состояние).
В 6 файлов добавлен модульный `logger`. Эти места трогать не нужно.

Линтеры на старте уже зелёные: `ruff`, `black --check`, `bandit -c pyproject.toml` (0 issues).
Не «чини» то, что не сломано.

## 3. Задачи (в порядке приоритета)

### Приоритет P1 — God-функции (138 функций ≥120 строк)

Декомпозируй перечисленные функции на связные приватные хелперы (целевой размер каждой
результирующей функции — ≤80 строк, одна зона ответственности). Метод: выдели логические блоки
(подготовка входных данных → основной проход → постобработка/сборка результата) в отдельные
`_`-функции с явными аргументами и возвращаемыми значениями. **Сначала напиши/запусти
характеризующие тесты** на текущее поведение, если покрытие недостаточно.

Топ-целей (строк / файл / функция):

| Строк | Файл | Функция |
|------:|------|---------|
| 2112 | `recon/reporting/stage1_enrichment_builder.py` | `build_stage1_enrichment_artifacts` |
| 1375 | `recon/vulnerability_analysis/active_scan/va_active_scan_phase.py` | `run_va_active_scan_phase` |
| 857 | `orchestration/handlers.py` | `run_vuln_analysis` |
| 741 | `recon/vulnerability_analysis/pipeline.py` | `_build_va_fallback_output` |
| 741 | `recon/reporting/html_report_builder.py` | `build_html_report` |
| 735 | `reports/valhalla_report_context.py` | `build_valhalla_report_context` |
| 710 | `reports/report_pipeline.py` | `run_generate_report_pipeline` |
| 563 | `orchestration/state_machine.py` | `_dispatch_phase_handler` |
| 518 | `reports/valhalla_report_context.py` | `_compute_mandatory_sections_and_coverage` |
| 495 | `orchestration/exploitation_executor.py` | `_execute_tool_in_sandbox` |

Полное распределение по модулям: `recon` 50, `reports` 33, `orchestration` 21, `api` 7,
`llm` 5, остальное — по 1–3.

> **Начни с 10 функций из таблицы.** Остальные — только после приёмки первых 10. Для каждой
> большой функции в state machine / фазовых обработчиках предварительно убедись, что есть
> тесты уровня фазы, иначе сначала добавь характеризующий тест.

### Приоритет P2 — Глубокая вложенность (69 функций с вложенностью ≥6)

Снизь вложенность через early-return / guard-clause, извлечение внутренних циклов в хелперы,
замену вложенных `try` на отдельные функции. Целевая максимальная вложенность — 4.

Топ-целей (глубина / файл / функция):

| Глубина | Файл | Функция |
|--------:|------|---------|
| **27** | `orchestration/exploitation_executor.py` | `_execute_tool_in_sandbox` |
| 18 | `recon/vulnerability_analysis/active_scan/va_active_scan_phase.py` | `run_va_active_scan_phase` |
| 18 | `.../va_active_scan_phase.py` | `_sink_plan_step` |
| 17 | `.../va_active_scan_phase.py` | `_sink_tool_run` |
| 13 | `orchestration/state_machine.py` | `_dispatch_phase_handler` |

`_execute_tool_in_sandbox` (вложенность 27, 495 строк) — наихудшая точка во всей базе; это
первый кандидат и для P1, и для P2 одновременно.

### Приоритет P3 — Слишком много аргументов (80 функций с ≥10 параметрами)

Сгруппируй связанные параметры в dataclass/Pydantic-модель «запроса» (напр. `ReportDocumentSpec`,
`UsageRecord`). Для каждой правки обнови все места вызова в том же коммите.

Топ-целей (аргументов / файл / функция):

| Арг | Файл | Функция |
|----:|------|---------|
| **43** | `reports/report_document.py` | `build_report_document` |
| 26 | `recon/vulnerability_analysis/active_scan/poc_schema.py` | `build_proof_of_concept` |
| 22 | `reports/valhalla_report_context.py` | `_compute_mandatory_sections_and_coverage` |
| 21 | `reports/valhalla_report_context.py` | `build_valhalla_report_context` |
| 17 | `orchestration/state_machine.py` | `_execute_phase` |
| 15 | `llm/facade.py` | `call_llm_unified` / `call_llm_sync` / `_call_llm_unified_impl` |

> `build_report_document` (43 аргумента) — начни с него: введи `@dataclass ReportDocumentSpec`,
> перенеси параметры в него, обнови вызовы. Это самый показательный случай.

### Приоритет P4 — Модернизация (точечно, низкий риск)

1. **Deprecated Pydantic `json_encoders`** — `recon/vulnerability_analysis/evidence_collector.py:52`:
   ```python
   model_config = ConfigDict(json_encoders={bytes: lambda _v: None})
   ```
   Заменить на кастомный сериализатор поля через `field_serializer` (Pydantic v2), т.к.
   `json_encoders` удаляется в Pydantic v3. Проверить, что сериализация `bytes → None`
   сохраняется.

## 4. Верификация (после КАЖДОЙ задачи)

Из `backend/` с активным venv (`backend/.venv`):

```bash
# 1. Линт + формат изменённых файлов
ruff check src/
black --check src/

# 2. SAST не должен деградировать
bandit -c pyproject.toml -r src/        # ожидаем 0 issues

# 3. Тесты по затронутой области (пример для reports/llm/orchestration/recon)
python -m pytest tests/reports/ tests/unit/llm/ tests/unit/orchestration/ tests/unit/recon/ -q

# 4. Для правок в фазовых обработчиках / state machine — профильные наборы
python -m pytest tests/api/ -q
```

Перед сдачей всей серии — полный прогон без docker-маркеров:
```bash
python -m pytest tests/ -q
```

## 5. Критерии приёмки

- [ ] Поведение не изменилось (все ранее зелёные тесты зелёные; новые характеризующие тесты
      проходят до и после).
- [ ] `ruff check src/` и `black --check src/` — чисто.
- [ ] `bandit -c pyproject.toml -r src/` — 0 issues (без деградации baseline).
- [ ] Ни одна целевая функция P1 не превышает ~80 строк; вложенность P2 ≤4;
      функции P3 принимают ≤6 позиционных параметров (остальное — в spec-объекте).
- [ ] Каждая задача — отдельный атомарный коммит с понятным сообщением
      (`refactor(<module>): split <func> into helpers`).
- [ ] `datetime`/Pydantic deprecation из P4 устранены без изменения сериализации.

## 6. Если застрял

- Функция без тестового покрытия и с неочевидным поведением → **сначала** напиши
  характеризующий тест (зафиксируй текущий вывод), потом рефактори.
- Неясно, приватная функция или часть публичного контракта → `grep -rn "<имя_функции>" src/ tests/`.
- Правка затрагивает подписанный YAML-каталог → после правки
  `python scripts/<payloads|tools|prompts>_sign.py`.
- Риск изменить поведение pentest-pipeline и нет уверенности → не трогай, оставь TODO с
  пояснением и переходи к следующей задаче.
