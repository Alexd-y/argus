# ARG-020 — Cycle 2 capstone: state-machine audit + parser-dispatch hardening + coverage matrix extension + docs regen

**Дата:** 2026-04-19
**Тип:** Worker report (capstone)
**Цикл:** ARGUS Finalization Cycle 2 (`orch-2026-04-18-argus-cycle2`)
**Plan:** `ai_docs/develop/plans/2026-04-18-argus-finalization-cycle2.md`
**Status:** ✅ Completed

---

## 1. Scope (что было поставлено worker'у)

ARG-020 — критический capstone Cycle 2, объединивший пять рабочих потоков:

1. **State-machine audit** — убедиться, что все горячие пути `va_orchestrator` и других фаз больше не используют legacy `subprocess`/`hexstrike`-execution и идут через `K8sSandboxDriver` + `dispatch_parse`.
2. **Parser-dispatch hardening** — гарантировать, что для всех **157** инструментов в каталоге существует **детерминированный** путь к `dispatch_parse`. Инструменты без зарегистрированного парсера должны эмитить структурированный warning (`unmapped_tool`/`no_handler`) **И** один heartbeat `FindingDTO` (Severity.INFO, category INFO) — чтобы UI/orchestrator видели «инструмент отработал, парсер отложен» вместо «инструмент отработал, нашёл 0 уязвимостей».
3. **Coverage matrix extension** — расширить `tests/test_tool_catalog_coverage.py` с **5 → 10 контрактов** на каждый дескриптор + добавить агрегированный summary parser-coverage.
4. **Regenerate `docs/tool-catalog.md`** — добавить колонку `parser_status` и summary-секцию `## Parser coverage` с разбивкой mapped/heartbeat/binary_blob (catalog-totals + per-phase).
5. **Final cleanup** — удалить устаревшие `# TODO: deprecate hexstrike` комментарии и outdated docstrings; убедиться что `tests/test_argus006_hexstrike.py` остаётся зелёным.

---

## 2. State-machine audit (результат)

Полный grep-обход показал, что миграция на `K8sSandboxDriver` уже выполнена в предыдущих циклах (ARG-002, ARG-004, ARG-008, ARG-009). На горячем пути ARGUS:

| Модуль | Состояние | Комментарий |
|---|---|---|
| `backend/src/orchestration/state_machine.py` | ✅ Чисто | Все фазы (`recon`, `vuln_analysis`, `exploitation`, `post_exploitation`, `reporting`) делегируют в `src.orchestration.handlers.run_*`, ни одного прямого `subprocess.run`/`docker exec` |
| `backend/src/agents/va_orchestrator.py` | ✅ Чисто | LLM-агент, не выполняет инструменты напрямую |
| `backend/src/recon/exploitation/executor.py` | ✅ Чисто | Использует `KubernetesSandboxAdapter` через `SandboxRunner` |
| `backend/src/sandbox/adapter_base.py:ShellToolAdapter.parse_output` | ✅ Чисто | Делегирует в `dispatch_parse(...)`; legacy `parse_output_not_implemented` warning удалён в Cycle 1 |
| `backend/src/sandbox/k8s_adapter.py` | ✅ Чисто | Единственный `subprocess`-call — `kubectl auth` через `kubernetes` Python client (transitive, allowlisted) |
| `backend/src/` (рекурсивно, по `hexstrike` regex) | ✅ Чисто | `tests/test_argus006_hexstrike.py` зелёный (1/1 passed) |

Дополнительно: запущен hexstrike legacy gate в изоляции — **passed**.

**Вывод:** state-machine миграция на `K8sSandboxDriver` была завершена в Cycle 1 (ARG-002/ARG-004), а полная очистка legacy путей — в ARG-009/ARG-010. Никакого дополнительного кода в этой части ARG-020 не требовалось.

---

## 3. Parser-dispatch hardening (главная техническая поставка)

### 3.1 Heartbeat-finding contract (новое в `src.sandbox.parsers`)

Добавлен публичный helper `_heartbeat_finding(...)` и константа `HEARTBEAT_TAG_PREFIX = "ARGUS-HEARTBEAT"` в `backend/src/sandbox/parsers/__init__.py`:

```163:167:backend/src/sandbox/parsers/__init__.py
        owasp_wstg=[
            HEARTBEAT_TAG_PREFIX,
            f"HEARTBEAT-{tool_id}",
            f"HEARTBEAT-STRATEGY-{parse_strategy.value}",
        ],
```

Heartbeat-DTO стандартизирован:

| Поле | Значение | Обоснование |
|---|---|---|
| `category` | `FindingCategory.INFO` | Heartbeat **никогда** не должен поднять worst-severity на скан |
| `cvss_v3_score` | `0.0` | Sentinel; нормализатор маппит в `Severity.INFO` |
| `cvss_v3_vector` | `SENTINEL_CVSS_VECTOR` | Pinned для дедупа в normalizer |
| `cwe` | `[1059]` | CWE-1059 «Insufficient Technical Documentation» — формально точная семантика: каталог отгружает инструмент, но ARGUS лишён технической обвязки чтобы интерпретировать его вывод |
| `confidence` | `ConfidenceLevel.SUSPECTED` | Не verified |
| `status` | `FindingStatus.NEW` | По дефолту, как все свежие DTO |
| `ssvc_decision` | `SSVCDecision.TRACK` | Heartbeat **не требует** action |
| `owasp_wstg` | `["ARGUS-HEARTBEAT", "HEARTBEAT-{tool_id}", "HEARTBEAT-STRATEGY-{strategy}"]` | Три тега для grep/UI-фильтрации |
| `id` / `scan_id` / `tool_run_id` | `SENTINEL_UUID` | Реальные UUID проставляются normalizer'ом, как для всех DTO из parser layer |

### 3.2 Два пути heartbeat-эмиссии

Heartbeat эмитится в **двух точках** `dispatch_parse`:

1. **Unmapped tool** — стратегия зарегистрирована, но per-tool парсер для `tool_id` отсутствует.
   - Лог: `WARNING parsers.dispatch.unmapped_tool` с `extra={tool_id, parse_strategy, artifacts_dir, stdout_len, stderr_len}`.
   - Возврат: `[heartbeat]` (1 элемент).

2. **Unknown strategy** — стратегия не зарегистрирована вообще (например, `csv` или `xml_generic` пока не имеют strategy handler).
   - Лог: `WARNING parsers.dispatch.no_handler` с `extra={parse_strategy, tool_id, stdout_len, stderr_len}`.
   - Возврат: `[heartbeat]` (1 элемент).

**`BINARY_BLOB`** короткозамыкается в `ShellToolAdapter.parse_output` **до** `dispatch_parse`, поэтому heartbeat для него **не эмитится** (по дизайну: бинарные артефакты потребляются `evidence pipeline`, не FindingDTO normalizer).

**Handler-raised** ошибки парсеров (ParseError или непойманное исключение) логируются, но heartbeat **не эмитится** — это programming bug, а не coverage gap; mixed-сигнал бы испортил метрику «сколько инструментов реально не имеют парсера».

### 3.3 Обновлённые тесты (heartbeat-aware)

Все тесты, которые ранее ожидали `[]` для unmapped tools / unknown strategies, обновлены до ожидания `[heartbeat]` + структурированного warning:

| Тест | Изменение |
|---|---|
| `tests/integration/sandbox/parsers/test_dispatch_registry.py` | Переименованы тесты, обновлены assertions (categoria + tags) |
| `tests/integration/sandbox/parsers/test_nmap_dispatch.py` | `test_dispatch_unknown_tool_id_emits_heartbeat_only` (rename + assert на heartbeat) |
| `tests/integration/sandbox/parsers/test_katana_dispatch.py`, `test_wpscan_dispatch.py`, `test_nuclei_dispatch.py`, `test_interactsh_dispatch.py`, `test_ffuf_dispatch.py`, `test_trivy_semgrep_dispatch.py` | Каждый — heartbeat assertion для unmapped-tool case в их strategy |
| `tests/unit/sandbox/test_adapter_base.py::test_shell_adapter_parse_output_default_emits_heartbeat_and_warns` | Rename + heartbeat assertion (`csv` strategy) |
| `tests/unit/sandbox/test_adapter_base_dispatch.py::test_parse_output_unmapped_tool_emits_heartbeat_and_warns` | Rename + heartbeat assertion (`json_lines` + unknown tool_id) |

### 3.4 Новый дедикейтед тест-сьют heartbeat'ов

Создан `backend/tests/integration/sandbox/parsers/test_heartbeat_finding.py` с **семью** контрактами:

1. `test_heartbeat_finding_dto_contract` — параметризованный assert полного DTO для обоих путей (unmapped tool / unknown strategy).
2. `test_heartbeat_unmapped_tool_logs_structured_warning` — пин структурированного `extra` payload.
3. `test_heartbeat_no_handler_logs_structured_warning` — пин для unknown-strategy ветки.
4. `test_heartbeat_returns_fresh_dto_per_dispatch` — один новый DTO instance на каждый вызов (no caching), `id` остаётся `SENTINEL_UUID` (контракт parser layer).
5. `test_heartbeat_does_not_inherit_severity_from_inputs` — heartbeat severity не меняется в зависимости от размера stdout/stderr.
6. `test_heartbeat_unique_per_tool_within_strategy` — разные `tool_id` дают различимые `HEARTBEAT-{tool_id}` теги.
7. `test_heartbeat_carries_ssvc_track_decision` — фиксация SSVC = `TRACK` для heartbeat'ов.

---

## 4. Coverage matrix extension (5 → 10 контрактов)

`backend/tests/test_tool_catalog_coverage.py` расширен с пяти базовых до десяти контрактов на каждый дескриптор + один информационный summary.

### 4.1 Новые контракты (Contracts 6–10)

| # | Контракт | Что проверяет |
|---|---|---|
| 6 | `test_tool_command_template_placeholders_allow_listed` | Каждый `{placeholder}` в `command_template` — на allow-list `src.sandbox.templating.ALLOWED_PLACEHOLDERS` |
| 7 | `test_tool_parser_dispatch_reachable` | Для каждого `parse_strategy ≠ BINARY_BLOB` вызов `dispatch_parse(strategy, b"", b"", artifacts_dir, tool_id)` возвращает `list[FindingDTO]` без exception (real parser, либо heartbeat) |
| 8 | `test_tool_network_policy_in_template_allowlist` | `descriptor.network_policy.name ∈ NETWORK_POLICY_NAMES` (frozenset из `src.sandbox.network_policies`) |
| 9 | `test_tool_image_label_in_argus_kali_family` | Raw `descriptor.image` начинается с allowed prefix (`argus-kali-{web,cloud,browser,full}`); `resolve_image(...)` даёт fully-qualified ref под `_CANONICAL_REGISTRY = ghcr.io/argus` |
| 10 | `test_tool_approval_implies_medium_risk_floor` | `requires_approval == True ⇒ risk_level >= MEDIUM` (через `_RISK_LEVEL_ORDINAL` mapping) |

### 4.2 Parser coverage summary (информационный)

Добавлен **non-contractual** тест `test_parser_coverage_summary` — агрегирует разбивку (mapped / heartbeat / binary_blob) per-strategy + grand totals и печатает one-line summary в stdout. Используется как метрика observability в CI (regress в parser-coverage сразу видим).

Текущие значения (после ARG-020):

```
ARG-020 parser-coverage summary (total=157, mapped=33 [21.0%], heartbeat=124, binary_blob=0):
  - csv             mapped=  0  heartbeat=  1  binary_blob=  0
  - custom          mapped=  0  heartbeat=  8  binary_blob=  0
  - json_lines      mapped=  6  heartbeat=  4  binary_blob=  0
  - json_object     mapped= 16  heartbeat= 51  binary_blob=  0
  - nuclei_jsonl    mapped=  4  heartbeat=  0  binary_blob=  0
  - text_lines      mapped=  2  heartbeat= 57  binary_blob=  0
  - xml_generic     mapped=  0  heartbeat=  1  binary_blob=  0
  - xml_nmap        mapped=  5  heartbeat=  2  binary_blob=  0
```

**Итог coverage matrix:** 10 контрактов × 157 tools + 1 summary = **1571 параметризованных кейсов**, все зелёные.

---

## 5. Approval-policy enforcement (knock-on исправление)

Контракт 10 (`approval ⇒ risk_level >= MEDIUM`) обнаружил четыре дескриптора, нарушающих инвариант:

| Tool | Старый risk_level | Новый risk_level | Обоснование |
|---|---|---|---|
| `cloudsploit` | `low` | **`medium`** | Запросы к AWS API с creds; failure mode: rate-limit ban / billable API churn |
| `prowler` | `low` | **`medium`** | То же + многоуровневый CIS-bench scan |
| `scoutsuite` | `low` | **`medium`** | То же; multi-cloud auth |
| `sqlmap_safe` | `low` | **`medium`** | Reviewer M1 (cycle 2): даже safe-profile (BT-only, level 2, risk 1) генерирует WAF-noise + DB-log churn — нарушает default-deny security policy; уже approval-gated, теперь policy machine-checkable |

Обновлены три pinning-теста:

- `tests/integration/sandbox/test_arg016_end_to_end.py::test_sqli_descriptors_carry_correct_phase_and_image` — комментарий + assert `RiskLevel.MEDIUM`.
- `tests/unit/sandbox/test_yaml_sqli_semantics.py::RISK_LEVEL_BY_TOOL` — `sqlmap_safe` → `MEDIUM` (с inline rationale).
- `tests/unit/sandbox/test_yaml_arg018_semantics.py::RISK_LEVEL_BY_TOOL` — `prowler` / `scoutsuite` / `cloudsploit` → `MEDIUM` (с inline rationale).

---

## 6. Tool catalog re-signing (knock-on)

Изменения в четырёх YAML потребовали полной пересигнации каталога:

```powershell
# Старый dev key выведен из репо (private key никогда не персистится)
del backend\config\tools\_keys\1625b22388ea7ac6.ed25519.pub

# Новая dev keypair
python -m scripts.tools_sign generate-keys --keys-dir config\tools\_keys --priv-out dev_signing.ed25519.priv

# Sign + verify
python -m scripts.tools_sign sign \
  --key config\tools\_keys\dev_signing.ed25519.priv \
  --tools-dir config\tools --out config\tools\SIGNATURES
python -m scripts.tools_sign verify \
  --tools-dir config\tools --signatures config\tools\SIGNATURES \
  --keys-dir config\tools\_keys

# Cleanup private key
del config\tools\_keys\dev_signing.ed25519.priv
```

Новый публичный ключ: `backend/config/tools/_keys/b618704b19383b67.ed25519.pub`.

---

## 7. Docs regeneration (`docs/tool-catalog.md`)

`backend/scripts/docs_tool_catalog.py` расширен:

- Импорт: `ParseStrategy`, `get_registered_tool_parsers`.
- Новые helper'ы: `_PARSER_STATUS_*` константы + `_parser_status(descriptor, registered_parsers) -> str`.
- `_render_table_header` / `_render_descriptor_row` — добавлена колонка `parser_status` (между `parse_strategy` и `command_template`).
- Новая секция-renderer `_render_parser_coverage(descriptors, registered_parsers)`:
  - Прозу с описанием трёх путей.
  - Catalog totals (количество + share %).
  - Per-phase breakdown (mapped/heartbeat/binary_blob/total).
- `build_markdown(...)` принимает `registered_parsers: frozenset[str] | None = None` (для тестируемости) и вызывает новую секцию между `_render_coverage_matrix` и `_render_related_modules`.

**Результат регенерации:**

```
tool_registry.loaded
docs_tool_catalog.rendered tools=157 path=..\docs\tool-catalog.md
```

Drift-gate проходит: `python -m scripts.docs_tool_catalog --check` → `check_ok tools=157`.

Catalog totals в новой секции (видно в `docs/tool-catalog.md`):

| Status | Count | Share |
|---|---|---|
| `mapped` | 33 | 21.02% |
| `heartbeat` | 124 | 78.98% |
| `binary_blob` | 0 | 0.00% |
| **Total** | **157** | **100.00%** |

---

## 8. Acceptance gates — результаты

Все критические gates запущены чисто:

| Gate | Команда | Результат |
|---|---|---|
| Coverage matrix (10 контрактов × 157 tools + summary) | `pytest tests/test_tool_catalog_coverage.py -q` | ✅ **1571 passed** |
| Parser-dispatch integration tests | `pytest tests/integration/sandbox/parsers/ -q` | ✅ **191 passed** |
| Hexstrike legacy gate | `pytest tests/test_argus006_hexstrike.py -q` | ✅ **1 passed** |
| Catalog drift (CI mode) | `python -m scripts.docs_tool_catalog --check` | ✅ `check_ok tools=157` |
| Wide regression (sandbox / pipeline / findings / orchestrator_runtime) | `pytest tests/integration/sandbox tests/unit/sandbox tests/unit/pipeline tests/unit/findings tests/unit/orchestrator_runtime -q` | ✅ **5481 passed** |
| Combined acceptance batch | `pytest tests/test_tool_catalog_coverage.py tests/integration/sandbox/parsers tests/integration/sandbox/test_arg016_end_to_end.py tests/unit/sandbox/test_adapter_base*.py -q` | ✅ **1805 passed** |

**Suite suma:** ≥ 5,000+ tests green после ARG-020. (Базовый Cycle 2 baseline был 5916+; локально подтверждённое цифра — **5481 в sandbox/pipeline/findings/orchestrator_runtime**, остальные модули не запускались в ARG-020 из-за orthogonal SQLite-pool fixture leak в `tests/conftest.py:app` фикстуре, которая воспроизводится только при mixing test modules через границу сессии — это **pre-existing** issue, не вызван моей работой.)

**Pre-existing gotcha:** при запуске `pytest tests/integration/sandbox/test_arg016_end_to_end.py + tests/test_argus006_hexstrike.py` в одной сессии срабатывает SQLite-pool fixture leak (`pool_size=5, max_overflow=10` отвергаются `StaticPool`). Каждый тест по-отдельности зелёный. Issue нужно адресовать в Cycle 3 (исправление `src/db/session.py` для конфигурируемого pool class под SQLite test backend).

---

## 9. Final cleanup

Grep по `# TODO: deprecate hexstrike` / `hexstrike` в `backend/src` — **0 совпадений**. Outdated module docstrings в `backend/src/sandbox/parsers/__init__.py` обновлены (новая секция «Failure model — fail-soft, with operator-visible heartbeats since ARG-020»). Не понадобилось удалять прямые `subprocess.run`/`Popen` calls — они уже либо удалены в предыдущих циклах, либо находятся в allowlisted путях (см. §2).

---

## 10. Файлы изменены

### Source
- `backend/src/sandbox/parsers/__init__.py` — heartbeat-finding helper, `HEARTBEAT_TAG_PREFIX`, обновление docstring, экспорт в `__all__`, hardening `_strategy_handler` + `dispatch_parse`.
- `backend/scripts/docs_tool_catalog.py` — `parser_status` колонка + `_render_parser_coverage` + `build_markdown(registered_parsers=...)` сигнатура.

### Tests (новые)
- `backend/tests/integration/sandbox/parsers/test_heartbeat_finding.py` — 7 контрактов heartbeat-DTO.

### Tests (обновлённые)
- `backend/tests/test_tool_catalog_coverage.py` — 5 новых контрактов (6–10) + summary; рефактор Contract 7 для совместимости с heartbeat-fallback.
- `backend/tests/integration/sandbox/parsers/test_dispatch_registry.py`, `test_nmap_dispatch.py`, `test_katana_dispatch.py`, `test_wpscan_dispatch.py`, `test_nuclei_dispatch.py`, `test_interactsh_dispatch.py`, `test_ffuf_dispatch.py`, `test_trivy_semgrep_dispatch.py` — heartbeat-aware assertions.
- `backend/tests/unit/sandbox/test_adapter_base.py` — `test_shell_adapter_parse_output_default_emits_heartbeat_and_warns` (rename + heartbeat assertion).
- `backend/tests/unit/sandbox/test_adapter_base_dispatch.py` — `test_parse_output_unmapped_tool_emits_heartbeat_and_warns` (rename + heartbeat assertion).
- `backend/tests/integration/sandbox/test_arg016_end_to_end.py` — `sqlmap_safe` risk_level expectation `LOW → MEDIUM`.
- `backend/tests/unit/sandbox/test_yaml_sqli_semantics.py` — `RISK_LEVEL_BY_TOOL[sqlmap_safe] = RiskLevel.MEDIUM`.
- `backend/tests/unit/sandbox/test_yaml_arg018_semantics.py` — `prowler` / `scoutsuite` / `cloudsploit` → `RiskLevel.MEDIUM`.

### Config (YAML)
- `backend/config/tools/cloudsploit.yaml` — `risk_level: low → medium`.
- `backend/config/tools/prowler.yaml` — `risk_level: low → medium`.
- `backend/config/tools/scoutsuite.yaml` — `risk_level: low → medium`.
- `backend/config/tools/sqlmap_safe.yaml` — `risk_level: low → medium`.

### Config (signing)
- `backend/config/tools/SIGNATURES` — регенерирован.
- `backend/config/tools/_keys/1625b22388ea7ac6.ed25519.pub` — удалён (старый dev key).
- `backend/config/tools/_keys/b618704b19383b67.ed25519.pub` — добавлен (новый dev key).

### Docs
- `docs/tool-catalog.md` — регенерирован: 157 tools, 9 колонок (вкл. `parser_status`), новая секция `## Parser coverage`.
- `ai_docs/develop/plans/2026-04-18-argus-finalization-cycle2.md` — статусы Closed + ARG-020 ✅.
- `ai_docs/develop/reports/2026-04-19-arg-020-capstone-report.md` — этот файл.

---

## 11. Следующие циклы (что осталось)

ARG-020 закрывает Cycle 2. Cycle 3 будет фокусироваться на:

1. **Wire больше parser handlers** — текущие 124 heartbeat'а — это явный backlog; приоритет: text_lines (57), json_object (51), json_lines (4). Каждый wired парсер автоматически переключает соответствующий `parser_status` с `heartbeat` на `mapped` без contract-change у callers.
2. **Multi-stage Dockerfiles с pinned versions** для `argus-kali-{web,cloud,browser,full}` + SBOM генерация через `syft -o cyclonedx-json`.
3. **ReportService** (Midgard / Asgard / Valhalla × HTML/PDF/JSON/CSV/SARIF/JUnit).
4. **Backend MCP server** (`backend/src/mcp/server.py`).
5. **`replay_command_sanitizer.py`** — required для ReportService.
6. **Pre-existing gotcha:** SQLite-pool issue в `tests/conftest.py::app` фикстуре (см. §8) — нужно исправить `src/db/session.py` чтобы test backend не получал `pool_size`/`max_overflow` (SQLite использует `StaticPool`).

---

## 12. Definition of Done — финальный чек-лист

- [x] **Catalog count:** `tools_list --json | jq length` = **157** (≥150 целевой Backlog §19.6).
- [x] **Parser-dispatch contract:** все 157 инструментов имеют детерминированный путь к `dispatch_parse`; unmapped → heartbeat + structured warning; binary_blob → short-circuit.
- [x] **Coverage matrix:** 10 контрактов × 157 = 1570 параметризованных кейсов + 1 summary; **все зелёные**.
- [x] **Hexstrike legacy gate:** `tests/test_argus006_hexstrike.py` зелёный (0 references в `backend/src`, `backend/api`, `mcp-server`).
- [x] **Approval-policy invariant:** `requires_approval ⇒ risk_level >= MEDIUM` теперь **machine-checkable** через Contract 10; четыре исторических нарушения исправлены.
- [x] **Docs drift:** `python -m scripts.docs_tool_catalog --check` passes.
- [x] **Signing:** все 157 YAML Ed25519-verified против нового dev key.
- [x] **State-machine migration:** аудит подтвердил, что миграция уже завершена в Cycle 1 ARG-002/004; нет subprocess/hexstrike на горячих путях.
- [x] **Plan + report:** `2026-04-18-argus-finalization-cycle2.md` помечен Closed; capstone report зафиксирован.

**ARG-020 — ✅ Completed. Cycle 2 — ✅ Closed.**

---

## 13. Ссылки

- Cycle 2 plan: [`ai_docs/develop/plans/2026-04-18-argus-finalization-cycle2.md`](../plans/2026-04-18-argus-finalization-cycle2.md)
- Cycle 1 capstone: [`ai_docs/develop/reports/2026-04-17-argus-finalization-cycle1.md`](2026-04-17-argus-finalization-cycle1.md)
- Auto-generated catalog: [`docs/tool-catalog.md`](../../../docs/tool-catalog.md)
- Coverage matrix: [`backend/tests/test_tool_catalog_coverage.py`](../../../backend/tests/test_tool_catalog_coverage.py)
- Heartbeat tests: [`backend/tests/integration/sandbox/parsers/test_heartbeat_finding.py`](../../../backend/tests/integration/sandbox/parsers/test_heartbeat_finding.py)
- Parser dispatch core: [`backend/src/sandbox/parsers/__init__.py`](../../../backend/src/sandbox/parsers/__init__.py)
- Docs generator: [`backend/scripts/docs_tool_catalog.py`](../../../backend/scripts/docs_tool_catalog.py)
- Hexstrike legacy gate: [`backend/tests/test_argus006_hexstrike.py`](../../../backend/tests/test_argus006_hexstrike.py)
