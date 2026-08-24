# TASK — ARGUS Profile & Orchestration Rework

Owner всех задач: **Cursor**. Статусы обновляются по факту выполнения и верификации.

Легенда статусов: `TODO` · `IN PROGRESS` · `DONE` · `PARTIAL` (сделано ядро + тесты, часть подпунктов вынесена) · `DEFERRED` (задокументировано, не реализовано в этой итерации).

---

## T1. Spec pack
- Зона: документация `.spec/argus-profile-orchestration-rework/`.
- Результат: Requirements.md, Design.md, TASK.md на русском.
- Требования: все.
- Статус: **DONE**
  - [x] Requirements.md
  - [x] Design.md
  - [x] TASK.md

## T2. Profile Resolver (backend ядро)
- Зона: `backend/src/profiles/`.
- Результат: `ScanProfile`, `ResolvedScanProfile`, `resolve_scan_profile`, `detect_legacy_conflict` + unit-тесты.
- Требования: R1, R2.2, R3.1, R4, P1, P3, P6.
- Подзадачи:
  - [x] Модуль резолвера с маппингом quick/light/deep
  - [x] Обнаружение legacy-конфликтов
  - [x] Unit-тесты (все маппинги, дефолт balanced, конфликты, quick isolation)
- Статус: **DONE**

## T3. API scan_profile + errors + migration
- Зона: `backend/src/api/schemas.py`, `backend/src/api/routers/scans.py`, `backend/src/api/errors.py`, `backend/alembic/versions/059_*`.
- Результат: канон. поле `scan_profile`, поля `engagement_id`/`lab_lease_id`, резолв в create_scan, 422-конфликты, новые колонки Scan, расширенный response, error contract.
- Требования: R1, R4, R12, P6.
- Подзадачи:
  - [x] `scan_profile`, `engagement_id`, `lab_lease_id` в `ScanCreateRequest`
  - [x] Error contract helper + коды
  - [x] Резолв profile в `create_scan` + persist новых колонок
  - [x] Расширение `ScanDetailResponse`
  - [x] Alembic 059 (аддитивные nullable колонки)
  - [x] Тесты создания скана по профилям + конфликты
- Статус: **DONE**

## T4. LAB lease preflight (deep)
- Зона: `backend/src/profiles/lab_preflight.py` (+ интеграция в create_scan).
- Результат: серверная валидация lease/scope с полным набором кодов ошибок.
- Требования: R4, P2.
- Подзадачи:
  - [x] `preflight_lab_lease` со всеми ветками (missing/expired/revoked/tenant/engagement/scope)
  - [x] Интеграция в create_scan для deep
  - [x] Unit-тесты всех веток + «Quick never gets LAB»
- Статус: **DONE**

## T5. Report canonical snapshot + 4 формата + parity
- Зона: `backend/src/reports/report_document.py`, `backend/src/reports/renderers/`.
- Результат: `ReportDocumentV1` + JSON/MD/XML/PDF(HTML) рендереры + evidence gate + parity-тесты.
- Требования: R6, R7, P4, P5, P7.
- Подзадачи:
  - [x] `ReportDocumentV1` Pydantic + `snapshot_hash`
  - [x] Renderers JSON/Markdown/XML/HTML
  - [x] Evidence gate (confirmed/exploitable без evidence → downgrade)
  - [x] Сборка snapshot из findings/coverage/tool_runs (адаптер)
  - [x] Parity-тесты (findings/severity/evidence/coverage/hash)
  - [ ] Автопостановка 4 render jobs в post-scan bundle (интеграция) — см. T11
- Статус: **DONE (ядро + parity)**; интеграция в celery-пайплайн — PARTIAL (см. T11).

## T6. LLM orchestration (guardrails + typed intent compiler)
- Зона: prompts + `backend/src/llm_orchestrator/intent_compiler.py`.
- Результат: санитизация опасных инструкций; typed `LLMScanIntent` + детерминированный compiler (schema/scope/profile/lease/approval/budget, argv без shell); валидация finding-claims.
- Требования: R8, R6.
- Подзадачи:
  - [x] Санитизация legacy-инструкций ("GO HARD"/"$500+"/"never leave evidence empty")
  - [x] untrusted-data guardrails-блок + тест целостности
  - [x] `LLMScanIntent` + `compile_intent` (raw command/payload rejected, scope/profile/lease/approval/budget gates, abstain allowed)
  - [x] `validate_finding_claim` (hallucinated finding / CVE-without-evidence rejected)
  - [x] Тесты (22) intent compiler + finding claims
  - [ ] Полная замена вызовов legacy state-machine prompts на Orchestrator — DEFERRED (compiler готов к подключению)
- Статус: **DONE (compiler+guardrails)** ; полная замена legacy — DEFERRED.

## T7. Tools registry (source of truth + registrability gate + parser fallback)
- Зона: `backend/src/sandbox/parsers/`, `backend/src/sandbox/tool_registrability.py`.
- Требования: R9.
- Подзадачи:
  - [x] `dispatch_parse_strict` — fallback без фиктивного INFO finding (`parser_unavailable`)
  - [x] `evaluate_tool_registrability` / `should_register_mcp_tool` — gate: descriptor+executable+parser+profile
  - [x] `load_known_executables` из `infra/sandbox/expected_executables.json`
  - [x] Тесты (10 + 4 strict dispatch)
  - [ ] Кодогенерация каталога/MCP/manifest из одного descriptor — DEFERRED
- Статус: **DONE (gate+fallback)** ; codegen из descriptor — DEFERRED.

## T8. Payloads taxonomy mapping
- Зона: `backend/src/payloads/taxonomy.py`.
- Требования: R10.
- Подзадачи:
  - [x] Taxonomy-based mapping (FindingCategory → CWE-якоря, + explicit CWE) — не keyword search
  - [x] Профильные политики quick/light/deep (`PayloadProfilePolicy`)
  - [x] Deterministic + dedup + stable manifest hash + provenance
  - [x] `families_allowed_by_profile` (allow-list для compiler)
  - [x] Тесты (11)
- Статус: **DONE**.

## T9. State machine profile-driven + checkpoints
- Зона: `backend/src/orchestration/profile_phase_policy.py`, `scan_checkpoint.py`, `scan_policy.py`.
- Требования: R11.
- Подзадачи:
  - [x] `plan_phases(resolved)` — allowed/skipped фазы, lease-preflight для destructive, capture_full
  - [x] `ScanCheckpointV1` (frozen profile, phase, budget, scope hash, lease state, registry versions, snapshot status) + hash
  - [x] `resume_context` — resume из immutable профиля (не из user input)
  - [x] `build_compiler_context` — мост profile+tools+payloads → intent compiler
  - [x] Тесты (7 + 4 bridge)
  - [ ] Врезка plan_phases в существующий `state_machine` loop — DEFERRED (модуль готов; quick-путь уже покрыт `quick/workflow`)
- Статус: **DONE (policy+checkpoint)** ; врезка в loop — DEFERRED.

## T10. Observability / audit events
- Зона: `backend/src/core/structured_events.py`.
- Требования: R13.
- Подзадачи:
  - [x] Полный каталог событий (22) с каноническими полями (tenant/scan/engagement/correlation/scan_profile/phase/reason_code/registry_versions)
  - [x] Рекурсивная redaction секретов/cookies/authorization/lease signing material
  - [x] Врезка в resolver / lab preflight / intent compiler / tool gate / payload taxonomy
  - [x] Тесты (7)
- Статус: **DONE**.

## T11. Frontend wiring (remove mock, real API)
- Зона: `Frontend/src/app/api/scans/*`, `Frontend/src/lib/scanClient.ts`, `backendClient.ts`.
- Требования: R5, R12.4.
- Подзадачи:
  - [x] Единый typed client `scanClient.ts` (create/status/cancel/list/findings/coverage/reports/SSE)
  - [x] Server-side proxy `backendClient.ts` (tenant/correlation/idempotency, error-normalize, no secrets)
  - [x] `/api/scans` + `[id]` proxy к backend `/api/v1`
  - [x] Real backend — **production default** (mock только при `ARGUS_DEMO_MODE` или отсутствии backend URL)
  - [x] tier→scan_profile mapping (free→quick, standard→light, premium→deep)
  - [x] Vitest на real async contract (11 тестов, без mock Map/setTimeout)
  - [x] UI/вёрстка не изменены
- Статус: **DONE** (демо-mock сохранён как явный offline-fallback, не production default).

## T12. Итоговая проверка
- Зона: тесты backend + Frontend.
- Подзадачи:
  - [x] Целевые pytest (profiles 37, lab preflight, reports parity 13, prompt guardrails+integrity 34, strict dispatch 4, api scan_profile 9, migration 059)
  - [x] Frontend vitest (scanClient — 7/7 passed)
  - [x] Frontend full vitest: 666 passed, 23 pre-existing localStorage-env failures (unrelated — `localStorage` undefined in runner)
  - [ ] Frontend `next build` полный прогон — не запускался в этой среде
- Статус: **DONE (targeted)** / build не запускался

---

## Сводка покрытия требований (на момент итерации)

| Требование | Статус | Задача |
|-----------|--------|--------|
| R1 (единая модель профиля) | DONE | T2,T3 |
| R2 (Quick) | DONE | T2,T3 |
| R3 (Light) | DONE | T2,T3 |
| R4 (Deep/LAB lease) | DONE | T2,T3,T4 |
| R5 (Frontend без mock) | DONE (real API = prod default; demo=offline fallback) | T11 |
| R6 (AI не выдумывает) | DONE (report gate + prompt guardrails + finding-claim validation) | T5,T6 |
| R7 (report pipeline 4 формата) | DONE (ядро+parity + врезка в report_pipeline: canonical_* артефакты, flag `ARGUS_CANONICAL_REPORT_SNAPSHOT`) | T5 |
| R8 (LLM orchestration) | DONE (typed intent compiler + runtime glue + врезка в VA handler: evidence-gate, flag `ARGUS_TYPED_INTENT_COMPILER`) / DEFERRED (полная замена tool-exec на compiled jobs) | T6 |
| R9 (tools registry) | DONE (gate + strict fallback + врезка в MCP `list_catalog`, flag `ARGUS_MCP_REGISTRABILITY_GATE`) / DEFERRED (codegen из descriptor) | T7 |
| R10 (payloads taxonomy) | DONE | T8 |
| R11 (state machine) | DONE (policy+checkpoint+bridge + врезка в state_machine: profile-driven skip + durable checkpoint в scan.options, flag `ARGUS_PROFILE_CHECKPOINT`) | T9 |
| R12 (API errors) | DONE | T3 |
| R13 (observability) | DONE | T10 |
| R14 (tests) | DONE (targeted; 2902 passed в regression edited subsystems) | T12 |

## Feature flags — теперь ВКЛючены по умолчанию (default ON), env-override сохранён

| Flag (env) | Требование | Default | Эффект |
|-----------|-----------|---------|--------|
| `ARGUS_CANONICAL_REPORT_SNAPSHOT` | R7 | **ON** | report_pipeline эмитит `canonical_json/md/xml/pdf` из одного `ReportDocumentV1` |
| `ARGUS_MCP_REGISTRABILITY_GATE` | R9 | **ON** | MCP `list_catalog` фильтрует tools без executable/parser |
| `ARGUS_TYPED_INTENT_COMPILER` | R8 | **ON** | VA + exploitation отбрасывают fabricated findings/exploits (evidence-gate) |
| `ARGUS_PROFILE_CHECKPOINT` | R11 | **ON** | state_machine: profile-driven skip фаз + durable `scan_checkpoint_v1` в scan.options |

Все пути fail-soft (обёрнуты try/except) — включение по умолчанию не ломает основной flow; отключаются через env (`=false`).

## DEFERRED — доделано

- **R9 codegen** (`backend/src/sandbox/tool_codegen.py`): из ОДНОГО signed descriptor-набора выводятся executable manifest, MCP definitions, parser map, risk/approval metadata; drift-тест подтверждает, что committed `expected_executables.json` совпадает с выводом из signed descriptors (source of truth).
- **R8 exec-gate**: LLM-fallback путь exploitation (`ai_exploitation`) пропускается через evidence-gate (`treat_as_provable=True` + exploit-specific evidence keys: poc_url/poc_curl/browser_evidence/screenshot/symbolic_execution_proven) — недоказанные exploit-claims отбрасываются. Sandbox-executor путь (реальные evidence) не затрагивается.
- Остаётся DEFERRED (архитектурно необязательно для корректности): полная замена детерминированного `_VULN_TOOL_MAP`/PayloadBuilder на `CompiledToolJob` — существующий путь уже детерминирован и не исполняет raw shell/payload.
