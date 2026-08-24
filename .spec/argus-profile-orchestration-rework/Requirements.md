# Requirements — ARGUS Profile & Orchestration Rework

## 1. Введение

Документ описывает требования к комплексной доработке платформы ARGUS в части единой
модели scan-профилей, подключения основного Frontend к реальному backend API, канонического
report-пайплайна, типизированной LLM-оркестрации, единого реестра инструментов/пейлоадов и
профиль-управляемой state machine.

Цель — привести внешний UI к строго трём scan-профилям (`quick` / `light` / `deep`), убрать
mock-исполнение из production-пути Frontend, гарантировать, что AI не выдумывает данные, а
отчёты формируются из единого неизменяемого snapshot во всех форматах (PDF/JSON/Markdown/XML).

Frontend является источником истины по API-контрактам (см. `.cursor/rules/api-contract.mdc`).
Backend реализуется строго по контрактам.

## 2. Глоссарий

| Термин | Определение |
|--------|-------------|
| **ScanProfile (external)** | Внешний канонический профиль скана: `quick` \| `light` \| `deep`. Единственная величина, которую выбирает внешний UI. |
| **scan_mode** | Внутренняя «глубина» пайплайна: `quick` \| `standard` \| `deep` \| `lab`. Не выбирается напрямую внешним UI. |
| **execution_mode** | Иммутабельный профиль исполнения: `production` \| `lab_unrestricted` \| `quick`. Определяет политику безопасности. |
| **quick_profile** | Бюджетный профиль Quick: `compact` \| `balanced` \| `extended`. По умолчанию `balanced`. |
| **nuclei_profile** | Идентификатор nuclei-профиля: `quick-default`, `vuln_default`, `lab_unrestricted` и т.д. |
| **ResolvedScanProfile** | Результат работы Profile Resolver — иммутабельная структура со всеми внутренними полями, вычисленными из внешнего `scan_profile`. |
| **LAB lease** | Подписанная аренда исполнения (`lab_execution_leases`), выданная под конкретный scope в рамках engagement. Обязательна для `deep`. |
| **engagement_id** | Идентификатор engagement, к которому привязаны execution_mode, lab scope и lab lease. |
| **ReportDocumentV1** | Канонический неизменяемый snapshot данных отчёта, из которого рендерятся все форматы. |
| **snapshot_hash** | Детерминированный SHA-256 хэш канонического snapshot; идентичен для всех форматов одного отчёта. |
| **Report tier** | Презентационный/биллинговый уровень отчёта: Midgard / Asgard / Valhalla. Не смешивается с scan_profile. |
| **Evidence** | Проверяемое доказательство (artifact/tool_run/validator), на которое обязана ссылаться каждая техническая находка. |
| **Coverage** | Отражение того, какие capability протестированы, а какие нет (`not_assessed`, `parser_unavailable`, `budget_exhausted` и т.д.). |
| **Capability** | Абстрактная проверяемая способность (например «SQLi active check»), реализуемая одним или несколькими tools. |

## 3. Требования

Формат: каждый критерий приёмки — «КОГДА <условие> / ТО система ДОЛЖНА <поведение>».

### R1. Единая модель scan-профиля

- R1.1 Внешний API `POST /api/v1/scans` ДОЛЖЕН принимать канонический `scan_profile: "quick" | "light" | "deep"`.
- R1.2 Backend ДОЛЖЕН централизованно вычислять внутренние `scan_mode`, `execution_mode`,
  `quick_profile`, `nuclei_profile` из `scan_profile` через единый Profile Resolver.
- R1.3 Внешний UI ДОЛЖЕН оперировать ровно тремя профилями.

Критерии приёмки:
- КОГДА клиент отправляет `scan_profile=quick` без legacy-полей / ТО система ДОЛЖНА разрешить
  профиль в `scan_mode=quick`, `execution_mode=quick`, `quick_profile=balanced`, `nuclei_profile=quick-default`.
- КОГДА клиент отправляет `scan_profile=light` / ТО система ДОЛЖНА разрешить в
  `scan_mode=standard`, `execution_mode=production`, `nuclei_profile=vuln_default`.
- КОГДА клиент отправляет `scan_profile=deep` c валидным `engagement_id`+`lab_lease_id` / ТО
  система ДОЛЖНА разрешить в `scan_mode=lab`, `execution_mode=lab_unrestricted`, `nuclei_profile=lab_unrestricted`.
- КОГДА клиент отправляет `scan_profile` и конфликтующие legacy `scan_mode`/`execution_mode` /
  ТО система ДОЛЖНА вернуть `422` с кодом `conflicting_profile_fields`.
- КОГДА клиент отправляет неизвестный `scan_profile` / ТО система ДОЛЖНА вернуть `422` с кодом `invalid_scan_profile`.

### R2. Quick

- R2.1 Quick ДОЛЖЕН использовать `quick_profile=balanced` по умолчанию; `compact`/`extended` доступны через API.
- R2.2 Quick НЕ ДОЛЖЕН получать `lab_unrestricted` разрешения ни при каких условиях.
- R2.3 Quick ДОЛЖЕН использовать только production-safe tools/payloads.
- R2.4 Quick budget/deadlines/circuit breakers/validation reserve ДОЛЖНЫ сохраняться.

Критерии приёмки:
- КОГДА Quick исчерпал budget / ТО система ДОЛЖНА завершить с partial coverage и НЕ ДОЛЖНА
  трактовать budget exhaustion как отсутствие уязвимостей (coverage reason=`budget_exhausted`).
- КОГДА для Quick запрашивается destructive payload family / ТО система ДОЛЖНА отклонить с
  кодом `payload_family_denied`.
- КОГДА Quick завершается / ТО отчёт ДОЛЖЕН явно перечислять непроверенные категории.

### R3. Light

- R3.1 Light ДОЛЖЕН резолвиться в `scan_mode=standard`, `execution_mode=production`.
- R3.2 Light ДОЛЖЕН использовать safe active nuclei profile, ограниченные rate/concurrency.
- R3.3 Light НЕ ДОЛЖЕН исполнять destructive payload families.
- R3.4 OAST в Light — только через production-safe policy при наличии разрешения.

Критерии приёмки:
- КОГДА в Light выбирается capability с повышенным риском / ТО система ДОЛЖНА требовать explicit approval gate.
- КОГДА в Light запрашивается destructive tool / ТО система ДОЛЖНА отклонить с `profile_capability_denied`.

### R4. Deep как LAB

- R4.1 Deep ДОЛЖЕН требовать `engagement_id` и `lab_lease_id`.
- R4.2 Deep ДОЛЖЕН проходить server-side boundary validation lease/scope.
- R4.3 Разрешения Deep определяются lease и scope.

Критерии приёмки:
- КОГДА `scan_profile=deep` без `lab_lease_id` / ТО система ДОЛЖНА вернуть ошибку `lab_lease_required`
  с `engagement_id` и `required_action=issue_or_select_lab_lease`.
- КОГДА `scan_profile=deep` без `engagement_id` / ТО система ДОЛЖНА вернуть `lab_engagement_required`.
- КОГДА lease истёк / ТО система ДОЛЖНА вернуть `lab_lease_expired`.
- КОГДА lease отозван / ТО система ДОЛЖНА вернуть `lab_lease_revoked`.
- КОГДА lease принадлежит другому tenant / ТО система ДОЛЖНА вернуть `lab_lease_tenant_mismatch`.
- КОГДА target вне lab scope / ТО система ДОЛЖНА вернуть `target_out_of_lab_scope`.

### R5. Frontend без mock

- R5.1 Основной Frontend НЕ ДОЛЖЕН использовать in-memory Map/setTimeout/mock findings в production-пути.
- R5.2 `POST /api/scans` (Next route) ДОЛЖЕН проксировать backend `POST /api/v1/scans`.
- R5.3 Все существующие scan-действия UI ДОЛЖНЫ использовать реальные backend API через единый typed client.
- R5.4 Внешний вид Frontend НЕ ДОЛЖЕН быть переработан (layout/JSX/CSS/цвета/responsive сохраняются).
- R5.5 Backend errors ДОЛЖНЫ нормализоваться в существующий UI error state.

Критерии приёмки:
- КОГДА пользователь запускает скан в UI / ТО Next route ДОЛЖЕН выполнить реальный async fetch к backend.
- КОГДА backend возвращает ошибку / ТО UI ДОЛЖЕН показать её в существующей области ошибок без stack trace.
- КОГДА выполняется Frontend build/lint / ТО в production-пути НЕ ДОЛЖНО остаться Map/setTimeout-сканера.

### R6. AI не выдумывает данные

- R6.1 AI НЕ ДОЛЖЕН генерировать vulnerabilities/evidence/CVE/CVSS/tool output/HTTP/endpoints/exploitability/business impact/remediation status.
- R6.2 При отсутствии данных система ДОЛЖНА использовать: `not_assessed`, `not_tested`,
  `insufficient_evidence`, `tool_failed`, `parser_unavailable`, `out_of_scope`, `budget_exhausted`.
- R6.3 AI narrative разрешён только как обобщение переданных фактов с evidence refs.

Критерии приёмки:
- КОГДА AI-секция содержит утверждение без evidence refs / ТО система ДОЛЖНА отклонить секцию,
  записать validation error и использовать deterministic fallback text.
- КОГДА нет данных по capability / ТО отчёт ДОЛЖЕН содержать один из статусов из R6.2.

### R7. Report pipeline

- R7.1 Для каждого завершённого скана ДОЛЖНЫ формироваться форматы PDF/JSON/Markdown/XML.
- R7.2 Все форматы ДОЛЖНЫ рендериться из единого `ReportDocumentV1` snapshot.
- R7.3 Все форматы ДОЛЖНЫ быть семантически эквивалентны.
- R7.4 Finding может иметь `confirmed`/`exploitable` только при наличии допустимого evidence.
- R7.5 Повторная генерация НЕ ДОЛЖНА менять смысл отчёта без изменения snapshot version.
- R7.6 Report tier (Midgard/Asgard/Valhalla) ДОЛЖЕН оставаться отдельным от scan_profile и billing tier.

Критерии приёмки:
- КОГДА scan завершён / ТО система ДОЛЖНА идемпотентно сформировать 4 формата из одного snapshot.
- КОГДА сравниваются 4 формата одного отчёта / ТО число findings, severities, evidence IDs,
  coverage/limitations и `snapshot_hash` ДОЛЖНЫ совпадать.
- КОГДА отчёт запрашивается повторно / ТО при неизменном snapshot version смысл НЕ ДОЛЖЕН измениться.

### R8. LLM orchestration

- R8.1 Typed `llm_orchestrator` ДОЛЖЕН быть подключён к production scan pipeline.
- R8.2 LLM НЕ ДОЛЖЕН запускать shell-команды напрямую; возвращает только typed intent.
- R8.3 Deterministic compiler ДОЛЖЕН валидировать schema/scope/profile/lease/approvals/budget и строить argv без `shell=True`.
- R8.4 Все LLM-вызовы ДОЛЖНЫ проходить через единый facade/gateway с redaction/policy/budget/versions/trace.
- R8.5 Опасные legacy-инструкции ("GO HARD", "$500+", "never leave evidence empty", генерация raw shell/payload) ДОЛЖНЫ быть удалены.
- R8.6 Все prompts ДОЛЖНЫ трактовать tool output/HTML/RAG/scanner text как untrusted data и разрешать abstain.

Критерии приёмки:
- КОГДА LLM возвращает не-schema-valid JSON / ТО система ДОЛЖНА отклонить и применить fallback.
- КОГДА LLM пытается вернуть raw command/raw payload вне registry / ТО система ДОЛЖНА отклонить.
- КОГДА в evidence присутствует инъекция инструкций / ТО система НЕ ДОЛЖНА её исполнять.

### R9. Tools registry

- R9.1 `backend/config/tools/*.yaml` (signed) ДОЛЖЕН быть единственным source of truth.
- R9.2 MCP НЕ ДОЛЖЕН регистрировать tool при отсутствии executable/compiler/parser/healthcheck или запрете profile.
- R9.3 Fallback parser НЕ ДОЛЖЕН создавать фиктивный INFO finding; ДОЛЖЕН выдавать raw artifact + `parser_status=unparsed` + coverage reason=`parser_unavailable`.

Критерии приёмки:
- КОГДА planner выбирает tool без доступного executable / ТО система ДОЛЖНА пометить `tool_unavailable` и не планировать его.
- КОГДА parser отсутствует / ТО система ДОЛЖНА сохранить raw artifact и НЕ создавать vulnerability без evidence.

### R10. Payloads

- R10.1 Signed payload registry ДОЛЖЕН оставаться source of truth.
- R10.2 Сопоставление payload↔finding ДОЛЖНО основываться на taxonomy (vuln type/CWE/CAPEC/sink/location/tech/oracle/profile/risk), а не только keyword search.
- R10.3 PayloadBuilder ДОЛЖЕН выполнять bounded deterministic expansion с дедупликацией и стабильным manifest hash.
- R10.4 Профильные политики: Quick — safe/low/allowed medium; Light — safe active; Deep — LAB high-risk с approvals.

Критерии приёмки:
- КОГДА один и тот же вход подаётся в PayloadBuilder дважды / ТО manifest hash ДОЛЖЕН совпадать (replayability).
- КОГДА профиль Quick / ТО набор payloads НЕ ДОЛЖЕН содержать destructive/high risk.

### R11. State machine

- R11.1 Стадии сохраняются; выбор стадий/tools/budgets определяется `ResolvedScanProfile`.
- R11.2 Quick разрешает phase skipping (отражается в coverage) и всегда создаёт partial report.
- R11.3 Deep требует lease preflight перед destructive-фазами; lease expiry останавливает опасные действия.
- R11.4 Durable checkpoints ДОЛЖНЫ хранить resolved profile, phase, remaining budget, scope hash, lease state, registry versions, report snapshot status.
- R11.5 Resume ДОЛЖЕН использовать сохранённый immutable profile context, а не заново интерпретировать input.

### R12. API contracts и errors

- R12.1 Единый machine-readable формат ошибок `{ "error": { "code", "message", "details", "correlation_id" } }`.
- R12.2 Добавить коды из раздела 12 задания.
- R12.3 НЕ возвращать stack trace и secrets.
- R12.4 Обновить OpenAPI и TypeScript types.

### R13. Observability и audit

- R13.1 Добавить structured events/metrics для profile/lease/capability/tool/parser/payload/llm/evidence/report.
- R13.2 Каждое событие содержит tenant_id/scan_id/engagement_id?/correlation_id/scan_profile/phase/reason code/registry versions.
- R13.3 НЕ логировать credentials/cookies/authorization/secrets/lease signing material.

### R14. Тесты

- R14.1 Backend unit tests: ProfileResolver, LAB lease, tool registry, payloads, LLM, reports.
- R14.2 Backend integration/e2e против локальных vulnerable targets.
- R14.3 Frontend: createScan real fetch, профиль-маппинг, статус, cancel, findings, coverage, lease errors, reports, отсутствие mock, отсутствие визуальной регрессии.

## 4. Свойства корректности (Correctness Properties)

- **P1 (Quick isolation):** Ни один путь резолва не присваивает Quick `execution_mode=lab_unrestricted`.
- **P2 (Deep gating):** Ни один Deep-скан не стартует без валидного, активного, tenant-совпадающего, in-scope lease.
- **P3 (Determinism):** `resolve_scan_profile(profile)` детерминирован для одинакового входа.
- **P4 (Snapshot parity):** Для любого snapshot все 4 формата дают одинаковые findings/severities/evidence/coverage/hash.
- **P5 (No fabrication):** В отчёте нет ни одного finding со статусом confirmed/exploitable без evidence refs.
- **P6 (Legacy safety):** Legacy `scan_mode=deep` без `scan_profile` сохраняет старую семантику (production-deep), не становится LAB.
- **P7 (Idempotency):** Повторная генерация отчёта при неизменном snapshot version не меняет `snapshot_hash`.

## 5. Простое объяснение архитектуры

Пользователь в UI выбирает один из трёх режимов: **Quick** (быстро и безопасно),
**Light** (стандартная безопасная проверка) или **Deep** (полноценный лабораторный пентест,
только с разрешением-«арендой» lease).

Frontend отправляет только `scan_profile`. Backend — единственное место, где решается, что это
значит внутри: какая «глубина», какая политика безопасности, какие инструменты и бюджеты.
Это решение принимает один компонент — **Profile Resolver**, и его результат замораживается на
весь скан (даже при resume).

Инструменты запускаются не напрямую LLM, а через детерминированный компилятор, который проверяет
разрешения и собирает безопасную команду. LLM только предлагает «что проверить», ссылаясь на факты.

Когда скан завершён, все собранные факты складываются в один неизменяемый «слепок»
(**ReportDocumentV1**), и из него генерируются четыре формата отчёта (PDF/JSON/Markdown/XML),
которые обязаны совпадать по смыслу. Если у AI нет доказательства — он обязан честно написать
«не проверено / недостаточно данных», а не выдумать уязвимость.
