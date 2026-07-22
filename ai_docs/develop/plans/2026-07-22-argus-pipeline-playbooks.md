# План: Единый исполняемый pipeline ARGUS + playbooks / multi-principal / oracles / WSTG / Nuclei argus-*

**Created:** 2026-07-22 01:07
**Orchestration:** orch-2026-07-22-01-07-pipeline
**Goal:** Связать подсистемы ARGUS в единый исполняемый pipeline `discovery → planning → execution → confirmation → evidence → finding → report` и добавить декларативные исполняемые playbook'и + multi-principal auth + oracles + WSTG coverage + Nuclei `argus-*` шаблоны. Идеи из внешнего чеклиста https://github.com/Az0x7/vulnerability-Checklist адаптируются с provenance/нормализацией, без дословного копирования.
**Total Tasks:** 8 (Фаза 1 = read-only аудит, выполнена; Фазы 2–8 = реализация с тестами)
**Priority:** High

---

## SECURITY-ИНВАРИАНТЫ (обязательны для КАЖДОЙ задачи)

- **SI-1 (approval не обходится):** высокорисковые/destructive/RCE/account-mutation/payment/race действия проходят `PreflightChecker`/`PayloadBuilder` gate. Ручной approve заменяется **Engagement Authorization Profile (EAP)** — подписанным per-engagement профилем, предавторизующим классы действий в пределах scope-allowlist, с записью в audit log. `requires_approval=True` семейства/действия остаются gated; EAP лишь удовлетворяет approval автоматически для предавторизованных классов внутри scope.
- **SI-2 (scope-driven SSRF):** внутренние цели разрешаются только если входят в targets-allowlist энгейджмента; произвольные third-party цели блокируются `ScopeEngine`. Ограничения не ослабляются.
- **SI-3 (split-plane секретов):** пароли/OTP/токены/cookies НИКОГДА не попадают в LLM prompt / логи / evidence в открытом виде. LLM оперирует хендлами (`principal_id`, `secret_ref`); реальные значения подставляет `SessionStore` на execution-слое. Redaction обязательна.
- **SI-4 (argv-only):** внешние команды — только argv-массивы, без shell-конкатенации / `shell=True`.
- **SI-5 (нет обхода PayloadRegistry):** LLM-payload'ы регистрируются как dynamic entries с provenance и проходят те же гейты (подпись/риск/approval). Нет LLM-fallback, обходящего PayloadRegistry или approval.
- **SI-6 (нет prompt injection):** внешний текст (чеклист) в prompts — только как данные внутри делимитеров, после нормализации.
- **SI-7 (обратная совместимость):** старые scan-конфиги и API продолжают работать; новые поля Optional/аддитивные.

---

## Tasks Overview

1. **P1-AUDIT-001** → Фаза 1: read-only аудит связей и разрывов (✅ выполнена, отчёт ниже)
2. **P2-PLAYBOOKS-002** → Фаза 2: подсистема декларативных playbook'ов (`backend/src/playbooks/*`)
3. **P3-AUTH-003** → Фаза 3: multi-principal auth + SessionStore/PrincipalSessionManager + пропагация Playwright-контекста
4. **P4-SCENARIO-004** → Фаза 4: ScenarioPlanner/ScenarioExecutor + actions + oracles + EAP + cleanup
5. **P5-SCEN-005** → Фаза 5: 12 базовых сценариев + integration-тесты
6. **P6-CHECKLIST-006** → Фаза 6: классификация Az0x7-чеклиста + Nuclei `argus-*` шаблоны + провенанс
7. **P7-WSTG-007** → Фаза 7: единый versioned WSTG registry + scenario coverage + расширение FindingDTO
8. **P8-QA-008** → Фаза 8: тесты/линт/mypy/миграции/startup/import-cycles/docs

## Dependencies Graph

```
P1-AUDIT-001
   └─> P2-PLAYBOOKS-002 ─┐
   └─> P3-AUTH-003 ──────┤
                         ├─> P4-SCENARIO-004 ─> P5-SCEN-005 ─┐
   └─> P6-CHECKLIST-006 ─┘                                   ├─> P8-QA-008
   └─> P7-WSTG-007 ──────────────────────────────────────────┘
```
- P4 зависит от P2 (playbook schema/registry/executor) и P3 (principals/SessionStore).
- P5 зависит от P4 (сценарии используют actions/oracles/EAP).
- P6 независима (payloads+nuclei), но интегрируется в P5-сценарии как источник payload-провенанса.
- P7 зависит от P4/P5 (scenario coverage, `scenario_id`/`playbook_run_id` в FindingDTO).
- P8 финальная (сквозная верификация).

## Progress (updated by orchestrator)

- ✅ P1-AUDIT-001: Read-only аудит (Completed)
- ⏳ P2-PLAYBOOKS-002: Playbooks subsystem (Pending)
- ⏳ P3-AUTH-003: Multi-principal auth (Pending)
- ⏳ P4-SCENARIO-004: Scenario planner/executor/oracles/EAP (Pending)
- ⏳ P5-SCEN-005: 12 сценариев + integration (Pending)
- ⏳ P6-CHECKLIST-006: Checklist classification + Nuclei argus-* (Pending)
- ⏳ P7-WSTG-007: WSTG registry + FindingDTO extension (Pending)
- ⏳ P8-QA-008: QA / migrations / docs (Pending)

---

## ФАЗА 1 — ОТЧЁТ АУДИТА (read-only)

### Карта фактических связей

| Слой | Файл | Роль | Реальное состояние |
|------|------|------|--------------------|
| Discovery (LLM) | `agents/va_orchestrator.py` | параллельные discovery-агенты по категориям, скиллы в prompt | Работает; выдаёт `list[dict]` findings из LLM. НЕ проходит PayloadRegistry (это discovery-хинты, не payload'ы). |
| Planning (stateless) | `recon/.../active_scan/injection_planner.py` | план инъекций по input-surface | Работает; `auth_context` — лишь строковая метка (`"authenticated"/"unknown"`), НЕ реальная сессия. |
| Payload gate | `payloads/registry.py`, `payloads/builder.py` | signed fail-closed registry + детерминированный bundle + preflight/approval | Зрелый механизм: подпись Ed25519, дедуп family_id, `requires_approval` для HIGH/DESTRUCTIVE, preflight (scope/ownership/policy/approval). |
| Policy/approval | `policy/preflight.py` (+ scope/ownership/policy_engine/approval_service) | 4 guardrail'а в одном `check()` | Работает; approval верифицируется по Ed25519-подписям (`ApprovalService.verify`, `expected_action=HIGH/DESTRUCTIVE`). Точка интеграции EAP. |
| Execution (active) | `orchestration/exploitation_executor.py` | payload→tool→sandbox `docker exec`→WRB-оценка | argv-массивы (SI-4 соблюдён). `PayloadBuilder` используется, но есть **LLM-fallback** `_wrb_generate_additional_payloads`/`_wrb_generate_scan_commands` (см. разрыв G-5). |
| Auth (login) | `orchestration/auth_config.py` | декларативный `TargetConfig`/`AuthConfig`/`login_flow` | **Один набор credentials** (`AuthCredentials` username/password/totp + email_login). Плейсхолдеры `$username/$password/$totp` резолвятся синхронно. Multi-principal НЕ поддержан. |
| Browser | `sandbox/playwright_adapter.py` | генерация Node-скрипта, `docker exec node`, `login_flow()` возвращает cookies | Работает как «одноразовый» запуск; каждый вызов поднимает/закрывает браузер, нет переиспользуемого `storageState`/контекста между действиями. |
| Confirmation | `recon/vulnerability_analysis/confirmation_policy.py` | переходы статусов findings + gate | Работает на моделях `schemas.vulnerability_analysis.*` (`FindingStatus`: HYPOTHESIS/PARTIALLY_CONFIRMED/CONFIRMED/REJECTED). |
| Evidence | `schemas/vulnerability_analysis/evidence_sufficiency.py` + `EvidenceSufficiencyEvaluator` | оценка достаточности | Работает; питает confirmation_policy. |
| Finding DTO | `pipeline/contracts/finding_dto.py` | межфазный DTO | `FindingStatus`: NEW/VALIDATED/... (ДРУГОЙ enum, чем в confirmation). Продюсеры — в основном `sandbox/parsers/*` (recon intel) + `findings/*`. |
| Nuclei | `recon/.../active_scan/nuclei_va_adapter.py`, `config/tools/nuclei.yaml` | безопасный argv + JSONL→intel-rows | argv-only allowlist (`-u/-jsonl/-duc/-ni/-rate-limit/-silent`). НЕТ передачи кастомных `argus-*` шаблонов (`-t`/templates-dir отсутствуют). |
| WSTG | `reports/wstg_coverage.py` + `wstg_coverage_v2.py` | покрытие WSTG в отчётах | Используется `wstg_coverage.build_wstg_coverage` (+ алиас `build_wstg_coverage_v2` в ТОМ ЖЕ модуле). |
| Skills | `skills/__init__.py` | загрузчик `.md`-скиллов в prompt | Загрузчик есть; в `backend/src/skills/` присутствует только `__init__.py` (нет `.md`-подкаталогов → `build_skills_prompt_block` часто вернёт ""). |
| Methodology | `training_data/tool_knowledge/methodology/va_checklist.yaml` | шаги VA + payload_families + WSTG | Декларативная методология (9 шагов), уже мапит `payload_families`/`owasp_wstg` — хороший каркас для scenario/WSTG-реестра. |

### Найденные РАЗРЫВЫ (функциональность есть, но не доходит до результата)

- **G-1 (Playwright auth обрывается — критично).** В `handlers.run_exploit_attempt` (backend/src/orchestration/handlers.py ~2219–2254) при `auth_config` выполняется `PlaywrightAdapter.login_flow()`, cookies кладутся в локальный `_browser_context`, но `execute_exploitation(findings, target=..., tenant_id=..., scan_id=...)` вызывается **без** `_browser_context`. `execute_exploitation` (exploitation_executor.py) вообще не имеет параметра auth/cookies → все sandbox-инструменты (dalfox/sqlmap/nuclei/ffuf) бегут **неаутентифицированными**. Аутентифицированная поверхность не тестируется.
- **G-2 (single-principal).** `auth_config.py` моделирует ровно один principal. Нет owner/attacker, нет изоляции cookie jar, нет `secret_ref`. IDOR/authz-сценарии (cross-user) невозможны корректно.
- **G-3 (два разных Finding-контракта).** `confirmation_policy` оперирует `schemas.vulnerability_analysis.FindingStatus` (HYPOTHESIS/…), а межфазный `pipeline.contracts.finding_dto.FindingDTO` — другим enum (NEW/VALIDATED/…). Мост `confirmation → evidence → FindingDTO` не сквозной: подтверждённый статус не проецируется в DTO, нет полей `scenario_id/playbook_run_id/principal/baseline-mutated/diff/oracle_result/cleanup_status/provenance/approval_id`.
- **G-4 (WSTG dead code).** `reports/wstg_coverage_v2.py` содержит собственную `build_wstg_coverage_v2`, но **никем не импортируется** (grep: 0 внешних ссылок). Реально используется `wstg_coverage.py`. Дубль → удалить/deprecate, ввести единый versioned registry.
- **G-5 (LLM-fallback у payloads/commands).** `exploitation_executor._wrb_generate_additional_payloads` и `_wrb_generate_scan_commands` генерируют payload'ы/команды напрямую от LLM в обход PayloadRegistry (нарушает критерий готовности). Требуется регистрация как dynamic entries с provenance + прохождение гейтов (SI-5).
- **G-6 (Nuclei без argus-* шаблонов).** `build_nuclei_va_argv` не поддерживает кастомные шаблоны/templates-dir → идеи Django/Symfony/AEM/Jira из чеклиста некуда подключить.
- **G-7 (Playwright без переиспользуемой сессии).** Каждый вызов адаптера — новый браузер/контекст; нет `storageState`/переиспользуемого контекста на principal → невозможно вести stateful-сценарии (login→действие→oracle) в одной сессии.
- **G-8 (нет исполняемых playbook'ов/сценариев).** Есть stateless `injection_planner`, но нет декларативных исполняемых сценариев (authz/authn/rate-limit/race/file-upload/business-logic) с lifecycle-статусами, oracles и cleanup.
- **G-9 (скиллы пусты).** Загрузчик skills есть, но контента `.md` в `backend/src/skills/` нет — discovery-подсказки деградируют молча.

**Вывод:** ядро (registry/builder/preflight/approval/evidence/confirmation) зрелое и НЕ требует ослабления. Основная работа — сшить обрывы (G-1, G-3, G-7), добавить multi-principal (G-2), исполняемый playbook/scenario-слой (G-8), закрыть LLM-обход (G-5), подключить argus-* nuclei (G-6), консолидировать WSTG (G-4), наполнить провенанс из чеклиста (P6) и расширить FindingDTO обратимо (G-3/P7).

---

## Детализация задач

### P2-PLAYBOOKS-002 — Подсистема декларативных playbook'ов
**Priority:** High · **Deps:** P1 · **Complexity:** Complex
**Files (create):**
- `backend/src/playbooks/__init__.py`
- `backend/src/playbooks/schema.py` — Pydantic-модели playbook (декларативная схема; **без Python-кода из YAML**), `extra="forbid"`, версия схемы, `playbook_id` (regex, дедуп), lifecycle-enum.
- `backend/src/playbooks/registry.py` — по образцу `payloads/registry.py`: fail-closed загрузка, Ed25519-подпись через `sandbox/signing`, дедуп `playbook_id`, соответствие `id==filename.stem`, версии, `SIGNATURES`.
- `backend/src/playbooks/planner.py` — выбор применимых playbook'ов (applicability по discovery/recon), эмиссия lifecycle `DISCOVERED/PLANNED/SKIPPED_NOT_APPLICABLE`.
- `backend/src/playbooks/executor.py` — исполнение шагов через actions/oracles, фиксация статусов `WAITING_APPROVAL/RUNNING/PARTIAL/CONFIRMED/REJECTED/CLEANUP_COMPLETE/CLEANUP_FAILED` с причинами.
- `backend/src/playbooks/actions.py` — базовые декларативные действия (HTTP-запрос, browser-действие) — argv/структурные, без shell.
- `backend/src/playbooks/oracles.py` — интерфейс oracle + базовые реализации (перенос/шеринг с P4).
- `backend/src/playbooks/evidence.py` — сбор baseline/mutated req/resp + diff, redaction, привязка к EvidenceDTO.
- `backend/config/playbooks/<категории>/*.yaml` + `backend/config/playbooks/SIGNATURES` + `scripts/playbooks_sign.py`.
**Acceptance criteria:**
- Registry fail-closed: неподписанный/битый/дубль `playbook_id` → отказ загрузки (тест).
- Схема запрещает исполняемый Python из YAML (только декларативные поля; `extra="forbid"`).
- Все lifecycle-статусы (DISCOVERED, PLANNED, SKIPPED_NOT_APPLICABLE, WAITING_APPROVAL, RUNNING, PARTIAL, CONFIRMED, REJECTED, CLEANUP_COMPLETE, CLEANUP_FAILED) присутствуют, переходы валидируются, причина фиксируется.
- `scripts/payloads_sign.py`-совместимый `playbooks_sign.py`; тест «no signature drift».
**Security-инварианты:** SI-4 (actions argv/структурные), SI-5 (payload'ы только через PayloadRegistry), SI-6 (описания из YAML не идут в prompt как инструкции), SI-7.

### P3-AUTH-003 — Multi-principal auth + SessionStore
**Priority:** High · **Deps:** P1 · **Complexity:** Complex
**Files:**
- `backend/src/orchestration/auth_config.py` (extend) — `PrincipalConfig` (`principal_id`, роль owner/attacker/anon, credentials как `secret_ref`), список `principals`; back-compat: одиночный `authentication` → default owner-principal.
- `backend/src/auth/session_store.py` (create) — `SessionStore`/`PrincipalSessionManager`: изолированный cookie jar / `storageState` per principal, резолв `secret_ref`→реальные значения ТОЛЬКО на execution-слое, redaction-хелперы.
- `backend/src/sandbox/playwright_adapter.py` (extend) — переиспользуемый контекст/`storageState` per principal (закрывает G-7); экспорт auth-контекста для HTTP/exploitation.
- `backend/src/orchestration/handlers.py` (fix G-1) — пробросить principal-контекст (cookies/headers) в `execute_exploitation`.
- `backend/src/orchestration/exploitation_executor.py` (fix G-1) — принять и применить auth-контекст (cookies/headers) в argv инструментов.
- `ai_docs/develop/architecture/2026-07-22-auth-migration-guide.md` (create) — migration guide.
**Acceptance criteria:**
- ≥2 principals (owner, attacker) с изолированными cookie jar; кросс-загрязнения нет (тест).
- Playwright-сессия owner реально применяется в exploitation/HTTP (G-1 закрыт: тест доказывает аутентифицированный запрос).
- Секреты не появляются в prompt/логах/evidence (тест на redaction; проверка `secret_ref`-плоскости) — SI-3.
- Старый одно-principal конфиг работает как default owner (back-compat тест) — SI-7.
**Security-инварианты:** SI-2, SI-3, SI-7.

### P4-SCENARIO-004 — ScenarioPlanner/Executor + oracles + EAP + cleanup
**Priority:** High · **Deps:** P2, P3 · **Complexity:** Complex
**Files:**
- `backend/src/playbooks/planner.py` → `ScenarioPlanner` (отдельно от `injection_planner` для stateless-инъекций; stateful multi-step сценарии).
- `backend/src/playbooks/executor.py` → `ScenarioExecutor` (использует principals из P3, actions из P2).
- `backend/src/playbooks/oracles.py` (extend) — oracles: `authz`, `authn`, `rate_limit`, `race`, `file_upload`, `business_logic`.
- `backend/src/policy/engagement_authorization.py` (create) — **Engagement Authorization Profile**: подписанный per-engagement профиль, `scope-allowlist` целей + предавторизованные классы действий; интеграция в `PreflightChecker`/`PayloadBuilder` как источник авто-approval для предавторизованных классов в scope; audit-запись `approval_id`.
- `backend/src/playbooks/cleanup.py` (create) — регистрация и исполнение cleanup-действий (созданные аккаунты/данные), статусы CLEANUP_COMPLETE/FAILED.
**Acceptance criteria:**
- EAP: предавторизованный класс действия в scope → approval удовлетворяется автоматически с записью `approval_id` в audit; действие ВНЕ scope или НЕ предавторизованное → по-прежнему `WAITING_APPROVAL`/deny (тест обоих путей) — SI-1.
- SSRF/внутренние цели: разрешены только из targets-allowlist EAP; third-party блокируется `ScopeEngine` (тест) — SI-2.
- Каждый oracle даёт детерминированный вердикт (baseline vs mutated) с evidence-diff.
- Cleanup запускается всегда (в т.ч. на PARTIAL/REJECTED), статус фиксируется.
**Security-инварианты:** SI-1, SI-2, SI-3, SI-4, SI-5.

### P5-SCEN-005 — 12 базовых сценариев + integration-тесты
**Priority:** High · **Deps:** P4 · **Complexity:** Complex
**Files:** `backend/config/playbooks/**/*.yaml` (+ подписи) и `backend/tests/integration/playbooks/test_*.py` для:
`auth.direct-protected-route`, `registration.duplicate-casefold`, `reset.token-reuse-after-password-change`, `mfa.direct-step-skip`, `session.logout-invalidation`, `idor.cross-user-read`, `idor.cross-user-write`, `authorization.method-variant`, `mass-assignment.role-injection`, `rate-limit.login-account-keyed`, `rate-limit.otp-resend`, `race.single-use-token`.
**Acceptance criteria:**
- Каждый сценарий: декларативный YAML (подписан), проходит planner→executor→oracle→evidence→finding в integration-тесте (mock/stub target).
- IDOR cross-user использует ≥2 principals (owner/attacker) из P3.
- race/mass-assignment/reset-token помечены как классы, требующие approval → удовлетворяются EAP только в scope (тест).
- Все 12 достигают терминального lifecycle-статуса с evidence-diff и cleanup.
**Security-инварианты:** SI-1, SI-2, SI-3.

### P6-CHECKLIST-006 — Классификация Az0x7-чеклиста + Nuclei argus-*
**Priority:** Medium · **Deps:** P1 · **Complexity:** Moderate
**Files:**
- `backend/config/checklist/az0x7_classified.yaml` (create) — категории A–F, provenance (источник/commit/URL), нормализованный текст (не дословный).
- `backend/config/payloads/*.yaml` (extend, при необходимости) — новые payload-семейства после дедупа против существующих; пере-подпись `payloads_sign.py`.
- `backend/config/nuclei-templates/argus-*.yaml` (create) — идеи Django/Symfony/AEM/Jira, строгие AND-matchers + negative fixtures + provenance.
- `backend/src/recon/vulnerability_analysis/active_scan/nuclei_va_adapter.py` (fix G-6) — безопасная передача templates-dir/`-t` только для argus-* (argv-allowlist).
- `backend/tests/.../test_nuclei_argus_templates.py` + CI-validate (`nuclei -validate`).
**Acceptance criteria:**
- Классификация A–F с provenance; тест «нет дословного копирования» (нормализация/делимитеры) — SI-6.
- Дедуп payload'ов против `config/payloads` (тест на отсутствие дублей family/seed).
- Каждый `argus-*` шаблон: AND-matcher + negative fixture (не срабатывает на чистом ответе) + provenance; `nuclei -validate` в CI зелёный.
- Внешний текст чеклиста не попадает в prompt как инструкция (только данные в делимитерах).
**Security-инварианты:** SI-5, SI-6.

### P7-WSTG-007 — Единый WSTG registry + scenario coverage + FindingDTO
**Priority:** Medium · **Deps:** P4, P5 · **Complexity:** Moderate
**Files:**
- `backend/src/reports/wstg_coverage.py` (consolidate) — единый versioned registry test-case'ов; статусы покрытия `NOT_APPLICABLE/NOT_RUN/BLOCKED/PARTIAL/EXECUTED_NO_FINDING/CONFIRMED_FINDING/ERROR` по выполненным сценариям.
- `backend/src/reports/wstg_coverage_v2.py` (remove/deprecate — G-4) — удалить dead code или оставить re-export с DeprecationWarning.
- `backend/src/pipeline/contracts/finding_dto.py` (extend, обратимо/Optional) — `scenario_id`, `playbook_run_id`, `source_principal`, `target_principal`, `baseline_request/response`, `mutated_request/response`, `diff`, `oracle_result`, `cleanup_status`, `provenance`, `approval_id`.
- мост `confirmation → evidence → FindingDTO` (fix G-3): проекция подтверждённого статуса и линковка evidence/scenario.
**Acceptance criteria:**
- Один источник истины WSTG; `wstg_coverage_v2` не импортируется нигде (grep=0) либо помечен deprecated.
- Scenario coverage маппит выполненные test case на 7 статусов с линками finding/evidence.
- Новые поля FindingDTO — Optional; существующие продюсеры/тесты не падают (back-compat) — SI-7.
- Подтверждённый в confirmation_policy статус доходит до FindingDTO (тест сквозного моста).
**Security-инварианты:** SI-3 (baseline/mutated req/resp редактируются), SI-7.

### P8-QA-008 — Тесты / линт / mypy / миграции / docs
**Priority:** High · **Deps:** P2–P7 · **Complexity:** Moderate
**Files:** `backend/tests/**`, `backend/alembic/versions/*` (при изменении моделей хранения findings), `docs/**`, `ai_docs/develop/**`.
**Acceptance criteria:**
- `ruff check src/`, `black src/`, `mypy` — чисто по затронутым модулям.
- unit + integration зелёные; `test_no_cyclic_imports` проходит (import cycles).
- `alembic upgrade head` применяется; startup backend ОК.
- catalog-signatures без дрейфа (payloads + playbooks); `nuclei -validate` в CI.
- docs обновлены (playbooks, multi-principal, EAP, WSTG registry, provenance).
**Security-инварианты:** все SI (регрессионная проверка), особенно SI-1 и SI-5 («нет LLM fallback в обход PayloadRegistry/approval»).

---

## Architecture Decisions

- Playbook/Scenario-слой строится **по образцу PayloadRegistry** (signed, fail-closed, дедуп, версии) — единый паттерн доверенных каталогов.
- Approval НЕ ослабляется: EAP — это подписанный источник авто-удовлетворения approval для предавторизованных классов в scope, встраиваемый в существующий `PreflightChecker`/`ApprovalService`, с audit `approval_id`.
- Секреты — split-plane: LLM видит только `principal_id`/`secret_ref`; `SessionStore` резолвит на execution-слое.
- FindingDTO расширяется только Optional-полями (обратимость), мост из VA-confirmation проецирует статус.
- WSTG — один versioned registry; дубль удаляется.
- Внешний чеклист — источник ИДЕЙ с provenance/нормализацией, не копипаст.

## Implementation Notes

- LLM-fallback в `exploitation_executor` (G-5) переписать: сгенерированные payload'ы регистрировать как dynamic entries PayloadRegistry (provenance=llm) и прогонять через builder/preflight; при невозможности регистрации — отказ, а не прямой запуск.
- Playwright: ввести переиспользуемый контекст с `storageState` per principal; экспортировать cookies/headers в HTTP/exploitation argv.
- Nuclei argus-*: только явный templates-dir внутри репозитория, argv-allowlist; никаких пользовательских путей.
