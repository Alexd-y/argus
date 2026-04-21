# План: ARGUS Cycle 6 — Batch 3 (Admin Frontend XL — Triage + Audit, ARG-051b)

**Создан:** 2026-04-21
**Оркестрация:** `orch-2026-04-21-15-30-argus-cycle6-b3`
**Workspace:** `.cursor/workspace/active/orch-2026-04-21-15-30-argus-cycle6-b3/`
**Roadmap:** [`Backlog/dev1_finalization_roadmap.md`](../../../Backlog/dev1_finalization_roadmap.md) §Batch 3
**Carry-over:** [`ai_docs/develop/issues/ISS-cycle6-carry-over.md`](../issues/ISS-cycle6-carry-over.md) (ARG-051 Phase 2)
**Backlog (источник истины):** [`Backlog/dev1_.md`](../../../Backlog/dev1_.md)
**Предыдущая оркестрация:** `orch-argus-20260420-1430` (Batch 1 + early Batch 2)
**Статус:** 🟢 Ready
**Всего задач:** 8 (T20–T27) — в пределах cap=10
**Ожидаемая wall-time:** ~4 дня при 3-worker parallelism

---

## 1. Контекст

Batch 3 — вторая половина **Admin Frontend XL** (`ARG-051b`): глобальная триаж-консоль findings, audit-log viewer с проверкой целостности hash-цепочки, переключатель экспорта SARIF/JUnit per-tenant и a11y/E2E-покрытие. Foundation (Batch 2: chrome layout + RBAC + tenants/scopes/scans/llm + bulk-cancel/bulk-suppress + audit search/export API) уже зафиксирован на диске — все RBAC-инварианты, table patterns и `Frontend/src/lib/admin*` слой готовы к расширению. Цель Cycle 6 — закрыть operator-side critical surface, без которой ARGUS не запускается в multi-tenant SaaS-режиме без CLI-доступа. Этот batch разблокирует Batch 4 (kill-switch UI поверх audit infrastructure) и Batch 5 (Webhook DLQ UI поверх таблиц триажа), которые пойдут в следующих орк-циклах.

## 2. Сводка верификации состояния (что подтверждено на диске)

**Batch 1 (T01–T10) — ВСЁ RESOLVED:** найдены `backend/src/oast/redis_stream.py` (T01), `backend/src/policy/{approval_dto,approval_service}.py` (T02), 16 YAML c `image: "argus-kali-network:latest"` против 75 c `argus-kali-web` (T03 — миграция done; Ed25519 re-sign документирован как deferred CI step), `backend/alembic/versions/024_tenant_exports_sarif_junit.py` (T04), `.github/workflows/{advisory-gates,helm-validation,sandbox-images,e2e-vuln-target-smoke}.yml` (T07/T08/T09/T10), `infra/scripts/sbom_drift_check.py` + root `renovate.json` (T09); T05/T06 закрытие подтверждено в ISS-cycle6-carry-over §carry-over.

**Batch 2 (T11–T19) — ВСЁ RESOLVED:** `Frontend/src/app/admin/{layout,page,tenants,tenants/[tenantId]/{settings,scopes},scans,llm,system,forbidden,error}.tsx` + `AdminLayoutClient.tsx` + `AdminRouteGuard.tsx` + `AdminAuthContext` + `useAdminAuth` + `adminRoles.ts` (T11–T16), `backend/src/api/routers/admin_bulk_ops.py` с `/scans/bulk-cancel` + `/findings/bulk-suppress` (T17), `GET /admin/audit-logs` + `GET /admin/audit-logs/export` (JSON/CSV) в `admin.py` lines 1222 + 1272 (T18), `backend/alembic/versions/025_tenant_limits_overrides.py` (T13 backend), `Frontend/tests/e2e/admin-console.spec.ts` (T19).

**Batch 3 (T20–T27) — НЕ НАЧАТ (этот цикл):** отсутствуют `Frontend/src/app/admin/{findings,audit}/`, отсутствует cross-tenant findings router (`admin_findings.py`), отсутствует public chain-verify API endpoint (логика hash-chain есть в `backend/src/policy/audit.py`, но не выставлена в HTTP), отсутствует SARIF/JUnit toggle в `TenantSettingsClient`, нет axe-core CI gate, нет E2E под admin part 2.

**Batch 4–6 — НЕ НАЧАТ (spot-check):** `Frontend/src/app/admin/system/page.tsx` — placeholder (`Empty state`), нет `backend/src/scheduling/`, нет `backend/src/notifications/webhook_dlq*.py`, нет `infra/helm/argus/templates/policy/`, нет `hpa-celery-worker-kev.yaml`, нет PDF/A pipeline. Эти задачи зависят от паттернов и RBAC-инфраструктуры, которые финализирует Batch 3.

## 3. Задачи

| ID | Title | Size | Wave | Deps | Files (est.) | Acceptance criteria | Status |
|----|-------|------|------|------|--------------|---------------------|--------|
| **T20** | Global finding triage UI (cross-tenant, SSVC-sorted, KEV-filtered) | **L** | 2 | T24 | ~7 (`Frontend/src/app/admin/findings/{page,AdminFindingsClient,FindingsTable,FindingsFilters}.tsx`, `Frontend/src/lib/adminFindings.ts` + `.test.ts`, partial E2E spec) | (a) Маршрут `/admin/findings` рендерит таблицу с пагинацией, сортировкой по SSVC outcome → KEV → severity → EPSS, фильтрами `tenant_id`, `severity`, `kev_listed`, `ssvc_action`, free-text `q`; (b) только `super-admin` видит cross-tenant view (`admin`/`operator` — только свой tenant, fail-safe); (c) p95 first paint ≤ 2 s на 100 строк; (d) skeleton-loader, error-state без stack-trace; (e) Vitest unit ≥ 6 cases (sort/filter/empty/error/RBAC mask); (f) **worker report mandatory** (L-size). | ⏳ Pending |
| **T21** | Bulk findings actions (suppress / escalate / mark-false-positive / attach-to-CVE) | M | 3 | T20 | ~6 (`Frontend/src/app/admin/findings/{BulkActionsBar,BulkActionDialog}.tsx`, `Frontend/src/lib/adminFindings.ts` extend, `backend/src/api/routers/admin_bulk_ops.py` extend, `schemas.py` extend, `backend/tests/api/admin/test_admin_bulk_findings_actions.py`) | (a) UI floating action bar при ≥1 selection; (b) double-confirmation modal с typed confirmation для escalate (destructive-ish); (c) backend endpoints `POST /admin/findings/bulk-{escalate,mark-false-positive,attach-cve}` с RBAC + audit emit + reason text mandatory ≥10 chars; (d) bulk cap = 100 IDs/request (как в существующем `bulk-suppress`); (e) audit row per request с `request_id` + sha256 fingerprint of sorted IDs; (f) backend tests ≥ 8 cases (RBAC, cap, idempotent, terminal status, validation, audit emit). | ⏳ Pending |
| **T22** | Audit log viewer UI с chain integrity verification | M | 2 | T25 | 13 (`Frontend/src/lib/adminAuditLogs.ts` + `.test.ts`, `Frontend/src/app/admin/audit-logs/{page,AdminAuditLogsClient,AdminAuditLogsQueryProvider,actions}.{tsx,ts}` + `actions.test.ts` + `AdminAuditLogsClient.test.tsx`, `Frontend/src/app/admin/audit-logs/export/route.ts`, `Frontend/src/components/admin/audit-logs/{AuditLogsFilterBar,AuditLogsTable,ChainVerifyResult}.tsx` + 3 `.test.tsx`, nav entry в `AdminLayoutClient.tsx`) | (a) ✅ Маршрут `/admin/audit-logs` рендерит paginated (infinite-scroll, virtualised) table c фильтрами `event_type`, `tenant_id` (super-admin only), `q`/`actor_subject`, `since`, `until`, синхронизированными с URL; (b) ✅ "Verify chain integrity" триггерит `POST /admin/audit-logs/verify-chain` через `"use server"` action и рендерит OK/DRIFT banner (`verified_count`, `last_verified_index`, `drift_event_id`, "scroll-to-record" если запись загружена); (c) ✅ Export — серверный route handler `/admin/audit-logs/export?format=csv\|json` (streaming, X-Admin-Key остаётся на сервере); (d) ✅ closed-taxonomy errors — никакого PII / stack-trace на UI, RBAC через `getServerAdminSession()` + `resolveEffectiveTenant()` (admin привязан к session tenant, super-admin — cross-tenant); (e) ✅ Vitest 84 кейса (Zod schemas + wire-нормализация, server actions: identity / tenant binding / query mapping / cursor synthesis / error taxonomy, фильтр-bar, virtualised table + drawer focus-trap, ChainVerifyResult, integration-tests клиента). ESLint clean, `tsc --noEmit` clean, full Frontend suite 297/297 ✅. | ✅ Completed |
| **T23** | SARIF / JUnit toggle UI per-tenant (закрывает T04 UI surface) | S | 1 | — | ~3 (`Frontend/src/app/admin/tenants/[tenantId]/settings/TenantSettingsClient.tsx` extend, `Frontend/src/lib/adminProxy.ts` mutation if needed, `Frontend/tests/unit/admin/exports-toggle.test.tsx`) | (a) В `TenantSettingsClient` секция "Report exports" с двумя toggle: SARIF, JUnit; (b) изменение → `PATCH /api/v1/admin/tenants/{id}` с `{exports_sarif_junit_enabled: bool}` (existing endpoint per ISS-cycle6 §T04); (c) optimistic-update + rollback на error; (d) Vitest ≥ 4 cases (initial state both toggles, optimistic update, rollback, RBAC mask для operator). | ⏳ Pending |
| **T24** | Backend: cross-tenant finding query API (super-admin only, RBAC) | M | 1 | — | ~5 (`backend/src/api/routers/admin_findings.py` NEW, `backend/src/api/schemas.py` extend, register router в `admin.py` или `main.py`, 2 test files) | (a) `GET /admin/findings?tenant_id=&severity=&kev_listed=&ssvc_action=&q=&since=&until=&limit=&offset=` возвращает 200 со страницей; (b) `super-admin` без `tenant_id` видит cross-tenant; `admin`/`operator` ОБЯЗАНЫ передать собственный `tenant_id` иначе 403; (c) ORM-query с RLS context: super-admin → `set_session_tenant(None)` или explicit cross-tenant view (одобренный паттерн), admin → tenant-scoped; (d) фильтры через parameterized SQLAlchemy (никаких string concat); (e) p95 ≤ 500 ms на reference dataset (документировано без CI gate, как `audit-logs`); (f) tests ≥ 12 cases (RBAC matrix × фильтры × пагинация × empty × invalid query). | ⏳ Pending |
| **T25** | Backend: chain integrity verification API endpoint | S | 1 | — | ~4 (`backend/src/api/routers/admin.py` add `POST /admin/audit-logs/verify-chain`, `backend/src/policy/audit.py` extend public helper если нет, `schemas.py` add `AuditChainVerifyResponse`, `backend/tests/api/admin/test_admin_audit_chain_verify.py`) | (a) `POST /admin/audit-logs/verify-chain?since=&until=&tenant_id=` возвращает `{ok: bool, verified_count: int, last_verified_index: int, drift_detected_at: str | null, drift_event_id: str | null}`; (b) логика — replay hash chain через существующий `policy/audit.py::GENESIS_HASH` + canonical_json + sha256; (c) p95 ≤ 2 s на 10⁴ events (verified в test); (d) RBAC: только `admin`/`super-admin`; (e) tests ≥ 6 cases (clean chain / synthetic drift detection / empty range / time-window guard / RBAC). | ⏳ Pending |
| **T26** | Vitest unit ≥30 cases + axe-core 0 violations CI gate | S | 4 | T20, T21, T22, T23 | ~5 (`Frontend/tests/unit/admin/*.test.tsx` ≥30 new across triage/audit/exports, `Frontend/tests/a11y/admin-axe.spec.ts` NEW, `Frontend/package.json` add `@axe-core/playwright`, `.github/workflows/ci.yml` или новый workflow add a11y job, vitest coverage threshold update if needed) | (a) Vitest passes ≥30 новых assertions cumulative across T20–T23 (включая уже размещённые в каждой задаче); (b) axe-core scan на каждом из `/admin/{findings,audit,tenants/[id]/settings}` → 0 critical/serious violations; (c) CI job non-blocking initially (advisory как T07/T08), но fail-on-regression policy документирован; (d) `npm run test:a11y` локальная команда работает. | ⏳ Pending |
| **T27** | Playwright E2E coverage ≥10 scenarios для admin part 2 routes | M | 4 | T20, T21, T22, T23 | ~5 (`Frontend/tests/e2e/{admin-findings,admin-audit,admin-exports-toggle,admin-rbac}.spec.ts`, shared `Frontend/tests/e2e/fixtures/admin.ts`) | (a) ≥10 scenarios суммарно: findings list/filter/sort/empty/RBAC denial; bulk-suppress happy + double-confirm cancel; bulk-escalate + reason validation; audit list + verify-chain OK + drift visualization; exports toggle on/off; (b) все assertions против real backend API через `webServer` config (как `admin-console.spec.ts`); (c) zero "Unhandled Runtime Error" overlay (assertion из существующих specs); (d) zero 5xx network responses (assertion из существующих specs); (e) запускаются в CI pipeline как часть Frontend E2E job. | ⏳ Pending |

**Итого:** 8 задач • ~35 файлов изменено/создано • ~4 дня wall-time при 3 параллельных воркерах.

## 4. Critical path / зависимости

```text
Wave 1 (parallel, день 1):
  ├─ T24 (backend cross-tenant findings API)  ─┐
  ├─ T25 (backend chain verify API)           ─┼─ блокирует Wave 2
  └─ T23 (SARIF/JUnit toggle UI — backend ≃ ✅)─┘ полностью независима

Wave 2 (parallel after Wave 1, дни 2-3):
  ├─ T20 (findings UI, depends on T24) ── L-size, worker report mandatory
  └─ T22 (audit UI, depends on T25)

Wave 3 (sequential after T20, день 3):
  └─ T21 (bulk actions UI + backend extension)

Wave 4 (parallel after T20–T23, день 4):
  ├─ T26 (Vitest ≥30 + axe-core CI gate)
  └─ T27 (Playwright E2E ≥10 scenarios)
```

**Критический путь по wall-time:** `T24 → T20 → T21 → T27` (~4 дня). T25, T22, T23, T26 — параллельны и не на критическом пути.

**Точки синхронизации:** после Wave 1 — review backend API contracts перед началом UI работ; после Wave 3 — фриз UI surface перед E2E + a11y.

## 5. Out-of-scope (вынесено в следующие циклы)

- **Webhook DLQ UI** (T41) — Batch 5, требует Alembic 026 (`webhook_dlq_entries`) + DLQ persistence repository (T37–T40) **до** UI.
- **Kill-switch UI** (T28–T30) и **scheduled scans** (T32–T36) — Batch 4. Требуют `system/page.tsx` редизайн поверх паттернов из T20/T22.
- **Cross-tenant audit log search** super-admin overlay — `audit-logs` уже cross-tenant в backend (по `tenant_id` фильтру), но dedicated multi-tenant view с aggregations — вне scope.
- **Bulk attach-to-CVE через CVE search-as-you-type** — backend получит endpoint в T21, но autocomplete UI с CVE database остаётся базовым (статический textbox + клиентская валидация формата `CVE-YYYY-NNNNN+`).
- **Audit log forensics export как WORM-S3 archive** — выходит за рамки T22; pipeline остаётся read-only из БД.
- **PDF/A-2u toggle** (T48) — Batch 6, отдельно от SARIF/JUnit toggle (T23).

## 6. DoD reminders (`Backlog/dev1_.md` §19)

Каждая задача ⟶ один атомарный коммит ⟶ перед merge:

1. ✅ **`pytest -q`** зелёный, coverage ≥ 85% для затронутых модулей (`backend/src/api/routers`, `backend/src/policy/audit`).
2. ✅ **`ruff check backend/src`** — 0 ошибок.
3. ✅ **`mypy --strict backend/src`** — 0 ошибок (advisory `mypy_capstone` gate; на Windows — WSL2, см. `ai_docs/develop/troubleshooting/mypy-windows-access-violation.md`).
4. ✅ **`bandit -q -r backend/src`** — 0 ошибок (advisory `bandit` gate из T08).
5. ✅ **`alembic upgrade head && alembic downgrade -1 && alembic upgrade head`** проходит (если в задаче есть migration; в Batch 3 миграций НЕТ — все backend задачи additive endpoints).
6. ✅ **`docker compose -f infra/docker-compose.yml up -d`** поднимает стек; smoke `scripts/e2e_full_scan.sh http://juice-shop:3000` зелёный (запускать раз в Batch перед merge — не на каждом коммите).
7. ✅ **Frontend публичный SSE/контракт не сломан** — все изменения только в `Frontend/src/{app/admin/**,components/admin/**,lib/admin*,services/admin/**}` и `Frontend/tests/`.
8. ✅ **`docs/tool-catalog.md` ≥150** строк — sustained inviolable; для Batch 3 не модифицируется.
9. ✅ **0 hexstrike/legacy** упоминаний — sustained gate (`backend/tests/test_no_hexstrike_active_imports.py`).
10. ✅ **`scripts/argus_validate.py`** — 3 required gates (`ruff_capstone`, `catalog_drift`, `coverage_matrix`) green; advisory gates (помимо kown skip mypy_capstone на Windows) предпочтительно тоже green.
11. ✅ **Conventional commit per task:** `feat(<scope>): <summary> (T<NN>)`. Примеры: `feat(admin-findings): add cross-tenant query API (T24)`, `feat(admin-ui): global finding triage console (T20)`, `chore(ci): add axe-core a11y gate (T26)`.
12. ✅ **Worker report MANDATORY для T20** (L-size) → `ai_docs/develop/reports/2026-04-21-arg-t20-admin-findings-triage.md`. Структура: цель → выполненные изменения → файлы → тесты → known limitations → next steps. Для других задач — опционально.

## 7. Coding & security guidelines (sustained from Cycle 5 invariants)

### Backend (T21, T24, T25)

- **Никакого `shell=True` / `docker.sock` / `docker exec host`** — не релевантно для admin endpoints, но напоминание для всего проекта.
- **Parameterized SQL ONLY** через SQLAlchemy ORM или `text()` с `:param` — никаких f-strings/`.format()` в SQL. Уже задано паттерном `_audit_logs_filtered_select` в `admin.py` — переиспользовать.
- **`X-Admin-Key` через `require_admin`** dependency — не bypass'ить. RBAC enforce строго: `super-admin` для cross-tenant queries, `admin`+ для bulk actions, audit emit с `user_id_hash` (не raw ID).
- **Closed-taxonomy errors** — не возвращать stack traces. HTTPException(status_code, detail=<short string>); все internal errors в structured logger без PII.
- **PII deny-list:** `tenant_id`, `user_id`, `email`, `password`, `secret`, `token`, `api_key`, `authorization` — не должны попадать в log records, в metric labels, в OTel span attributes (sustained `safe_set_span_attribute` контракт).
- **Audit emit per state-changing action** — каждый bulk endpoint, каждый chain-verify call → `AuditLog` row с canonical event_type из `AuditEventType` enum + reason text + sha256 fingerprint of input.
- **Rate-limit / cap:** bulk operations cap=100 IDs/request (sustained pattern); chain verify time-window cap (например, ≤90 дней) — fail-fast при превышении.

### Frontend (T20, T21, T22, T23)

- **Public surface FROZEN:** менять ТОЛЬКО `Frontend/src/app/admin/**`, `Frontend/src/components/admin/**`, `Frontend/src/lib/admin*` (`adminProxy.ts`, `serverAdminBackend.ts`, `adminErrorMapping.ts`), `Frontend/src/services/admin/**`, `Frontend/tests/**`. Любой touch вне этих путей = блокирующий violation.
- **API contracts:** не сломать существующие `/api/v1/admin/*` schemas, по которым работает `Frontend/src/lib/adminProxy.ts`. Все новые поля — additive nullable.
- **No PII in client-side state / localStorage / sessionStorage** — кроме existing `argus.admin.role` (RBAC simulation для dev). Никаких токенов в JS-памяти beyond auth flow.
- **Error UI без stack traces** — `<AdminErrorBoundary>` уже паттерн (`Frontend/src/app/admin/error.tsx`). Для всех новых ошибок — closed-taxonomy mapping через `Frontend/src/lib/adminErrorMapping.ts`.
- **a11y:** `aria-label` на все interactive elements; semantic `<table>` + `<th scope="col">` для FindingsTable / AuditTable; focus-visible ring; keyboard nav для bulk action bar (Esc для закрытия dialog). axe-core CI gate (T26) ловит regressions.
- **CSP / XSS:** все user-supplied строки (filter inputs, free-text search, reason text) — рендерить через React (auto-escape). Никаких `dangerouslySetInnerHTML`. Если нужно highlight match — использовать `<mark>` через splitting текста, не innerHTML.
- **Optimistic updates + rollback** — для toggle (T23) и bulk actions (T21). Network failure → revert local state + show toast (existing `adminErrorMapping`).

### Cross-cutting

- **Атомарные коммиты** — один Tnn = один commit. Pre-commit hook (если есть) не bypass'ить (`--no-verify` запрещено).
- **`.env` / secrets** — никогда не коммитить. `Frontend/.env.example` уже содержит шаблон для `NEXT_PUBLIC_ADMIN_DEV_ROLE`; новые admin env vars (e.g., `NEXT_PUBLIC_ADMIN_FINDINGS_PAGE_SIZE`) с `NEXT_PUBLIC_` префиксом — добавлять туда, а не в `.env`.
- **No regression на coverage matrix** — 16 contracts × 157 tools = 2 546 cases inviolable. Все backend изменения в Batch 3 — в `backend/src/api/routers/`, что не пересекается с tool catalog.
- **JSON структурированное логирование** для всех новых endpoints; без PII; с `request_id` correlation.

## 8. Прогресс (обновляется оркестратором)

- ⏳ T20: Global finding triage UI — Pending
- ⏳ T21: Bulk findings actions — Pending
- ✅ T22: Audit log viewer UI с chain verify — Completed (84 vitest cases в 6 файлах; suite 297/297; ESLint+tsc clean)
- ✅ T23: SARIF / JUnit toggle UI — Completed (commit `dc7b256`; 24 tests; suite 123/123)
- ✅ T24: Backend cross-tenant finding query API — Completed (commits `1e002e58` + `9678a86`; 47 tests)
- ✅ T25: Backend chain integrity verify API — Completed (commits `a35a6b41` + `e4ab4e0`; 30 tests; deferred ISS-T25-001..005)
- ⏳ T26: Vitest ≥30 + axe-core CI gate — Pending
- ⏳ T27: Playwright E2E ≥10 scenarios — Pending

**Всего:** 4 / 8 completed.

## 9. Открытые вопросы / blockers (для пользователя перед стартом)

1. **`super-admin` cross-tenant SQL strategy:** использовать `set_session_tenant(None)` для bypass RLS, или явный named view `v_admin_findings_global` через DBA-controlled grant? Рекомендация: первый вариант (consistent с существующим bulk-ops паттерном), но требует подтверждения, что RLS политика на `findings` поддерживает `tenant_id IS NULL` session bypass для admin role. **Action:** worker T24 уточнит в reading фазе и зафиксирует в комментарии endpoint.
2. **Bulk `attach-to-CVE` source-of-truth:** валидация формата `CVE-YYYY-NNNNN+` или lookup в локальной таблице `kev_entries` (NVD/KEV ingest)? Рекомендация: формат-валидация только в T21 (M-size); CVE existence check — следующий цикл (Batch 6).
3. **Axe-core gate severity:** initially advisory (`required=false`) или fail-on-violations? Рекомендация: advisory сейчас, promote-to-required после 2-х недель stable runs (документировать в operator runbook). Согласовано с T07/T08 advisory pattern.
4. **E2E backend dependency:** Playwright tests против real backend через `webServer` (как `admin-console.spec.ts`) или mock layer? Рекомендация: **real backend** — sustained pattern; mock — out of scope.

Если ответов нет до старта — будут приняты defaults (Recommendation выше).

## 10. Skills consulted

- [`task-management/SKILL.md`](../../../.cursor/skills/task-management/SKILL.md) — workspace structure, file formats, Mode B (file-backed orchestration с roadmap)
- [`orchestration/SKILL.md`](../../../.cursor/skills/orchestration/SKILL.md) — sequential per-task lifecycle, max 10 tasks/cycle, retry logic
- [`architecture-principles/SKILL.md`](../../../.cursor/skills/architecture-principles/SKILL.md) — SOLID для нового `admin_findings.py`, layered separation backend/frontend
- [`code-quality-standards/SKILL.md`](../../../.cursor/skills/code-quality-standards/SKILL.md) — DRY (переиспользовать `_audit_logs_filtered_select`, `require_admin`, `_operator_subject_dep`)
- [`security-guidelines/SKILL.md`](../../../.cursor/skills/security-guidelines/SKILL.md) — RBAC, parameterized SQL, audit emit, no PII в logs

---

**Maintained by:** planner agent (Cursor / Claude Opus 4.7) — auto-update on each task completion via workspace `progress.json` + `tasks.json`.
