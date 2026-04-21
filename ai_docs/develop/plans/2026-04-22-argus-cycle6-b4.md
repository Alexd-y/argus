# План: ARGUS Cycle 6 — Batch 4 (Operations UI: Kill-switch + Schedules, ARG-052 + ARG-056)

**Создан:** 2026-04-22
**Оркестрация:** `orch-2026-04-22-argus-cycle6-b4`
**Workspace:** `.cursor/workspace/active/orch-2026-04-22-argus-cycle6-b4/`
**Roadmap (источник истины):** [`Backlog/dev1_finalization_roadmap.md`](../../../Backlog/dev1_finalization_roadmap.md) §Batch 4
**Backlog (canonical spec):** [`Backlog/dev1_.md`](../../../Backlog/dev1_.md) §8 Policy Engine (`kill_switch`, `maintenance_window`) + §18 Critical guardrails (global kill-switch)
**Carry-over:** [`ai_docs/develop/issues/ISS-cycle6-batch3-carry-over.md`](../issues/ISS-cycle6-batch3-carry-over.md)
**Предыдущая оркестрация:** `orch-2026-04-21-15-30-argus-cycle6-b3` (Batch 3 — Triage + Audit)
**Предыдущий отчёт:** [`ai_docs/develop/reports/2026-04-21-cycle6-batch3-implementation.md`](../reports/2026-04-21-cycle6-batch3-implementation.md)
**Статус:** 🟢 Ready
**Всего задач:** 9 (T28–T36) — в пределах cap=10
**Ожидаемая wall-time:** ~4 дня при 2-worker parallelism (foundation wave может быть параллельным)

---

## TL;DR

Batch 4 закрывает **operator-side emergency-stop UI** (`ARG-052`: per-scan / per-tenant / global kill-switch + audit trail) и **scheduled-scan management** (`ARG-056`: visual cron builder + maintenance windows + redbeat-driven dynamic loader). 9 атомарных задач (T28–T36), 1 новая Alembic-миграция (`026_scan_schedules.py`, **не 024 — занято**), 2 новые backend-зависимости (`celery-redbeat`, `croniter`), 1 новая frontend-зависимость (`react-js-cron`). Архитектура переиспользует все паттерны Batch 3: `"use server"` actions, `getServerAdminSession()`, `callAdminBackendJson`, closed-taxonomy errors, mock backend для Playwright. Этот batch разблокирует Batch 5 (Webhook DLQ UI) поверх audit-схемы emergency events и Batch 6 (HPA autoscaling) поверх scheduled-scan metrics.

---

## 1. Контекст

### Что закрывает Batch 4

**ARG-052 — Kill-switch UI** (T28–T31): впервые даёт оператору возможность **остановить running scan, throttle тенант, или global stop_all** через UI, а не только через `redis-cli SET argus:emergency:* 1`. Сейчас в продакшене kill-switch упоминается в `Backlog/dev1_.md` §8 (`kill_switch: tenant admin может остановить все scans одним вызовом`) и §18 (`global kill-switch`), но реализация — только в зачаточном виде (есть `POST /scans/{id}/cancel` per-scan, есть `POST /admin/scans/bulk-cancel` per-tenant, но **нет** `policy/kill_switch.py`, **нет** Redis-flag-store, **нет** PolicyEngine consultation, **нет** UI). Этот batch даёт полную операторскую поверхность.

**ARG-056 — Scheduled scans** (T32–T36): впервые даёт оператору возможность **планировать сканы по cron** через визуальный UI, с maintenance windows и Run Now override. Сейчас Celery beat использует **статический** `BEAT_SCHEDULE` dict (`backend/src/celery/beat_schedule.py`) для EPSS / KEV refresh — нельзя добавить per-tenant scan schedule без перезапуска. Этот batch заменяет статику на dynamic loader (`celery-redbeat`) с CRUD endpoints + visual cron builder.

### Что _не_ закрывает Batch 4

- **Webhook DLQ UI** (T37–T41) — Batch 5
- **Sigstore Kyverno admission policy** (T42–T45) — Batch 5
- **PDF/A archival** (T46–T48) — Batch 6
- **HPA autoscaling** (T49–T51) — Batch 6
- **JWT/session-bound admin auth** (`ISS-T20-003`) — production-gate, deferred to Cycle 7 / pre-launch (Batch 4 продолжает использовать cookie shim из Batch 3)
- **Design token `--accent-high-contrast`** (`ISS-T26-001`) — quick fix, можно сделать в polish-PR между batches; в этот batch не включаем чтобы не размыть scope

### Зависимости Batch 4 от Batch 3 (всё ✅ shipped)

- `getServerAdminSession()` resolver — переиспользуется во всех 4 frontend задачах
- `callAdminBackendJson` helper — переиспользуется
- `AdminLayoutClient.tsx` NAV pattern — расширяется на `/admin/operations` и `/admin/schedules`
- `AdminRouteGuard` с `minimumRole` prop — переиспользуется (super-admin для T30)
- Mock backend `Frontend/tests/e2e/fixtures/admin-backend-mock.ts` (T26+T27) — расширяется новыми endpoints
- `axe-core` Playwright config (T26) — расширяется новыми routes
- `_operator_subject_dep` (admin_bulk_ops.py) — переиспользуется для audit emit
- `_audit_logs_filtered_select` + `_redact_audit_details` (admin.py) — переиспользуются для T30 audit trail
- `AuditLog` ORM + hash chain — переиспользуется для emergency event emit

---

## 2. Сводка верификации состояния (что подтверждено на диске)

### ✅ Подтверждённые факты

| Проверка | Результат |
|----------|-----------|
| Batch 3 commits в `git log` | ✅ Latest = `42a742a` (cycle6-b3 docs); 11 commits T20–T27 присутствуют |
| Frontend test baseline | ✅ 354 vitest + 7 a11y E2E + 11 functional E2E (per Batch 3 report) |
| Existing admin routers | ✅ `admin.py`, `admin_scans.py`, `admin_findings.py`, `admin_audit_chain.py`, `admin_bulk_ops.py` |
| Canonical actions.ts pattern | ✅ `Frontend/src/app/admin/findings/actions.ts` + `Frontend/src/app/admin/audit-logs/actions.ts` |
| Existing per-scan cancel | ✅ `POST /scans/{scan_id}/cancel` (`backend/src/api/routers/scans.py:327`) — kill-switch reuses this primitive |
| Existing per-tenant bulk-cancel | ✅ `POST /admin/scans/bulk-cancel` (`backend/src/api/routers/admin_bulk_ops.py:50`) — global stop_all reuses this |
| Celery beat infra | ✅ `backend/src/celery_app.py` + `backend/src/celery/beat_schedule.py` + `apply_beat_schedule()` integration point |
| Celery Redis broker | ✅ `celery[redis]>=5.3.0` в `backend/requirements.txt:12` |
| Mock backend для E2E | ✅ `Frontend/tests/e2e/fixtures/admin-backend-mock.ts` (722 lines, реальный HTTP listener на 127.0.0.1) |
| Audit hash chain | ✅ `backend/src/policy/audit.py::verify_audit_log_chain` + `GENESIS_HASH` |

### ⚠️ DEVIATIONS FROM ROADMAP (action required)

| # | Deviation | Impact | Resolution |
|---|-----------|--------|------------|
| **D-1** | Roadmap says "**Alembic 024**_scan_schedules.py", но `024_tenant_exports_sarif_junit.py` (T04, Batch 1) и `025_tenant_limits_overrides.py` (T13 backend, Batch 2) **уже на диске**. | T32 не может использовать revision 024. | **T32 использует revision `026`, down_revision `025`**. File: `026_scan_schedules.py`. |
| **D-2** | `celery-redbeat` отсутствует в `backend/requirements.txt`. | T33 не может работать без redbeat. | **T33 commit добавляет** `celery-redbeat>=2.2.0` (стабильная мажорная); SCA gate (`safety` / `pip-audit` advisory) должен пройти. |
| **D-3** | `croniter` отсутствует в `backend/requirements.txt`. | T34 не может валидировать cron expressions. | **T34 commit добавляет** `croniter>=2.0.5`; SCA gate должен пройти. |
| **D-4** | Roadmap не упоминает frontend-зависимость для visual cron builder. | T35 нужна accessible cron-builder библиотека. | **T35 commit добавляет** `react-js-cron@^5.x` (актуальный maintained fork с a11y support); fallback — raw expression text input + cron_parser preview через server action. |
| **D-5** | `backend/src/policy/kill_switch.py` отсутствует (упоминается только косметически в `Backlog/dev1_.md` §8). | T31 — greenfield. | **T31 создаёт `KillSwitchService` с нуля** в `backend/src/policy/kill_switch.py`; PolicyEngine integration — отдельный hook в существующий `backend/src/policy/policy_engine.py`. |
| **D-6** | Нет partial Batch 4 кода (kill-switch / emergency / scan_schedules / redbeat / cron) в src trees — clean slate. | Никакого waste / re-do. | Зафиксировано; никаких subtasks не пропускаем. |

### Latest Alembic migration on disk

```
backend/alembic/versions/
  ...
  023_epss_kev_tables.py         (Batch 1, ARG-044)
  024_tenant_exports_sarif_junit.py  (Batch 1 T04, ARG-051a precursor)
  025_tenant_limits_overrides.py     (Batch 2 T13 backend, ARG-051a)
  → 026_scan_schedules.py         ← THIS BATCH (T32)
```

### Existing Frontend admin routes (after Batch 3)

```
/admin                  → page.tsx (dashboard)
/admin/tenants          → page.tsx + TenantsAdminClient.tsx
/admin/scans            → page.tsx + AdminScansClient.tsx
/admin/findings         → page.tsx + AdminFindingsClient.tsx (T20)
/admin/audit-logs       → page.tsx + AdminAuditLogsClient.tsx (T22)
/admin/llm              → page.tsx + AdminLlmClient.tsx
/admin/system           → page.tsx (placeholder, replaced by /admin/operations in T28+)
/admin/forbidden        → forbidden RBAC fallback
```

**This batch adds:**

```
/admin/operations       → page.tsx + tabs:
    - Per-scan kill-switch (T28, integrated into scans table action menu)
    - Per-tenant emergency throttle (T29, PerTenantThrottleClient)
    - Global kill-switch + audit trail (T30, GlobalKillSwitchClient + EmergencyAuditTrail, super-admin only)
/admin/schedules        → page.tsx + AdminSchedulesClient.tsx (T35)
```

`AdminLayoutClient.tsx` NAV получает 2 новых entry: `Operations` и `Schedules` (T35 commit включает NAV diff).

---

## 3. Задачи

| ID | Title | Size | Wave | Deps | Files (est.) | Acceptance criteria summary | Status |
|----|-------|------|------|------|--------------|----------------------------|--------|
| **T31** | Backend `POST /admin/system/emergency/{stop_all,resume_all,throttle}` API | M | 1 | — | ~7 | Endpoints + `KillSwitchService` (Redis flags) + PolicyEngine hook; RBAC matrix (super-admin для stop_all, admin own tenant + super-admin для throttle); audit emit; ≥26 backend tests | ⏳ Pending |
| **T32** | Alembic migration `026_scan_schedules.py` (table + RLS) | S | 1 | — | ~3 | revision=026 (NOT 024); table `scan_schedules` с tenant FK + cron + maintenance window + last/next run + RLS policy `tenant_isolation`; upgrade/downgrade/upgrade idempotent | ⏳ Pending |
| **T34** | `src.scheduling.cron_parser` (croniter) + maintenance window logic + tests | M | 1 | — | ~4 | `validate_cron`, `next_fire_time`, `is_in_maintenance_window`, `normalize_to_utc`; reject expressions firing more often than every 5 min; ≥20 unit tests; 100% branch coverage | ⏳ Pending |
| **T28** | Per-scan kill-switch UI (double-confirmation typed scan ID match) | S | 2 | T31 | ~5 | Per-row "Kill scan" в `/admin/scans` → modal с typed scan-ID match (paste-disabled) → server-action POST `/scans/{id}/cancel`; admin/super-admin only; a11y focus trap + Esc; ≥6 vitest cases | ⏳ Pending |
| **T29** | Per-tenant emergency throttle UI (countdown timer, audit emit) | M | 2 | T31 | ~7 | Tenant + duration (15m/1h/4h/24h) + reason text → POST `/admin/system/emergency/throttle`; countdown timer + manual override; admin (own tenant) + super-admin (any tenant) only; ≥10 vitest cases | ⏳ Pending |
| **T30** | Global kill-switch UI (super-admin) + audit trail viewer | M | 2 | T31 | ~7 | Super-admin only; typed phrase "STOP ALL SCANS" (paste-disabled) → POST `stop_all`; resume button → POST `resume_all`; audit trail таблица фильтрованная по `event_type='emergency.*'`; ≥12 vitest cases | ⏳ Pending |
| **T33** | Backend `scan_schedules` CRUD endpoints + redbeat dynamic loader | L | 3 | T32, T34 | ~9 | GET/POST/PATCH/DELETE `/admin/scan-schedules` + RBAC + `/run-now` override; `redbeat_loader.sync_from_db()` reconciles RedBeatScheduler atomically; idempotency on `(tenant_id, name)`; ≥21 backend tests | ⏳ Pending |
| **T35** | Frontend scheduled scan UI (table + visual cron builder) | M | 4 | T33 | ~9 | `/admin/schedules` table + `ScheduleEditorDialog` с `react-js-cron` builder + raw escape hatch + maintenance window builder + cron preview ("Next 3 fires at: ...") + Run Now с double-confirm; ≥12 vitest; axe-core 0 violations | ⏳ Pending |
| **T36** | E2E: schedule trigger + maintenance window blocking + Run Now override + emergency stop | S | 5 | T28, T29, T30, T35 | ~4 | ≥10 functional Playwright scenarios (kill, throttle, stop_all, schedule CRUD, run-now, maintenance window blocking); RBAC matrix per role × per route; axe-core extension; reuses T26/T27 mock backend; runs in CI | ⏳ Pending |

**Итого:** 9 задач • ~55 файлов изменено/создано • ~4 дня wall-time при 2-worker parallelism.

---

## 4. Per-task детали

### T31 — Backend emergency API + KillSwitchService

**Goal:** Дать операторам programmatic kill-switch на 3 уровнях (scan / tenant / global), с Redis-flag-based блокировкой будущих ToolAdapter dispatches и полным audit trail.

**Backend / Frontend split:** 100% backend (no UI in this task; UIs T28/T29/T30 consume).

**Backend contract sketch:**

```python
# backend/src/api/routers/admin_emergency.py — NEW

@router.post("/system/emergency/stop_all", response_model=EmergencyStopAllResponse,
             status_code=status.HTTP_202_ACCEPTED)
async def emergency_stop_all(
    body: EmergencyStopAllRequest,    # {reason: str ≥10 chars, confirmation_phrase: "STOP ALL SCANS"}
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),               # reused from admin_findings.py
    operator_subject: str = Depends(_operator_subject_dep),
) -> EmergencyStopAllResponse:
    # RBAC: super-admin only (admin/operator → 403)
    # 1. Set Redis flag argus:emergency:global with reason + operator + ts (no TTL until resume)
    # 2. Cross-tenant fanout: for each tenant, call existing bulk-cancel internal helper
    # 3. Audit emit: AuditLog row event_type="emergency.stop_all", details={cancelled_count, reason, ts}
    # 4. Return {status: "stopped", cancelled_count, audit_id}

@router.post("/system/emergency/resume_all", response_model=EmergencyResumeResponse)
async def emergency_resume_all(
    body: EmergencyResumeRequest,     # {reason: str ≥10 chars}
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    operator_subject: str = Depends(_operator_subject_dep),
) -> EmergencyResumeResponse:
    # RBAC: super-admin only
    # Clear Redis flag, audit emit event_type="emergency.resume_all"

@router.post("/system/emergency/throttle", response_model=EmergencyThrottleResponse)
async def emergency_throttle(
    body: EmergencyThrottleRequest,   # {tenant_id: UUID, duration_minutes: 15|60|240|1440, reason: str}
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
    operator_subject: str = Depends(_operator_subject_dep),
) -> EmergencyThrottleResponse:
    # RBAC: super-admin (any tenant) OR admin (must equal role_tenant)
    # Set Redis flag argus:emergency:tenant:{id} with TTL = duration_minutes*60
    # Audit emit event_type="emergency.throttle", details={tenant_id, duration_minutes, expires_at, reason}
```

```python
# backend/src/policy/kill_switch.py — NEW

class KillSwitchService:
    """Redis-backed global + per-tenant emergency flag store.
    
    Flag schema:
      - argus:emergency:global = JSON {reason, operator, ts}  (no TTL)
      - argus:emergency:tenant:{tenant_id} = JSON {reason, expires_at_iso, operator, ts}  (TTL)
    
    PolicyEngine MUST call is_blocked(tenant_id) before allowing ToolAdapter dispatch.
    """

    def __init__(self, redis_client: redis.Redis): ...

    def stop_all(self, *, reason: str, operator_subject: str) -> None: ...
    def resume_all(self, *, operator_subject: str) -> None: ...
    def throttle_tenant(self, tenant_id: str, *, duration_seconds: int, reason: str, operator_subject: str) -> None: ...
    def is_blocked(self, tenant_id: str) -> KillSwitchVerdict:  # (blocked: bool, reason_taxonomy: "global"|"tenant"|None, expires_at: datetime|None)
        ...
    def get_status(self) -> KillSwitchStatus:  # for /admin/system/emergency/status read endpoint (optional in this task)
        ...
```

**PolicyEngine hook:** add 1 line to `backend/src/policy/policy_engine.py::PolicyEngine.evaluate()`:

```python
verdict = kill_switch_service.is_blocked(tenant_id)
if verdict.blocked:
    return PolicyDecision(allow=False, reason=f"emergency:{verdict.reason_taxonomy}", ...)
```

**Acceptance criteria (≥6):**
- (a) `POST /admin/system/emergency/stop_all` — super-admin only; admin/operator → 403; missing `confirmation_phrase` → 400 с closed-taxonomy; sets Redis flag; cancels all non-terminal scans cross-tenant; emits exactly 1 `AuditLog` row с event_type `"emergency.stop_all"` + details JSONB; returns 202 + `{cancelled_count, audit_id}`.
- (b) `POST /admin/system/emergency/resume_all` — super-admin only; clears Redis flag; emits `"emergency.resume_all"` audit row; idempotent (calling twice → 200 second time, no DB error).
- (c) `POST /admin/system/emergency/throttle` — admin может throttle ТОЛЬКО `role_tenant`; super-admin может throttle любой; неизвестный tenant → 404; duration not in {15,60,240,1440} → 422; sets Redis flag с TTL; emits `"emergency.throttle"` audit row.
- (d) `KillSwitchService.is_blocked(tenant_id)` returns `KillSwitchVerdict.blocked=True` если: global flag set OR tenant flag set AND not expired.
- (e) `PolicyEngine.evaluate()` consults KillSwitchService первым — возвращает `PolicyDecision(allow=False, reason="emergency:global"|"emergency:tenant")` без дальнейшей оценки правил.
- (f) Все ошибки — closed-taxonomy strings (`"forbidden"`, `"validation_failed"`, `"emergency_already_active"`, etc.); никаких stack traces.

**Test minima:**
- Unit: 6 (`KillSwitchService` happy + edge: global blocks tenant; tenant flag expires; idempotent resume; PolicyEngine hook returns deny).
- Integration / API: 20 (RBAC matrix 3 endpoints × 3 roles + happy path stop_all → resume → throttle → re-throttle; closed-taxonomy errors; audit emit verification).
- E2E: 0 (covered in T36).
- **Total: 26+ backend tests.**

**Files to touch (estimated 7):**
- `backend/src/api/routers/admin_emergency.py` (NEW, ~250 LoC)
- `backend/src/policy/kill_switch.py` (NEW, ~180 LoC)
- `backend/src/api/schemas.py` (extend with 5 new request/response models)
- `backend/src/policy/policy_engine.py` (extend `evaluate()` with kill-switch hook, ~10 LoC)
- `backend/main.py` (1 line: `import src.api.routers.admin_emergency`)
- `backend/tests/api/admin/test_admin_emergency_stop_all.py` (NEW, ~10 cases)
- `backend/tests/api/admin/test_admin_emergency_throttle.py` (NEW, ~10 cases)
- `backend/tests/policy/test_kill_switch_service.py` (NEW, ~6 cases)

**Architectural notes:**
- Role/tenant resolution: reuse `_admin_role_dep` + `_admin_tenant_dep` from `admin_findings.py` (T24).
- Operator attribution: reuse `_operator_subject_dep` from `admin_bulk_ops.py` (T17).
- Audit emit pattern: reuse `_sorted_ids_fingerprint` + AuditLog construction from `admin_bulk_ops.py::admin_bulk_cancel_scans` (T17).
- Redis client: reuse `src.core.redis_client` (already exists per `health_dashboard`).
- Bulk-cancel internals: reuse logic from `admin_bulk_ops.py::admin_bulk_cancel_scans` but loop per-tenant for `stop_all`.

**Commit message:** `feat(admin-ops): emergency stop_all/resume_all/throttle API + KillSwitchService (T31)`

---

### T32 — Alembic migration 026_scan_schedules.py

**Goal:** Persistent storage для scheduled scans с RLS isolation.

**Backend / Frontend split:** 100% backend (DB layer).

**Migration sketch:**

```python
# backend/alembic/versions/026_scan_schedules.py — NEW

revision: str = "026"
down_revision: str | None = "025"
branch_labels: str | None = None
depends_on: str | None = None

def upgrade() -> None:
    op.create_table(
        "scan_schedules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("cron_expression", sa.String(64), nullable=False),
        sa.Column("target_url", sa.String(2048), nullable=False),
        sa.Column("scan_mode", sa.String(50), nullable=False, server_default="standard"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("maintenance_window_cron", sa.String(64), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "name", name="uq_scan_schedules_tenant_name"),
    )
    op.create_index("ix_scan_schedules_next_run_at", "scan_schedules", ["next_run_at"], unique=False)
    op.create_index("ix_scan_schedules_tenant_enabled", "scan_schedules", ["tenant_id", "enabled"], unique=False)
    
    # RLS: identical pattern to other tenant-scoped tables (see 003_backend_core_tables_rls.py)
    op.execute("ALTER TABLE scan_schedules ENABLE ROW LEVEL SECURITY")
    op.execute("""
        CREATE POLICY tenant_isolation ON scan_schedules
        USING (tenant_id::text = current_setting('app.current_tenant_id', true))
    """)

def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS tenant_isolation ON scan_schedules")
    op.drop_index("ix_scan_schedules_tenant_enabled", table_name="scan_schedules")
    op.drop_index("ix_scan_schedules_next_run_at", table_name="scan_schedules")
    op.drop_table("scan_schedules")
```

**Acceptance criteria (≥4):**
- (a) Revision string = `"026"`, down_revision = `"025"`; `alembic upgrade head` from clean DB succeeds; `alembic upgrade head && downgrade -1 && upgrade head` сохраняет схему.
- (b) Table создана с правильными типами; UNIQUE `(tenant_id, name)` enforced (создание дубликата → IntegrityError).
- (c) RLS policy `tenant_isolation` создан; cross-tenant SELECT с одного tenant context не видит rows другого tenant (`set_session_tenant` test).
- (d) Indexes `ix_scan_schedules_next_run_at` и `ix_scan_schedules_tenant_enabled` присутствуют (assert via `pg_indexes`).

**Test minima:**
- Migration: 4 (upgrade/downgrade idempotency, RLS isolation, unique constraint, FK cascade).
- ORM: integrated with T33 tests.
- **Total: 4 migration tests.**

**Files to touch (estimated 3):**
- `backend/alembic/versions/026_scan_schedules.py` (NEW)
- `backend/src/db/models.py` (extend — `class ScanSchedule(Base): ...` ORM model)
- `backend/tests/db/test_scan_schedules_migration.py` (NEW)

**Architectural notes:**
- RLS policy idiom: copy from `003_backend_core_tables_rls.py` (canonical).
- ORM model placement: append to `backend/src/db/models.py` near other tenant-scoped tables.
- `gen_random_uuid()` requires `pgcrypto` extension — already enabled per `001_initial_schema.py`.

**Commit message:** `feat(db): scan_schedules table + RLS (T32 migration 026)`

**⚠️ DEVIATION CALLOUT in commit body:** "Roadmap T32 names migration `024_scan_schedules.py`; revisions 024 (`tenant_exports_sarif_junit`) and 025 (`tenant_limits_overrides`) already on disk from Batches 1+2 — this migration uses revision `026` to maintain linear chain."

---

### T34 — src.scheduling.cron_parser

**Goal:** Closed-taxonomy cron expression validation, next-fire calculation, и maintenance-window membership check, с DOS guard и timezone safety.

**Backend / Frontend split:** 100% backend (utility module).

**Module sketch:**

```python
# backend/src/scheduling/cron_parser.py — NEW

from datetime import datetime, timezone
from typing import Literal
from croniter import croniter, CroniterBadCronError

CronErrorTaxonomy = Literal[
    "invalid_syntax",
    "too_many_fields",
    "frequency_too_high",
    "unknown_timezone",
]

class CronValidationError(Exception):
    def __init__(self, taxonomy: CronErrorTaxonomy, message: str = "") -> None: ...

class ParsedCron:
    expression: str
    timezone_name: str
    next_fire_after: callable  # (after: datetime) -> datetime, UTC

MIN_INTERVAL_MINUTES: int = 5
MAX_FIELDS: int = 5  # standard 5-field cron only (no second-level)

def validate_cron(expression: str, *, max_freq_minutes: int = MIN_INTERVAL_MINUTES) -> ParsedCron:
    """Validate a 5-field cron expression. Raise CronValidationError on failure."""
    fields = expression.strip().split()
    if len(fields) > MAX_FIELDS:
        raise CronValidationError("too_many_fields")
    try:
        c = croniter(expression, datetime.now(timezone.utc))
    except (CroniterBadCronError, ValueError, KeyError):
        raise CronValidationError("invalid_syntax")
    # Frequency guard: compute 2 next fires; reject if delta < max_freq_minutes
    n1 = c.get_next(datetime)
    n2 = c.get_next(datetime)
    if (n2 - n1).total_seconds() < max_freq_minutes * 60:
        raise CronValidationError("frequency_too_high")
    return ParsedCron(...)

def next_fire_time(expression: str, after: datetime, *, tz: str = "UTC") -> datetime:
    """Compute next fire after `after`. Always returns UTC-normalized."""
    ...

def is_in_maintenance_window(window_cron: str, at: datetime, *, tz: str = "UTC") -> bool:
    """Check if `at` is within a maintenance window defined by cron expression
    (window = current cron-tick start to next-cron-tick start)."""
    ...

def normalize_to_utc(dt: datetime, source_tz: str) -> datetime: ...
```

**Acceptance criteria (≥4):**
- (a) `validate_cron("*/5 * * * *")` → ParsedCron OK; `validate_cron("*/4 * * * *")` → `CronValidationError("frequency_too_high")`; `validate_cron("not a cron")` → `"invalid_syntax"`; `validate_cron("* * * * * *")` → `"too_many_fields"`.
- (b) `next_fire_time("0 4 * * *", at=datetime(2026,4,22,3,0,tzinfo=UTC), tz="UTC")` returns `datetime(2026,4,22,4,0,tzinfo=UTC)`; same expr in `tz="America/New_York"` returns appropriate UTC offset.
- (c) `is_in_maintenance_window("0 22 * * *", at=datetime(2026,4,22,22,30,tzinfo=UTC))` → True (within hour starting at 22:00); at 21:59 → False; at 23:00 → False (next day's window starts).
- (d) DST transition test: `next_fire_time` correctly handles spring-forward / fall-back в `America/New_York` (no double-fire, no skip).
- (e) Closed-taxonomy errors only — Pydantic / FastAPI handlers map to HTTP 422 без stack traces.

**Test minima:**
- Unit: 20 (valid + invalid expressions × edge cases × DST × leap year × frequency guard × timezone normalization × Feb 29 × end-of-month).
- 100% branch coverage on `cron_parser.py` (small module, achievable).
- **Total: 20 unit tests.**

**Files to touch (estimated 4):**
- `backend/requirements.txt` (add `croniter>=2.0.5`)
- `backend/src/scheduling/__init__.py` (NEW empty)
- `backend/src/scheduling/cron_parser.py` (NEW, ~150 LoC)
- `backend/tests/scheduling/test_cron_parser.py` (NEW, ~250 LoC)

**Architectural notes:**
- `croniter>=2.0.5` is the active maintained fork (last release Q1 2026); no known CVEs per OSV.
- 5-field cron only (no seconds, no year-field) — keeps surface small and aligned with operator mental model.
- All datetimes returned in UTC; tz handling internal — UI never sees raw local times.
- This module is a hard prerequisite for T33 (CRUD validates via this) and T35 (UI preview hits server action that calls this).

**Commit message:** `feat(scheduling): cron_parser with maintenance-window logic + DOS guard (T34)`

---

### T28 — Per-scan kill-switch UI

**Goal:** Operator может убить running scan через UI, защищённый double-confirmation (typed scan-ID match с paste-disabled).

**Backend / Frontend split:** 100% frontend. Backend reuses existing `POST /scans/{id}/cancel` (`backend/src/api/routers/scans.py:327`) — no new endpoint needed.

**Frontend component map:**

```
/admin/scans (existing AdminScansClient.tsx)
  └─ extend SCANS_TABLE row to include "Kill scan" action button (visible if scan.status not in {completed, failed, cancelled})
        └─ opens PerScanKillSwitchDialog.tsx (NEW component)
              └─ fields: typed_scan_id (paste disabled, must equal scan.id), reason text
              └─ button "Kill scan" disabled until typed_scan_id === scan.id
              └─ on submit → server action killScanAction(scan_id, reason)
                    └─ server-action POSTs /api/v1/scans/{scan_id}/cancel
                    └─ on success → optimistic row update to status="cancelled"; toast
                    └─ on error → closed-taxonomy mapping
```

**Acceptance criteria (≥4):**
- (a) Per-row "Kill scan" button присутствует ТОЛЬКО для non-terminal scans (status not in {completed, failed, cancelled}); button hidden for terminal scans.
- (b) Modal требует exact match scan ID типизированный (НЕ paste — `onPaste={e => e.preventDefault()}` + `onDrop={e => e.preventDefault()}`); reason text mandatory ≥10 chars.
- (c) RBAC: button скрыт для `operator` role; для `admin` — visible только для own tenant scans; для `super-admin` — visible для всех.
- (d) Server-action `killScanAction(scan_id, reason)` использует `getServerAdminSession()` + `callAdminBackendJson` → POST `/scans/{scan_id}/cancel`; никакого browser-side fetch.
- (e) Optimistic update — row status flips на "cancelled" immediately; on error → revert + toast с closed-taxonomy code.
- (f) A11y: focus trap в modal (Tab/Shift-Tab cycle in dialog); Esc closes; auto-focus на typed_scan_id input при open; aria-label на all interactive elements.
- (g) Vitest ≥6: dialog open/close, typed match enables button, paste blocked, RBAC mask per role × per status, success path, failure path.

**Test minima:**
- Unit (vitest): 6.
- Integration: covered by E2E in T36.
- **Total: 6 vitest cases.**

**Files to touch (estimated 5):**
- `Frontend/src/app/admin/scans/AdminScansClient.tsx` (extend — add per-row "Kill scan" button + state)
- `Frontend/src/components/admin/operations/PerScanKillSwitchDialog.tsx` (NEW)
- `Frontend/src/app/admin/scans/actions.ts` (extend — `killScanAction(scan_id, reason)` server action)
- `Frontend/src/app/admin/scans/AdminScansClient.test.tsx` (extend — ≥6 new vitest cases)
- (Optional) `Frontend/src/lib/adminScans.ts` (extend Zod schemas if needed)

**Architectural notes:**
- Reuses existing scan list page — no new route needed (operator-friendly: kill is contextual to scan).
- Reuses existing backend `POST /scans/{id}/cancel` — already emits scan_event "cancelled".
- Audit emit: existing `cancel_scan` does NOT emit AuditLog row (only `ScanEvent`); for parity with bulk-cancel, **add a single AuditLog emit inside the server action** OR **request adding emit to backend cancel_scan** (preferred — backend audit emit). For T28 scope: the server action posts a separate `POST /admin/audit-logs/emit` if such endpoint exists, OR documents this as a Phase-2 issue (`ISS-T28-001` filed during execution if not addressed). Recommended: backend `cancel_scan` extension is OUT OF SCOPE for T28 — keep T28 frontend-only and file ISS for backend audit-emit Phase 2.

**Commit message:** `feat(admin-ops): per-scan kill-switch UI with double-confirmation (T28)`

---

### T29 — Per-tenant emergency throttle UI

**Goal:** Operator throttles один tenant на заданное время с countdown timer; auto-resume + manual override.

**Backend / Frontend split:** 100% frontend (T31 backend already done).

**Frontend component map:**

```
/admin/operations (page.tsx, NEW route — host для operations UIs)
  └─ tabs: [Per-scan, Per-tenant throttle, Global stop]
        └─ Per-tenant throttle tab:
              └─ PerTenantThrottleClient.tsx (NEW)
                    ├─ TenantSelector (super-admin: any; admin: bound to session tenant, disabled select)
                    ├─ DurationSelector (15m / 1h / 4h / 24h)
                    ├─ ReasonInput (≥10 chars)
                    ├─ "Throttle tenant" button → opens PerTenantThrottleDialog.tsx (typed phrase confirm)
                    └─ Active throttles section:
                          └─ for each active throttle: TenantName + CountdownTimer (mm:ss) + "Resume now" button
                                └─ CountdownTimer.tsx (NEW reusable: setInterval 1s, auto-clears on expiry)
                                └─ "Resume now" → callsthrottle endpoint with duration=0 (or dedicated resume-tenant action)
```

**Acceptance criteria (≥4):**
- (a) `/admin/operations` route создаётся; tabs UI с aria-roles "tablist" / "tab" / "tabpanel".
- (b) Tenant selector: для `admin` — locked на session tenant; для `super-admin` — dropdown of all tenants (via existing `/admin/tenants` query).
- (c) Duration selector — radio buttons {15m, 1h, 4h, 24h}; reason text ≥10 chars; submit button disabled пока validation fails.
- (d) Throttle dialog: typed phrase "THROTTLE {tenant-name}" required (paste-disabled).
- (e) Active throttles list — fetched from `GET /admin/system/emergency/status` (если есть) или из `GET /admin/audit-logs?event_type=emergency.throttle&since=` (последние 24h).
- (f) CountdownTimer renders mm:ss until `expires_at`; auto-removes throttle from list on expiry; manual "Resume now" клик → server action.
- (g) Closed-taxonomy errors; никаких browser-side fetch.
- (h) Vitest ≥10: tenant selector RBAC, duration validation, reason validation, dialog confirm, countdown render, countdown expiry, resume action, network error handling, RBAC denial, optimistic add to list.

**Test minima:**
- Unit (vitest): 10.
- Integration: covered by E2E in T36.
- **Total: 10 vitest cases.**

**Files to touch (estimated 7):**
- `Frontend/src/app/admin/operations/page.tsx` (NEW — operations route entry, tabs)
- `Frontend/src/app/admin/operations/PerTenantThrottleClient.tsx` (NEW)
- `Frontend/src/components/admin/operations/PerTenantThrottleDialog.tsx` (NEW)
- `Frontend/src/components/admin/operations/CountdownTimer.tsx` (NEW)
- `Frontend/src/app/admin/operations/actions.ts` (NEW — `throttleTenantAction`, `resumeTenantAction`, `listActiveThrottlesAction`)
- `Frontend/src/lib/adminOperations.ts` (NEW — Zod schemas + closed-taxonomy errors)
- `Frontend/src/app/admin/operations/PerTenantThrottleClient.test.tsx` (NEW)

**Architectural notes:**
- `actions.ts` создаётся с нуля для `/admin/operations` route — не extend от существующих файлов.
- `getServerAdminSession()` reused; `callAdminBackendJson` reused.
- CountdownTimer как plain React component с `useEffect(setInterval)` — без external libs.
- Active throttle list: либо backend exposes `GET /admin/system/emergency/status` (T31 optional addition), либо frontend queries audit log filtered. Recommended: T31 includes lightweight `GET /status` endpoint returning current global flag + active tenant throttles.

**Commit message:** `feat(admin-ops): per-tenant emergency throttle UI with countdown (T29)`

---

### T30 — Global kill-switch UI + audit trail

**Goal:** Super-admin может остановить ВСЕ scans cross-tenant с typed-phrase confirmation; видит recent emergency audit trail.

**Backend / Frontend split:** 100% frontend.

**Frontend component map:**

```
/admin/operations (extend page from T29)
  └─ Global Stop tab (super-admin only — operator/admin → tab disabled with tooltip "Super-admin only"):
        └─ GlobalKillSwitchClient.tsx (NEW)
              ├─ Status banner: "All systems normal" GREEN / "🚨 GLOBAL STOP ACTIVE since {ts} by {operator}" RED
              ├─ if normal: button "STOP ALL SCANS" (red, full-width, prominent)
              │     └─ opens GlobalKillSwitchDialog.tsx (NEW)
              │           ├─ Typed phrase input: "STOP ALL SCANS" (paste-disabled, case-sensitive)
              │           ├─ Reason text ≥10 chars
              │           ├─ Submit → server action stopAllAction
              │           └─ Renders cancelled_count in toast on success
              └─ if stopped: button "Resume all scans" (yellow)
                    └─ opens ResumeAllDialog (typed phrase "RESUME ALL SCANS")
                    └─ Submit → server action resumeAllAction
        └─ EmergencyAuditTrail.tsx (NEW — recent 50 emergency.* audit rows)
              ├─ filter event_type IN ('emergency.stop_all', 'emergency.resume_all', 'emergency.throttle')
              ├─ table: ts | event_type | operator_subject | tenant_id (if applicable) | reason | details
              └─ refetch every 30s + manual refresh button
```

**Acceptance criteria (≥4):**
- (a) Global Stop tab visible ВСЕМ rolls в navigation, но disabled с tooltip для admin/operator; click → no-op.
- (b) Server action `stopAllAction` уверенно валидирует session.role === "super-admin" перед вызовом backend (defence in depth — backend тоже валидирует).
- (c) Status banner real-time: polls `GET /admin/system/emergency/status` каждые 10 секунд; shows GREEN/RED state.
- (d) STOP dialog: typed phrase "STOP ALL SCANS" (paste-disabled, case-sensitive); reason ≥10 chars; submit button disabled до match.
- (e) On success: toast renders `cancelled_count`, banner flips to RED, audit trail refetches.
- (f) Audit trail таблица: фильтр event_type set('emergency.stop_all', 'emergency.resume_all', 'emergency.throttle'); shows operator_subject + reason; click row → expand details JSONB.
- (g) Vitest ≥12: RBAC mask all 3 roles, banner GREEN→RED transition, dialog typed phrase, dialog reason validation, dialog paste blocked, success path, failure path, audit trail render, audit row expand, refetch on stop, resume flow, status polling.

**Test minima:**
- Unit (vitest): 12.
- Integration: covered by E2E in T36.
- **Total: 12 vitest cases.**

**Files to touch (estimated 7):**
- `Frontend/src/app/admin/operations/GlobalKillSwitchClient.tsx` (NEW)
- `Frontend/src/components/admin/operations/GlobalKillSwitchDialog.tsx` (NEW)
- `Frontend/src/components/admin/operations/ResumeAllDialog.tsx` (NEW — небольшой, может быть в том же файле)
- `Frontend/src/components/admin/operations/EmergencyAuditTrail.tsx` (NEW)
- `Frontend/src/app/admin/operations/actions.ts` (extend from T29 — `stopAllAction`, `resumeAllAction`, `listEmergencyAuditAction`, `getEmergencyStatusAction`)
- `Frontend/src/lib/adminOperations.ts` (extend from T29)
- `Frontend/src/app/admin/operations/GlobalKillSwitchClient.test.tsx` (NEW)
- `Frontend/src/components/admin/operations/EmergencyAuditTrail.test.tsx` (NEW)

**Architectural notes:**
- Reuses `EmergencyAuditTrail` — это slimmed audit log viewer аналогичен `AdminAuditLogsClient` (T22), но с pre-set фильтром.
- Status polling — `setInterval(10_000)` в `useEffect` cleanup на unmount.
- "Run Now" override (per roadmap T36 mention) is for **scheduled scans** в T35, не здесь.
- ⚠️ This is the most security-sensitive UI in Batch 4 — defence in depth: server-side RBAC check + backend RBAC check + typed phrase + reason text.

**Commit message:** `feat(admin-ops): global kill-switch UI with super-admin gating + emergency audit trail (T30)`

---

### T33 — scan_schedules CRUD endpoints + redbeat dynamic loader

**Goal:** Backend CRUD для scan_schedules с RBAC + redbeat loader, который синкает DB-записи в `RedBeatScheduler` так, что Celery beat подхватывает изменения без перезапуска.

**Backend / Frontend split:** 100% backend.

**Backend contract sketch:**

```python
# backend/src/api/routers/admin_schedules.py — NEW

@router.get("/scan-schedules", response_model=ScanSchedulesListResponse)
async def list_scan_schedules(
    tenant_id: UUID | None = Query(None),
    enabled: bool | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
    _: None = Depends(require_admin),
) -> ScanSchedulesListResponse:
    # RBAC: super-admin → any; admin → MUST equal role_tenant; operator → 403

@router.post("/scan-schedules", response_model=ScanScheduleResponse, status_code=201)
async def create_scan_schedule(
    body: ScanScheduleCreateRequest,  # {tenant_id, name, cron_expression, target_url, scan_mode, maintenance_window_cron?}
    operator_subject: str = Depends(_operator_subject_dep),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
    _: None = Depends(require_admin),
) -> ScanScheduleResponse:
    # 1. RBAC: super-admin → any tenant; admin → tenant must equal role_tenant; operator → 403
    # 2. Validate cron_expression via cron_parser.validate_cron(max_freq_minutes=5)
    # 3. Validate maintenance_window_cron (if set) via cron_parser.validate_cron(max_freq_minutes=60)
    # 4. INSERT row (UNIQUE constraint on (tenant_id, name) — IntegrityError → 409)
    # 5. Compute next_run_at via cron_parser.next_fire_time
    # 6. Call redbeat_loader.sync_one(schedule_id) — atomic upsert into RedBeatScheduler
    # 7. Audit emit event_type="scan_schedule.created"

@router.patch("/scan-schedules/{schedule_id}", response_model=ScanScheduleResponse)
async def update_scan_schedule(...): ...
    # Same RBAC, validation, redbeat sync; audit "scan_schedule.updated"

@router.delete("/scan-schedules/{schedule_id}", status_code=204)
async def delete_scan_schedule(...): ...
    # RBAC; redbeat_loader.remove_one(schedule_id); audit "scan_schedule.deleted"

@router.post("/scan-schedules/{schedule_id}/run-now", response_model=ScanScheduleRunNowResponse, status_code=202)
async def run_now_scan_schedule(
    body: ScanScheduleRunNowRequest,  # {bypass_maintenance_window: bool, reason: str ≥10 chars}
    ...,
) -> ScanScheduleRunNowResponse:
    # RBAC: super-admin OR admin own tenant
    # If schedule.maintenance_window_cron AND cron_parser.is_in_maintenance_window(...) AND NOT bypass:
    #   return 409 + closed-taxonomy "in_maintenance_window"
    # Enqueue argus.scheduling.run_scheduled_scan(schedule_id) via Celery
    # Audit emit event_type="scan_schedule.run_now" + bypass_flag
```

```python
# backend/src/scheduling/redbeat_loader.py — NEW

from redbeat import RedBeatSchedulerEntry
from celery.schedules import crontab

def sync_one(schedule_id: str) -> None:
    """Atomically upsert one schedule into RedBeatScheduler. Idempotent."""
    row = SQL: SELECT * FROM scan_schedules WHERE id = schedule_id
    if not row.enabled:
        return remove_one(schedule_id)
    # parse cron → celery crontab schedule
    fields = row.cron_expression.split()
    schedule = crontab(minute=fields[0], hour=fields[1], day_of_month=fields[2], month_of_year=fields[3], day_of_week=fields[4])
    entry = RedBeatSchedulerEntry(
        name=f"argus.scheduling.scan.{schedule_id}",
        task="argus.scheduling.run_scheduled_scan",
        schedule=schedule,
        args=[schedule_id],
        app=app,
    )
    entry.save()

def remove_one(schedule_id: str) -> None: ...
def sync_all_from_db() -> None: ...  # called on Celery beat startup
```

```python
# backend/src/scheduling/scan_trigger.py — NEW

@app.task(name="argus.scheduling.run_scheduled_scan", queue="argus.scans")
def run_scheduled_scan(schedule_id: str, *, bypass_maintenance_window: bool = False) -> None:
    """Triggered by RedBeat. Checks maintenance window before launching scan."""
    row = SQL: SELECT * FROM scan_schedules WHERE id = schedule_id AND enabled = true
    if not row:
        return  # schedule deleted/disabled — no-op
    if row.maintenance_window_cron and not bypass_maintenance_window:
        if cron_parser.is_in_maintenance_window(row.maintenance_window_cron, datetime.utcnow()):
            structured_log("scan_schedule.skipped_maintenance_window", schedule_id=schedule_id)
            return
    # Enqueue actual scan via existing scan service
    # Update last_run_at, next_run_at
```

**Acceptance criteria (≥4):**
- (a) GET / POST / PATCH / DELETE `/admin/scan-schedules` — full CRUD; super-admin без `tenant_id` → cross-tenant view; admin/operator must specify own tenant; operator → 403 на write actions.
- (b) Cron validation via T34 cron_parser — невалидные expressions → HTTP 422 closed-taxonomy.
- (c) UNIQUE `(tenant_id, name)` enforced; duplicate → HTTP 409.
- (d) `redbeat_loader.sync_one` атомарен; create/update/delete schedule → RedBeatScheduler reflects change immediately.
- (e) `POST /run-now` без `bypass_maintenance_window=true` в maintenance window → HTTP 409 closed-taxonomy `"in_maintenance_window"`; с bypass=true → 202 + audit emit.
- (f) Celery task `argus.scheduling.run_scheduled_scan` — registered с queue `argus.scans`; on startup `sync_all_from_db()` загружает все enabled schedules в RedBeat.
- (g) Closed-taxonomy errors; никаких stack traces.
- (h) Audit emit per state change: `"scan_schedule.created"`, `"scan_schedule.updated"`, `"scan_schedule.deleted"`, `"scan_schedule.run_now"`.

**Test minima:**
- Unit / API: 15 (CRUD × RBAC matrix × validation × cron rejection × maintenance window blocking).
- Integration: 6 (redbeat_loader sync, deletion, idempotency, atomic update, sync_all_from_db on startup, run_scheduled_scan happy + maintenance skip).
- **Total: 21+ backend tests.**

**Files to touch (estimated 9):**
- `backend/requirements.txt` (add `celery-redbeat>=2.2.0`)
- `backend/src/api/routers/admin_schedules.py` (NEW, ~350 LoC)
- `backend/src/api/schemas.py` (extend — 5 new request/response models)
- `backend/src/scheduling/redbeat_loader.py` (NEW, ~150 LoC)
- `backend/src/scheduling/scan_trigger.py` (NEW, ~100 LoC)
- `backend/src/celery_app.py` (extend — `app.conf.beat_scheduler = "redbeat.RedBeatScheduler"`, `app.conf.redbeat_redis_url = settings.redis_url`, include `src.scheduling.scan_trigger`)
- `backend/main.py` (1 line: `import src.api.routers.admin_schedules`)
- `backend/tests/api/admin/test_admin_scan_schedules_crud.py` (NEW, ~15 cases)
- `backend/tests/scheduling/test_redbeat_loader.py` (NEW, ~6 cases mocking RedBeatScheduler — mock the redis interaction so tests don't require live Redis)

**Architectural notes:**
- RedBeat reads / writes its own Redis keys (`redbeat:*` namespace) — orthogonal to KillSwitchService (`argus:emergency:*`).
- `sync_all_from_db()` should be idempotent + tolerate Redis being unavailable at startup (graceful degradation: log warning, retry on next operator mutation).
- `argus.scheduling.run_scheduled_scan` queue routing уже covered: add to `task_routes` в `celery_app.py`.
- KillSwitchService consult: `run_scheduled_scan` MUST call `kill_switch_service.is_blocked(tenant_id)` first — если global stop active → no-op + audit emit `"scan_schedule.skipped_emergency_stop"`.
- T31 PolicyEngine integration covers ToolAdapter dispatches; this adds an extra check at the schedule-task level for explicit denial trail.

**Commit message:** `feat(scheduling): scan_schedules CRUD + redbeat dynamic loader (T33)`

---

### T35 — Frontend scheduled scan UI

**Goal:** Operator может управлять scan schedules через визуальный cron builder + maintenance window, с предпросмотром fire times и Run Now override.

**Backend / Frontend split:** 100% frontend.

**Frontend component map:**

```
/admin/schedules (NEW route)
  └─ page.tsx (server component, render AdminSchedulesClient)
        └─ AdminSchedulesClient.tsx (NEW client wrapper, React Query, cookies session check)
              ├─ "+ New schedule" button → opens ScheduleEditorDialog (mode="create")
              └─ SchedulesTable.tsx (NEW)
                    ├─ columns: Name | Tenant (super-admin) | Cron | Next run | Last run | Status | Actions
                    └─ row actions: Edit (opens dialog mode="edit") | Run now | Delete (confirm modal) | Toggle enabled

ScheduleEditorDialog.tsx (NEW)
  ├─ Name input
  ├─ Tenant selector (super-admin: any; admin: locked to session tenant)
  ├─ Target URL input
  ├─ Scan mode select (standard / deep)
  ├─ Cron expression: VisualCronBuilder (react-js-cron) + raw expression text input + toggle between
  ├─ Cron preview: "Next 3 fire times: ..." (server action returns from cron_parser.next_fire_time)
  ├─ Maintenance window (optional): VisualCronBuilder (same approach) + preview "Currently in window: yes/no"
  ├─ Enabled toggle
  └─ Submit → server action createScheduleAction / updateScheduleAction

RunNowDialog.tsx (small modal)
  ├─ "Bypass maintenance window?" checkbox
  ├─ Reason text ≥10 chars
  ├─ Confirm phrase typed: schedule.name (paste-disabled)
  └─ Submit → server action runNowScheduleAction
```

**Acceptance criteria (≥4):**
- (a) `/admin/schedules` route создан; AdminLayoutClient NAV получает entry "Schedules" + "Operations".
- (b) Schedules table renders все schedules с RBAC: admin видит только own tenant; super-admin — все (с tenant column).
- (c) ScheduleEditorDialog — visual cron builder работает (react-js-cron); raw escape hatch текстовое поле; cron preview показывает "Next 3 fires: ..." (server action calls `validate_cron` + `next_fire_time`).
- (d) Maintenance window поле — optional; отдельный visual cron builder с preview "Currently in window: yes/no" (server action calls `is_in_maintenance_window`).
- (e) Run Now dialog — typed phrase = schedule.name match; bypass_maintenance_window toggle; reason text ≥10 chars.
- (f) Toggle enabled directly в table row — server action updateScheduleAction({enabled}).
- (g) Closed-taxonomy errors через `Frontend/src/lib/adminSchedules.ts`.
- (h) `react-js-cron` rendered с aria attributes; axe-core 0 violations on `/admin/schedules`.
- (i) Vitest ≥12: table render, RBAC mask, create flow, edit flow, delete confirm, toggle enabled, run now с/без bypass, cron preview success, cron preview validation error, raw escape hatch, maintenance window builder, dialog focus trap.

**Test minima:**
- Unit (vitest): 12.
- A11y: covered by axe-core extension в T36.
- Integration: covered by E2E в T36.
- **Total: 12 vitest cases.**

**Files to touch (estimated 9):**
- `Frontend/package.json` (add `react-js-cron` and its peer deps)
- `Frontend/src/app/admin/schedules/page.tsx` (NEW)
- `Frontend/src/app/admin/schedules/AdminSchedulesClient.tsx` (NEW)
- `Frontend/src/components/admin/schedules/SchedulesTable.tsx` (NEW)
- `Frontend/src/components/admin/schedules/ScheduleEditorDialog.tsx` (NEW)
- `Frontend/src/components/admin/schedules/RunNowDialog.tsx` (NEW)
- `Frontend/src/app/admin/schedules/actions.ts` (NEW — listSchedulesAction, createScheduleAction, updateScheduleAction, deleteScheduleAction, runNowAction, previewCronAction)
- `Frontend/src/lib/adminSchedules.ts` (NEW — Zod schemas + closed-taxonomy errors)
- `Frontend/src/app/admin/AdminLayoutClient.tsx` (extend NAV: + "Operations" + "Schedules")
- `Frontend/src/app/admin/schedules/AdminSchedulesClient.test.tsx` (NEW)

**Architectural notes:**
- `react-js-cron@^5.x` — accessible visual cron builder (Apache 2.0 license, ~50KB gzipped, last release 2026-Q1, no known CVEs). If lib turns out to have a11y issues, fallback strategy: pure raw expression input + cron_parser preview (still meets acceptance criteria).
- `previewCronAction` server action — calls T34 `cron_parser.validate_cron` + `next_fire_time(n=3)`; returns `{valid: bool, error_taxonomy: string|null, next_fires: ISO[]}`.
- AdminLayoutClient NAV — split into 2 sub-groups visually: "Triage" (Tenants/Scans/Findings/Audit/LLM) + "Operations" (Operations/Schedules/System).

**Commit message:** `feat(admin-schedules): scheduled scan UI with visual cron builder (T35)`

---

### T36 — E2E: emergency UI + schedules + maintenance window

**Goal:** ≥10 functional E2E scenarios covering kill-switch + scheduled-scan flows; reuse Batch 3 mock backend infrastructure.

**Backend / Frontend split:** 100% frontend (test infra).

**E2E spec layout:**

```
Frontend/tests/e2e/admin-operations.spec.ts (NEW):
  1. admin role: "Kill scan" button visible for non-terminal scan; click → typed-ID dialog → submit → row flips to cancelled
  2. operator role: "Kill scan" button hidden everywhere
  3. admin role: throttle own tenant → countdown renders → "Resume now" works
  4. admin role: throttle different tenant → 403 / no UI affordance
  5. super-admin role: throttle any tenant works
  6. super-admin role: stop_all → typed phrase confirm → status banner flips RED → cancelled_count toast
  7. super-admin role: resume_all → banner flips GREEN
  8. admin role: Global Stop tab disabled with tooltip
  9. EmergencyAuditTrail renders rows after stop_all + throttle

Frontend/tests/e2e/admin-schedules.spec.ts (NEW):
  10. admin role: create schedule (visual cron) → row appears in table → next_run_at displayed
  11. admin role: edit schedule cron expression → preview updates → save → table reflects
  12. admin role: delete schedule with confirm → row gone
  13. admin role: toggle enabled inline → state persists on reload
  14. admin role: run-now (no bypass) for schedule в maintenance window → 409 toast
  15. admin role: run-now с bypass → 202 + audit emit visible
  16. super-admin role: cross-tenant view shows tenant column
  17. operator role: /admin/schedules → forbidden
  18. ScheduleEditorDialog raw cron escape hatch round-trips with visual builder

Frontend/tests/a11y/admin-axe.spec.ts (extend):
  - Add /admin/operations + /admin/schedules to axe-core scan list
  - Both routes: 0 critical / serious violations
```

**Acceptance criteria (≥4):**
- (a) ≥10 functional E2E scenarios across `admin-operations.spec.ts` + `admin-schedules.spec.ts`; всех проходят локально через `npm run test:e2e:functional`.
- (b) RBAC matrix coverage: 3 roles × emergency endpoints × schedules endpoints (denial path verified for at least 4 combinations).
- (c) Mock backend (`tests/e2e/fixtures/admin-backend-mock.ts`) extended с emergency endpoints (`stop_all`, `resume_all`, `throttle`, `status`) + schedules CRUD + run-now; mock honours `?_test_*=true` query params для drift-style negative tests (например, `?_test_in_maintenance=true` для testing 409 path).
- (d) `Frontend/tests/a11y/admin-axe.spec.ts` extended: `/admin/operations` + `/admin/schedules` get axe scans → 0 critical/serious violations.
- (e) E2E tests run в CI на existing `admin-e2e.yml` workflow без новых secrets / без нового docker stack.

**Test minima:**
- Functional E2E: 10+ scenarios.
- A11y E2E: +2 routes (extend existing 7).
- **Total: 10+ Playwright cases + 2 axe-core extensions.**

**Files to touch (estimated 4):**
- `Frontend/tests/e2e/fixtures/admin-backend-mock.ts` (extend significantly: new mock routes, ~200 LoC added)
- `Frontend/tests/e2e/admin-operations.spec.ts` (NEW, ~250 LoC)
- `Frontend/tests/e2e/admin-schedules.spec.ts` (NEW, ~300 LoC)
- `Frontend/tests/a11y/admin-axe.spec.ts` (extend — add 2 page paths)

**Architectural notes:**
- Mock backend extension is the largest file change в T36 — keeping all synthetic data в одном месте per Batch 3 precedent.
- Test-control query params (`?_test_in_maintenance=true`, `?_test_global_stop_active=true`) are mock-only — real FastAPI rejects unknown params per `admin_findings.py` design.
- `playwright.mock.config.ts` уже сконфигурирован — добавлять новый config НЕ нужно; просто add testMatch entries OR just rely on the regex match for `admin-(operations|schedules)\.spec\.ts$` (extend regex).

**Commit message:** `test(admin-ops): E2E coverage for emergency UI + schedules + maintenance window (T36)`

---

## 5. Зависимости / DAG

```text
Wave 1 (parallel — foundation, день 1):
  ├─ T31 (Backend emergency API + KillSwitchService)        ── блокирует T28, T29, T30
  ├─ T32 (Alembic migration 026_scan_schedules)             ── блокирует T33
  └─ T34 (cron_parser + maintenance window logic)           ── блокирует T33, T35 (preview)
        ↓
Wave 2 (parallel — kill-switch UIs, день 2):
  ├─ T28 (Per-scan kill UI)                                  ← зависит от T31 (audit emit), может работать паттерн-only без T31
  ├─ T29 (Per-tenant throttle UI)                            ← зависит от T31
  └─ T30 (Global kill UI + audit trail)                      ← зависит от T31
        ↓
Wave 3 (sequential — schedules backend, день 3):
  └─ T33 (scan_schedules CRUD + redbeat loader)              ← зависит от T32, T34
        ↓
Wave 4 (sequential — schedules UI, день 3-4):
  └─ T35 (Frontend scheduled scan UI)                         ← зависит от T33
        ↓
Wave 5 (sequential — verification, день 4):
  └─ T36 (E2E across kill + schedules)                       ← зависит от T28, T29, T30, T35
```

**ASCII dependency graph:**

```
       T31 ─────┬──► T28 ───┐
       T32 ──┐  ├──► T29 ───┤
       T34 ──┴─►T33 ──► T35 ──► T36 ◄── T29, T30
                ├──► T30 ───┘
```

---

## 6. Critical path + recommended execution order

**Critical path по wall-time:** `T32 → T34 → T33 → T35 → T36` (~3 дня). T31 на параллельной ветке (~1 день), T28/T29/T30 — каждая ~0.5 дня после T31.

**Recommended sequential execution order** (один-worker mode для простоты orchestration):

```
1. T32  → migration foundation (S, ~2h)
2. T31  → backend emergency API (M, ~6h, unblocks UI wave)
3. T34  → cron_parser (M, ~4h, unblocks T33)
4. T28  → per-scan kill UI (S, ~3h)
5. T29  → per-tenant throttle UI (M, ~5h)
6. T30  → global kill UI (M, ~5h)
7. T33  → scan_schedules CRUD + redbeat (L, ~10h)
8. T35  → schedules UI (M, ~6h)
9. T36  → E2E (S, ~4h)
```

**Justification for this order (matches user's recommended order):**
- **T32 first:** smallest task, zero deps, sets revision marker so subsequent backend work knows the schema state.
- **T31 second:** unblocks 3 frontend tasks (T28/T29/T30) — gets parallelism / wave-2 ready soonest.
- **T34 third:** independent from T31, but ordered here because cron_parser will be needed by T33 (next wave).
- **T28 → T29 → T30:** kill-switch UI complexity ramps up (S → M → M); T28 simplest validates T31 contract; T30 most security-sensitive last (operators / reviewers fresh).
- **T33 after kill-switch UIs:** schedules backend depends on T32+T34; scheduling tied logically to operations theme.
- **T35 → T36:** schedule UI then E2E covers everything.

**Total wall-time estimate:** ~45 hours sequential = ~5.5 days at 8h/day; with 2-worker parallelism in Wave 2 (T28/T29/T30 simultaneous): ~4 days.

---

## 7. Risks (3-5)

| # | Risk | Severity | Mitigation |
|---|------|----------|------------|
| **R-1** | **`celery-redbeat` Redis state desync** with DB if `redbeat_loader.sync_one()` partially fails (e.g., DB INSERT succeeds, RedBeat write fails). Operator sees schedule в UI but it never fires. | 🟠 High | Wrap CRUD endpoint в transactional pattern: DB write → flush (not commit) → RedBeat sync → commit; rollback both on RedBeat failure. Add `sync_all_from_db()` startup reconciliation. Health endpoint `GET /health/scheduler` reports drift count. |
| **R-2** | **`react-js-cron` accessibility regressions** — visual cron builder может иметь невидимые axe-core violations или клавиатурную навигацию. | 🟡 Medium | Pre-T35 spike (30 min): rendered prototype через `npx create-next-app` + axe-core scan. Если violations → переключиться на raw expression input + server-side preview only (acceptance criteria still met without visual builder). |
| **R-3** | **Global kill-switch race condition** — operator clicks STOP ALL while another operator is provisioning a new scan; new scan slips through gap between Redis flag set и PolicyEngine consultation. | 🟠 High | (a) PolicyEngine consults KillSwitchService на КАЖДОМ ToolAdapter dispatch (per-tool, не per-scan); (b) бэкенд `stop_all` после set flag вызывает bulk-cancel cross-tenant — ловит scans, которые проскочили; (c) audit log shows reconciliation. Documented in T31 acceptance criteria. |
| **R-4** | **Maintenance window edge cases** — DST transitions cause cron to fire double / skip; operator sets `0 2 * * *` в `America/New_York` and на DST forward — fire skipped. | 🟡 Medium | T34 cron_parser hands off to `croniter` which has documented DST behaviour; T34 unit tests explicitly cover DST forward/back transitions for `America/New_York` and `Europe/Berlin`. Document edge cases в `ai_docs/develop/issues/ISS-T34-001` if any deviation found. |
| **R-5** | **Audit trail volume** — global stop_all on 100 tenants × 50 scans = 5000 cancelled scans → 5000+ scan_event rows + 1 audit_log row. EmergencyAuditTrail UI fetches 50 most recent — OK; но if operator triggers stop+resume cycle 10× / hour → audit table growth. | 🔵 Low | Existing `ix_audit_logs_tenant_created` composite index supports time-windowed queries. EmergencyAuditTrail uses pre-set filter — no scan-event-level fetch. Document in `ai_docs/develop/architecture/audit-volume.md` если потребуется (Phase 2). |

---

## 8. Constraints (sustained from Cycle 5/6 invariants + Batch 4 specific)

### Frontend constraints

- **Server-action only** для admin frontend (T28/T29/T30/T35) — extend существующий `actions.ts` ИЛИ create новый, но всегда `"use server"` + `getServerAdminSession()` + `callAdminBackendJson`.
- **Никакого browser-side fetch** для admin endpoints — лимиты в `Frontend/src/app/api/admin/tenants/route.ts` уже HTTP 410 для legacy fetch attempts.
- **Closed-taxonomy errors** — все error UIs только из мап в `Frontend/src/lib/admin*Errors.ts` (или extend `adminErrorMapping.ts`). Никаких stack traces, никаких raw JSON detail strings.
- **A11y compliance** — каждый new dialog gets focus trap + Esc + auto-focus; T26's axe-core gate должен оставаться 0 critical/serious после Batch 4.
- **RBAC enforcement** — operator denied from kill-switch (все 3) + scheduled scans CRUD; admin allowed для own tenant; super-admin для cross-tenant. Defence in depth: server-action checks role before backend call.
- **Public surface FROZEN** — менять ТОЛЬКО `Frontend/src/app/admin/**`, `Frontend/src/components/admin/**`, `Frontend/src/lib/admin*`, `Frontend/src/services/admin/**`, `Frontend/tests/**`. Любой touch вне этих путей = блокирующий violation.

### Backend constraints

- **Parameterized SQL ONLY** через SQLAlchemy ORM или `text()` с `:param` — никаких f-strings/`.format()` в SQL.
- **`X-Admin-Key` через `require_admin`** dependency — не bypass'ить.
- **Audit emit per state-changing action** — каждый emergency endpoint, каждый schedule CRUD → `AuditLog` row с canonical event_type + reason text + sha256 fingerprint of input.
- **Closed-taxonomy errors** — `HTTPException(status_code, detail=<short string>)`; все internal errors в structured logger без PII.
- **PII deny-list:** `tenant_id`, `user_id`, `email`, `password`, `secret`, `token`, `api_key`, `authorization` — не должны попадать в log records, в metric labels, в OTel span attributes.
- **Rate-limit / cap:** schedule cron expressions reject `< 5min` interval; chain verify time-window cap (≤90 дней) sustained.

### Cross-cutting

- **Атомарные коммиты** — один Tnn = один commit. Pre-commit hook не bypass'ить (`--no-verify` запрещено).
- **Conventional commit messages** с task id: `feat(admin-ops): per-scan kill-switch UI (T28)`, `feat(scheduling): cron_parser with maintenance-window logic (T34)`, etc.
- **Reuse mock backend infrastructure** from T26/T27 для E2E tests — ОДИН file `tests/e2e/fixtures/admin-backend-mock.ts` extended; никаких новых mock services.
- **`.env` / secrets** — никогда не коммитить. Новые env vars (если потребуются — нет в этом batch) с `NEXT_PUBLIC_` префиксом для frontend.
- **Windows / PowerShell-friendly commands** — все команды для тестов / локального запуска должны работать в PowerShell (`npm run test:run`, `npx playwright test`, `python -m pytest`, `alembic upgrade head`). Bash-only `&&` chaining ОК если оператор использует Git Bash; альтернатива — `;` chains в PowerShell или separate Run cells.
- **0 hexstrike/legacy** упоминаний — sustained gate (`backend/tests/test_no_hexstrike_active_imports.py`).

---

## 9. DoD reminders (`Backlog/dev1_.md` §19 sustained)

Каждая задача ⟶ один атомарный коммит ⟶ перед merge:

1. ✅ **`pytest -q`** зелёный, coverage ≥ 85% для затронутых модулей (`backend/src/api/routers/admin_emergency`, `backend/src/api/routers/admin_schedules`, `backend/src/policy/kill_switch`, `backend/src/scheduling`).
2. ✅ **`ruff check backend/src`** — 0 ошибок.
3. ✅ **`mypy --strict backend/src`** — 0 ошибок (advisory `mypy_capstone` gate; на Windows — WSL2).
4. ✅ **`bandit -q -r backend/src`** — 0 ошибок (advisory `bandit` gate).
5. ✅ **`alembic upgrade head && alembic downgrade -1 && alembic upgrade head`** проходит — обязательно для T32; advisory для остальных.
6. ✅ **`docker compose -f infra/docker-compose.yml up -d`** поднимает стек; smoke `scripts/e2e_full_scan.sh http://juice-shop:3000` зелёный (раз в Batch перед merge).
7. ✅ **Frontend публичный SSE/контракт не сломан** — все изменения только в `Frontend/src/{app/admin/**,components/admin/**,lib/admin*,services/admin/**}` и `Frontend/tests/`.
8. ✅ **`docs/tool-catalog.md` ≥150** строк — sustained inviolable; для Batch 4 не модифицируется.
9. ✅ **0 hexstrike/legacy** упоминаний — sustained gate.
10. ✅ **`scripts/argus_validate.py`** — 3 required gates (`ruff_capstone`, `catalog_drift`, `coverage_matrix`) green; advisory gates предпочтительно тоже green.
11. ✅ **Conventional commit per task:** `feat(<scope>): <summary> (T<NN>)`. Examples в каждом per-task block выше.
12. ✅ **SCA gate** для T33 (`celery-redbeat`) и T34 (`croniter`) и T35 (`react-js-cron`) — `safety check` / `pip-audit` / `npm audit` should not flag critical CVEs at install time.

---

## 10. Sign-off

**Plan author:** planner subagent (Cursor / Claude Opus 4.7)
**Date:** 2026-04-22
**Workspace:** `.cursor/workspace/active/orch-2026-04-22-argus-cycle6-b4/`
**Permanent plan:** `ai_docs/develop/plans/2026-04-22-argus-cycle6-b4.md`
**Status:** 🟢 Ready to execute
**Next command:** `/orchestrate execute orch-2026-04-22-argus-cycle6-b4`

**Approval needed:** Batch 4 lead (TBD assignment) для backlog acceptance + sequencing confirmation, особенно для D-1 (Alembic 024 → 026 deviation) и D-2/D-3 (added dependencies).

---

## 11. References

- **Roadmap:** [`Backlog/dev1_finalization_roadmap.md`](../../../Backlog/dev1_finalization_roadmap.md) §Batch 4
- **Backlog spec:** [`Backlog/dev1_.md`](../../../Backlog/dev1_.md) §8 Policy Engine + §18 Critical guardrails
- **Batch 3 plan:** [`ai_docs/develop/plans/2026-04-21-argus-cycle6-b3.md`](2026-04-21-argus-cycle6-b3.md)
- **Batch 3 carry-over:** [`ai_docs/develop/issues/ISS-cycle6-batch3-carry-over.md`](../issues/ISS-cycle6-batch3-carry-over.md)
- **Batch 3 report:** [`ai_docs/develop/reports/2026-04-21-cycle6-batch3-implementation.md`](../reports/2026-04-21-cycle6-batch3-implementation.md)
- **Production gate (deferred):** [`ai_docs/develop/issues/ISS-T20-003.md`](../issues/ISS-T20-003.md) — JWT/session auth pre-launch requirement
- **Existing canonical patterns:**
  - Server-action: `Frontend/src/app/admin/findings/actions.ts`, `Frontend/src/app/admin/audit-logs/actions.ts`
  - Backend admin router: `backend/src/api/routers/admin_findings.py`, `backend/src/api/routers/admin_audit_chain.py`
  - Bulk operations + audit emit: `backend/src/api/routers/admin_bulk_ops.py`
  - Mock backend для E2E: `Frontend/tests/e2e/fixtures/admin-backend-mock.ts`
  - Session resolver: `Frontend/src/services/admin/serverSession.ts`
  - Backend proxy: `Frontend/src/lib/serverAdminBackend.ts`
- **Celery infra:** `backend/src/celery_app.py`, `backend/src/celery/beat_schedule.py`
- **Existing scan cancel:** `backend/src/api/routers/scans.py:327` (`POST /scans/{id}/cancel`)
- **Existing bulk-cancel:** `backend/src/api/routers/admin_bulk_ops.py:50` (`POST /admin/scans/bulk-cancel`)
