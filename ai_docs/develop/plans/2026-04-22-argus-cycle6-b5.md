# План: ARGUS Cycle 6 — Batch 5 (Webhook DLQ + Kyverno admission policy, ARG-053 + ARG-054)

**Создан:** 2026-04-22
**Оркестрация:** `orch-2026-04-22-argus-cycle6-b5`
**Workspace:** `.cursor/workspace/active/orch-2026-04-22-argus-cycle6-b5/`
**Roadmap (источник истины):** [`Backlog/dev1_finalization_roadmap.md`](../../../Backlog/dev1_finalization_roadmap.md) §Batch 5
**Backlog (canonical spec):** [`Backlog/dev1_.md`](../../../Backlog/dev1_.md) §14 Webhooks/integrations + §17 SDLC/CI + §19 Acceptance
**Carry-over:** [`ai_docs/develop/issues/ISS-cycle6-batch4-carry-over.md`](../issues/ISS-cycle6-batch4-carry-over.md)
**Предыдущая оркестрация:** `orch-2026-04-22-argus-cycle6-b4` (Batch 4 — Operations UI: Kill-switch + Schedules)
**Предыдущий отчёт:** [`ai_docs/develop/reports/2026-04-22-cycle6-batch4-implementation.md`](../reports/2026-04-22-cycle6-batch4-implementation.md)
**Статус:** Ready
**Всего задач:** 9 (T37–T45) — в пределах cap=10
**Ожидаемая wall-time:** ~4 дня при 2-worker parallelism (foundation wave T37+T42 параллелится мгновенно)

---

## TL;DR

Batch 5 закрывает **operator-side webhook Dead-Letter-Queue management** (`ARG-053`: persistent DLQ для всех webhook-доставок, admin replay/abandon API, ежедневный Celery beat replay с экспоненциальным backoff и автоабандоном через 14 дней, frontend UI с filters/dialogs) и **supply-chain admission policy** (`ARG-054`: Kyverno cluster-policy YAML, требующая cosign-signed images + image digest, Helm-флаг `policy.enabled` для opt-in rollout, kind-based CI gate с positive/negative deploy assertions). 9 атомарных задач (T37–T45), 1 новая Alembic-миграция (`027_webhook_dlq.py`, **не 025 — 025 + 026 заняты**), новых backend-зависимостей нет (replay использует существующий `httpx` из `mcp/services/notifications/_base.py::NotifierBase.send_with_retry`), 1 новый infra-deps stack (Kyverno chart `3.6.x` + `sigstore/cosign-installer@v4.1.0` для CI gate), новых frontend-зависимостей нет. Архитектура переиспользует все паттерны Batch 4: closed-taxonomy errors (`WEBHOOK_DLQ_FAILURE_TAXONOMY`), `extractActionCode` для server-action serialization, mock backend для Playwright (с новым sentinel `webhook_url ~= https://webhook.failtest.invalid/*` для детерминистичного "replay always fails"), audit emit на каждое мутирующее действие. Этот batch разблокирует Batch 6 (HPA autoscaling + PDF/A archival) — admission-policy gate начинает охранять supply-chain до деплоя HPA-метрик.

---

## 1. Контекст

### Что закрывает Batch 5

**ARG-053 — Webhook DLQ** (T37–T41): впервые даёт операторам **визуальную и программную поверхность** для просмотра, ручного replay и abandon webhook-доставок, провалившихся после исчерпания retry-budget внутри `NotifierBase.send_with_retry`. Сейчас в коде (`backend/src/mcp/services/notifications/_base.py`, lines 418-512) failed-after-retry отправки возвращают `AdapterResult(delivered=False, error_code=..., status_code=...)` и логируются в `NotificationDispatcher`, но **не персистируются** — операторы не видят их и не могут replay. Этот batch вводит:

- Persistent table `webhook_dlq_entries` с RLS isolation (T37 миграция, T38 DAO).
- Admin API (T39) c RBAC: admin (own tenant), super-admin (cross-tenant).
- Periodic Celery beat replay (T40) c exponential backoff + автоабандон по age >= 14 дней.
- Frontend triage UI (T41) с фильтрами (статус / адаптер / диапазон дат), per-row replay/abandon dialogs, audit emit.

**ARG-054 — Sigstore Kyverno admission policy** (T42–T45): впервые даёт кластеру **рантайм-проверку**, что каждый Pod-image (a) имеет cosign-подпись через Sigstore Fulcio + Rekor, (b) задан в `@sha256:<digest>` форме (immutable reference). Сейчас supply-chain story в репозитории состоит из build-side (`infra/scripts/sign_images.sh` + `cosign verify-init` контейнер из `cosign.verify.enabled: true` в `infra/helm/argus/values.yaml`), но cluster-side admission gate отсутствует — оператор может развернуть `helm upgrade` с произвольным неподписанным образом (deviation от prod overlay-локов проходит). Этот batch вводит:

- Kyverno `ClusterPolicy` YAML (T42) под `infra/kyverno/`.
- Helm `policy.enabled` флаг (T43) с conditional template render — default `false` для backward-compat с существующими `helm upgrade` workflows; CI gate включает в `true`.
- kind-based CI workflow (T44) c kind cluster + Kyverno install + positive (signed-with-digest deploy → 201) и negative (unsigned-or-no-digest deploy → 403) assertions.
- Documentation (T45): `docs/admission-policy.md` (EN, devops-facing) + `docs/webhook-dlq.md` (RU, operator runbook).

### Что _не_ закрывает Batch 5

- **PDF/A archival** (T46–T48) — Batch 6.
- **HPA autoscaling** (T49–T51) — Batch 6.
- **JWT/session-bound admin auth** (`ISS-T20-003`) — production-gate, deferred к Cycle 7 / pre-launch (Batch 5 продолжает использовать cookie-shim из Batch 2-4).
- **Design token `--accent-high-contrast` / WCAG AA fix** (`ISS-T26-001`) — quick fix, между batches; в Batch 5 не закрываем — новые axe scenarios для `/admin/webhooks/dlq` наследуют `test.fail()` с reference на ISS-T26-001.
- **Webhook signing key rotation** (роадмап-out-of-scope для DLQ task family) — отдельная задача, не относится к replay/abandon-логике.
- **DLQ retention beyond 14 days** — фиксированный potolok; long-term архивация в S3/MinIO + cold-storage politik не входит в Batch 5.
- **Manual webhook-dispatcher replay-from-UI** (intercept webhook ДО провала, симулировать replay из UI ДО исчерпания retries) — Phase 2 / Cycle 7.
- **SARIF/SBOM generation в CI** — самостоятельная инициатива, не пересекается с admission-policy.

### Зависимости Batch 5 от Batch 4 (всё shipped)

- `getServerAdminSession()` resolver (`Frontend/src/services/admin/serverSession.ts`) — переиспользуется во всех T41-action helpers.
- `callAdminBackendJson` helper — переиспользуется для DLQ admin API calls.
- `AdminLayoutClient.tsx` NAV pattern — расширяется на новый entry `Webhooks DLQ`.
- `AdminRouteGuard` с `minimumRole` prop — переиспользуется (admin для list/replay/abandon в собственном tenant; super-admin для cross-tenant).
- Mock backend `Frontend/tests/e2e/fixtures/admin-backend-mock.ts` — расширяется новыми handlers `/admin/webhooks/dlq*` + sentinel.
- `axe-core` Playwright config (T26 `Frontend/tests/e2e/admin-axe.spec.ts`) — расширяется 1 route + 2 dialog scenarios (под `test.fail()` ISS-T26-001).
- `_operator_subject_dep` (`backend/src/api/routers/admin_bulk_ops.py`) — переиспользуется для audit emit на replay/abandon.
- `_admin_role_dep` + `_admin_tenant_dep` (`backend/src/api/routers/admin_findings.py`) — переиспользуются для RBAC parsing.
- `_emit_audit` (`backend/src/api/routers/admin_emergency.py`) — каноничный audit-row constructor, переиспользуется.
- `AuditLog` ORM + hash chain (`backend/src/policy/audit.py`) — переиспользуется для emit `webhook_dlq.replay`, `webhook_dlq.abandon`.
- `NotifierBase.send_with_retry` (`backend/src/mcp/services/notifications/_base.py`) — переиспользуется как replay-engine: T40 + T39 replay вызывают тот же entry-point с теми же circuit/dedup/backoff гарантиями.
- `hash_target` (`backend/src/mcp/services/notifications/_base.py`) — переиспользуется для `target_url_hash` колонки (URL никогда не персистится в clear).
- `apply_beat_schedule` (`backend/src/celery/beat_schedule.py`) — расширяется новой entry `argus.notifications.webhook_dlq_replay`.
- `SCHEDULE_FAILURE_TAXONOMY` + `extractScheduleActionCode` pattern (`Frontend/src/lib/adminSchedules.ts`) — каноничный template для нового `WEBHOOK_DLQ_FAILURE_TAXONOMY` + `extractWebhookDlqActionCode`.

---

## 2. Сводка верификации состояния (что подтверждено на диске)

### Подтверждённые факты

| Проверка | Результат |
|----------|-----------|
| Latest Alembic migration на диске | `026_scan_schedules.py` (Batch 4 T32, ARG-056). Glob: `backend/alembic/versions/*.py` |
| Existing webhook adapter инфраструктура | `backend/src/mcp/services/notifications/{_base.py, dispatcher.py, schemas.py, slack.py}` |
| `NotifierBase.send_with_retry` (replay engine) | `backend/src/mcp/services/notifications/_base.py:418-512` (httpx + retry + circuit + dedup) |
| `hash_target` (URL redaction для DLQ persistence) | `backend/src/mcp/services/notifications/_base.py` (re-export from `__all__`) |
| Existing admin routers | `admin.py`, `admin_scans.py`, `admin_findings.py`, `admin_audit_chain.py`, `admin_bulk_ops.py`, `admin_emergency.py`, `admin_schedules.py` |
| Canonical `actions.ts` pattern | `Frontend/src/app/admin/{schedules,findings,audit-logs,operations}/actions.ts` |
| Canonical closed-taxonomy lib | `Frontend/src/lib/adminSchedules.ts` (`SCHEDULE_FAILURE_TAXONOMY`, `extractScheduleActionCode`, `ERROR_MESSAGES_RU`) |
| Canonical mock backend для E2E | `Frontend/tests/e2e/fixtures/admin-backend-mock.ts` (1559 lines, реальный HTTP listener на 127.0.0.1, со встроенными `_test_*` query-флагами для детерминистичных edge-cases) |
| Existing axe-core gate | `Frontend/tests/e2e/admin-axe.spec.ts` (с 6+ `test.fail()` annotations referencing `ISS-T26-001`) |
| Audit hash chain | `backend/src/policy/audit.py::verify_audit_log_chain` + `GENESIS_HASH` |
| Celery beat infra | `backend/src/celery/beat_schedule.py::BEAT_SCHEDULE` + `apply_beat_schedule()` integration point |
| Helm values supply-chain контекст | `infra/helm/argus/values.yaml` lines 125-147 (`cosign.verify.enabled: true`, keyless GHA OIDC config) |
| Kyverno папка | `infra/kyverno/` — пустая (greenfield для T42) |
| Existing CI workflow для Helm | `.github/workflows/helm-validation.yml` (kubeconform matrix; шаблон для нового `admission-policy-kind.yml`) |
| Existing `cosign.verify.image` | `gcr.io/projectsigstore/cosign:v2.4.1` (используется как verify-init container, не как fixture для T44) |
| AdminLayoutClient navigation | `Frontend/src/app/admin/AdminLayoutClient.tsx:9-17` — 8 entries; T41 commit добавит 9-й (`Webhooks DLQ`) |
| Admin existing routes | `/admin`, `/admin/{tenants,scans,schedules,findings,audit-logs,operations,llm,system,forbidden}` + tenants subroutes |

### DEVIATIONS FROM ROADMAP (action required)

| # | Deviation | Impact | Resolution |
|---|-----------|--------|------------|
| **D-1** | Roadmap §Batch 5 называет миграцию `025_webhook_dlq.py`. Revision `025_tenant_limits_overrides` уже на диске (Batch 2 T13), revision `026_scan_schedules` уже на диске (Batch 4 T32). | T37 не может использовать revision 025 без рассинхронизации линейной цепочки `down_revision`. | **T37 использует revision `027`, down_revision `026`**. File: `027_webhook_dlq.py`. Docstring повторяет стиль "Deviation from roadmap" из `026_scan_schedules.py:15-22`. |
| **D-2** | Roadmap §T38 называет файл `backend/src/notifications/webhook_dlq_persistence.py`. Папка `backend/src/notifications/` НЕ существует — вся webhook-инфраструктура в проекте живёт в `backend/src/mcp/services/notifications/` (см. `_base.py`, `dispatcher.py`, `schemas.py`, `slack.py`). | Создание новой top-level папки `backend/src/notifications/` нарушает существующую модульную организацию (MCP `services/notifications/` исторически объединяет ВСЕ webhook-адаптеры и retry/circuit инфраструктуру). | **T38 размещает `webhook_dlq_persistence.py` рядом с существующими адаптерами**: `backend/src/mcp/services/notifications/webhook_dlq_persistence.py`. T39 импорт: `from src.mcp.services.notifications.webhook_dlq_persistence import (...)`. Зафиксировать в commit body как "intentional deviation D-2 — co-located with existing webhook adapter package". |
| **D-3** | Roadmap §T39 не уточняет URL-prefix DLQ admin endpoints, только "DLQ admin API". | Ambiguity между `/admin/webhooks/dlq` и `/admin/notifications/dlq`. | **Use `/admin/webhooks/dlq`** — соответствует frontend route `/admin/webhooks/dlq` (см. T41 в roadmap "Frontend DLQ UI"); URL-name "webhooks" уже знаком в Helm `secrets.webhooks.*` и `Backlog/dev1_.md` §14 ("Webhooks/integrations"). |
| **D-4** | Roadmap §T40 не уточняет dotted-name beat task. | Без явного name `apply_beat_schedule` не может зарегистрировать. | **Beat task name = `argus.notifications.webhook_dlq_replay`** (mirrors `argus.intel.epss_refresh` / `argus.intel.kev_refresh` dotted convention из `beat_schedule.py:11-14`). Daily at `06:00 UTC` (на час после KEV refresh, чтобы один beat-pod секвенировал I/O без contention). |
| **D-5** | Roadmap §T42 не уточняет имя ClusterPolicy и version range Kyverno. | Без pin chart-versions kind CI flaky-prone. | **Kyverno chart pin: `3.6.4` (Kyverno application `1.16.x`) — supports kind K8s `1.31.x`** (matches existing `helm-validation.yml` matrix top). ClusterPolicy name: `argus-require-signed-images`. Pinned exactly в `infra/kyverno/cluster-policy-require-signed-images.yaml` + workflow env. |
| **D-6** | Roadmap §T44 hint к "test images: `kennethreitz/httpbin@sha256:...` для signed/digest baseline" — но `kennethreitz/httpbin` НЕ Sigstore-подписан (это Docker Hub image без Cosign attestation). | Если выбрать неподписанный image как positive fixture, негативный тест не сможет отличить "не подписан" от "не в digest-форме" — false-positive в gate. | **Positive fixture билдится и подписывается **прямо в CI workflow** через `sigstore/cosign-installer@v4.1.0` + GHA OIDC keyless** (push в `ghcr.io/${{ github.repository_owner }}/argus-policy-fixture:${{ github.sha }}` → `cosign sign --yes <ref>@sha256:<digest>` → deploy с `@sha256:<digest>`). **Negative fixture: `nginx:1.27.0`** (no `@sha256:` digest — каноничный negative case, отрицает оба требования policy одновременно). |
| **D-7** | Нет partial Batch 5 кода (DLQ table / persistence / admin endpoints / beat task / Kyverno YAML / Helm flag) в src trees — clean slate. | Никакого waste / re-do. | Зафиксировано; никаких subtasks не пропускаем. |

### Latest Alembic migration on disk

```
backend/alembic/versions/
  ...
  023_epss_kev_tables.py             (Batch 1, ARG-044)
  024_tenant_exports_sarif_junit.py  (Batch 1 T04)
  025_tenant_limits_overrides.py     (Batch 2 T13)
  026_scan_schedules.py              (Batch 4 T32)
  -> 027_webhook_dlq.py              <- THIS BATCH (T37, ARG-053)
```

### Existing Frontend admin routes (after Batch 4)

```
/admin                  -> page.tsx (dashboard)
/admin/tenants          -> page.tsx + TenantsAdminClient.tsx
/admin/scans            -> page.tsx + AdminScansClient.tsx
/admin/schedules        -> page.tsx + AdminSchedulesClient.tsx (T35)
/admin/findings         -> page.tsx + AdminFindingsClient.tsx (T20)
/admin/audit-logs       -> page.tsx + AdminAuditLogsClient.tsx (T22)
/admin/operations       -> page.tsx + tabs (T28+T29+T30)
/admin/llm              -> page.tsx + AdminLlmClient.tsx
/admin/system           -> page.tsx (placeholder)
/admin/forbidden        -> RBAC fallback
```

**This batch adds:**

```
/admin/webhooks/dlq     -> page.tsx + WebhookDlqClient.tsx + actions.ts (T41)
                          + components: DlqTable, ReplayDialog, AbandonDialog
```

`AdminLayoutClient.tsx` NAV получает 1 новый entry: `Webhooks DLQ` (T41 commit включает NAV diff).

---

## 3. Задачи (T37–T45) с зависимостями

| ID | Title | Size | Wave | Deps | Files (est.) | Owner | Acceptance criteria summary | Status |
|----|-------|------|------|------|--------------|-------|----------------------------|--------|
| **T37** | Alembic migration `027_webhook_dlq.py` — table + RLS FORCE | S | 1 (foundation) | — | ~3 | worker | revision=027 (NOT 025 — D-1); table `webhook_dlq_entries` с tenant FK + adapter/event/target/payload/status/attempts/timestamps + RLS policy `tenant_isolation` + FORCE; upgrade/downgrade/upgrade idempotent на Postgres + SQLite смок-раунд | Pending |
| **T38** | `webhook_dlq_persistence.py` — DAO + lifecycle helpers (D-2) | M | 2 (foundation/data) | T37 | ~4 | worker | DAO: `enqueue`, `get_for_replay`, `mark_replayed`, `mark_abandoned`, `list_for_tenant`, `count_pending`; lifecycle helper `compute_next_retry_at(attempt, base, cap)` (mirror `compute_backoff_seconds` из `_base.py`); >= 18 unit tests; cross-tenant RLS smoke test | Pending |
| **T39** | DLQ admin API: `GET/POST/POST` `/admin/webhooks/dlq[/{id}/{replay,abandon}]` | M | 3 (surface) | T38 | ~6 | worker | 3 endpoints + RBAC matrix (admin own-tenant, super-admin cross-tenant); reuse `_admin_role_dep` + `_admin_tenant_dep` + `_operator_subject_dep`; closed-taxonomy errors `WEBHOOK_DLQ_FAILURE_TAXONOMY`; audit emit `webhook_dlq.{replay,abandon}` через `_emit_audit`; >= 22 backend tests | Pending |
| **T40** | Celery beat task `argus.notifications.webhook_dlq_replay` | M | 3 (background, parallel с T39) | T38 | ~4 | worker | Daily 06:00 UTC; per-row exponential backoff (base=30s, cap=24h via `compute_next_retry_at`); abandon если age >= 14 дней через `mark_abandoned(reason="max_age")`; integration test с инжектированными rows (один pending, один past-cutoff, один past-next-retry); reuse `NotifierBase.send_with_retry` для actual replay; >= 12 backend tests | Pending |
| **T41** | Frontend DLQ UI: `/admin/webhooks/dlq` list + filters + per-row replay/abandon dialogs + audit emit | L | 4 (surface) | T39 | ~9 | worker | Page + Client + actions + DlqTable + ReplayDialog (typed-confirm) + AbandonDialog (reason input) + `adminWebhookDlq.ts` (closed taxonomy + `extractWebhookDlqActionCode`); >= 18 vitest cases; mock-backend extension; >= 8 functional E2E (`admin-webhooks-dlq.spec.ts`); axe-core 1 route + 2 dialog scenarios под `test.fail()` ISS-T26-001 | Pending |
| **T42** | Kyverno cluster policy YAML — require cosign-signed images + image digest | S | 1 (foundation, parallel с T37) | — | ~2 | worker | `infra/kyverno/cluster-policy-require-signed-images.yaml` — `ClusterPolicy` с `verifyImages` rule (`required: true`, `verifyDigest: true`, `mutateDigest: false`, keyless attestor с `certificateOidcIssuer: https://token.actions.githubusercontent.com`); `validationFailureAction: Enforce`; `match: kinds: [Pod, Deployment, StatefulSet, DaemonSet, CronJob]`; pinned API version `kyverno.io/v1` | Pending |
| **T43** | Helm `policy.enabled` values flag + conditional template | S | 2 (foundation/infra) | T42 | ~3 | worker | `infra/helm/argus/values.yaml`: `policy: { enabled: false, kyverno: { policyFile: "..." } }`; новый template `infra/helm/argus/templates/kyverno-cluster-policy.yaml` под `{{- if .Values.policy.enabled -}}`; default `false` (existing `helm upgrade` workflows не ломаются); `kubeconform` smoke и `helm-validation.yml` зелёные с обоими `enabled=false/true` | Pending |
| **T44** | kind CI gate `policy-test` — apply policy, deny unsigned, allow signed-with-digest | M | 3 (gate) | T42, T43 | ~3 | worker | `.github/workflows/admission-policy-kind.yml`: kind v1.31 → Kyverno helm install (chart 3.6.4) → `kubectl apply -f` policy → build+sign positive fixture (`sigstore/cosign-installer@v4.1.0` keyless) → `kubectl run --dry-run=server` unsigned image → expect 403 → `kubectl run --dry-run=server` signed+digest image → expect 0 (server-side dry-run accept); timeouts <= 25 min; artifact upload kubernetes-events + kyverno-logs | Pending |
| **T45** | Документация: `docs/admission-policy.md` (EN) + `docs/webhook-dlq.md` (RU) | S | 5 (docs) | T41, T44 | ~2 | documenter | `docs/admission-policy.md` — devops-facing EN runbook: что делает policy, как opt-in через `policy.enabled=true`, как разблокировать failed-deploy (whitelist пометка), как обновить fixture для подписи новых images; `docs/webhook-dlq.md` — operator-facing RU runbook: как читать список DLQ, что значит каждый `error_code`, когда replay безопасен (idempotency dedup window), когда abandon оправдан, какие audit-rows эмитятся | Pending |

**Итого:** 9 задач • ~36 файлов изменено/создано • ~4 дня wall-time при 2-worker parallelism.

---

## 4. DAG визуально

ASCII-граф зависимостей (стрелка `->` = "блокирует"):

```
                                                                
  WAVE 1 (foundation, fully parallel):                         
                                                                
   T37 (027 migration)            T42 (Kyverno YAML)           
        |                              |                       
                                                                
                                                                
                                                                
  WAVE 2 (foundation/data):                                    
                                                                
   T38 (DAO)               T43 (Helm policy.enabled flag)      
        |                              |                       
                                                                
                                                                
                                                                
  WAVE 3 (surface + gate, parallel within wave):               
                                                                
   T39 (DLQ admin API)     T40 (Celery beat replay)            
        |                          |                           
                                                              
                                                                
                                                                
   T44 (kind CI policy-test)                                   
                                                                
                                                                
                                                                
                                                                
  WAVE 4 (frontend surface):                                   
                                                                
   T41 (Frontend DLQ UI + E2E + axe gate)                      
                                                                
                                                                
                                                                
                                                                
  WAVE 5 (docs, blocking commit batch):                        
                                                                
   T45 (admission-policy.md EN + webhook-dlq.md RU)            
                                                                
                                                                
```

**Параллелизм по wave (с 2 workers):**

| Wave | Задачи | Параллельно? | Длина (часов) |
|------|--------|--------------|---------------|
| 1 | T37 + T42 | да (нет shared files) | 3 |
| 2 | T38 + T43 | да (T38=Python, T43=Helm/YAML — нет конфликта) | 6 |
| 3 | T39 + T40 + T44 | T39+T40 параллельны (оба зависят от T38; T39 = router, T40 = celery — нет конфликта); T44 параллельно (зависит только от T42+T43, не от T38) | max(7, 6, 7) = 7 |
| 4 | T41 | один worker (frontend-heavy) | 9 |
| 5 | T45 | один worker (docs requires T41+T44 done) | 4 |

**Wall-time с 2-worker:** 3 + 6 + 7 + 9 + 4 = **29 часов = ~4 рабочих дня** (с CI runs и review циклами).

---

## 5. Per-task детали

### T37 — Alembic migration `027_webhook_dlq.py`

**Goal:** Persistent storage для failed-after-retry webhook доставок с RLS isolation, indexed для hot-path "list pending для tenant" и "scan для Celery beat replay".

**Backend / Frontend split:** 100% backend (DB layer).

**Migration sketch:**

```python
# backend/alembic/versions/027_webhook_dlq.py — NEW

revision: str = "027"
down_revision: str | None = "026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE_NAME = "webhook_dlq_entries"
INDEX_TENANT_STATUS = "ix_webhook_dlq_tenant_status"
INDEX_NEXT_RETRY = "ix_webhook_dlq_next_retry_at"
INDEX_CREATED = "ix_webhook_dlq_created_at"
RLS_POLICY_NAME = "tenant_isolation"


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    op.create_table(
        TABLE_NAME,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("adapter_name", sa.String(64), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("event_id", sa.String(64), nullable=False),
        sa.Column("target_url_hash", sa.String(64), nullable=False),
        sa.Column("payload_json", sa.JSON(), nullable=False),
        sa.Column("last_error_code", sa.String(64), nullable=False),
        sa.Column("last_status_code", sa.Integer(), nullable=True),
        sa.Column(
            "attempt_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("replayed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("abandoned_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("abandoned_reason", sa.String(64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "tenant_id", "adapter_name", "event_id",
            name="uq_webhook_dlq_tenant_adapter_event",
        ),
    )

    op.create_index(
        INDEX_TENANT_STATUS,
        TABLE_NAME,
        ["tenant_id", "abandoned_at", "replayed_at"],
    )
    op.create_index(INDEX_CREATED, TABLE_NAME, ["created_at"])

    if is_postgres:
        # Partial index — Celery beat scan только pending rows.
        op.execute(
            """
            CREATE INDEX ix_webhook_dlq_next_retry_at
                ON webhook_dlq_entries (next_retry_at)
                WHERE abandoned_at IS NULL AND replayed_at IS NULL
            """
        )
        op.execute(f'ALTER TABLE "{TABLE_NAME}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{TABLE_NAME}" FORCE ROW LEVEL SECURITY')
        op.execute(f'DROP POLICY IF EXISTS {RLS_POLICY_NAME} ON "{TABLE_NAME}"')
        op.execute(
            f"""
            CREATE POLICY {RLS_POLICY_NAME} ON "{TABLE_NAME}"
                USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
                WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
            """
        )
    else:
        op.create_index(INDEX_NEXT_RETRY, TABLE_NAME, ["next_retry_at"])


def downgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"
    if is_postgres:
        op.execute(f'DROP POLICY IF EXISTS {RLS_POLICY_NAME} ON "{TABLE_NAME}"')
        op.execute(f'ALTER TABLE "{TABLE_NAME}" NO FORCE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{TABLE_NAME}" DISABLE ROW LEVEL SECURITY')
        op.execute(f"DROP INDEX IF EXISTS {INDEX_NEXT_RETRY}")
    else:
        op.drop_index(INDEX_NEXT_RETRY, table_name=TABLE_NAME)
    op.drop_index(INDEX_CREATED, table_name=TABLE_NAME)
    op.drop_index(INDEX_TENANT_STATUS, table_name=TABLE_NAME)
    op.drop_table(TABLE_NAME)
```

**ORM model добавляется в `backend/src/db/models.py`:**

```python
class WebhookDlqEntry(Base):
    """Webhook DLQ entry — one failed-after-retry delivery (T37 / ARG-053)."""

    __tablename__ = "webhook_dlq_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=gen_uuid)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    adapter_name: Mapped[str] = mapped_column(String(64), nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    event_id: Mapped[str] = mapped_column(String(64), nullable=False)
    target_url_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    last_error_code: Mapped[str] = mapped_column(String(64), nullable=False)
    last_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attempt_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    replayed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    abandoned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    abandoned_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "adapter_name", "event_id",
            name="uq_webhook_dlq_tenant_adapter_event",
        ),
        Index("ix_webhook_dlq_tenant_status", "tenant_id", "abandoned_at", "replayed_at"),
        Index("ix_webhook_dlq_created_at", "created_at"),
    )
```

**Acceptance criteria (>= 5):**
- (a) Revision string = `"027"`, down_revision = `"026"`; `alembic upgrade head` from clean DB succeeds; `upgrade head -> downgrade -1 -> upgrade head` сохраняет схему.
- (b) Table создана с правильными типами; UNIQUE `(tenant_id, adapter_name, event_id)` enforced (re-enqueue одного и того же `event_id` для того же adapter+tenant -> IntegrityError).
- (c) RLS policy `tenant_isolation` создан + FORCE на Postgres; cross-tenant SELECT с одного tenant context не видит rows другого tenant (`set_session_tenant` тест).
- (d) Indexes `ix_webhook_dlq_tenant_status`, `ix_webhook_dlq_next_retry_at` (partial на Postgres, plain на SQLite), `ix_webhook_dlq_created_at` присутствуют (`pg_indexes` assert).
- (e) Docstring содержит секцию "Deviation from roadmap" mirroring `026_scan_schedules.py:15-22` (revision 025 занята Batch 2 T13, 026 занята Batch 4 T32 -> 027).

**Test minima:**
- Migration: 5 (upgrade/downgrade idempotency, RLS isolation, FORCE bypasses owner role, unique constraint, FK cascade on tenant DROP).
- ORM: integrated с T38 tests.
- **Total: 5 migration tests.**

**Files to touch (estimated 3):**
- `backend/alembic/versions/027_webhook_dlq.py` (NEW)
- `backend/src/db/models.py` (extend — `class WebhookDlqEntry(Base)`)
- `backend/tests/db/test_webhook_dlq_migration.py` (NEW)

**Architectural notes:**
- RLS + FORCE idiom: copy-paste из `026_scan_schedules.py:174-199` (canonical pattern).
- Partial index on `next_retry_at` (Postgres) ускоряет Celery beat scan: `WHERE abandoned_at IS NULL AND replayed_at IS NULL AND next_retry_at <= now()` -> hot subset only.
- ORM `gen_uuid` reuse — same convention как `ScanSchedule`, `Tenant`, etc.

**Commit message:** `feat(db): webhook_dlq_entries table + RLS FORCE (T37 migration 027)`

**Deviation callout in commit body:** "Roadmap §Batch 5 names migration `025_webhook_dlq.py`; revisions 025 (`tenant_limits_overrides`) and 026 (`scan_schedules`) already on disk from Batches 2+4 — this migration uses revision `027` to maintain linear chain. See plan §2 deviation D-1."

---

### T38 — `webhook_dlq_persistence.py` — DAO + lifecycle helpers

**Goal:** Тонкий DAO layer над `WebhookDlqEntry` ORM с lifecycle helpers, инкапсулирующий все мутирующие операции (enqueue / mark_replayed / mark_abandoned), exponential-backoff calc и query-helpers для T39 admin API + T40 beat task.

**Backend / Frontend split:** 100% backend (data-access layer).

**Module sketch (D-2: location `backend/src/mcp/services/notifications/webhook_dlq_persistence.py`):**

```python
# backend/src/mcp/services/notifications/webhook_dlq_persistence.py — NEW

"""T38 / ARG-053 — DAO + lifecycle helpers for webhook DLQ entries.

Co-located with existing notification adapters (`_base.py`, `dispatcher.py`,
`slack.py`) per plan deviation D-2 — webhook subsystem package boundary lives
at `mcp/services/notifications/`, not at top-level `notifications/`.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import and_, asc, desc, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import WebhookDlqEntry, gen_uuid
from src.mcp.services.notifications._base import hash_target

# Exponential backoff bounds — mirrors _base.py constants for symmetry.
DLQ_BACKOFF_BASE_SECONDS: Final[float] = 30.0
DLQ_BACKOFF_FACTOR: Final[float] = 4.0
DLQ_BACKOFF_CAP_SECONDS: Final[float] = 24 * 3600.0  # 24 hours
DLQ_MAX_AGE_DAYS: Final[int] = 14


def compute_next_retry_at(
    *, attempt_count: int, now: datetime | None = None
) -> datetime:
    """Return UTC timestamp for next replay attempt; mirrors compute_backoff_seconds."""
    if attempt_count < 0:
        raise ValueError("attempt_count must be >= 0")
    delay = min(
        DLQ_BACKOFF_CAP_SECONDS,
        DLQ_BACKOFF_BASE_SECONDS * (DLQ_BACKOFF_FACTOR ** attempt_count),
    )
    base = now or datetime.now(UTC)
    return base + timedelta(seconds=delay)


async def enqueue(
    session: AsyncSession,
    *,
    tenant_id: str,
    adapter_name: str,
    event_type: str,
    event_id: str,
    target_url: str,
    payload: dict,
    last_error_code: str,
    last_status_code: int | None,
    attempt_count: int,
) -> WebhookDlqEntry:
    """Persist a failed-after-retry webhook delivery into the DLQ."""
    entry = WebhookDlqEntry(
        id=gen_uuid(),
        tenant_id=tenant_id,
        adapter_name=adapter_name,
        event_type=event_type,
        event_id=event_id,
        target_url_hash=hash_target(target_url),
        payload_json=payload,
        last_error_code=last_error_code,
        last_status_code=last_status_code,
        attempt_count=attempt_count,
        next_retry_at=compute_next_retry_at(attempt_count=attempt_count),
    )
    session.add(entry)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        # Idempotent re-enqueue: same (tenant, adapter, event_id) -> noop.
        return await get_by_event(
            session,
            tenant_id=tenant_id,
            adapter_name=adapter_name,
            event_id=event_id,
        )
    return entry


async def get_by_id(
    session: AsyncSession, *, entry_id: str, tenant_id: str | None = None
) -> WebhookDlqEntry | None:
    """Fetch a single entry by id; tenant_id parameter for super-admin RLS bypass."""
    ...


async def get_by_event(
    session: AsyncSession,
    *,
    tenant_id: str,
    adapter_name: str,
    event_id: str,
) -> WebhookDlqEntry | None:
    ...


async def list_for_tenant(
    session: AsyncSession,
    *,
    tenant_id: str | None,  # None = super-admin cross-tenant
    status: str | None = None,  # "pending" | "replayed" | "abandoned"
    adapter_name: str | None = None,
    created_after: datetime | None = None,
    created_before: datetime | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[Sequence[WebhookDlqEntry], int]:
    """Paginated list + total count for the admin DLQ table."""
    ...


async def list_due_for_replay(
    session: AsyncSession,
    *,
    now: datetime | None = None,
    limit: int = 100,
) -> Sequence[WebhookDlqEntry]:
    """Fetch entries whose next_retry_at <= now, not abandoned and not replayed.
    Used by T40 Celery beat scan."""
    ...


async def list_abandoned_candidates(
    session: AsyncSession,
    *,
    now: datetime | None = None,
    limit: int = 100,
) -> Sequence[WebhookDlqEntry]:
    """Fetch entries whose age >= DLQ_MAX_AGE_DAYS and still not terminal."""
    ...


async def mark_replayed(
    session: AsyncSession, *, entry_id: str, tenant_id: str | None
) -> WebhookDlqEntry:
    """Set replayed_at = now (terminal). Raises DlqEntryNotFoundError or
    AlreadyTerminalError as appropriate."""
    ...


async def mark_abandoned(
    session: AsyncSession,
    *,
    entry_id: str,
    tenant_id: str | None,
    reason: str,  # "operator" | "max_age" | "manual_abandon"
) -> WebhookDlqEntry:
    """Set abandoned_at = now + reason (terminal)."""
    ...


async def increment_attempt(
    session: AsyncSession,
    *,
    entry_id: str,
    last_error_code: str,
    last_status_code: int | None,
) -> WebhookDlqEntry:
    """Increment attempt_count after a replay failure; recompute next_retry_at."""
    ...


# Closed-taxonomy DAO exceptions
class DlqEntryNotFoundError(Exception):
    """Raised by mark_* / get_by_id when row not found OR cross-tenant probe."""


class AlreadyTerminalError(Exception):
    """Raised when caller tries to mutate an entry that is already replayed/abandoned."""


__all__ = [
    "DLQ_BACKOFF_BASE_SECONDS",
    "DLQ_BACKOFF_CAP_SECONDS",
    "DLQ_BACKOFF_FACTOR",
    "DLQ_MAX_AGE_DAYS",
    "AlreadyTerminalError",
    "DlqEntryNotFoundError",
    "compute_next_retry_at",
    "enqueue",
    "get_by_event",
    "get_by_id",
    "increment_attempt",
    "list_abandoned_candidates",
    "list_due_for_replay",
    "list_for_tenant",
    "mark_abandoned",
    "mark_replayed",
]
```

**Acceptance criteria (>= 6):**
- (a) `enqueue()` happy path: создаёт row с `target_url_hash = hash_target(target_url)` (raw URL никогда не персистится); `next_retry_at = now + 30s` для первого attempt.
- (b) `enqueue()` idempotency: вторая попытка с тем же `(tenant_id, adapter_name, event_id)` НЕ создаёт duplicate, возвращает существующий row (UNIQUE constraint -> IntegrityError -> rollback -> get_by_event).
- (c) `compute_next_retry_at(attempt_count=0)` = +30s; `attempt_count=1` = +120s; `attempt_count=4` = +7680s; `attempt_count=20` capped at +24h.
- (d) `list_due_for_replay(now=t)` возвращает только rows где `next_retry_at <= t`, `abandoned_at IS NULL`, `replayed_at IS NULL`; ordered by `created_at ASC` (FIFO).
- (e) `list_abandoned_candidates(now=t)` возвращает rows где `created_at <= t - 14d`, `abandoned_at IS NULL`, `replayed_at IS NULL`.
- (f) `mark_replayed` / `mark_abandoned` идемпотентны при повторном вызове raise `AlreadyTerminalError`; cross-tenant probe (admin tenant=A пытается mutate row tenant=B) raise `DlqEntryNotFoundError` (existence-leak protection).

**Test minima:**
- Unit: 18 (`compute_next_retry_at` 5 cases + `enqueue` happy/dup 4 + `get_*` 3 + `list_*` 4 + `mark_*` happy/idempotent/cross-tenant 6).
- Integration: 2 (RLS isolation smoke с реальным `set_session_tenant` на Postgres test DB).
- **Total: 20 backend tests.**

**Files to touch (estimated 4):**
- `backend/src/mcp/services/notifications/webhook_dlq_persistence.py` (NEW, ~300 LoC)
- `backend/src/mcp/services/notifications/__init__.py` (extend `__all__` exports)
- `backend/tests/notifications/test_webhook_dlq_persistence.py` (NEW, ~18 cases)
- `backend/tests/db/test_webhook_dlq_rls.py` (NEW, ~2 cases — Postgres-only)

**Architectural notes:**
- Co-locate с existing webhook adapters: deviation D-2; commit body must explicitly cite plan §2 D-2.
- `hash_target` reuse — same hash function used by `_base.py` для `target_redacted` в `AdapterResult` -> симметрия в audit/log analysis.
- Closed-taxonomy DAO exceptions (NOT raw `sqlalchemy.exc.NoResultFound` или `IntegrityError`): T39 router map в HTTP error -> `WEBHOOK_DLQ_FAILURE_TAXONOMY` codes без leak internals.
- Backoff формула повторяет `compute_backoff_seconds` из `_base.py` но без jitter — T40 запускается раз в день, jitter не добавляет ценности и усложняет debugging "почему row 17 не replayed?".

**Commit message:** `feat(notifications): webhook DLQ persistence DAO + lifecycle helpers (T38)`

---

### T39 — DLQ admin API: `GET/POST/POST` `/admin/webhooks/dlq[/{id}/{replay,abandon}]`

**Goal:** REST поверхность для frontend T41 + операторских CLI-tools, c полным RBAC и audit emit.

**Backend / Frontend split:** 100% backend (FastAPI router + Pydantic schemas).

**Endpoints contract:**

```python
# backend/src/api/routers/admin_webhook_dlq.py — NEW

@router.get("/admin/webhooks/dlq", response_model=WebhookDlqListResponse)
async def list_webhook_dlq(
    status: Literal["pending", "replayed", "abandoned"] | None = Query(None),
    adapter_name: str | None = Query(None),
    created_after: datetime | None = Query(None),
    created_before: datetime | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
) -> WebhookDlqListResponse:
    # RBAC: admin -> own tenant only (role_tenant required); super-admin -> any tenant.
    # Returns paginated list + total_count + per-row {id, adapter_name, event_type,
    #   event_id, target_url_hash, attempt_count, last_error_code, last_status_code,
    #   created_at, next_retry_at, replayed_at, abandoned_at, abandoned_reason,
    #   triage_status: "pending"|"replayed"|"abandoned"}.

@router.post(
    "/admin/webhooks/dlq/{entry_id}/replay",
    response_model=WebhookDlqReplayResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def replay_webhook_dlq(
    entry_id: UUID,
    body: WebhookDlqReplayRequest,  # {reason: str ≥ 10 chars}
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
    operator_subject: str = Depends(_operator_subject_dep),
) -> WebhookDlqReplayResponse:
    # RBAC: admin (entry.tenant == role_tenant) OR super-admin (any).
    # 1. DAO get_by_id; missing OR cross-tenant -> 404 dlq_entry_not_found.
    # 2. Already terminal -> 409 already_replayed | already_abandoned.
    # 3. Reconstruct NotificationEvent from payload_json + dispatch
    #    NotifierBase.send_with_retry; on success -> mark_replayed; on
    #    final failure -> increment_attempt + return 200 с replay_failed.
    # 4. Audit emit event_type="webhook_dlq.replay", details={entry_id,
    #    adapter_name, event_id, success, attempt_count, reason}.

@router.post(
    "/admin/webhooks/dlq/{entry_id}/abandon",
    response_model=WebhookDlqAbandonResponse,
    status_code=status.HTTP_200_OK,
)
async def abandon_webhook_dlq(
    entry_id: UUID,
    body: WebhookDlqAbandonRequest,  # {reason: str ≥ 10 chars}
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
    operator_subject: str = Depends(_operator_subject_dep),
) -> WebhookDlqAbandonResponse:
    # RBAC: admin (entry.tenant == role_tenant) OR super-admin (any).
    # 1. DAO get_by_id; missing OR cross-tenant -> 404.
    # 2. Already terminal -> 409.
    # 3. mark_abandoned(reason="operator").
    # 4. Audit emit event_type="webhook_dlq.abandon", details={entry_id, reason}.
```

**Pydantic schemas (added to `backend/src/api/schemas.py`):**

```python
class WebhookDlqEntryItem(BaseModel):
    id: UUID
    tenant_id: UUID
    adapter_name: str
    event_type: str
    event_id: str
    target_url_hash: str  # 64-char hex; raw URL never returned
    attempt_count: int
    last_error_code: str
    last_status_code: int | None
    next_retry_at: datetime | None
    created_at: datetime
    replayed_at: datetime | None
    abandoned_at: datetime | None
    abandoned_reason: str | None
    triage_status: Literal["pending", "replayed", "abandoned"]


class WebhookDlqListResponse(BaseModel):
    items: list[WebhookDlqEntryItem]
    total: int
    limit: int
    offset: int


class WebhookDlqReplayRequest(BaseModel):
    reason: str = Field(min_length=10, max_length=500)


class WebhookDlqReplayResponse(BaseModel):
    entry_id: UUID
    success: bool
    attempt_count: int
    new_status: Literal["replayed", "pending"]  # "pending" если replay снова провалился
    audit_id: UUID
    message_code: Literal["replay_succeeded", "replay_failed"]


class WebhookDlqAbandonRequest(BaseModel):
    reason: str = Field(min_length=10, max_length=500)


class WebhookDlqAbandonResponse(BaseModel):
    entry_id: UUID
    new_status: Literal["abandoned"]
    audit_id: UUID
```

**Acceptance criteria (>= 7):**
- (a) `GET /admin/webhooks/dlq` (admin) — возвращает только rows для `role_tenant`; missing `X-Admin-Tenant` для admin -> 403 `tenant_required`; pagination корректно (`limit/offset/total`).
- (b) `GET /admin/webhooks/dlq` (super-admin) — без `X-Admin-Tenant` возвращает cross-tenant; с `X-Admin-Tenant=X` фильтрует на X.
- (c) `POST /admin/webhooks/dlq/{id}/replay` happy path — реконструирует `NotificationEvent`, dispatch через `NotifierBase.send_with_retry`, success -> `mark_replayed` -> 202 + `success=true`; emit AuditLog `webhook_dlq.replay`.
- (d) `POST /admin/webhooks/dlq/{id}/replay` failure path — replay снова падает, `increment_attempt`, 202 + `success=false`, `new_status="pending"`, `message_code="replay_failed"`; AuditLog emit с `success=false`.
- (e) `POST /admin/webhooks/dlq/{id}/abandon` (admin own tenant) — `mark_abandoned(reason="operator")`, 200, AuditLog emit.
- (f) Cross-tenant probe (admin tenant=A пытается replay/abandon row tenant=B) -> 404 `dlq_entry_not_found` (existence-leak protection — НЕ 403; НЕ leak existence через discriminator status code).
- (g) Все ошибки — closed-taxonomy strings из `WEBHOOK_DLQ_FAILURE_TAXONOMY`; стек-трейсы НЕ возвращаются клиенту.

**Test minima:**
- Unit: 4 (Pydantic schema validation: `reason` length, UUID format, `status` literal).
- Integration / API: 22 (RBAC matrix 3 endpoints × 3 roles + `replay` happy + `replay` failure + `abandon` happy + `abandon` already-abandoned + `replay` already-replayed + `replay` already-abandoned + cross-tenant 404 + invalid `reason` 422 + audit emit verification + `list` filter combinations).
- E2E: 0 (covered in T41).
- **Total: 26+ backend tests.**

**Files to touch (estimated 6):**
- `backend/src/api/routers/admin_webhook_dlq.py` (NEW, ~280 LoC)
- `backend/src/api/schemas.py` (extend — 6 new request/response models)
- `backend/main.py` (1 line: `import src.api.routers.admin_webhook_dlq`)
- `backend/tests/api/admin/test_admin_webhook_dlq_list.py` (NEW, ~10 cases)
- `backend/tests/api/admin/test_admin_webhook_dlq_replay.py` (NEW, ~10 cases)
- `backend/tests/api/admin/test_admin_webhook_dlq_abandon.py` (NEW, ~6 cases)

**Architectural notes:**
- Reuse `require_admin` + `_admin_role_dep` + `_admin_tenant_dep` + `_operator_subject_dep` (canonical).
- Audit emit reuse `_emit_audit` from `admin_emergency.py` (canonical helper that handles `tenant_hash` + `user_id_hash` + hash-chain commit).
- `target_url_hash` НИКОГДА не возвращается как clear URL — frontend показывает hash как opaque ID.
- Replay engine: import `NotificationDispatcher` или `NotifierBase` factory из `mcp/services/notifications/dispatcher.py`; reconstruct `NotificationEvent` из `payload_json` (валидируем через `NOTIFICATION_EVENT_TYPES`).
- Closed-taxonomy mapping (HTTP -> taxonomy code) синхронизируется с `WEBHOOK_DLQ_FAILURE_TAXONOMY` (см. §6).

**Commit message:** `feat(admin): webhook DLQ admin API (list/replay/abandon) + RBAC + audit (T39)`

---

### T40 — Celery beat task `argus.notifications.webhook_dlq_replay`

**Goal:** Daily background task, который scan-ит DLQ, replay все rows с `next_retry_at <= now`, abandon все rows с age >= 14 дней.

**Backend / Frontend split:** 100% backend (Celery task module).

**Module sketch:**

```python
# backend/src/celery/tasks/webhook_dlq_replay.py — NEW

"""T40 / ARG-053 — Daily Celery beat task replaying DLQ entries.

Schedule
--------
Registered under `argus.notifications.webhook_dlq_replay` in
`backend/src/celery/beat_schedule.py`. Fires daily at 06:00 UTC (one hour
after `argus.intel.kev_refresh` to avoid contention on a single beat pod).

Loop body
---------
1. `list_due_for_replay(now)` -> N pending rows (limit 100 per tick).
2. For each row:
   a. Skip if circuit breaker open для (adapter_name, tenant_id).
   b. Reconstruct NotificationEvent from payload_json.
   c. dispatch -> NotifierBase.send_with_retry.
   d. On 2xx -> mark_replayed.
   e. On final failure -> increment_attempt (recomputes next_retry_at).
3. `list_abandoned_candidates(now)` -> M aged rows.
4. For each: mark_abandoned(reason="max_age").
5. Emit metric `argus_webhook_dlq_replay_processed` (counter) с labels
   {result="replayed"|"failed"|"abandoned_max_age", adapter_name}.
6. Structured log с counts (no PII; only adapter_name + counts).
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from src.celery_app import app
from src.db.session import async_session_factory
from src.mcp.services.notifications.dispatcher import NotificationDispatcher
from src.mcp.services.notifications.schemas import NotificationEvent
from src.mcp.services.notifications.webhook_dlq_persistence import (
    DLQ_MAX_AGE_DAYS,
    increment_attempt,
    list_abandoned_candidates,
    list_due_for_replay,
    mark_abandoned,
    mark_replayed,
)


@app.task(
    name="argus.notifications.webhook_dlq_replay",
    bind=True,
    autoretry_for=(),  # we don't retry the task itself; per-row retries handled internally
    queue="argus.notifications",
)
def webhook_dlq_replay(self: Any) -> dict[str, int]:
    """Sync wrapper для async loop (Celery task call shape)."""
    return asyncio.run(_run())


async def _run() -> dict[str, int]:
    counts = {"replayed": 0, "failed": 0, "abandoned_max_age": 0}
    now = datetime.now(UTC)

    async with async_session_factory() as session:
        for entry in await list_due_for_replay(session, now=now, limit=100):
            ...  # dispatch -> mark_replayed | increment_attempt
        await session.commit()

        for entry in await list_abandoned_candidates(session, now=now, limit=100):
            await mark_abandoned(
                session,
                entry_id=entry.id,
                tenant_id=entry.tenant_id,
                reason="max_age",
            )
            counts["abandoned_max_age"] += 1
        await session.commit()

    return counts
```

**Beat schedule extension (`backend/src/celery/beat_schedule.py`):**

```python
BEAT_SCHEDULE: dict[str, dict[str, Any]] = {
    "argus.intel.epss_refresh": {...},
    "argus.intel.kev_refresh": {...},
    # NEW for T40:
    "argus.notifications.webhook_dlq_replay": {
        "task": "argus.notifications.webhook_dlq_replay",
        "schedule": _schedule(hour=6, minute=0),
        "options": {"queue": "argus.notifications"},
    },
}
```

**Acceptance criteria (>= 5):**
- (a) Task registered as `argus.notifications.webhook_dlq_replay` в `BEAT_SCHEDULE`; daily at 06:00 UTC; routes to queue `argus.notifications`.
- (b) `list_due_for_replay` integration: row with `next_retry_at = now - 1h, attempt_count=0` -> picked up; row with `next_retry_at = now + 1h` -> NOT picked up; row with `replayed_at = ...` -> NOT picked up; row with `abandoned_at = ...` -> NOT picked up.
- (c) Replay success -> `mark_replayed` called; row's `replayed_at` set; counter `replayed` incremented.
- (d) Replay failure -> `increment_attempt` called с актуальным `last_error_code`; `attempt_count++`; `next_retry_at` = `compute_next_retry_at(new_attempt_count)`.
- (e) Aged-out row (`created_at = now - 15d`, still pending) -> `mark_abandoned(reason="max_age")`; counter `abandoned_max_age` incremented.
- (f) Task body НЕ raise — все exceptions из per-row dispatches absorbed (mirror `NotificationDispatcher` semantics); structured log с stack для observability, BUT task возвращает `{"replayed": N, "failed": M, "abandoned_max_age": K}`.

**Test minima:**
- Unit: 4 (`_run` shape, beat-schedule registration, `list_due_for_replay` filtering, `compute_next_retry_at` boundary).
- Integration: 8 (real DB rows + mocked dispatcher: replay-success / replay-failure / abandon-aged / circuit-open-skip / cross-tenant-isolated / pending-not-due-skipped / replayed-skipped / abandoned-skipped).
- **Total: 12 backend tests.**

**Files to touch (estimated 4):**
- `backend/src/celery/tasks/webhook_dlq_replay.py` (NEW, ~150 LoC)
- `backend/src/celery/beat_schedule.py` (extend `BEAT_SCHEDULE` dict, ~6 LoC)
- `backend/src/celery_app.py` (1 line route: `"argus.notifications.*": {"queue": "argus.notifications"}`)
- `backend/tests/celery/test_webhook_dlq_replay_task.py` (NEW, ~12 cases)

**Architectural notes:**
- Async-in-Celery-sync wrapper pattern скопирован из `src/scheduling/scan_trigger.py:40-46` (canonical pattern в репо).
- Replay engine — `NotifierBase.send_with_retry` — переиспользует ту же circuit-breaker / dedup / backoff infrastructure что и first-time delivery, поэтому повторный circuit-open для (adapter, tenant) автоматически блокирует beat replay (no flooding upstream).
- Beat schedule registered через `apply_beat_schedule` — operator overrides из ENV/values.yaml имеют приоритет (см. `apply_beat_schedule:60-66`).
- Exception handling: каждый per-row error logged + counter incremented; loop НЕ останавливается на single-row failure -> N successful rows из 100 не блокируются 1 broken row.

**Commit message:** `feat(notifications): daily Celery beat DLQ replay + auto-abandon at 14d (T40)`

---

### T41 — Frontend DLQ UI: `/admin/webhooks/dlq`

**Goal:** Operator-facing triage UI: list pending DLQ entries с filters, per-row replay/abandon dialogs с typed-confirmation, audit emit, axe-core compliant (под `test.fail()` ISS-T26-001).

**Backend / Frontend split:** 100% frontend (Next.js Server Actions + Client + Components + closed-taxonomy lib).

**Files to create:**

| File | Purpose |
|------|---------|
| `Frontend/src/app/admin/webhooks/dlq/page.tsx` | Server-component shell — RBAC guard, layout, ErrorBoundary, suspense wrapper |
| `Frontend/src/app/admin/webhooks/dlq/WebhookDlqClient.tsx` | Client-component: state mgmt, filters, table, dialog orchestration |
| `Frontend/src/app/admin/webhooks/dlq/actions.ts` | Server actions: `listDlqEntriesAction`, `replayDlqEntryAction`, `abandonDlqEntryAction` |
| `Frontend/src/components/admin/webhooks/DlqTable.tsx` | Pure-presentation table: columns id/adapter/event_type/target_hash/attempt/error/created/status; per-row action menu |
| `Frontend/src/components/admin/webhooks/ReplayDialog.tsx` | Dialog: typed-confirm `event_id`, reason textarea, submit button, error/success banner |
| `Frontend/src/components/admin/webhooks/AbandonDialog.tsx` | Dialog: typed-confirm `event_id`, reason textarea, submit button, error/success banner |
| `Frontend/src/lib/adminWebhookDlq.ts` | Closed taxonomy: `WEBHOOK_DLQ_FAILURE_TAXONOMY`, `extractWebhookDlqActionCode`, `webhookDlqActionErrorMessage`, RU error dict, Zod schemas |
| `Frontend/src/lib/adminWebhookDlq.test.ts` | Vitest для taxonomy + extractor (mirror `adminSchedules.test.ts`) |
| `Frontend/src/app/admin/AdminLayoutClient.tsx` | Extend NAV: `{ href: "/admin/webhooks/dlq", label: "Webhooks DLQ" }` |

**Closed-taxonomy lib (`adminWebhookDlq.ts`) — mirror Batch 4 `adminSchedules.ts`:**

```typescript
export const WEBHOOK_DLQ_FAILURE_TAXONOMY = [
  "unauthorized",
  "forbidden",
  "tenant_required",
  "tenant_mismatch",
  "dlq_entry_not_found",
  "already_replayed",
  "already_abandoned",
  "replay_failed",
  "rate_limited",
  "validation_failed",
  "store_unavailable",
  "server_error",
  "network_error",
] as const;

export const WebhookDlqFailureCodeSchema = z.enum(WEBHOOK_DLQ_FAILURE_TAXONOMY);
export type WebhookDlqFailureCode = z.infer<typeof WebhookDlqFailureCodeSchema>;

export class WebhookDlqActionError extends Error {
  readonly code: WebhookDlqFailureCode;
  readonly status: number | null;
  constructor(code: WebhookDlqFailureCode, status: number | null = null) {
    super(code);
    this.name = "WebhookDlqActionError";
    this.code = code;
    this.status = status;
  }
}

export function extractWebhookDlqActionCode(
  err: unknown,
): WebhookDlqFailureCode | null {
  if (err instanceof WebhookDlqActionError) return err.code;
  if (typeof err !== "object" || err === null) return null;
  const candidate = err as { code?: unknown; message?: unknown };
  const taxonomy = WEBHOOK_DLQ_FAILURE_TAXONOMY as readonly string[];
  if (typeof candidate.code === "string" && taxonomy.includes(candidate.code)) {
    return candidate.code as WebhookDlqFailureCode;
  }
  if (typeof candidate.message === "string") {
    const trimmed = candidate.message.trim();
    if (taxonomy.includes(trimmed)) {
      return trimmed as WebhookDlqFailureCode;
    }
  }
  return null;
}
```

(Полное содержимое — см. §6 "Closed taxonomy" с `ERROR_MESSAGES_RU` mapping.)

**Acceptance criteria (>= 9):**
- (a) `/admin/webhooks/dlq` рендерится для admin (own tenant) с list rows того тенанта; для super-admin — cross-tenant с tenant-selector dropdown.
- (b) Filters: `status`, `adapter_name`, `created_after/before` — каждое изменение filter -> server-action re-fetch -> table updates.
- (c) Per-row "Replay" action -> ReplayDialog: `event_id` typed-confirm (paste-disabled), `reason` textarea (>= 10 chars, <= 500), submit -> `replayDlqEntryAction` -> success banner OR error banner с RU message из `WEBHOOK_DLQ_FAILURE_TAXONOMY`.
- (d) Per-row "Abandon" action -> AbandonDialog: same UX но action -> `abandonDlqEntryAction`.
- (e) Server actions используют `extractWebhookDlqActionCode` (НЕ `instanceof WebhookDlqActionError`) для error mapping (mirrors batch 4 `extractScheduleActionCode` pattern; commit `acf6f76` в Batch 4 fixed это уже).
- (f) Audit emit на каждый replay/abandon — backend (T39) уже эмитит `webhook_dlq.{replay,abandon}` через `_emit_audit`; frontend success banner отображает `audit_id` для traceability.
- (g) Таблица RBAC: super-admin видит column `tenant_id`; admin не видит (column hidden когда `userRole !== "super-admin"`).
- (h) A11y: dialogs имеют focus-trap (стандартный Radix UI pattern), Esc closes, button labels с `aria-label` для screen readers.
- (i) >= 18 vitest cases (DlqTable rendering, ReplayDialog typed-confirm gates, AbandonDialog reason validation, error mapping happy/all-codes, RBAC column visibility, filter state mgmt).

**Test minima:**
- Unit (vitest): 18.
  - `WebhookDlqClient.test.tsx`: 6 (initial render, filter state, RBAC column visibility, error banner, success banner, refresh).
  - `ReplayDialog.test.tsx`: 6 (typed-confirm gate, paste-disabled, reason length validation, submit happy, submit error, focus management).
  - `AbandonDialog.test.tsx`: 4 (same shape but no replay-specific paths).
  - `adminWebhookDlq.test.ts`: 4 (taxonomy enum, `extractWebhookDlqActionCode` через `instanceof` / `code` / `message` / fallback).
- E2E (functional, Playwright): 8 (`admin-webhooks-dlq.spec.ts`):
  - List rendering для admin own tenant.
  - List rendering для super-admin cross-tenant + tenant selector switch.
  - Filter change refresh.
  - Replay happy path (mock backend says 2xx) -> success banner.
  - Replay failed path (mock backend uses sentinel `https://webhook.failtest.invalid/*` -> always 5xx) -> "replay_failed" banner.
  - Abandon happy path.
  - Cross-tenant probe (admin tries replay other tenant entry) -> hidden in UI (RBAC client-side guard).
  - Audit-trail entry visible на `/admin/audit-logs` после replay (cross-spec sanity check).
- E2E (axe): 3 scenarios in `admin-axe.spec.ts`:
  - 1 route scan: `/admin/webhooks/dlq` table view (под `test.fail()` ISS-T26-001 — accent-on-dark CTA).
  - 1 dialog state: ReplayDialog open (под `test.fail()` ISS-T26-001 — confirm CTA `bg-amber-600` или `bg-[var(--accent)]`).
  - 1 dialog state: AbandonDialog open (под `test.fail()` ISS-T26-001 — destructive CTA `bg-red-600`).
- **Total: 18 vitest + 8 functional E2E + 3 axe E2E = 29 frontend tests.**

**Files to touch (estimated 9):**
- `Frontend/src/app/admin/webhooks/dlq/page.tsx` (NEW)
- `Frontend/src/app/admin/webhooks/dlq/WebhookDlqClient.tsx` (NEW)
- `Frontend/src/app/admin/webhooks/dlq/WebhookDlqClient.test.tsx` (NEW)
- `Frontend/src/app/admin/webhooks/dlq/actions.ts` (NEW)
- `Frontend/src/components/admin/webhooks/DlqTable.tsx` (NEW)
- `Frontend/src/components/admin/webhooks/ReplayDialog.tsx` (NEW)
- `Frontend/src/components/admin/webhooks/ReplayDialog.test.tsx` (NEW)
- `Frontend/src/components/admin/webhooks/AbandonDialog.tsx` (NEW)
- `Frontend/src/components/admin/webhooks/AbandonDialog.test.tsx` (NEW)
- `Frontend/src/lib/adminWebhookDlq.ts` (NEW)
- `Frontend/src/lib/adminWebhookDlq.test.ts` (NEW)
- `Frontend/src/app/admin/AdminLayoutClient.tsx` (1-line NAV diff)
- `Frontend/tests/e2e/admin-webhooks-dlq.spec.ts` (NEW)
- `Frontend/tests/e2e/admin-axe.spec.ts` (extend with 3 scenarios)
- `Frontend/tests/e2e/fixtures/admin-backend-mock.ts` (extend — see §8)

**Architectural notes:**
- Reuse `getServerAdminSession` + `callAdminBackendJson` (canonical Batch 2-4 pattern).
- `WebhookDlqClient.tsx` - "use client"; `page.tsx` - server-component shell с RBAC guard (`getServerAdminSession` -> redirect to `/admin/forbidden`).
- DlqTable colors / CTA reuse existing tokens — no new design-token decisions (ISS-T26-001 carry-over).
- ReplayDialog typed-confirm pattern скопирован из `Frontend/src/app/admin/operations/GlobalKillSwitchClient.tsx` (T30).
- Pagination использует server-side `limit/offset/total` из T39 response.

**Commit message:** `feat(admin): webhook DLQ triage UI (/admin/webhooks/dlq) (T41)`

---

### T42 — Kyverno cluster policy YAML

**Goal:** Cluster-side admission gate, отрицающий любой Pod, чьи images (a) не подписаны cosign keyless через GHA OIDC OR (b) не задаются в `@sha256:<digest>` форме.

**Backend / Frontend split:** 0% backend / 0% frontend; 100% IaC (YAML).

**Policy sketch (`infra/kyverno/cluster-policy-require-signed-images.yaml`):**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: argus-require-signed-images
  annotations:
    policies.kyverno.io/title: ARGUS — require Cosign-signed images with digest
    policies.kyverno.io/category: Software Supply Chain Security
    policies.kyverno.io/severity: high
    policies.kyverno.io/subject: Pod
    policies.kyverno.io/minversion: 1.16.0
    policies.kyverno.io/description: |
      Closes ARG-054. Every workload image must (a) be signed by Sigstore
      Cosign keyless attestation issued via GitHub Actions OIDC for the
      ARGUS organisation, and (b) reference a sha256 digest. Tag-only
      references are immutable-vulnerable and rejected.
spec:
  validationFailureAction: Enforce
  background: false
  webhookTimeoutSeconds: 30
  rules:
    - name: verify-cosign-signed
      match:
        any:
          - resources:
              kinds:
                - Pod
                - Deployment
                - StatefulSet
                - DaemonSet
                - Job
                - CronJob
      verifyImages:
        - imageReferences:
            - "*"
          required: true
          verifyDigest: true
          mutateDigest: false
          attestors:
            - count: 1
              entries:
                - keyless:
                    subject: "https://github.com/your-org/ARGUS/.github/workflows/*"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: "https://rekor.sigstore.dev"
```

**Acceptance criteria (>= 4):**
- (a) `kubectl apply -f infra/kyverno/cluster-policy-require-signed-images.yaml` succeeds после Kyverno install (T44 CI gate verifies).
- (b) `validationFailureAction: Enforce` — policy blocks (НЕ только warns).
- (c) `verifyDigest: true` AND `required: true` — оба требуют одновременно signed AND digest-pinned.
- (d) `keyless.issuer` matches GHA OIDC issuer (соответствует `cosign.verify.keyless.certificateOidcIssuer` в `values.yaml:141`); `keyless.subject` regex покрывает все ARGUS GHA workflows.
- (e) Kyverno minversion `1.16.0` соответствует chart pin 3.6.4 (см. D-5).

**Test minima:**
- 0 unit/integration в этой задаче — всё verification в T44 CI gate.

**Files to touch (estimated 2):**
- `infra/kyverno/cluster-policy-require-signed-images.yaml` (NEW)
- `infra/kyverno/README.md` (NEW, 30 LoC — pointer на `docs/admission-policy.md` + how to apply manually)

**Architectural notes:**
- `mutateDigest: false` — мы НЕ хотим, чтобы Kyverno auto-добавлял digest; это спрятало бы наследие неподписанных deploy-spec и противоречит T43 expectation что operator явно указывает digest.
- `keyless.subject` regex должен включать ВСЕ workflow paths которые подписывают images — включая будущий `.github/workflows/admission-policy-kind.yml` сам.
- Owner organization `your-org` placeholder — в реальном PR заменяется на актуальный GitHub org-name.

**Commit message:** `feat(infra): Kyverno ClusterPolicy require-signed-images (T42, ARG-054)`

---

### T43 — Helm `policy.enabled` flag + conditional template

**Goal:** Opt-in deployment cluster-policy через Helm flag, чтобы существующие `helm upgrade` workflows НЕ ломались на первом deploy после Batch 5 merge.

**Backend / Frontend split:** 0% / 0%; 100% IaC.

**Values extension (`infra/helm/argus/values.yaml`):**

```yaml
# ── Admission policy (Kyverno ClusterPolicy require-signed-images) ───────────
# When enabled, the chart renders the Kyverno ClusterPolicy that requires
# every Pod's image to be Cosign-signed (GHA OIDC keyless) AND digest-pinned.
# Default: false — flipping this to `true` BLOCKS unsigned images cluster-wide,
# so it must be opt-in. CI sets it to `true` for the policy-test job (T44).
# Mirrors the `cosign.verify.enabled` opt-in pattern (init-container side).
policy:
  enabled: false
  kyverno:
    # Path resolved relative to the chart root.
    policyFile: "kyverno/cluster-policy-require-signed-images.yaml"
```

**Template extension (`infra/helm/argus/templates/kyverno-cluster-policy.yaml`):**

```yaml
{{- if .Values.policy.enabled -}}
{{- $policy := .Files.Get .Values.policy.kyverno.policyFile -}}
{{- if not $policy -}}
  {{- fail (printf "policy.kyverno.policyFile not found: %s" .Values.policy.kyverno.policyFile) -}}
{{- end -}}
---
{{ $policy }}
{{- end -}}
```

**Note: `infra/kyverno/cluster-policy-require-signed-images.yaml` лежит ВНЕ chart-tree; чтобы `.Files.Get` нашёл его, ритуал — symlink `infra/helm/argus/kyverno/cluster-policy-require-signed-images.yaml -> ../../../kyverno/cluster-policy-require-signed-images.yaml`** (на Windows — это файл-копия + Makefile-rule sync; на Linux/macOS — symlink). Альтернатива — встроить policy YAML inline в template (более громоздко но cross-platform). **Решение: симлинк через Makefile + проверка в pre-commit / CI**.

Если симлинк/копия слишком хрупкий, fallback — генерировать YAML через Helm `tpl` функцию из inline-string в template:

```yaml
{{- if .Values.policy.enabled -}}
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: argus-require-signed-images
  ...
{{- end -}}
```

**Acceptance criteria (>= 4):**
- (a) `helm template . --set policy.enabled=false` renders 0 ClusterPolicy resources.
- (b) `helm template . --set policy.enabled=true` renders 1 ClusterPolicy resource с правильным `metadata.name` и `spec.rules[0].verifyImages[0].attestors[0].entries[0].keyless.issuer`.
- (c) `kubeconform` (existing `helm-validation.yml`) проходит с обоими values (`enabled=false` AND `enabled=true`); добавить Kyverno schema в `KUBECONFORM_SCHEMA_LOCATIONS` если требуется (`https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/kyverno.io/clusterpolicy_v1.json` — public CRD schema).
- (d) Default `policy.enabled: false` сохраняется в values.yaml — никакая overlay без явного override не активирует policy.

**Test minima:**
- 0 unit/integration; smoke verification:
  - `helm template` оба values (CI step в `admission-policy-kind.yml`).
  - `kubeconform` проход (extension в существующем `helm-validation.yml`).

**Files to touch (estimated 3):**
- `infra/helm/argus/values.yaml` (extend — `policy:` section)
- `infra/helm/argus/templates/kyverno-cluster-policy.yaml` (NEW)
- `infra/helm/argus/values-prod.yaml` (extend — `policy.enabled: true` для prod overlay; sealed by senior reviewer на release-time)

**Architectural notes:**
- Mirrors `cosign.verify.enabled: true` opt-in pattern — оба supply-chain features feature-flag enabled.
- Default `false` критично: первый PR merging Batch 5 НЕ должен ломать deploy для users которые ещё не подписали images.
- Prod overlay (`values-prod.yaml`) flippable to `true` после того, как все production images подписаны cosign — это dependency на cycle-5 supply-chain work (`infra/scripts/sign_images.sh`).

**Commit message:** `feat(helm): policy.enabled flag + conditional Kyverno template (T43)`

---

### T44 — kind CI gate `policy-test`

**Goal:** Automated CI verification что (a) policy applies clean, (b) unsigned image deny возвращает 403, (c) signed-with-digest image deploy возвращает 0/201.

**Backend / Frontend split:** 0% / 0%; 100% CI workflow YAML.

**Workflow sketch (`.github/workflows/admission-policy-kind.yml`):**

```yaml
# ──────────────────────────────────────────────────────────────────────────────
# T44 (Cycle 6 Batch 5) — Kyverno admission policy kind CI gate.
# ──────────────────────────────────────────────────────────────────────────────
# Validates that the ARG-054 Kyverno ClusterPolicy (T42) deny-lists unsigned
# images and accepts cosign-signed digest-pinned images. Provides supply-chain
# regression coverage BEFORE production rollout.
#
# Negative fixture: `nginx:1.27.0` — Docker-Hub image without Cosign signature
# AND without sha256 digest — fails on BOTH policy checks simultaneously.
#
# Positive fixture: built and signed in this workflow itself via cosign keyless
# (GHA OIDC) — `ghcr.io/${{ github.repository_owner }}/argus-policy-fixture`.
# Pinned to the workflow's commit SHA so each PR rebuilds its own fixture.

name: Admission policy (Kyverno + kind)

on:
  pull_request:
    branches: [main, develop]
    paths:
      - "infra/kyverno/**"
      - "infra/helm/argus/templates/kyverno-cluster-policy.yaml"
      - "infra/helm/argus/values*.yaml"
      - ".github/workflows/admission-policy-kind.yml"
  push:
    branches: [main]
    paths: [...same...]
  workflow_dispatch: {}

permissions:
  contents: read
  packages: write   # build+push positive fixture to GHCR
  id-token: write   # cosign keyless via GHA OIDC

concurrency:
  group: admission-policy-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

env:
  KIND_VERSION: v0.24.0
  KIND_K8S_VERSION: v1.31.0
  KYVERNO_CHART_VERSION: 3.6.4
  COSIGN_RELEASE: v3.0.5
  POLICY_NAME: argus-require-signed-images
  FIXTURE_REPO: ghcr.io/${{ github.repository_owner }}/argus-policy-fixture
  NEGATIVE_IMAGE: nginx:1.27.0

jobs:
  policy-test:
    name: Kyverno policy-test on kind k8s ${{ env.KIND_K8S_VERSION }}
    runs-on: ubuntu-latest
    timeout-minutes: 25

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up kind ${{ env.KIND_VERSION }} (k8s ${{ env.KIND_K8S_VERSION }})
        uses: helm/kind-action@v1
        with:
          version: ${{ env.KIND_VERSION }}
          node_image: kindest/node:${{ env.KIND_K8S_VERSION }}
          cluster_name: argus-policy-test
          wait: 90s

      - name: Set up helm v3.14.4 (matches helm-validation.yml)
        uses: azure/setup-helm@v4
        with:
          version: "v3.14.4"

      - name: Install Kyverno chart ${{ env.KYVERNO_CHART_VERSION }}
        run: |
          set -euo pipefail
          helm repo add kyverno https://kyverno.github.io/kyverno/
          helm repo update
          helm install kyverno kyverno/kyverno \
            --version "${KYVERNO_CHART_VERSION}" \
            --namespace kyverno \
            --create-namespace \
            --wait \
            --timeout 5m

      - name: Apply ARGUS ClusterPolicy
        run: |
          set -euo pipefail
          kubectl apply -f infra/kyverno/cluster-policy-require-signed-images.yaml
          kubectl wait --for=condition=Ready --timeout=2m \
            clusterpolicy/${POLICY_NAME}

      - name: Install Cosign ${{ env.COSIGN_RELEASE }}
        uses: sigstore/cosign-installer@v4.1.0
        with:
          cosign-release: ${{ env.COSIGN_RELEASE }}

      - name: Log in to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build + push positive fixture image
        id: build
        run: |
          set -euo pipefail
          mkdir -p fixture && cat > fixture/Dockerfile <<'EOF'
          FROM gcr.io/distroless/static-debian12@sha256:0000  # replaced by digest
          ENTRYPOINT ["/usr/bin/true"]
          EOF
          # ... resolve real distroless digest, push, capture full ref
          IMG_REF="${FIXTURE_REPO}:${{ github.sha }}"
          docker build -t "${IMG_REF}" fixture/
          docker push "${IMG_REF}"
          DIGEST=$(docker inspect "${IMG_REF}" --format '{{ index .RepoDigests 0 }}')
          echo "image_digest=${DIGEST}" >> "$GITHUB_OUTPUT"

      - name: Cosign-sign positive fixture (keyless via GHA OIDC)
        run: |
          set -euo pipefail
          cosign sign --yes "${{ steps.build.outputs.image_digest }}"

      - name: Negative deploy MUST be denied (unsigned tag-only image)
        id: negative
        run: |
          set +e
          OUT=$(kubectl run policy-test-negative \
            --image="${NEGATIVE_IMAGE}" \
            --restart=Never \
            --dry-run=server -o yaml 2>&1)
          RC=$?
          set -e
          echo "${OUT}" >> kubectl-negative.log
          if [[ $RC -eq 0 ]]; then
            echo "::error::Negative test FAILED — unsigned image was accepted"
            exit 1
          fi
          if ! echo "${OUT}" | grep -q "${POLICY_NAME}"; then
            echo "::error::Denied but not by ${POLICY_NAME}"
            exit 1
          fi
          echo "Negative test PASSED — policy correctly denied unsigned image"

      - name: Positive deploy MUST succeed (signed + digest)
        run: |
          set -euo pipefail
          kubectl run policy-test-positive \
            --image="${{ steps.build.outputs.image_digest }}" \
            --restart=Never \
            --dry-run=server -o yaml \
            > kubectl-positive.log
          echo "Positive test PASSED — policy correctly allowed signed+digest image"

      - name: Collect Kyverno + kube events for forensics
        if: always()
        run: |
          set +e
          kubectl get events --all-namespaces -o wide > kube-events.log
          kubectl logs -n kyverno -l app.kubernetes.io/component=admission-controller --tail=500 \
            > kyverno-admission.log

      - name: Upload artefacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: admission-policy-kind-logs
          path: |
            kubectl-*.log
            kube-events.log
            kyverno-admission.log
          if-no-files-found: ignore
          retention-days: 14
```

**Acceptance criteria (>= 5):**
- (a) Kind cluster v1.31.0 поднимается, Kyverno chart 3.6.4 устанавливается без ошибок.
- (b) `kubectl apply` policy успешен; `kubectl wait` finds `Ready` condition в течение 2 минут.
- (c) Negative deploy (unsigned `nginx:1.27.0`) -> non-zero RC AND output содержит policy name `argus-require-signed-images`.
- (d) Positive deploy (signed + digest fixture) -> zero RC; `kubectl run --dry-run=server` returns Pod manifest.
- (e) Workflow run-time <= 25 min p95 (no timeouts на cold-start).

**Test minima:**
- 0 unit; integration verification — это сам workflow.

**Files to touch (estimated 3):**
- `.github/workflows/admission-policy-kind.yml` (NEW)
- `.github/workflows/helm-validation.yml` (extend — добавить Kyverno CRD schema URL в `KUBECONFORM_SCHEMA_LOCATIONS` для T43 кубконформа с `policy.enabled=true`)
- `infra/scripts/build_policy_fixture.sh` (NEW, ~30 LoC — extracted из workflow для local re-runs)

**Architectural notes:**
- Build-and-sign-in-workflow pattern (D-6) — никаких внешних third-party signed images, нет dependency на чужие GHA artifacts; полная детерминированность.
- `--dry-run=server` НЕ создаёт реальный Pod — только проверяет admission-time validation; идеально для CI gate (cleanup-free).
- Permissions `id-token: write` обязательно для Cosign keyless (GHA OIDC token).
- Distroless base image (`gcr.io/distroless/static-debian12`) — минимальный fixture, не использует ненужные shell/utils.
- Concurrency group cancels previous PR runs to save runner minutes.

**Commit message:** `ci: kind-based Kyverno admission-policy gate (T44)`

---

### T45 — Документация: `docs/admission-policy.md` (EN) + `docs/webhook-dlq.md` (RU)

**Goal:** Operator + devops runbooks для двух новых поверхностей.

**Backend / Frontend split:** 0%; 100% docs.

**`docs/admission-policy.md` (English, devops-facing) — outline:**

```markdown
# Kyverno Admission Policy: require-signed-images (ARG-054)

## What it does
Blocks any Pod whose images are not (a) Cosign-signed via GitHub Actions
OIDC keyless attestation and (b) referenced by `@sha256:<digest>`.

## When to enable
- Production environments AFTER all chart images have been signed by
  `infra/scripts/sign_images.sh` (Cycle 4 ARG-033).
- Set `policy.enabled: true` in `values-prod.yaml`.

## How to opt in
```bash
helm upgrade --install argus ./infra/helm/argus \
  --values infra/helm/argus/values-prod.yaml \
  --set policy.enabled=true
```

## How to debug a denied deployment
- Inspect Kyverno admission controller logs:
  `kubectl logs -n kyverno -l app.kubernetes.io/component=admission-controller`
- Common failure modes: ...
- Whitelisting (NOT recommended): ...

## How to update fixture / sign a new image
- Use `infra/scripts/sign_images.sh` (Cycle 4 ARG-033 pattern).
- For CI test fixture, see `.github/workflows/admission-policy-kind.yml`.

## Rollback
- Set `policy.enabled: false` and `helm upgrade` — policy resource removed.
- Existing Pods NOT affected (admission-time only).
```

**`docs/webhook-dlq.md` (Russian, operator-facing) — outline:**

```markdown
# Webhook Dead-Letter Queue (DLQ) — операторский runbook (ARG-053)

## Что это и зачем
DLQ — это persistent table `webhook_dlq_entries`, куда попадают
все webhook-доставки (Slack/Linear/Jira/...), исчерпавшие retry-budget
внутри `NotifierBase.send_with_retry`. UI: `/admin/webhooks/dlq`.

## Когда смотреть DLQ
- Утром после daily Celery beat replay (06:00 UTC).
- При алерте `argus_webhook_dlq_replay_processed{result="failed"} > 0`.
- При жалобе пользователя "уведомление не пришло".

## Что значит каждый error_code
- `timeout` — upstream не ответил за timeout window. Replay безопасен.
- `network_error` — TCP-ошибка. Замерьте upstream через `curl`, replay.
- `http_4xx` — 4xx, не-retriable. Скорее всего payload broken — abandon.
- `http_5xx` — upstream сбой. Replay через час-два после resolve.
- `circuit_open` — circuit breaker активен. НЕ трогайте — авто-resolve.

## Когда replay безопасен
- Adapter имеет idempotency dedup window (см. `_BoundedRecentSet`)
  — повторная отправка дубликатов отбрасывается на upstream-side.
- Если payload был uniquely identified `event_id`, replay не создаст
  duplicate в Slack/Linear/Jira.

## Когда abandon оправдан
- `last_error_code = "http_4xx"` AND `last_status_code in {400, 401, 403}`
  — payload или auth broken; replay не поможет.
- Old entry, recipient канал/issue удалён upstream.
- `attempt_count >= 8` AND ничего не меняется — manual abandon с
  `reason="payload_invalid"` для трасировки.

## Что попадает в audit
- `webhook_dlq.replay` — детали `{entry_id, success, attempt_count, reason}`.
- `webhook_dlq.abandon` — детали `{entry_id, reason}`.
- Записи immutable (audit chain).

## Auto-abandon (14 дней)
- Daily beat task `argus.notifications.webhook_dlq_replay` помечает любой
  pending entry с age >= 14 дней как `abandoned_at = now, abandoned_reason = "max_age"`.
- Этот entry больше НЕ replay-ит-ся; UI показывает его в filter `status=abandoned`.

## RBAC
- admin: видит/replay/abandon только свой tenant.
- super-admin: cross-tenant + tenant-selector.
```

**Acceptance criteria (>= 4):**
- (a) `docs/admission-policy.md` ≥ 200 lines, на английском, содержит секции "What", "When to enable", "Opt-in command", "Debug", "Sign new image", "Rollback".
- (b) `docs/webhook-dlq.md` ≥ 250 lines, на русском, содержит секции "Что это", "Когда смотреть", "error_code dictionary", "Replay safety", "Abandon decision", "Audit", "Auto-abandon", "RBAC".
- (c) Оба документа cross-link между собой (admission-policy упоминает что webhook-deploys тоже под admission gate; webhook-dlq упоминает что replay reuses NotifierBase).
- (d) Cross-link на: `Backlog/dev1_finalization_roadmap.md` §Batch 5, `ai_docs/develop/plans/2026-04-22-argus-cycle6-b5.md`, `ai_docs/develop/issues/ISS-cycle6-batch5-carry-over.md` (создаётся в Phase 4 documenter).

**Test minima:**
- markdown linter (`markdownlint-cli` если в репо есть) на оба файла; 0 errors.
- Spell-check (optional; `cspell`) на EN doc.

**Files to touch (estimated 2):**
- `docs/admission-policy.md` (NEW)
- `docs/webhook-dlq.md` (NEW)

**Architectural notes:**
- Bilingualism: mirror `docs/e2e-testing.md` (RU operator-facing) vs `docs/architecture-*.md` (EN devops-facing).
- НЕ дублировать схему таблицы — ссылка на migration `027_webhook_dlq.py`.

**Commit message:** `docs: admission policy + webhook DLQ runbooks (T45)`

---

## 6. Архитектурные решения

### Decision: Migration revision 027 (deviation D-1)
- **Контекст:** roadmap §Batch 5 называет миграцию `025_webhook_dlq.py`. Revision 025 (`tenant_limits_overrides`) на диске с Batch 2 T13; revision 026 (`scan_schedules`) на диске с Batch 4 T32.
- **Решение:** ship as revision `027`, down_revision `026`.
- **Прецедент:** Batch 4 уже сделал ту же deviation (T32 ship as 026 вместо roadmap-supplied 024) — каноничный шаблон в `026_scan_schedules.py:15-22`.

### Decision: `webhook_dlq_entries` schema (T37)
- **Columns:** `id (PK)`, `tenant_id (FK)`, `adapter_name`, `event_type`, `event_id`, `target_url_hash` (NEVER raw URL), `payload_json`, `last_error_code`, `last_status_code`, `attempt_count`, `next_retry_at`, `replayed_at`, `abandoned_at`, `abandoned_reason`, `created_at`, `updated_at`.
- **Constraints:** UNIQUE `(tenant_id, adapter_name, event_id)` — re-enqueue одного событа idempotent.
- **Indexes:** 
  - `ix_webhook_dlq_tenant_status (tenant_id, abandoned_at, replayed_at)` — hot path для admin list.
  - `ix_webhook_dlq_next_retry_at (next_retry_at) WHERE abandoned_at IS NULL AND replayed_at IS NULL` — partial для Celery beat scan (Postgres-only; SQLite — plain index).
  - `ix_webhook_dlq_created_at (created_at)` — sort + 14-day age scan.
- **RLS:** `tenant_isolation` policy + `FORCE ROW LEVEL SECURITY` (mirrors 026).

### Decision: Co-locate `webhook_dlq_persistence.py` с notification adapters (deviation D-2)
- **Контекст:** roadmap §T38 указывает `backend/src/notifications/...` — папка не существует.
- **Решение:** разместить файл по пути `backend/src/mcp/services/notifications/webhook_dlq_persistence.py` рядом с существующими `_base.py`, `dispatcher.py`, `slack.py`.
- **Обоснование:** module boundary "notification subsystem" уже зафиксирован в репо как `mcp/services/notifications/`; новая top-level папка усложнит навигацию и повторяет concept.

### Decision: Closed-taxonomy errors `WEBHOOK_DLQ_FAILURE_TAXONOMY` (T39 + T41)
- **Контекст:** Admin Frontend XL pattern требует closed enum для всех server-action errors (Batch 2/3/4).
- **Решение:** 13-element enum (см. §7); mirror `SCHEDULE_FAILURE_TAXONOMY` shape; реализация в `Frontend/src/lib/adminWebhookDlq.ts` с `extractWebhookDlqActionCode` extractor (Next.js Server Action serialization-safe; см. Batch 4 commit `acf6f76`).

### Decision: Mock-backend sentinel `webhook_url ~= "https://webhook.failtest.invalid/*"` (T41 E2E)
- **Контекст:** для детерминистичного "replay always fails" E2E нужно избежать real network OR time-mocking.
- **Решение:** mock backend (`admin-backend-mock.ts`) при handler `POST /admin/webhooks/dlq/{id}/replay`:
  - Если entry.target_url_hash matches фиктивный hash для `webhook.failtest.invalid` -> return 202 + `{success: false, message_code: "replay_failed", attempt_count: incremented}`.
  - В остальных случаях return 202 + `{success: true, message_code: "replay_succeeded"}`.
- **См.** §8 для полной handler signature.

### Decision: Default `policy.enabled=false` в Helm (T43)
- **Контекст:** flipping admission policy on cluster-wide ломает any deploy с unsigned/no-digest images.
- **Решение:** default `false` для backward-compat existing `helm upgrade` workflows; CI policy-test job sets `--set policy.enabled=true`; `values-prod.yaml` flippable on release-time.
- **Обоснование:** mirror existing `cosign.verify.enabled` opt-in pattern (init-container side) и `existingSecret`/`existingConfigMap` opt-in convention из `values.yaml:243-261`.

### Decision: Kyverno chart pin 3.6.4 + test image strategy (D-5 + D-6)
- **Chart pin:** `3.6.4` (Kyverno application 1.16.x) — supports K8s 1.31 (matches `helm-validation.yml` matrix top).
- **Negative fixture:** `nginx:1.27.0` (no signature, no digest — fails both policy checks simultaneously).
- **Positive fixture:** билдится+подписывается прямо в `admission-policy-kind.yml` workflow через `sigstore/cosign-installer@v4.1.0` keyless GHA OIDC -> `ghcr.io/${{ github.repository_owner }}/argus-policy-fixture:${{ github.sha }}@sha256:<digest>`. Это даёт детерминированность без зависимости от third-party signed images.

---

## 7. Closed taxonomy: `WEBHOOK_DLQ_FAILURE_TAXONOMY`

13 codes. Каждый имеет russian-language operator message (для frontend ErrorBanner) AND backend HTTP mapping.

| Code | HTTP | Backend trigger | RU message (frontend) |
|------|------|-----------------|----------------------|
| `unauthorized` | 401 | Missing/invalid `X-Admin-Key` (production gate) | "Сессия истекла. Войдите заново." |
| `forbidden` | 403 | Operator role insufficient (operator -> 403) | "Недостаточно прав для управления DLQ этого tenant." |
| `tenant_required` | 403 | Admin role без `X-Admin-Tenant` header | "Не указан tenant. Admin обязан выбрать tenant; super-admin — оставить пустым для cross-tenant." |
| `tenant_mismatch` | 403 | Admin role с `X-Admin-Tenant != entry.tenant_id` | "X-Admin-Tenant не совпадает с tenant записи DLQ." |
| `dlq_entry_not_found` | 404 | `get_by_id` returns None OR cross-tenant probe (existence-leak protection) | "Запись DLQ не найдена." |
| `already_replayed` | 409 | `mark_replayed` raises `AlreadyTerminalError` для replayed row | "Запись уже была успешно повторена." |
| `already_abandoned` | 409 | `mark_replayed` / `mark_abandoned` raises `AlreadyTerminalError` для abandoned row | "Запись уже была отброшена." |
| `replay_failed` | 200 (с `success=false` в body) | `NotifierBase.send_with_retry` returns `delivered=False`; `increment_attempt` called | "Повтор не удался; попытка засчитана. Запись остаётся в DLQ." |
| `rate_limited` | 429 | Future: per-operator rate-limit | "Слишком много запросов. Повторите попытку через минуту." |
| `validation_failed` | 422 | Pydantic validation: `reason` < 10 chars OR > 500 chars OR malformed UUID | "Неверные параметры запроса. Проверьте обоснование (10-500 символов)." |
| `store_unavailable` | 503 | DB / Redis / dispatcher временно недоступен (callAdminBackendJson collapses transport errors) | "Backend временно недоступен. Повторите попытку через минуту." |
| `server_error` | 500 | Unhandled (default for unknown HTTP) | "Не удалось выполнить операцию. Повторите попытку." |
| `network_error` | n/a (client-side fetch failure) | `callAdminBackendJson` throws before HTTP code | "Сеть недоступна. Проверьте соединение и повторите попытку." |

**Status mapping helper (`statusToWebhookDlqActionCode`):**

```typescript
export function statusToWebhookDlqActionCode(
  status: number,
): WebhookDlqFailureCode {
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 404) return "dlq_entry_not_found";
  if (status === 409) return "already_replayed";  // override via detailToWebhookDlqActionCode
  if (status === 422) return "validation_failed";
  if (status === 429) return "rate_limited";
  if (status === 503) return "store_unavailable";
  return "server_error";
}
```

**Detail-token mapping (`detailToWebhookDlqActionCode`):**

```typescript
export function detailToWebhookDlqActionCode(
  detail: string,
): WebhookDlqFailureCode | null {
  const map: Record<string, WebhookDlqFailureCode> = {
    forbidden: "forbidden",
    tenant_required: "tenant_required",
    tenant_mismatch: "tenant_mismatch",
    dlq_entry_not_found: "dlq_entry_not_found",
    already_replayed: "already_replayed",
    already_abandoned: "already_abandoned",
    replay_failed: "replay_failed",
  };
  return map[detail] ?? null;
}
```

---

## 8. API surface contract

### `GET /admin/webhooks/dlq`

| Aspect | Value |
|--------|-------|
| **Method / Path** | `GET /admin/webhooks/dlq` |
| **Query params** | `status?: "pending"|"replayed"|"abandoned"`, `adapter_name?: string`, `created_after?: ISO8601`, `created_before?: ISO8601`, `limit?: int(1..200, default=50)`, `offset?: int(>=0, default=0)` |
| **Request body** | none |
| **Request schema (Pydantic)** | n/a (query-only) |
| **Response (200)** | `WebhookDlqListResponse` `{items: WebhookDlqEntryItem[], total: int, limit: int, offset: int}` |
| **Error codes (closed taxonomy)** | 401 `unauthorized` • 403 `forbidden` / `tenant_required` • 422 `validation_failed` • 503 `store_unavailable` • 500 `server_error` |
| **RBAC matrix** | operator -> 403 • admin -> own tenant only (X-Admin-Tenant required) • super-admin -> any tenant (X-Admin-Tenant optional, filters when provided) |
| **Headers required** | `X-Admin-Key` (always); `X-Admin-Role` (mirror); `X-Admin-Tenant` (admin: required; super-admin: optional); `X-Operator-Subject` (audit attribution) |

### `POST /admin/webhooks/dlq/{entry_id}/replay`

| Aspect | Value |
|--------|-------|
| **Method / Path** | `POST /admin/webhooks/dlq/{entry_id}/replay` |
| **Path param** | `entry_id: UUID` |
| **Request body (Pydantic)** | `WebhookDlqReplayRequest` `{reason: str (10..500 chars)}` |
| **Response (202)** | `WebhookDlqReplayResponse` `{entry_id: UUID, success: bool, attempt_count: int, new_status: "replayed"|"pending", audit_id: UUID, message_code: "replay_succeeded"|"replay_failed"}` |
| **Error codes (closed taxonomy)** | 401 `unauthorized` • 403 `forbidden` / `tenant_required` / `tenant_mismatch` • 404 `dlq_entry_not_found` (включая cross-tenant existence-leak protection) • 409 `already_replayed` / `already_abandoned` • 422 `validation_failed` • 503 `store_unavailable` • 500 `server_error` |
| **RBAC matrix** | operator -> 403 • admin -> own tenant only (entry.tenant == X-Admin-Tenant) • super-admin -> any tenant |
| **Side effects** | (a) Reconstruct `NotificationEvent` from `payload_json`; (b) dispatch via `NotifierBase.send_with_retry`; (c) on 2xx -> `mark_replayed` (terminal); on final fail -> `increment_attempt` (recompute next_retry_at); (d) `_emit_audit("webhook_dlq.replay", details={entry_id, adapter_name, event_id, success, attempt_count, reason})`. |

### `POST /admin/webhooks/dlq/{entry_id}/abandon`

| Aspect | Value |
|--------|-------|
| **Method / Path** | `POST /admin/webhooks/dlq/{entry_id}/abandon` |
| **Path param** | `entry_id: UUID` |
| **Request body (Pydantic)** | `WebhookDlqAbandonRequest` `{reason: str (10..500 chars)}` |
| **Response (200)** | `WebhookDlqAbandonResponse` `{entry_id: UUID, new_status: "abandoned", audit_id: UUID}` |
| **Error codes (closed taxonomy)** | 401 `unauthorized` • 403 `forbidden` / `tenant_required` / `tenant_mismatch` • 404 `dlq_entry_not_found` • 409 `already_replayed` / `already_abandoned` • 422 `validation_failed` • 503 `store_unavailable` • 500 `server_error` |
| **RBAC matrix** | operator -> 403 • admin -> own tenant only • super-admin -> any tenant |
| **Side effects** | (a) `mark_abandoned(reason="operator")`; (b) `_emit_audit("webhook_dlq.abandon", details={entry_id, adapter_name, event_id, reason})`. |

---

## 9. Mock-backend extension (`Frontend/tests/e2e/fixtures/admin-backend-mock.ts`)

Добавляются 3 handlers + 1 sentinel + 4 in-memory rows.

### In-memory state

```typescript
// Add to mock-state init alongside SCHEDULES / FINDINGS arrays:
const WEBHOOK_DLQ_ENTRIES: JsonValue[] = [
  {
    id: "dlq00000-0000-0000-0000-000000000001",
    tenant_id: MOCK_TENANT_PRIMARY,
    adapter_name: "slack",
    event_type: "scan.completed",
    event_id: "evt-00001",
    target_url_hash: "a".repeat(64),  // synthetic hash
    payload_json: { scan_id: MOCK_SCAN_ID, status: "completed" },
    last_error_code: "http_5xx",
    last_status_code: 503,
    attempt_count: 3,
    next_retry_at: "2026-04-22T10:00:00Z",
    replayed_at: null,
    abandoned_at: null,
    abandoned_reason: null,
    triage_status: "pending",
    created_at: "2026-04-22T06:00:00Z",
    // SENTINEL: for replay-always-fails E2E:
    _failtest_target: false,
  },
  {
    id: "dlq00000-0000-0000-0000-000000000002",
    tenant_id: MOCK_TENANT_PRIMARY,
    adapter_name: "linear",
    event_type: "finding.high",
    event_id: "evt-00002",
    target_url_hash: "b".repeat(64),
    payload_json: { finding_id: "fnd-1", severity: "high" },
    last_error_code: "timeout",
    last_status_code: null,
    attempt_count: 5,
    next_retry_at: "2026-04-22T11:00:00Z",
    replayed_at: null,
    abandoned_at: null,
    abandoned_reason: null,
    triage_status: "pending",
    created_at: "2026-04-22T05:00:00Z",
    // SENTINEL: replay always fails (failtest.invalid origin)
    _failtest_target: true,
  },
  {
    id: "dlq00000-0000-0000-0000-000000000003",
    tenant_id: MOCK_TENANT_SECONDARY,
    adapter_name: "jira",
    event_type: "scan.failed",
    event_id: "evt-00003",
    target_url_hash: "c".repeat(64),
    payload_json: { scan_id: MOCK_SCAN_SECONDARY_ID, status: "failed" },
    last_error_code: "http_4xx",
    last_status_code: 422,
    attempt_count: 8,
    next_retry_at: null,  // already abandoned by max_age
    replayed_at: null,
    abandoned_at: "2026-04-21T23:00:00Z",
    abandoned_reason: "max_age",
    triage_status: "abandoned",
    created_at: "2026-04-08T05:00:00Z",
    _failtest_target: false,
  },
  {
    id: "dlq00000-0000-0000-0000-000000000004",
    tenant_id: MOCK_TENANT_PRIMARY,
    adapter_name: "slack",
    event_type: "kill_switch.global",
    event_id: "evt-00004",
    target_url_hash: "d".repeat(64),
    payload_json: { reason: "test", operator: "demo" },
    last_error_code: "http_5xx",
    last_status_code: 502,
    attempt_count: 2,
    next_retry_at: null,
    replayed_at: "2026-04-22T07:00:00Z",  // already successfully replayed
    abandoned_at: null,
    abandoned_reason: null,
    triage_status: "replayed",
    created_at: "2026-04-22T04:00:00Z",
    _failtest_target: false,
  },
];
```

### Handler 1: `GET /admin/webhooks/dlq`

```typescript
// Inside the existing dispatchByPath() switch:
if (req.method === "GET" && req.url.pathname === "/api/v1/admin/webhooks/dlq") {
  const tenantHeader = headers["x-admin-tenant"] ?? null;
  const role = headers["x-admin-role"] ?? "operator";
  if (role === "operator") return forbidden(res);
  let items = WEBHOOK_DLQ_ENTRIES.slice();
  // Admin role: filter by tenant. Super-admin without tenant header: all.
  if (role === "admin") {
    if (!tenantHeader) return forbidden(res, "tenant_required");
    items = items.filter((e: any) => e.tenant_id === tenantHeader);
  } else if (tenantHeader) {
    items = items.filter((e: any) => e.tenant_id === tenantHeader);
  }
  // Apply filters
  const url = new URL(req.url, `http://${req.headers.host}`);
  const status = url.searchParams.get("status");
  if (status) items = items.filter((e: any) => e.triage_status === status);
  const adapterName = url.searchParams.get("adapter_name");
  if (adapterName) items = items.filter((e: any) => e.adapter_name === adapterName);
  // Pagination
  const limit = Math.min(200, Number(url.searchParams.get("limit") ?? 50));
  const offset = Math.max(0, Number(url.searchParams.get("offset") ?? 0));
  const total = items.length;
  const slice = items.slice(offset, offset + limit);
  // Strip _failtest_target sentinel from response
  const sanitised = slice.map(({ _failtest_target, ...rest }: any) => rest);
  json(res, 200, { items: sanitised, total, limit, offset });
  return;
}
```

### Handler 2: `POST /admin/webhooks/dlq/{id}/replay`

```typescript
const replayMatch = req.url.pathname.match(
  /^\/api\/v1\/admin\/webhooks\/dlq\/([0-9a-f-]+)\/replay$/i,
);
if (req.method === "POST" && replayMatch) {
  const entryId = replayMatch[1];
  const entry = WEBHOOK_DLQ_ENTRIES.find((e: any) => e.id === entryId) as any;
  if (!entry) return notFound(res, "dlq_entry_not_found");
  // RBAC
  const role = headers["x-admin-role"] ?? "operator";
  const tenantHeader = headers["x-admin-tenant"] ?? null;
  if (role === "operator") return forbidden(res);
  if (role === "admin" && entry.tenant_id !== tenantHeader)
    return notFound(res, "dlq_entry_not_found");  // existence-leak protection
  // Idempotency
  if (entry.replayed_at) return conflict(res, "already_replayed");
  if (entry.abandoned_at) return conflict(res, "already_abandoned");
  // SENTINEL: failtest target -> replay always fails
  if (entry._failtest_target) {
    entry.attempt_count += 1;
    entry.last_error_code = "http_5xx";
    entry.last_status_code = 502;
    json(res, 202, {
      entry_id: entry.id,
      success: false,
      attempt_count: entry.attempt_count,
      new_status: "pending",
      audit_id: nextAuditId(),
      message_code: "replay_failed",
    });
    return;
  }
  // Happy path
  entry.replayed_at = new Date().toISOString();
  entry.triage_status = "replayed";
  json(res, 202, {
    entry_id: entry.id,
    success: true,
    attempt_count: entry.attempt_count,
    new_status: "replayed",
    audit_id: nextAuditId(),
    message_code: "replay_succeeded",
  });
  return;
}
```

### Handler 3: `POST /admin/webhooks/dlq/{id}/abandon`

```typescript
const abandonMatch = req.url.pathname.match(
  /^\/api\/v1\/admin\/webhooks\/dlq\/([0-9a-f-]+)\/abandon$/i,
);
if (req.method === "POST" && abandonMatch) {
  const entryId = abandonMatch[1];
  const entry = WEBHOOK_DLQ_ENTRIES.find((e: any) => e.id === entryId) as any;
  if (!entry) return notFound(res, "dlq_entry_not_found");
  const role = headers["x-admin-role"] ?? "operator";
  const tenantHeader = headers["x-admin-tenant"] ?? null;
  if (role === "operator") return forbidden(res);
  if (role === "admin" && entry.tenant_id !== tenantHeader)
    return notFound(res, "dlq_entry_not_found");
  if (entry.replayed_at) return conflict(res, "already_replayed");
  if (entry.abandoned_at) return conflict(res, "already_abandoned");
  entry.abandoned_at = new Date().toISOString();
  entry.abandoned_reason = "operator";
  entry.triage_status = "abandoned";
  json(res, 200, {
    entry_id: entry.id,
    new_status: "abandoned",
    audit_id: nextAuditId(),
  });
  return;
}
```

### Sentinel

| Sentinel | Trigger | Effect |
|----------|---------|--------|
| `_failtest_target: true` (mock-only field NEVER returned to client) | `POST .../replay` on a dlq entry where this flag is true | Returns `202 + {success: false, attempt_count: incremented, new_status: "pending", message_code: "replay_failed"}` deterministically — no real network, no time mocking. Used by `admin-webhooks-dlq.spec.ts` для тестирования "replay-failed banner" UX. |

**Reset endpoint:** существующий `POST /api/v1/__test__/reset` расширяется на сброс `WEBHOOK_DLQ_ENTRIES` к initial 4 rows.

---

## 10. Frontend surface (T41)

| File | Что делает (1 строка) |
|------|----------------------|
| `Frontend/src/app/admin/webhooks/dlq/page.tsx` | Server-component shell: `getServerAdminSession` -> redirect на `/admin/forbidden` если operator; рендерит `WebhookDlqClient`. |
| `Frontend/src/app/admin/webhooks/dlq/WebhookDlqClient.tsx` | "use client": filter state, fetches via `listDlqEntriesAction`, renders `<DlqTable>`, opens `<ReplayDialog>` / `<AbandonDialog>` per row. |
| `Frontend/src/app/admin/webhooks/dlq/actions.ts` | "use server": `listDlqEntriesAction(filters)`, `replayDlqEntryAction(entryId, reason)`, `abandonDlqEntryAction(entryId, reason)` — всё через `callAdminBackendJson`. |
| `Frontend/src/components/admin/webhooks/DlqTable.tsx` | Pure-presentation table: id (truncated) / adapter / event_type / target_hash (truncated) / attempt_count / last_error_code / created_at / status badge / per-row action menu. |
| `Frontend/src/components/admin/webhooks/ReplayDialog.tsx` | Typed-confirm `event_id` (paste-disabled), `reason` textarea (10-500 chars), submit -> `replayDlqEntryAction`, success/error banner с `webhookDlqActionErrorMessage`. |
| `Frontend/src/components/admin/webhooks/AbandonDialog.tsx` | Same UX shape, action -> `abandonDlqEntryAction`. |
| `Frontend/src/lib/adminWebhookDlq.ts` | Closed-taxonomy `WEBHOOK_DLQ_FAILURE_TAXONOMY` enum, `extractWebhookDlqActionCode`, `webhookDlqActionErrorMessage`, RU dict, `WebhookDlqActionError` class, Zod schemas mirror `adminSchedules.ts`. |

---

## 11. Test contract

### Backend tests (added)

| Spec file | Cases | Notes |
|-----------|-------|-------|
| `backend/tests/db/test_webhook_dlq_migration.py` | 5 | Upgrade/downgrade idempotency, RLS isolation, FORCE bypasses owner role, UNIQUE, FK cascade |
| `backend/tests/db/test_webhook_dlq_rls.py` | 2 | Postgres-only RLS smoke |
| `backend/tests/notifications/test_webhook_dlq_persistence.py` | 18 | DAO unit (`compute_next_retry_at` 5 + `enqueue` 4 + `get_*` 3 + `list_*` 4 + `mark_*` 6) |
| `backend/tests/api/admin/test_admin_webhook_dlq_list.py` | 10 | RBAC (operator/admin/super-admin) × pagination/filters |
| `backend/tests/api/admin/test_admin_webhook_dlq_replay.py` | 10 | RBAC, happy, replay-failed, already-terminal × 2, cross-tenant, validation, audit emit verification |
| `backend/tests/api/admin/test_admin_webhook_dlq_abandon.py` | 6 | RBAC, happy, already-terminal × 2, cross-tenant, audit emit |
| `backend/tests/celery/test_webhook_dlq_replay_task.py` | 12 | Beat task: due-replay, abandon-aged, circuit-open-skip, terminal-skip, idempotent re-fire |

**Backend total: 63 new tests.**

### Frontend tests (added)

| Spec file | Cases | Notes |
|-----------|-------|-------|
| `Frontend/src/app/admin/webhooks/dlq/WebhookDlqClient.test.tsx` | 6 | Initial render, filter state, RBAC column visibility, error banner, success banner, refresh |
| `Frontend/src/components/admin/webhooks/ReplayDialog.test.tsx` | 6 | Typed-confirm gate, paste-disabled, reason length validation, submit happy, submit error, focus management |
| `Frontend/src/components/admin/webhooks/AbandonDialog.test.tsx` | 4 | Typed-confirm + reason + submit happy + error |
| `Frontend/src/lib/adminWebhookDlq.test.ts` | 4 | `extractWebhookDlqActionCode` через `instanceof` / `code` / `message` / fallback |
| `Frontend/tests/e2e/admin-webhooks-dlq.spec.ts` | 8 | List render admin/super-admin, filter change, replay happy, replay failed (sentinel), abandon happy, cross-tenant hidden, audit-trail cross-spec |
| `Frontend/tests/e2e/admin-axe.spec.ts` (extension) | 3 | 1 route + 2 dialog scenarios под `test.fail()` ISS-T26-001 |

**Frontend total: 31 new tests (20 vitest + 11 Playwright).**

### Total Batch 5 tests: 63 backend + 31 frontend = **94 new tests**

---

## 12. CI gate (T44) — `.github/workflows/admission-policy-kind.yml`

| Aspect | Value |
|--------|-------|
| **Trigger** | `pull_request` + `push (main)` on `infra/kyverno/**`, `infra/helm/argus/templates/kyverno-cluster-policy.yaml`, `infra/helm/argus/values*.yaml`, `.github/workflows/admission-policy-kind.yml` paths; `workflow_dispatch` |
| **Runner** | `ubuntu-latest` |
| **Timeout** | 25 min hard limit |
| **Permissions** | `contents: read`, `packages: write` (push fixture к GHCR), `id-token: write` (cosign keyless) |
| **Concurrency** | `admission-policy-${{ github.ref }}`, cancel-in-progress on PR |
| **Steps** | 1. checkout • 2. setup-kind v0.24.0 + kindest/node v1.31.0 • 3. setup-helm v3.14.4 • 4. helm repo add kyverno + install chart 3.6.4 + wait • 5. kubectl apply ARGUS ClusterPolicy + kubectl wait Ready • 6. cosign-installer@v4.1.0 (release v3.0.5) • 7. docker login ghcr • 8. build+push positive fixture • 9. cosign sign --yes (keyless) • 10. kubectl run negative (`nginx:1.27.0`) --dry-run=server -> assert non-zero RC + stderr contains `argus-require-signed-images` • 11. kubectl run positive (signed+digest) --dry-run=server -> assert zero RC • 12. (always) collect kubectl events + Kyverno admission logs • 13. (always) upload artefacts |
| **Artefact upload** | `admission-policy-kind-logs` — `kubectl-*.log`, `kube-events.log`, `kyverno-admission.log` — 14d retention |
| **Pinned versions** | `kind v0.24.0` • `kindest/node v1.31.0` • `kyverno chart 3.6.4` • `helm v3.14.4` • `cosign v3.0.5` • `sigstore/cosign-installer@v4.1.0` • `helm/kind-action@v1` • `azure/setup-helm@v4` • `actions/checkout@v4` |

---

## 13. New dependencies

### Backend (Python)
- **None new.** Replay engine reuses existing `httpx` через `NotifierBase.send_with_retry` (`backend/src/mcp/services/notifications/_base.py`). Persistence reuses `sqlalchemy.ext.asyncio` (already in `requirements.txt`). Celery task reuses `celery[redis]` (already pinned). Closed-taxonomy errors — Pydantic models (already exists). 

### Frontend (TypeScript)
- **None new.** Closed-taxonomy lib uses `zod` (already in repo per Batch 4). Tables / dialogs reuse existing component primitives. Audit-emit / RBAC client helpers already shipped.

### Infrastructure (Helm / IaC)
- **Kyverno chart pin: `kyverno/kyverno@3.6.4`** (Kyverno application 1.16.x). Sourced from `https://kyverno.github.io/kyverno/`. Compatible with Kubernetes 1.31 (target kind cluster).
- **Optional schema validation (kubeconform extension):** Kyverno CRDs schema URL `https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/kyverno.io/clusterpolicy_v1.json` — добавляется в `infra/scripts/helm_kubeconform.sh::KUBECONFORM_SCHEMA_LOCATIONS` для рендера с `policy.enabled=true`.

### CI (GitHub Actions used by T44)
- **`actions/checkout@v4`** (already used).
- **`helm/kind-action@v1`** (NEW; canonical kind setup action).
- **`azure/setup-helm@v4`** (already used in `helm-validation.yml`).
- **`sigstore/cosign-installer@v4.1.0`** (NEW; default cosign release v3.0.5).
- **`docker/login-action@v3`** (NEW; for GHCR push of positive fixture).
- **`actions/upload-artifact@v4`** (already used in `helm-validation.yml`).

---

## 14. Migrations

### `backend/alembic/versions/027_webhook_dlq.py`

**Revision chain:** `026 -> 027` (deviation D-1).

**Columns (verbatim):**

| Column | Type | Constraint |
|--------|------|------------|
| `id` | `VARCHAR(36)` | PRIMARY KEY (ORM-generated UUID via `gen_uuid()`) |
| `tenant_id` | `VARCHAR(36)` | FK `tenants(id)` ON DELETE CASCADE; NOT NULL |
| `adapter_name` | `VARCHAR(64)` | NOT NULL (e.g. "slack", "linear", "jira") |
| `event_type` | `VARCHAR(100)` | NOT NULL (matches `NOTIFICATION_EVENT_TYPES`) |
| `event_id` | `VARCHAR(64)` | NOT NULL (idempotency key) |
| `target_url_hash` | `VARCHAR(64)` | NOT NULL (NEVER raw URL — always `hash_target()` output) |
| `payload_json` | `JSONB` (Postgres) / `JSON` (SQLite) | NOT NULL |
| `last_error_code` | `VARCHAR(64)` | NOT NULL (closed taxonomy: `timeout`, `network_error`, `http_4xx`, `http_5xx`, `circuit_open`, `unknown_error`) |
| `last_status_code` | `INTEGER` | NULLABLE |
| `attempt_count` | `INTEGER` | NOT NULL DEFAULT 0 |
| `next_retry_at` | `TIMESTAMPTZ` | NULLABLE (NULL для terminal rows) |
| `replayed_at` | `TIMESTAMPTZ` | NULLABLE (non-null = success terminal) |
| `abandoned_at` | `TIMESTAMPTZ` | NULLABLE (non-null = giveup terminal) |
| `abandoned_reason` | `VARCHAR(64)` | NULLABLE ("operator", "max_age", "manual_abandon") |
| `created_at` | `TIMESTAMPTZ` | NOT NULL DEFAULT now() |
| `updated_at` | `TIMESTAMPTZ` | NOT NULL DEFAULT now() (ORM `onupdate=func.now()`) |

**Constraints:**
- `UNIQUE (tenant_id, adapter_name, event_id)` — idempotent re-enqueue protection.

**Indexes:**
- `ix_webhook_dlq_tenant_status (tenant_id, abandoned_at, replayed_at)` — admin list hot-path.
- `ix_webhook_dlq_next_retry_at (next_retry_at) WHERE abandoned_at IS NULL AND replayed_at IS NULL` — partial; Postgres only. SQLite — plain index.
- `ix_webhook_dlq_created_at (created_at)` — sort + 14-day age scan.

**RLS (Postgres only):**
- `ENABLE ROW LEVEL SECURITY`
- `FORCE ROW LEVEL SECURITY`
- POLICY `tenant_isolation`: `USING (tenant_id = current_setting('app.current_tenant_id', true)::text) WITH CHECK (...)`

---

## 15. Acceptance criteria per task (literal exit-code = 0 commands)

### T37
- `cd backend && pytest tests/db/test_webhook_dlq_migration.py -v` -> PASS (all 5 cases).
- `cd backend && alembic upgrade head` -> revision `027` applied; `alembic current` shows `027 (head)`.
- `cd backend && alembic upgrade head && alembic downgrade -1 && alembic upgrade head` -> idempotent.

### T38
- `cd backend && pytest tests/notifications/test_webhook_dlq_persistence.py -v` -> PASS (18 cases).
- `cd backend && pytest tests/db/test_webhook_dlq_rls.py -v` -> PASS (2 cases) on Postgres test DB.
- `cd backend && mypy src/mcp/services/notifications/webhook_dlq_persistence.py --strict` -> 0 errors.

### T39
- `cd backend && pytest tests/api/admin/test_admin_webhook_dlq_list.py tests/api/admin/test_admin_webhook_dlq_replay.py tests/api/admin/test_admin_webhook_dlq_abandon.py -v` -> PASS (26 cases).
- `cd backend && python -m src.api.openapi_export | python -c "import sys,json; spec=json.load(sys.stdin); assert '/admin/webhooks/dlq' in spec['paths']" ` -> PASS.

### T40
- `cd backend && pytest tests/celery/test_webhook_dlq_replay_task.py -v` -> PASS (12 cases).
- `cd backend && python -c "from src.celery.beat_schedule import BEAT_SCHEDULE; assert 'argus.notifications.webhook_dlq_replay' in BEAT_SCHEDULE"` -> PASS.

### T41
- `cd Frontend && pnpm test -- adminWebhookDlq WebhookDlqClient ReplayDialog AbandonDialog --run` -> PASS (20 cases).
- `cd Frontend && pnpm exec playwright test admin-webhooks-dlq` -> PASS (8 cases).
- `cd Frontend && pnpm exec playwright test --config=playwright.a11y.config.ts admin-axe -g "webhook"` -> 3 scenarios run (под `test.fail()` ISS-T26-001 — passes by failing as expected).
- `cd Frontend && pnpm lint && pnpm tsc --noEmit` -> 0 errors.

### T42
- `kubectl apply --dry-run=client -f infra/kyverno/cluster-policy-require-signed-images.yaml` -> exits 0; output: `clusterpolicy.kyverno.io/argus-require-signed-images created (dry run)`.
- `yq '.spec.validationFailureAction' infra/kyverno/cluster-policy-require-signed-images.yaml` -> `Enforce`.

### T43
- `helm template ./infra/helm/argus --set policy.enabled=false | yq 'select(.kind == "ClusterPolicy")' | grep -c '^---' || echo 0` -> `0`.
- `helm template ./infra/helm/argus --set policy.enabled=true | yq 'select(.kind == "ClusterPolicy") | .metadata.name'` -> `argus-require-signed-images`.
- `bash infra/scripts/helm_kubeconform.sh --kube-version 1.31.0` -> PASS for both `policy.enabled=false/true` paths.

### T44
- GitHub Actions workflow `Admission policy (Kyverno + kind)` runs к концу (negative + positive both green). Job log shows `Negative test PASSED` AND `Positive test PASSED`.

### T45
- `markdownlint docs/admission-policy.md docs/webhook-dlq.md` -> 0 errors.
- `wc -l docs/admission-policy.md` >= 200 lines; `wc -l docs/webhook-dlq.md` >= 250 lines.

---

## 16. Non-goals

Эти пункты ЯВНО не входят в Batch 5; reviewers НЕ должны спрашивать:

- **JWT/session-bound admin auth (`ISS-T20-003`)** — production-gate, deferred к Cycle 7 / pre-launch. Batch 5 продолжает использовать cookie-shim (см. `Frontend/src/services/admin/serverSession.ts`).
- **Design token `--accent-high-contrast` / WCAG AA fix (`ISS-T26-001`)** — quick fix, между batches; новые axe scenarios для `/admin/webhooks/dlq` наследуют `test.fail()` с reference на ISS-T26-001 (3 scenarios: list view + ReplayDialog + AbandonDialog).
- **Webhook signing key rotation** — отдельная задача (рамок DLQ не касается); planned для Cycle 7.
- **DLQ retention beyond 14 days** — фиксированный potolok; long-term архивация в S3/MinIO + cold-storage politik не входит в Batch 5.
- **Manual webhook-dispatcher replay-from-UI до исчерпания retries (intercept ДО провала)** — Phase 2 / Cycle 7. T41 UI работает только с persisted DLQ entries.
- **SARIF/SBOM generation в CI** — самостоятельная supply-chain инициатива; не пересекается с admission-policy gate.
- **Multi-cluster Kyverno federation** — out-of-scope; T42 — single-cluster ClusterPolicy.
- **Per-tenant DLQ quotas** — out-of-scope; backpressure уже есть на адаптер-side через circuit breaker.

---

## 17. Carry-over hooks

Эти carry-over issues НЕ закрываются в Batch 5, но T41 ДОЛЖЕН на них ссылаться в коде:

| Issue ID | File | Where in Batch 5 | Action |
|----------|------|-----------------|--------|
| `ISS-T26-001` | [`ai_docs/develop/issues/ISS-T26-001.md`](../issues/ISS-T26-001.md) | T41 axe scenarios для `/admin/webhooks/dlq` | 3 новых scenarios под `test.fail()` с RU/EN comment "ISS-T26-001: <CTA token>" |
| `ISS-T20-003` | [`ai_docs/develop/issues/ISS-T20-003.md`](../issues/ISS-T20-003.md) | T39 endpoints — продолжают использовать cookie-shim auth | Comment в `admin_webhook_dlq.py` docstring: "Auth: same cookie-shim envelope as Batch 2-4 (X-Admin-Key + X-Admin-Role/Tenant/Operator-Subject); ISS-T20-003 deferred." |
| `ISS-cycle6-batch4-carry-over.md` | [`ai_docs/develop/issues/ISS-cycle6-batch4-carry-over.md`](../issues/ISS-cycle6-batch4-carry-over.md) | Foundation (общий контекст) | Phase 4 documenter создаёт `ISS-cycle6-batch5-carry-over.md` со ссылкой на этот файл. |

---

## 18. Total estimated wall-time

**~4 рабочих дня при 2-worker parallelism** (29 часов работы + CI/review циклы).

Разбивка по wave (см. §4 DAG):

| Wave | Tasks | Parallel? | Wall-time |
|------|-------|-----------|-----------|
| 1 | T37 + T42 | Yes | 3 ч |
| 2 | T38 + T43 | Yes | 6 ч |
| 3 | T39 + T40 + T44 | Yes | 7 ч |
| 4 | T41 | No | 9 ч |
| 5 | T45 | No | 4 ч |
| **Total** | | | **29 часов = ~4 рабочих дня** |

Mirror Batch 4 estimate (`~4d wall-time at 2-worker parallelism`).

---

## 19. Cross-links

### Backlog
- [`Backlog/dev1_finalization_roadmap.md`](../../../Backlog/dev1_finalization_roadmap.md) §Batch 5 (T37-T45)
- [`Backlog/dev1_.md`](../../../Backlog/dev1_.md) §14 Webhooks/integrations + §17 SDLC/CI + §19 Acceptance

### Prior plans (Cycle 6)
- [`ai_docs/develop/plans/2026-04-22-argus-cycle6-b4.md`](2026-04-22-argus-cycle6-b4.md) — Batch 4 (Operations UI: Kill-switch + Schedules; ARG-052 + ARG-056)
- Earlier plans: Batch 1 (T01-T07), Batch 2 (T08-T14), Batch 3 (T15-T21).

### Prior reports (Cycle 6)
- [`ai_docs/develop/reports/2026-04-22-cycle6-batch4-implementation.md`](../reports/2026-04-22-cycle6-batch4-implementation.md) — Batch 4 implementation report
- [`ai_docs/develop/reports/2026-04-21-cycle6-batch3-implementation.md`](../reports/2026-04-21-cycle6-batch3-implementation.md) — Batch 3 implementation report

### Carry-over issues
- [`ai_docs/develop/issues/ISS-cycle6-batch4-carry-over.md`](../issues/ISS-cycle6-batch4-carry-over.md)
- [`ai_docs/develop/issues/ISS-T26-001.md`](../issues/ISS-T26-001.md)
- [`ai_docs/develop/issues/ISS-T20-003.md`](../issues/ISS-T20-003.md)

### Architecture references
- [`backend/src/mcp/services/notifications/_base.py`](../../../backend/src/mcp/services/notifications/_base.py) — `NotifierBase.send_with_retry` (replay engine).
- [`backend/src/mcp/services/notifications/dispatcher.py`](../../../backend/src/mcp/services/notifications/dispatcher.py) — `NotificationDispatcher`.
- [`backend/src/api/routers/admin_emergency.py`](../../../backend/src/api/routers/admin_emergency.py) — canonical `_emit_audit` + RBAC dependency wiring.
- [`backend/src/api/routers/admin_schedules.py`](../../../backend/src/api/routers/admin_schedules.py) — canonical CRUD endpoint pattern.
- [`backend/alembic/versions/026_scan_schedules.py`](../../../backend/alembic/versions/026_scan_schedules.py) — canonical RLS+FORCE migration template.
- [`backend/src/celery/beat_schedule.py`](../../../backend/src/celery/beat_schedule.py) — canonical `BEAT_SCHEDULE` extension point.
- [`Frontend/src/lib/adminSchedules.ts`](../../../Frontend/src/lib/adminSchedules.ts) — canonical closed-taxonomy + `extractScheduleActionCode` template.
- [`Frontend/tests/e2e/fixtures/admin-backend-mock.ts`](../../../Frontend/tests/e2e/fixtures/admin-backend-mock.ts) — mock backend extension point.
- [`Frontend/tests/e2e/admin-axe.spec.ts`](../../../Frontend/tests/e2e/admin-axe.spec.ts) — axe-core gate extension point.
- [`infra/helm/argus/values.yaml`](../../../infra/helm/argus/values.yaml) — Helm values extension point.
- [`.github/workflows/helm-validation.yml`](../../../.github/workflows/helm-validation.yml) — CI workflow template для T44.

---

## 20. Sign-off / DoD

Batch 5 считается готовым к release когда:

1. Все 9 задач (T37-T45) shipped с проходящими acceptance-criteria commands из §15.
2. Все 94 новых tests (63 backend + 31 frontend) PASSED.
3. Existing test suites НЕ регрессируют:
   - `cd backend && pytest -q` -> 100% PASS (no new failures).
   - `cd Frontend && pnpm test --run` -> 100% PASS.
   - `cd Frontend && pnpm exec playwright test --config=playwright.config.ts` -> 100% PASS.
   - `cd Frontend && pnpm exec playwright test --config=playwright.a11y.config.ts` -> existing 6+ `test.fail()` annotations remain unchanged; 3 new scenarios под ISS-T26-001 also `test.fail()`.
4. CI gates green:
   - `helm-validation.yml` (existing) — все matrix legs PASS.
   - `admission-policy-kind.yml` (NEW T44) — negative + positive deploys behave correctly.
   - `ci.yml` (existing) — full backend + frontend lint/test/build matrix.
5. CHANGELOG.md под `[Unreleased]` содержит секцию `### Cycle 6 Batch 5 (Webhook DLQ + Kyverno admission policy)` с per-task entries.
6. Phase 4 documenter создаёт:
   - `ai_docs/develop/reports/2026-04-22-cycle6-batch5-implementation.md` (final report).
   - `ai_docs/develop/issues/ISS-cycle6-batch5-carry-over.md` (если есть deferred items).
7. Plan file `ai_docs/develop/plans/2026-04-22-argus-cycle6-b5.md` committed alongside report (mirror Batch 4 commit `d4818c3 docs(plan): ...`).

---

**END OF PLAN**
