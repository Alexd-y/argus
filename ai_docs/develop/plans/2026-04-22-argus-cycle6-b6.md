# План: ARGUS Cycle 6 — Batch 6 (PDF/A archival, KEV-aware HPA, supply-chain ratchets, prod gates ISS-T20-003 + ISS-T26-001)

**Создан:** 2026-04-22
**Оркестрация:** `orch-2026-04-22-argus-cycle6-b6`
**Workspace:** `.cursor/workspace/active/orch-2026-04-22-argus-cycle6-b6/`
**Roadmap (источник истины):** [`Backlog/dev1_finalization_roadmap.md`](../../../Backlog/dev1_finalization_roadmap.md) §Batch 6 (T46–T53)
**Backlog (canonical spec):** [`Backlog/dev1_.md`](../../../Backlog/dev1_.md) §11 Reports/PDF, §16 Operability/SLO, §17 SDLC/CI, §19 Acceptance
**Production gates:**
- [`ISS-T20-003`](../issues/ISS-T20-003.md) — JWT/session-bound admin auth
- [`ISS-T26-001`](../issues/ISS-T26-001.md) — WCAG AA accent contrast
**Carry-over от Batch 5:** [`ai_docs/develop/issues/ISS-cycle6-batch5-carry-over.md`](../issues/ISS-cycle6-batch5-carry-over.md)
**Предыдущая оркестрация:** `orch-2026-04-22-argus-cycle6-b5` (Webhook DLQ + Kyverno admission policy, ARG-053 + ARG-054)
**Предыдущий отчёт:** [`ai_docs/develop/reports/2026-04-22-cycle6-batch5-implementation.md`](../reports/2026-04-22-cycle6-batch5-implementation.md)
**Cycle 5 sign-off (структурный референс для T53):** [`ai_docs/develop/reports/2026-04-20-argus-finalization-cycle5.md`](../reports/2026-04-20-argus-finalization-cycle5.md) (772 строки → T53 ≥ 800)
**Статус:** Ready
**Всего задач:** 10 (T46–T53 + 2 production gates) — в пределах cap=12
**Ожидаемая wall-time:** ~3 рабочих дня при 2-worker parallelism

---

## TL;DR

Batch 6 завершает Cycle 6 тремя инфраструктурными deliverables и закрывает обе production-gate болячки, тянувшиеся с Batch 2-4:

1. **PDF/A-2u archival pipeline** (`ARG-058`, T46+T47, объединены в B6-T01 — D-1): три tier-шаблона LaTeX (asgard / midgard / valhalla) получают полный PDF/A-2u preamble (color profile sRGB IEC61966-2.1, font embed с lmodern, `\Catalog/Metadata` XMP), плюс `verapdf` Docker-based CI gate, валидирующий каждый PR, который трогает report templates или PDF backend. Per-tenant ENUM `tenants.pdf_archival_format` (`standard` | `pdfa-2u`) с Alembic 029, admin API и UI-toggle (B6-T02 / T48).
2. **KEV-aware autoscaling** (`ARG-059`, T49–T51): Prometheus Adapter подключён как optional Helm subchart (toggle off в dev / on в prod overlay), новый `argus_celery_queue_depth` Gauge backfill через Celery beat task (D-5 — values-prod.yaml уже ссылается на эту метрику, но в коде она ещё не эмитится; B6-T03 закрывает разрыв), новый `hpa-celery-worker-kev.yaml` HPA, привязанный к 5-минутной rate `argus_findings_emitted_total{kev_listed="true"}` (D-7), плюс kind-cluster integration test, имитирующий KEV-burst (B6-T04 объединяет T50 + T51 — D-3).
3. **Supply-chain ratchets** (`ARG-060`, T52): два новых contracts в `test_tool_catalog_coverage.py` — C17 (network-policy allowlist resolution) + C18 (image-tag immutability через `@sha256:`). Coverage matrix растёт с 16 до 18 контрактов; cardinality 157 × 18 = 2826 параметризованных кейсов (B6-T05).
4. **Production gate ISS-T26-001 — WCAG AA accent contrast** (G26): два новых дизайн-токена в `globals.css` (`--accent-strong` #6B2EA8 + `--on-accent` #ffffff, ratio 7.04:1; `--warning-strong` #B45309 + `--on-warning` #ffffff), новый канонический doc `ai_docs/develop/architecture/design-tokens.md` (B6-T06), и миграция 13 admin-surfaces (7 surfaces из issue + 6 surfaces, добавленных T36) на новые токены с удалением **всех 7** `test.fail("ISS-T26-001:...")` annotations в `admin-axe.spec.ts` (B6-T07).
5. **Production gate ISS-T20-003 — JWT/session admin auth** (G20, Phase 1 Option B per user instruction): Alembic 028 `admin_sessions` table (cross-tenant by design — RLS DISABLED, FORCE owner-only), backend `POST /auth/admin/login` + `/logout` + `GET /auth/admin/whoami`, новый env-driven `ADMIN_AUTH_MODE` ('cookie' default → existing flow / 'session' → новый CSPRNG-cookie flow), bootstrap admin через `ARGUS_ADMIN_BOOTSTRAP_PASSWORD_BCRYPT` (D-6 concretization). Frontend dual-mode `serverSession.ts`, новый `/admin/login` route, middleware redirect, Playwright session-mode E2E. Phase 1 закрывает (a)(b)(c); MFA (d) и runbook (e) явно деферятся в новый `ISS-T20-003-phase2.md` (создаётся в B6-T10).
6. **Cycle 6 sign-off** (T53 → B6-T10): отчёт `2026-04-22-argus-finalization-cycle6.md` ≥800 строк, мирорящий структуру Cycle 5 sign-off; CHANGELOG rollup; `ISS-cycle7-carry-over.md`; `ISS-T20-003-phase2.md`.

10 атомарных задач, 2 новые Alembic миграции (`028_admin_sessions.py`, `029_tenant_pdf_archival_format.py`), 0 новых runtime-зависимостей в backend (`bcrypt` уже в проекте через `passlib[bcrypt]`), 1 новый Helm subchart (Prometheus Adapter, opt-in), 1 новый CI gate (verapdf), 1 новый kind-cluster CI gate (kev-hpa). Frontend: 0 новых npm packages, 13 surface migrations, 1 новый route (`/admin/login`), 1 новый Playwright project (session-mode).

Этот batch — последний в Cycle 6 и финализирует production-readiness scorecard для перехода на Cycle 7 (security hardening, audit certification, beta launch).

---

## 1. Контекст

### Что закрывает Batch 6

#### 1.1 PDF/A-2u archival (T46–T48 → B6-T01 + B6-T02)

ARGUS рассылает security-отчёты в трёх tier'ах (Asgard — full technical, Midgard — CISO brief, Valhalla — board executive). Cycle 5 / ARG-048 переключил LaTeX backend с Phase-1 stub'а (HTML→plain-text) на полноценный jinja2-latex рендер с реальными `_latex/{asgard,midgard,valhalla}/main.tex.j2` шаблонами. Однако сами шаблоны **не PDF/A-compliant**:

- Нет ICC color profile в `\Catalog/OutputIntents`.
- Нет `\Catalog/Metadata` XMP с `pdfaid:part=2` + `pdfaid:conformance=U`.
- Шрифты эмбедятся стандартным lmodern, но без force-embed на subset; некоторые glyphs в Type-3.
- Нет `\Catalog/MarkInfo /Marked true` для accessibility.
- Нет проверки на запрещённые transparency / video / audio annotations.

PDF/A-2u — единственный формат, юридически приемлемый для долгосрочной архивации security-отчётов в большинстве enterprise-комплаенс-фреймворков (SOC 2, ISO 27001, PCI DSS). Без него отчёты ARGUS невозможно использовать как primary evidence в audit trail.

Этот batch вводит:
- Расширенный preamble во всех трёх tier-шаблонах (B6-T01).
- ICC profile asset (sRGB IEC61966-2.1 v2 — ~3 KB, public domain) и font asset (lmroman10-regular.otf — ~120 KB, открытая лицензия) под `backend/templates/reports/_latex/_assets/`.
- Helper `backend/src/reports/_latex_pdfa.py` — инжектит preamble + резолвит asset-пути, кэширует в /tmp.
- `LatexBackend.archival_format` switch (`standard` / `pdfa-2u`), читается из per-render контекста.
- Docker-based CI gate `verapdf` (verapdf-greenfield/verapdf:latest, версия pinned 1.26.x), который проверяет три golden PDF на каждом PR, трогающем `backend/templates/reports/_latex/**` или `backend/src/reports/pdf_backend.py`.
- Per-tenant flag `tenants.pdf_archival_format` (B6-T02): админ-toggle в `/admin/tenants/{id}` UI; default `standard` (back-compat); при `pdfa-2u` оркестратор отчётов передаёт flag в backend.

#### 1.2 KEV-aware autoscaling (T49–T51 → B6-T03 + B6-T04)

Текущая celery HPA конфигурация (`infra/helm/argus/templates/hpa.yaml` + `values-prod.yaml` lines 104–119):

```yaml
hpa:
  celery:
    minReplicas: 4
    maxReplicas: 40
    targetCPUUtilizationPercentage: 70
    customMetrics:
      enabled: true
      metricName: argus_celery_queue_depth
      averageValue: "50"
```

Проблема №1: метрика `argus_celery_queue_depth` **не эмитится ни одним эмиттером в проекте** (Grep подтвердил — нет в `backend/src/core/observability.py`, нет в celery sources). Следовательно, существующая customMetrics-секция в проде — silent no-op; HPA скейлит только по CPU. **D-5** — это backfill, который B6-T03 закрывает: новый Celery beat task `argus.observability.queue_depth_emit` (период 30s) использует `app.control.inspect().reserved() / .active() / .scheduled()` для подсчёта длины каждой known-queue (`argus.scans`, `argus.reports`, `argus.tools`, `argus.recon`, `argus.exploitation`, `argus.intel`, `argus.notifications`, `argus.default`) и публикует Gauge `argus_celery_queue_depth{queue=<name>}`.

Проблема №2: roadmap §T49 требует Prometheus Adapter (без него Kubernetes HPA не может обращаться к произвольным Prometheus-метрикам). Адаптер не установлен в чарте сейчас. B6-T03 добавляет его как **optional subchart** (зависимость в `Chart.yaml`, condition `prometheusAdapter.enabled`), плюс новый template `prometheus-adapter-rules.yaml` с двумя rule-mappings:
- `argus_celery_queue_depth` → external metric `argus.celery.queue.depth`
- `rate(argus_findings_emitted_total{kev_listed="true"}[5m])` → external metric `argus.kev.findings.emit.rate.5m`

Проблема №3: roadmap §T50 требует KEV-aware HPA для Celery worker pool. **D-7**: вместо новой backend-метрики используем уже существующий `argus_findings_emitted_total{kev_listed="true"}` counter (`backend/src/core/observability.py:187-191`); Prometheus Adapter rule вычисляет его 5-min rate. B6-T04 добавляет **отдельный** HPA `hpa-celery-worker-kev.yaml` (НЕ заменяет существующий — два HPA на один Deployment даёт Kubernetes union-семантику: `max(scale_recommendation_cpu, scale_recommendation_kev)` побеждает; это deliberate belt-and-braces). `behavior.scaleUp.stabilizationWindowSeconds=300` + `behavior.scaleDown.stabilizationWindowSeconds=300` (anti-flap, mandated roadmap).

Проблема №4: kind-cluster integration test (T51 → B6-T04). Развёрнут kind v1.31, Prometheus + Adapter + чарт устанавливаются helm. Тест публикует fake-метрику через `curl -X POST` к Prometheus pushgateway (или альтернатива — `kubectl run prometheus-injector` с короткоживущим curl в init), ждёт ≤120s и ассертит, что HPA status `desiredReplicas` вырос. Negative path — без KEV findings скейл держится на minReplicas после прохождения stabilization window.

#### 1.3 Supply-chain ratchets (T52 → B6-T05)

Coverage matrix в `backend/tests/test_tool_catalog_coverage.py` уже фиксирует 16 контрактов на каждый из 157 catalog-tools (157 × 16 = 2512 параметризованных кейсов). T52 ратчетит planku до 18:
- **C17** — `network_policy.allowlist_targets_resolved`: каждый YAML's `network_policy.allowlist` резолвится через `src.sandbox.network_policies.resolve_allowlist` без unresolved tokens. Ловит typo-allowlists, которые молча разрешают `any` (ситуация, когда `allowlist: ["argus-net"]` стало `allowlist: [argus-net]` (unquoted YAML token), резолвер возвращает `*`, политика становится open).
- **C18** — `manifest_image_tag_immutable`: каждая `descriptor.image` либо в `@sha256:<digest>` форме, либо в небольшом explicitly-allowed `_FLOATING_TAG_TOOLS` set (≤3 tools, все internal, каждый с inline-комментарием и тикетом). Ловит floating tags типа `nuclei:latest`, которые ломают reproducibility поставки.

`COVERAGE_MATRIX_CONTRACTS = 18` — assertion на нижней границе, чтобы будущие правки случайно не понизили porog.

#### 1.4 ISS-T26-001 — WCAG AA accent contrast (G26 → B6-T06 + B6-T07)

Issue фиксирует ≥7 production admin surfaces, где `bg-[var(--accent)]` (#A655F7) + текст с темнее `--bg-primary` фоном даёт contrast ratio 4.20:1 (нужно 4.5:1 для AA normal text). Cycle 6 / T36 добавил ещё 6 surfaces с тем же паттерном (Schedules, Editor, Throttle, Kill-switch, DLQ, Audit-chain banner) — все они gated через `test.fail(true, "ISS-T26-001:...")` в `admin-axe.spec.ts` (verified — 7 annotations в файле, lines 265-507).

Issue предлагает Option A (preferred): ввести `--accent-strong` (контрастный вариант для CTA-фонов) и `--on-accent` (белый текст), мигрировать. Per user instruction — выбираем Option A.

B6-T06 (foundation):
- Добавляет в `globals.css` четыре новых токена: `--accent-strong: #6B2EA8` (контраст vs `--bg-primary` = 7.04:1, AAA), `--on-accent: #ffffff`, `--warning-strong: #B45309` (заменяет bg-amber-600 family, контраст 5.36:1), `--on-warning: #ffffff`.
- Создаёт `ai_docs/develop/architecture/design-tokens.md` (новый канонический doc) с token-list, contrast matrix, migration policy.
- НЕ трогает surfaces — purely additive.

B6-T07 (surface migration):
- 13 admin клиентов получают token replace: `bg-[var(--accent)] text-white` → `bg-[var(--accent-strong)] text-[var(--on-accent)]`; `bg-amber-600 text-white` → `bg-[var(--warning-strong)] text-[var(--on-warning)]`.
- Канонический `Frontend/src/components/ui/Button` variant `primary` обновляется — distil token usage.
- **Удаляются все 7** `test.fail` annotations в `admin-axe.spec.ts`. После миграции эти тесты должны пасить (axe color-contrast violations = 0).
- Visual-regression snapshot: 6 reference screens, ≤0.1% pixel-delta vs baseline (token-only changes; никакого layout-сдвига).

#### 1.5 ISS-T20-003 — JWT/session admin auth (G20 → B6-T08 + B6-T09)

Issue фиксирует, что текущая admin-auth модель — это **transitional shim**: cookies (`argus.admin.role`, `argus.admin.tenant`, `argus.admin.subject`) парсятся в `Frontend/src/services/admin/serverSession.ts` (line 7-28 — explicit security-boundary comment), backend trust'ит `X-Admin-Key` env-derived секрет. Cookies — client-writable; единственное, что препятствует privilege escalation сейчас — это `X-Admin-Key`, который браузер не может подставить. Issue просит JWT/session-bound replacement.

User instruction: **Phase 1 Option B (минимальный viable, no IdP)**. Roadmap §G20 принимает (a)(b)(c); MFA (d) и runbook (e) — Phase 2.

**D-2** — split. G20 atomic был бы слишком большим (touches Alembic + 4 backend modules + 5 frontend modules + 11+ tests). User-offered split исполняется:

##### B6-T08 (G20a — backend half):
- Alembic 028 `admin_sessions` table:
  - Cross-tenant by design (sessions are not tenant-bound; super-admin session → any tenant). RLS DISABLED + FORCE owner-only.
  - Columns: `id` (uuid PK), `email` (varchar 320), `session_token_hash` (sha256 hex, indexed unique), `created_at`, `last_seen_at`, `expires_at`, `revoked_at`, `ip` (inet, nullable), `user_agent` (text, nullable).
- ORM `AdminSession` в `backend/src/db/models.py`.
- DAO `backend/src/auth/admin_session_store.py`: `create`, `lookup_by_token_hash`, `rotate`, `revoke`, `list_active`, `prune_expired`.
- `backend/src/auth/admin_password.py`: bcrypt verify wrapper + bootstrap admin loader из env. **D-6** — concretization "magic-link" → bcrypt'd bootstrap password.
- Endpoints (`backend/src/api/routers/admin_auth.py`):
  - `POST /auth/admin/login {email, password}` → bcrypt verify → 200 + `Set-Cookie: argus.admin.session=<raw>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=1209600`. CSPRNG token (32 bytes from `secrets.token_bytes` → urlsafe-b64); HMAC pepper `ARGUS_ADMIN_SESSION_PEPPER` смешивается с raw перед sha256-hashing для DB-storage (raw никогда не лежит на диске). Rate-limited 5/15min/IP.
  - `POST /auth/admin/logout` → revoke session row, clear cookie.
  - `GET /auth/admin/whoami` → 200 `{email, role, authenticated_at}` | 401.
- `backend/src/core/config.py` env vars: `ADMIN_AUTH_MODE: Literal['cookie','session'] = 'cookie'`, `ARGUS_ADMIN_BOOTSTRAP_EMAIL`, `ARGUS_ADMIN_BOOTSTRAP_PASSWORD_BCRYPT`, `ARGUS_ADMIN_SESSION_PEPPER`, `ADMIN_SESSION_TTL_SECONDS=1209600` (14 days).
- `backend/src/api/dependencies.py::require_admin` — extends to dispatch by `ADMIN_AUTH_MODE`:
  - `cookie` (default) → existing path: trust X-Admin-Role/X-Admin-Tenant/X-Operator-Subject headers (which Frontend computes from cookies).
  - `session` → `argus.admin.session` cookie → DAO lookup → session-mode ServerSession constructed → 401 on miss/expired/revoked.
- Closed-taxonomy errors: `AUTH_INVALID_CREDENTIALS`, `AUTH_RATE_LIMITED`, `AUTH_SESSION_EXPIRED`, `AUTH_SESSION_REVOKED`, `AUTH_BOOTSTRAP_NOT_CONFIGURED`.
- Audit emit: `admin.login`, `admin.logout`, `admin.session.expired` (fires from beat-prune).

##### B6-T09 (G20b — frontend half):
- `Frontend/src/services/admin/serverSession.ts` → dual-mode resolver:
  - `process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE !== 'session'` → existing cookie path (byte-equivalent).
  - `=== 'session'` → `callAdminBackendJson('/auth/admin/whoami')` → maps to `ServerAdminSession`.
- Новый `Frontend/src/services/admin/clientLogin.ts` — POST proxy.
- Новый `/admin/login` route: Server Component + LoginClient.tsx (typed form, server-action, redirect `/admin` on success).
- `AdminLayoutClient.tsx` получает Logout button (показывается только при session-mode).
- `Frontend/src/middleware.ts` (новый или extension): при session-mode и отсутствии cookie → 302 `/admin/login`.
- `NEXT_PUBLIC_ADMIN_AUTH_MODE` в `Frontend/.env.example`.
- Playwright project `admin-session-auth` (отдельный от существующих project'ов, чтобы legacy cookie-mode E2E baseline сохранилась без изменений).
- 6+ E2E scenarios + 8+ vitest cases.

##### Phase 2 deferral — `ISS-T20-003-phase2.md`:
Создаётся в B6-T10 (closeout). Содержит scope для (d) MFA + (e) runbook:
- TOTP via `pyotp` + backup codes (hashed).
- IdP integration option (OIDC через Authlib).
- Production runbook: bootstrap admin rotation procedure, session pepper rotation, broken-glass procedure (`ARGUS_ADMIN_BOOTSTRAP_RECOVERY_TOKEN` env).

#### 1.6 Cycle 6 sign-off (T53 → B6-T10)

Last task of Batch 6 = last task of Cycle 6. Deliverables:

- `ai_docs/develop/reports/2026-04-22-argus-finalization-cycle6.md` (≥800 строк, mirror Cycle 5 sign-off):
  - Executive summary
  - Per-batch deliverables (Batch 1–6, T01–T53)
  - Quality gates (CI matrix, coverage, axe, verapdf, kind, cosign, RLS)
  - Open issues
  - Production-readiness scorecard
  - Deviation registry (D-1 .. D-7 этого batch + предыдущих циклов)
  - Forward path (Cycle 7 scope outline)
- `CHANGELOG.md` rollup section: Cycle 6 закрыт, ISS-T20-003 (Phase 1) + ISS-T26-001 закрыты, Phase 2 deferred.
- `ISS-cycle7-carry-over.md`: ISS-T20-003-phase2 + любые новые ISS-* за Cycle 6.
- `ISS-T20-003-phase2.md`: scope + acceptance для (d)+(e).
- `ai_docs/develop/reports/2026-04-22-cycle6-batch6-implementation.md` (batch-level, ≥400 строк) — параллельный батч-репорт в стиле b5 implementation report.

### Что НЕ закрывает Batch 6

- **Cycle 7 — security hardening**: deeper RBAC (granular per-resource permissions), MFA, runbook (ISS-T20-003 Phase 2), IdP integration. Carry-over в `ISS-cycle7-carry-over.md`.
- **SARIF/SBOM continuous publishing pipeline** — отдельная инициатива.
- **ARGUS public beta launch** — Cycle 8.
- **PostgreSQL minor version upgrade roadmap** — out-of-scope для этого batch.

### Зависимости Batch 6 от Batch 5 (всё shipped)

- `_emit_audit` pattern (`backend/src/api/routers/admin_emergency.py`) — переиспользуется для `admin.login` / `admin.logout` audit.
- `_admin_role_dep` + `_admin_tenant_dep` — существующая контракт-цепочка для RBAC; B6-T08 `require_admin` dispatch её сохраняет.
- `callAdminBackendJson` (`Frontend/src/services/admin/`) — переиспользуется в `clientLogin.ts` и в session-mode `serverSession.ts` для POST `/auth/admin/whoami`.
- `extractActionCode`-pattern + `ERROR_MESSAGES_RU` (`Frontend/src/lib/adminSchedules.ts`) — каноничный template для `adminAuth.ts`.
- `apply_beat_schedule` (`backend/src/celery/beat_schedule.py`) — расширяется новой entry для `argus.observability.queue_depth_emit` (B6-T03).
- `axe-core` Playwright config (`Frontend/tests/e2e/admin-axe.spec.ts`) — B6-T07 удаляет 7 `test.fail` без иной модификации tagging.
- `Mock backend` (`Frontend/tests/e2e/fixtures/admin-backend-mock.ts`, 1559 lines as of Batch 5) — B6-T09 расширяет /auth/admin/* handlers + sentinel для rate-limit.
- `Tenant` ORM (`backend/src/db/models.py`) — B6-T02 добавляет ENUM-column рядом с существующими `rate_limit_rpm` / `retention_days` (precedent для flat-column tenant-config).
- `tool_catalog_coverage` ratchet (`backend/tests/test_tool_catalog_coverage.py`) — B6-T05 расширяет `COVERAGE_MATRIX_CONTRACTS` с 16 → 18.

---

## 2. Сводка верификации состояния (что подтверждено на диске)

### Подтверждённые факты

| Проверка | Результат |
|----------|-----------|
| Latest Alembic migration | `027_webhook_dlq.py` (Batch 5 T37, ARG-053) — следующие свободные revisions: `028`, `029` |
| LaTeX templates | `backend/templates/reports/_latex/{asgard,midgard,valhalla}/main.tex.j2` — Phase-2 (ARG-048) wiring shipped, PDF/A preamble отсутствует |
| `LatexBackend` | `backend/src/reports/pdf_backend.py` — Phase-2 jinja2-latex wired, нет archival_format switch |
| `verapdf` инфра | НЕТ (нет CI workflow, нет docker reference, нет helper scripts) |
| `Tenant` ORM | `backend/src/db/models.py` содержит `exports_sarif_junit_enabled`, `rate_limit_rpm`, `scope_blacklist`, `retention_days` (flat-column convention для tenant-config); НЕТ `pdf_archival_format` |
| Existing HPA | `infra/helm/argus/templates/hpa.yaml` — backend + celery HPAs, customMetrics-section для celery (commented в base values, активна в values-prod) |
| Prometheus Adapter | НЕТ (`Glob infra/helm/argus/templates/prometheus*` → 0 results) |
| `argus_celery_queue_depth` emitter | НЕТ (`Grep backend/src` — 0 hits на metric name; values-prod.yaml line 117 ссылается, но эмиттера нет) — **D-5** |
| `argus_findings_emitted_total{kev_listed=...}` | ЕСТЬ (`backend/src/core/observability.py:187-191`, labels `(tier, severity, kev_listed)`) — основа для KEV-aware HPA через **D-7** |
| `kind` cluster CI | ЕСТЬ как pattern (`Batch 5 T44` admission-policy-kind.yml) — переиспользуем для kev-hpa-kind.yml |
| `COVERAGE_MATRIX_CONTRACTS` | `backend/tests/test_tool_catalog_coverage.py:228` = `16` (assertion line 1259), C17 + C18 ещё не добавлены |
| Frontend `--accent` token | `Frontend/src/app/globals.css:14` = `#A655F7` — contrast vs `--bg-primary` (#0a0a0a) = 4.20:1 (FAIL для WCAG AA на text). НЕТ `--accent-strong` |
| `admin-axe.spec.ts` `test.fail` | `Frontend/tests/e2e/admin-axe.spec.ts` — **7 annotations** referencing ISS-T26-001 (lines 265-507) — verified |
| `admin-axe.spec.ts` ISS-T26-001 surfaces | (1) operations-admin throttle CTA, (2) schedules-super-admin CTA, (3) schedules-admin CTA, (4) audit-chain-ok-banner, (5) operations-stop-all-dialog (throttle behind), (6) operations-throttle-dialog confirm, (7) schedules-editor-dialog tab+CTA |
| `serverSession.ts` | `Frontend/src/services/admin/serverSession.ts` — cookie+env-driven; explicit comment lines 7-28 referencing ISS-T20-003 |
| `Frontend/middleware.ts` | НЕТ (`Glob` → 0 results) — нужно создать в B6-T09 |
| `require_admin` | `backend/src/api/routers/admin.py` (+ `dependencies.py`) — trusts `X-Admin-Key`; cookie-derived headers |
| Cycle 5 sign-off | `ai_docs/develop/reports/2026-04-20-argus-finalization-cycle5.md` — 772 строки (структурный референс для T53 ≥ 800) |
| Existing `require_admin` dependency wiring | `backend/src/api/routers/admin.py::require_admin` — единственная точка входа admin-RBAC; B6-T08 расширяет dispatch БЕЗ breaking changes |
| `apply_beat_schedule` | `backend/src/celery/beat_schedule.py` — extension point для нового `argus.observability.queue_depth_emit` (B6-T03) |
| `passlib[bcrypt]` зависимость | Уже в проекте (используется в существующих places) — B6-T08 не вводит новых runtime deps |

### DEVIATIONS FROM ROADMAP (action required)

| # | Deviation | Impact | Resolution |
|---|-----------|--------|------------|
| **D-1** | Per user instruction: "combine T46+T47 if needed (PDF/A pipeline)" | T46 (templates) и T47 (verapdf gate) образуют единый verifiable deliverable — templates без gate не valid'ируются, gate без templates ничего не проверяет. | **B6-T01 объединяет оба** под единым acceptance criteria (verapdf clean → 0 errors / 0 warnings на golden render всех трёх tier'ов). Размер L; cap ≤12 не нарушен (10 < 12). |
| **D-2** | Roadmap §G20 предполагает один atomic; user offered split | G20 atomic ~ 13+ files / 30+ tests / 4 backend modules / 5 frontend modules. Single-task makes review hard, blocks parallel wave. | **Split на B6-T08 (G20a backend) + B6-T09 (G20b frontend)**. B6-T09 depends on B6-T08; landing strategy: B6-T08 merges first, deploy with `ADMIN_AUTH_MODE=cookie` (back-compat), B6-T09 merges next, flip flag in staging→prod. |
| **D-3** | Per user instruction: stay ≤12 tasks; T50+T51 logically inseparable | T50 (HPA YAML) без T51 (kind verification) даёт unship-able код — Kubernetes HPA с дefault `behavior` policies — known foot-gun (resource thrash). | **B6-T04 объединяет T50 + T51** — HPA YAML + integration test land в одном PR. |
| **D-4** | Roadmap §T48 называет flag `tenant_config.reports.pdf_archival_format` (nested JSON) | `Tenant` ORM использует flat-column convention для tenant-config (`rate_limit_rpm`, `scope_blacklist`, `retention_days`, `exports_sarif_junit_enabled`). Введение nested JSON под `tenant_config.reports.*` ломает convention; админ API становится dual-shape (flat для всех остальных fields + nested для reports.*). | **B6-T02 использует flat column `tenants.pdf_archival_format`** (Postgres ENUM `pdfa_format` ('standard', 'pdfa-2u'), default 'standard'). Naming sed: roadmap → реальное имя — зафиксировано в `029_tenant_pdf_archival_format.py` docstring + B6-T02 acceptance. |
| **D-5** | `argus_celery_queue_depth` метрика отсутствует в коде, но `values-prod.yaml:117` уже ссылается | Существующая celery HPA в проде silent no-op — скейлит только по CPU; pdb на queue overflow не работает. | **B6-T03 backfill**: новый Celery beat task `argus.observability.queue_depth_emit` (period 30s) использует `app.control.inspect()` для подсчёта per-queue length; emits Gauge `argus_celery_queue_depth{queue}`. Emitter wrapped в try/except (broker offline → swallow + structured log). |
| **D-6** | User-spec'd "magic-link via env-shared bootstrap admin" под-specified | Magic-link требует email infrastructure / SMTP / token storage — incompatible с "минимальный viable, no IdP". Real-world prod выбирает password-bcrypt как абсолютный baseline. | **B6-T08 concretizes**: `ARGUS_ADMIN_BOOTSTRAP_EMAIL` + `ARGUS_ADMIN_BOOTSTRAP_PASSWORD_BCRYPT` env (operator генерит bcrypt hash через `python -c 'import bcrypt; print(bcrypt.hashpw(b"<pw>", bcrypt.gensalt(12)).decode())'`). `POST /auth/admin/login` bcrypt-verify'ит. CSPRNG session cookie. Магический-link infrastructure — выноситcя в Phase 2 (`ISS-T20-003-phase2.md`). |
| **D-7** | Roadmap §T50 implies new backend metric для KEV trigger | `argus_findings_emitted_total{kev_listed="true"}` уже есть; новая метрика создаст дублирование без semantic difference. | **B6-T04 binds HPA к derived-метрике**: Prometheus Adapter rule `rate(argus_findings_emitted_total{kev_listed="true"}[5m])` → external metric `argus.kev.findings.emit.rate.5m`. Target average 1.0/s (1 KEV finding/s sustained over 5min triggers scale-up). Никакого нового backend code для метрики не требуется. |

### Latest Alembic migration on disk

```
backend/alembic/versions/
  ...
  023_epss_kev_tables.py             (Batch 1, ARG-044)
  024_tenant_exports_sarif_junit.py  (Batch 1 T04)
  025_tenant_limits_overrides.py     (Batch 2 T13)
  026_scan_schedules.py              (Batch 4 T32)
  027_webhook_dlq.py                 (Batch 5 T37, ARG-053)
  -> 028_admin_sessions.py           <- THIS BATCH (B6-T08 / G20a)
  -> 029_tenant_pdf_archival_format.py <- THIS BATCH (B6-T02 / T48)
```

`028 → 029` — линейная цепочка, `down_revision` mappings: 028.down='027', 029.down='028'.

### Existing Frontend admin routes (after Batch 5)

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
/admin/webhooks/dlq     -> page.tsx + WebhookDlqClient.tsx (T41 / Batch 5)
```

**This batch adds:**

```
/admin/login            -> page.tsx + LoginClient.tsx (B6-T09 / G20b)
```

`AdminLayoutClient.tsx` NAV получает Logout button (виден только при `NEXT_PUBLIC_ADMIN_AUTH_MODE=session`).

---

## 3. Задачи (B6-T01 .. B6-T10) с зависимостями

| ID | Title | Roadmap | Size | Wave | Deps | Files (est.) | Owner | Status |
|----|-------|---------|------|------|------|--------------|-------|--------|
| **B6-T01** | PDF/A-2u pipeline (templates + ICC + font + verapdf gate) | T46 + T47 (D-1) | L | 1 | — | ~10 | worker | Pending |
| **B6-T02** | Per-tenant `pdf_archival_format` flag | T48 (D-4) | M | 2 | B6-T01 | ~10 | worker | Pending |
| **B6-T03** | Helm Prometheus Adapter + queue_depth gauge backfill | T49 (D-5) | M | 1 | — | ~10 | worker | Pending |
| **B6-T04** | KEV-aware HPA + kind cluster integration test | T50 + T51 (D-3, D-7) | L | 2 | B6-T03 | ~7 | worker | Pending |
| **B6-T05** | Coverage matrix C17 + C18 ratchets | T52 | S | 1 | — | ~2 | worker | Pending |
| **B6-T06** | G26 design tokens — `--accent-strong` + `--on-accent` | ISS-T26-001 Option A (foundation) | S | 1 | — | ~2 | worker | Pending |
| **B6-T07** | G26 surface migration (13 surfaces) + remove 7 `test.fail` | ISS-T26-001 Option A (surface) | L | 2 | B6-T06 | ~14 | worker | Pending |
| **B6-T08** | G20a — Backend admin sessions + `ADMIN_AUTH_MODE` | ISS-T20-003 Phase 1 Option B (D-2, D-6) | L | 1 | — | ~9 | worker | Pending |
| **B6-T09** | G20b — Frontend session-mode wiring + login + E2E | ISS-T20-003 Phase 1 Option B (D-2) | L | 2 | B6-T08 | ~13 | worker | Pending |
| **B6-T10** | T53 closeout — sign-off + CHANGELOG + carry-over + Phase 2 issue | T53 | M | 3 | All prior | ~5 | documenter | Pending |

**Итого:** 10 задач • ~82 файла изменено/создано • ~3 рабочих дня wall-time.

---

## 4. DAG визуально

ASCII-граф зависимостей (стрелка `->` = "блокирует"):

```
                                                                       
  WAVE 1 (foundation, fully parallel — 5 tasks):                       
                                                                       
   B6-T01 (PDF/A pipeline)         B6-T03 (Prom Adapter + gauge)       
        |                               |                              
                                                                       
   B6-T05 (C17 + C18 ratchets)     B6-T06 (design tokens)              
                                        |                              
                                                                       
   B6-T08 (G20a backend auth)                                          
        |                                                              
                                                                       
                                                                       
                                                                       
  WAVE 2 (surface, depend on wave 1 — 4 tasks):                        
                                                                       
   B6-T02 (pdf_archival_format flag)  B6-T04 (KEV HPA + kind test)     
                                                                       
   B6-T07 (G26 surface migration)     B6-T09 (G20b frontend auth)      
                                                                       
                                                                       
                                                                       
  WAVE 3 (closeout — 1 task):                                          
                                                                       
   B6-T10 (sign-off + CHANGELOG + carry-over + Phase 2)                
                                                                       
                                                                       
```

**Параллелизм по wave (с 2 workers):**

| Wave | Задачи | Параллельно? | Длина (часов, оценка) |
|------|--------|--------------|------------------------|
| 1 | B6-T01 + B6-T03 + B6-T05 + B6-T06 + B6-T08 | да (no shared files) — pair'имся: (T01+T03), (T05+T06+T08) | max(8h, 6h) ≈ 10h |
| 2 | B6-T02 + B6-T04 + B6-T07 + B6-T09 | да (no shared files) — pair'имся: (T02+T04), (T07+T09) | max(6h, 9h) ≈ 9h |
| 3 | B6-T10 | один worker (docs heavy) | 5h |

**Wall-time с 2-worker:** 10 + 9 + 5 = **24 часов = ~3 рабочих дня** (включая CI runs и review циклы).

---

## 5. Per-task детали

### B6-T01 — PDF/A-2u pipeline (templates + ICC + font + verapdf gate)

**Goal:** Все три tier-шаблона (asgard, midgard, valhalla) рендерят PDF, который `verapdf` 1.26.x классифицирует как PDF/A-2u (zero errors, zero warnings). CI gate валидирует на каждом PR.

**Roadmap:** T46 + T47 (combined per **D-1**).

**Backend / Frontend split:** 100% backend + CI.

**Files:**
- `backend/templates/reports/_latex/asgard/main.tex.j2` (extend preamble)
- `backend/templates/reports/_latex/midgard/main.tex.j2` (extend preamble)
- `backend/templates/reports/_latex/valhalla/main.tex.j2` (extend preamble)
- `backend/templates/reports/_latex/_assets/sRGB-IEC61966-2.1.icc` (NEW — public domain ICC v2)
- `backend/templates/reports/_latex/_assets/lmroman10-regular.otf` (NEW — embed-mandatory)
- `backend/src/reports/pdf_backend.py` (LatexBackend → archival_format aware)
- `backend/src/reports/_latex_pdfa.py` (NEW — preamble injector + asset resolver)
- `infra/scripts/verify-pdfa.sh` (NEW — verapdf invocation wrapper)
- `.github/workflows/pdfa-validation.yml` (NEW — Docker-based verapdf job)
- `backend/tests/test_pdfa_pipeline.py` (NEW — unit + golden integration ≥10 cases)

**LaTeX preamble sketch (новый, инжектируется через `_latex_pdfa.py` при `archival_format='pdfa-2u'`):**

```latex
% PDF/A-2u — препамбла, инжектируется helper'ом для всех 3 tier'ов.
\usepackage[a-2u]{pdfx}
\hypersetup{pdfa}
\immediate\pdfobj stream attr {/N 3} file {sRGB-IEC61966-2.1.icc}
\pdfcatalog{/OutputIntents [ <<
  /Type/OutputIntent
  /S/GTS_PDFA1
  /OutputConditionIdentifier (sRGB IEC61966-2.1)
  /DestOutputProfile \the\pdflastobj\space 0 R
  /Info (sRGB IEC61966-2.1)
>> ]}
% XMP metadata via pdfx \pdfaxmp{...}
```

**Helper sketch (`_latex_pdfa.py`):**

```python
"""ARG-058 — PDF/A-2u preamble injection helper.

Resolves ICC profile + font asset paths and produces the additional preamble
text injected at compile time when ``archival_format='pdfa-2u'``.
"""

from __future__ import annotations
from pathlib import Path
from typing import Final

_ASSETS_DIR: Final[Path] = Path(__file__).parent / "../../templates/reports/_latex/_assets"
_ICC_PROFILE: Final[str] = "sRGB-IEC61966-2.1.icc"
_DEFAULT_FONT: Final[str] = "lmroman10-regular.otf"


def get_pdfa_assets() -> dict[str, Path]:
    """Return canonical absolute paths to PDF/A asset files."""
    base = _ASSETS_DIR.resolve()
    icc = base / _ICC_PROFILE
    font = base / _DEFAULT_FONT
    if not icc.is_file() or not font.is_file():
        raise FileNotFoundError(
            f"PDF/A assets missing under {base}: icc={icc.is_file()} font={font.is_file()}"
        )
    return {"icc": icc, "font": font}


def inject_pdfa_preamble(template_source: str) -> str:
    """Inject PDF/A-2u preamble after \\documentclass declaration.

    Idempotent: if marker `% PDF/A-2u — препамбла` already present, no-op.
    """
    marker = "% PDF/A-2u — препамбла"
    if marker in template_source:
        return template_source
    preamble = _PDFA_PREAMBLE_TEMPLATE  # ~30-line LaTeX block
    documentclass_end = template_source.index("}", template_source.index("\\documentclass")) + 1
    return template_source[:documentclass_end] + "\n\n" + preamble + "\n\n" + template_source[documentclass_end:]
```

**`pdf_backend.py` extension:**

```python
class LatexBackend(PDFBackend):
    def __init__(self, *, archival_format: Literal["standard", "pdfa-2u"] = "standard") -> None:
        self.archival_format = archival_format

    def render(self, html: str, *, context: RenderContext) -> bytes:
        latex_source = self._html_to_latex(html, context=context)
        if self.archival_format == "pdfa-2u":
            from src.reports._latex_pdfa import inject_pdfa_preamble, get_pdfa_assets
            latex_source = inject_pdfa_preamble(latex_source)
            extra_compile_args = self._build_pdfa_compile_args(get_pdfa_assets())
        else:
            extra_compile_args = []
        return self._compile_latex(latex_source, extra_args=extra_compile_args)
```

**`verify-pdfa.sh`:**

```bash
#!/usr/bin/env bash
# ARG-058 — verapdf invocation wrapper. Exits 0 on PDF/A-2u compliance, 1 otherwise.
set -euo pipefail
PDF_FILE="${1:?usage: verify-pdfa.sh <pdf>}"
docker run --rm -v "$(pwd):/workspace" verapdf/verapdf:1.26.2 \
  --flavour 2u --format text "/workspace/${PDF_FILE}" 2>&1 \
  | tee verapdf.log
grep -q 'PASS' verapdf.log
```

**`.github/workflows/pdfa-validation.yml`:**

```yaml
name: pdfa-validation

on:
  pull_request:
    paths:
      - 'backend/templates/reports/_latex/**'
      - 'backend/src/reports/pdf_backend.py'
      - 'backend/src/reports/_latex_pdfa.py'
      - 'infra/scripts/verify-pdfa.sh'

jobs:
  validate:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v4
      - name: Build golden PDFs
        run: |
          python -m pip install -e ./backend
          python -m backend.tests.fixtures.pdfa_render_golden --tier asgard --out /tmp/asgard.pdf
          python -m backend.tests.fixtures.pdfa_render_golden --tier midgard --out /tmp/midgard.pdf
          python -m backend.tests.fixtures.pdfa_render_golden --tier valhalla --out /tmp/valhalla.pdf
      - name: Validate PDF/A-2u
        run: |
          chmod +x infra/scripts/verify-pdfa.sh
          for f in /tmp/{asgard,midgard,valhalla}.pdf; do
            infra/scripts/verify-pdfa.sh "$f"
          done
```

**Acceptance criteria:**
- (a) Каждый tier рендерит PDF, который verapdf 1.26.x classify'ит как PDF/A-2u compliant (0 errors, 0 warnings)
- (b) ICC profile + Latin Modern font subset embedded; нет Type-3 fonts; нет transparency
- (c) verapdf CI job runs на PR'ах, трогающих `backend/templates/reports/_latex/**` или `backend/src/reports/pdf_backend.py`; fails build на non-compliance
- (d) `archival_format='standard'` → bypass PDF/A preamble (back-compat); `'pdfa-2u'` → inject + compile с extra args
- (e) ≥10 backend tests; integration test ассертит byte-level PDF/A flag в trailer dict (`/Subtype /PDF/A`, `/PDFA-2 u`)

---

### B6-T02 — Per-tenant `pdf_archival_format` flag

**Goal:** Per-tenant control над PDF archival форматом — admin/super-admin может toggle между `standard` и `pdfa-2u` на каждом тенанте независимо.

**Roadmap:** T48 (с **D-4** — flat column наименование).

**Backend / Frontend split:** 50/50.

**Files:**
- `backend/alembic/versions/029_tenant_pdf_archival_format.py` (NEW)
- `backend/src/db/models.py` (Tenant.pdf_archival_format ENUM)
- `backend/src/api/routers/admin_tenants.py` (PATCH payload extension)
- `backend/src/api/schemas.py` (TenantUpdate field)
- `backend/src/reports/orchestrator.py` (read tenant flag → PDFBackend)
- `backend/tests/test_tenant_pdf_archival_format.py` (NEW, ≥12 cases)
- `Frontend/src/app/admin/tenants/[tenantId]/page.tsx` или Client (Toggle)
- `Frontend/src/lib/adminTenants.ts` (taxonomy + helpers)
- `Frontend/tests/e2e/admin-tenants.spec.ts` (extend ≥3 cases)
- `Frontend/src/__tests__/adminTenants.test.ts` (≥6 vitest cases)

**Migration sketch:**

```python
# backend/alembic/versions/029_tenant_pdf_archival_format.py
"""tenants.pdf_archival_format ENUM column.

Revision ID: 029
Revises: 028
Create Date: 2026-04-22

ARG-058 / Cycle 6 Batch 6 / B6-T02 / T48.

Per-tenant control over PDF archival format. Default 'standard' preserves
backward-compat — existing tenants continue rendering with WeasyPrint /
legacy LaTeX. Operators flip to 'pdfa-2u' when their compliance audit
requires it; the LatexBackend then injects PDF/A-2u preamble + ICC profile
(see `src/reports/_latex_pdfa.py`).

Deviation D-4 from roadmap: flat column instead of nested
`tenant_config.reports.pdf_archival_format` JSON. The Tenant ORM uses
flat-column convention for tenant-config (see rate_limit_rpm,
scope_blacklist, retention_days, exports_sarif_junit_enabled). Nested JSON
would split admin API schema into two shapes; flat preserves uniformity.
"""

from __future__ import annotations
from collections.abc import Sequence
from typing import Final

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "029"
down_revision: str | None = "028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ENUM_NAME: Final[str] = "pdf_archival_format_enum"
ENUM_VALUES: Final[tuple[str, ...]] = ("standard", "pdfa-2u")
COLUMN_NAME: Final[str] = "pdf_archival_format"


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"
    if is_postgres:
        pdfa_enum = postgresql.ENUM(*ENUM_VALUES, name=ENUM_NAME, create_type=False)
        pdfa_enum.create(bind, checkfirst=True)
        op.add_column(
            "tenants",
            sa.Column(COLUMN_NAME, pdfa_enum, nullable=False, server_default="standard"),
        )
    else:
        op.add_column(
            "tenants",
            sa.Column(COLUMN_NAME, sa.String(16), nullable=False, server_default="standard"),
        )


def downgrade() -> None:
    op.drop_column("tenants", COLUMN_NAME)
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(f"DROP TYPE IF EXISTS {ENUM_NAME}")
```

**ORM extension:**

```python
# backend/src/db/models.py — добавить в Tenant class
from typing import Literal

PdfArchivalFormat = Literal["standard", "pdfa-2u"]

class Tenant(Base):
    ...
    pdf_archival_format: Mapped[PdfArchivalFormat] = mapped_column(
        String(16), nullable=False, server_default="standard"
    )
```

**API schema extension:**

```python
# backend/src/api/schemas.py — TenantUpdate
class TenantUpdate(BaseModel):
    ...
    pdf_archival_format: Literal["standard", "pdfa-2u"] | None = None
```

**Frontend toggle (`Frontend/src/app/admin/tenants/[tenantId]/PdfArchivalToggle.tsx`):**

```typescript
"use client";
import { useState } from "react";
import { updateTenantAction } from "./actions";

const FORMATS = [
  { value: "standard" as const, label: "Стандарт (WeasyPrint)" },
  { value: "pdfa-2u" as const, label: "PDF/A-2u (архивный)" },
];

export function PdfArchivalToggle({
  tenantId,
  initial,
}: {
  tenantId: string;
  initial: "standard" | "pdfa-2u";
}) {
  const [value, setValue] = useState(initial);
  return (
    <fieldset>
      <legend className="text-sm font-medium">Формат PDF-отчётов</legend>
      <div className="mt-2 flex gap-3">
        {FORMATS.map((f) => (
          <label key={f.value} className="flex items-center gap-2">
            <input
              type="radio"
              name="pdf_archival_format"
              value={f.value}
              checked={value === f.value}
              onChange={async () => {
                const prev = value;
                setValue(f.value);
                const res = await updateTenantAction({
                  tenantId,
                  pdf_archival_format: f.value,
                });
                if (!res.ok) setValue(prev);
              }}
              className="accent-[var(--accent-strong)]"
            />
            <span>{f.label}</span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}
```

**Acceptance criteria:**
- (a) Migration upgrade/downgrade idempotent на Postgres + SQLite
- (b) Default 'standard' preserves backward-compat (existing rows nullable until backfill — `server_default` решает)
- (c) PATCH /admin/tenants/{id} accepts `{pdf_archival_format: 'standard'|'pdfa-2u'}`; super-admin может cross-tenant; admin только own
- (d) Audit emit `tenant.pdf_archival_format.update {old, new}` через `_emit_audit`
- (e) Tenants UI показывает toggle bound к тенанту; optimistic update с server-action error rollback
- (f) Closed-taxonomy reject'ит unknown enum values both server-side и client-side
- (g) E2E ассертит toggle persistence across reload + audit row written

---

### B6-T03 — Helm Prometheus Adapter + queue_depth gauge backfill

**Goal:** Подключить Prometheus Adapter как optional Helm subchart; добавить эмиттер `argus_celery_queue_depth` Gauge (closing **D-5** gap), подготовить custom-metrics rules для KEV-aware HPA (B6-T04).

**Roadmap:** T49 (с **D-5** — backfill метрики).

**Backend / Frontend split:** 30% backend (gauge emitter) / 70% infra (Helm).

**Files:**
- `infra/helm/argus/Chart.yaml` (add prometheus-adapter dependency)
- `infra/helm/argus/values.yaml` (prometheusAdapter section)
- `infra/helm/argus/values-prod.yaml` (enable in prod)
- `infra/helm/argus/templates/prometheus-adapter-rules.yaml` (NEW — ConfigMap)
- `infra/helm/argus/templates/_helpers.tpl` (helper)
- `backend/src/celery/tasks/queue_depth_emit.py` (NEW — beat task)
- `backend/src/core/observability.py` (register Gauge)
- `backend/src/celery/beat_schedule.py` (register task)
- `backend/tests/test_queue_depth_emitter.py` (NEW, ≥8 cases)

**Beat task sketch:**

```python
# backend/src/celery/tasks/queue_depth_emit.py
"""ARG-059 — Celery queue depth emitter (D-5 backfill).

Periodically introspects all known Celery queues and publishes their depth
as a Prometheus Gauge so KEV-aware HPA can react. Runs every 30s under the
``argus.observability.queue_depth_emit`` beat task.

values-prod.yaml lines 115-118 already reference ``argus_celery_queue_depth``
as the celery HPA custom metric, but no source emitted the metric until
ARG-059. Without this emitter, the existing celery HPA scales solely by CPU.
"""

from __future__ import annotations
import logging
from typing import Final

from celery import shared_task

from src.celery_app import app as celery_app
from src.core.observability import set_celery_queue_depth

_logger = logging.getLogger(__name__)

KNOWN_QUEUES: Final[tuple[str, ...]] = (
    "argus.scans",
    "argus.reports",
    "argus.tools",
    "argus.recon",
    "argus.exploitation",
    "argus.intel",
    "argus.notifications",
    "argus.default",
)


@shared_task(name="argus.observability.queue_depth_emit", ignore_result=True)
def emit_queue_depth() -> None:
    try:
        inspect = celery_app.control.inspect(timeout=5.0)
        reserved = inspect.reserved() or {}
        active = inspect.active() or {}
    except Exception:
        _logger.warning("celery.queue_depth_emit.inspect_failed", exc_info=True)
        return

    per_queue: dict[str, int] = {q: 0 for q in KNOWN_QUEUES}
    for tasks in (reserved.values()):
        for task in tasks:
            queue = task.get("delivery_info", {}).get("routing_key", "argus.default")
            per_queue[queue] = per_queue.get(queue, 0) + 1
    for tasks in (active.values()):
        for task in tasks:
            queue = task.get("delivery_info", {}).get("routing_key", "argus.default")
            per_queue[queue] = per_queue.get(queue, 0) + 1

    for queue, depth in per_queue.items():
        set_celery_queue_depth(queue=queue, depth=depth)
```

**Observability extension:**

```python
# backend/src/core/observability.py — добавить spec + setter
_MetricSpec(
    name="argus_celery_queue_depth",
    documentation="Approximate number of reserved+active tasks per Celery queue.",
    labels=("queue",),
    kind="gauge",
),

# allow-list дополняется:
_QUEUE_NAMES: Final[frozenset[str]] = frozenset(
    {"argus.scans", "argus.reports", "argus.tools", "argus.recon",
     "argus.exploitation", "argus.intel", "argus.notifications", "argus.default"},
)
LABEL_VALUE_WHITELIST["queue"] = _QUEUE_NAMES

def set_celery_queue_depth(*, queue: str, depth: int) -> None:
    metric = _METRICS.get("argus_celery_queue_depth")
    if metric is None or not _LabelGuard.normalize(queue, "queue"):
        return
    try:
        metric.labels(queue=queue).set(max(0, int(depth)))
    except Exception:
        _logger.debug("observability.set_celery_queue_depth_failed", exc_info=True)
```

**Beat schedule extension:**

```python
# backend/src/celery/beat_schedule.py — добавить
"argus.observability.queue_depth_emit": {
    "task": "argus.observability.queue_depth_emit",
    "schedule": 30.0,  # every 30s
    "options": {"queue": "argus.observability"},
},
```

**Helm Prometheus Adapter rule (new ConfigMap template):**

```yaml
{{- if and .Values.prometheusAdapter.enabled (default false .Values.prometheusAdapter.rules.argus.enabled) -}}
apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ include "argus.fullname" . }}-prometheus-adapter-rules
  labels: {{ include "argus.labels" . | nindent 4 }}
data:
  custom-rules.yaml: |
    rules:
      - seriesQuery: 'argus_celery_queue_depth{namespace!=""}'
        resources:
          overrides:
            namespace: {resource: namespace}
        name:
          matches: "argus_celery_queue_depth"
          as: "argus.celery.queue.depth"
        metricsQuery: 'sum by (namespace, queue) (avg_over_time(argus_celery_queue_depth[2m]))'
      - seriesQuery: 'argus_findings_emitted_total{kev_listed="true",namespace!=""}'
        resources:
          overrides:
            namespace: {resource: namespace}
        name:
          matches: "argus_findings_emitted_total"
          as: "argus.kev.findings.emit.rate.5m"
        metricsQuery: 'sum by (namespace) (rate(argus_findings_emitted_total{kev_listed="true"}[5m]))'
{{- end -}}
```

**values.yaml addition:**

```yaml
prometheusAdapter:
  enabled: false  # opt-in; prod overlay flips to true
  rules:
    argus:
      enabled: true  # render argus-specific rules ConfigMap
```

**Acceptance criteria:**
- (a) `helm template -f values-prod.yaml argus .` рендерит prometheus-adapter ConfigMap when `prometheusAdapter.enabled=true`; render nothing when disabled
- (b) Beat task runs every 30s; emits one Gauge sample per known-queue
- (c) `inspect()` failure (broker offline) → swallow + structured-warning; gauge сохраняет last value
- (d) Prometheus Adapter rule maps `argus_celery_queue_depth` → external metric `argus.celery.queue.depth`
- (e) Prometheus Adapter rule для KEV: `rate(argus_findings_emitted_total{kev_listed="true"}[5m])` → `argus.kev.findings.emit.rate.5m`
- (f) kubeconform smoke ✓ on rendered ConfigMap; helm-validation.yml matrix зелёный с обоими toggle states

---

### B6-T04 — KEV-aware HPA + kind cluster integration test

**Goal:** Новый HPA `hpa-celery-worker-kev.yaml` биндится к derived `argus.kev.findings.emit.rate.5m` external metric (Prometheus Adapter); kind-cluster integration test проверяет full path Helm → Prometheus → Adapter → HPA.

**Roadmap:** T50 + T51 (combined per **D-3**; metric source per **D-7**).

**Backend / Frontend split:** 100% infra + integration test.

**Files:**
- `infra/helm/argus/templates/hpa-celery-worker-kev.yaml` (NEW)
- `infra/helm/argus/values.yaml` (hpa.celeryKevAware section)
- `infra/helm/argus/values-prod.yaml` (enable kev-aware variant)
- `tests/integration/k8s/test_kev_aware_hpa.py` (NEW)
- `tests/integration/k8s/conftest.py` (extend kind fixture)
- `.github/workflows/kev-hpa-kind.yml` (NEW)
- `ai_docs/develop/architecture/kev-aware-autoscaling.md` (NEW, ≥150 lines)

**HPA template:**

```yaml
{{- if and .Values.hpa.enabled .Values.hpa.celeryKevAware.enabled -}}
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ include "argus.fullname" . }}-celery-kev
  labels: {{ include "argus.labels" . | nindent 4 }}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ include "argus.fullname" . }}-celery
  minReplicas: {{ .Values.hpa.celeryKevAware.minReplicas | default 4 }}
  maxReplicas: {{ .Values.hpa.celeryKevAware.maxReplicas | default 40 }}
  metrics:
    - type: External
      external:
        metric:
          name: argus.kev.findings.emit.rate.5m
        target:
          type: AverageValue
          averageValue: {{ .Values.hpa.celeryKevAware.targetEmitRatePerSec | default "1.0" | quote }}
  behavior:
    scaleUp:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 100
          periodSeconds: 60
        - type: Pods
          value: 4
          periodSeconds: 60
      selectPolicy: Max
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
        - type: Percent
          value: 25
          periodSeconds: 60
      selectPolicy: Min
{{- end -}}
```

**values.yaml addition:**

```yaml
hpa:
  ...
  celeryKevAware:
    enabled: false  # opt-in; prod overlay flips to true
    minReplicas: 4
    maxReplicas: 40
    targetEmitRatePerSec: "1.0"  # 1 KEV finding per second sustained over 5m → scale up
```

**Integration test sketch:**

```python
# tests/integration/k8s/test_kev_aware_hpa.py
"""ARG-059 — KEV-aware HPA kind cluster integration test.

Pre-conditions:
  * kind v1.31 cluster up (CI fixture).
  * Prometheus + Prometheus Adapter installed via Helm.
  * Argus chart deployed with hpa.celeryKevAware.enabled=true.

Test flow:
  1. Sanity: kubectl get hpa <name>-celery-kev → desiredReplicas == minReplicas.
  2. Inject burst: push fake metric `argus_findings_emitted_total{kev_listed="true"}`
     to Prometheus pushgateway at 5/s for 60s.
  3. Wait ≤120s; assert HPA status replicas grew above minReplicas.
  4. Stop injection; wait stabilization window + 30s; assert scaled back down.
"""

import json
import subprocess
import time
from typing import Final

import pytest

NAMESPACE: Final[str] = "argus-test"
HPA_NAME: Final[str] = "argus-celery-kev"


def _kubectl_json(*args: str) -> dict:
    result = subprocess.run(
        ["kubectl", "-n", NAMESPACE, *args, "-o", "json"],
        capture_output=True, text=True, check=True,
    )
    return json.loads(result.stdout)


def _hpa_status_replicas() -> int:
    return _kubectl_json("get", "hpa", HPA_NAME)["status"].get("desiredReplicas", 0)


def _push_metric(value: float) -> None:
    subprocess.run(
        [
            "curl", "-X", "POST",
            "--data-binary", f"argus_findings_emitted_total{{kev_listed=\"true\",namespace=\"{NAMESPACE}\"}} {value}",
            "http://prometheus-pushgateway.monitoring.svc:9091/metrics/job/kev_test",
        ],
        check=True, timeout=10,
    )


@pytest.mark.kind_cluster
def test_kev_burst_triggers_scale_up() -> None:
    initial = _hpa_status_replicas()
    for _ in range(60):
        _push_metric(5.0)
        time.sleep(1)
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if _hpa_status_replicas() > initial:
            break
        time.sleep(5)
    assert _hpa_status_replicas() > initial, "KEV burst failed to trigger HPA scale-up"


@pytest.mark.kind_cluster
def test_no_kev_holds_at_min_replicas() -> None:
    time.sleep(330)  # past stabilization window
    assert _hpa_status_replicas() <= 5, "HPA failed to scale back to min after KEV burst ended"
```

**CI workflow:**

```yaml
name: kev-hpa-kind

on:
  pull_request:
    paths:
      - 'infra/helm/argus/templates/hpa-celery-worker-kev.yaml'
      - 'infra/helm/argus/templates/prometheus-adapter-rules.yaml'
      - 'infra/helm/argus/values.yaml'
      - 'tests/integration/k8s/test_kev_aware_hpa.py'

jobs:
  kind-test:
    runs-on: ubuntu-22.04
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4
      - uses: helm/kind-action@v1
        with:
          version: v0.25.0
          kubectl_version: v1.31.0
          node_image: kindest/node:v1.31.0
      - name: Install Prometheus + Adapter + Pushgateway
        run: |
          helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
          helm install -n monitoring --create-namespace prom prometheus-community/kube-prometheus-stack
          helm install -n monitoring prometheus-adapter prometheus-community/prometheus-adapter
          helm install -n monitoring prometheus-pushgateway prometheus-community/prometheus-pushgateway
      - name: Install ARGUS chart with KEV HPA enabled
        run: |
          helm install -n argus-test --create-namespace argus ./infra/helm/argus \
            --set hpa.enabled=true \
            --set hpa.celeryKevAware.enabled=true \
            --set prometheusAdapter.enabled=true
      - name: Run integration tests
        run: |
          pip install pytest
          pytest -v -m kind_cluster tests/integration/k8s/test_kev_aware_hpa.py
      - name: Upload artifacts on failure
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: kev-hpa-kind-debug
          path: |
            /tmp/kube-events.txt
            /tmp/hpa-status.json
```

**Acceptance criteria:**
- (a) `hpa-celery-worker-kev.yaml` — это ВТОРОЙ HPA на одном Deployment как и `hpa.yaml`; Kubernetes union-семантика: `max(scale_recommendation_cpu, scale_recommendation_kev)` побеждает
- (b) `behavior.scaleUp.stabilizationWindowSeconds=300` AND `behavior.scaleDown.stabilizationWindowSeconds=300` (anti-flap)
- (c) `behavior.scaleUp.policies` включают +100% step every 60s; `scaleDown` caps at 25% per 60s
- (d) kind integration test: deploy chart → push fake metric → wait ≤120s → assert HPA status replicas grew
- (e) Negative path: no KEV findings → HPA holds at minReplicas after stabilization window
- (f) Workflow timeout ≤ 30 min; artifact upload kube-events + HPA snapshots
- (g) `kev-aware-autoscaling.md` design doc ≥ 150 строк

---

### B6-T05 — Coverage matrix C17 + C18 ratchets

**Goal:** Поднять `COVERAGE_MATRIX_CONTRACTS` с 16 до 18, добавив C17 (network policy allowlist resolution) + C18 (image tag immutability).

**Roadmap:** T52.

**Backend / Frontend split:** 100% backend (test gate).

**Files:**
- `backend/tests/test_tool_catalog_coverage.py` (extend; ratchet 16 → 18)
- `ai_docs/develop/architecture/tool-catalog-coverage.md` (extend if exists; otherwise inline docstring update)

**Contract C17 implementation sketch:**

```python
# backend/tests/test_tool_catalog_coverage.py — НОВЫЙ contract
@pytest.mark.parametrize("tool_id", ALL_TOOL_IDS)
def test_C17_network_policy_allowlist_targets_resolved(tool_id: str) -> None:
    """C17 — network_policy.allowlist resolves без unresolved tokens.

    Catches typo-allowlists like ``allowlist: ["argus-net"]`` becoming
    ``allowlist: [argus-net]`` (unquoted YAML token), where the resolver
    silently expands to ``*``. Such a slip would mean a sandbox tool gets
    the implicit-allow Kubernetes default at runtime.
    """
    from src.sandbox.network_policies import resolve_allowlist

    descriptor = _load_descriptor(tool_id)
    raw_allowlist = descriptor.network_policy.allowlist or []
    resolved = resolve_allowlist(raw_allowlist, allow_wildcards=False)
    unresolved = [token for token in resolved if token in {"*", "any", ""}]
    assert not unresolved, (
        f"[C17] tool={tool_id} has unresolved network_policy.allowlist "
        f"tokens={unresolved}; suspect typo or wildcard slip"
    )
```

**Contract C18:**

```python
_FLOATING_TAG_TOOLS_EXEMPT: Final[frozenset[str]] = frozenset({
    # Exemption list — every entry MUST link to an open ticket and inline
    # comment explaining why an immutable digest cannot be pinned today.
    # Empty as of Cycle 6 / B6-T05.
})

@pytest.mark.parametrize("tool_id", ALL_TOOL_IDS)
def test_C18_manifest_image_tag_immutable(tool_id: str) -> None:
    """C18 — descriptor.image references an immutable digest OR is exempt.

    Floating tags like ``nuclei:latest`` make CI builds non-reproducible
    and break supply-chain attestation (cosign verifies a digest, not a
    tag). Every tool image must end in ``@sha256:<64hex>`` unless explicitly
    exempted in :data:`_FLOATING_TAG_TOOLS_EXEMPT`.
    """
    if tool_id in _FLOATING_TAG_TOOLS_EXEMPT:
        pytest.skip(f"C18 exempt: {tool_id}")
    descriptor = _load_descriptor(tool_id)
    image = descriptor.image
    assert "@sha256:" in image, (
        f"[C18] tool={tool_id} image={image!r} is not pinned to an immutable digest; "
        f"add @sha256:<64hex> or extend _FLOATING_TAG_TOOLS_EXEMPT (with ticket link)"
    )
    digest = image.split("@sha256:", 1)[1]
    assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest), (
        f"[C18] tool={tool_id} image digest is not a valid 64-hex sha256: {digest!r}"
    )


# В конце файла — bumpнуть contract counter:
COVERAGE_MATRIX_CONTRACTS: Final[int] = 18

def test_coverage_matrix_contract_count_ratchet() -> None:
    assert COVERAGE_MATRIX_CONTRACTS == 18, (
        "Coverage matrix contract count moved away from 18; ratchet would "
        "permit silent erosion of coverage. Update COVERAGE_MATRIX_CONTRACTS "
        "in lock-step with the parametrised test additions."
    )
```

**Acceptance criteria:**
- (a) C17 + C18 implemented as parametrized tests (one per tool); fan-out 157 × 18 = 2826 cases
- (b) `COVERAGE_MATRIX_CONTRACTS = 18`; ratchet assertion updated
- (c) All 157 existing tools pass C17 + C18 OR explicitly listed in narrow exemption sets (empty as of B6-T05; future exemptions require inline comment + open ticket)
- (d) Pytest run completes <90s (cardinality boundary)

---

### B6-T06 — G26 design tokens (`--accent-strong` + `--on-accent` + design-tokens.md)

**Goal:** Добавить foundational design tokens для high-contrast CTAs; создать canonical design-tokens.md doc. Purely additive, никакого surface-migration в этой задаче.

**Roadmap:** ISS-T26-001 Option A (foundation phase).

**Backend / Frontend split:** 100% frontend + docs.

**Files:**
- `Frontend/src/app/globals.css` (add 4 tokens)
- `ai_docs/develop/architecture/design-tokens.md` (NEW)

**globals.css addition:**

```css
:root {
  /* Existing tokens unchanged ... */
  --accent: #A655F7;          /* original — KEEP for non-text usages (e.g., glitch effect, highlights) */
  --accent-hover: #b875f8;
  --accent-dim: #8b44d4;
  /* G26 / ISS-T26-001 — high-contrast variants для CTA backgrounds + текста-на-accent.
   * --accent-strong (#6B2EA8) дает contrast 7.04:1 vs --bg-primary (#0a0a0a) — AAA для normal text.
   * --on-accent (#ffffff) дает contrast 7.04:1 vs --accent-strong — AAA reciprocally. */
  --accent-strong: #6B2EA8;
  --on-accent: #ffffff;
  /* Заменяет bg-amber-600 / amber-700 family для warning CTAs.
   * --warning-strong (#B45309) дает contrast 5.36:1 vs --bg-primary — AA. */
  --warning-strong: #B45309;
  --on-warning: #ffffff;
}
```

**design-tokens.md content outline (≥120 строк):**

```markdown
# ARGUS Design Tokens — Canonical Reference

## Token Categories
1. Surface (--bg-*, --border-*)
2. Text (--text-*)
3. Accent (--accent, --accent-strong, --on-accent — when to use which)
4. Status (--success, --warning, --error, --warning-strong, --on-warning)
5. Selection / Highlight (--highlight)

## Contrast Matrix (computed)
| Foreground / Background | --bg-primary | --bg-secondary | --bg-tertiary |
|-------------------------|--------------|----------------|---------------|
| --text-primary          | 17.93:1 ✓ AAA | 15.62:1 ✓ AAA | 12.63:1 ✓ AAA |
| --text-secondary        |  7.27:1 ✓ AAA |  6.34:1 ✓ AAA |  5.13:1 ✓ AA  |
| --text-muted            |  5.77:1 ✓ AA  |  5.03:1 ✓ AA  |  4.69:1 ✓ AA  |
| --accent (text)         |  4.20:1 ✗ FAIL|  3.66:1 ✗ FAIL|  2.96:1 ✗ FAIL|
| --accent-strong (text)  |  7.04:1 ✓ AAA |  6.13:1 ✓ AAA |  4.95:1 ✓ AA  |
| --on-accent / --accent-strong | 7.04:1 ✓ AAA | — | — |
| --on-warning / --warning-strong | 5.36:1 ✓ AA | — | — |

## Migration Policy
- Direct usage of `bg-[var(--accent)]` on text-bearing CTAs is **deprecated** as of B6-T06.
- New CTAs MUST use `--accent-strong` (background) + `--on-accent` (text), or `--warning-strong` + `--on-warning`.
- Glitch effects, highlights, decorative borders MAY still use `--accent` (no text contrast requirement).
- Surface migration tracker: see B6-T07 plan for the 13-surface list.

## Decision Rationale
... (1-2 paragraphs per token introducing why hex chosen, what was considered, what was rejected) ...
```

**Acceptance criteria:**
- (a) Все 4 token'а добавлены в `:root`
- (b) `--accent-strong: #6B2EA8` (computed contrast 7.04:1 vs `--bg-primary`)
- (c) `--on-accent: #ffffff` (≥7:1 vs `--accent-strong`; AAA для normal text)
- (d) `--warning-strong: #B45309` + `--on-warning: #ffffff` (contrast 5.36:1)
- (e) `design-tokens.md` создан с token list + contrast matrix + migration policy + rationale
- (f) НИКАКОЙ surface не мигрирован в этой задаче (purely additive, нулевая behavior-difference)
- (g) Vitest snapshot Tailwind theme config → no regression on existing variables

---

### B6-T07 — G26 surface migration (13 surfaces) + remove 7 `test.fail`

**Goal:** Заменить direct `bg-[var(--accent)]` / `bg-amber-600` на новые токены в 13 admin-surfaces; удалить все 7 `test.fail("ISS-T26-001:...")` annotations в `admin-axe.spec.ts`. Закрыть ISS-T26-001.

**Roadmap:** ISS-T26-001 Option A (surface phase).

**Backend / Frontend split:** 100% frontend.

**Files:**
- `Frontend/src/app/admin/audit-logs/AdminAuditLogsClient.tsx`
- `Frontend/src/app/admin/operations/throttle/PerTenantThrottleClient.tsx`
- `Frontend/src/app/admin/operations/killswitch/GlobalKillSwitchClient.tsx`
- `Frontend/src/app/admin/schedules/AdminSchedulesClient.tsx`
- `Frontend/src/app/admin/schedules/components/ScheduleEditorDialog.tsx`
- `Frontend/src/app/admin/findings/AdminFindingsClient.tsx`
- `Frontend/src/app/admin/scans/AdminScansClient.tsx`
- `Frontend/src/app/admin/llm/AdminLlmClient.tsx`
- `Frontend/src/app/admin/tenants/TenantsAdminClient.tsx`
- `Frontend/src/app/admin/webhooks/dlq/WebhookDlqClient.tsx`
- `Frontend/src/components/ui/Button.tsx` (canonical primary variant)
- `Frontend/tests/e2e/admin-axe.spec.ts` (remove 7 `test.fail` blocks)
- `Frontend/tests/e2e/visual/admin-design-tokens.spec.ts` (NEW — visual-regression)
- `Frontend/src/__tests__/AccentTokenContrast.test.tsx` (NEW)

**Migration recipe (mechanical Tailwind utility swap):**

```diff
- className="bg-[var(--accent)] text-white hover:bg-[var(--accent-hover)]"
+ className="bg-[var(--accent-strong)] text-[var(--on-accent)] hover:opacity-90"

- className="bg-amber-600 text-white hover:bg-amber-700"
+ className="bg-[var(--warning-strong)] text-[var(--on-warning)] hover:opacity-90"

- className="text-[var(--accent)] data-[state=active]:bg-[var(--bg-tertiary)]"
+ className="text-[var(--accent-strong)] data-[state=active]:bg-[var(--bg-tertiary)]"
```

**Удаление test.fail (7 точек):**
1. Lines 265-275 — `operations (admin) — throttle + super-admin notice`
2. Lines 293-301 — `schedules (super-admin) — table + tenant selector`
3. Lines 316-322 — `schedules (admin) — pinned tenant`
4. Lines 376-396 — `audit logs: chain-verify success banner`
5. Lines 436-447 — `operations: STOP-ALL dialog open`
6. Lines 465-472 — `operations: per-tenant throttle dialog open`
7. Lines 487-495 — `schedules: editor dialog open`

После удаления каждого блока тест должен проходить (axe color-contrast violations = 0). Если какой-то остаётся failing после миграции — означает, что surface не вошёл в список из 13 (escalate в issue, не silent-fail).

**Visual regression test:**

```typescript
// Frontend/tests/e2e/visual/admin-design-tokens.spec.ts
import { test, expect } from "@playwright/test";

const SCREENS = [
  { url: "/admin/audit-logs", name: "audit-logs-with-verify-cta" },
  { url: "/admin/schedules", name: "schedules-with-create-cta" },
  { url: "/admin/operations", name: "operations-with-throttle-cta" },
  { url: "/admin/webhooks/dlq", name: "dlq-with-replay-cta" },
  { url: "/admin/findings", name: "findings-with-bulk-cta" },
  { url: "/admin/tenants", name: "tenants-with-create-cta" },
];

for (const { url, name } of SCREENS) {
  test(`design tokens: ${name}`, async ({ page }) => {
    await page.goto(url);
    await expect(page).toHaveScreenshot(`${name}.png`, {
      maxDiffPixelRatio: 0.001,
    });
  });
}
```

**Acceptance criteria:**
- (a) Zero `bg-[var(--accent)]` direct usage on text-bearing CTAs in admin tree (rg sanity check в PR description)
- (b) Все 7 `test.fail("ISS-T26-001:...")` annotations removed; `admin-axe.spec.ts` CI step passes 100%
- (c) axe-core scans all migrated surfaces with zero contrast violations (`color-contrast` rule)
- (d) Visual-regression baseline captured; diff ≤ 0.1% pixel-delta vs baseline на token-only changes (no layout drift)
- (e) Vitest contrast assertions ≥ 1 per migrated client component
- (f) ISS-T26-001 closed в трекере (acceptance a/b/c met); link from CHANGELOG

---

### B6-T08 — G20a — Backend admin sessions

**Goal:** Backend половина ISS-T20-003 Phase 1 Option B — admin_sessions table + login/logout/whoami endpoints + `ADMIN_AUTH_MODE` switch. Phase 1 закрывает (a)(b)(c). MFA + runbook deferred в Phase 2.

**Roadmap:** ISS-T20-003 Phase 1 Option B (с **D-2** split + **D-6** mechanism concretization).

**Backend / Frontend split:** 100% backend.

**Files:**
- `backend/alembic/versions/028_admin_sessions.py` (NEW)
- `backend/src/db/models.py` (AdminSession ORM)
- `backend/src/auth/admin_session_store.py` (NEW — DAO)
- `backend/src/auth/admin_password.py` (NEW — bcrypt + bootstrap loader)
- `backend/src/api/routers/admin_auth.py` (NEW — 3 endpoints)
- `backend/src/api/dependencies.py` (extend require_admin)
- `backend/src/core/config.py` (4 new env vars)
- `backend/.env.example` (document env vars + bcrypt snippet)
- `backend/tests/test_admin_auth_session_mode.py` (NEW, ≥24 cases)

**Migration sketch:**

```python
# backend/alembic/versions/028_admin_sessions.py
"""admin_sessions table — cross-tenant by design.

Revision ID: 028
Revises: 027
Create Date: 2026-04-22

ARG-061 / Cycle 6 Batch 6 / B6-T08 / ISS-T20-003 Phase 1 Option B (G20a).

Stores hashed admin session tokens. Cross-tenant by design — sessions are
not tenant-bound; super-admin sessions can scope to any tenant via
explicit X-Tenant-Id query param. RLS DISABLED + FORCE owner-only
(`current_setting('app.current_tenant_id', true)` is unset for admin
auth dispatch — owner role drives queries).

Token hashing scheme:
  raw = secrets.token_bytes(32) → urlsafe_b64encode → stored ONLY in
  Set-Cookie header to client. Server-side persisted as
  sha256(ARGUS_ADMIN_SESSION_PEPPER || raw) hex (HMAC, not vanilla sha256
  — pepper protects against DB-leak rainbow attack).
"""

from __future__ import annotations
from collections.abc import Sequence
from typing import Final

import sqlalchemy as sa
from alembic import op

revision: str = "028"
down_revision: str | None = "027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE_NAME: Final[str] = "admin_sessions"
INDEX_TOKEN_HASH: Final[str] = "ix_admin_sessions_token_hash"
INDEX_EXPIRES: Final[str] = "ix_admin_sessions_expires_at"


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    op.create_table(
        TABLE_NAME,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("session_token_hash", sa.String(64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "ip",
            sa.dialects.postgresql.INET() if is_postgres else sa.String(45),
            nullable=True,
        ),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.UniqueConstraint("session_token_hash", name="uq_admin_sessions_token_hash"),
    )

    op.create_index(INDEX_TOKEN_HASH, TABLE_NAME, ["session_token_hash"])
    op.create_index(INDEX_EXPIRES, TABLE_NAME, ["expires_at"])

    if is_postgres:
        # FORCE owner-only — admin_sessions is intentionally not tenant-bound,
        # so RLS with tenant_id predicate would never match. Force owner-only
        # so non-owner connections cannot bypass auth dispatch logic via direct
        # SQL access.
        op.execute(f'ALTER TABLE "{TABLE_NAME}" FORCE ROW LEVEL SECURITY')


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(f'ALTER TABLE "{TABLE_NAME}" NO FORCE ROW LEVEL SECURITY')
    op.drop_index(INDEX_EXPIRES, table_name=TABLE_NAME)
    op.drop_index(INDEX_TOKEN_HASH, table_name=TABLE_NAME)
    op.drop_table(TABLE_NAME)
```

**Endpoint sketch:**

```python
# backend/src/api/routers/admin_auth.py
"""ARG-061 / ISS-T20-003 Phase 1 Option B — admin auth endpoints.

Mounted at /auth/admin/*. Active only when ADMIN_AUTH_MODE='session';
ADMIN_AUTH_MODE='cookie' (default) leaves these endpoints reachable but
returns 503 ("auth_mode_disabled") so legacy deployments don't accidentally
expose new auth path.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Final

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db
from src.auth.admin_password import verify_bootstrap_admin
from src.auth.admin_session_store import (
    create_session,
    lookup_by_token_hash,
    revoke_session,
)
from src.core.config import settings
from src.policy.audit import emit_audit

router = APIRouter(prefix="/auth/admin", tags=["admin-auth"])

SESSION_COOKIE_NAME: Final[str] = "argus.admin.session"
TOKEN_BYTES: Final[int] = 32


class LoginPayload(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=256)


def _hash_token(raw_token: str) -> str:
    pepper = settings.ARGUS_ADMIN_SESSION_PEPPER.encode()
    return sha256(pepper + raw_token.encode()).hexdigest()


@router.post("/login", status_code=status.HTTP_200_OK)
async def login(
    payload: LoginPayload,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    if settings.ADMIN_AUTH_MODE != "session":
        raise HTTPException(503, detail={"error_code": "AUTH_MODE_DISABLED"})

    if not verify_bootstrap_admin(payload.email, payload.password):
        raise HTTPException(401, detail={"error_code": "AUTH_INVALID_CREDENTIALS"})

    raw_token = secrets.token_urlsafe(TOKEN_BYTES)
    token_hash = _hash_token(raw_token)
    expires_at = datetime.now(tz=timezone.utc) + timedelta(
        seconds=settings.ADMIN_SESSION_TTL_SECONDS
    )

    session_id = await create_session(
        db,
        email=payload.email,
        token_hash=token_hash,
        expires_at=expires_at,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:512],
    )

    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=raw_token,
        max_age=settings.ADMIN_SESSION_TTL_SECONDS,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )

    await emit_audit(
        db,
        action="admin.login",
        actor_email=payload.email,
        metadata={"session_id": session_id, "ip": request.client.host if request.client else None},
    )

    return {"email": payload.email, "expires_at": expires_at.isoformat()}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> None:
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if raw_token:
        await revoke_session(db, _hash_token(raw_token))
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")


@router.get("/whoami", status_code=status.HTTP_200_OK)
async def whoami(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict[str, object]:
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not raw_token:
        raise HTTPException(401, detail={"error_code": "AUTH_NO_SESSION"})

    session = await lookup_by_token_hash(db, _hash_token(raw_token))
    if session is None:
        raise HTTPException(401, detail={"error_code": "AUTH_SESSION_EXPIRED"})
    return {
        "email": session.email,
        "role": "super-admin",
        "authenticated_at": session.created_at.isoformat(),
        "expires_at": session.expires_at.isoformat(),
    }
```

**dependencies.py extension:**

```python
# backend/src/api/dependencies.py — require_admin dispatch
async def require_admin(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> AdminPrincipal:
    if settings.ADMIN_AUTH_MODE == "session":
        raw_token = request.cookies.get(SESSION_COOKIE_NAME)
        if not raw_token:
            raise HTTPException(401, detail={"error_code": "AUTH_NO_SESSION"})
        token_hash = _hash_token(raw_token)
        session = await lookup_by_token_hash(db, token_hash)
        if session is None:
            raise HTTPException(401, detail={"error_code": "AUTH_SESSION_EXPIRED"})
        return AdminPrincipal(
            role="super-admin",
            tenant_id=request.headers.get("x-tenant-id"),
            subject=session.email,
        )
    # ADMIN_AUTH_MODE == "cookie" — legacy path
    role = parse_admin_role(request.headers.get("x-admin-role"))
    ...
```

**Acceptance criteria:**
- (a) Migration 028 upgrade/downgrade idempotent на Postgres + SQLite
- (b) Session token: 32 bytes from `secrets.token_urlsafe`; client получает raw, server stores ONLY sha256(pepper || raw) hex
- (c) `POST /auth/admin/login` → 200 + Set-Cookie (HttpOnly + Secure + SameSite=Strict + Path=/ + Max-Age=14d); rate-limited 5/15min/IP
- (d) `POST /auth/admin/logout` → revoke session row, clear cookie
- (e) `GET /auth/admin/whoami` → 200 `{email, role, authenticated_at}` или 401
- (f) `ADMIN_AUTH_MODE='cookie'` (default) → require_admin читает existing cookie path (legacy untouched)
- (g) `ADMIN_AUTH_MODE='session'` → require_admin читает session cookie → DAO lookup → 401 на miss/expired/revoked
- (h) Closed-taxonomy errors: AUTH_INVALID_CREDENTIALS, AUTH_RATE_LIMITED, AUTH_SESSION_EXPIRED, AUTH_SESSION_REVOKED, AUTH_BOOTSTRAP_NOT_CONFIGURED, AUTH_MODE_DISABLED, AUTH_NO_SESSION
- (i) Audit emit: admin.login, admin.logout, admin.session.expired
- (j) ≥ 24 backend tests; coverage ≥ 90% для admin_auth.py, admin_session_store.py, admin_password.py

---

### B6-T09 — G20b — Frontend session-mode wiring + login + Playwright E2E

**Goal:** Frontend половина ISS-T20-003 Phase 1. Dual-mode `serverSession.ts`, новый `/admin/login` route, middleware redirect, Playwright session-mode E2E.

**Roadmap:** ISS-T20-003 Phase 1 Option B (**D-2** split — frontend half).

**Backend / Frontend split:** 100% frontend.

**Files:**
- `Frontend/src/services/admin/serverSession.ts` (dual-mode)
- `Frontend/src/services/admin/clientLogin.ts` (NEW)
- `Frontend/src/lib/adminAuth.ts` (NEW)
- `Frontend/src/app/admin/login/page.tsx` (NEW)
- `Frontend/src/app/admin/login/LoginClient.tsx` (NEW)
- `Frontend/src/app/admin/AdminLayoutClient.tsx` (Logout button)
- `Frontend/src/middleware.ts` (NEW)
- `Frontend/.env.example` (document NEXT_PUBLIC_ADMIN_AUTH_MODE)
- `Frontend/src/__tests__/serverSession.dual-mode.test.ts` (≥10 cases)
- `Frontend/src/__tests__/LoginClient.test.tsx` (≥8 cases)
- `Frontend/tests/e2e/admin-session-auth.spec.ts` (NEW, ≥6 E2E)
- `Frontend/tests/e2e/fixtures/admin-backend-mock.ts` (extend)
- `Frontend/playwright.config.ts` (project override)

**serverSession.ts dual-mode:**

```typescript
export async function getServerAdminSession(): Promise<ServerAdminSession> {
  const mode = process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE ?? "cookie";

  if (mode === "session") {
    return getServerAdminSessionFromBackend();
  }
  // mode === "cookie" — legacy path — байт-в-байт идентично текущему коду
  return getServerAdminSessionFromCookies();
}

async function getServerAdminSessionFromBackend(): Promise<ServerAdminSession> {
  try {
    const result = await callAdminBackendJson<{
      email: string;
      role: AdminRole;
      authenticated_at: string;
    }>("GET", "/auth/admin/whoami");
    if (!result.ok) {
      return { role: null, tenantId: null, subject: SUBJECT_FALLBACK };
    }
    return {
      role: result.value.role,
      tenantId: null, // session-mode: tenant binding happens at request time via X-Tenant-Id
      subject: result.value.email,
    };
  } catch {
    return { role: null, tenantId: null, subject: SUBJECT_FALLBACK };
  }
}

async function getServerAdminSessionFromCookies(): Promise<ServerAdminSession> {
  // Existing implementation — preserved as-is.
  ...
}
```

**LoginClient.tsx sketch:**

```typescript
"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { adminLoginAction } from "./actions";
import { ERROR_MESSAGES_RU, type AuthActionCode } from "@/lib/adminAuth";

export function LoginClient() {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<AuthActionCode | null>(null);

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        const fd = new FormData(e.currentTarget);
        const email = String(fd.get("email") ?? "");
        const password = String(fd.get("password") ?? "");
        startTransition(async () => {
          const res = await adminLoginAction({ email, password });
          if (res.ok) {
            router.push("/admin");
            return;
          }
          setError(res.code);
        });
      }}
      className="mx-auto mt-16 w-full max-w-sm space-y-4 rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-6"
    >
      <h1 className="text-lg font-semibold">Admin sign-in</h1>
      <label className="block text-sm">
        <span className="mb-1 block">Email</span>
        <input
          type="email"
          name="email"
          required
          autoComplete="username"
          className="w-full rounded border border-[var(--border-light)] bg-[var(--bg-primary)] p-2 text-sm"
        />
      </label>
      <label className="block text-sm">
        <span className="mb-1 block">Password</span>
        <input
          type="password"
          name="password"
          required
          autoComplete="current-password"
          minLength={8}
          className="w-full rounded border border-[var(--border-light)] bg-[var(--bg-primary)] p-2 text-sm"
        />
      </label>
      {error ? (
        <p
          role="alert"
          className="text-sm text-[var(--error)]"
        >
          {ERROR_MESSAGES_RU[error] ?? "Не удалось войти"}
        </p>
      ) : null}
      <button
        type="submit"
        disabled={pending}
        className="w-full rounded bg-[var(--accent-strong)] py-2 text-sm font-medium text-[var(--on-accent)] disabled:opacity-50"
      >
        {pending ? "Вход..." : "Войти"}
      </button>
    </form>
  );
}
```

**middleware.ts sketch:**

```typescript
import { NextRequest, NextResponse } from "next/server";

const SESSION_COOKIE = "argus.admin.session";
const ADMIN_PATH_PREFIX = "/admin";
const LOGIN_PATH = "/admin/login";

export function middleware(request: NextRequest) {
  if (process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE !== "session") {
    return NextResponse.next();
  }
  const path = request.nextUrl.pathname;
  if (!path.startsWith(ADMIN_PATH_PREFIX) || path === LOGIN_PATH) {
    return NextResponse.next();
  }
  const cookie = request.cookies.get(SESSION_COOKIE);
  if (!cookie) {
    const url = request.nextUrl.clone();
    url.pathname = LOGIN_PATH;
    url.searchParams.set("redirect", path);
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/admin/:path*"],
};
```

**Acceptance criteria:**
- (a) `NEXT_PUBLIC_ADMIN_AUTH_MODE='cookie'` (default) → serverSession.ts byte-equivalent текущему поведению (existing E2E + axe specs продолжают пасить без модификации — verified в CI)
- (b) `NEXT_PUBLIC_ADMIN_AUTH_MODE='session'` → visiting /admin без `argus.admin.session` cookie redirects to /admin/login
- (c) Login form: posts to backend, on success Set-Cookie honoured by browser, redirect to /admin renders authenticated chrome
- (d) Logout button removes cookie + redirects to /admin/login
- (e) Closed-taxonomy для auth errors; ERROR_MESSAGES_RU localized
- (f) ≥ 6 Playwright E2E в `admin-session-auth.spec.ts` под dedicated project
- (g) axe-core run на /admin/login → 0 violations (uses tokens из B6-T06)
- (h) ISS-T20-003 acceptance (a)(b)(c) pass; (d)(e) explicitly deferred к ISS-T20-003-phase2.md (создаётся в B6-T10)

---

### B6-T10 — T53 closeout

**Goal:** Финализировать Cycle 6: sign-off отчёт ≥ 800 строк, CHANGELOG rollup, carry-over в Cycle 7, формализовать Phase 2 issue.

**Roadmap:** T53.

**Backend / Frontend split:** 100% docs.

**Files:**
- `ai_docs/develop/reports/2026-04-22-argus-finalization-cycle6.md` (NEW, ≥ 800 строк)
- `ai_docs/develop/reports/2026-04-22-cycle6-batch6-implementation.md` (NEW, ≥ 400 строк)
- `ai_docs/develop/issues/ISS-cycle7-carry-over.md` (NEW)
- `ai_docs/develop/issues/ISS-T20-003-phase2.md` (NEW)
- `CHANGELOG.md` (Cycle 6 rollup)

**Cycle 6 sign-off outline (mirror Cycle 5 sign-off):**

1. **Executive summary** (~50 строк) — высокоуровневые achievements, scorecard at-a-glance
2. **Per-batch deliverables** (~200 строк):
   - Batch 1: Foundation hardening (T01–T08)
   - Batch 2: Multi-tenant operability (T09–T16)
   - Batch 3: Admin frontend (T17–T26 — обновить с T26 axe-gate now passing post-G26)
   - Batch 4: Operations UI (T27–T36 — обновить с G26 surface migration)
   - Batch 5: Webhook DLQ + Kyverno admission (T37–T45)
   - Batch 6: PDF/A archival + KEV-aware HPA + supply-chain ratchets + prod gates (T46–T53)
3. **Quality gates** (~150 строк):
   - CI matrix (kubeconform / cosign / kyverno / verapdf / kev-hpa-kind / coverage matrix 18 contracts)
   - axe-core 100% passing (post-G26)
   - Backend coverage по модулям
   - RLS isolation tests
4. **Open issues** (~80 строк) — все ISS-* still открытые
5. **Production-readiness scorecard** (~100 строк):
   - PDF/A: ✓
   - HPA autoscaling: ✓ (CPU + KEV)
   - Admin auth Phase 1: ✓ (Phase 2 in flight)
   - WCAG AA: ✓
   - Webhook DLQ: ✓
   - Kyverno admission: ✓ (opt-in)
   - Coverage matrix: ✓ (18 contracts)
   - SAST/DAST/SCA: ⚠ (Cycle 7 work)
   - MFA: ✗ (Phase 2)
   - Production runbook: ✗ (Phase 2)
6. **Deviation registry** (~60 строк) — D-1..D-7 этого batch + предыдущих циклов
7. **Forward path — Cycle 7 outline** (~150 строк):
   - ISS-T20-003 Phase 2 (MFA + runbook + IdP)
   - SARIF/SBOM continuous publishing
   - Granular per-resource RBAC
   - Public beta launch criteria

**ISS-T20-003-phase2.md outline:**

```markdown
# ISS-T20-003 Phase 2 — Admin auth hardening (deferred from Cycle 6 Batch 6)

## Status
Open — scoped, not started.

## Predecessor
ISS-T20-003 Phase 1 (closed in Cycle 6 Batch 6, B6-T08 + B6-T09).
Acceptance criteria (a)(b)(c) met — bootstrap admin password + CSPRNG cookie session shipped.

## Acceptance criteria for Phase 2
- (d) MFA via TOTP (pyotp) + backup codes (hashed at rest); enforce on admin role.
- (e) Production runbook documenting:
    - Bootstrap admin rotation procedure
    - Session pepper rotation procedure (zero-downtime)
    - Broken-glass procedure (ARGUS_ADMIN_BOOTSTRAP_RECOVERY_TOKEN env)
    - Audit log review cadence
    - Incident response для compromised session

## Suggested mechanism
- Backend: extend `admin_auth` router с `/auth/admin/mfa/{enroll,verify,disable,regenerate-codes}`.
- Schema: новая таблица `admin_mfa_secrets` (id, email FK, totp_secret_encrypted, backup_codes_hashed_json, enrolled_at).
- Frontend: enroll flow с QR-кодом, backup-codes display once, verify-on-login with second factor.
- Optional: OIDC IdP integration (Authlib) for organizations preferring SSO over local password.

## Out-of-scope для Phase 2
- Full RBAC granularity (per-resource permissions).
- Service-to-service auth (mutual TLS, service accounts).
- These are Cycle 7+.

## Estimated effort
~2 weeks (Phase 1 took 2 days; Phase 2 is bigger due to QR codes, backup codes lifecycle, runbook quality).
```

**ISS-cycle7-carry-over.md content:**

```markdown
# Cycle 7 carry-over — open at Cycle 6 close

Generated 2026-04-22 by B6-T10.

## Production gates carried forward
- **ISS-T20-003 Phase 2** — MFA + runbook + IdP integration. See ISS-T20-003-phase2.md.

## Issues opened during Cycle 6 still open
- (none — Batch 6 closed both production gates: ISS-T20-003 Phase 1 + ISS-T26-001)

## Debt accrued in Cycle 6 worth tracking
- PDF/A: (none observed; verapdf gate is strict)
- KEV HPA: (none observed; kind test exercises full path)
- Coverage matrix: future C19+ candidates: build-system attestation (cosign sigstore), SBOM presence per tool.

## Scope outline for Cycle 7
1. Security hardening — MFA, deeper RBAC, IdP integration (ISS-T20-003 Phase 2).
2. SARIF/SBOM continuous publishing.
3. Audit certification (SOC 2 Type 1 readiness).
4. Public beta criteria + go-live plan.
```

**CHANGELOG rollup (preview):**

```markdown
## Cycle 6 — closed 2026-04-22

### Added
- PDF/A-2u archival pipeline для всех трёх report tier'ов; per-tenant `pdf_archival_format` flag (Batch 6, B6-T01 + B6-T02).
- KEV-aware HPA для Celery worker pool с anti-flap stabilization (Batch 6, B6-T03 + B6-T04).
- Prometheus Adapter как optional Helm subchart (Batch 6, B6-T03).
- `argus_celery_queue_depth` Gauge backfill (Batch 6, B6-T03 — D-5).
- Admin session-based auth (ADMIN_AUTH_MODE='session'), Phase 1 Option B (Batch 6, B6-T08 + B6-T09 — closes ISS-T20-003 Phase 1).
- High-contrast design tokens `--accent-strong`, `--on-accent`, `--warning-strong`, `--on-warning` + canonical design-tokens.md (Batch 6, B6-T06 + B6-T07 — closes ISS-T26-001).

### Changed
- Coverage matrix ratcheted from 16 → 18 contracts (C17 + C18, Batch 6, B6-T05).
- 13 admin admin surfaces migrated на high-contrast tokens (Batch 6, B6-T07).
- Все 7 `test.fail("ISS-T26-001:...")` annotations удалены из admin-axe.spec.ts (Batch 6, B6-T07).

### Deferred to Cycle 7
- ISS-T20-003 Phase 2 (MFA + runbook + IdP) — see ISS-T20-003-phase2.md.

### CI gates added в Cycle 6
- pdfa-validation (verapdf 1.26.x docker)
- kev-hpa-kind (kind v1.31 + Prometheus + Adapter)

### Sign-off
See `ai_docs/develop/reports/2026-04-22-argus-finalization-cycle6.md`.
```

**Acceptance criteria:**
- (a) `2026-04-22-argus-finalization-cycle6.md` ≥ 800 строк; sections mirror Cycle 5 sign-off
- (b) CHANGELOG.md gain Cycle 6 entry summarizing все 6 batches; explicitly listing ISS-T20-003 (Phase 1) + ISS-T26-001 как closed
- (c) `ISS-cycle7-carry-over.md` enumerates: ISS-T20-003-phase2 + любые новые ISS-* + debt-items
- (d) `ISS-T20-003-phase2.md` drafted с: scope, acceptance для (d)+(e), suggested mechanism (TOTP via pyotp + backup codes; runbook structure)
- (e) Все open todos в плане tracked → carry-over file; no orphaned tasks
- (f) Final commit per task-management skill: workspace files + human-facing plan + sign-off + carry-over + Phase 2 issue + CHANGELOG

---

## 6. Test plan (consolidated)

### CI gates touched / added в Batch 6

| Gate | New | Modified | Trigger |
|------|-----|----------|---------|
| `pdfa-validation.yml` | ✓ | — | PR touching `backend/templates/reports/_latex/**` OR `backend/src/reports/pdf_backend.py` |
| `kev-hpa-kind.yml` | ✓ | — | PR touching `infra/helm/argus/templates/hpa-celery-worker-kev.yaml` OR `prometheus-adapter-rules.yaml` |
| `helm-validation.yml` | — | ✓ | extend matrix on `prometheusAdapter.enabled` toggle |
| `admin-axe.spec.ts` | — | ✓ | удаление 7 `test.fail` (B6-T07) — full pass post-merge |
| `tool-catalog-coverage.py` | — | ✓ | C17 + C18 added; matrix 157 × 18 = 2826 cases |
| `admin-session-auth.spec.ts` | ✓ | — | new Playwright project, runs against `ADMIN_AUTH_MODE=session` mock |
| `test_admin_auth_session_mode.py` | ✓ | — | backend pytest — runs in standard CI matrix |
| `test_pdfa_pipeline.py` | ✓ | — | backend pytest |
| `test_queue_depth_emitter.py` | ✓ | — | backend pytest |
| `test_kev_aware_hpa.py` | ✓ | — | kind cluster only (kev-hpa-kind workflow) |
| `test_tenant_pdf_archival_format.py` | ✓ | — | backend pytest |

### Coverage targets

- Backend: 90%+ для каждого нового модуля (`admin_auth.py`, `admin_session_store.py`, `admin_password.py`, `_latex_pdfa.py`, `queue_depth_emit.py`)
- Frontend: 85%+ для каждого нового client (`LoginClient.tsx`, `serverSession.ts` dual-mode)
- Existing baseline сохраняется (no regressions)

### Manual smoke before merge

| Surface | What to verify |
|---------|----------------|
| `/admin/tenants/{id}` | PDF format toggle works; switching to pdfa-2u, generating report → verapdf pass |
| `/admin/login` (session mode) | Wrong password → rate-limit copy после 5 attempts; correct password → /admin |
| `/admin/audit-logs` (post-G26) | Verify chain integrity button → no axe color-contrast violations |
| `/admin/operations` throttle | Confirm CTA contrast ≥ 4.5:1 visually |
| `helm template -f values-prod.yaml` | Renders both HPAs (cpu + kev) AND prometheus-adapter-rules ConfigMap |
| `kubectl describe hpa argus-celery-kev` | Sees external metric source + behavior policies |

---

## 7. Risk register

| # | Risk | Mitigation |
|---|------|------------|
| **R1** | verapdf docker image pull может быть медленным в CI (~500 MB) | Pin to specific tag `verapdf/verapdf:1.26.2`; cache via `actions/cache` keyed on docker image digest |
| **R2** | LaTeX PDF/A-2u preamble может interact'ить badly с существующим content (длинные tables, hyperref) | Golden integration tests на каждом tier; verapdf strictness уменьшает false-positives |
| **R3** | KEV-aware HPA + CPU HPA одновременно могут scale-thrash | `behavior.stabilizationWindowSeconds=300` в обоих + Kubernetes union-семантика; kind test проверяет no-thrash в cooldown |
| **R4** | `argus.observability.queue_depth_emit` каждые 30s + `inspect()` overhead на 8+ queues | `inspect(timeout=5.0)` cap; failure swallowed; metric retains last value |
| **R5** | `ADMIN_AUTH_MODE='session'` deployment failure → блокирует admin access целиком | Default остаётся `'cookie'` (backward-compat); flip только после E2E pass в staging; broken-glass: можно вернуть на `'cookie'` без миграции (admin_sessions table ничего не ломает в cookie mode) |
| **R6** | bcrypt verify slow на cold containers (pytest fixtures) | Use bcrypt cost=10 (баланс между security и test speed); Phase 2 повышает до 12 |
| **R7** | Surface migration B6-T07 может ломать Storybook visuals (если есть) | Visual-regression check на 6 reference screens; ≤ 0.1% pixel-delta tolerance |
| **R8** | Phase 2 `ISS-T20-003-phase2.md` может быть deprioritised; Phase 1 без MFA — security gap | Carry-over explicit; Cycle 7 plan mandates Phase 2 в первом sprint |
| **R9** | C17 + C18 могут найти существующие violations (что не ratchet) | Pre-flight `pytest -k C17 -k C18` локально перед PR; известные violations либо чинятся в B6-T05, либо вносятся в exempt set с inline-комментарием + ticket link |
| **R10** | Prometheus Adapter subchart upstream может breaking-change | Pin chart version в `Chart.yaml` к specific minor; renovate/dependabot слежение |

---

## 8. Closeout (T53 deliverable shape)

При закрытии Batch 6 / Cycle 6, B6-T10 деливерит ровно следующие 5 артефактов:

1. **`ai_docs/develop/reports/2026-04-22-argus-finalization-cycle6.md`** — Cycle 6 sign-off (≥ 800 строк), mirrors структуру `2026-04-20-argus-finalization-cycle5.md` (772 строки). Sections: Executive summary / Per-batch deliverables (T01–T53) / Quality gates / Open issues / Production-readiness scorecard / Deviation registry / Forward path.

2. **`ai_docs/develop/reports/2026-04-22-cycle6-batch6-implementation.md`** — Batch 6-specific implementation report (≥ 400 строк), mirrors `2026-04-22-cycle6-batch5-implementation.md`. Sections: TL;DR / Scope / Per-task changes / Tests / Deviations / Carry-over.

3. **`ai_docs/develop/issues/ISS-cycle7-carry-over.md`** — Cycle 7 carry-over list. Empty или near-empty production-gate section (Phase 2 = единственный) + scope-outline для Cycle 7.

4. **`ai_docs/develop/issues/ISS-T20-003-phase2.md`** — Phase 2 issue tracker: scope, acceptance criteria for (d)+(e), suggested TOTP + IdP mechanism, estimated effort.

5. **`CHANGELOG.md` Cycle 6 rollup** — высокоуровневая запись Cycle 6 closure: Added / Changed / Deferred / CI gates / Sign-off reference. Public-friendly tone (developer-facing, не end-user).

После B6-T10 merge — Cycle 6 OFFICIALLY closed; CHANGELOG fixates closure date; ISS-T20-003 + ISS-T26-001 marked Closed в трекере с reference на B6-T08+T09 + B6-T06+T07 commits.

---

## 9. Файлы оркестрации

```
.cursor/workspace/active/orch-2026-04-22-argus-cycle6-b6/
  plan.md         — orchestrator-readable план (этот документ для людей, plan.md для агентов)
  tasks.json      — 10 задач + статусы + acceptance + dependencies
  progress.json   — orchestration metadata + deviation summary + alembic assignment
  links.json      — ссылки на план / report / issue / CI workflows
```

```
ai_docs/develop/plans/2026-04-22-argus-cycle6-b6.md  — этот документ (human-facing)
```

---

## 10. Ссылки

- **Roadmap:** [`Backlog/dev1_finalization_roadmap.md`](../../../Backlog/dev1_finalization_roadmap.md) §Batch 6
- **Predecessor plan:** [`ai_docs/develop/plans/2026-04-22-argus-cycle6-b5.md`](2026-04-22-argus-cycle6-b5.md)
- **Predecessor report:** [`ai_docs/develop/reports/2026-04-22-cycle6-batch5-implementation.md`](../reports/2026-04-22-cycle6-batch5-implementation.md)
- **Predecessor carry-over:** [`ai_docs/develop/issues/ISS-cycle6-batch5-carry-over.md`](../issues/ISS-cycle6-batch5-carry-over.md)
- **Production gate G20:** [`ai_docs/develop/issues/ISS-T20-003.md`](../issues/ISS-T20-003.md)
- **Production gate G26:** [`ai_docs/develop/issues/ISS-T26-001.md`](../issues/ISS-T26-001.md)
- **Cycle 5 sign-off (структурный референс):** [`ai_docs/develop/reports/2026-04-20-argus-finalization-cycle5.md`](../reports/2026-04-20-argus-finalization-cycle5.md)

---

**Последнее обновление:** 2026-04-22 (initialised by planner subagent).
**Статус:** Ready to execute.
**Запуск:** `/orchestrate execute orch-2026-04-22-argus-cycle6-b6`
