# План: ARGUS Cycle 7 — Admin auth Phase 2 (MFA + runbook + Alembic 031) + PDF/A acceptance + KEV-HPA prod rollout

**Создан:** 2026-04-22
**Оркестрация:** `orch-2026-04-22-argus-cycle7`
**Workspace:** `.cursor/workspace/active/orch-2026-04-22-argus-cycle7/`
**Carry-over (вход):** [`ai_docs/develop/issues/ISS-cycle7-carry-over.md`](../issues/ISS-cycle7-carry-over.md)
**Phase 2 spec:** [`ai_docs/develop/issues/ISS-T20-003-phase2.md`](../issues/ISS-T20-003-phase2.md)
**Production gates (входной статус):**
- [`ISS-T20-003`](../issues/ISS-T20-003.md) — Phase 1 ✅ (grace window открыт до 2026-06-21)
- [`ISS-T26-001`](../issues/ISS-T26-001.md) — Phase 1 ✅ (follow-up: amber-700 uniformity)
**Предыдущая оркестрация:** [`orch-2026-04-22-argus-cycle6-b6`](2026-04-22-argus-cycle6-b6.md)
**Предыдущий отчёт:** [`ai_docs/develop/reports/2026-04-22-cycle6-batch6-implementation.md`](../reports/2026-04-22-cycle6-batch6-implementation.md)
**Статус:** Ready
**Всего задач:** 10 (C7-T01..C7-T10) — в пределах cap=10
**Ожидаемая wall-time:** ~3.5 рабочих дня при 2-worker parallelism

---

## TL;DR

Cycle 7 закрывает три параллельных work-stream'а Phase 2 для admin-auth и финализирует две операционных болячки, оставшиеся после Cycle 6 Batch 6:

1. **Admin auth Phase 2 — MFA enforcement (HIGH).** Backend-managed TOTP + bcrypt-hashed one-time backup codes. Per-operator `mfa_enabled` flag (forced ON для super-admin), Fernet-encrypted TOTP secret в `admin_users.mfa_secret_encrypted`, `admin_sessions.mfa_passed_at` timestamp с re-auth window. Login flow меняется с одношагового (`POST /login` → cookie) на двухшаговый (`POST /login` → 200 `{status:"mfa_required", mfa_token}` → `POST /mfa/verify` → cookie). Frontend gets enrollment screen, QR display, single-show backup-codes modal, и second-factor input page. Решение по Option выбрано **планнером явно** — см. §Architecture decisions.

2. **Admin auth Phase 2 — operator runbook (HIGH).** Канонический `docs/operations/admin-sessions.md` mirroring структуру существующих `docs/admission-policy.md` / `docs/webhook-dlq.md`. Шесть секций: session lifecycle / login procedure / MFA / logout & revocation / audit-trail queries / pepper rotation procedure. Линкуется из README operations.

3. **Admin auth Phase 2 — Alembic 031 + legacy code cleanup (HIGH).** Drop `admin_sessions.session_id` raw column (Phase 1 grace-window legacy), promote `session_token_hash` to PK, удаление обоих `ADMIN_SESSION_LEGACY_RAW_*` flag'ов из Settings + .env.example, удаление legacy fallback branches в `admin_sessions.py` resolver / `create_session` / `revoke_session`. Pre-flight signal table из ISS-T20-003-phase2.md §Phase 2c (3 signals across two TTL windows = 24h total) — обязательная gate перед merge.

4. **PDF/A acceptance hardening (MEDIUM).** Существующий `pdfa-validation.yml` workflow уже использует production `LatexBackend` через `render_pdfa_sample.py` (НЕ pure mock — verified on disk), но carry-over корректно отмечает три gap'а: (a) verapdf assertion проверяет только `isCompliant`, не учитывает warnings; (b) fixture data статичная — нет coverage для Cyrillic content + longtable overflow + hyperref edge-cases, которые в реальных tenant-отчётах могут спровоцировать non-conformance; (c) workflow не валидирует path через per-tenant `pdf_archival_format='pdfa-2u'` flag (только тестирует `LatexBackend(pdfa_mode=True)` напрямую). C7-T02 закрывает все три.

5. **KEV-aware HPA prod rollout signals (MEDIUM).** На диске `infra/helm/argus/values-prod.yaml:106` уже имеет `prometheusAdapter.enabled: true` и обе rule-секции (`queueDepth`, `kevEmitRate`); HPA `hpa-celery-worker-kev.yaml` рендерится. **Реальный gap** — это операционные сигналы вокруг rollout, не сама конфигурация: (a) verification, что Prometheus action скрейпит `argus_celery_queue_depth` Gauge и `argus_findings_emitted_total{kev_listed="true"}` counter в prod (подтверждение через staging soak); (b) Prometheus alert rules на missing-metric (защита от silent no-op); (c) staging soak instructions (1-2 weeks observation period); (d) rollback procedure в operator docs. C7-T06 закрывает.

6. **LOW priority (если влезает в budget).** Amber-700 surface uniformity audit — три surfaces из B6-T04 batch уже мигрировали на `--warning-strong`, но carry-over просит проверить остальной admin tree на residual `bg-amber-700` usages (которые проходят AA, но breaking uniformity). Admin axe-core periodic re-run — cron-triggered workflow на existing `admin-axe.spec.ts` для catch'а regressions от новых components.

10 атомарных задач, **1 новая Alembic миграция** (`032_admin_mfa_columns.py`), **1 destructive миграция** (`031_drop_legacy_admin_session_id.py` — с pre-flight gate), **1 новая pip dependency** (`pyotp` — TOTP generation, BSD license, no transitive deps), **0 новых npm packages** (frontend MFA reuses existing UI primitives), **1 новый CI workflow** (`admin-axe-cron.yml`), **1 hardened CI workflow** (`pdfa-validation.yml`).

Этот cycle разблокирует: production hardening для admin auth (MFA gate переход с "single-factor → SOC 2 Type 1 ready"), полная фиксация PDF/A archival contract, KEV-aware autoscaling в prod с поддержкой rollback. После Cycle 7 — backlog focus переключается на SARIF/SBOM continuous publishing (Cycle 8) и public beta launch criteria.

---

## 1. Архитектурные решения (планнер)

### P-1. MFA: Option 1 (backend-managed TOTP) — выбрано

ISS-T20-003-phase2.md §Phase 2a предлагает две опции:

| Критерий | Option 1: Backend TOTP | Option 2: IdP OIDC |
|----------|------------------------|--------------------|
| Внешние зависимости | `pyotp` (1 pip pkg, BSD, 0 transitives) | IdP procurement (Azure AD / Auth0 / Keycloak) — *out of engineering's hands* per spec |
| CI testability | 100% — TOTP генерируется in-process | Требует mock-IdP fixture; интеграционные тесты flaky |
| Wall-time | 3-4 дня (Phase 2 doc estimate) | Зависит от procurement; может быть 4-8+ недель |
| Соответствие compliance | TOTP = ISO/IEC 27001 Annex A.9.4.2 acceptable; SOC 2 Type 1 ✓ | OIDC mandatory для federated trust scenarios; SOC 2 Type 2 + |
| Onboarding cost | Operator scans QR; 1 minute | Требует SSO setup + group mapping; 1-2 hours per operator |
| Rollback | Disable feature flag; legacy single-factor restored | Потеря IdP = lockout (потенциально destructive) |

**Решение:** **Option 1.** ISS-T20-003-phase2.md §Trade-off explicitly defers Option 2 "to the cycle in which procurement closes". Cycle 7 не блокируется на procurement; Option 1 self-contained, testable, и rollbackable. Future Cycle (8+) может надстроить OIDC при необходимости (TOTP остаётся как fallback или secondary factor).

**Backup codes:** 10 one-time codes per operator. Хранение: `text[]` of bcrypt-hashed strings (cost 12). Использование = удаление элемента из массива (atomic UPDATE с predicate). Re-generation (`POST /mfa/regenerate-backup-codes`) wipes и replaces — старые ноды немедленно invalidated.

**TOTP secret encryption:** `cryptography.Fernet` keyed off `ADMIN_MFA_KEYRING` env (32 url-safe-base64 bytes). Key rotation procedure: новый key prepended в keyring (`MultiFernet`), все секреты opportunistically re-encrypted на следующий verify call, старый key dropped после observation window. Документировано в runbook (C7-T05).

### P-2. Sequencing: runbook **до** Alembic 031

ISS-T20-003-phase2.md §Phase 2c specifies:

> **T+0**: Both flags ON (Phase 1 default state).
> **T+1× TTL** (~12h): Flip `ADMIN_SESSION_LEGACY_RAW_WRITE=false`.
> **T+2× TTL**: Verify the three pre-flight signals. Flip `ADMIN_SESSION_LEGACY_RAW_FALLBACK=false`.
> **T+3× TTL**: Run `alembic upgrade 031`.

Это **operator-driven sequence**, не automated migration. Без runbook (C7-T05) operators не знают, какие 3 pre-flight signals проверять, как валидировать grace-window соблюдение, или что делать при aborted migration. Runbook ОБЯЗАН ship'нуться **до** того, как destructive migration попадёт в main.

**Implementation gate:** C7-T07 PR description MUST включать (a) скриншот pre-flight signal table из staging environment с все-зелёными значениями, (b) ссылку на merged C7-T05 runbook, (c) подтверждение, что `ADMIN_SESSION_LEGACY_RAW_FALLBACK=false` deployed в staging минимум один TTL window назад. Без этих трёх — PR должен быть rejected reviewer'ом.

### P-3. Sequencing: KEV-HPA prod rollout **после** PDF/A workflow

User constraint: "avoid two infra changes overlapping". Хотя обе работы изолированы (PDF/A это CI gate, KEV-HPA это runtime HPA), параллельное rollout усложняет debugging если что-то ломается:

- PDF/A workflow failure → easy rollback (revert workflow PR), не влияет на runtime
- KEV-HPA scrape failure → silent no-op в prod; HPA пин-понгует между CPU-only и max(cpu, kev) recommendations

Land C7-T02 первым → дать ему 24h soak в main → land C7-T06.

### P-4. PDF/A workflow: текущий "skeleton" описание частично stale

`.github/workflows/pdfa-validation.yml` на диске is **NOT** a pure mock. Verified facts:
- Использует `verapdf-cli:1.24.1` (pinned)
- Matrix `[asgard, midgard, valhalla]` — все три tier'а
- `--flavour 2u` PDF/A profile
- `render_pdfa_sample.py` driver вызывает `LatexBackend` напрямую с `pdfa_mode=True`
- Asserts `isCompliant="true"` в verapdf XML output
- Uploads artefacts on failure

**Реальные gap'ы** (что C7-T02 закрывает):
1. **Warnings игнорируются.** verapdf может report `isCompliant="true"` AND содержать warning rules (e.g., "font subset incomplete"). Production-grade gate должен fail на warnings тоже (или explicitly список allow-listed warning IDs с inline-ticket'ом).
2. **Static fixture data.** `render_pdfa_sample.py` использует synthetic mock-data; нет coverage для (a) Cyrillic + Latin mixed, (b) longtable overflow > 1 page, (c) embedded images, (d) hyperref-heavy footnotes. Real-world tenant reports trigger PDF/A non-conformance в этих edge-cases.
3. **Per-tenant flag path не покрыт.** Workflow тестирует `LatexBackend(pdfa_mode=True)`, но реальная prod path: tenant config → `tenants.pdf_archival_format='pdfa-2u'` → `ReportService.generate_pdf` → backend selection → `LatexBackend(pdfa_mode=resolved_from_db)`. End-to-end coverage этого path требует смол-инстанс ReportService с in-memory tenant fixture.

C7-T02 расширяет workflow на (1) zero-warning enforcement, (2) три новых fixture variants (Cyrillic / longtable / images), (3) одну integration matrix entry, exercising per-tenant flag path.

### P-5. Carry-over LOW items: всё влезает в 10-task budget

User instruction:
> "If LOW items don't fit, push them into a fresh `ISS-cycle8-carry-over.md` recommendation in your plan summary."

Counting:
- 5 HIGH/MEDIUM substantive: C7-T01, C7-T02, C7-T03, C7-T04, C7-T05, C7-T06, C7-T07 = 7 tasks
- 1 closeout: C7-T10 = 8 tasks
- 2 LOW: C7-T08, C7-T09 = 10 tasks ✓

Budget covered. **Никаких LOW items не push'ается в Cycle 8.**

---

## 2. Контекст: что carry-over от Cycle 6 Batch 6

### Состояние production gates на disk (verified)

| Gate | Phase 1 status | Phase 2 status | Где проверить |
|------|----------------|----------------|---------------|
| ISS-T20-003 admin auth | ✅ Closed (B6-T08+T09) | ⏳ Pending (this cycle) | `ISS-T20-003.md`, `ISS-T20-003-phase2.md` |
| ISS-T26-001 WCAG AA contrast | ✅ Closed (B6-T06+T07) | N/A — Phase 1 only | `ISS-T26-001.md` |
| ARG-058 PDF/A archival | ✅ Closed (B6-T01+T02) | Hardening (C7-T02) | `pdfa-validation.yml`, `render_pdfa_sample.py` |
| ARG-059 KEV-aware HPA | ✅ Closed (B6-T03+T04) | Prod rollout signals (C7-T06) | `values-prod.yaml`, `hpa-celery-worker-kev.yaml` |

### Что уже на диске (НЕ нужно делать заново)

**Backend Phase 1 — verified:**
- `backend/alembic/versions/028_admin_sessions.py` — table created, applied
- `backend/alembic/versions/030_hash_admin_session_ids.py` — `session_token_hash` column + HMAC-SHA256(pepper, raw) construction
- `backend/src/auth/admin_sessions.py` — `create_session`, `revoke_session`, `resolve_session` с opportunistic backfill
- `backend/src/auth/admin_users.py` — bcrypt-12 verify + bootstrap loader
- `backend/src/api/routers/admin_auth.py` — `POST /login`, `POST /logout`, `GET /whoami`
- `backend/src/core/config.py` — `ADMIN_AUTH_MODE`, `ADMIN_SESSION_PEPPER`, `ADMIN_SESSION_LEGACY_RAW_*`

**Frontend Phase 1 — verified:**
- `Frontend/src/services/admin/serverSession.ts` — dual-mode resolver (`cookie | session | auto`)
- `Frontend/src/app/admin/login/{page.tsx,actions.ts}` — login form
- `Frontend/src/app/admin/LogoutButton.tsx` — visible only в session-mode
- `Frontend/middleware.ts` — session-mode + missing cookie → redirect
- `Frontend/instrumentation.ts` — boot-time guard для `NODE_ENV=production`

**Infra — verified:**
- `infra/helm/argus/values-prod.yaml:106` — `prometheusAdapter.enabled: true` (УЖЕ true)
- `infra/helm/argus/templates/prometheus-adapter-rules.yaml` — `queueDepth` + `kevEmitRate` rules
- `infra/helm/argus/templates/hpa-celery-worker-kev.yaml` — KEV-aware HPA template
- `.github/workflows/kev-hpa-kind.yml` — kind cluster integration test
- `.github/workflows/pdfa-validation.yml` — verapdf gate (matrix all 3 tiers, --flavour 2u, real LatexBackend)
- `backend/scripts/render_pdfa_sample.py` — production renderer driver

### Что C6-B6 deferred (precise scope для C7)

| Item | Deferred from | Picked up в | Spec |
|------|---------------|-------------|------|
| MFA enforcement | B6-T08 (Phase 1 acceptance criterion `d`) | C7-T01, C7-T03, C7-T04 | ISS-T20-003-phase2.md §Phase 2a Option 1 |
| Operator runbook | B6-T08 (Phase 1 acceptance criterion `e`) | C7-T05 | ISS-T20-003-phase2.md §Phase 2b |
| Alembic 031 cleanup | B6-T08 (Phase 1 acceptance criterion `f`) | C7-T07 | ISS-T20-003-phase2.md §Phase 2c |
| PDF/A real verapdf | B6-T01 (workflow as "skeleton") | C7-T02 | ISS-cycle7-carry-over.md §"PDF/A acceptance" |
| KEV-HPA prod rollout signal | B6-T04 (kind test only) | C7-T06 | ISS-cycle7-carry-over.md §"KEV-HPA prod rollout" |
| Amber-700 uniformity | B6-T07 (3 surfaces deferred) | C7-T08 | ISS-cycle7-carry-over.md §"ISS-T26-001 Follow-up" |
| Admin axe-core periodic | (new — not deferred) | C7-T09 | ISS-cycle7-carry-over.md §"Admin axe-core" |

---

## 3. Задачи (C7-T01 .. C7-T10)

| ID | Title | Priority | Wave | Deps | Size (LOC) | Owner |
|----|-------|----------|------|------|------------|-------|
| **C7-T01** | MFA backend foundation (Alembic 032 + DAO + Fernet crypto) | High | 1 | — | M (~350) | worker |
| **C7-T02** | PDF/A acceptance hardening (zero-warning gate + 3 fixture variants + per-tenant path) | Medium | 1 | — | M (~250) | worker |
| **C7-T03** | MFA endpoints + super-admin enforcement (login → mfa_required → verify) | High | 2 | C7-T01 | L (~450) | worker |
| **C7-T04** | MFA frontend (enroll + QR + backup-codes + verify-on-login) | High | 3 | C7-T03 | L (~500) | worker |
| **C7-T05** | Operator runbook `docs/operations/admin-sessions.md` (≥600 строк) | High | 1 | — | M (~600) | documenter |
| **C7-T06** | KEV-HPA prod rollout signals (scrape verify + alerts + soak doc + rollback) | Medium | 2 | C7-T02 | M (~300) | worker |
| **C7-T07** | Alembic 031 + legacy code cleanup + flag removal | High | 3 | C7-T05 | L (~450) | worker |
| **C7-T08** | Amber-700 surface uniformity audit | Low | 1 | — | S (~120) | worker |
| **C7-T09** | Admin axe-core periodic CI cron | Low | 2 | C7-T08 | S (~100) | worker |
| **C7-T10** | Cycle 7 closeout (report + CHANGELOG + ISS-cycle8-carry-over) | High | 4 | All prior | M (~500) | documenter |

**Итого:** 10 задач • ~3170 LOC ожидаемо • ~3.5 рабочих дня wall-time с 2-worker parallelism.

---

## 4. DAG визуально

```
WAVE 1 (foundation, параллельно — 4 tasks):
   C7-T01 (MFA backend foundation)        C7-T02 (PDF/A hardening)
        |                                       |
   C7-T05 (Runbook)                        C7-T08 (Amber-700 audit)
        |                                       |
        |                                       |

WAVE 2 (MFA + infra rollout, 3 tasks):
   C7-T03 (MFA endpoints)                  C7-T06 (KEV-HPA prod signals)
        |                                       |
   C7-T09 (axe cron)                            |
        |                                       |

WAVE 3 (frontend + destructive cleanup, 2 tasks):
   C7-T04 (MFA frontend)                   C7-T07 (Alembic 031)
                                                |
                                                |
WAVE 4 (closeout, 1 task):
   C7-T10 (sign-off + CHANGELOG + ISS-cycle8-carry-over)
```

**Параллелизм по wave (2 workers):**

| Wave | Задачи | Параллельно? | Оценка часов |
|------|--------|--------------|--------------|
| 1 | C7-T01, C7-T02, C7-T05, C7-T08 | да; pair (T01+T02), (T05+T08) | max(8, 6) ≈ 8h |
| 2 | C7-T03, C7-T06, C7-T09 | да; pair (T03 alone), (T06+T09) | max(8, 5) ≈ 8h |
| 3 | C7-T04, C7-T07 | да; pair (T04), (T07) | max(9, 7) ≈ 9h |
| 4 | C7-T10 | один worker (docs heavy) | 5h |

**Wall-time:** 8 + 8 + 9 + 5 = **30 часов = ~3.5 рабочих дня** (включая CI runs + review циклы).

---

## 5. Per-task детали

### C7-T01 — MFA backend foundation (Alembic 032 + DAO + Fernet crypto)

**Goal:** Schema + crypto utilities + DAO layer для MFA. Никаких endpoints в этой задаче (split per Single Responsibility — endpoints land в C7-T03 и могут быть reviewed independently).

**Spec ref:** ISS-T20-003-phase2.md §Phase 2a Option 1 schema table.

**Files:**
- `backend/alembic/versions/032_admin_mfa_columns.py` (NEW)
- `backend/src/db/models.py` — добавить `mfa_enabled`, `mfa_secret_encrypted`, `mfa_backup_codes_hash` в `AdminUser`; `mfa_passed_at` в `AdminSession`
- `backend/src/auth/admin_mfa.py` (NEW) — DAO + crypto wrappers
- `backend/src/auth/_mfa_crypto.py` (NEW) — Fernet/MultiFernet keyring helper
- `backend/src/core/config.py` — `ADMIN_MFA_KEYRING: str` (csv of base64 Fernet keys), `ADMIN_MFA_REAUTH_WINDOW_SECONDS: int = 43200` (12h), `ADMIN_MFA_ENFORCE_ROLES: list[str] = ["super_admin"]`
- `backend/.env.example` — document new env vars + key generation snippet
- `backend/tests/auth/test_admin_mfa_dao.py` (NEW, ≥10 cases)
- `backend/tests/auth/test_mfa_crypto.py` (NEW, ≥6 cases)
- `backend/tests/integration/migrations/test_032_admin_mfa_columns_migration.py` (NEW)
- `backend/requirements.txt` — добавить `pyotp==2.9.0` (latest stable, BSD, no transitives)

**Migration shape (sketch):**

```python
# backend/alembic/versions/032_admin_mfa_columns.py
"""Admin MFA columns — TOTP secret + backup codes + session mfa_passed_at.

Revision ID: 032
Revises: 031
Create Date: 2026-04-22

ARG-062 / Cycle 7 / C7-T01 / ISS-T20-003 Phase 2a Option 1.

Adds backend-managed TOTP MFA columns to existing admin_users table
(from migration 028) and adds mfa_passed_at to admin_sessions so the
resolver can enforce a re-auth window for super-admin endpoints.

Schema (per ISS-T20-003-phase2.md §Phase 2a):
  admin_users.mfa_enabled            BOOL DEFAULT FALSE
  admin_users.mfa_secret_encrypted   BYTEA NULLABLE      -- Fernet-encrypted TOTP secret
  admin_users.mfa_backup_codes_hash  TEXT[] NULLABLE     -- bcrypt-hashed one-time codes
  admin_sessions.mfa_passed_at       TIMESTAMPTZ NULLABLE -- when 2FA accepted

Backwards-compat: existing rows get mfa_enabled=FALSE, mfa_secret_encrypted=NULL.
Super-admin enforcement happens in app code (config.ADMIN_MFA_ENFORCE_ROLES),
not at the DB layer — operators can roll out MFA gradually.
"""
```

**Crypto wrapper sketch (`_mfa_crypto.py`):**

```python
"""ARG-062 — Fernet-based at-rest encryption для TOTP secrets.

Reads ADMIN_MFA_KEYRING (csv of base64 Fernet keys, newest-first) and
exposes encrypt/decrypt + opportunistic re-encryption. MultiFernet
allows zero-downtime key rotation: prepend new key to keyring; on next
verify call, decrypt with any key, re-encrypt with newest, persist.

Never logs secret material. ValueError on malformed keyring or empty
plaintext (defence in depth — caller must supply non-empty TOTP secret).
"""
```

**DAO sketch (`admin_mfa.py`):**

```python
"""ARG-062 / C7-T01 — admin MFA data access layer.

NOT for endpoint use — endpoints live in api/routers/admin_auth.py
(C7-T03). This module is the seam for unit tests + future migration
to an external IdP (Phase 2 Option 2 in ISS-T20-003-phase2.md).
"""

async def enroll_totp(db, *, subject: str, secret: str) -> None: ...
async def confirm_enrollment(db, *, subject: str, totp_code: str, generated_codes: list[str]) -> None: ...
async def verify_totp(db, *, subject: str, totp_code: str) -> bool: ...
async def consume_backup_code(db, *, subject: str, code: str) -> bool: ...
async def disable_mfa(db, *, subject: str) -> None: ...
async def regenerate_backup_codes(db, *, subject: str) -> list[str]: ...
async def mark_session_mfa_passed(db, *, session_token_hash: str) -> None: ...
```

**Acceptance criteria:**
- (a) Migration 032 upgrade/downgrade idempotent на Postgres + SQLite
- (b) Все 4 новых column'а present в моделях с правильными типами / nullability
- (c) Fernet keyring parsing fails fast с структурированным error на malformed input (нет stack trace в logs)
- (d) Backup code generation: 10 strings, каждая 16 chars, alphabet `[0-9A-HJ-NP-Z]` (no I/O/0/1 — operator-typeable), entropy ≥80 bits
- (e) Backup code consumption: атомарный UPDATE с predicate (`WHERE code_hash = ANY(backup_codes_hash)`), success → удаление из массива; double-spend → return False
- (f) `mark_session_mfa_passed` обновляет timestamp; resolver проверяет `now() - mfa_passed_at < ADMIN_MFA_REAUTH_WINDOW_SECONDS`
- (g) `pyotp==2.9.0` добавлен в requirements.txt с `# C7-T01 — ISS-T20-003 Phase 2a Option 1 (TOTP)` комментарием
- (h) ≥16 backend tests; coverage ≥90% для `admin_mfa.py` и `_mfa_crypto.py`
- (i) **Никаких endpoints** в этой задаче — `admin_auth.py` не модифицируется

**Risk notes:**
- Security: Fernet secret leakage через логи — MUST не логировать `mfa_secret_encrypted` content в любом code path. Tests assert log-output не содержит byte sequences from encrypted secret.
- Performance: bcrypt cost 12 для backup codes — verify time ~150ms; acceptable для редкого consume path.
- Breaking: NONE; миграция additive, новые columns nullable, existing rows unaffected.

---

### C7-T02 — PDF/A acceptance hardening (zero-warning gate + fixture variants + per-tenant path)

**Goal:** Расширить `pdfa-validation.yml` workflow до production-grade gate: warnings рассматриваются как failures, fixture покрывает Cyrillic + longtable + images, плюс one matrix entry exercises per-tenant flag path end-to-end.

**Spec ref:** ISS-cycle7-carry-over.md §"PDF/A acceptance".

**Files:**
- `.github/workflows/pdfa-validation.yml` — extend existing matrix + assertion logic
- `backend/scripts/render_pdfa_sample.py` — добавить `--fixture-variant {basic|cyrillic|longtable|images|per_tenant}` flag
- `backend/tests/fixtures/pdfa_variants.py` (NEW) — fixture data for each variant
- `backend/tests/integration/reports/test_pdfa_per_tenant_path.py` (NEW, ≥4 cases) — exercises `tenants.pdf_archival_format='pdfa-2u'` → `ReportService.generate_pdf` end-to-end with in-memory tenant
- `backend/scripts/_verapdf_assert.py` (NEW) — replaces inline grep with structured XML parser; flags warnings as well as errors
- `ai_docs/develop/architecture/pdfa-acceptance.md` (NEW, ≥150 строк) — design doc: что покрывается, какие warnings разрешены и почему, fixture rationale

**Workflow extension sketch:**

```yaml
# Extend matrix:
strategy:
  matrix:
    tier: [midgard, asgard, valhalla]
    variant: [basic, cyrillic, longtable, images, per_tenant]
    exclude:
      # per_tenant variant only runs once (independent of tier — exercises
      # ReportService routing, not tier templates).
      - tier: asgard
        variant: per_tenant
      - tier: valhalla
        variant: per_tenant
```

**Assert script sketch:**

```python
# backend/scripts/_verapdf_assert.py
"""ARG-058-followup / C7-T02 — verapdf XML assertion с warning enforcement.

Replaces the brittle ``grep 'isCompliant="false"'`` shell pipeline with
a deterministic XML parser. Exits non-zero on:
  * isCompliant="false" (any failed rule)
  * Any warning rule NOT in the explicit allow-list (--allow-warnings)
  * Empty / malformed report

Allow-list: empty by default. Each entry MUST link to an open ticket
in the form ``<rule_id>:<ticket_url>`` (e.g.,
``6.1.5:https://argus.example.com/tickets/ARG-099``).
"""
```

**Acceptance criteria:**
- (a) Matrix expanded: 3 tiers × 4 variants + 1 per_tenant = 13 jobs
- (b) Zero-warning enforcement: any verapdf `<warningRules>` block fails the job (unless rule_id in `--allow-warnings`)
- (c) Cyrillic variant: fixture с T2A glyphs (рос. text), validates fontEncoding correctness
- (d) Longtable variant: ≥3 page table; validates outline + bookmark structure
- (e) Images variant: PNG embedded with correct color space (sRGB ICC); rejected на CMYK / RGB-without-profile
- (f) Per-tenant variant: in-memory tenant fixture с `pdf_archival_format='pdfa-2u'`; `ReportService.generate_pdf` resolves flag и dispatches to `LatexBackend(pdfa_mode=True)`; result passes verapdf
- (g) Allow-list initially empty; first warning encountered → CI blocks → engineer must либо fix или add allow-list entry с ticket
- (h) Workflow runtime ≤25 минут (current: ~15 min для 3 jobs; expected: ~30 min для 13 jobs — within budget)
- (i) `pdfa-acceptance.md` documents: variants rationale, allow-list policy, escalation path при verapdf upstream behaviour change

**Risk notes:**
- Performance: 13 jobs × ~5 min each = ~65 CPU-minutes per PR touching reports. Mitigated через `paths` filter (existing — only triggered на reports/templates touches).
- False positives: Real-world tenant content может trigger warnings, что blocks release. Mitigation: allow-list policy документирована; staging soak (1 week) перед merging C7-T02.
- Breaking: NONE; existing workflow continues to fail on real non-conformance, just with stricter criteria.

---

### C7-T03 — MFA endpoints + super-admin enforcement

**Goal:** Endpoints для enrollment / confirmation / verification / disable; `require_admin` extension которое gate'ит super-admin endpoints через MFA re-auth window.

**Spec ref:** ISS-T20-003-phase2.md §Phase 2a Option 1 endpoints + resolver section.

**Deps:** C7-T01 (DAO must exist).

**Files:**
- `backend/src/api/routers/admin_auth.py` — extend с 5 new endpoints + login response shape change
- `backend/src/api/dependencies.py` — `require_admin` обновляется + new `require_super_admin_mfa` dependency
- `backend/src/auth/admin_mfa_tokens.py` (NEW) — short-lived MFA challenge token (CSPRNG, 5 min TTL, in-memory или Redis-backed cache)
- `backend/src/api/schemas.py` — `MfaEnrollResponse`, `MfaVerifyPayload`, etc.
- `backend/tests/auth/test_admin_auth_mfa_endpoints.py` (NEW, ≥14 cases)
- `backend/tests/auth/test_super_admin_mfa_enforcement.py` (NEW, ≥6 cases)
- `backend/.env.example` — document `ADMIN_MFA_CHALLENGE_TTL_SECONDS=300`, `ADMIN_MFA_ENFORCE_ROLES`
- `backend/CHANGELOG-internal.md` (если existing) или inline в C7-T10 changelog rollup — login API contract change documented

**Endpoint contract (detailed):**

```python
# POST /auth/admin/login {subject, password}
# Behaviour:
#   * Step 1: bcrypt verify (existing)
#   * Step 2: if user.mfa_enabled → return 200 {status: "mfa_required", mfa_token: str}
#                                    NO Set-Cookie issued
#   * Step 2': if !user.mfa_enabled → existing flow (Set-Cookie + return session info)
#   * Rate-limit: existing per-IP token-bucket unchanged
#
# POST /auth/admin/mfa/enroll
# Auth: existing session cookie (reuses non-MFA login window для enrollment)
# Returns: {provisioning_uri, secret_base32, qr_svg_data_uri}
# Side-effect: persists encrypted secret в pending state (mfa_enabled still FALSE)
#
# POST /auth/admin/mfa/enroll/confirm {totp_code}
# Validates pending TOTP code. On success: sets mfa_enabled=TRUE, generates
# 10 backup codes, returns them ONCE (client MUST store them; never re-shown).
#
# POST /auth/admin/mfa/verify {mfa_token, totp_code | backup_code}
# Validates mfa_token (from /login response), then TOTP or backup code.
# On success: issues session cookie + marks session.mfa_passed_at.
# Backup code path: deletes consumed code from array atomically.
#
# POST /auth/admin/mfa/disable {password, totp_code}
# Re-authenticates с password + current TOTP, then clears mfa_secret + backup codes.
# Requires self-only OR super-admin actor (audit logged).
#
# POST /auth/admin/mfa/regenerate-backup-codes {totp_code}
# Re-authenticates с TOTP, generates 10 new codes (replaces array). Returns them ONCE.
#
# GET /auth/admin/mfa/status
# Returns: {enabled: bool, last_verified_at: timestamp | null, backup_codes_remaining: int}
```

**Resolver extension:**

```python
# backend/src/api/dependencies.py
def require_super_admin_mfa(...) -> SessionPrincipal:
    principal = require_admin(...)  # existing
    if principal.role not in settings.ADMIN_MFA_ENFORCE_ROLES:
        return principal
    if principal.mfa_passed_at is None:
        raise HTTPException(403, detail={"error_code": "AUTH_MFA_REQUIRED"})
    age = datetime.now(tz=timezone.utc) - principal.mfa_passed_at
    if age.total_seconds() > settings.ADMIN_MFA_REAUTH_WINDOW_SECONDS:
        raise HTTPException(403, detail={"error_code": "AUTH_MFA_EXPIRED"})
    return principal
```

**Wiring:** Audit log all MFA actions через existing `_emit_audit` helper (`admin.mfa.enrolled`, `admin.mfa.verified`, `admin.mfa.disabled`, `admin.mfa.backup_code_consumed`, `admin.mfa.failed_attempt`).

**Rate-limit:** `/mfa/verify` — 5 attempts per 5 минут per `mfa_token` (prevent TOTP brute-force during 5-min challenge window). On exhaustion: invalidate token, force re-login.

**Acceptance criteria:**
- (a) Login → mfa_required path: backwards-compat preserved (если MFA не enabled, существующее поведение unchanged); E2E test asserts both paths
- (b) Enrollment flow: provisioning URI valid (`otpauth://totp/...`); QR SVG renders в standard authenticator apps (verified manually + base64 length check)
- (c) Backup code generation: 10 codes returned once, client never sees them again; subsequent enroll/confirm rejected as "already enrolled"
- (d) MFA verify: TOTP validates через `pyotp.TOTP.verify(window=1)` (60-sec leniency); backup codes validate via bcrypt + atomic deletion
- (e) Replay protection: backup code used twice → second attempt fails (consumed from array)
- (f) Re-auth window: `mfa_passed_at` enforced на super-admin endpoints; expiry → 403 `AUTH_MFA_EXPIRED`
- (g) Audit emit для всех 5+ MFA actions
- (h) Rate-limit: `/mfa/verify` 5/5min/token; brute-force test asserts 6th attempt → 429
- (i) Test coverage: ≥20 cases between two test files; coverage ≥90% для new endpoints
- (j) Closed-taxonomy errors: `AUTH_MFA_REQUIRED`, `AUTH_MFA_EXPIRED`, `AUTH_MFA_INVALID_CODE`, `AUTH_MFA_TOKEN_EXPIRED`, `AUTH_MFA_BACKUP_EXHAUSTED`, `AUTH_MFA_NOT_ENABLED`
- (k) `require_super_admin_mfa` dependency wired в minimum один super-admin endpoint в этой задаче (smoke test); broader rollout — Cycle 8 task

**Risk notes:**
- Security: TOTP brute-force через rapid-fire requests — mitigated rate-limit. Backup code brute-force impossible due to bcrypt cost 12 (verify ≥150ms).
- Breaking: Login response shape changes для MFA-enabled users (returns `{status: "mfa_required"}` instead of session info). Frontend MUST be ready (C7-T04 dependency); legacy clients (если existing) — N/A в admin context.
- Performance: TOTP verify is fast (~5ms); backup code verify uses bcrypt (slow but rare path).

---

### C7-T04 — MFA frontend (enroll + QR + backup-codes + verify-on-login)

**Goal:** Полный frontend flow для MFA — enrollment screen, QR display, backup-codes single-show modal, и second-factor input page после login.

**Spec ref:** Frontend mirror C7-T03 endpoints.

**Deps:** C7-T03 (backend API must exist).

**Files:**
- `Frontend/src/app/admin/mfa/enroll/page.tsx` (NEW) — Server Component wrapper
- `Frontend/src/app/admin/mfa/enroll/EnrollClient.tsx` (NEW) — QR display + confirmation form
- `Frontend/src/app/admin/mfa/enroll/BackupCodesModal.tsx` (NEW) — single-show modal с download/copy actions
- `Frontend/src/app/admin/mfa/verify/page.tsx` (NEW) — second-step page после login
- `Frontend/src/app/admin/mfa/verify/VerifyClient.tsx` (NEW) — TOTP / backup code input toggle
- `Frontend/src/app/admin/login/LoginClient.tsx` (UPDATED) — handle `{status: "mfa_required"}` response → redirect to /admin/mfa/verify
- `Frontend/src/app/admin/AdminLayoutClient.tsx` (UPDATED) — show MFA status badge для super-admin
- `Frontend/src/services/admin/mfaClient.ts` (NEW) — API client wrappers
- `Frontend/src/lib/mfaErrors.ts` (NEW) — closed-taxonomy + ERROR_MESSAGES_RU
- `Frontend/src/middleware.ts` (UPDATED) — extend session-mode check: super-admin path requires `argus.admin.mfa_passed_at` cookie или redirect /admin/mfa/verify
- `Frontend/tests/e2e/admin-mfa.spec.ts` (NEW, ≥8 scenarios)
- `Frontend/src/__tests__/EnrollClient.test.tsx` (NEW, ≥6 cases)
- `Frontend/src/__tests__/VerifyClient.test.tsx` (NEW, ≥6 cases)
- `Frontend/tests/e2e/fixtures/admin-backend-mock.ts` (UPDATED) — extend `/auth/admin/*` handlers + MFA endpoints
- `Frontend/.env.example` — document `NEXT_PUBLIC_ADMIN_MFA_ENABLED=true` (server-side hint для conditional UI)

**UX flow (textual):**

```
1. Operator visits /admin/login.
2. Submits subject + password.
3. Backend returns 200 {status: "mfa_required", mfa_token}.
4. LoginClient detects mfa_required → router.push(`/admin/mfa/verify?mfa_token=${token}`).
5. VerifyClient loads. Shows: TOTP input (default) + "Use backup code instead" link.
6. Operator enters TOTP. POST /auth/admin/mfa/verify {mfa_token, totp_code}.
7. Backend validates → Set-Cookie + 200.
8. router.push("/admin").
9. AdminLayoutClient shows MFA badge (green check) при super-admin role.

Enrollment flow (separately, после login):
1. Super-admin visits /admin (logged in без MFA enabled).
2. Layout shows MFA-required banner: "Enable MFA to access super-admin features".
3. Operator clicks → /admin/mfa/enroll.
4. EnrollClient calls POST /auth/admin/mfa/enroll → renders QR + base32 secret (fallback for non-camera).
5. Operator scans QR в authenticator app.
6. Enters first TOTP code → POST /enroll/confirm.
7. Backend returns 10 backup codes.
8. BackupCodesModal opens, modal forces user to either download or copy ALL codes (no dismiss without action).
9. Modal closes; operator sees /admin/mfa/status confirmation page.
```

**Acceptance criteria:**
- (a) MFA-not-enabled user: existing login flow byte-equivalent (no UX change для standard admin role)
- (b) MFA-enabled user: login → /admin/mfa/verify → /admin (3-step flow с loading states)
- (c) QR SVG renders inline (no external CDN); base32 secret displayed для manual entry fallback
- (d) Backup-codes modal: forces interaction (download или copy); cannot dismiss with codes uncopied; copy-to-clipboard работает; download generates `argus-mfa-backup-codes-${timestamp}.txt`
- (e) Backup codes never re-displayed после initial modal; if operator закрывает без save → /admin/mfa/regenerate-backup-codes доступен с TOTP re-auth
- (f) Verify form: TOTP input default; backup code input как fallback с warning copy ("Backup codes are single-use")
- (g) Error states: invalid TOTP → inline error message; rate-limited (429) → cooldown timer; mfa_token expired → redirect /admin/login с info banner
- (h) Middleware: super-admin role + missing mfa_passed_at cookie → redirect /admin/mfa/verify (not /admin/login — operator уже past first factor)
- (i) Axe-core: 0 violations на /admin/mfa/{enroll,verify} (uses existing tokens из B6-T06)
- (j) i18n: все user-facing strings в ERROR_MESSAGES_RU; English fallback present
- (k) ≥8 Playwright scenarios + ≥12 vitest cases; coverage ≥85% для new clients

**Risk notes:**
- Security: QR SVG inlined (no external image fetch) — prevents leak через referrer / 3rd-party logging.
- UX: Backup-codes modal "forced interaction" может frustrate users. Mitigated через clear copy + visible download button + skip-with-confirm option (которая отдельно audited).
- Breaking: Login response handling в LoginClient.tsx меняется; existing E2E baseline для login без MFA continues to pass через mock backend extension.

---

### C7-T05 — Operator runbook `docs/operations/admin-sessions.md`

**Goal:** Канонический operator-facing runbook покрывающий весь lifecycle admin sessions, документация для destructive procedures (pepper rotation, Alembic 031), и audit-trail query cookbook.

**Spec ref:** ISS-T20-003-phase2.md §Phase 2b detailed sections.

**Files:**
- `docs/operations/admin-sessions.md` (NEW, ≥600 строк)
- `README.md` — добавить link в "Operations" section (один-line link)
- `docs/operations/_index.md` (если existing) — добавить entry; иначе создать с двумя entries (existing webhook-dlq.md + new admin-sessions.md)

**Sections (per ISS-T20-003-phase2.md §Phase 2b):**

1. **Session lifecycle** (~80 lines)
   - TTL: `ADMIN_SESSION_TTL_SECONDS=43200` (12h)
   - Sliding window mechanic
   - Token shape: 48 CSPRNG bytes → URL-safe base64 → `HMAC-SHA256(pepper, token)` storage
   - Cookie attributes (HttpOnly, Secure, SameSite=Strict)

2. **Login procedure** (~80 lines)
   - Endpoint contract
   - bcrypt cost 12 + `_burn_dummy_cycle` rationale
   - Per-IP rate-limit (`ADMIN_LOGIN_RATE_LIMIT_PER_MINUTE`)
   - Reverse-proxy requirements (X-Forwarded-For trust)

3. **MFA** (~100 lines) — UPDATED post C7-T03
   - Enrollment procedure (operator-facing)
   - Verification flow
   - Backup codes lifecycle (single-use, regenerate procedure)
   - Disable procedure (when, how, audit trail)
   - Lost-device recovery (broken-glass — super-admin может disable MFA для другого operator с audit log)

4. **Logout & revocation** (~80 lines)
   - Self-logout endpoint
   - Force-revoke endpoint (super-admin only)
   - Beat-prune cadence + retention
   - Audit emits

5. **Audit-trail queries** (~100 lines) — SQL cookbook
   - Operator activity since timestamp
   - Currently active sessions
   - Failed login attempts (DDoS / brute-force forensics)
   - MFA enrollment / disable history
   - Pepper rotation events

6. **Pepper rotation procedure** (~120 lines) — destructive procedure
   - Pre-flight checklist
   - Step-by-step с command examples (PowerShell + bash)
   - Validation queries between steps
   - Rollback procedure
   - Emergency rotation (accept downtime path)

7. **Pre-Alembic-031 checklist** (~40 lines) — gates для C7-T07
   - Three pre-flight signals (per ISS-T20-003-phase2.md §Phase 2c)
   - Two-TTL observation window
   - How to verify в Grafana / Prometheus (panels referenced если existing)

**Acceptance criteria:**
- (a) ≥600 строк markdown с ToC navigation
- (b) Все 7 sections present и cross-referenced
- (c) Каждая destructive procedure (pepper rotation, MFA disable, force-revoke) имеет explicit "Pre-flight" + "Rollback" subsections
- (d) SQL queries tested в local SQLite + Postgres staging; результаты pasted в `<details>` blocks
- (e) Linked from README.md `## Operations` section с one-liner: `* [Admin sessions runbook](docs/operations/admin-sessions.md) — lifecycle, MFA, pepper rotation, pre-031 checklist`
- (f) Operations team review: один Ops engineer signs off через PR review (planner cannot self-approve own runbook)
- (g) Mirrors style + section depth существующих `docs/admission-policy.md` и `docs/webhook-dlq.md` (если существуют — verified в C7-T05 worker)

**Risk notes:**
- Security: SQL queries в audit cookbook NOT include WHERE clauses которые operators могут blindly copy-paste и execute против production без review. Каждый query header в комментарии: "Run in staging first; production execution requires DBA review".
- Operational: Pepper rotation procedure complex — runbook MUST documenter запрашивает Ops review (gate criterion `f` above).

---

### C7-T06 — KEV-HPA prod rollout signals (scrape verify + alerts + soak doc + rollback)

**Goal:** Operational hardening для KEV-aware HPA в prod. **NOT** flag flip (already enabled на disk); это monitoring + documentation work.

**Spec ref:** ISS-cycle7-carry-over.md §"KEV-HPA prod rollout".

**Deps:** C7-T02 (PDF/A workflow lands first per P-3).

**Files:**
- `infra/helm/argus/templates/prometheus-rules-kev-hpa.yaml` (NEW) — PrometheusRule CRD с alert на missing scrape target
- `infra/helm/argus/values-prod.yaml` — verify `prometheusAdapter.enabled=true` + add comment block referencing rollout doc
- `infra/scripts/verify-kev-hpa-scrape.sh` (NEW) — operator script: validates Prometheus сервер действительно скрейпит обе метрики
- `docs/operations/kev-hpa-rollout.md` (NEW, ≥250 строк) — staging soak instructions, scrape verification, rollback
- `docs/operations/admin-sessions.md` — add cross-link section (если C7-T05 уже merged) для consistency
- `infra/helm/argus/values-staging.yaml` (если существует) или inline в rollout doc — staging-specific overrides
- `tests/integration/k8s/test_kev_hpa_prod_signals.py` (NEW, ≥4 cases) — extends existing kev-hpa-kind workflow с alert-firing path

**PrometheusRule sketch:**

```yaml
{{- if and .Values.prometheusAdapter.enabled .Values.prometheusRules.enabled -}}
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: {{ include "argus.fullname" . }}-kev-hpa-signals
  labels: {{ include "argus.labels" . | nindent 4 }}
spec:
  groups:
    - name: argus.kev-hpa.scrape-health
      interval: 30s
      rules:
        - alert: ArgusKevHpaMetricMissing
          expr: |
            absent(argus_celery_queue_depth) or
            absent(argus_findings_emitted_total{kev_listed="true"})
          for: 5m
          labels:
            severity: warning
            component: kev-hpa
          annotations:
            summary: "KEV-aware HPA scrape target missing for >5m"
            description: |
              The Prometheus Adapter cannot derive the external metric
              feeding the KEV-aware HPA. The HPA will silently fall back
              to CPU-only recommendations. Verify the celery beat task
              `argus.metrics.queue_depth_refresh` is running and the
              backend `/metrics` endpoint is being scraped.
              Runbook: docs/operations/kev-hpa-rollout.md#missing-scrape-target
        - alert: ArgusKevHpaScaleStuck
          expr: |
            kube_horizontalpodautoscaler_status_desired_replicas{
              horizontalpodautoscaler=~".*-celery-kev"
            } == kube_horizontalpodautoscaler_spec_max_replicas{
              horizontalpodautoscaler=~".*-celery-kev"
            }
          for: 30m
          labels:
            severity: warning
            component: kev-hpa
          annotations:
            summary: "KEV-aware HPA stuck at maxReplicas for >30m"
{{- end -}}
```

**Verification script (`verify-kev-hpa-scrape.sh`) sketch:**

```bash
#!/usr/bin/env bash
# C7-T06 — verify Prometheus is scraping both KEV-HPA-driving metrics.
# Exits 0 if both have non-empty results in the last 5m window, 1 otherwise.
# Operator runs this в staging перед merging Cycle 7 production deploy PR.
```

**Rollout doc outline:**

1. **Pre-deploy checklist** — chart version pin, Prometheus Adapter installed, ServiceMonitor для backend `/metrics` scraped
2. **Deploy sequence** — `helm upgrade` с `--set prometheusAdapter.enabled=true` (already in values-prod, double-check), wait 30s, run `verify-kev-hpa-scrape.sh`
3. **Staging soak** — 1-2 weeks observation; metrics to watch (queue_depth p95, KEV emit rate p95, HPA replica trajectory); aborted-rollout criteria (>5% scale-thrash, >30m stuck-at-max alerts firing)
4. **Production cutover** — same procedure; rollback < 5 min via `helm rollback` (since HPA-celery-kev и hpa-celery union semantics — disabling kevAware preserves CPU-driven HPA)
5. **Rollback procedure** — `helm rollback`, verify HPA-celery still active, verify alert recovers

**Acceptance criteria:**
- (a) PrometheusRule renders correctly: `helm template -f values-prod.yaml argus .` produces valid PrometheusRule YAML; `kubeconform` validates
- (b) Two alerts present: scrape-missing + stuck-at-max
- (c) Verification script: validates both metrics non-empty in last 5m via Prometheus API; structured exit codes
- (d) Rollout doc ≥250 lines covers все 5 sections с command examples
- (e) Existing `kev-hpa-kind.yml` extended: new test asserts `ArgusKevHpaMetricMissing` alert fires when `argus_celery_queue_depth` not emitted (negative path)
- (f) values-prod.yaml comment block references `docs/operations/kev-hpa-rollout.md` для operator discoverability
- (g) `prometheusRules.enabled=true` defaulted в values-prod.yaml; values.yaml keeps `false` (опт-in для dev)

**Risk notes:**
- Security: Alert annotations не expose metric values (которые могут leak tenant info через label cardinality); only counts + thresholds.
- Operational: PrometheusRule может conflict с upstream `kube-prometheus-stack` rules if labels overlap. Mitigated через explicit `app.kubernetes.io/component: kev-hpa` label.
- Breaking: NONE; additive PrometheusRule + verification script + docs.

---

### C7-T07 — Alembic 031 + legacy session_id resolver removal + flag cleanup

**Goal:** Destructive cleanup. Drop `admin_sessions.session_id` raw column, promote `session_token_hash` to PK, удалить `ADMIN_SESSION_LEGACY_RAW_*` flag'ы из Settings + .env.example, удалить legacy fallback branches в `admin_sessions.py`.

**Spec ref:** ISS-T20-003-phase2.md §Phase 2c (full migration shape, code cleanup, rollback procedure already drafted).

**Deps:** C7-T05 (runbook MUST be merged для pre-flight checklist availability).

**Files:**
- `backend/alembic/versions/031_drop_legacy_admin_session_id.py` (NEW) — destructive migration per Phase 2 spec
- `backend/src/auth/admin_sessions.py` — drop `legacy_raw_value` branch в `create_session`, drop legacy-fallback в `revoke_session` и `resolve_session`, drop opportunistic backfill, drop `is_session_pepper_configured` short-circuits
- `backend/src/db/models.py` — drop `session_id` column declaration, promote `session_token_hash` to `primary_key=True, nullable=False`
- `backend/src/core/config.py` — remove `admin_session_legacy_raw_write` и `admin_session_legacy_raw_fallback` settings + their validators
- `backend/.env.example` — remove two flag lines + comment block; add migration notice
- `backend/tests/auth/test_admin_sessions_hash_at_rest.py` — drop the 4 tests covering legacy fallback path (contract removed)
- `backend/tests/integration/migrations/test_031_drop_legacy_admin_session_id_migration.py` (NEW)
- `backend/tests/auth/test_admin_sessions_no_legacy_path.py` (NEW, ≥6 cases) — assert removed code paths не reachable
- `ai_docs/develop/architecture/admin-session-token-storage.md` (если existing — UPDATE; иначе NEW) — schema doc reflecting post-031 state

**Pre-flight gate (PR description requirements):**

PR MUST include three items в description:

1. **Pre-flight signal screenshot** from staging Prometheus / Grafana:
   - `SELECT count(*) FROM admin_sessions WHERE session_token_hash IS NULL AND revoked_at IS NULL;` returns `0` across two consecutive 12h windows (24h total)
   - `argus.auth.admin_session.resolved` events с `extra.matched_via == "legacy"` over last 24h returns 0
   - `ADMIN_SESSION_LEGACY_RAW_FALLBACK=false` deployed в staging минимум 12h ago (env source-of-truth confirmation)

2. **Link to merged C7-T05 PR** confirming runbook published.

3. **Rollback rehearsal note:** "Rolled back staging to revision 030 successfully on YYYY-MM-DD; force-revoke + re-login validated."

Reviewer rejects PR без всех трёх items.

**Migration шейп (per spec, full code):**

```python
# backend/alembic/versions/031_drop_legacy_admin_session_id.py
"""Drop legacy admin_sessions.session_id; promote session_token_hash to PK.

Revision ID: 031
Revises: 030
Create Date: 2026-04-22

ARG-061 / Cycle 7 / C7-T07 / ISS-T20-003 Phase 2c.

DESTRUCTIVE: Forward-only by design. Pre-flight signals MUST be green
in production before this migration runs (see PR description + the
Phase 2c checklist in docs/operations/admin-sessions.md).

Schema delta:
  - DROP COLUMN admin_sessions.session_id (was Phase 1 grace-window legacy
    raw bearer storage; replaced by HMAC-hashed session_token_hash в 030)
  - PROMOTE session_token_hash to PK (was UNIQUE INDEX в 030)
  - DROP CONSTRAINT admin_sessions_pkey (replace с new PK)
  - REMOVE settings: admin_session_legacy_raw_write, admin_session_legacy_raw_fallback
  - REMOVE code paths: legacy fallback в create_session / revoke_session /
    resolve_session; opportunistic backfill

Downgrade: STRICTLY FORWARD-ONLY. The pre-flight checklist в Phase 2c
ensures 031 is safe to run; downgrading would re-introduce the security
regression (raw token at rest). If 031 breaks production, follow the
rollback procedure в docs/operations/admin-sessions.md §Pepper rotation
emergency path (force-revoke all sessions + re-deploy revision 030 +
operators re-login).
"""

def upgrade() -> None:
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"
    if is_sqlite:
        # SQLite needs batch_alter_table для PK changes
        with op.batch_alter_table("admin_sessions", recreate="auto") as batch_op:
            batch_op.alter_column(
                "session_token_hash",
                existing_type=sa.String(64),
                nullable=False,
            )
            # SQLite recreates table; PK reassignment via batch_op.create_primary_key
            batch_op.drop_constraint("pk_admin_sessions", type_="primary")
            batch_op.create_primary_key(
                "pk_admin_sessions",
                ["session_token_hash"],
            )
            batch_op.drop_column("session_id")
    else:
        op.alter_column(
            "admin_sessions",
            "session_token_hash",
            existing_type=sa.String(64),
            nullable=False,
        )
        op.execute("ALTER TABLE admin_sessions DROP CONSTRAINT admin_sessions_pkey")
        op.execute("ALTER TABLE admin_sessions ADD PRIMARY KEY (session_token_hash)")
        op.drop_column("admin_sessions", "session_id")


def downgrade() -> None:
    raise RuntimeError(
        "031 is forward-only — see ISS-T20-003-phase2.md §Phase 2c rollback "
        "and docs/operations/admin-sessions.md §Pepper rotation emergency path."
    )
```

**Acceptance criteria:**
- (a) Migration 031 upgrade clean на Postgres + SQLite; downgrade explicitly raises (verified в migration test)
- (b) `session_id` column dropped; `session_token_hash` is now PK (NOT NULL + UNIQUE)
- (c) Settings: `admin_session_legacy_raw_write` и `admin_session_legacy_raw_fallback` removed; `_enforce_production_admin_auth` no longer references them
- (d) `.env.example`: two flag lines removed; comment block replaced с migration completion notice (date + revision)
- (e) `admin_sessions.py`: legacy branches removed; resolver only looks up by `session_token_hash`; `create_session` only writes hash; no opportunistic backfill
- (f) Removed tests: 4 legacy-fallback tests dropped; comment в test file documenting removal с reference to revision 031
- (g) New tests: ≥6 cases asserting removed code paths не reachable (i.e., если legacy code accidentally re-introduced, tests fail)
- (h) Pre-flight gate enforced via PR description (manual reviewer enforcement; automated check optional но not required)
- (i) Architecture doc updated reflecting post-031 schema; link from CHANGELOG entry в C7-T10
- (j) Full pytest + vitest + E2E suites green post-cleanup (regression-free)

**Risk notes:**
- Security: Forward-only migration — rollback impossible через alembic. Mitigated через pre-flight gate + force-revoke + re-deploy procedure documented.
- Breaking: ANY existing session с `session_token_hash IS NULL` — invalidated. Pre-flight signal #1 ensures this is 0 before merge.
- Performance: PK promotion на existing column = brief table lock. Estimated < 5s на typical prod table size (1k-10k rows). Document в PR description.

---

### C7-T08 — Amber-700 surface uniformity audit

**Goal:** Найти все остающиеся `bg-amber-700` (или text-amber-700) usages в admin tree и migrate to `--warning-strong` для visual uniformity. Carry-over подтверждает три surfaces из B6-T04 batch уже мигрировали; audit needed для остатков.

**Spec ref:** ISS-cycle7-carry-over.md §"ISS-T26-001 Follow-up — amber-700".

**Files (estimate):**
- `Frontend/src/app/admin/**/*.tsx` (audit + migrate residuals; expect 0-3 hits)
- `Frontend/src/components/admin/**/*.tsx` (audit + migrate)
- `Frontend/src/__tests__/AmberSurfaceAudit.test.tsx` (NEW) — vitest rule asserting zero `bg-amber-700` в admin path
- `Frontend/tests/e2e/visual/admin-amber-uniformity.spec.ts` (NEW; optional если visual-regression уже covers это)

**Audit procedure (worker executes):**

```powershell
# Audit step:
rg -l "bg-amber-700|text-amber-700" Frontend/src/app/admin Frontend/src/components/admin
rg -l "bg-amber-700|text-amber-700" Frontend/src
```

For each hit: replace `bg-amber-700` → `bg-[var(--warning-strong)] text-[var(--on-warning)]` (или just `bg-[var(--warning-strong)]` если text не белый), preserve hover states.

**Acceptance criteria:**
- (a) Audit completed: list of all hits в PR description с before/after diff
- (b) All admin-tree hits migrated to `--warning-strong` (or explicit exemption с inline comment + reason)
- (c) Vitest rule `AmberSurfaceAudit.test.tsx` asserts zero `bg-amber-700` или `text-amber-700` в admin paths (via filesystem grep — fast вспомогательный test)
- (d) Existing axe-core scenarios still pass (no regression)
- (e) Chromatic / visual-regression diff ≤ 0.1% pixel-delta (token-only swap; визуально equivalent due to same hex post-migration)
- (f) PR description: explicit count of files changed (expect 0-3); if 0 — task closes с "audit complete, no migrations needed" note

**Risk notes:**
- Security: NONE.
- UX: amber-700 (#B45309) и `--warning-strong` (#B45309) are литерально same hex on disk (verified в design-tokens.md); migration is naming-only. Zero visual delta.
- Breaking: NONE.

---

### C7-T09 — Admin axe-core periodic CI cron

**Goal:** Workflow на cron schedule (daily) re-run admin-axe.spec.ts на main branch для catch'а regressions от новых components, которые могут не trigger PR-level axe gate.

**Spec ref:** ISS-cycle7-carry-over.md §"Admin axe-core — remaining edge cases".

**Deps:** C7-T08 (audit MUST complete first; иначе cron immediately failures на existing amber-700 violations).

**Files:**
- `.github/workflows/admin-axe-cron.yml` (NEW)
- `Frontend/tests/e2e/admin-axe.spec.ts` — minor adjustments если needed (existing spec from B6-T07 already passes; no logic changes)
- `docs/operations/admin-axe-cron.md` (NEW, ≥80 строк) — what to do when cron fails (triage runbook)

**Workflow sketch:**

```yaml
name: admin-axe-cron

on:
  schedule:
    # Daily at 03:00 UTC (low-traffic window)
    - cron: "0 3 * * *"
  workflow_dispatch: {}

permissions:
  contents: read
  issues: write  # Auto-create issue on failure

concurrency:
  group: admin-axe-cron
  cancel-in-progress: false

jobs:
  axe-scan:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps:
      - uses: actions/checkout@v4
        with:
          ref: main
      - name: Setup Node + Playwright
        # ... (mirror existing playwright workflow setup)
      - name: Run admin-axe.spec.ts against main
        run: |
          cd Frontend
          npx playwright test admin-axe --project=chromium
      - name: Auto-file issue on failure
        if: failure()
        uses: actions/github-script@v7
        with:
          script: |
            const title = `axe-cron failure on main — ${new Date().toISOString().split('T')[0]}`;
            const body = `Daily admin axe-core re-run failed on main.\n\n` +
                         `Workflow: ${context.runId}\n` +
                         `Triage: docs/operations/admin-axe-cron.md`;
            await github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title,
              body,
              labels: ["accessibility", "regression", "auto-filed"],
            });
```

**Triage runbook content (~80 lines):**
- How to reproduce failure locally (`npx playwright test admin-axe --project=chromium --headed`)
- How to inspect axe violation details (Playwright report html)
- Common false positives (loading states, focus traps в modals)
- Fix routing: if violation в new component, owner team paged; if existing component changed, revert или patch in next PR

**Acceptance criteria:**
- (a) Workflow runs daily at 03:00 UTC; manually triggerable
- (b) On failure: GitHub issue auto-filed с standardized title + labels
- (c) Concurrency group prevents overlapping runs
- (d) Triage runbook documents reproduction + common fixes
- (e) C7-T08 audit completed prior (otherwise immediate failure on existing residuals)
- (f) First successful cron run within 24h of merge — verified manually post-merge

**Risk notes:**
- Operational: Auto-filed issues могут pile up если accessibility regressions ignored. Mitigated через label-filter alert + monthly accessibility review cadence.
- Performance: Daily cron consumes ~20 min CI minutes/day = ~10 hrs/month — acceptable budget.
- Breaking: NONE.

---

### C7-T10 — Cycle 7 closeout (report + CHANGELOG + ISS-cycle8-carry-over)

**Goal:** Финализировать Cycle 7. Implementation report ≥500 lines (mirrors structure cycle6-batch6-implementation.md), CHANGELOG rollup, и ISS-cycle8-carry-over.md если есть deferred items (планнер не expects ничего deferred — все 10 tasks — must-have or nice-to-have, все complete).

**Files:**
- `ai_docs/develop/reports/2026-04-22-argus-cycle7-implementation.md` (NEW, ≥500 строк)
- `ai_docs/changelog/CHANGELOG.md` — добавить `## [Unreleased] — Cycle 7` section с C7-T01..T09 bullets
- `ai_docs/develop/issues/ISS-cycle8-carry-over.md` (NEW; expected near-empty)
- `ai_docs/develop/issues/ISS-T20-003.md` — UPDATE: Phase 2 complete, grace window closed (Alembic 031 applied), gate fully closed
- `ai_docs/develop/issues/ISS-T20-003-phase2.md` — UPDATE: status = closed, link to C7-T10 report
- `ai_docs/develop/issues/ISS-cycle7-carry-over.md` — UPDATE: status = closed (всё shipped)

**Report sections:**

1. **TL;DR** (~50 lines) — high-level achievements + scorecard
2. **Per-task summaries** (~250 lines) — C7-T01 .. C7-T09 каждая ~25 lines
3. **Verification matrix** (~80 lines) — backend tests / frontend tests / migration tests / E2E / axe / verapdf gates
4. **Migration timeline** (~30 lines) — 030 → 032 (MFA columns) → 031 (legacy cleanup) с deploy sequence proof
5. **Production gates status** (~40 lines) — ISS-T20-003 Phase 1+2 ✅ closed; ISS-T26-001 Phase 1 ✅ closed; ARG-058 PDF/A hardened; ARG-059 KEV-HPA prod operational
6. **Open issues** (~20 lines) — expected: 0 open critical; carry-over near-empty
7. **Forward path Cycle 8** (~30 lines) — SARIF/SBOM continuous publishing, granular per-resource RBAC, public beta criteria

**ISS-cycle8-carry-over.md expected content:**

```markdown
# Cycle 8 — carry-over

**Дата:** 2026-04-22
**Статус:** Open items at end of Cycle 7

## Открытые темы (expected: empty или near-empty)

### MFA Option 2 (IdP OIDC) — when procurement closes
- **Статус:** Cycle 7 Option 1 (TOTP) shipped; Option 2 deferred per ISS-T20-003-phase2.md §Trade-off
- **Pre-condition:** IdP procurement (Azure AD / Auth0 / Keycloak) closed by Ops team
- **Scope:** OIDC integration с amr=mfa claim trust; TOTP path remains as fallback
- **Блокер:** Procurement; engineering ready

## Recommendations для Cycle 8 kickoff

- SARIF/SBOM continuous publishing pipeline (deferred since Cycle 6)
- Granular per-resource RBAC (Cycle 8+ scope)
- Audit certification (SOC 2 Type 1 readiness assessment)
- Public beta launch criteria + go-live plan
```

**CHANGELOG rollup outline:**

```markdown
## [Unreleased] — Cycle 7 (2026-04-22)

### Added — Admin auth Phase 2 (C7-T01..T04, ISS-T20-003 Phase 2a)
- TOTP MFA enforcement для super-admin role
- Backup codes (10 single-use, bcrypt-hashed at rest)
- Fernet-encrypted TOTP secret storage с keyring rotation support
- New endpoints: enroll / confirm / verify / disable / regenerate-backup-codes / status
- Frontend enrollment flow + verify-on-login + backup-codes modal

### Added — Operator runbook (C7-T05, ISS-T20-003 Phase 2b)
- `docs/operations/admin-sessions.md` — lifecycle, MFA, audit queries, pepper rotation
- Linked from README operations section

### Changed — Admin session storage (C7-T07, ISS-T20-003 Phase 2c)
- Alembic 031: dropped legacy `session_id` raw column; `session_token_hash` promoted to PK
- Removed `ADMIN_SESSION_LEGACY_RAW_*` flags
- Code cleanup: legacy fallback branches removed from resolver

### Added — PDF/A acceptance hardening (C7-T02)
- Zero-warning verapdf gate
- Fixture variants: Cyrillic, longtable, images, per-tenant flag path
- 13-job matrix (3 tiers × 4 variants + 1 per-tenant integration)

### Added — KEV-aware HPA prod rollout signals (C7-T06)
- PrometheusRule для scrape-missing + stuck-at-max alerts
- Verification script + rollout doc + rollback procedure

### Changed — Visual consistency (C7-T08)
- Amber-700 residuals migrated to `--warning-strong` token

### Added — Periodic accessibility scan (C7-T09)
- Daily cron re-running admin-axe.spec.ts на main
- Auto-issue creation on failure

### Production gates closed
- ISS-T20-003 Phase 1 + Phase 2 ✅ — admin auth fully hardened
- ISS-T26-001 ✅ — WCAG AA contrast (carry-over uniformity audit)
- ARG-058 PDF/A — production gate
- ARG-059 KEV-HPA — production gate с rollback procedure

### Sign-off
See `ai_docs/develop/reports/2026-04-22-argus-cycle7-implementation.md`.
```

**Acceptance criteria:**
- (a) Report ≥500 строк; sections mirror `2026-04-22-cycle6-batch6-implementation.md`
- (b) CHANGELOG rollup added под `## [Unreleased] — Cycle 7`; bullets reference task IDs
- (c) ISS-cycle8-carry-over.md created (even if near-empty); status = open
- (d) ISS-T20-003.md: Phase 2 marked complete; grace window noted closed via Alembic 031
- (e) ISS-T20-003-phase2.md: status = closed; link to report
- (f) ISS-cycle7-carry-over.md: status = closed; всё shipped reference
- (g) Workspace progress.json updated to status=completed; tasks.json все completed; links.json includes report

**Risk notes:**
- Documentation drift: link rot если future cycles rename files. Mitigated через relative paths + canonical anchors.
- Breaking: NONE.

---

## 6. Test plan (consolidated)

### CI gates touched / added в Cycle 7

| Gate | New | Modified | Trigger |
|------|-----|----------|---------|
| `pdfa-validation.yml` | — | ✓ (C7-T02) | extends matrix to 13 jobs; zero-warning enforcement |
| `admin-axe-cron.yml` | ✓ (C7-T09) | — | daily 03:00 UTC + manual dispatch |
| `kev-hpa-kind.yml` | — | ✓ (C7-T06) | extends с alert-firing test |
| `test_admin_mfa_dao.py` | ✓ (C7-T01) | — | backend pytest |
| `test_mfa_crypto.py` | ✓ (C7-T01) | — | backend pytest |
| `test_032_admin_mfa_columns_migration.py` | ✓ (C7-T01) | — | backend pytest (migration) |
| `test_admin_auth_mfa_endpoints.py` | ✓ (C7-T03) | — | backend pytest |
| `test_super_admin_mfa_enforcement.py` | ✓ (C7-T03) | — | backend pytest |
| `test_pdfa_per_tenant_path.py` | ✓ (C7-T02) | — | backend pytest |
| `test_kev_hpa_prod_signals.py` | ✓ (C7-T06) | — | kind cluster only |
| `test_031_drop_legacy_admin_session_id_migration.py` | ✓ (C7-T07) | — | backend pytest (migration) |
| `test_admin_sessions_no_legacy_path.py` | ✓ (C7-T07) | — | backend pytest |
| `admin-mfa.spec.ts` (Playwright) | ✓ (C7-T04) | — | E2E |
| `EnrollClient.test.tsx` (vitest) | ✓ (C7-T04) | — | unit |
| `VerifyClient.test.tsx` (vitest) | ✓ (C7-T04) | — | unit |
| `AmberSurfaceAudit.test.tsx` (vitest) | ✓ (C7-T08) | — | unit (filesystem assertion) |

### Coverage targets

- Backend: 90%+ для каждого нового модуля (`admin_mfa.py`, `_mfa_crypto.py`, `admin_mfa_tokens.py`)
- Frontend: 85%+ для каждого нового client (`EnrollClient.tsx`, `VerifyClient.tsx`, `mfaClient.ts`)
- Existing baseline сохраняется (no regressions; legacy fallback tests dropped per C7-T07 are intentional removal)

### Manual smoke before each merge

| Surface | What to verify |
|---------|----------------|
| `/admin/mfa/enroll` | QR scans в Google Authenticator, Authy, 1Password; backup codes downloadable + copyable; cannot dismiss modal без save |
| `/admin/mfa/verify` | TOTP accepts 30-sec window codes; backup code accepts once + rejects re-use; rate-limit triggers at 6th attempt |
| `/admin/login` (MFA enabled super-admin) | Two-step flow: password → mfa_required → verify → /admin |
| `/admin/login` (no MFA) | Single-step flow byte-equivalent to Phase 1 |
| Pepper rotation procedure | Follow runbook end-to-end в staging; verify zero downtime |
| Pre-031 checklist | Three signals all-green в staging Prometheus; documented в C7-T07 PR |
| `verapdf 13-job matrix` | All variants pass; allow-list empty; warnings = 0 |
| KEV-HPA scrape | `verify-kev-hpa-scrape.sh` returns 0 в staging; alerts silent |
| `/admin/audit-logs` | MFA action audit entries visible (`admin.mfa.enrolled`, etc.) |

---

## 7. Risk register

| # | Risk | Likelihood | Impact | Mitigation |
|---|------|-----------|--------|------------|
| **R1** | TOTP secret leakage через debug logs | Low | Critical | Crypto wrapper never logs; tests assert log-output free of secret bytes; structured logging filters `mfa_*` keys |
| **R2** | Backup-codes lost (operator не save'нул из modal) | Medium | High | Modal forces interaction; regenerate-backup-codes endpoint requires TOTP re-auth |
| **R3** | MFA lockout (operator loses TOTP device + no backup codes) | Low | Critical | Super-admin может disable MFA для другого operator с audit log; documented в runbook §"Lost-device recovery" |
| **R4** | Alembic 031 drops session column too early (live sessions exist) | Medium | Critical | Pre-flight gate; three signals; reviewer enforcement; force-revoke fallback |
| **R5** | Alembic 031 forward-only — невозможно roll back через alembic | Low (after gate) | High | Documented procedure: revert deploy + force-revoke + re-deploy 030 + operators re-login (accept session loss) |
| **R6** | KEV-HPA scrape missing post-deploy | Medium | Medium (HPA silent CPU-only) | PrometheusRule alert ArgusKevHpaMetricMissing fires within 5m; `verify-kev-hpa-scrape.sh` smoke check |
| **R7** | verapdf upstream behaviour change (1.24.x → 1.25.x) | Low | Medium | Pinned version; comment block в workflow documents bump procedure |
| **R8** | Rate-limit too aggressive (lockout legitimate operators) | Medium | Medium | Defaults conservative (5 verify attempts/5min/token); documented в runbook; super-admin может wait or use backup code |
| **R9** | Fernet keyring misconfigured (empty / invalid base64) | Low | High | Settings validator fails fast at boot; structured ConfigurationError; documented в runbook |
| **R10** | Frontend MFA flow breaks legacy bookmarked URLs | Low | Low | Middleware redirects gracefully; `?from=` query param preserves intent |
| **R11** | PDF/A allow-list creep (warnings whitelisted без discipline) | Medium | Medium | Each allow-list entry MUST link ticket; quarterly review cadence в `pdfa-acceptance.md` |
| **R12** | Auto-issue noise from cron (false positives) | Medium | Low | Triage runbook; label-based filtering; monthly review |

---

## 8. Closeout (C7-T10 deliverable shape)

При закрытии Cycle 7, C7-T10 деливерит ровно следующие 5 артефактов:

1. **`ai_docs/develop/reports/2026-04-22-argus-cycle7-implementation.md`** — Cycle 7 implementation report (≥500 строк), mirrors структуру `2026-04-22-cycle6-batch6-implementation.md`. Sections: TL;DR / Per-task summaries / Verification matrix / Migration timeline / Production gates status / Open issues / Forward path Cycle 8.

2. **`ai_docs/changelog/CHANGELOG.md`** rollup — `## [Unreleased] — Cycle 7` section с bullets per major area (Phase 2 MFA, runbook, Alembic 031, PDF/A hardening, KEV-HPA prod, visual consistency, axe cron).

3. **`ai_docs/develop/issues/ISS-cycle8-carry-over.md`** — near-empty carry-over (only Option 2 IdP procurement deferred); scope outline для Cycle 8.

4. **`ai_docs/develop/issues/ISS-T20-003.md`** + **`ISS-T20-003-phase2.md`** updates — both gates closed; cross-link to C7 report.

5. **`ai_docs/develop/issues/ISS-cycle7-carry-over.md`** update — status = closed; всё shipped.

После C7-T10 merge — Cycle 7 OFFICIALLY closed. ISS-T20-003 (Phase 1 + Phase 2) гате полностью закрыт. ARGUS production-ready scorecard updated: admin auth fully hardened (MFA + runbook + clean schema), PDF/A archival production-grade (hardened gate), KEV-HPA prod operational с rollback procedure.

---

## 9. Файлы оркестрации

```
.cursor/workspace/active/orch-2026-04-22-argus-cycle7/
  plan.md         — workspace pointer (содержит summary + ссылку на canonical)
  tasks.json      — 10 задач + статусы + acceptance + dependencies
  progress.json   — orchestration metadata + scope + deviation summary
  links.json      — ссылки на canonical plan / report / issues
```

```
ai_docs/develop/plans/2026-04-22-argus-cycle7.md  — этот документ (canonical, human-facing)
```

---

## 10. Ссылки

- **Carry-over (вход):** [`ai_docs/develop/issues/ISS-cycle7-carry-over.md`](../issues/ISS-cycle7-carry-over.md)
- **Phase 2 spec:** [`ai_docs/develop/issues/ISS-T20-003-phase2.md`](../issues/ISS-T20-003-phase2.md)
- **Phase 1 closure:** [`ai_docs/develop/reports/2026-04-22-cycle6-batch6-implementation.md`](../reports/2026-04-22-cycle6-batch6-implementation.md)
- **Predecessor plan:** [`ai_docs/develop/plans/2026-04-22-argus-cycle6-b6.md`](2026-04-22-argus-cycle6-b6.md)
- **ISS-T20-003 parent:** [`ai_docs/develop/issues/ISS-T20-003.md`](../issues/ISS-T20-003.md)
- **ISS-T26-001:** [`ai_docs/develop/issues/ISS-T26-001.md`](../issues/ISS-T26-001.md)
- **Architecture skill:** [`.cursor/skills/architecture-principles/SKILL.md`](../../../.cursor/skills/architecture-principles/SKILL.md)
- **Task management skill:** [`.cursor/skills/task-management/SKILL.md`](../../../.cursor/skills/task-management/SKILL.md)
- **Security guidelines skill:** [`.cursor/skills/security-guidelines/SKILL.md`](../../../.cursor/skills/security-guidelines/SKILL.md)

---

**Последнее обновление:** 2026-04-22 (initialised by planner subagent).
**Статус:** Ready to execute.
**Запуск:** `/orchestrate execute orch-2026-04-22-argus-cycle7`
