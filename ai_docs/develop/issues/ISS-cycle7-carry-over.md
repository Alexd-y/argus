# Cycle 7 — carry-over

**Дата:** 2026-04-22  
**Статус:** Список открытых проблем, не включённых в scope Cycle 6 Batch 6, но требующих решения в Cycle 7  

---

## Открытые темы (приоритет, зависимости)

### ISS-T20-003 Phase 2 — MFA + runbook (HIGH)
- **Статус:** Phase 1 (session auth backend + frontend) ✅ завершена в B6-T08/T09. Phase 2 деферена.
- **Что осталось:**
  - MFA enforcement для super-admin роли (d) — TOTP + email-based backup codes, или интеграция с IdP.
  - Operator runbook `docs/admin-sessions.md` — session lifecycle, TTL (14d), revocation path, audit trail queryable via `/admin/audit-logs?actor={email}`.
  - Backwards-compat flag cleanup: `admin_session_legacy_raw_*` удаление из Settings после grace window (D-2).
  - Alembic 031 — drop `admin_sessions.session_token_raw` и связанные legacy-поля (откладывается на 30-60 дней после Phase 1 deploy).
- **Блокер:** None; Phase 2 — чистая фича, не блокирует.
- **Tickets:** `ISS-T20-003-phase2.md`, roadmap §Cycle 7.

### ISS-T26-001 Follow-up — amber-700 & other tokens (MEDIUM)
- **Статус:** Основной набор (`--accent-strong`, `--warning-strong`, их `--on-*` пары) ✅ завершён в B6-T06/T07.
- **Что осталось:**
  - Audit amber-700 (`bg-amber-700`) surfaces — выявленные в B6-T07 но не мигрировать, т.к. ratio уже 5.36:1 (выше 4.5:1 threshold). Тем не менее, рекомендуется использовать `--warning-strong` для uniformity.
  - Three amber-700 surfaces из B6-T04 batch (`PerTenantThrottleClient`, `RunNowDialog`, `DeleteScheduleDialog`) — уже мигрировали на `--warning-strong`; проверить pixel-perfect в Chromatic.
  - Expand design-tokens.md с примерами usage, deprecated token list (если бывают).
- **Блокер:** None; рекомендация, не obligation.
- **Tickets:** Перейти в `ai_docs/develop/issues/ISS-T26-001-follow-up.md` (optional, может быть inline в T26 issue).

### PDF/A acceptance — real verapdf runs in CI (MEDIUM)
- **Статус:** B6-T01 добавил шаблоны + helper; B6-T02 добавил admin toggle.
- **Что осталось:**
  - `.github/workflows/pdfa-validation.yml` на данный момент — это skeleton; нужно написать actual PDF generation из live template. Текущий `.yaml` может быть pure mock (генерирует fake PDF в /tmp).
  - Acceptance criteria: каждый из трёх tier-шаблонов (asgard / midgard / valhalla) с `archival_format=pdfa-2u` должен пройти `verapdf --format=ua` validation без нарушений.
  - Положительный path: CI генерирует live PDF через backend renderer (требует запуска вспомогательного FastAPI + LaTeX docker service в workflow).
  - Отрицательный path: без `archival_format=pdfa-2u` template fallback to standard; validation step skipped.
- **Блокер:** False alarm risk — если verapdf fails на prod; рекомендуется пилот на staging перед публичным запуском.
- **Tickets:** Может быть открыт `ISS-T26-031-pdfa-acceptance.md` или inline в `ISS-cycle7-carry-over.md`.

### KEV-HPA prod rollout — Prometheus Adapter enablement (MEDIUM)
- **Статус:** B6-T03 добавил Prometheus Adapter как optional subchart. B6-T04 добавил `hpa-celery-worker-kev.yaml`.
- **Что осталось:**
  - `infra/helm/argus/values-prod.yaml` — убедиться, что `prometheusAdapter.enabled: true` (может уже быть, нужно верифицировать).
  - Monitoring: новые Prometheus rules для `argus_celery_queue_depth` Gauge — убедиться, что scrape job настроен правильно (или будет ошибка: nil metric = no scale-up).
  - Staging pilot: 1–2 недели на production staging cluster перед main prod rollout.
- **Блокер:** False alarm risk — если Adapter не настроен, HPA может выбросить error events.
- **Tickets:** Inline в `ISS-cycle7-carry-over.md` или `ISS-T26-040-kev-hpa-prod.md`.

### Admin axe-core — remaining edge cases (LOW)
- **Статус:** B6-T07 удалил все 7 `test.fail` из основного набора. E2E `admin-axe.spec.ts` должна быть full-green на color-contrast.
- **Что осталось:**
  - Периодический re-run axe-core на `/admin/**` routes — убедиться, что новые компоненты (например, future dialogs, menus) не вводят новые нарушения.
  - WCAG 2.1 AAA (7:1 ratio) — опциональная цель для visibility или high-contrast mode.
- **Блокер:** None.

### Legacy admin identity shim cleanup (LOW)
- **Статус:** B6-T09 введена `NEXT_PUBLIC_ADMIN_DEV_*` env-var поддержка для dev-loop backward-compat.
- **Что осталось:**
  - Нельзя удалять `NEXT_PUBLIC_ADMIN_DEV_ROLE`, `NEXT_PUBLIC_ADMIN_DEV_TENANT`, `NEXT_PUBLIC_ADMIN_DEV_SUBJECT` из `.env.example` — нужны для local development в `ADMIN_AUTH_MODE=cookie`.
  - Phase 2 / ISS-T20-003-phase2 включает удаление этих vars из production builds.
- **Блокер:** None; полная очистка откладывается до Phase 2.

---

## Верификация (что нужно проверить в начале Cycle 7)

1. **Backend B6 commits:**
   - `backend/alembic/versions/028_admin_sessions.py` — миграция применяется без error, таблица создана.
   - `backend/alembic/versions/029_tenant_pdf_archival_format.py` — миграция применяется, enum добавлен.
   - `backend/src/auth/admin_sessions.py`, `admin_users.py` — unit tests green.
   - `backend/tests/auth/test_admin_auth_endpoints.py` — integration tests green (login / logout / whoami).

2. **Frontend B6 commits:**
   - `Frontend/src/middleware.ts` — TypeScript compile OK, middleware redirects on session-mode without cookie.
   - `Frontend/tests/e2e/admin-axe.spec.ts` — zero `test.fail` для color-contrast scenarios.
   - `Frontend/src/app/admin/login/page.tsx` — Playwright E2E green (happy path + error case).

3. **Infrastructure B6 commits:**
   - `infra/helm/argus/templates/hpa-celery-worker-kev.yaml` — Helm chart synth OK.
   - `infra/helm/argus/templates/prometheus-adapter-rules.yaml` — Prometheus rules syntax valid.
   - `.github/workflows/kev-hpa-kind.yml` — kind CI workflow passes on PR trigger.

4. **Documentation B6 commits:**
   - `ai_docs/develop/architecture/design-tokens.md` — новый файл, contrast matrix accurate.
   - `CHANGELOG.md` — B6-T01–T09 entries present.

---

## Рекомендации для Cycle 7 kickoff

- **Sprint planning:** Phase 2 (ISS-T20-003) + PDF/A acceptance + KEV-HPA production pilot = ~3–4 дня при 2-worker parallelism.
- **Risk register:** PDF/A verapdf может отклонить шаблоны по strict conformance (требует padding / color-space fixes); план B — downgrade архивный формат к PDF/X (близко к PDF/A, но проще).
- **Dependencies:** IdP procurement (для MFA, если Option A выберется в Phase 2).

---

## История (не пусто)

- **2026-04-22** — Initial carry-over после B6-T10 closeout.
