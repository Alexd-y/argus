# ISS-cycle8-carry-over

**Дата:** 2026-04-22  
**Статус:** PROPOSED (carry-over из Cycle 7; источник: plan + implementation)  
**Owner:** TBD (Cycle 8 planner)  
**Источник цикла:** Cycle 7 (завершен 2026-04-22)  

---

## Обзор

Cycle 7 завершил **все 9 основных задач**, включая полную Phase 2 admin-auth hardening (MFA backend + endpoints + legacy cleanup), PDF/A production-grade gate, KEV-HPA prod rollout signals, и нечетыре runbooks. **Одна задача явно deferred:**

### C7-T04 — MFA frontend

**Статус:** Explicitly deferred to Cycle 8 per plan (not blocker; backend stable)

**Rationale:**
- C7-T03 backend fully complete, tested, deployed
- Frontend работа — крупный multi-component task (≥500 LOC estimate, ≥8 E2E scenarios, ≥12 unit cases)
- Clean separation: backend stabilization ≠ frontend implementation
- Blocker-free: backend API stable, no code changes in frontend path

**Scope (Cycle 8 task):**
- `/admin/mfa/enroll` page — QR display + base32 fallback + enrollment form
- `/admin/mfa/BackupCodesModal` component — forced save/copy interaction (modal cannot dismiss unacted)
- `/admin/mfa/verify` page — TOTP input (default) + backup code fallback + rate-limit cooldown timer
- `LoginClient.tsx` update — handle `{status: "mfa_required"}` response → redirect `/admin/mfa/verify`
- Middleware update — super-admin role + missing `mfa_passed_at` → redirect `/admin/mfa/verify`
- E2E tests: ≥8 Playwright scenarios (enroll + verify + backup-code paths, rate-limit, already-enrolled guard)
- Unit tests: `EnrollClient.test.tsx`, `VerifyClient.test.tsx`, `mfaClient.ts` (≥12 vitest cases)
- Coverage target: ≥85%

**Dependencies:** ✅ All cleared (C7-T03 backend ready; no blockers)

**Entry point for C8:** Accept C7-T04 scope as-is; stack on wave 1 (foundation task) since enroll/verify flows are primary user touchpoint post-MFA backend

---

## Carry-over follow-ups (nice-to-have из Cycle 7)

### из C7-T03 (MFA endpoints)

#### F1. Multi-pod rate limiting (Redis backplane)

**Описание:** C7-T03 реализована in-memory LRU token-bucket (`_LoginRateLimiter`, `_VerifyRateLimiter`). На single-pod deployment это правильно, но на multi-pod это неточно — каждый pod держит свой state, и распределённый атакующий может обойти лимит.

**Текущее состояние:** Работает; design pattern (шаблон) уже documented в endpoint'е (TODO комментарий в `src/api/admin/mfa.py:verify_endpoint`).

**Scope (C8 nice-to-have):**
- Swap in-memory LRU на Redis-backed rate limiter (same interface, different backend)
- Update tests to mock Redis (or use Redis in CI)
- Update runbook `docs/operations/admin-sessions.md` section 4.2 (rate-limit) с note о multi-pod accuracy

**Effort:** Small (1-2 commits)  
**Blocker:** None  
**Owner:** TBD (C8 planner)

#### F2. QR code generation library pinning

**Описание:** C7-T03 deliberately не pinned `qrcode` library в backend (to avoid bloat). C7-T04 frontend должна render QR из `provisioning_uri` returned by backend. Это правильно, но требует фронтенду явно handle QR rendering.

**Текущее состояние:** Backend returns `provisioning_uri` (valid `otpauth://totp/...`); frontend expected to handle

**Scope (C8 implementation in C7-T04):**
- Frontend uses `qrcode.js` или similar lightweight lib (verify no bloat vs pip alternatives)
- C7-T04 PR description должна document выбор + rationale
- Update `backend/.env.example` comment section (C7-T03) с note "QR rendering delegated to frontend"

**Effort:** Already part of C7-T04  
**Blocker:** None  
**Owner:** C7-T04 frontend worker (C8)

#### F3. `status.enrolled_at` field population

**Описание:** C7-T03 добавила `mfa_enabled` + `mfa_secret_encrypted` + `mfa_backup_codes_hash`, но не добавила `mfa_enrolled_at` timestamp. GET `/auth/admin/mfa/status` response включает `enrolled_at` field (per C7-T03 spec), но схема её не tracking. Это создаёт тонкий gap: если DAO переболдлась, enrolled_at становится NULL.

**Текущее состояние:** Status endpoint works; pero `enrolled_at` всегда NULL в legacy rows (C7-T03-мигрированные)

**Scope (C8 follow-up):**
- Добавить Alembic миграция (033?) с `admin_users.mfa_enrolled_at TIMESTAMPTZ NULLABLE`, backfill = `mfa_enabled ? NOW() : NULL` для existing rows
- OR: Decide to drop `enrolled_at` from response model и use `mfa_enabled=true` as proxy (simpler but less auditable)

**Effort:** Small (1 commit if decision to drop field; 2-3 if adding migration)  
**Blocker:** None  
**Owner:** TBD (C8 planner)  
**Decision point:** Cycle 8 kickoff

#### F4. Stale "downgrade is a no-op" formulation

**Описание:** C7-T07-followup fixed CHANGELOG entry downgrade semantics, но осталось две stale формулировки в другие места:

1. `docs/operations/admin-sessions.md:70` — старый текст о "downgrade is a no-op" (outdated per C7-T07 reality)
2. `backend/tests/auth/test_admin_mfa_endpoints.py:28` — comment "downgrade safely restores..." (copy-paste dari C7-T07 spec старой версии)

**Текущее состояние:** Tests pass; docs readable; но inconsistent semantic

**Scope (C8 cleanup):**
- Grep for "downgrade" in docs/operations/ и backend/tests/auth/ 
- Replace with C7-T07 corrected semantics (forward-only migration; downgrade raises; emergency rollback procedure documented)

**Effort:** Trivial (1 commit, 2-3 line changes)  
**Blocker:** None  
**Owner:** Any C8 worker  
**Suggest:** Include in C8-T01 or first touchpoint

---

### из C7-T07 (Alembic 031 + legacy cleanup)

#### F5. Session ID kwarg rename (clarity improvement)

**Описание:** API `admin_sessions.py` function `create_session(..., session_id=...)` использует kwarg name `session_id`, но переменная now points to hash, не raw token (после C7-T07 cleanup). Это confusing для новых readers; `raw_token` более explicit.

**Текущее состояние:** Code works; naming misleading

**Scope (C8 refactor):**
- Rename parameter `session_id` → `raw_token` in `create_session` signature (backend only; internal API)
- Update callers (tests, fixtures, DAO layer)
- Update docstrings

**Effort:** Small (1 commit, find-replace)  
**Blocker:** None  
**Owner:** TBD (C8 refactor worker)  
**Timing:** Post-C8-T01 (after any urgent work)

---

### из C7-T06 (KEV-HPA prod rollout)

#### F6. Per-pod aggregation refinement

**Описание:** C7-T06-followup "DEBUG-2" fixed `KEVHPAMetricLatencyHigh` alert для per-pod aggregation, но комментарий в `prometheus-rules-kev-hpa.yaml` всё ещё generic. Операторам нужен explicit note о почему per-pod vs global scope.

**Текущее состояние:** Alert works correctly; документация is implicit

**Scope (C8 documentation):**
- Add comment block в `prometheus-rules-kev-hpa.yaml` section `ArgusKevHpaMetricLatencyHigh` с explanation (per-pod captures latency variance across Celery worker distribution; global latency can mask outliers)
- Update `docs/operations/kev-hpa-rollout.md` section 4 (staging soak) с note о per-pod metric interpretation

**Effort:** Trivial (comment + doc update)  
**Blocker:** None  
**Owner:** Any C8 worker  
**Suggest:** Include в Cycle 8 runbook review pass

---

### из C7-T09 (Axe-core cron)

#### F7. Multi-match dedupe warning

**Описание:** C7-T09 parser (`Frontend/scripts/parse-axe-report.mjs`) dedupes issues на title prefix match (`[axe-core] Nightly admin a11y scan:`), но если multiple unrelated violations fire on same day, они all land в single issue with separate comments. Это OK в rare case, но workflow should emit WARNING log line когда dedup happens для operator visibility.

**Текущее состояние:** Workflow works; dedup silent (не bad, но could warn)

**Scope (C8 nice-to-have):**
- Modify "File / update axe regression issue" step in `.github/workflows/admin-axe-cron.yml` to emit GitHub Actions warning log (`::warning::Multiple violations on same day — check dedup logic`)
- OR: Skip dedup entirely (simpler — file fresh issue every time, let bot tools dedup)

**Effort:** Trivial (1 line in workflow)  
**Blocker:** None  
**Owner:** TBD (C8 CI worker)  
**Decision point:** Cycle 8 kickoff (operator preference on issue dedupe)

#### F8. Actionlint hashFiles warnings

**Описание:** C7-T09 workflow uses GitHub Actions `hashFiles()` function для caching Playwright binaries, но `actionlint` (if enabled) flags это как неправильный синтаксис на job-level (actionlint expects hash at step-level). Это ложный positive; действительного кода нет проблемы, но CI может fail в strict linting.

**Текущее состояние:** Workflow works; potential CI noise if actionlint added

**Scope (C8 hardening):**
- Lift `hashFiles()` calls из job-level `cache:` key в step-level `uses: actions/cache@v4` parameter (proper actionlint syntax)
- Apply same fix to sibling workflows `helm-validation.yml`, etc. если they exist

**Effort:** Small (1-2 commits for sweep)  
**Blocker:** None  
**Owner:** TBD (C8 CI worker)  
**Timeline:** When actionlint is enabled repo-wide (not urgent)

---

### из C7-T02 (PDF/A hardening)

#### F9. Operator follow-up: branch protection rename

**Описание:** C7-T02 extends verapdf workflow status check name, но GitHub branch protection rule still references old name `'PDF/A-2u validation (verapdf)'`. After C7-T02 merge to main, branch protection must be updated to `'PDF/A-2u validation (verapdf) — zero-warning'` (otherwise pre-merge check passes locally but CI shows unexpected failure).

**Текущее состояние:** Documented in "Outstanding operator follow-ups" section of C7 report

**Owner:** DevOps / CODEOWNERS  
**Timeline:** After C7-T02 merge to main (same-day action)  
**Effort:** Trivial (GitHub UI update)  
**Block:** C7 production merge

---

### из C7-T01 (MFA backend)

#### F10. Keyring rotation timing window

**Описание:** `_mfa_crypto.py` implements zero-downtime TOTP secret re-encryption via MultiFernet keyring rotation. Design assumes operators will add new key to keyring and wait for opportunistic re-encryption on next verify call, then drop old key. Но no documented "safe window" for when to drop old key (how long to keep dual-key state?). This should be в runbook.

**Текущее状态:** Implemented; runbook (C7-T05) mentions key rotation but не specifies timing

**Scope (C8 documentation):**
- Update `docs/operations/admin-sessions.md` section 6 (pepper rotation procedure) с subsection "TOTP key rotation" (mirrors pepper rotation logic but for MFA keyring)
- Add timing guidance: "Keep both keys active for ≥1 ADMIN_MFA_REAUTH_WINDOW_SECONDS (default 12h) to ensure operators with MFA devices can re-encrypt before old key is dropped"

**Effort:** Small (1 runbook update)  
**Blocker:** None  
**Owner:** TBD (C8 documenter)  
**Priority:** Nice-to-have (current design safe; just needs documentation)

---

## Cycle 8 приоритизация (рекомендация)

### Фаза 1 (blocking MFA rollout)

1. **C7-T04 — MFA frontend** (foundation task) — разблокирует все MFA UX flows
2. **Option:** F5 (session_id → raw_token rename) если это будет быстро (5 min) иначе отложить

### Фаза 2 (nice-to-have refinements)

3. **F1 — Redis-backed rate limiting** (multi-pod accuracy) — small effort, high value
4. **F9 — Branch protection rename** (operational requirement) — must-do same-day post-C7-T02 merge
5. **F6 — Per-pod aggregation doc** (runbook clarity)
6. **F10 — Keyring rotation doc** (runbook clarity)

### Фаза 3 (cleanup)

7. **F4 — Stale downgrade text** (1 commit, trivial)
8. **F2 — QR code lib note** (already included in C7-T04)
9. **F3 — enrolled_at field decision** (defer to UX review phase)
10. **F7, F8 — Cron workflow cosmetics** (very low priority, nice-to-have)

---

## Кросс-ссылки (трейсабилити)

### Входные документы (Cycle 7)

- **Plan:** [`ai_docs/develop/plans/2026-04-22-argus-cycle7.md`](../plans/2026-04-22-argus-cycle7.md)
- **Report:** [`ai_docs/develop/reports/2026-04-22-cycle7-implementation-report.md`](../reports/2026-04-22-cycle7-implementation-report.md)
- **ISS-T20-003:** [`ai_docs/develop/issues/ISS-T20-003.md`](ISS-T20-003.md)
- **ISS-T20-003-phase2:** [`ai_docs/develop/issues/ISS-T20-003-phase2.md`](ISS-T20-003-phase2.md)

### Контекст Cycle 6

- **B6 Plan:** [`ai_docs/develop/plans/2026-04-22-argus-cycle6-b6.md`](../plans/2026-04-22-argus-cycle6-b6.md)
- **B6 Report:** [`ai_docs/develop/reports/2026-04-22-cycle6-batch6-implementation.md`](../reports/2026-04-22-cycle6-batch6-implementation.md)
- **B6 Carry-over (resolved):** [`ai_docs/develop/issues/ISS-cycle7-carry-over.md`](ISS-cycle7-carry-over.md) [CLOSED — всё shipped]

---

## Signoff

**Cycle 7 officially closed.** No blocking carry-overs. One task (C7-T04) deferred per explicit plan; blocker-free, ready for clean C8 implementation.

**Next action:** Cycle 8 planner accepts C7-T04 scope + prioritizes nice-to-have follow-ups per recommendation above.

---

**Дата создания:** 2026-04-22  
**Источник:** C7-T10 closeout (C7 Implementation Report)  
**Статус:** Open (awaiting C8 planner review + prioritization)
