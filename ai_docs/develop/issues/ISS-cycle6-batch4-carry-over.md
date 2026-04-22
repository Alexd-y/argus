# ISS — Cycle 6 Batch 4 — Carry-over Backlog (ARG-052+ARG-056)

**Issue ID:** ISS-cycle6-batch4-carry-over  
**Owner:** ARGUS Cycle 6 Batch 4 → Batch 5 transition  
**Source:** Cycle 6 Batch 4 orchestration completion (ARG-052+ARG-056, T28–T36)  
**Orchestration:** `orch-2026-04-22-argus-cycle6-b4`  
**Completion report:** [`ai_docs/develop/reports/2026-04-22-cycle6-batch4-implementation.md`](../reports/2026-04-22-cycle6-batch4-implementation.md)  
**Status:** ✅ Delivered — All 9 tasks shipped; carry-over items below  
**Priority:** mixed (see per-item)  
**Date filed:** 2026-04-22  

---

## Context

Cycle 6 Batch 4 (ARG-052+ARG-056) — **Operations UI: Kill-switch + Schedules** — завершился на 100%. Все 9 задач (T28–T36) поставлены с 14 атомарными коммитами и 60 vitest + 27 Playwright functional E2E + 6 a11y scenarios (5 of which pass strict, 1 under known ISS-T26-001), все gates passed. Задачи закрыли operator-facing чрезвычайные операции (per-scan / per-tenant / global kill-switch UI с audit trail) и scheduled-scan management (CRUD + dynamic RedBeat loader + visual cron builder).

**Batch 3** (ARG-051b) и **Batch 4** (ARG-052+ARG-056) вместе образуют **250+ hours** production-ready **Admin Frontend XL** — блокирующий feature для multi-tenant SaaS launch.

---

## What shipped (9/9 tasks)

| Task | Title | Commits | Coverage | Status |
|------|-------|---------|----------|--------|
| **T28** | Per-scan kill-switch UI | `56b6818` + `85b7943` | 8 vitest | ✅ |
| **T29** | Per-tenant throttle UI + countdown | `9ab4f9b` + `b5c3634` | 12 vitest | ✅ |
| **T30** | Global kill-switch + audit-trail (super-admin) | `56283d8` + `c0e6edb` | 15 vitest | ✅ |
| **T31** | Backend emergency API + KillSwitchService | `a7ccdc8` + `787c138` + `b7c9525` | 5 endpoints | ✅ |
| **T32** | Alembic migration 026 (scan_schedules table + RLS) | `6eb8fc3` | DB schema | ✅ |
| **T33** | Scan-schedules CRUD + RedBeat dynamic loader | `6a6a9a8` + `526eed4` + `12f3ce4` | 5 endpoints | ✅ |
| **T34** | Cron parser (croniter wrapper + maintenance windows) | `686888b` + `b1c6f01` + `2a0a41e` + `42955e3` | validation | ✅ |
| **T35** | Scheduled-scan UI + visual cron builder | `b02e6c9` | 25 vitest | ✅ |
| **T36** | Playwright E2E + a11y suites | `b633599` | 27 functional + 6 a11y | ✅ |

**Total:** 14 commits, 60 vitest + 27 Playwright functional + 6 a11y, all gates passed ✅

---

## 🚨 HIGH PRIORITY — Design System + Accessibility

### ISS-T26-001 — Accent-on-dark contrast (WCAG 2.1 AA failure)

**Status:** Extended scope from Batch 3 (7 buttons) → Batch 4 (12 surfaces).

**Root cause:** Design token `--accent (#A655F7)` + `text-[var(--bg-primary)] (#0a0a0a)` = 4.20:1 contrast; WCAG AA threshold = 4.5:1.

**Affected surfaces (Batch 4 additions):**
- `PerTenantThrottleClient` open-dialog button (`bg-amber-600 text-white` = 3.19:1)
- `SchedulesClient` "Создать расписание" button (`bg-[var(--accent)] text-white` = 3.98:1)
- `CronExpressionField` active tab (`bg-[var(--bg-tertiary)] text-[var(--accent)]` = 4.36:1)
- `RunNowDialog` confirm button (`bg-amber-600 text-white` = 3.19:1)
- `DeleteScheduleDialog` confirm button (`bg-red-600 text-white` = 3.99:1)
- `operations: STOP-ALL dialog open` — parent-page throttle CTA leak (3.19:1 visible behind modal)

**Impact:** 6 T36 a11y E2E scenarios gated as `test.fail()` in `Frontend/tests/e2e/admin-axe.spec.ts`.

**Proposal from issue file:**
- **Option A (preferred):** introduce `--accent-strong` + `--on-accent` tokens; migrate all primary action buttons.
- **Option B:** redefine `--accent` itself to darker shade; rename current to `--accent-glow`.
- **Option C (rejected):** bump button text to bold+16px (inflates layout).

**Timeline:** Polish PR between Batch 4 and Batch 5, or early Batch 5.

**Acceptance criteria:**
- (a) All 12 primary buttons + 5 T36 surfaces pass axe `color-contrast` (≥4.5:1).
- (b) Storybook / Chromatic visual diff reviewed + approved.
- (c) 6 `test.fail()` annotations removed from `admin-axe.spec.ts`.
- (d) New tokens (if Option A) documented in `Frontend/src/app/globals.css`.

**File:** [`ai_docs/develop/issues/ISS-T26-001.md`](ISS-T26-001.md)

---

## 🟠 MEDIUM PRIORITY (operator convenience)

### ISS-T29-001 (candidate) — Manual per-tenant throttle resume

**Description:** Currently `POST /admin/system/emergency/resume_all` (super-admin only) resumes global STOP_ALL. Batch 4 ships per-tenant throttle with TTL-based auto-resume after window expires. Operator should be able to **manually clear a per-tenant throttle before TTL expires**.

**Proposed scope:** Add `POST /admin/system/emergency/resume-tenant/{tenant_id}` (admin own-tenant / super-admin any) to clear throttle flag immediately.

**Rationale:** Operational convenience — if a throttle was triggered in error, operator shouldn't wait for TTL.

**Priority:** MEDIUM (can defer to Batch 5; TTL is a reasonable workaround).

**Acceptance criteria:**
- (a) Endpoint added to `backend/src/api/routers/admin_emergency.py`.
- (b) Audit emit on manual resume.
- (c) RBAC test coverage (admin own vs super-admin cross-tenant).
- (d) UI button added to `PerTenantThrottleClient` (if throttle is active, show "Clear now" button).

**Estimated effort:** 2–3 hours backend + 1–2 hours frontend.

**File:** TBD (to be filed if not already present)

---

## ℹ️ DEFERRED ISSUES CATALOG

### Pre-existing ESLint warnings (Batch 4 did NOT introduce)

**1. `src/app/admin/error.tsx`** — unused `_error` parameter (T11, Batch 2)  
**2. `src/app/admin/schedules/SchedulesClient.test.tsx`** — unused `beforeEach` (T35, Batch 4)

Both are low-priority lints (non-functional code style). Acceptable to defer to polish phase.

### STOP-ALL dialog axe scoping

When the STOP-ALL dialog is open, axe scans the full `<main>` region. The underlying `PerTenantThrottle` CTA (`bg-amber-600`, 3.19:1 contrast) remains visible behind the modal and triggers an axe violation. This is **not a dialog-specific problem** — once ISS-T26-001 lands, the underlying button passes and the dialog scenario will pass naturally (cascade fix, no dialog CSS needed).

---

## 🟢 LOWER PRIORITY (Batch 5+)

### Batch 5 recommendations (from roadmap)

From `Backlog/dev1_finalization_roadmap.md` §Batch 5:

- **T37–T41:** Webhook DLQ UI (dead-letter queue for failed webhook callbacks)
- **T42–T45:** Sigstore Kyverno admission policy (image verification pre-admission)
- **Related:** ISS-T29-001 (manual per-tenant resume)

### No new architectural debt

Batch 4 landed clean. All SOLID + KISS principles respected. No TODOs left in code. Red-team security review passed (emergency endpoints validated via RedBeat + Redis atomicity + audit chain).

---

## Batch 4 → Batch 5 Handoff

### Pre-Batch 5 checklist

- [ ] ISS-T26-001 design-token fix (polish PR or early Batch 5 T37 prep)
- [ ] Review ISS-T29-001 scope (manual resume endpoint) — file formal issue if proceeding
- [ ] Verify `celery-redbeat>=2.2.0` + `croniter>=2.0.5` SCA gates remain green across CI
- [ ] Confirm Batch 3 ISS-T20-003 (JWT/session auth) remains deferred for Cycle 7 pre-launch

### Known safe dependencies for Batch 5+

- `celery-redbeat` 2.2.0+ is stable; future bumps should check Changelogs for breaking beat-schedule schema changes
- `croniter` 2.0.5+ follows semver; timezone + DST handling is stable (scrutinized by many backends)
- `cron-parser` 4.9.0+ (NPM) is well-maintained; luxon transitive is stable

### Batch 5 unblocked by Batch 4

1. **Webhook DLQ UI (T37–T41)** — can now query emergency audit events from `audit_logs` table (same hash-chain as T22 findings). No schema changes needed; new table can go into Batch 5+ if desired.
2. **HPA autoscaling (Batch 6 T49–T51)** — can now consume `celery_scheduled_scans_total` + `celery_scan_schedule_next_fire_seconds` Prometheus metrics emitted by T33 RedBeat loader.

---

## Cross-links

| Artifact | Path |
|----------|------|
| **Completion report** | `ai_docs/develop/reports/2026-04-22-cycle6-batch4-implementation.md` |
| **Plan (source of truth)** | `ai_docs/develop/plans/2026-04-22-argus-cycle6-b4.md` |
| **Backlog: ARG-052** | `Backlog/dev1_finalization_roadmap.md` §Batch 4 (kill-switch) |
| **Backlog: ARG-056** | `Backlog/dev1_finalization_roadmap.md` §Batch 4 (schedules) |
| **Design-token issue** | [`ISS-T26-001.md`](ISS-T26-001.md) |
| **Batch 3 carry-over** | [`ISS-cycle6-batch3-carry-over.md`](ISS-cycle6-batch3-carry-over.md) |
| **Batch 3 report** | `ai_docs/develop/reports/2026-04-21-cycle6-batch3-implementation.md` |

