# ARGUS — dev1_.md Finalization Roadmap

**Status:** PRIMED — Cycle 6 ready to start
**Created:** 2026-04-20
**Owner (planner):** Cursor / Claude Opus 4.7
**Source-of-truth:** [`Backlog/dev1_.md`](dev1_.md) (Backlog v1)
**Cycle 5 sign-off:** [`ai_docs/develop/reports/2026-04-20-argus-finalization-cycle5.md`](../ai_docs/develop/reports/2026-04-20-argus-finalization-cycle5.md)
**Cycle 6 priming:** [`ai_docs/develop/issues/ISS-cycle6-carry-over.md`](../ai_docs/develop/issues/ISS-cycle6-carry-over.md)
**Active orchestration:** `orch-argus-20260420-1430` ([plan](../.cursor/workspace/active/orch-argus-20260420-1430/plan.md))

---

## TL;DR

ARGUS — production-grade active pentest engine с 150+ Kali tools, 6-фазным state-machine, full AI orchestrator, 23 Alembic migrations, 9 Prometheus metric families, и 2 546 PASS coverage matrix на конец Cycle 5. **Spec из `dev1_.md` реализован на ~92 %**. Оставшиеся ~8 % — это:

- **Cycle 5 known-limitations** (7 пунктов) — требуют foundation hygiene refactor.
- **Cycle 6 primed tasks** (7 пунктов: ARG-051..057) — production-launch features (Admin XL, kill-switch UI, Sigstore policy, PDF/A-2u, KEV-aware HPA, scheduled scans, webhook DLQ).
- **Heartbeat parsers** (59 → 39) — DoD §19.6 catalog coverage uplift.

Roadmap разбит на **6 batches × ~9 tasks = 53 tasks**. Estimated wall-time **~25 days at 3-4 worker parallelism**.

---

## Roadmap

### Batch 1 — Foundation Hygiene & Carry-over Closure (10 tasks, ~6d wall-time)

**Theme:** Закрыть Cycle 5 known-limitations + ARG-058 candidates. Прокачать parser coverage + CI quality bar.

| Task | Title | Size | Files | Status |
|------|-------|------|-------|--------|
| **T01** | OAST correlator — durable Redis-streams refactor | M | 9 | pending |
| **T02** | Latent cyclic policy import refactor (split approval module) | S | 7 | pending |
| **T03** | Network-tool YAML migration (web → network для 16 dual-listed) | S | 17 | pending |
| **T04** | SARIF + JUnit API exposure (closes 12 vs 18 reports drift) | M | 10 | pending |
| **T05** | Heartbeat-parsers → mapped (top 20 наиболее-используемых) | L | ~61 | pending |
| **T06** | Mypy Windows access-violation root-cause + WSL2 docs | S | 5 | pending |
| **T07** | Helm chart kubeconform schema validation in CI (multi-K8s matrix) | S | 5 | pending |
| **T08** | argus_validate.py extension (4 advisory gates: pip-audit / npm audit / kubeconform / trivy fs) | S | 7 | pending |
| **T09** | Sandbox SBOM auto-update + drift detection (Renovate watcher) | M | 11 | pending |
| **T10** | E2E multi-target matrix (DVWA + WebGoat alongside Juice Shop) | M | 9 | pending |

**Wall-time:** ~6 days с 3 worker parallel; ~5 days с 4 worker.
**Critical path:** T01 → T10.
**Detailed plan:** [`.cursor/workspace/active/orch-argus-20260420-1430/plan.md`](../.cursor/workspace/active/orch-argus-20260420-1430/plan.md) §3.

---

### Batch 2 — Admin Frontend XL — Foundation (ARG-051a) (9 tasks, ~4d wall-time)

**Theme:** Tenant + Scope + Scan history admin sub-routes + RBAC + bulk operations API.

| Task | Title | Size |
|------|-------|------|
| T11 | Admin chrome layout + RBAC guard (`useAdminAuth`, 3-tier hierarchy) | S |
| T12 | Tenant management list/create/edit/delete UI | M |
| T13 | Per-tenant rate-limit + scope blacklist + retention config UI | M |
| T14 | Scopes editor с DNS preview + IP range expansion + ownership proof status | M |
| T15 | Scan history table + drill-down (per-tool metrics + error log) | M |
| T16 | Per-tenant LLM provider config UI (encrypted secrets, never plaintext возврат) | M |
| T17 | Backend: bulk operations API (`POST /admin/scans/bulk-cancel`, `POST /admin/findings/bulk-suppress`) | S |
| T18 | Backend: audit log search/export API (`q=`, `since=`, `until=`, CSV export) | M |
| T19 | Playwright E2E coverage ≥5 scenarios для admin part 1 routes | S |

---

### Batch 3 — Admin Frontend XL — Triage + Audit (ARG-051b) (8 tasks, ~4d wall-time) **✅ DELIVERED 2026-04-21**

**Theme:** Global finding triage + audit log viewer + chain integrity verification + SARIF/JUnit toggle UI.

| Task | Title | Size |
|------|-------|------|
| T20 | Global finding triage UI (cross-tenant, SSVC-sorted, KEV-filtered) | L |
| T21 | Bulk findings actions (suppress / escalate / mark-false-positive / attach to CVE) | M |
| T22 | Audit log viewer UI с chain integrity verification (re-compute hash chain) | M |
| T23 | SARIF / JUnit toggle UI per-tenant (closes T04 UI surface) | S |
| T24 | Backend: cross-tenant finding query API (super-admin only, RBAC) | M |
| T25 | Backend: chain integrity verification API endpoint | S |
| T26 | Vitest unit ≥30 cases + axe-core 0 violations CI gate | S |
| T27 | Playwright E2E coverage ≥10 scenarios для admin part 2 routes | M |

---

### Batch 4 — Operations UI — Kill-switch + Schedules (ARG-052 + ARG-056) (9 tasks, ~4d wall-time)

**Theme:** Emergency-stop UI + scheduled scans (Alembic 024 + redbeat + visual cron UI).

| Task | Title | Size |
|------|-------|------|
| T28 | Per-scan kill-switch UI (double-confirmation typed scan ID match) | S |
| T29 | Per-tenant emergency throttle UI (countdown timer, audit emit) | M |
| T30 | Global kill-switch UI (super-admin) + audit trail viewer | M |
| T31 | Backend: `POST /admin/system/emergency/{stop_all,resume_all}` API | M |
| T32 | Alembic migration `024_scan_schedules.py` (table `scan_schedules` с RLS) | S |
| T33 | Backend: scan_schedules CRUD endpoints + redbeat dynamic loader | L |
| T34 | `src.scheduling.cron_parser` (croniter) + maintenance window logic + tests | M |
| T35 | Frontend: scheduled scan UI (table + visual cron builder via `react-cron`) | M |
| T36 | E2E: schedule trigger + maintenance window blocking + "Run Now" override | S |

---

### Batch 5 — Webhook DLQ + Supply chain (ARG-057 + ARG-053) (9 tasks, ~4d wall-time)

**Theme:** Persistent webhook DLQ (Alembic 025 + auto-replay) + Sigstore Kyverno admission policy.

| Task | Title | Size |
|------|-------|------|
| T37 | Alembic migration `025_webhook_dlq.py` (table `webhook_dlq_entries` с RLS) | S |
| T38 | Backend: `src.notifications.webhook_dlq_persistence` repository | M |
| T39 | Backend: DLQ admin API (GET / POST replay / DELETE abandon) | M |
| T40 | Backend: Celery beat task `webhook_dlq_replay` (daily, exp backoff, abandon ≥14d) | M |
| T41 | Frontend: DLQ list UI с search/filter + bulk replay (double-confirmation) | M |
| T42 | Kyverno cluster policy YAML (cosign-signed images required + immutable digest) | M |
| T43 | Helm chart extension (`policy.enabled` toggle + Kyverno cluster policy template) | S |
| T44 | kind cluster CI gate (`policy-test`) — attempt unsigned image deploy → expect HTTP 403 | M |
| T45 | Documentation: `docs/admission-policy.md` + `docs/webhook-dlq.md` operator runbooks | S |

---

### Batch 6 — Compliance + Autoscaling + Cycle 6 capstone (8 tasks, ~4d wall-time)

**Theme:** PDF/A-2u archival + KEV-aware HPA autoscaling + capstone (C17/C18 ratchets + sign-off).

| Task | Title | Size |
|------|-------|------|
| T46 | LaTeX PDF/A-2u preamble (3 tier-aware templates) + ICC profile + font embed | S |
| T47 | CI gate `pdfa-validation` через verapdf (Docker image-based) | S |
| T48 | Per-tenant config flag `tenant_config.reports.pdf_archival_format` | S |
| T49 | Helm: Prometheus Adapter + custom-metrics rules для `argus_*` metrics | M |
| T50 | Helm: HPA YAML `hpa-celery-worker-kev.yaml` (KEV-aware autoscaling) | S |
| T51 | kind cluster integration test `test_kev_aware_hpa.py` (simulated KEV burst) | M |
| T52 | Coverage matrix: C17 (`helm-template-cosign-asserts-prod`) + C18 (`every-tool-has-network-policy-or-justified-skip`) ratchets | M |
| T53 | Cycle 6 sign-off report (≥800 LoC, mirror ARG-040/049) + CHANGELOG rollup + ISS-cycle7-carry-over.md | M |

---

## Cycle 6 success metrics (target)

| Metric | Cycle 5 close | Cycle 6 target |
|--------|---------------|----------------|
| Tasks completed (Cycle 6) | n/a | 53 / 53 (100 %) |
| Acceptance criteria met | n/a | ≥ 95 % across all batches |
| Coverage matrix contracts | 16 | 18 (+12.5 %) |
| Coverage matrix cases | 2 546 | ≥ 2 800 (+10 %) |
| Mapped parsers | 98 / 157 (62.4 %) | 118 / 157 (75.2 %) |
| Heartbeat parsers | 59 / 157 (37.6 %) | 39 / 157 (24.8 %) |
| Reports per scan | 12 (3 tier × 4 format) | 18 (3 tier × 6 format) |
| Helm chart templates | 18 | ~20 (+2 — Kyverno + Prometheus Adapter) |
| Alembic migrations | 23 | 25 (+024 schedules + 025 webhook DLQ) |
| Frontend admin sub-routes | ~3 | ~12 (+9 admin XL routes) |
| New CI workflows | 0 | +3 (`policy-test`, `pdfa-validation`, `sbom-drift`) |
| Production-launch readiness | "production-deployable" | **"production-launched at scale"** |

---

## Top-5 risks for the entire Cycle 6 (with mitigation)

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| **R1** Admin Frontend XL (Batch 2 + 3) overrun на effort estimate (~10d → 14d) | medium | high | Phase Batch 2 (foundation must-have) + Batch 3 (triage nice-to-have); Batch 3 может slip to Cycle 7 без блокировки production launch |
| **R2** Kyverno admission policy (Batch 5) requires production-cluster maturity | medium | medium | Start с `kind` test cluster; defer prod cluster admission policy enable до Cycle 7 (after `kind` E2E tests stable for 2 weeks); document opt-in toggle (`policy.enabled=false` by default) |
| **R3** KEV-aware HPA (Batch 6) thrashing risk (rapid scale-up/down) | low | medium | Use `behavior.scaleUp.policies` + `behavior.scaleDown.policies` в HPA YAML с `stabilizationWindowSeconds=300`; integration test simulates burst + gradual decay |
| **R4** Webhook DLQ (Batch 5) auto-replay storm после long outage (e.g., Jira down for 3 days) | low | medium | Apply exponential backoff (1m, 5m, 15m, 1h, 6h, 1d, 7d, abandon); rate limit DLQ replay через Redis token bucket (max 10 replays/min) |
| **R5** Heartbeat parsers (Batch 1 T05) разрастается из-за неожиданной complexity tool-specific parser logic | medium | medium | Разбить T05 на 2 sub-batch по 10 tools; data-driven priorities (Prometheus metric); опциональный downgrade до 10 tools если deadline тонкий |

---

## Recommended execution policy

1. **Sequential batches** — один batch за орч-цикл; review + approval перед запуском следующего.
2. **Parallel within batch** — 3-4 worker parallelism; используем DAG из plan.md §4 (Batch 1) и аналогично для Batch 2-6.
3. **Atomic commits** — каждая T0X = ровно 1 commit; conventional commit message с task-id.
4. **DoD enforcement** — CI gate `argus_validate.py` (3 required + 7 advisory) сейчас, добавятся ещё 4 после T08 (всё advisory до Cycle 7).
5. **No regression** — coverage matrix C1..C16 × 157 = 2 546 cases — inviolable.
6. **Worker reports** — для L-size tasks или architectural changes (T05, T20, T33, T53) — обязательны в `ai_docs/develop/reports/`.
7. **Cycle 7 carry-over** — любые задачи которые не закрылись в Cycle 6 → ISS-cycle7-carry-over.md (T53 deliverable).

---

## Skills consulted

- [`architecture-principles/SKILL.md`](../.cursor/skills/architecture-principles/SKILL.md) — SOLID, DI, layered architecture
- [`task-management/SKILL.md`](../.cursor/skills/task-management/SKILL.md) — workspace structure, file formats
- [`code-quality-standards/SKILL.md`](../.cursor/skills/code-quality-standards/SKILL.md) — DRY, KISS, YAGNI, code smells
- [`security-guidelines/SKILL.md`](../.cursor/skills/security-guidelines/SKILL.md) — OWASP Top 10, secrets, RBAC, input validation

---

**Maintained by:** planner agent (Cursor / Claude Opus 4.7) — auto-update on each batch completion via `progress.json` + worker reports.
