# ISS — Cycle 6 Carry-over Backlog (ARG-051..ARG-057)

**Issue ID:** ISS-cycle6-carry-over
**Owner:** ARGUS Cycle 5 → Cycle 6 transition
**Source:** ARG-049 capstone (`ai_docs/develop/plans/2026-04-21-argus-finalization-cycle5.md` §3 ARG-049)
**Sign-off report:** [`ai_docs/develop/reports/2026-04-20-argus-finalization-cycle5.md`](../reports/2026-04-20-argus-finalization-cycle5.md)
**Status:** Primed — Cycle 6 not yet started
**Priority:** mixed (см. per-item)
**Date filed:** 2026-04-21
**Last updated:** 2026-04-21 (initial filing during Cycle 5 capstone)

**Operational security (SEC-001):** Full operator runbook (provider rotation, git-history purge procedure without embedded secrets, pre-commit/CI pointers) — [`ISS-SEC-001-env-example-sanitization.md`](ISS-SEC-001-env-example-sanitization.md). Execution remains human-only.

---

## Context

Cycle 5 (ARG-041..ARG-049) закрыл все девять направлений плана: production-grade observability (OTel + 9 Prometheus families + 4 health endpoints + structured logging), Frontend MCP integration (consume TS SDK + 4-component UI + interactive `/mcp` route), real cloud_iam ownership для AWS/GCP/Azure (3 verifier'а + 24 closed-taxonomy summaries + 3 NetworkPolicy YAML'а), full CISA SSVC v2.1 (4 axes × 36 leaves × 4 outcomes) + EPSS + KEV daily ingest + FindingPrioritizer, production-grade Helm chart (18 templates + 4 overlays + 3 Bitnami sub-charts + cosignAssertProd self-protect helper) + 5 Alembic миграций (019..023, additive-only, RLS-preserving), полный hexstrike purge (18 → 0 active hits + permanent regression gate), e2e capstone scan против OWASP Juice Shop (12-фазный orchestrator + 8 pinned services + nightly CI workflow + 16 pytest зеркало), Cycle 4 known-gap closure (sandbox 4 → 6 / 6 image profiles + LaTeX Phase-2 + Slack callbacks с 7 security gates), и capstone (coverage matrix 14 → 16 contracts + frozen baseline + meta-runner + sign-off + Cycle 6 priming).

Final state на момент закрытия Cycle 5 — 2 546 PASS на coverage matrix gate (14 % growth), 9 Prometheus metric families с cardinality cap 1000 per family, 24 closed-taxonomy CLOUD_IAM_FAILURE_REASONS, 36 SSVC v2.1 leaves, 23 Alembic миграций (3 RLS-preserving), 6 / 6 sandbox image profiles built, 7 Slack security gates, 0 active hexstrike hits, 18 Helm templates с self-protect, ~14 850 LoC чистого добавления.

Этот документ собирает 7 carry-over пунктов (ARG-051..ARG-057), которые **выявлены и задокументированы внутри Cycle 5 worker reports как explicit «Cycle 6 candidate»** или внутри ARG-049 plan §6 «Known Gaps / Cycle 6 Candidates». Сознательно отложены до Cycle 6 (либо для соблюдения task-budget cap = 9, либо потому что требуют отдельных архитектурных решений, либо потому что блокируются external dependencies — например, Sigstore admission policy требует stable Kyverno/OPA Gatekeeper version в production cluster).

Каждый пункт содержит: **title**, **description**, **complexity estimate** (S / M / L / XL), **dependencies**, **source** (какой Cycle 5 task'ой surfaced), **proposed acceptance criteria**, **rationale**.

---

## ARG-051 — Admin Frontend XL (full `/admin/*` surface)

- **Description:** Full admin operations UI surface для multi-tenant production deployment:
  1. **Tenant management** (`/admin/tenants`) — list/create/edit/delete tenants; per-tenant rate-limit overrides (LLM tokens/day, scans/day, MCP calls/min); per-tenant scope blacklist; per-tenant retention policies; per-tenant Slack/Linear/Jira webhook config. Bulk operations (CSV import/export tenants).
  2. **Scope editor** (`/admin/scopes`) — visual scope editor (target URL/IP/CIDR + OOS exclusions + custom headers + auth method); scope validation (DNS resolution preview, IP range expansion, ownership proof status); per-tenant scope library (templates).
  3. **Scan history viewer** (`/admin/scans`) — paginated table со sortable columns (started_at, tenant, target, tier, status, finding_count, duration); drill-down to scan detail (full pipeline timeline, per-tool metrics, error log); bulk re-trigger; bulk cancel.
  4. **Finding triage** (`/admin/findings`) — global finding queue (cross-tenant for SaaS operator); SSVC-sorted, KEV-filtered, severity-faceted; bulk operations (mark as false-positive, suppress, escalate to incident, attach to existing CVE record).
  5. **Audit log viewer** (`/admin/audit`) — paginated audit log (hash-chained, append-only); search by event_type / tenant_hash / time range; export to JSON / CSV для compliance audits; chain integrity verification UI (re-compute hash chain to detect tampering).
  6. **Per-tenant LLM provider config UI** (`/admin/llm-providers`) — list providers (OpenAI / Anthropic / Gemini), per-tenant API key management (encrypted storage), per-tenant model selection, per-tenant cost ceiling, per-tenant model fallback chain.
  7. **SARIF / JUNIT API exposure** (closes 12 vs 18 reports drift) — toggle per-tenant report formats; UI checkbox для каждого формата (PDF, HTML, JSON, CSV, SARIF, JUNIT); update `POST /reports/generate-all` API contract.
  All routes guarded by `useAdminAuth` hook + RBAC role check (operator / admin / super-admin).
- **Complexity:** XL (≈ 6-8 person-days; Next.js app-router structure для 7 sub-routes + RBAC integration + ~20 React components + form validation + accessible UI; backend API surface уже частично существует, но нужно extend для bulk operations + audit-log search).
- **Dependencies:** ARG-042 (Frontend MCP integration ✅ — service layer pattern reused); ARG-041 (observability — admin actions emit Prometheus counters); existing audit-log persistence (sustained from Cycle 3).
- **Source:** Cycle 5 ARG-042 worker report «Out-of-scope: Admin Frontend XL → Cycle 6»; Cycle 5 ARG-049 plan §6 known-gap; Backlog/dev1_md §14.
- **Proposed acceptance criteria:** (a) все 7 sub-routes accessible под `/admin/*`; (b) RBAC role check enforces 3-tier hierarchy; (c) bulk operations работают для ≥100 entities at a time с pagination; (d) audit-log search возвращает результаты ≤500 ms p95; (e) all forms accessible (axe-core 0 violations); (f) Playwright E2E coverage ≥10 scenarios; (g) Vitest unit ≥30 cases.
- **Rationale:** Без Admin Frontend XL, ARGUS не может работать в multi-tenant SaaS режиме без direct DB / CLI access. Это blocking для production launch. Самая большая Cycle 6 задача (XL); рекомендуется assign senior frontend worker.

## ARG-052 — Tenant kill-switch UI (M)

- **Description:** Emergency-stop UI surface для incident response:
  1. **Per-scan kill-switch** (`/admin/scans/{id}` → "Emergency Stop" button) — `POST /admin/scans/{id}/kill` API уже существует, нужен UI button с double-confirmation (typed scan ID match) + audit emit + immediate UI state update;
  2. **Per-tenant emergency-throttle** (`/admin/tenants/{id}` → "Emergency Throttle" toggle) — temporary disable scan creation для tenant'а на N hours/days; UI countdown timer; audit emit;
  3. **Global kill-switch** (`/admin/system/emergency`) — super-admin-only; `POST /admin/system/emergency/{stop_all,resume_all}` API endpoints (NEW); stops all running scans across all tenants (incident response only); UI лог последних 10 emergency-actions с full attribution;
  4. **Audit trail viewer** для emergency actions (`/admin/audit?event_type=emergency_*`) — фильтр audit-log по emergency event types, специальный UI badge для visibility.
  RBAC enforces super-admin-only for global kill-switch; admin для per-tenant; operator для per-scan.
- **Complexity:** M (≈ 2-3 person-days; основная сложность — backend API extensions для global kill-switch + careful audit-log integration; UI relatively simple).
- **Dependencies:** ARG-051 (Admin Frontend XL — RBAC infra + audit-log viewer reuse); existing kill-switch API (sustained — `POST /admin/scans/{id}/kill`).
- **Source:** Cycle 5 ARG-049 plan §6 known-gap; ARG-047 e2e worker report (incident response gap surfaced).
- **Proposed acceptance criteria:** (a) per-scan kill stops Celery task within 5 s; (b) per-tenant throttle blocks new scans (HTTP 429); (c) global kill-switch stops all Celery tasks within 10 s; (d) audit-log records full attribution (admin user_id_hash + reason text); (e) Playwright E2E test covers all 3 levels.
- **Rationale:** Critical for SOC operator incident response. Без UI, kill-switch требует CLI access — slow MTTR в incident-response. Mid-priority Cycle 6 task.

## ARG-053 — Sigstore policy controller GA (L)

- **Description:** Production-grade admission webhook policy enforcing image-signature-required для ARGUS namespace:
  1. **Choose policy engine:** Kyverno OR OPA Gatekeeper (recommend Kyverno для simpler maintenance + native Sigstore integration через `cosign verify` rule);
  2. **Helm chart extension** — add `infra/helm/argus/templates/policy/kyverno-cluster-policy.yaml` (или `gatekeeper-constraint-template.yaml`); enforce: every image in `argus-*` namespace must (a) use immutable digest pin (regex `@sha256:[0-9a-f]{64}$`), (b) have valid Sigstore Cosign signature with Fulcio root CA, (c) have valid Rekor transparency log entry;
  3. **Defence-in-depth contract** — Helm chart cosign verify-init container (ARG-045 ✅) ловит на pod-startup; Kyverno admission policy ловит на admission (earlier — never lets pod into cluster); two layers независимо;
  4. **Test infra** — `infra/scripts/policy_test.{sh,ps1}` runs Kyverno в `kind` test cluster, attempts to deploy unsigned image, expects HTTP 403; runs in CI gate `policy-test`.
  5. **Documentation** — `docs/admission-policy.md` (NEW, ~200 LoC operator runbook).
- **Complexity:** L (≈ 4-5 person-days; Kyverno setup + policy authoring + test cluster infra + CI integration; основная сложность — policy testing в `kind` cluster).
- **Dependencies:** ARG-045 (Helm chart cosignAssertProd ✅ — defence-in-depth layer 1); ARG-033/034 (cosign keyless + GHCR push ✅).
- **Source:** Cycle 5 ARG-049 plan §6 known-gap; ARG-045 worker report «Out-of-scope: Sigstore policy controller → Cycle 6».
- **Proposed acceptance criteria:** (a) Kyverno policy YAML deployed via Helm chart (opt-in via `policy.enabled=true`); (b) attempt to deploy unsigned image → HTTP 403 from API server; (c) attempt to deploy tag-only ref → HTTP 403; (d) `kind`-based CI gate runs end-to-end; (e) operator runbook documents enable/disable flow + bypass procedure для incident response.
- **Rationale:** Defence-in-depth для supply-chain integrity. Cluster-wide admission policy предотвращает любые backdoor pod creation paths (например, raw `kubectl apply` обходящий Helm chart cosignAssertProd). Required для production deployment в regulated environments (PCI / HIPAA).

## ARG-054 — PDF/A-2u archival (S)

- **Description:** Extend ARG-048 LaTeX Phase-2 backend до PDF/A-2u standard для long-term archival compliance:
  1. **PDF/A-2u** (ISO 19005-2:2011, Unicode subset) — добавить `\\usepackage[a-2u]{pdfx}` в LaTeX preamble (всех 3 tier-aware templates); add ICC color profile (`sRGB IEC61966-2.1`); embed all fonts; remove non-PDF/A-compliant features (transparency, JavaScript, encryption);
  2. **Per-tenant config** — opt-in flag `tenant_config.reports.pdf_archival_format = "PDF/A-2u" | "PDF-1.7"` (default `PDF-1.7` для backward-compat);
  3. **Validation** — `infra/scripts/verify_pdfa.{sh,ps1}` использует `verapdf` CLI (java-based; recommend deploy в CI Docker image); verify each generated PDF против PDF/A-2u spec; CI gate `pdfa-validation`;
  4. **Frontend UI toggle** в `/admin/tenants/{id}` (под ARG-051 Admin Frontend XL) для per-tenant config;
  5. **Documentation** — extend `docs/report-service.md` с PDF/A section.
- **Complexity:** S (≈ 1-2 person-days; LaTeX preamble extension + verapdf integration; основная сложность — CI Docker image для verapdf).
- **Dependencies:** ARG-048 (LaTeX Phase-2 ✅); ARG-051 (Admin Frontend XL — per-tenant config UI).
- **Source:** Cycle 5 ARG-049 plan §6 known-gap; ARG-048 worker report «Out-of-scope: PDF/A-2u → Cycle 6».
- **Proposed acceptance criteria:** (a) per-tenant config flag works (default `PDF-1.7`, opt-in `PDF/A-2u`); (b) PDF/A-2u output passes `verapdf` validation; (c) CI gate `pdfa-validation` runs ≤30 s; (d) operator runbook documents enable/disable + spec compliance details.
- **Rationale:** Required для long-term retention in regulated environments (HIPAA 6+ years, PCI DSS 1+ year, GDPR audit trails). Quick win — small-effort, high-value compliance feature.

## ARG-055 — KEV-aware autoscaling (M)

- **Description:** Celery worker autoscaling reacting to KEV-listed-finding burst:
  1. **HPA custom metric** — Kubernetes HPA configured to scale `argus-celery-worker` replicas based on Prometheus metric `rate(argus_finding_emitted_total{kev_listed="true"}[5m])`; threshold: scale-up если rate > 1 finding/min; scale-down если rate < 0.1 finding/min;
  2. **Prometheus Adapter wiring** — `infra/helm/argus/templates/prometheus-adapter.yaml` (NEW); exposes Prometheus `argus_*` metrics в Kubernetes Custom Metrics API;
  3. **HPA YAML** — `infra/helm/argus/templates/hpa-celery-worker-kev.yaml` (NEW); `metrics: [{type: Pods, pods: {metric: {name: argus_kev_findings_per_minute}, target: {type: AverageValue, averageValue: 1}}}]`;
  4. **Test infra** — `tests/integration/autoscaling/test_kev_aware_hpa.py` (NEW, ~150 LoC); simulates KEV-finding burst через Prometheus pushgateway; asserts HPA scales up replica count в minikube/kind cluster;
  5. **Documentation** — `docs/autoscaling.md` (NEW, ~150 LoC).
- **Complexity:** M (≈ 2-3 person-days; Prometheus Adapter + HPA YAML + kind-based testing infra; основная сложность — kind/minikube cluster orchestration в CI).
- **Dependencies:** ARG-041 (Prometheus metric `argus_finding_emitted_total{kev_listed=...}` ✅); ARG-044 (KEV ingest ✅); ARG-045 (Helm chart ✅).
- **Source:** Cycle 5 ARG-049 plan §6 known-gap; ARG-041 worker report «Out-of-scope: HPA custom metric → Cycle 6»; ARG-044 worker report.
- **Proposed acceptance criteria:** (a) Prometheus Adapter exposes `argus_*` metrics в Custom Metrics API; (b) HPA scales up replicas в response to simulated KEV burst (≤60 s reaction time); (c) HPA scales down replicas after burst subsides (≤300 s cooldown); (d) integration test runs в `kind` cluster в CI; (e) operator runbook documents tuning parameters.
- **Rationale:** Critical для production scalability. Без KEV-aware autoscaling, incident-load surge (Log4shell-style mass-CVE event) will overwhelm Celery worker pool — scan throughput drops, alerting backlog grows. Mid-priority Cycle 6 task.

## ARG-056 — Scheduled scan UI (M)

- **Description:** Recurring scan scheduling UI + backend support:
  1. **Backend API** — `POST /scans/schedules` (create), `GET /scans/schedules` (list), `PATCH /scans/schedules/{id}` (update), `DELETE /scans/schedules/{id}` (delete); persistence в new Alembic migration `024_scan_schedules.py` (table `scan_schedules` с RLS preserved для tenant-scoped); Celery beat dynamically loads schedules через `redbeat` или `django-celery-beat` (recommend `redbeat` для simpler deploy);
  2. **Schedule format** — cron expression (Quartz-compatible: `0 0 2 * * ?` = daily at 02:00) + maintenance windows (operator-defined excluded date/time ranges, e.g., "no scans during 2026-12-25 to 2026-01-01"); scope reuse via `scope_id` reference;
  3. **Frontend UI** (`/admin/scans/schedules`) — табле schedules с columns (cron expression human-readable, scope, tier, mode, last run, next run); create/edit form с visual cron builder (`react-cron` library) + visual maintenance window calendar;
  4. **On-demand override** — operator может trigger scheduled scan immediately через "Run Now" button (independent of cron);
  5. **Test infra** — unit tests для cron parsing + maintenance window logic + schedule overlap detection; integration test для end-to-end schedule trigger через redbeat.
- **Complexity:** M (≈ 3-4 person-days; backend persistence + redbeat integration + frontend UI с visual cron builder; основная сложность — maintenance window logic edge cases).
- **Dependencies:** ARG-051 (Admin Frontend XL — table/form patterns reused); existing Celery beat infra (sustained).
- **Source:** Cycle 5 ARG-049 plan §6 known-gap; ARG-041 worker report «Out-of-scope: scheduled scans → Cycle 6».
- **Proposed acceptance criteria:** (a) operator can create cron-based schedule с maintenance windows; (b) schedule fires within ±60 s of cron trigger time; (c) maintenance window blocks scan creation; (d) "Run Now" button bypasses schedule; (e) Playwright E2E test covers create/edit/delete + manual trigger; (f) RLS preserved for `scan_schedules` table (tenant-scoped).
- **Rationale:** Operator convenience для regular compliance scans (e.g., weekly PCI DSS scan against production endpoints). Без scheduled scan UI, operators должны maintain external cron jobs или manual triggers — lossy и не auditable. Mid-priority Cycle 6 task.

## ARG-057 — Webhook delivery DLQ + replay UI (M)

- **Description:** Dead-letter queue для failed webhook deliveries (Slack / Linear / Jira / Slack-callback) + replay UI:
  1. **DLQ persistence** — new Alembic migration `025_webhook_dlq.py`; table `webhook_dlq_entries` (RLS preserved for tenant-scoped) with columns: `id, tenant_id, webhook_provider, event_type, payload (JSONB), failure_summary, failure_count, first_failed_at, last_failed_at, next_retry_at, status (pending|replaying|delivered|abandoned)`;
  2. **Backend API** — `GET /admin/webhook-dlq` (paginated list), `POST /admin/webhook-dlq/{id}/replay` (single replay), `POST /admin/webhook-dlq/replay-all` (bulk replay), `DELETE /admin/webhook-dlq/{id}` (abandon entry);
  3. **Failure handler** — extend ARG-035 webhook delivery infra (`src/notifications/webhook_dispatcher.py`); on max retries exceeded, persist to DLQ instead of dropping;
  4. **Frontend UI** (`/admin/webhook-dlq`) — paginated table с search/filter (provider, event_type, status, time range); per-row "Replay" and "Abandon" actions; bulk replay button с double-confirmation;
  5. **Auto-replay job** — Celery beat task daily at 06:00 UTC retries `pending` DLQ entries with exponential backoff; abandons entries older than 14 days с `status=abandoned`;
  6. **Audit log** — every replay action emits audit entry (operator user_id_hash + reason text);
  7. **Test infra** — unit tests для replay logic + abandonment policy; integration test для end-to-end DLQ flow (deliver → fail → DLQ → replay → success).
- **Complexity:** M (≈ 3-4 person-days; backend DLQ infra + frontend UI + auto-replay Celery beat task; основная сложность — exponential backoff + abandonment policy edge cases).
- **Dependencies:** ARG-035 (webhook dispatcher with retry/circuit handling ✅); ARG-051 (Admin Frontend XL — table/form patterns reused).
- **Source:** Cycle 5 ARG-049 plan §6 known-gap; ARG-035 worker report (Cycle 4) «Out-of-scope: persistent DLQ → Cycle 6»; ARG-048 worker report.
- **Proposed acceptance criteria:** (a) failed webhook delivery після N retries persists to DLQ; (b) operator can replay individual or bulk DLQ entries; (c) auto-replay Celery beat task runs daily; (d) entries older than 14 days auto-abandoned; (e) audit log records all replay actions; (f) Playwright E2E test covers DLQ flow; (g) RLS preserved for `webhook_dlq_entries` table.
- **Rationale:** Critical для notification reliability в production. Без persistent DLQ, webhook failures (e.g., Slack outage, Jira API rate limit, Linear schema migration) lead to silent notification loss — incident response degraded. Mid-priority Cycle 6 task.

---

## ARG-058 — Network-tool YAML migration (`web` → `network` для 16 dual-listed инструментов) (S, ~2d)

- **Status:** RESOLVED (Cycle 6, T03 — 2026-04-20). Content migration complete; cryptographic re-sign delegated to CI/orchestrator (worker had no private-key access).
- **Resolution summary:**
  - 16 dual-listed YAMLs (`bloodhound_python`, `crackmapexec`, `evil_winrm`, `ike_scan`, `impacket_examples`, `impacket_secretsdump`, `kerbrute`, `ldapsearch`, `mongodb_probe`, `ntlmrelayx`, `onesixtyone`, `redis_cli_probe`, `responder`, `smbclient`, `snmp_check`, `snmpwalk`) flipped from `image: "argus-kali-web:latest"` → `image: "argus-kali-network:latest"` in `backend/config/tools/`. No other YAML field touched.
  - `infra/sandbox/images/tool_to_package.json` cleaned: 16 tool_ids removed from `argus-kali-web.tools` (91 → 75); `argus-kali-network.tools` unchanged (already had all 16); `$comment` + `schema_version` (1.1.0 → 1.2.0) + `generated_by` + per-profile `purpose` strings rewritten to mark migration as complete. The pre-existing schema has no `_meta` block — the closure note lives in `$comment` / `schema_version` / `generated_by` / `purpose` instead, since adding `_meta` would have been an out-of-scope schema change.
  - `docs/tool-catalog.md` Image-coverage section regenerated by hand (script run deferred — see Re-sign note below): web row 91 → 75 (47.77%); new `argus-kali-network:latest` row at 16 (10.19%); descriptor total stays 157; built-image count stays 6. `backend/scripts/docs_tool_catalog.py` updated in lock-step so the next CI regen produces a zero-diff render.
  - **Re-sign (step 3) DEFERRED to CI/orchestrator.** Private signing keys (`backend/config/tools/_keys/dev_signing*`, `*.priv`) are `.gitignore`'d and unavailable to the worker; the YAML content edits invalidated 16 entries in `backend/config/tools/SIGNATURES`, so an authorised runner MUST execute `python -m scripts.tools_sign sign-all` before merge to satisfy `ToolRegistry` fail-closed verification + ratchet C13 (`signature-mtime-stability`).
- **Acceptance criteria status:** (a) 0 dual-listed tools ✅ (verified — `argus-kali-web.tools` has 75 entries, `argus-kali-network.tools` has 16, set intersection = ∅); (b) catalog regen idempotent ⏳ (pending CI run of `docs_tool_catalog`); (c) C16 ratchet remains green ✅ (every tool still pinned to ≥1 image profile); (d) `argus-kali-network` +16 / `argus-kali-web` -16 ✅; (e) Ed25519 re-sign ⏳ (deferred to CI as above); (f) sandbox image security contract 108 / 108 ⏳ (pending pytest run by test-runner agent).

- **Description:** ARG-048 ввёл новый sandbox image profile `argus-kali-network` (Backlog §4.17 protocol exploitation: SNMP/LDAP/SMB/IKE/impacket suite). 16 инструментов сейчас dual-listed в `infra/sandbox/images/tool_to_package.json` (`network` И `web`) — это переходное состояние, чтобы не делать risky migration в один cycle. Cycle 6 завершает миграцию:
  1. **Audit** — enumerate все 16 dual-listed tool'ов (см. `infra/sandbox/images/tool_to_package.json::_meta` + ratchet C16 inverse map).
  2. **YAML migration** — для каждого: сменить `image: argus-kali-web:latest` → `image: argus-kali-network:latest` в `backend/config/tools/<tool_id>.yaml`.
  3. **Re-sign** — `python -m scripts.tools_sign sign-all` (~16 YAMLs); freshness check через C13 (`signature-mtime-stability` ratchet).
  4. **`tool_to_package.json` cleanup** — убрать tool_id из `argus-kali-web.tools` array (оставить только в `argus-kali-network.tools`); update `_meta.cycle = ARG-058`; update `_meta.dual_listed_count = 0`.
  5. **Catalog regen** — `python -m scripts.docs_tool_catalog --out ../docs/tool-catalog.md`; idempotency verified.
  6. **C9/C16 ratchet validation** — обновить `_C16_TOOLS_NOT_PINNED` allowlist (must remain `frozenset()`); per-image coverage column в catalog updates 6 / 6.
- **Complexity:** S (≈ 1-2 person-days; mostly mechanical YAML edits + signature regeneration + catalog regen; no architecture change).
- **Dependencies:** ARG-048 (`argus-kali-network` image profile built ✅); ARG-049 (C16 ratchet ✅).
- **Source:** Cycle 5 ARG-048 worker report «Out-of-scope: dual-listed migration → Cycle 6»; ARG-049 capstone (`infra/sandbox/images/tool_to_package.json::_meta` notes).
- **Proposed acceptance criteria:** (a) 0 tool_id'а dual-listed после migration; (b) catalog regen idempotent (zero diff на second run); (c) C16 ratchet остаётся green; (d) `argus-kali-network` tool count ↑ +16, `argus-kali-web` tool count ↓ -16; (e) all 16 migrated YAMLs Ed25519-resigned; (f) sandbox image security contract test 108 / 108 sustained.
- **Rationale:** Технический долг от ARG-048; нет blocking impact на production функционал (web-image cover'ит protocol exploitation tools правильно как fallback), но cleanup улучшает image isolation invariant ("каждый tool работает в наиболее narrow возможном sandbox").

---

## Capacity for additional Cycle 6 candidates (lower-priority, opt-in)

Если Cycle 6 решит расширить scope (4-worker parallel вместо 3), кандидаты для добавления к 8 базовым задачам выше (приоритет ниже, но техническая готовность есть):

### ARG-059 — Frontend SDK auto-publish to npm (S, ~1d)

- **Description:** `Frontend/src/sdk/argus-mcp/` сейчас generated в-monorepo. Cycle 6 candidate: extract в standalone npm package `@argus/mcp-sdk` с auto-publish workflow (`.github/workflows/sdk-publish.yml`) на tag push.
- **Rationale:** Enables third-party MCP integrations без cloning ARGUS monorepo. Quick win.
- **Dependencies:** ARG-039 (SDK generation infra — already exists в Cycle 4).
- **Acceptance criteria:** (a) `@argus/mcp-sdk` published на npm (or private registry); (b) version bump on tag push; (c) backward-compat policy documented (semver major.minor.patch).

### ARG-060 — Test-suite sharding (M, ~3d)

- **Description:** Backend `pytest` сейчас sequential (~14 min full sweep). Cycle 6 candidate: shard test suite (4 workers через `pytest-xdist` или GH Actions matrix); reduce wall-time до ~4 min.
- **Rationale:** CI iteration speed (faster PR feedback). Mid-priority.
- **Dependencies:** None (independent).
- **Acceptance criteria:** (a) `pytest -n 4` (xdist) runs ≤5 min wall-time; (b) parallelism-safe (no shared state); (c) CI matrix integration.

### ARG-061 — OAST correlator Redis-streams refactor (M, ~5d)

- **Status:** **IMPLEMENTED (Cycle 6, T01 — 2026-04-21)** — MVP: `OASTRedisStreamBridge` + settings + unit tests; operator notes in [`ai_docs/develop/components/oast-correlator.md`](../components/oast-correlator.md).
- **Description:** ARG-058 candidate listed выше — promote to dedicated Cycle 6 task если capacity allows.
- **Rationale:** Production reliability (correlation state durable across restart).
- **Dependencies:** Redis cluster в production deployment (sustained from ARG-045 Helm chart).

### ARG-062 — Argus-CI-LaTeX docker image (S, ~2d)

- **Description:** ARG-048 LaTeX Phase-2 требует TeX toolchain (`xelatex` + `latexmk`). Cycle 6 candidate: build dedicated Docker image `argus-ci-latex` с pinned TeXLive 2025; use в CI gate `latex-render` для PDF parity tests.
- **Rationale:** Eliminates `requires_latex` skip в CI; full PDF parity coverage.
- **Dependencies:** ARG-048 (LaTeX Phase-2 ✅).
- **Acceptance criteria:** (a) Docker image built + pushed to GHCR; (b) CI gate `latex-render` activated; (c) all `requires_latex` tests run in CI (instead of skip).

### ARG-063 — `argus_validate.py` extension (S, ~2d)

- **Status:** **RESOLVED (Cycle 6, T08 — 2026-04-21).** Four advisory gates added (`pip_audit`, `npm_audit`, `trivy_fs`, `bandit`) plus `helm_kubeconform` in the `--only-advisory` bundle; dedicated non-blocking workflow `.github/workflows/advisory-gates.yml`; local wrappers `scripts/run_advisory_gates.{sh,ps1}`. **Kubeval** was not added — `helm_kubeconform` (T07) already validates rendered manifests against Kubernetes OpenAPI schemas; **bandit** is the fourth complementary gate. CI pins `pip-audit==2.7.3`, `bandit==1.8.6`, `trivy` v0.59.1 tarball.
- **Description:** Extend ARG-049 meta-runner с дополнительными gates: `pip-audit` (Python SCA), `npm audit` (Node SCA), `kubeconform` (Kubernetes manifest validation), `trivy fs` (container image vulnerability scan, fs-mode for build context).
- **Rationale:** Closes DoD §19.5 SCA + IaC gates без external workflow steps.
- **Dependencies:** ARG-049 (`scripts/argus_validate.py` ✅).
- **Acceptance criteria:** (a) 4 new gates registered в `_GATES`; (b) all 4 advisory (`required=False`) initially; (c) operator runbook documents promote-to-required policy.

---

## Invariants from Cycle 5 to enforce in Cycle 6 (no regression allowed)

Эти invariants унаследованы из Cycle 5 close + sustained from earlier cycles. Любая Cycle 6 задача, которая случайно draggает их вниз, будет ловиться существующими CI gates с readable error message.

### From coverage matrix (`backend/tests/test_tool_catalog_coverage.py`)

- **C1..C16 contracts sustained** — 16 × 157 = 2 512 параметризованных кейсов + 34 misc/summary/ratchet тестов = 2 546 cases. Любой regression в любом contract = CI failure.
- **C13 — `signature-mtime-stability` ratchet** — `os.utime(yaml_path, ns=(time_ns, time_ns))` keeps `verify_one(yaml_path) == True` для всех 185 signed catalog files (157 tools + 23 payloads + 5 prompts).
- **C14 — `tool-yaml-version-field-presence` ratchet** — все 157 tools имеют top-level `version: <semver>` field (regex-validated by Pydantic).
- **C15 — `tool-yaml-version-monotonic` ratchet** — `Version(current) >= Version(baseline)` per tool; `_C15_VERSION_BUMPED_NEEDS_BASELINE` allowlist must remain empty unless explicit baseline-bump PR с worker-report rationale.
- **C16 — `image-coverage-completeness` ratchet** — `len(_TOOL_TO_IMAGES[tool_id]) >= 1` per tool; `_C16_TOOLS_NOT_PINNED` allowlist must remain empty.

### From sandbox image hardening (`backend/tests/integration/sandbox/test_image_security_contract.py`)

- **6 / 6 sandbox image profiles built** — `IMAGE_PROFILES = ("web", "cloud", "browser", "full", "recon", "network")`; new image profile в Cycle 6 must extend tuple + update `EXPECTED_CYCLE_PER_PROFILE` mapping.
- **108 / 108 invariants × 6 profiles** — `runAsNonRoot=True`, `readOnlyRootFilesystem=True`, dropped capabilities, seccomp `RuntimeDefault`, no service-account token, ingress=deny, egress allowlisted, USER 65532, no SUID, SBOM CycloneDX 1.5, OCI + ARGUS labels с `argus.image.cycle=ARG-XXX`, etc.

### From observability (`backend/src/core/observability.py`)

- **9 Prometheus metric families** — `METRIC_CATALOGUE` frozen `_MetricSpec` каталог; добавление 10-й family требует explicit code review.
- **Cardinality cap 1000 per family** — `_CARDINALITY_LIMIT_PER_METRIC = 1000`; overflow → sentinel `_other` + single warning per family per process.
- **Tenant-id physical isolation** — raw `tenant_id` физически не может попасть в metrics labels / OTel span attributes / log records — только sha256-truncated `tenant_hash`.
- **OTel span attribute PII deny-list** — `safe_set_span_attribute` блокирует `tenant_id|tenantid|tenant.id|user_id|userid|user.id|authorization|cookie|x-api-key`.

### From cloud_iam ownership (`backend/src/policy/cloud_iam/_common.py`)

- **24 closed-taxonomy `CLOUD_IAM_FAILURE_REASONS`** — frozenset; new failure mode requires explicit addition + PR review.
- **`_FORBIDDEN_EXTRA_KEYS` deny-list** — `("token", "secret", "access_key", "credential", "assertion", "signed_request")` substring match (case-insensitive); audit emit отвергает any extra key matching deny-list.
- **`constant_time_str_equal` для всех чувствительных сравнений** — `hmac.compare_digest`-based; grep-verified.
- **Bounded SDK calls** — `run_with_timeout(coro, summary, timeout_s=CLOUD_SDK_TIMEOUT_S=5.0)`.
- **Sliding cache success-only** — `CLOUD_IAM_TTL_S = 600` секунд только для успехов.
- **3 NetworkPolicy YAML'а без wildcard'ов** — FQDN-pinned, ports 443/TCP + DNS only к kube-system/kube-dns.

### From threat-intel prioritizer (`backend/src/findings/`)

- **SSVC v2.1 36-leaf tree integrity** — immutable `MappingProxyType`; exhaustively параметризованный 36-leaf тест + monotonicity / surjectivity invariants.
- **`FindingPrioritizer` deterministic** — ordinal ranker `KEV → SSVC → CVSSv3 → EPSS percentile → root_cause_hash`; tie-break lexicographic.
- **EPSS rate limit 60 rpm** — `asyncio.Semaphore(60)`.
- **KEV ETag caching + air-gap short-circuit** — daily refresh; ETag spares network when unchanged.

### From Helm chart (`infra/helm/argus/templates/_helpers.tpl`)

- **`cosignAssertProd` self-protection** — chart fail'ит `helm template` в prod overlay если `cosign.verify.enabled=false`.
- **`imageRef`-with-digest-required** — chart fail'ит если digest pin — placeholder в prod overlay.
- **5 Alembic migrations sustained** — chain contiguous `017 → 023`; downgrade reversible; RLS preserved для tenant-scoped tables (`report_bundles`, `mcp_audit`, `notification_dispatch_log`).

### From hexstrike purge (`backend/tests/test_no_hexstrike_active_imports.py`)

- **0 hexstrike в active surface** — `test_no_hexstrike_active_imports.py` — 4 cases, cross-platform pure pathlib; whitelist'ит 10 immutable historical entries.
- **`EXCLUDED_PATHS` self-protected** — gates ensure whitelist не может быть accidentally обнулён.

### From Slack inbound callback (`backend/src/api/routers/mcp_slack_callbacks.py`)

- **7 Slack security gates preserved verbatim** — SLACK_SIGNING_SECRET hard-fail, headers required, body cap 16 KiB, replay window ±5 min, HMAC-SHA-256 constant-time, `block_actions`-only, action_id grammar.
- **Soft-intent contract** — Slack click never substitutes Ed25519 cryptographic approval (dual-control + crypto provenance preserved verbatim).

### From e2e capstone (`scripts/e2e_full_scan.{sh,ps1}` + `infra/docker-compose.e2e.yml`)

- **8 services pinned в e2e compose** — все image refs immutable; CI flake rate < 5 % invariant.
- **12-фазный orchestrator always-tear-down** — `tear_down` continues to run на любой failure.
- **Per-phase JSON-record без stack trace** — `summary.json::failure_detail` содержит только summary string.

### From DoD §19 meta-runner (`scripts/argus_validate.py`)

- **3 required gates green** — `ruff_capstone`, `catalog_drift`, `coverage_matrix`; new mandatory gate must be added to `_REQUIRED_GATES` list with PR review.

---

## Known limitations carry-over (deferred technical debt — ARG-058 candidates)

### T05 — Top-20 heartbeat parser mapping (RESOLVED 2026-04-21)

Twenty backlog-prioritised tools (§4.5–§4.10 cluster: discovery text, XSS JSON auxiliaries, `jsql`, SQL/NoSQL/SSTI heuristics, `arachni`) now register first-class parsers (`118` mapped / `39` heartbeat). **Methodology:** [`parsers-t05-heartbeat-batch.md`](../parsers-t05-heartbeat-batch.md#methodology).

---

Эти не оформлены как dedicated Cycle 6 tasks (бекапная категория), но требуют адресации либо в Cycle 6, либо в Cycle 7 как ARG-058+ research/refactor candidates.

1. **Mypy Windows access-violation bug.** **RESOLVED (Cycle 6, T06 — 2026-04-21).** Root-cause investigation + operational policy (CI Linux only, Windows engineers use WSL2) документированы как [`ai_docs/develop/troubleshooting/mypy-windows-access-violation.md`](../troubleshooting/mypy-windows-access-violation.md) (top-3 hypotheses with diagnostic commands; primary fix = WSL2; pure-Windows secondary workarounds — clear `.mypy_cache/`, `--no-incremental`, Defender exclusion, Win32 long-path enable) и [`ai_docs/develop/wsl2-setup.md`](../wsl2-setup.md) (full WSL2 onboarding runbook for ARGUS dev box). README.md updated с pointer to both docs. Upstream bug report deferred (low-priority Cycle 7 candidate — repro would require non-trivial isolation from this codebase). `argus_validate.py` Gate `mypy_capstone` остаётся `required=False`; no mypy/pyproject/CI config changed.
   - **Original problem statement (preserved for history):** На Windows mypy --strict иногда падает с access violation; CI Linux source-of-truth. Документировано как `requires_linux_for_mypy_strict` informal contract в `argus_validate.py` Gate `mypy_capstone` (`required=False`). Operational workaround сейчас принят, но developer convenience страдает (Windows-based engineers не могут run mypy локально). Cycle 6 / 7 candidate (ARG-058 informal): root-cause investigation (heap corruption? psutil interaction? mypyc cache?) + либо upstream bug report, либо documented operational policy (CI Linux only, Windows engineers use WSL2).
2. **12 vs 18 reports drift (SARIF/JUNIT API exposure).** **RESOLVED (Cycle 6, T04 — 2026-04-21).** Остаётся 12 форматов в `POST .../reports/generate-all` (без breaking change). Отдельные read-only эндпоинты экспорта findings: `GET /api/v1/scans/{scan_id}/findings/export?format=sarif|junit`, плюс `.../export.sarif` и `.../export.junit.xml`. Включение только при `tenants.exports_sarif_junit_enabled=true` (миграция `024`); иначе **404 Not found** без уточнения причины. Админ: `PATCH /api/v1/admin/tenants/{id}` с телом `{"exports_sarif_junit_enabled": true}`. Сериализация: существующие `generate_sarif` / `generate_junit` + `build_report_data_from_scan_findings`. Краткая схема: [`ai_docs/develop/api/findings-sarif-junit-export.md`](../api/findings-sarif-junit-export.md).
3. **OAST in-memory correlator.** **RESOLVED (Cycle 6, T01 — 2026-04-21).** `OASTRedisStreamBridge` (`backend/src/oast/redis_stream.py`) adds Redis Streams producer (`XADD` after successful ingest) + consumer group (`XREADGROUP` / `XACK`, idempotent re-ingest). Settings: `OAST_REDIS_STREAMS_ENABLED`, `OAST_STREAM_*`, reuse `redis_url` (TLS via `rediss://`). Operator doc: [`ai_docs/develop/components/oast-correlator.md`](../components/oast-correlator.md). In-process state remains the fast path; Redis is best-effort when enabled (degraded logging if unavailable).
4. **Latent cyclic policy import.** `src.policy.__init__ → src.policy.approval → ... → src.policy.preflight → src.policy.approval` цикл; ARG-043 пришлось добавить `tests/security/conftest.py` с pre-warm импортом `src.pipeline.contracts.phase_io` чтобы security-тесты collect'ились. Workaround стабилен, но root cause не fixed. **Cycle 6 / 7 candidate (ARG-058):** full refactor latent cyclic import (split `src.policy.approval` на `src.policy.approval_dto` + `src.policy.approval_service` с inverted dependency direction).
5. **OAST для Juice Shop в e2e / multi-target smoke.** Juice Shop не делает OOB-callback'и по умолчанию; ARG-047 Phase 07 OAST verification часто завершается graceful со `status='no_oast_in_scope'`. **RESOLVED (Cycle 6, T10 — 2026-04-21)** для **Playwright multi-target smoke** (без расширения полного 12-фазного `e2e_full_scan`): добавлены `infra/docker-compose.vuln-targets.yml` (профили Juice Shop / DVWA / WebGoat, pin `tag@sha256`), `Frontend/tests/e2e/vuln-targets/`, matrix workflow `.github/workflows/e2e-vuln-target-smoke.yml` (`continue-on-error` для dvwa/webgoat), документация `docs/e2e-testing.md` §11 и `infra/e2e-vuln-targets.md`. Полный capstone-скан по-прежнему только Juice Shop; честный OAST exercise на нескольких мишенях внутри `e2e_full_scan` остаётся внешним backlog-кандидатом (ARG-058+), если понадобится loop в обёртке.
6. **Sandbox SBOM auto-update on dependency bump.** **RESOLVED (Cycle 6, T09 — 2026-04-21).** Root [`renovate.json`](../../../renovate.json) configures Renovate (dockerfile manager only) for the six `sandbox/images/argus-kali-*/Dockerfile` files: weekly schedule, grouped `kalilinux/kali-rolling` PRs with digest pinning, labels `dependencies` / `supply-chain` / `sandbox` / `sbom-watch`, `docker/dockerfile` syntax image ignored. Advisory drift detection: [`infra/scripts/sbom_drift_check.py`](../../../infra/scripts/sbom_drift_check.py) + non-blocking step in [`.github/workflows/sandbox-images.yml`](../../../.github/workflows/sandbox-images.yml); optional committed baselines under `sandbox/images/sbom-baselines/<profile>.json`. Operator runbook: [`sandbox-sbom-renovate.md`](../sandbox-sbom-renovate.md) and [`ci-cd.md`](../ci-cd.md) §Sandbox Renovate + SBOM drift (T09).
   - **Original problem statement (preserved for history):** Сейчас SBOM регенерируется только при image build; если apt-get install pulls new transitive package versions, SBOM drift not detected до next CI run. **Cycle 6 candidate:** Renovate/Dependabot watcher для SBOM diff + auto-PR на drift detection.
7. **Helm chart kubeconform schema validation в CI.** **RESOLVED (Cycle 6, T07 — 2026-04-21).** A new dedicated workflow `.github/workflows/helm-validation.yml` matrix-runs kubeconform v0.6.7 (pinned, never `:latest`) against three K8s versions (`1.27.0` chart floor + `1.29.0` LTS-ish + `1.31.0` latest) × three overlays (`dev` / `staging` / `prod`) on every chart-touching PR. The validation logic lives in cross-platform helpers `infra/scripts/helm_kubeconform.{sh,ps1}` so a developer can reproduce the CI pipeline locally without GitHub round-tripping. `scripts/argus_validate.py` learns a new Gate `helm_kubeconform` registered as `required=False` (advisory) — T08 promotes it alongside the SCA / IaC batch (`pip-audit`, `npm audit`, `trivy fs`). The pre-existing `helm-lint` job in `ci.yml` (ARG-045) is left intact as the cheaper basic gate. Operator runbook + extension recipe for new CRDs documented in [`ai_docs/develop/ci-cd.md`](../ci-cd.md).
   - **Original problem statement (preserved for history):** ARG-045 `infra/scripts/helm_lint.{sh,ps1}` запускает `helm lint` + `helm template`, но не `kubeconform` (который validate'ит manifest YAMLs против Kubernetes API server schema для конкретной версии — note: `helm_lint.sh` actually invokes `kubeconform` conditionally on `command -v kubeconform`, but only against ONE Kubernetes version and only the `prod` overlay; T07 promotes that conditional best-effort run to a strict matrix-validated gate). **Cycle 6 candidate:** add `kubeconform` step в CI gate `helm-lint` для prod overlay; pin K8s version в matrix (1.29+, 1.30+, 1.31+).

---

## Top-5 risks for Cycle 6 (with mitigation)

| Risk | Likelihood | Impact | Mitigation strategy |
|---|---|---|---|
| **R1** Admin Frontend XL (ARG-051) overrun на effort estimate (XL → 2x) | medium | high (blocks Cycle 6 critical path) | Phase ARG-051 в две части: ARG-051a (tenant + scope + scan history — 3-4 days, must-have) + ARG-051b (finding triage + audit viewer + LLM provider config — 3-4 days, nice-to-have). ARG-051b может slip to Cycle 7 без блокировки production launch. |
| **R2** Kyverno/OPA policy controller (ARG-053) requires production-cluster maturity | medium | medium | Start с `kind` test cluster; defer prod cluster admission policy enable до Cycle 7 (after `kind` E2E tests stable for 2 weeks); document opt-in toggle (`policy.enabled=false` by default). |
| **R3** KEV-aware autoscaling (ARG-055) thrashing risk (rapid scale-up/down) | low | medium | Use `behavior.scaleUp.policies` + `behavior.scaleDown.policies` в HPA YAML с stabilizationWindowSeconds=300; integration test simulates burst + gradual decay. |
| **R4** Webhook DLQ (ARG-057) auto-replay storm после long outage (e.g., Jira down for 3 days) | low | medium | Apply exponential backoff (1m, 5m, 15m, 1h, 6h, 1d, 7d, abandon); rate limit DLQ replay через Redis token bucket (max 10 replays/min). |
| **R5** Scheduled scan (ARG-056) cron parsing edge cases (DST transitions, leap seconds, timezone confusion) | low | low | Use `croniter` library (battle-tested); document operator policy "all schedules в UTC"; integration tests cover DST transitions для 3 timezones. |

---

## Recommended Cycle 6 critical path (3-worker parallel)

Based on dependency graph (ARG-051 → ARG-052, ARG-051 → ARG-054, ARG-051 → ARG-056, ARG-051 → ARG-057, independent: ARG-053, ARG-055):

### Phase 1 — Admin Frontend foundation (Week 1-2)

- **Worker A:** ARG-051a — Admin Frontend XL part 1 (tenant + scope + scan history sub-routes) — **3-4 days**.
- **Worker B (parallel):** ARG-053 — Sigstore policy controller — **4-5 days** (no dependency on ARG-051).
- **Worker C (parallel):** ARG-054 — PDF/A-2u archival — **1-2 days** (small task, can finish quickly and free up Worker C для ARG-058 candidate).

### Phase 2 — Admin Frontend completion + autoscaling (Week 2-3)

- **Worker A:** ARG-051b — Admin Frontend XL part 2 (finding triage + audit viewer + LLM provider config) — **3-4 days**.
- **Worker B:** ARG-055 — KEV-aware autoscaling — **2-3 days** (depends on ARG-051b RBAC infra reuse, но minimal).
- **Worker C:** ARG-058 candidate research (mypy Windows / OAST Redis-streams / latent cyclic refactor — pick one) — **3-5 days**.

### Phase 3 — Operations UI surface (Week 3-4)

- **Worker A:** ARG-052 — Tenant kill-switch UI — **2-3 days** (depends on ARG-051a/b).
- **Worker B:** ARG-056 — Scheduled scan UI — **3-4 days** (depends on ARG-051a/b).
- **Worker C:** ARG-057 — Webhook delivery DLQ + replay UI — **3-4 days** (depends on ARG-051a/b).

### Phase 4 — Cycle 6 capstone (Week 5)

- **Worker A:** Cycle 6 capstone (ARG-059 или ARG-060 — number depends on ARG-058 result):
  - Coverage matrix expansion 16 → 18 contracts (proposed C17 — `helm-template-cosign-asserts-prod` ratchet что `helm template -f values-prod.yaml` всегда fail'ит без cosign config; C18 — `every-tool-has-network-policy-or-justified-skip` ratchet).
  - Регенерация `docs/tool-catalog.md` (sustainment).
  - Cycle 6 sign-off report (mirror ARG-040 / ARG-049 структуры; ≥800 LoC).
  - CHANGELOG rollup.
  - Cycle 7 carry-over.

**Total estimated:** XL (6-8d for ARG-051 split into a+b) + L (4-5d for ARG-053) + S (1-2d for ARG-054) + M (2-3d for ARG-055) + ARG-058 research (3-5d, variable) + M (2-3d for ARG-052) + M (3-4d for ARG-056) + M (3-4d for ARG-057) + capstone (~7d) ≈ **~32-42 person-days** estimated; параллелизация уменьшает critical-path до **~25 days wall-time** при 3-4 параллельных worker'ах. Оставляет buffer для ARG-058 unforeseen complexity.

---

## Cycle 6 entry conditions (gate from Cycle 5 sign-off)

✅ **All preconditions met as of 2026-04-21:**

- ✅ Все 9 Cycle 5 задач (ARG-041..ARG-049) Completed
- ✅ Coverage matrix 16 contracts × 157 tools = 2 512 + 34 misc = 2 546 cases (с C13 + C14 + C15 + C16)
- ✅ 6 / 6 sandbox image profiles built (no `pending`)
- ✅ Mapped sustained ≥98 (DoD §19.6 catalog coverage > 60 %) — **118 mapped (75.2 %) as of T05 (2026-04-21)**.
- ✅ Heartbeat sustained 59 — **superseded 2026-04-21 by T05 → 39 heartbeat (24.9 %)** (heartbeat-fallback C11 still inviolable for remaining tools).
- ✅ Catalog signing chain integrity (157 + 23 + 5 = 185 Ed25519-verifiable; sustained from Cycle 4 ARG-040)
- ✅ `argus_validate.py` meta-runner present (10 gates: 3 required + 7 advisory)
- ✅ Production-grade Helm chart с 4 overlays + 18 templates + 3 Bitnami sub-charts + cosignAssertProd self-protect
- ✅ Production observability stack (9 Prometheus families + 5 OTel auto-instrumentors + 4 health endpoints + structured logging)
- ✅ Production cloud_iam ownership (3 verifier'а + 24 closed-taxonomy + 3 NetworkPolicy YAML'а)
- ✅ Production threat-intel pipeline (SSVC v2.1 36-leaf + EPSS + KEV daily ingest + FindingPrioritizer)
- ✅ Production Frontend MCP integration (6-module service layer + 4-component UI + interactive `/mcp` route)
- ✅ Production e2e capstone scan (12-фазный orchestrator + 8 pinned services + nightly CI workflow + 16 pytest зеркало)
- ✅ Production Slack inbound callbacks (7 security gates + soft-intent contract)
- ✅ Production LaTeX Phase-2 reports (3 tier-aware templates + xelatex prefer + pdflatex fallback)
- ✅ 0 active hexstrike imports (permanent regression gate)
- ✅ 5 Alembic migrations 019..023 (additive-only, reversible, RLS-preserving for tenant-scoped tables)
- ✅ Frozen tool versions baseline (`backend/tests/snapshots/tool_versions_baseline.json`) + image-to-tool mapping (`infra/sandbox/images/tool_to_package.json`)
- ✅ `pytest -q` dev-default (no docker) — sustained green from Cycle 4 (11 934 PASS / 165 SKIP / 0 FAIL — Cycle 5 added ~520 new tests; full count reaches ~12 450 PASS at Cycle 5 close)

Cycle 6 готов стартовать на следующей неделе. ARG-051 (Admin Frontend XL part 1) — рекомендуемый primary первой недели; ARG-053 (Sigstore policy controller) и ARG-054 (PDF/A-2u archival) — recommended parallels.

---

## Sign-off

**Filed by:** ARG-049 worker (Cycle 5 capstone) — Cursor / Claude opus-4.7-thinking-max.
**Date:** 2026-04-21.
**Cycle 5 status:** ✅ **CLOSED** — all 9 tasks completed, 18/18 acceptance criteria met for ARG-049 capstone, coverage matrix expanded 14 → 16 без exemption'ов, production-readiness posture achieved.
**Cycle 6 status:** ✅ **PRIMED** — 7 candidate tasks (ARG-051..057) with priority/complexity/effort estimates + invariants from Cycle 5 + known limitations + top-5 risks + recommended critical path.
**Approval needed:** Cycle 6 lead (TBD assignment) for backlog acceptance + sequencing finalisation + worker pool allocation.

---

## References

- **Cycle 5 sign-off:** [`ai_docs/develop/reports/2026-04-20-argus-finalization-cycle5.md`](../reports/2026-04-20-argus-finalization-cycle5.md)
- **Cycle 5 plan:** [`ai_docs/develop/plans/2026-04-21-argus-finalization-cycle5.md`](../plans/2026-04-21-argus-finalization-cycle5.md)
- **Cycle 5 carry-over (closed):** [`ai_docs/develop/issues/ISS-cycle5-carry-over.md`](ISS-cycle5-carry-over.md) (predecessor — 7 items ARG-041..047)
- **Per-task worker reports (Cycle 5):**
  - [`2026-04-21-arg-041-observability-report.md`](../reports/2026-04-21-arg-041-observability-report.md)
  - [`2026-04-21-arg-042-frontend-mcp-integration-report.md`](../reports/2026-04-21-arg-042-frontend-mcp-integration-report.md)
  - [`2026-04-21-arg-043-cloud-iam-ownership-report.md`](../reports/2026-04-21-arg-043-cloud-iam-ownership-report.md)
  - [`2026-04-21-arg-044-epss-kev-ssvc-prioritizer-report.md`](../reports/2026-04-21-arg-044-epss-kev-ssvc-prioritizer-report.md)
  - [`2026-04-21-arg-045-helm-alembic-report.md`](../reports/2026-04-21-arg-045-helm-alembic-report.md)
  - [`2026-04-21-arg-046-hexstrike-purge-report.md`](../reports/2026-04-21-arg-046-hexstrike-purge-report.md)
  - [`2026-04-20-arg-047-e2e-capstone-juice-shop-report.md`](../reports/2026-04-20-arg-047-e2e-capstone-juice-shop-report.md)
  - [`2026-04-21-arg-048-cycle4-known-gap-closure-report.md`](../reports/2026-04-21-arg-048-cycle4-known-gap-closure-report.md)
- **Backlog (источник истины):** `Backlog/dev1_md`
- **CHANGELOG:** [`CHANGELOG.md`](../../../CHANGELOG.md) (закрытая Cycle 5 секция в шапке)

---

## Appendix A — Proposed file structure for Cycle 6 tasks

### ARG-051 — Admin Frontend XL

```
Frontend/
├── src/
│   ├── app/
│   │   └── admin/
│   │       ├── layout.tsx                    # NEW — admin chrome (sidebar + nav + RBAC guard)
│   │       ├── page.tsx                      # NEW — admin dashboard (KPIs)
│   │       ├── tenants/
│   │       │   ├── page.tsx                  # NEW — tenant list
│   │       │   └── [id]/page.tsx             # NEW — tenant detail/edit
│   │       ├── scopes/
│   │       │   ├── page.tsx                  # NEW
│   │       │   └── [id]/page.tsx             # NEW
│   │       ├── scans/
│   │       │   ├── page.tsx                  # NEW — scan history
│   │       │   ├── [id]/page.tsx             # NEW — scan detail
│   │       │   └── schedules/                # ARG-056
│   │       ├── findings/page.tsx             # NEW — global finding triage
│   │       ├── audit/page.tsx                # NEW — audit log viewer
│   │       ├── llm-providers/page.tsx        # NEW — per-tenant LLM config
│   │       ├── webhook-dlq/page.tsx          # ARG-057
│   │       └── system/
│   │           └── emergency/page.tsx        # ARG-052 — global kill-switch
│   ├── components/
│   │   └── admin/                            # NEW — admin-specific UI components (~12 files)
│   ├── hooks/
│   │   ├── useAdminAuth.ts                   # NEW — RBAC role check
│   │   └── useAdminApi.ts                    # NEW — admin API client wrapper
│   └── services/
│       └── admin/                            # NEW — admin API client (extends MCP service layer pattern)
└── tests/
    └── e2e/
        └── admin/                            # NEW — Playwright E2E for admin routes
```

### ARG-053 — Sigstore policy controller

```
infra/
├── helm/
│   └── argus/
│       └── templates/
│           └── policy/                       # NEW
│               ├── kyverno-cluster-policy.yaml
│               └── kyverno-policy-exception.yaml.example
├── scripts/
│   └── policy_test.{sh,ps1}                  # NEW — kind cluster e2e
└── kind/                                     # NEW — kind cluster config for CI
    └── argus-policy-test.yaml
docs/
└── admission-policy.md                       # NEW — operator runbook (~200 LoC)
.github/
└── workflows/
    └── policy-test.yml                       # NEW — Kyverno admission e2e in kind
```

### ARG-055 — KEV-aware autoscaling

```
infra/
└── helm/
    └── argus/
        └── templates/
            ├── prometheus-adapter.yaml       # NEW
            ├── hpa-celery-worker-kev.yaml    # NEW
            └── prometheus-adapter-config.yaml # NEW (custom-metrics rules)
backend/
└── tests/
    └── integration/
        └── autoscaling/
            ├── __init__.py                   # NEW
            └── test_kev_aware_hpa.py         # NEW — kind cluster e2e (~150 LoC)
docs/
└── autoscaling.md                            # NEW (~150 LoC)
```

### ARG-056 — Scheduled scan UI

```
backend/
├── alembic/
│   └── versions/
│       └── 024_scan_schedules.py             # NEW
├── src/
│   ├── api/
│   │   └── routers/
│   │       └── scan_schedules.py             # NEW — CRUD endpoints
│   ├── celery/
│   │   └── tasks/
│   │       └── scheduled_scan_runner.py      # NEW — redbeat handler
│   └── scheduling/
│       ├── __init__.py                       # NEW
│       ├── cron_parser.py                    # NEW — Quartz-compatible cron + maintenance windows
│       └── schedule_runner.py                # NEW
└── tests/
    ├── unit/
    │   └── scheduling/
    │       ├── test_cron_parser.py           # NEW
    │       └── test_maintenance_windows.py   # NEW
    └── integration/
        └── scheduling/
            └── test_scheduled_scan_e2e.py    # NEW
Frontend/
└── src/
    └── app/
        └── admin/
            └── scans/
                └── schedules/
                    ├── page.tsx              # NEW — schedule list
                    └── [id]/page.tsx         # NEW — schedule create/edit
```

### ARG-057 — Webhook delivery DLQ

```
backend/
├── alembic/
│   └── versions/
│       └── 025_webhook_dlq.py                # NEW
├── src/
│   ├── api/
│   │   └── routers/
│   │       └── webhook_dlq.py                # NEW — admin DLQ CRUD
│   ├── celery/
│   │   └── tasks/
│   │       └── webhook_dlq_replay.py         # NEW — daily auto-replay beat task
│   └── notifications/
│       ├── webhook_dispatcher.py             # MODIFIED — DLQ persistence on max retries
│       └── webhook_dlq_persistence.py        # NEW — repository pattern
└── tests/
    ├── unit/
    │   └── notifications/
    │       └── test_webhook_dlq_persistence.py # NEW
    └── integration/
        └── notifications/
            └── test_webhook_dlq_e2e.py       # NEW
Frontend/
└── src/
    └── app/
        └── admin/
            └── webhook-dlq/
                ├── page.tsx                  # NEW — DLQ table + filters
                └── [id]/page.tsx             # NEW — DLQ entry detail + replay
```

---

## Appendix B — API contracts proposed for Cycle 6

### ARG-051 — Admin Frontend XL (selected new endpoints)

- `GET /admin/tenants?limit=50&offset=0` → 200 `{tenants: TenantSummary[], total: int}`
- `POST /admin/tenants` → 201 `TenantDetail`
- `PATCH /admin/tenants/{id}` → 200 `TenantDetail`
- `DELETE /admin/tenants/{id}` → 204
- `GET /admin/scopes?tenant_id=...` → 200 `{scopes: ScopeSummary[]}`
- `POST /admin/scans/bulk-cancel` → 202 `{cancelled_count: int, audit_id: str}`
- `GET /admin/findings?tenant_id=&severity=&kev_listed=&ssvc_action=&offset=&limit=&q=` → 200 `{findings: FindingSummary[], total: int}`
- `POST /admin/findings/bulk-suppress` → 202 `{suppressed_count: int, audit_id: str}`
- `GET /admin/audit?event_type=&tenant_id=&q=&since=&until=&limit=&offset=` → 200 `{events: AuditEntry[], total: int, chain_integrity_ok: bool}`
- `POST /admin/audit/verify-chain?since=&until=` → 200 `{ok: bool, last_verified_index: int, drift_detected_at: str | null}`
- `GET /admin/llm-providers?tenant_id=...` → 200 `{providers: LlmProviderConfig[]}`
- `PATCH /admin/llm-providers/{id}` → 200 `LlmProviderConfig` (encrypted-at-rest API key NEVER returned in plaintext)

### ARG-052 — Tenant kill-switch UI

- `POST /admin/scans/{id}/kill` → 202 `{status: "killing", audit_id: str}` (sustained from earlier)
- `POST /admin/tenants/{id}/emergency-throttle` → 202 `{status: "throttled", until: str, audit_id: str}`
- `DELETE /admin/tenants/{id}/emergency-throttle` → 200 `{status: "throttle_removed", audit_id: str}`
- `POST /admin/system/emergency/stop-all` → 202 `{stopped_count: int, audit_id: str}` (super-admin only)
- `POST /admin/system/emergency/resume-all` → 200 `{audit_id: str}` (super-admin only)

### ARG-056 — Scheduled scan

- `POST /scans/schedules` body `{cron_expression: str, scope_id: str, tier: str, mode: str, maintenance_windows: [{start: str, end: str, recurrence: str}]}` → 201 `ScheduleDetail`
- `GET /scans/schedules?tenant_id=...` → 200 `{schedules: ScheduleSummary[], total: int}`
- `PATCH /scans/schedules/{id}` → 200 `ScheduleDetail`
- `DELETE /scans/schedules/{id}` → 204
- `POST /scans/schedules/{id}/run-now` → 202 `{scan_id: str}`

### ARG-057 — Webhook DLQ

- `GET /admin/webhook-dlq?tenant_id=&provider=&status=&since=&until=&limit=&offset=` → 200 `{entries: DlqSummary[], total: int}`
- `GET /admin/webhook-dlq/{id}` → 200 `DlqDetail` (includes redacted payload — secrets stripped)
- `POST /admin/webhook-dlq/{id}/replay` → 202 `{status: "replaying", audit_id: str}`
- `POST /admin/webhook-dlq/replay-all?provider=&max_count=` → 202 `{queued_count: int, audit_id: str}`
- `DELETE /admin/webhook-dlq/{id}` → 204 `{status: "abandoned", audit_id: str}` (audit emit)

---

## Appendix C — Database schema additions proposed for Cycle 6

### ARG-056 — Migration `024_scan_schedules.py`

```sql
CREATE TABLE scan_schedules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    cron_expression VARCHAR(255) NOT NULL,
    scope_id UUID NOT NULL REFERENCES scopes(id) ON DELETE RESTRICT,
    tier VARCHAR(32) NOT NULL CHECK (tier IN ('midgard', 'asgard', 'valhalla')),
    mode VARCHAR(32) NOT NULL CHECK (mode IN ('passive', 'active', 'intrusive')),
    maintenance_windows JSONB NOT NULL DEFAULT '[]'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by_user_id_hash VARCHAR(64) NOT NULL,
    UNIQUE (tenant_id, name)
);

ALTER TABLE scan_schedules ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON scan_schedules
    USING (tenant_id::text = current_setting('app.tenant_id', true));

CREATE INDEX idx_scan_schedules_next_run ON scan_schedules (next_run_at) WHERE enabled = TRUE;
```

### ARG-057 — Migration `025_webhook_dlq.py`

```sql
CREATE TABLE webhook_dlq_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    webhook_provider VARCHAR(32) NOT NULL CHECK (webhook_provider IN ('slack', 'linear', 'jira', 'slack_callback')),
    event_type VARCHAR(64) NOT NULL,
    payload JSONB NOT NULL,                     -- redacted at write time (no secrets)
    failure_summary VARCHAR(128) NOT NULL,      -- closed-taxonomy
    failure_count INTEGER NOT NULL DEFAULT 1,
    first_failed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_failed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    next_retry_at TIMESTAMPTZ NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'replaying', 'delivered', 'abandoned')),
    abandoned_at TIMESTAMPTZ,
    abandoned_by_user_id_hash VARCHAR(64),
    audit_chain_id UUID
);

ALTER TABLE webhook_dlq_entries ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON webhook_dlq_entries
    USING (tenant_id::text = current_setting('app.tenant_id', true));

CREATE INDEX idx_webhook_dlq_pending ON webhook_dlq_entries (next_retry_at) WHERE status = 'pending';
CREATE INDEX idx_webhook_dlq_provider ON webhook_dlq_entries (tenant_id, webhook_provider, status);
```

---

## Appendix D — Test coverage additions proposed for Cycle 6

| Task | New unit tests | New integration tests | New E2E (Playwright) | New smoke / contract |
|---|---|---|---|---|
| ARG-051 | ~60 (admin services + RBAC + form validators) | ~25 (admin API endpoints с RLS scenarios) | ~10 (per-route flows) | RBAC contract test (3-tier hierarchy enforcement) |
| ARG-052 | ~15 (kill-switch state machine) | ~8 (per-scan + per-tenant + global) | ~3 (kill-switch UI flows) | super-admin RBAC contract |
| ARG-053 | n/a | ~6 (Kyverno policy in `kind` cluster) | n/a | admission policy contract (HTTP 403 on unsigned) |
| ARG-054 | ~8 (LaTeX preamble validation) | ~4 (verapdf validation) | n/a | PDF/A-2u spec compliance contract |
| ARG-055 | ~6 (HPA scaling logic) | ~4 (kind cluster simulated burst) | n/a | autoscaling contract (scale-up SLO) |
| ARG-056 | ~25 (cron parser + maintenance windows) | ~12 (redbeat trigger e2e) | ~5 (schedule UI) | cron correctness contract |
| ARG-057 | ~20 (DLQ persistence + replay) | ~10 (DLQ flow e2e + auto-replay) | ~5 (DLQ UI) | RLS preservation contract for DLQ |

**Coverage matrix proposed expansion:** C17 — `helm-template-cosign-asserts-prod` (Helm chart prod overlay must fail without cosign config); C18 — `every-tool-has-network-policy-or-justified-skip` (each tool YAML must declare `requires_network: true` + match NetworkPolicy allow-list, or `requires_network: false` + justification field).

---

## Appendix E — Cycle 6 recommended dependency / library additions

| Dependency | Version | Purpose | Used by |
|---|---|---|---|
| `croniter` | `^2.0` | Quartz-compatible cron expression parsing | ARG-056 |
| `celery-redbeat` | `^2.2` | Dynamic Celery beat schedule (Redis-backed) | ARG-056 |
| `react-cron` | `^4.0` | Visual cron expression builder UI | ARG-056 (Frontend) |
| `react-datepicker` | `^7.0` | Maintenance window date range picker | ARG-056 (Frontend) |
| `verapdf` (system binary, JAR) | `^1.24` | PDF/A spec validation | ARG-054 (CI) |
| `kyverno` (cluster admission webhook) | `^1.13` | Kubernetes admission policy engine | ARG-053 (cluster) |
| `prometheus-adapter` (helm chart) | `^4.11` | Custom Metrics API exposure | ARG-055 (cluster) |
| `kind` (kubernetes-in-docker) | `^0.25` | CI test cluster для policy + autoscaling | ARG-053, ARG-055 (CI) |
| `axe-core` + `@axe-core/playwright` | `^4.10` | Accessibility CI gate | ARG-051 (Frontend tests) |
| `@rjsf/core` + `@rjsf/validator-ajv8` | sustained from ARG-042 | JSON-schema form rendering | ARG-051 (admin forms) |

**No high-risk additions:** все libs — Apache 2.0 / BSD-3 / MIT licenses; widely-adopted в production environments; battle-tested.

---

## Appendix F — Rollback strategy per task

Cycle 6 production-launch focused, требует careful rollback strategy для каждой задачи:

| Task | Rollback trigger | Rollback procedure | Recovery RTO |
|---|---|---|---|
| ARG-051 (Admin Frontend XL) | UI broken / RBAC bug | Disable `NEXT_PUBLIC_ADMIN_ENABLED=false` env var; rollback Frontend pod к previous digest | < 5 min |
| ARG-052 (Kill-switch UI) | False kill triggered | UI hidden by `NEXT_PUBLIC_KILL_SWITCH_ENABLED=false`; backend API still callable via curl for super-admin recovery | < 5 min |
| ARG-053 (Sigstore policy) | Legitimate deploys blocked | Helm chart `--set policy.enabled=false`; or apply `kubectl delete clusterpolicy require-cosign-signed-images` | < 2 min |
| ARG-054 (PDF/A-2u) | verapdf validation failures | Per-tenant config rollback to `pdf_archival_format=PDF-1.7` | < 1 min (config-only) |
| ARG-055 (KEV-aware HPA) | Thrashing / OOM | `kubectl delete hpa argus-celery-worker-kev`; revert to fixed replicas | < 2 min |
| ARG-056 (Scheduled scan) | Schedule misfire / loop | Disable schedule via API (`PATCH /scans/schedules/{id}` `{enabled: false}`); revoke redbeat schedule | < 2 min |
| ARG-057 (Webhook DLQ) | DLQ replay storm | `kubectl scale deployment argus-celery-worker --replicas=1`; pause `webhook_dlq_replay` Celery beat task | < 5 min |

**General principle:** every Cycle 6 task должен иметь (a) feature flag for soft-disable, (b) rollback procedure ≤5 min RTO, (c) incident-response runbook entry в `docs/incident-response.md`, (d) rollback test as part of integration suite.

---

## Appendix G — Cycle 6 success metrics (target)

| Metric | Target |
|---|---|
| Tasks completed | 7 / 7 (ARG-051..057) |
| Acceptance criteria met | ≥ 95 % (across all 7 tasks) |
| Coverage matrix size | 16 → 18 contracts (+12.5 %) |
| Total test cases | ≥ 2 800 (~+250 from Cycle 5 close) |
| Helm chart templates | 18 → ~20 (+2 — Kyverno + Prometheus Adapter) |
| Alembic migrations | 23 → 25 (+2 — `024_scan_schedules` + `025_webhook_dlq`) |
| Frontend components | ~95 → ~120 (+25 — admin UI components) |
| Frontend routes | ~12 → ~22 (+10 — admin sub-routes) |
| New CI workflows | +2 (`policy-test`, `pdfa-validation`) |
| Production-launch readiness | ✅ achieved (all admin operations have UI; supply-chain enforced cluster-wide; threat-intel autoscales) |
| Estimate accuracy | ≥ 90 % (target: ≥95 % matching Cycle 5 96 %) |
| Calendar wall-time | ≤ 5 weeks (3-4 worker parallel) |

**Cycle 6 success vector:** ARGUS transitions from "production-deployable" (Cycle 5 close) to "production-launched at scale" (Cycle 6 close) with full multi-tenant SaaS UX surface, defence-in-depth supply-chain enforcement, threat-intel-driven autoscaling, scheduled compliance scans, и durable webhook delivery.
