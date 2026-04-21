# ARGUS Finalization Cycle 5 — Plan

**Date:** 2026-04-21  
**Orchestration:** `orch-2026-04-21-argus-cycle5`  
**Status:** 🟢 Active (planning → ready to execute)  
**Predecessor (plan):** [`ai_docs/develop/plans/2026-04-19-argus-finalization-cycle4.md`](2026-04-19-argus-finalization-cycle4.md)  
**Predecessor (report):** [`ai_docs/develop/reports/2026-04-19-argus-finalization-cycle4.md`](../reports/2026-04-19-argus-finalization-cycle4.md)  
**Carry-over backlog:** [`ai_docs/develop/issues/ISS-cycle5-carry-over.md`](../issues/ISS-cycle5-carry-over.md)  
**Backlog (источник истины):** [`Backlog/dev1_.md`](../../../Backlog/dev1_.md) §6, §10, §13, §15, §16.10/§16.13/§16.16, §17, §19  

---

## 1. Cycle 4 carry-over (✅ closed — DO NOT replan)

Final state, locked from `ai_docs/develop/reports/2026-04-19-argus-finalization-cycle4.md`:

- **Tool catalog:** **157** signed YAMLs (Backlog §4 fully covered, DoD §19.6 ✅), **23** signed payloads, **5** signed prompts, **1** signed MCP manifest — все Ed25519-verifiable; backfilled `version: "1.0.0"` field на всех 157 tool YAMLs (C14 enforced).
- **Per-tool parsers:** **98 mapped (62.4 %)** / **59 heartbeat (37.6 %)** / 0 BINARY_BLOB. Цель Cycle 4 «mapped → ~98, heartbeat → ~59, DoD §19.6 catalog coverage > 60 %» — попадание ровно в цель (+30 parsers через ARG-032 batch 4).
- **Coverage matrix:** **14 контрактов × 157 tools = 2 230 параметризованных кейсов** (C1–C14, новые C13 `signature-mtime-stability` + C14 `tool-yaml-version-field-presence`); **2 230 / 2 230 PASS**.
- **ReportService:** **18 / 18** ячеек матрицы — Midgard / Asgard / **Valhalla** × {HTML, PDF, JSON, CSV, SARIF v2.1.0, JUnit XML}. Valhalla executive lens (risk quantification + OWASP rollup + business-impact ranking) wired через `tier_classifier._project_valhalla` + Pydantic `ValhallaSectionAssembly`. Branded WeasyPrint templates (Midgard / Asgard / Valhalla) + LaTeX **Phase-1** scaffold (`REPORT_PDF_BACKEND=weasyprint|latex|disabled`) + deterministic watermark (`SHA-256(tenant_id|scan_id|completed_at)[:16]`). 990 / 990 secret-leak gate cases зелёные (3 tiers × 6 formats × 55 patterns).
- **Backend MCP server:** 15 tools / 4 resources / 3 prompts стабильно; **+webhooks** (Slack / Linear / Jira за `MCP_NOTIFICATIONS_ENABLED=false` feature-flag) + **per-LLM-client token-bucket rate-limiter** (memory + redis backends, JSON-RPC error code -32029, circuit breaker threshold=5/cooldown=60s); 588 / 588 MCP суит cases. Manifest re-signed после `notifications` + `rate_limiter` секций.
- **OpenAPI 3.1 export:** `docs/mcp-server-openapi.yaml` (22 paths / 65 schemas / 68 004 bytes) + auto-generated TypeScript SDK в `Frontend/src/sdk/argus-mcp/` (75 файлов, 73 959 байт). 3 CI gates: `export_mcp_openapi --check` + `pytest test_mcp_tools_have_docstrings` + `pytest test_openapi_export_stable`.
- **Supply-chain (production):** `.github/workflows/sandbox-images.yml` — 7 jobs: hardening-contract / build-images (GHCR push) / trivy-scan (blocking CRITICAL+HIGH) / compose-smoke / **sign-images** (Cosign **keyless** через GH OIDC + Sigstore Fulcio + Rekor tlog) / **verify-images** (matrix:4 cosign verify + verify-attestation) / sign-dry-run (PR lane). 16 required status checks для merge в `main`.
- **PDF Phase-1:** `REPORT_PDF_BACKEND` env-var fallback chain `weasyprint → latex → disabled`, branded HTML+CSS templates per tier, 4 bundled fonts (Inter Regular/Bold/Italic + DejaVu fallback ~600 KB), deterministic metadata (no `/CreationDate` randomness). Phase-2 LaTeX wiring (`_latex/<tier>/main.tex.j2` через `jinja2-latex`) — **carry-over в Cycle 5** (см. ARG-048).
- **Test infrastructure:** Read-only catalog session fixture (chmod 0444 / `FILE_ATTRIBUTE_READONLY` на 188 каталог-файлов); `requires_latex` + `mutates_catalog` markers; 4 stale-import issues + 1 apktool drift issue closed; 17 ruff F401/F811 errors → 0; 11 test class collisions → 0.
- **Cycle 4 → Cycle 5 carry-over:** **7 пунктов** (ARG-041..ARG-047) задокументированы в `ai_docs/develop/issues/ISS-cycle5-carry-over.md`.

Цикл 4 закрыт **без regress'ов**: catalog signing инвариант (157 tools / 23 payloads / 5 prompts / 1 MCP manifest = 186 Ed25519-verifiable) сохранён байт-в-байт; supply-chain push live + verifiable; full backend test suite **11 934 PASS / 165 SKIP / 0 FAIL**.

---

## 2. Cycle 5 goals

Cycle 5 — это финальный production-readiness sprint перед v1.0 release. В отличие от Cycle 3 (foundations) и Cycle 4 (completion + hardening существующих поверхностей), Cycle 5 **запускает в production те поверхности, которые Cycle 4 явно отложил**: observability, real cloud authentication, deployment infra, frontend integration. После Cycle 5 ARGUS можно будет деплоить на реальный k8s-кластер с реальными tenant'ами, реальной телеметрией, реальными cloud-провайдерами и проводить full e2e demo на Juice Shop.

**Цель 1 — Production-grade observability stack (Backlog §15).** ARG-041 включает полный observability tier: OpenTelemetry traces (FastAPI + Celery + sandbox runtime + MCP server + ReportService + LLM clients), Prometheus metrics (6 counter'ов + 3 histogram'а — `argus_tool_runs_total{tool,category,status}`, `argus_findings_total{severity,category,owasp_top10}`, `argus_oast_callbacks_total{provider,payload_class}`, `argus_llm_tokens_total{provider,model,role}`, `argus_scan_duration_seconds{tier}`, `argus_report_generation_seconds{tier,format}`, `argus_rate_limit_rejections_total`, `mcp_tools_calls_total`), четыре health endpoint'а (`/health` liveness + `/ready` readiness + `/providers/health` LLM + `/queues/health` Celery/Redis), structured logging с `trace_id` / `span_id` корреляцией через `structlog` processor + OTel context propagator. Cycle 4 уже завёз scaffold (`backend/src/core/observability.py` + `backend/src/api/routers/{health,metrics}.py` с 3 базовыми метриками); ARG-041 — **завершение до production-grade**: cardinality discipline (`tool_id × tenant_id` хэшируется), OTLP exporter к Tempo / Jaeger, `traceparent` propagation через async-await boundaries, circuit-breaker state expose в `/providers/health`. После закрытия — каждый scan имеет полный trace в Tempo, каждый tool run — counter в Prometheus, каждая ошибка — корреляционный `trace_id` в Loki.

**Цель 2 — Frontend MCP integration (Backlog §14, §16.10).** ARG-042 подключает auto-generated TypeScript SDK из ARG-039 (`Frontend/src/sdk/argus-mcp/`) в Frontend pipeline. Cycle 4 SDK (75 файлов, 22 path / 65 schema) уже работает (`npx tsc --noEmit` clean), но Frontend пока не имеет MCP-страниц — `Frontend/src/services/mcp/` пустой. ARG-042 создаёт integration layer: типизированные React hooks (`useMcpTool`, `useMcpResource`, `useMcpPrompt`) поверх `@tanstack/react-query`, bearer-auth + per-tenant headers, interactive `/mcp` page (list tools → form-render input schema через `react-jsonschema-form` → invoke → render structured output), notifications widget (live SSE feed с MCP webhook events из ARG-035 — Slack/Linear/Jira deliveries отображаются realtime). Backward compatibility сохраняется через feature-flag `NEXT_PUBLIC_MCP_ENABLED=false` (default off). Базовый Playwright E2E тест на сценарий «list tools → trigger findings_list → render result».

**Цель 3 — Real cloud_iam ownership для AWS / GCP / Azure (Backlog §10).** ARG-043 заменяет `OwnershipMethod` placeholder на полноценный multi-cloud authentication слой. Расширение `OwnershipMethod` enum: `aws_sts_assume_role`, `gcp_service_account_jwt`, `azure_managed_identity`. Каждый cloud-method имеет separate verifier module (`backend/src/policy/cloud_iam/{aws,gcp,azure}.py`) поверх существующего `OwnershipVerifier` шаблона из Cycle 1. AWS: `boto3.client('sts').get_caller_identity()` + verify trust policy contains tenant_id condition; GCP: `googleapiclient.discovery.build('iamcredentials', 'v1')` JWT validation против ARGUS audience pin'а; Azure: `azure.identity.DefaultAzureCredential` + `azure.mgmt.resource.SubscriptionClient` для subscription ownership. Каждый method имеет TTL (sliding window 10 minutes), refresh через operator UI, audit log entry на каждом `OwnershipProof.verify()` call через существующий `AuditLogger`. NetworkPolicy egress allowlist для AWS STS / GCP IAM / Azure Login endpoints (не wildcard egress).

**Цель 4 — EPSS percentile + KEV catalog ingest + полная CISA SSVC v2.1 (Backlog §6).** ARG-044 завершает scaffold из Cycle 3+4. EPSS client (`backend/src/findings/epss_client.py`) уже реализован и кеширует через Redis (24h TTL); ARG-044 добавляет **periodic batch refresh** через Celery beat (`epss_batch_refresh_task` — раз в сутки fetch top-10000 CVE), persists в новую Postgres таблицу `epss_scores`. KEV catalog (CISA `known_exploited_vulnerabilities.json`) — **новая** интеграция: daily fetch через Celery beat, persists в `kev_catalog` таблицу, `FindingDTO.kev_listed: bool` + `FindingDTO.kev_added_date: date` filled at enrichment time. SSVC scaffold (`backend/src/findings/ssvc.py`) — **simplification** v2.x; ARG-044 расширяет до **полного** v2.1 4-axis decision tree (Exploitation × Automatable × Technical Impact × Mission/Well-being → 4 outcomes Track / Track\* / Attend / Act × 4 priorities Defer / Scheduled / Out-of-Cycle / Immediate); integrate в `FindingPrioritizer` (override CVSSv3-only logic). Frontend integration: SSVC badge в finding cards (4 colors per action), filter/sort by SSVC priority, expose в Valhalla executive summary (top-10 ranked by SSVC, не composite score).

**Цель 5 — Helm chart для production deployment + Alembic migrations (Backlog §16.13/§16.16/§19).** ARG-045 — самая инфраструктурно-тяжёлая задача цикла. Полный Helm chart `infra/helm/argus/` с values.yaml templating per environment (`dev / staging / prod`): три main deployment'а (`argus-backend` FastAPI + Celery worker как separate pods, `argus-frontend` Next.js SSR, `argus-mcp-server` separate pod для MCP stdio + streamable-http transports), три stateful service'а (Postgres 15 + pgvector через PVC + StatefulSet, Redis 7 Sentinel для HA, MinIO S3-compatible для evidence storage), sandbox image references pin'нутые на immutable `ghcr.io/<org>/argus-kali-{web,cloud,browser,full}@sha256:<digest>` (из ARG-034), **Cosign verify-init container** для каждого sandbox-pod (defence-in-depth: pod не стартует если signature не verifiable), Ingress + cert-manager (Let's Encrypt cert-manager.io/v1.ClusterIssuer + NGINX Ingress), Sealed Secrets / External Secrets Operator (никаких plain-text secrets в values.yaml), Prometheus ServiceMonitor + OpenTelemetry Operator integration (для ARG-041 metrics + traces). Alembic migrations (новая ветка `019..023` поверх существующих 18): `019_reports_table` (ReportBundle persistence — пока in-memory), `020_mcp_audit_table` (per-call MCP tool audit), `021_mcp_notification_dispatch_log` (webhook delivery log из ARG-035), `022_rate_limiter_state_table` (Redis fallback persistence), `023_epss_kev_tables` (если ARG-044 land'ит до этого; `epss_scores` + `kev_catalog`). Migration smoke-test: empty Postgres → upgrade head → downgrade -5 → upgrade head → schema diff = 0.

**Цель 6 — Hexstrike full purge + Cycle 4 known-gap closure (Backlog §0 cleanup discipline).** ARG-046 закрывает legacy hexstrike-references — `rg -i hexstrike` сейчас даёт ~50 hits в `docs/`, `tests/`, `ai_docs/develop/plans/` (исторические артефакты Cycle 0+1). Audit pass → categorize (a) docs comments referencing as historical context — keep with explicit «deprecated» marker, (b) tests importing hexstrike modules — delete or rewrite на native parsers, (c) production source files (`backend/src/api/routers/intelligence.py:1`, `backend/src/api/routers/scans.py:2`, `backend/src/api/routers/sandbox.py:1` — single-line legacy references) — clean up. Regression gate: `test_no_hexstrike_imports.py` проверяет `rg -c hexstrike backend/src tests/ docs/ ai_docs/develop/plans/<current-cycle>+ == 0` (исторические Cycle 1-3 plans/reports исключены из gate как immutable artifacts). Параллельно ARG-048 закрывает 3 known-gap из Cycle 4 sign-off: (a) sandbox image profiles `argus-kali-recon` + `argus-kali-network` Dockerfiles (currently MISSING — `docs/tool-catalog.md` ссылается на них как «pending»), (b) LaTeX **Phase-2** wiring `_latex/<tier>/main.tex.j2` через `jinja2-latex` для layout parity с WeasyPrint, (c) Slack interactive callbacks (`approve::<id>` / `deny::<id>` action handler — Cycle 4 ARG-035 эмитит pending-events в Slack, но не ingests'ит callback'и).

**Цель 7 — DoD §19.4 e2e capstone scan (Backlog §19.4).** ARG-047 — final integration test: `scripts/e2e_full_scan.sh http://juice-shop:3000`. Wrapper script: `docker compose -f infra/docker-compose.e2e.yml up -d` (backend + frontend + Postgres + Redis + MinIO + 4 sandbox images + OWASP Juice Shop как target), wait for health (`curl backend:8000/ready`, `curl frontend:3000/api/health`), trigger scan via `POST /scans` capturing `scan_id`, poll `GET /scans/{scan_id}` until `status="completed"` (timeout 30 min), verify все 18 reports generated (3 tier × 6 formats), verify OAST callback received (Juice Shop has known SSRF), verify cosign verify exit 0 на всех 4 image references, verify Prometheus `argus_findings_total > 0` + `argus_scan_duration_seconds_bucket{le="600"} > 0`, tear down. Full results archived as CI artifact. New GitHub Actions job `e2e-full-scan` (manual `workflow_dispatch` trigger или nightly cron на `requires_docker` runner). После закрытия — **proof что full ARGUS stack работает end-to-end** на live target с verifiable supply-chain + observability + 18 reports.

**Цель 8 — Cycle 5 capstone (sign-off + Cycle 6 priming).** ARG-049 — capstone, mirror ARG-040 / ARG-030 структуры: расширяет coverage matrix с **14 → 16** контрактов (C15 — `tool-yaml-version-monotonic` semver bumps только вверх; C16 — `image-coverage-completeness` каждый tool_id обязан быть pinned в ≥1 sandbox image), регенерирует `docs/tool-catalog.md` (с completed `argus-kali-recon` + `argus-kali-network` rows из ARG-048), пишет sign-off report Cycle 5 (`ai_docs/develop/reports/2026-04-20-argus-finalization-cycle5.md`), обновляет CHANGELOG, готовит Cycle 6 carry-over (`ISS-cycle6-carry-over.md` — Admin Frontend §14, kill-switch UI §8, advanced KEV-aware autoscaling §6, `ai_docs/develop/issues/ISS-cycle6-carry-over.md`).

**Trade-offs:** Admin Frontend (отдельная Next.js admin app per Backlog §14 — tenants / users / subscriptions / providers health / policies / audit logs / usage metering) — **defer Cycle 6** (XL scope, требует отдельного frontend track). Tenant kill-switch UI (kill-switch backend существует, UI tooling нет) — defer Cycle 6. Polный Sigstore policy controller для in-cluster admission — defer Cycle 6 (после ARG-045 Helm chart land'нет). PDF/A-2u export profile для long-term archival — defer Cycle 6.

---

## 3. Tasks (9, упорядочены по зависимостям)

### ARG-041 — Observability (OTel spans + Prometheus metrics + health endpoints)

- **Status:** ⏸ Pending
- **Backlog reference:** §15 (Reports / observability), §16.13 (DevSecOps SLI/SLO), §19 (DoD — observability requirements)
- **Priority:** HIGH
- **Complexity:** complex
- **Hours:** 12
- **Dependencies:** none — Cycle 4 ARG-035 ✅ (rate-limiter `argus_rate_limit_rejections_total`), ARG-039 ✅ (MCP `mcp_tools_calls_total`); scaffold (`backend/src/core/observability.py`, `backend/src/api/routers/{health,metrics}.py`) уже live с 3 базовыми метриками — ARG-041 расширяет до полного set'а

**Description:**  
Завершить production-grade observability stack. Cycle 4 завёз scaffold (3 counter'а + базовые `/health` + `/ready` + `/metrics`); ARG-041 расширяет до полного DoD §15 surface'а. **OpenTelemetry tracing** — instrument backend через `opentelemetry-instrumentation-{fastapi,celery,sqlalchemy,httpx,asgi}`; OTLP exporter к Tempo / Jaeger через `OTEL_EXPORTER_OTLP_ENDPOINT` env; trace propagation через `traceparent` header (incoming HTTP + outgoing httpx + Celery task headers); per-tool span `argus.sandbox.tool_run` с attributes `tool_id, tenant_id_hash, scan_id, exit_code, duration_ms, finding_count` (tenant_id хэшируется через SHA-256[:16] для cardinality discipline). **Prometheus metrics** — расширить current set (`argus_scans_total`, `argus_phase_duration_seconds`, `argus_tool_runs_total`) до полного 9-метрика surface: `argus_tool_runs_total{tool,category,status}`, `argus_findings_total{severity,category,owasp_top10}`, `argus_oast_callbacks_total{provider,payload_class}`, `argus_llm_tokens_total{provider,model,role}`, `argus_scan_duration_seconds{tier}` (histogram, buckets 10/30/60/300/600/1800/3600), `argus_report_generation_seconds{tier,format}` (histogram), `argus_rate_limit_rejections_total{client_id_hash}` (хук в ARG-035 rate-limiter), `mcp_tools_calls_total{tool,tenant_id_hash}` (хук в MCP server из ARG-039), `argus_phase_duration_seconds{phase}` (sustained from Cycle 4). **Health endpoints** — `/health` (liveness, no deps, returns version + uptime), `/ready` (readiness — sustained from Cycle 4: DB + Redis + S3 probe), `/providers/health` (NEW: LLM provider availability — OpenAI / Anthropic / Gemini circuit breaker state per-tenant; returns `{provider: {available: bool, last_error: str|null, circuit_state: "closed"|"open"|"half_open", last_success_at: ISO8601}}`), `/queues/health` (NEW: Celery queue depth via Redis BLLEN + active worker count via `celery.control.inspect().active()`). **Structured logging** — `structlog` processor `add_otel_context` injects `trace_id` / `span_id` в каждый log record; correlate logs ↔ traces через Loki ↔ Tempo. **Cardinality discipline** — `tool_id × tenant_id_hash` метрики имеют hard label whitelist; запрет `tenant_id` raw в labels (только hash); запрет cycling label values (per-call UUIDs).

**Acceptance criteria:**

- [ ] `backend/src/core/observability.py` — расширить с 3 → 9 metric definitions; добавить `register_otel_instrumentation(app: FastAPI)` функцию (instrument FastAPI + httpx + sqlalchemy + asgi); добавить `inject_otel_log_processor()` для `structlog` integration
- [ ] `backend/src/core/celery_observability.py` (new) — `register_celery_otel_signals()` хук на `task_prerun_signal` / `task_postrun_signal` / `task_failure_signal` для span lifecycle
- [ ] `backend/src/api/routers/providers_health.py` (new) — `/providers/health` endpoint, returns LLM provider circuit-breaker state (через existing `LLMClientRegistry` или CostTracker)
- [ ] `backend/src/api/routers/queues_health.py` (new) — `/queues/health` endpoint, returns Celery queue depth (BLLEN на default + per-tenant queues) + active worker count + broker reachability
- [ ] `backend/src/api/routers/health.py` — extend response с `version`, `uptime_seconds`, `git_commit_sha` (из ENV `ARGUS_GIT_SHA`)
- [ ] `backend/src/api/routers/metrics.py` — sustained from Cycle 4 (только проверить что все 9 метрик exposed, content-type `text/plain; version=0.0.4; charset=utf-8`)
- [ ] `backend/src/sandbox/runtime.py` (или эквивалент) — wrap каждый tool execution в `tracer.start_as_current_span("argus.sandbox.tool_run", attributes={...})`; emit `argus_tool_runs_total{tool,category,status}.inc()` на completion
- [ ] `backend/src/findings/normalizer.py` (или where findings созданы) — emit `argus_findings_total{severity,category,owasp_top10}.inc()` на каждом FindingDTO emit
- [ ] `backend/src/oast/correlator.py` (или где OAST callbacks обрабатываются) — emit `argus_oast_callbacks_total{provider,payload_class}.inc()`
- [ ] `backend/src/llm/cost_tracker.py` (расширить) — emit `argus_llm_tokens_total{provider,model,role}.inc()` на token usage events
- [ ] `backend/src/reports/report_service.py` — wrap `generate(...)` в `tracer.start_as_current_span("argus.report.generate", attributes={"tier": ..., "format": ...})` + emit `argus_report_generation_seconds{tier,format}.observe(duration)`
- [ ] `backend/src/mcp/runtime/rate_limiter.py` — emit `argus_rate_limit_rejections_total{client_id_hash}.inc()` на каждом rejection
- [ ] `backend/src/mcp/server.py` — emit `mcp_tools_calls_total{tool,tenant_id_hash}.inc()` на каждом tool call
- [ ] `backend/src/core/structlog_config.py` (new) — `add_otel_context_processor()` injects `trace_id` / `span_id` через `opentelemetry.trace.get_current_span().get_span_context()`
- [ ] `backend/src/api/main.py` (или где FastAPI app создан) — call `register_otel_instrumentation(app)` + register new health routers
- [ ] Unit tests — `backend/tests/unit/core/test_observability.py` (≥ 30 cases: counter increments, histogram buckets, label cardinality whitelist enforcement, OTel span attributes, structlog injection)
- [ ] Unit tests — `backend/tests/unit/api/routers/test_providers_health.py` + `test_queues_health.py` (≥ 15 cases each: degraded states, circuit open/closed/half_open, broker reachability false, schema invariants)
- [ ] Integration tests — `backend/tests/integration/observability/test_otel_trace_propagation.py` (≥ 10 cases: HTTP request → Celery task → tool run → finding emit — все spans link'нуты через одинаковый `trace_id`)
- [ ] Integration tests — `backend/tests/integration/observability/test_metrics_endpoint.py` (≥ 12 cases: scrape `/metrics` → assert 9 metric families present + label whitelist + counter monotonicity)
- [ ] Cardinality test — `backend/tests/security/test_observability_cardinality.py` (≥ 8 cases: `tenant_id` raw absent, no per-call UUID labels, max label values per metric < 1000)
- [ ] `mypy --strict` clean для всех new modules (`observability.py`, `celery_observability.py`, `providers_health.py`, `queues_health.py`, `structlog_config.py`)
- [ ] `ruff check + ruff format --check` clean для touched files
- [ ] `bandit -r src/core src/api/routers` clean для new modules
- [ ] `docs/observability.md` (new) — section `## Metrics catalog` (9 metrics × labels × type), `## Trace topology` (FastAPI → Celery → sandbox span chain), `## Health endpoints` (`/health`, `/ready`, `/providers/health`, `/queues/health` schema + curl examples), `## Local Tempo + Prometheus stack` (docker-compose snippet)
- [ ] `CHANGELOG.md` — `### Added (ARG-041 — Cycle 5: Production-grade observability)` block

**Files to create / modify:**

```
backend/src/core/observability.py                         (modify: 3 → 9 metrics + OTel instrumentation registrar)
backend/src/core/celery_observability.py                  (new)
backend/src/core/structlog_config.py                      (new)
backend/src/api/routers/providers_health.py               (new)
backend/src/api/routers/queues_health.py                  (new)
backend/src/api/routers/health.py                         (modify: extended HealthResponse)
backend/src/api/routers/metrics.py                        (sustained — verify content-type)
backend/src/api/main.py                                   (modify: register_otel_instrumentation + new routers)
backend/src/sandbox/runtime.py                            (modify: span + tool counter)
backend/src/findings/normalizer.py                        (modify: findings counter)
backend/src/oast/correlator.py                            (modify: OAST counter)
backend/src/llm/cost_tracker.py                           (modify: tokens counter)
backend/src/reports/report_service.py                     (modify: span + report histogram)
backend/src/mcp/runtime/rate_limiter.py                   (modify: rate-limit counter)
backend/src/mcp/server.py                                 (modify: MCP calls counter)
backend/tests/unit/core/test_observability.py             (new)
backend/tests/unit/api/routers/test_providers_health.py   (new)
backend/tests/unit/api/routers/test_queues_health.py      (new)
backend/tests/integration/observability/test_otel_trace_propagation.py (new)
backend/tests/integration/observability/test_metrics_endpoint.py (new)
backend/tests/security/test_observability_cardinality.py  (new)
backend/pyproject.toml                                    (modify: +opentelemetry-* deps + structlog if missing)
docs/observability.md                                     (new)
CHANGELOG.md                                              (modify: +ARG-041 entry)
```

**Workflow:** Worker → Test-writer → Test-runner → Reviewer

---

### ARG-042 — Frontend MCP integration (consume generated TS SDK + interactive UI)

- **Status:** ⏸ Pending
- **Backlog reference:** §14 (Admin Frontend — partial — MCP page), §16.10 (TS SDK consumption)
- **Priority:** MEDIUM
- **Complexity:** moderate
- **Hours:** 8
- **Dependencies:** ARG-039 ✅ (TS SDK уже в `Frontend/src/sdk/argus-mcp/` — 75 файлов, `tsc --noEmit` clean); ARG-035 ✅ (опционально для notifications widget); ARG-041 (опционально для traces correlation в Frontend)

**Description:**  
Подключить auto-generated TypeScript SDK из ARG-039 в Frontend pipeline. Cycle 4 SDK (3 services: `McpToolService`, `McpResourceService`, `McpPromptService`) уже работает через generated `OpenAPI.BASE`, но Frontend пока не имеет MCP-страниц — `Frontend/src/services/mcp/` отсутствует. ARG-042 создаёт integration layer: типизированные React hooks (`useMcpTool<TInput, TOutput>`, `useMcpResource<TUri, TContent>`, `useMcpPrompt<TName, TArgs>`) поверх `@tanstack/react-query` (queries + mutations + optimistic updates), bearer-auth integration через `OpenAPI.TOKEN` callback (читает JWT из existing auth context), per-tenant headers через `OpenAPI.HEADERS` callback. Создаёт interactive `/mcp` page в Next.js app router: list tools (через `mcp_resource_get('mcp://tools/catalog')`), форма-render input schema через `react-jsonschema-form` (или custom JSON Schema dispatcher), invoke кнопка → mutation → render structured output как pretty-printed JSON + table view для array result'ов. Notifications widget — live SSE connection к `/api/mcp/notifications/stream` (если ARG-035 эмиттит SSE; иначе polling каждые 5s) — отображает Slack / Linear / Jira webhook deliveries в realtime drawer. Backward compatibility сохраняется через feature-flag `NEXT_PUBLIC_MCP_ENABLED=false` (default off — `/mcp` page redirect'ит на `/dashboard`); existing REST-based UI **не трогается**. Базовый Playwright E2E тест — сценарий «open `/mcp` → click `findings_list` tool → fill form (filter=`severity:high`) → invoke → assert response contains array of FindingSummary objects».

**Acceptance criteria:**

- [ ] `Frontend/src/services/mcp/index.ts` (new) — re-export public API; configure `OpenAPI.BASE`, `OpenAPI.TOKEN`, `OpenAPI.HEADERS` callbacks
- [ ] `Frontend/src/services/mcp/auth.ts` (new) — bearer JWT extractor из existing auth context (read from `useAuth()` hook); per-tenant header injector (`X-Tenant-Id` from active tenant)
- [ ] `Frontend/src/services/mcp/hooks/useMcpTool.ts` (new) — typed React Query mutation hook: `useMcpTool<TInput, TOutput>(toolName: string, opts?: UseMutationOptions)`; calls `McpToolService.callTool(toolName, input)`; auto-invalidate `['mcp', 'tools']` query key on success
- [ ] `Frontend/src/services/mcp/hooks/useMcpResource.ts` (new) — typed React Query hook: `useMcpResource<TContent>(uri: string, opts?: UseQueryOptions)`
- [ ] `Frontend/src/services/mcp/hooks/useMcpPrompt.ts` (new) — typed React Query hook + auto-render через `McpPromptService.renderPrompt`
- [ ] `Frontend/src/services/mcp/hooks/useMcpNotifications.ts` (new) — SSE subscription `EventSource('/api/mcp/notifications/stream')` с auto-reconnect + polling fallback (5s interval) при SSE downgrade
- [ ] `Frontend/src/app/mcp/page.tsx` (new — Next.js app router) — page component: load tool catalog, render tool list, click → modal с input schema form (через `@rjsf/core` или custom dispatcher), invoke → render output panel
- [ ] `Frontend/src/app/mcp/layout.tsx` (new) — feature-flag guard: redirect to `/dashboard` if `NEXT_PUBLIC_MCP_ENABLED !== 'true'`
- [ ] `Frontend/src/components/mcp/ToolForm.tsx` (new) — JSON Schema → form renderer (handles primitive types + enums + arrays + nested objects)
- [ ] `Frontend/src/components/mcp/ToolOutputView.tsx` (new) — structured output renderer (pretty-printed JSON для object outputs; sortable table для array outputs; download-as-JSON button)
- [ ] `Frontend/src/components/mcp/NotificationsDrawer.tsx` (new) — drawer/sidebar, slides in from right; lists `MCPNotificationEvent[]` с severity badges + timestamp + provider icon
- [ ] `Frontend/src/components/mcp/__tests__/ToolForm.test.tsx` + `ToolOutputView.test.tsx` (new) — Vitest + React Testing Library, ≥ 20 cases each (rendering primitives, enum dropdown, required field validation, output type discrimination)
- [ ] `Frontend/tests/e2e/mcp-tool-runner.spec.ts` (new — Playwright) — E2E scenario: «open `/mcp` → list tools → click `findings_list` → fill filter → invoke → assert array result rendered»
- [ ] `Frontend/package.json` — add `@tanstack/react-query`, `@rjsf/core` (или `@rjsf/utils`), `@rjsf/validator-ajv8` if not present; sustain `argus-mcp` SDK reference
- [ ] `Frontend/src/app/layout.tsx` — wrap app в `<QueryClientProvider>` если ещё не wrapped
- [ ] `npm run build` — clean (Next.js production build succeeds)
- [ ] `npx tsc --noEmit` — clean (no TypeScript errors in new code)
- [ ] `npm run lint` — clean для new files (eslint + prettier)
- [ ] Playwright E2E test passes against running backend stack (либо mock backend через MSW)
- [ ] `Frontend/README.md` — section `## MCP integration` (feature-flag activation, available hooks, JSON Schema form recipe)
- [ ] `CHANGELOG.md` — `### Added (ARG-042 — Cycle 5: Frontend MCP integration)` block

**Files to create / modify:**

```
Frontend/src/services/mcp/index.ts                        (new)
Frontend/src/services/mcp/auth.ts                         (new)
Frontend/src/services/mcp/hooks/useMcpTool.ts             (new)
Frontend/src/services/mcp/hooks/useMcpResource.ts         (new)
Frontend/src/services/mcp/hooks/useMcpPrompt.ts           (new)
Frontend/src/services/mcp/hooks/useMcpNotifications.ts    (new)
Frontend/src/app/mcp/page.tsx                             (new)
Frontend/src/app/mcp/layout.tsx                           (new)
Frontend/src/components/mcp/ToolForm.tsx                  (new)
Frontend/src/components/mcp/ToolOutputView.tsx            (new)
Frontend/src/components/mcp/NotificationsDrawer.tsx       (new)
Frontend/src/components/mcp/__tests__/ToolForm.test.tsx   (new)
Frontend/src/components/mcp/__tests__/ToolOutputView.test.tsx (new)
Frontend/tests/e2e/mcp-tool-runner.spec.ts                (new)
Frontend/src/app/layout.tsx                               (modify: QueryClientProvider wrap if needed)
Frontend/package.json                                     (modify: deps)
Frontend/README.md                                        (modify: +MCP integration section)
CHANGELOG.md                                              (modify: +ARG-042 entry)
```

**Workflow:** Worker → Test-writer → Test-runner → Reviewer

---

### ARG-043 — Real cloud_iam ownership (AWS STS / GCP SA JWT / Azure Managed Identity)

- **Status:** ✅ Completed (2026-04-21) — worker report: [`ai_docs/develop/reports/2026-04-21-arg-043-cloud-iam-ownership-report.md`](../reports/2026-04-21-arg-043-cloud-iam-ownership-report.md)
- **Backlog reference:** §10 (cloud_iam — `OwnershipProof` для cloud accounts), §17 (testing — cross-cloud audit), §19 (DoD — multi-cloud authentication)
- **Priority:** HIGH
- **Complexity:** complex
- **Hours:** 16
- **Dependencies:** Cycle 1 `OwnershipProof` Pydantic-модель ✅ (`backend/src/policy/ownership.py`); existing `OwnershipVerifier` шаблон с DNS_TXT / HTTP_HEADER / WEBROOT methods ✅; existing `AuditLogger` ✅; cloud SDK deps (`boto3`, `google-cloud-iam`, `azure-identity`, `azure-mgmt-resource`) — добавить в `pyproject.toml`

**Description:**  
Заменить three placeholder cloud-methods на полноценный multi-cloud authentication слой. **Архитектурный подход:** не создавать отдельный `backend/src/intel/cloud_iam/` (как изначально предполагалось в `ISS-cycle5-carry-over.md`), а **расширить** существующий `OwnershipMethod` enum + `OwnershipVerifier` контракт, потому что cloud_iam — это **alternate ownership challenge method** для domains/IPs/subnets, принадлежащих cloud account. Расширение `OwnershipMethod` enum: `AWS_STS_ASSUME_ROLE = "aws_sts_assume_role"`, `GCP_SERVICE_ACCOUNT_JWT = "gcp_service_account_jwt"`, `AZURE_MANAGED_IDENTITY = "azure_managed_identity"`. Каждый cloud-method имеет separate verifier module: `backend/src/policy/cloud_iam/aws.py` (`AwsStsVerifier` — `boto3.client('sts').get_caller_identity()` + verify trust policy contains `tenant_id` external_id condition + verify role ARN matches `OwnershipChallenge.target` regex `arn:aws:iam::<account>:role/<role>`), `backend/src/policy/cloud_iam/gcp.py` (`GcpServiceAccountVerifier` — `googleapiclient.discovery.build('iamcredentials', 'v1').projects().serviceAccounts().signJwt()` для challenge JWT validation; verify audience pin'нут на `argus-prod-<tenant_id_hash>`; verify SA email matches `OwnershipChallenge.target` regex `<sa>@<project>.iam.gserviceaccount.com`), `backend/src/policy/cloud_iam/azure.py` (`AzureManagedIdentityVerifier` — `azure.identity.DefaultAzureCredential().get_token('https://management.azure.com/.default')` для challenge OAuth token; `azure.mgmt.resource.SubscriptionClient.subscriptions.get(subscription_id)` для subscription ownership verification). Каждый cloud-method TTL = 10 минут (sliding window), refresh через operator UI. Audit log entry на каждом `OwnershipProof.verify()` call через existing `AuditLogger.emit(event_type=AuditEventType.OWNERSHIP_VERIFY, ...)` — `failure_summary` использует closed taxonomy (расширить `OWNERSHIP_FAILURE_REASONS` с `cloud_aws_sts_failed`, `cloud_aws_trust_policy_invalid`, `cloud_gcp_jwt_audience_mismatch`, `cloud_gcp_sa_invalid`, `cloud_azure_oauth_invalid`, `cloud_azure_subscription_not_found`). NetworkPolicy egress allowlist для AWS STS / GCP IAM / Azure Login endpoints (whitelisted FQDNs `sts.amazonaws.com`, `iamcredentials.googleapis.com`, `login.microsoftonline.com`; **не** wildcard egress). Все cloud SDK calls — через injected client (`StsClientProtocol`, `GcpIamProtocol`, `AzureCredentialProtocol`) для testability без real cloud credentials. Audit log invariant: cloud-method failures **не** логируют raw responses (only closed-taxonomy summaries) для PII protection.

**Acceptance criteria:**

- [x] `backend/src/policy/ownership.py` — расширен `OwnershipMethod` enum (`AWS_STS_ASSUME_ROLE`, `GCP_SERVICE_ACCOUNT_JWT`, `AZURE_MANAGED_IDENTITY`); добавлены `CLOUD_IAM_FAILURE_REASONS` (11 closed-taxonomy summaries) + cross-cutting (`method_mismatch`, `challenge_expired`, `tenant_mismatch`); `OwnershipVerifier._verify_cloud` дispатчит к Protocol-injected verifier'ам c sliding-window 600s TTL cache
- [x] `backend/src/policy/cloud_iam/__init__.py` — публичный API: re-export всех трёх verifier'ов + Protocol'ов + adapter'ов + helper'ов из `_common`
- [x] `backend/src/policy/cloud_iam/aws.py` — `AwsStsVerifier(sts_client: StsClientProtocol)` + `BotoStsAdapter`; маппинг `botocore` exception'ов на closed taxonomy
- [x] `backend/src/policy/cloud_iam/gcp.py` — `GcpServiceAccountJwtVerifier(iam_client: GcpIamProtocol)` + `GoogleAuthIamAdapter`; JWT claim validation (aud/sub/exp/iat) через `google.auth`
- [x] `backend/src/policy/cloud_iam/azure.py` — `AzureManagedIdentityVerifier(credential: AzureCredentialProtocol)` + `AzureManagedIdentityAdapter`; `client_request_id` нос challenge token, JWT claims (`iss`, `tid`, `oid`, `xms_mirid`) валидируются
- [x] `backend/src/policy/cloud_iam/_common.py` — `CloudPrincipalDescriptor`, `make_proof`, `run_with_timeout` (5s SDK budget), `emit_cloud_attempt` (deny-list для `extra` payload), `redact_token`, `CLOUD_METHOD_METADATA`
- [x] `backend/pyproject.toml` — `boto3 ^1.35`, `google-auth ^2.35`, `google-cloud-iam ^2.16`, `google-api-python-client ^2.150`, `azure-identity ^1.19`, `azure-core ^1.32`, `cryptography ^43`; `requirements.txt` re-synced (`scripts/sync_requirements.py --check` clean)
- [x] Unit tests — `backend/tests/unit/policy/cloud_iam/test_aws.py` (28 cases collected) — ARN parsing (15 параметризованных), happy path, AccessDenied → `aws_sts_access_denied`, ExternalId mismatch, region routing, throttling → `aws_sts_unknown_error`, timeout → `aws_sts_timeout`, audit-log discipline, DI safety
- [x] Unit tests — `backend/tests/unit/policy/cloud_iam/test_gcp.py` (22 cases collected) — happy path, audience mismatch, subject mismatch, signature invalid, expired (clock-skew), invalid SA email regex, timeout, audit-log discipline
- [x] Unit tests — `backend/tests/unit/policy/cloud_iam/test_azure.py` (22 cases collected) — constructor validation, MI resource id parsing, happy path, mismatched `tid`/`aud`/`oid`/`xms_mirid`, missing oid, expired token, ClientAuthenticationError → `azure_token_acquisition_denied`, timeout, audit-log discipline
- [x] Unit tests — `backend/tests/unit/policy/cloud_iam/test_common.py` (32 cases collected) — `utcnow`, `constant_time_str_equal`, `hash_identifier`, `CloudPrincipalDescriptor`, `make_proof`, `run_with_timeout` (timeout reads `CLOUD_SDK_TIMEOUT_S` at call time для monkeypatch), `emit_cloud_attempt` (extra-payload deny-list), `redact_token`, `metadata_for`
- [x] Integration tests — `backend/tests/integration/policy/test_cloud_iam_ownership.py` (15 cases collected, все 15 deselected без `-m ""` из-за `requires_docker` marker, наследуемого от родительского policy `conftest.py`; runs cleanly с `-m ""`) — `OwnershipVerifier` constructor валидирует cloud-only mapping, dispatch, TTL caching (success-only, per `(tenant_id, method, target)`), audit log `cache_hit=True/False`, expired challenge / method mismatch без вызова cloud verifier
- [x] Security tests — `backend/tests/security/test_cloud_iam_no_secret_leak.py` (37 cases collected) — closed taxonomy invariants, no-secret-leak proof per provider, `emit_cloud_attempt` extra deny-list, `constant_time_str_equal` usage grep, `redact_token` length-leak guard, NetworkPolicy invariants (no wildcards, label selector present, ports 443/53 only, DNS only к kube-dns), TTL/timeout constants frozen, Protocol conformance, no event-loop pollution
- [x] NetworkPolicy egress allowlist — `infra/k8s/networkpolicies/cloud-aws.yaml` (sts/iam IP ranges + DNS + IMDS deny), `cloud-gcp.yaml` (iamcredentials/oauth2/www.googleapis.com IP ranges), `cloud-azure.yaml` (login.microsoftonline.com / management.azure.com IP ranges); все 3 YAML'а pin'ят `app: argus-backend AND cloud-iam: enabled` podSelector + ports `443/TCP` + `53/UDP+TCP` к `kube-system/kube-dns` only
- [x] `mypy --strict` clean — `python -m mypy --strict --follow-imports=silent src/policy/cloud_iam/` → `Success: no issues found in 5 source files` (cloud SDK lazy-imports помечены `# type: ignore[import-untyped|import-not-found]` на верхнем уровне `from ... import` — комментарий на правильной строке для mypy)
- [x] `ruff check` clean для touched files — `python -m ruff check src/policy/cloud_iam/ src/policy/ownership.py tests/unit/policy/cloud_iam/ tests/integration/policy/test_cloud_iam_ownership.py tests/security/test_cloud_iam_no_secret_leak.py` → `All checks passed!`
- [x] `pytest -m ""` для cloud_iam suite → **156/156 PASS за 5.10s** (28 + 22 + 22 + 32 + 15 + 37)
- [x] `docs/cloud-iam-ownership.md` (~410 LoC) — architecture (layering + lifecycle), per-cloud setup (AWS STS / GCP SA JWT / Azure MI), failure-reason table, NetworkPolicy invariants, audit-log schema, operator runbook, 7 security guarantees, "adding a new cloud verifier" sketch
- [x] `CHANGELOG.md` — `### Added (ARG-043 — Real cloud_iam ownership: AWS STS AssumeRole + GCP Service Account JWT + Azure Managed Identity verifiers, closed-taxonomy failure model, sliding 600 s proof cache, NetworkPolicy egress allowlists, 2026-04-21)` — присутствует на L62-125 + Metrics block

**Files to create / modify:**

```
backend/src/policy/ownership.py                           (modify: enum + reasons + verify branches)
backend/src/policy/cloud_iam/__init__.py                  (new)
backend/src/policy/cloud_iam/aws.py                       (new)
backend/src/policy/cloud_iam/gcp.py                       (new)
backend/src/policy/cloud_iam/azure.py                     (new)
backend/src/policy/cloud_iam/_common.py                   (new)
backend/pyproject.toml                                    (modify: +cloud SDK deps)
backend/tests/unit/policy/cloud_iam/__init__.py           (new)
backend/tests/unit/policy/cloud_iam/test_aws.py           (new)
backend/tests/unit/policy/cloud_iam/test_gcp.py           (new)
backend/tests/unit/policy/cloud_iam/test_azure.py         (new)
backend/tests/integration/policy/test_cloud_iam_ownership.py (new)
backend/tests/security/test_cloud_iam_no_secret_leak.py   (new)
infra/k8s/networkpolicies/cloud-aws.yaml                  (modify or new: egress allowlist)
infra/k8s/networkpolicies/cloud-gcp.yaml                  (modify or new)
infra/k8s/networkpolicies/cloud-azure.yaml                (modify or new)
docs/cloud-iam-ownership.md                               (new)
CHANGELOG.md                                              (modify: +ARG-043 entry)
```

**Workflow:** Worker → Test-writer → Security-auditor (cloud credential leak gates!) → Test-runner → Reviewer

---

### ARG-044 — EPSS percentile + KEV catalog ingest + полный CISA SSVC v2.1

- **Status:** ✅ Completed (2026-04-21)
- **Worker report:** [`ai_docs/develop/reports/2026-04-21-arg-044-epss-kev-ssvc-prioritizer-report.md`](../reports/2026-04-21-arg-044-epss-kev-ssvc-prioritizer-report.md)
- **Backlog reference:** §6 (intel — EPSS / KEV / SSVC), §11 (FindingDTO `epss_score`, `kev_listed`, `ssvc_decision`), §15 (Valhalla executive summary — top-10 ranked by SSVC), §17 (testing — formal SSVC tree)
- **Priority:** HIGH
- **Complexity:** complex
- **Hours:** 12
- **Dependencies:** Cycle 1 `FindingDTO` ✅; Cycle 3 EPSS scaffold (`backend/src/findings/epss_client.py`) ✅; Cycle 3+4 SSVC scaffold (`backend/src/findings/ssvc.py`) ✅; ARG-031 Valhalla executive summary ✅ (для SSVC integration); ARG-045 Alembic migrations (для `epss_scores` + `kev_catalog` tables — может land параллельно через separate migration `023_epss_kev_tables`)

**Description:**  
Завершить EPSS + KEV + SSVC scaffold из Cycle 3+4. EPSS client (`backend/src/findings/epss_client.py`) уже реализован: per-CVE lookup с Redis 24h TTL caching через injected `HttpClientProtocol` + `RedisLike`. ARG-044 добавляет (1) **periodic batch refresh** через Celery beat — `epss_batch_refresh_task` (раз в сутки, 04:00 UTC) batch-fetches top-10000 CVE из FIRST.org `/data/v1/epss?envelope=true&pretty=false&limit=10000&offset=<batch>`, persists в новую Postgres таблицу `epss_scores` (`cve_id, score, percentile, last_updated, fetched_at`); (2) **KEV catalog ingest** — `kev_catalog_refresh_task` (раз в сутки, 05:00 UTC) fetches CISA `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (single batch), persists в `kev_catalog` таблицу (`cve_id, vendor_project, product, vulnerability_name, date_added, short_description, required_action, due_date, known_ransomware_use, notes`); (3) **enrichment integration** — `FindingNormalizer` (или `FindingEnricher` если нужно создать) в `backend/src/findings/normalizer.py` — fill `FindingDTO.epss_score` (Decimal 0..1) + `FindingDTO.epss_percentile` (Decimal 0..100) + `FindingDTO.kev_listed` (bool) + `FindingDTO.kev_added_date` (date | None) + `FindingDTO.ssvc_decision` (SSVCDecision | None) на каждом FindingDTO emit (если CVE_id присутствует); (4) **полный SSVC v2.1** — расширить current `backend/src/findings/ssvc.py` simplification до полного CISA tree v2.1 (currently 5×3×2×2×3 = 180 leaf simplification → full tree 5×3×2×2×4 = 240 leaf с output mapping {ACT, ATTEND, TRACK_STAR, TRACK} × {Defer, Scheduled, Out-of-Cycle, Immediate}); reference: https://www.cisa.gov/sites/default/files/2023-11/SSVC_Decision_Tree_v2.1.pdf; (5) **`FindingPrioritizer`** — `backend/src/findings/prioritizer.py` (new или extend existing) — composite ranking: KEV-listed → top, then SSVC `ACT` → SSVC `ATTEND` → CVSSv3 desc, then EPSS percentile desc для tie-break; expose `prioritize(findings: list[FindingDTO]) → list[FindingDTO]`; (6) **Valhalla integration** — `ValhallaSectionAssembly.top_findings_by_business_impact` — replace current `(severity × exploitability × business_value)` formula с `prioritize(...)` call (KEV-aware ranking); (7) **Frontend integration** — SSVC badge component (`Frontend/src/components/findings/SsvcBadge.tsx` — 4 colors per outcome) + filter/sort by SSVC priority (`Frontend/src/components/findings/FindingFilters.tsx` modification).

**Acceptance criteria:**

- [x] `backend/src/findings/epss_client.py` — sustained from Cycle 4; добавить `async batch_get(cve_ids: list[str], chunk_size: int = 100) → dict[str, EpssScore]` для bulk lookup
- [x] `backend/src/findings/epss_persistence.py` (new) — `class EpssScoreRepository` (Postgres CRUD: `upsert_batch(scores)`, `get(cve_id) → EpssScore | None`, `get_many`, `get_stale_after(age: timedelta) → list[str]`, `count`)
- [x] `backend/src/findings/kev_client.py` (new) — `class KevClient` + `async fetch_kev_catalog() → list[KevEntry] | None`; injected `HttpClientProtocol`; ETag caching + airgap fallback
- [x] `backend/src/findings/kev_persistence.py` (new) — `class KevCatalogRepository` (Postgres CRUD: `upsert_batch(entries)`, `get(cve_id)`, `is_listed`, `get_listed_set`, `count() → int`)
- [x] `backend/src/celery/tasks/intel_refresh.py` (new) — Celery beat tasks `epss_batch_refresh_task` (04:00 UTC daily) + `kev_catalog_refresh_task` (05:00 UTC daily); both use distributed lock (Redis SET NX EX) для prevent concurrent refresh; rate-limited (FIRST.org API 60 req/min limit respected)
- [x] `backend/src/findings/ssvc.py` — расширить с current simplified branch до полного CISA v2.1 4-axis tree (Exploitation × Automatable × Technical Impact × Mission/Well-being → 36 leaves × 4 outcomes); preserve backward-compat (current `ssvc_decide(...)` signature stable)
- [x] `backend/src/findings/prioritizer.py` (new или modify) — `class FindingPrioritizer` + `rank_findings(findings) → list[FindingDTO]` (KEV-listed → SSVC outcome → CVSSv3 → EPSS percentile → root_cause_hash) + `top_n` + `rank_objects` (duck-typed для API schema)
- [x] `backend/src/findings/normalizer.py` (modify) — `FindingNormalizer` integrates with `FindingEnricher`; populates `FindingDTO.epss_score`, `epss_percentile`, `kev_listed`, `kev_added_date`, `ssvc_decision`; gracefully degrades если CVE_id отсутствует
- [x] `backend/src/pipeline/contracts/finding_dto.py` — verify all 5 fields exist (`epss_score`, `epss_percentile`, `kev_listed`, `kev_added_date`, `ssvc_decision`); add if missing
- [x] `backend/src/reports/valhalla_tier_renderer.py` — `assemble_valhalla_sections(...)` calls `FindingPrioritizer.rank_objects(...)` для `top_findings_by_business_impact` field + new `KEV-listed findings` section
- [x] Unit tests — `backend/tests/unit/findings/test_epss_persistence.py` (15 cases: upsert, get, get_many, stale lookup, schema invariants, batch insert determinism)
- [x] Unit tests — `backend/tests/unit/findings/test_kev_client.py` + `test_kev_persistence.py` (~25 + 15 = 40 cases combined: fetch happy path, ETag caching, airgap fallback, malformed JSON, ransomware-use flag)
- [x] Unit tests — `backend/tests/unit/findings/test_ssvc.py` (62 cases — параметризованных по всем 36 leaves + monotonicity + surjectivity + `derive_ssvc_inputs` projection)
- [x] Unit tests — `backend/tests/unit/findings/test_prioritizer.py` (48 cases: KEV-first ordering, SSVC ACT > ATTEND, CVSSv3 tie-break, EPSS tie-break, empty list, all-equal findings, `rank_objects` duck-typed)
- [x] Unit tests — `backend/tests/unit/celery/tasks/test_intel_refresh.py` (17 cases: distributed lock, airgap, rate-limit respect, partial batch failure recovery, idempotent re-run)
- [x] Integration tests — `backend/tests/integration/findings/test_enrichment_pipeline_with_epss_kev_ssvc.py` (11 cases: end-to-end FindingDTO → enriched FindingDTO; in-memory SQLite repos; SSVC integration; Valhalla top-N ordering verified)
- [x] Frontend — `Frontend/src/components/findings/SsvcBadge.tsx` (new): props `{decision: SsvcDecision}`; 4 colors per outcome (Track=slate, Track\*=blue, Attend=orange, Act=red); accessible `role="status"` + `aria-label`
- [x] Frontend — `Frontend/src/components/findings/SsvcBadge.test.tsx` (new) — Vitest, 7 cases (rendering all 4 decisions, color distinctness, accessibility, fallback)
- [x] Frontend — `Frontend/src/components/findings/FindingFilters.tsx` (modify) — add SSVC outcome multi-select filter + KEV-only toggle; bonus: `Frontend/src/components/findings/FindingFilters.test.tsx` (new, 17 cases)
- [⚠] `mypy --strict` clean для всех new modules (`epss_persistence.py`, `kev_*.py`, `prioritizer.py`, `intel_refresh.py`, full `ssvc.py`) — Windows mypy 1.20.1 hits STATUS_ACCESS_VIOLATION crash на sqlalchemy stubs (см. worker report §6); `ssvc.py` clean independently; кодовые ошибки типизации (14) исправлены прямой типизацией
- [x] `ruff check + ruff format --check` clean для touched files
- [x] `docs/intel-prioritization.md` (new) — 304 LoC: high-level architecture diagram, persistence layer, daily refresh, SSVC v2.1 (full 36 leaves), `FindingPrioritizer` ordering, `FindingEnricher`, Valhalla integration, Frontend, API schema additions, DB schema, operations (air-gap seeding, health checks), test coverage matrix
- [x] `CHANGELOG.md` — `### Added (ARG-044 — EPSS percentile + KEV catalog ingest + full CISA SSVC v2.1 + FindingPrioritizer)` block (existing, line 191)

**Files to create / modify:**

```
backend/src/findings/epss_client.py                       (modify: +batch_get)
backend/src/findings/epss_persistence.py                  (new)
backend/src/findings/kev_client.py                        (new)
backend/src/findings/kev_persistence.py                   (new)
backend/src/findings/ssvc.py                              (modify: simplification → full v2.1)
backend/src/findings/prioritizer.py                       (new or modify)
backend/src/findings/normalizer.py                        (modify: +EPSS/KEV/SSVC enrichment)
backend/src/celery/tasks/intel_refresh.py                 (new)
backend/src/pipeline/contracts/finding_dto.py             (verify fields)
backend/src/reports/valhalla_tier_renderer.py             (modify: prioritizer integration)
backend/tests/unit/findings/test_epss_persistence.py      (new)
backend/tests/unit/findings/test_kev_client.py            (new)
backend/tests/unit/findings/test_kev_persistence.py       (new)
backend/tests/unit/findings/test_ssvc_full.py             (new)
backend/tests/unit/findings/test_prioritizer.py           (new)
backend/tests/unit/celery/tasks/test_intel_refresh.py     (new)
backend/tests/integration/findings/test_enrichment_pipeline_with_epss_kev_ssvc.py (new)
Frontend/src/components/findings/SsvcBadge.tsx            (new)
Frontend/src/components/findings/SsvcBadge.test.tsx       (new)
Frontend/src/components/findings/FindingFilters.tsx       (modify)
docs/intel-prioritization.md                              (new)
CHANGELOG.md                                              (modify: +ARG-044 entry)
```

**Workflow:** Worker → Test-writer → Test-runner → Reviewer

---

### ARG-045 — Helm chart для production deployment + Alembic migrations

- **Status:** ⏸ Pending
- **Backlog reference:** §16.13 (DevSecOps — production deployment), §16.16 (Alembic migrations strategy), §19 (DoD — Helm + migrations smoke test)
- **Priority:** HIGH
- **Complexity:** complex
- **Hours:** 16
- **Dependencies:** ARG-033 ✅ (cosign verify — для sandbox-pod init container); ARG-034 ✅ (GHCR images — для immutable refs); все Cycle 1-4 deployment infra; ARG-041 (для Prometheus ServiceMonitor + OTel Operator integration — может land параллельно)

**Description:**  
Полный production-ready Helm chart `infra/helm/argus/` + Alembic migrations для new tables. **Helm chart structure:** `Chart.yaml` (apiVersion v2, type application, version 0.1.0), `values.yaml` (default values), `values-dev.yaml` / `values-staging.yaml` / `values-prod.yaml` (environment-specific overrides), `templates/_helpers.tpl` (named templates: `argus.fullname`, `argus.labels`, `argus.serviceAccountName`, `argus.image.<component>`), three main `Deployment`s (`backend.yaml` — FastAPI app, `celery-worker.yaml` — separate Deployment, `frontend.yaml` — Next.js SSR, `mcp-server.yaml` — separate pod для MCP), three `StatefulSet`s (`postgres.yaml` — Postgres 15 + pgvector через `bitnami/postgresql` chart dep или custom StatefulSet с PVC, `redis.yaml` — Redis 7 Sentinel HA через `bitnami/redis` или custom, `minio.yaml` — MinIO S3-compatible через `bitnami/minio` или custom). **Sandbox image references** — `values.yaml::sandbox.images` pin'нут на immutable digest `ghcr.io/<org>/argus-kali-{web,cloud,browser,full,recon,network}@sha256:<digest>` (digests читаются из ARG-034 latest CI run артефакта или manually pinned). **Cosign verify-init container** для каждого sandbox-pod: `initContainers: [- name: verify-image, image: ghcr.io/sigstore/cosign/cosign:v2.4, command: [cosign, verify, --certificate-identity-regexp, ..., --certificate-oidc-issuer, https://token.actions.githubusercontent.com, "{{ .Values.sandbox.images.web }}"], env: [- name: COSIGN_EXPERIMENTAL, value: "1"]]` (defence-in-depth: pod не стартует если signature не verifiable). **Ingress + cert-manager:** `Ingress` resource (NGINX class или Traefik), TLS via `cert-manager.io/v1.ClusterIssuer` annotation, host `argus.<domain>` + `mcp.<domain>` + `frontend.<domain>`. **Secrets management:** Sealed Secrets (Bitnami `bitnami-labs/sealed-secrets`) или External Secrets Operator (Vault / AWS Secrets Manager / GCP Secret Manager); никаких plain-text secrets в `values.yaml` — only references к sealed/external. **Observability integration:** ServiceMonitor для Prometheus Operator (scrape `/metrics` каждые 30s); PodMonitor для Celery worker pods; OpenTelemetry Operator `Instrumentation` CR для auto-instrumentation. **NetworkPolicies:** sustained from Cycle 3 (11 templates), Helm chart применяет relevant ones к каждому Deployment. **HPA** (`autoscaling/v2.HorizontalPodAutoscaler`): backend + Celery worker scale 1..10 by CPU + MEM + custom metric `argus_scan_duration_seconds_p95`. **Alembic migrations** (новая ветка поверх existing 18): `019_reports_table.py` (id PK, scan_id FK, tenant_id, tier, format, sha256, content_path в S3, generated_at, retention_until), `020_mcp_audit_table.py` (id PK, tenant_id, tool_name, args_hash, response_hash, duration_ms, status, called_at), `021_mcp_notification_dispatch_log.py` (id PK, tenant_id, event_type, target_provider, target_id, payload_hash, status, dispatched_at, retry_count), `022_rate_limiter_state_table.py` (client_id PK, tenant_id, bucket_tokens, last_refill_at, circuit_state, circuit_open_until), `023_epss_kev_tables.py` (epss_scores: cve_id PK, score, percentile, fetched_at; kev_catalog: cve_id PK, vendor_project, product, ..., date_added). **Migration smoke-test:** new `infra/scripts/migrate_smoke.sh` — `docker run postgres:15 → argus-backend alembic upgrade head → alembic downgrade -5 → alembic upgrade head → schema diff = 0`.

**Acceptance criteria:**

- [ ] `infra/helm/argus/Chart.yaml` (new) — apiVersion v2, type application, version 0.1.0, appVersion 1.0.0, description, dependencies (`bitnami/postgresql ^16`, `bitnami/redis ^20`, `bitnami/minio ^14`)
- [ ] `infra/helm/argus/values.yaml` (new) — default values: `image.repository`, `image.tag`, `replicaCount`, `service.port`, `ingress.enabled`, `resources.{requests,limits}`, `sandbox.images.{web,cloud,browser,full,recon,network}` (pinned digests), `cosign.verify.enabled=true`, `cosign.verify.identityRegexp`, `serviceMonitor.enabled=true`, `otel.enabled=true`, `otel.endpoint`
- [ ] `infra/helm/argus/values-dev.yaml` (new) — dev overrides: `replicaCount=1`, `ingress.enabled=false`, `cosign.verify.enabled=false`, `postgres.persistence.enabled=false`
- [ ] `infra/helm/argus/values-staging.yaml` (new) — staging overrides: `replicaCount=2`, `ingress.host=argus.staging.<domain>`, `cosign.verify.enabled=true`, `autoscaling.enabled=false`
- [ ] `infra/helm/argus/values-prod.yaml` (new) — prod overrides: `replicaCount=3`, `ingress.host=argus.<domain>`, `cosign.verify.enabled=true`, `autoscaling.{enabled=true,minReplicas=3,maxReplicas=10}`, `resources.requests.{cpu=2000m,memory=4Gi}`
- [ ] `infra/helm/argus/templates/_helpers.tpl` (new) — named templates `argus.fullname`, `argus.labels`, `argus.selectorLabels`, `argus.serviceAccountName`, `argus.image.backend`, `argus.image.frontend`, `argus.image.mcp`
- [ ] `infra/helm/argus/templates/backend-deployment.yaml` (new) — Deployment `argus-backend` (FastAPI), Cosign verify-init container per pod, OTel auto-instrumentation env vars
- [ ] `infra/helm/argus/templates/celery-worker-deployment.yaml` (new) — Deployment `argus-celery-worker`, Celery beat sidecar или отдельный CronJob
- [ ] `infra/helm/argus/templates/frontend-deployment.yaml` (new) — Deployment `argus-frontend` (Next.js SSR)
- [ ] `infra/helm/argus/templates/mcp-server-deployment.yaml` (new) — Deployment `argus-mcp-server` (separate pod для MCP transports)
- [ ] `infra/helm/argus/templates/postgres-statefulset.yaml` (new или sub-chart wire) — Postgres 15 + pgvector через PVC + StatefulSet
- [ ] `infra/helm/argus/templates/redis-statefulset.yaml` (new или sub-chart wire) — Redis 7 Sentinel HA
- [ ] `infra/helm/argus/templates/minio-statefulset.yaml` (new или sub-chart wire) — MinIO S3-compatible
- [ ] `infra/helm/argus/templates/services.yaml` (new) — ClusterIP Services для каждого Deployment + StatefulSet
- [ ] `infra/helm/argus/templates/ingress.yaml` (new) — Ingress + cert-manager.io/v1.ClusterIssuer annotation
- [ ] `infra/helm/argus/templates/networkpolicies.yaml` (new) — applies relevant из Cycle 3 templates
- [ ] `infra/helm/argus/templates/servicemonitor.yaml` (new) — Prometheus Operator ServiceMonitor + PodMonitor
- [ ] `infra/helm/argus/templates/otel-instrumentation.yaml` (new) — OpenTelemetry Operator Instrumentation CR
- [ ] `infra/helm/argus/templates/hpa.yaml` (new) — HorizontalPodAutoscaler v2 для backend + celery-worker
- [ ] `infra/helm/argus/templates/sealedsecrets.yaml.example` (new) — example для operator (sealed secrets) — НЕ commit'ить актуальные secrets
- [ ] `backend/alembic/versions/019_reports_table.py` (new) — `op.create_table('reports', ...)` + RLS policy + downgrade
- [ ] `backend/alembic/versions/020_mcp_audit_table.py` (new)
- [ ] `backend/alembic/versions/021_mcp_notification_dispatch_log.py` (new)
- [ ] `backend/alembic/versions/022_rate_limiter_state_table.py` (new)
- [ ] `backend/alembic/versions/023_epss_kev_tables.py` (new — два table в одной migration)
- [ ] `infra/scripts/migrate_smoke.sh` (new) — `docker run postgres:15 → alembic upgrade head → downgrade -5 → upgrade head → assert schema diff == 0`
- [ ] `infra/scripts/helm_lint.sh` (new) — `helm lint infra/helm/argus -f infra/helm/argus/values-{dev,staging,prod}.yaml`
- [ ] Tests — `backend/tests/integration/migrations/test_alembic_smoke.py` (≥ 8 cases: upgrade head, downgrade всех new migrations one by one, schema diff invariants, RLS policies preserved, FK constraints preserved)
- [ ] Tests — `infra/helm/argus/tests/helm_template_render_test.go` (или `tests/helm_template.bats` через `helm template -f values-prod.yaml | kubectl apply --dry-run=client`) — assert все 12+ resources render без errors на каждой values файле
- [ ] CI gate — `.github/workflows/ci.yml` job `helm-lint` — runs `helm lint` + `kubectl apply --dry-run` per environment values
- [ ] CI gate — `.github/workflows/ci.yml` job `migrations-smoke` — runs `infra/scripts/migrate_smoke.sh` per push to migration files
- [ ] `docs/deployment-helm.md` (new) — section `## Quickstart` (`helm install argus infra/helm/argus -f values-dev.yaml`), `## Production deploy` (sealed secrets recipe, cosign verify integration, ingress + cert-manager setup, HPA tuning), `## Migration runbook` (zero-downtime upgrade strategy), `## Rollback` (helm rollback + alembic downgrade pattern)
- [ ] `CHANGELOG.md` — `### Added (ARG-045 — Cycle 5: Helm chart + Alembic migrations 019..023)` block

**Files to create / modify:**

```
infra/helm/argus/Chart.yaml                               (new)
infra/helm/argus/values.yaml                              (new)
infra/helm/argus/values-dev.yaml                          (new)
infra/helm/argus/values-staging.yaml                      (new)
infra/helm/argus/values-prod.yaml                         (new)
infra/helm/argus/templates/_helpers.tpl                   (new)
infra/helm/argus/templates/backend-deployment.yaml        (new)
infra/helm/argus/templates/celery-worker-deployment.yaml  (new)
infra/helm/argus/templates/frontend-deployment.yaml       (new)
infra/helm/argus/templates/mcp-server-deployment.yaml     (new)
infra/helm/argus/templates/postgres-statefulset.yaml      (new)
infra/helm/argus/templates/redis-statefulset.yaml         (new)
infra/helm/argus/templates/minio-statefulset.yaml         (new)
infra/helm/argus/templates/services.yaml                  (new)
infra/helm/argus/templates/ingress.yaml                   (new)
infra/helm/argus/templates/networkpolicies.yaml           (new)
infra/helm/argus/templates/servicemonitor.yaml            (new)
infra/helm/argus/templates/otel-instrumentation.yaml      (new)
infra/helm/argus/templates/hpa.yaml                       (new)
infra/helm/argus/templates/sealedsecrets.yaml.example     (new)
backend/alembic/versions/019_reports_table.py             (new)
backend/alembic/versions/020_mcp_audit_table.py           (new)
backend/alembic/versions/021_mcp_notification_dispatch_log.py (new)
backend/alembic/versions/022_rate_limiter_state_table.py  (new)
backend/alembic/versions/023_epss_kev_tables.py           (new)
infra/scripts/migrate_smoke.sh                            (new)
infra/scripts/helm_lint.sh                                (new)
backend/tests/integration/migrations/test_alembic_smoke.py (new)
.github/workflows/ci.yml                                  (modify: +helm-lint job + migrations-smoke job)
docs/deployment-helm.md                                   (new)
CHANGELOG.md                                              (modify: +ARG-045 entry)
```

**Workflow:** Worker → Test-writer → Security-auditor (sealed secrets discipline + cosign verify enforcement) → Test-runner → Reviewer

---

### ARG-046 — Полный hexstrike purge из docs / tests / production source

- **Status:** ⏸ Pending
- **Backlog reference:** §0 (cleanup discipline — legacy migration), §17 (test discipline — no dead imports)
- **Priority:** MEDIUM
- **Complexity:** moderate
- **Hours:** 5
- **Dependencies:** ARG-032 ✅ (parsers batch 4 — hexstrike functionality fully replaced); ARG-037 ✅ (stale-import discipline — workflow для cleanup batch'ей established)

**Description:**  
Cycle 0/1 наследие — ~50 stale references на legacy `hexstrike` tooling в `docs/`, `tests/`, и нескольких production source модулях. Cycle 4 ARG-037 закрыл четыре related cleanup'а (stale imports / payload signatures / pytest prefix collisions), но hexstrike-references — отдельный класс, не closed. Текущая разведка: `rg -i hexstrike` даёт 88+ hits, из них (a) **immutable исторические артефакты** — `Backlog/dev1_.md` (1 hit), `CHANGELOG.md` (5 hits), `README-REPORT.md` (3 hits), `docs/develop/reports/2026-03-09-argus-implementation-report.md` (2 hits), `ai_docs/develop/plans/2026-04-02-hexstrike-v4-mcp-orchestration.md` (3 hits), `ai_docs/develop/plans/2026-04-17-argus-finalization-cycle1.md` (19 hits), `ai_docs/develop/plans/2026-04-18-argus-finalization-cycle2.md` (9 hits), `ai_docs/develop/plans/2026-04-19-argus-finalization-cycle3.md` (6 hits), `ai_docs/develop/reports/*` (Cycle 1-4 — 22+ hits) — **keep**, mark «historical context», (b) **active production source** — `backend/src/api/routers/intelligence.py` (1 hit), `backend/src/api/routers/scans.py` (2 hits), `backend/src/api/routers/sandbox.py` (1 hit) — **clean up** (single-line legacy references), (c) **active tests** — `backend/tests/test_argus006_hexstrike.py` (7 hits) — **delete or rewrite** (если legacy test без current relevance — delete; если covers actual current functionality под старым именем — rename + update). Каждый hit category'd через worker spreadsheet. Final regression gate: `test_no_hexstrike_active_imports.py` integration test — `assert 0 == count_hexstrike_in(backend/src/, backend/tests/, docs/, ai_docs/develop/plans/2026-04-21-* + later, ai_docs/develop/reports/2026-04-20-* + later)`; whitelist'ит immutable Cycle 1-4 artifacts через explicit path filter.

**Acceptance criteria:**

- [ ] Audit pass — `rg -i 'hexstrike' --type-add 'cfg:*.{yaml,yml,toml,ini,cfg}' --type=md --type=py --type=ts --type=cfg backend/src docs ai_docs` → enumerate всех references; categorize в `ai_docs/develop/issues/ISS-arg046-hexstrike-audit.md` (3 categories × file × line)
- [ ] Production source cleanup — `backend/src/api/routers/intelligence.py` — remove hexstrike reference (single-line); replace с current parser-driven pipeline reference или delete entirely
- [ ] Production source cleanup — `backend/src/api/routers/scans.py` — remove 2 hexstrike references (likely comments или docstrings); clean up
- [ ] Production source cleanup — `backend/src/api/routers/sandbox.py` — remove single hexstrike reference
- [ ] Test cleanup — `backend/tests/test_argus006_hexstrike.py` — analyze 7 references; либо delete (если covers нет actual current functionality) либо rewrite (rename file + update test bodies на current `tools_sign verify` / sandbox dispatcher / etc.)
- [ ] Test cleanup — search для дополнительных test files matching `*hexstrike*` или imports `from src.recon.hexstrike*` — delete dead modules + corresponding tests + fixtures
- [ ] Docs cleanup — `docs/architecture.md` (если есть hexstrike refs) — replace с current parser-driven pipeline diagram
- [ ] Docs cleanup — `docs/recon-pipeline.md` (если есть) — same
- [ ] Regression gate — `backend/tests/test_no_hexstrike_active_imports.py` (new) — uses `subprocess.run(["rg", "-c", "-i", "hexstrike", "backend/src/", "backend/tests/", "docs/"])` → assert 0 hits, OR if rg unavailable, fall back to recursive `pathlib.Path.read_text()` scan; whitelist Cycle 1-4 immutable artifacts через explicit `EXCLUDED_PATHS` constant в test file
- [ ] Regression gate — `backend/tests/test_no_hexstrike_active_imports.py` — secondary check: `pytest --collect-only -q | rg -c hexstrike == 0` (через `_pytest.config` collect manager API)
- [ ] Whitelist documentation — внутри `test_no_hexstrike_active_imports.py` — explicit list of immutable historical paths (Cycle 1-4 plans / reports / Backlog / CHANGELOG / README-REPORT) с rationale comment («исторические артефакты не модифицируются ради audit trail»)
- [ ] `mypy --strict` clean для new test
- [ ] `ruff check + ruff format --check` clean для все touched files
- [ ] `pytest backend/tests/test_no_hexstrike_active_imports.py -v` — pass (0 hits в active source/tests/docs)
- [ ] `pytest -q` (full backend suite) — no regressions (≥ 11 934 PASS sustained)
- [ ] `ai_docs/develop/issues/ISS-arg046-hexstrike-audit.md` (new) — audit spreadsheet (file × line × category × resolution)
- [ ] `CHANGELOG.md` — `### Removed (ARG-046 — Cycle 5: Hexstrike legacy purge from active source/tests/docs)` block

**Files to create / modify:**

```
backend/src/api/routers/intelligence.py                   (modify: remove hexstrike ref)
backend/src/api/routers/scans.py                          (modify: remove hexstrike refs)
backend/src/api/routers/sandbox.py                        (modify: remove hexstrike ref)
backend/tests/test_argus006_hexstrike.py                  (delete or rewrite)
backend/tests/test_no_hexstrike_active_imports.py         (new)
docs/architecture.md                                      (modify: replace hexstrike refs if any)
docs/recon-pipeline.md                                    (modify: same if any)
ai_docs/develop/issues/ISS-arg046-hexstrike-audit.md      (new)
CHANGELOG.md                                              (modify: +ARG-046 entry)
```

**Workflow:** Worker → Test-writer → Test-runner → Reviewer

---

### ARG-047 — DoD §19.4 e2e capstone (`scripts/e2e_full_scan.sh http://juice-shop:3000`)

- **Status:** ⏸ Pending
- **Backlog reference:** §19.4 (DoD — full e2e scan), §16.13 (CI nightly e2e), §17 (testing — long-running flake prevention)
- **Priority:** HIGH
- **Complexity:** complex
- **Hours:** 12
- **Dependencies:** **все Cycle 1-4** (full stack должен быть production-ready); ARG-031 ✅ (18/18 reports), ARG-033 ✅ (cosign verify), ARG-034 ✅ (GHCR images); ARG-041 (Prometheus metrics — для verification step); ARG-045 (либо Helm chart либо docker-compose stack — ARG-047 use docker-compose как baseline)

**Description:**  
Final integration test, доказывающий что full ARGUS stack работает end-to-end на live target (OWASP Juice Shop). **`scripts/e2e_full_scan.sh <target_url>`** — wrapper script (POSIX shell + PowerShell wrapper для Windows): (1) `docker compose -f infra/docker-compose.e2e.yml up -d` — backend + frontend + Postgres + Redis + MinIO + 4 sandbox images + OWASP Juice Shop как target service, (2) wait for health (polling `curl backend:8000/ready` + `curl frontend:3000/api/health` каждые 5s, max 120s), (3) trigger scan via `POST /scans` с body `{"target_url": "$1", "scan_profile": "deep", "tier_requested": "valhalla"}`, capture `scan_id` из response, (4) poll `GET /scans/$scan_id` каждые 30s until `status="completed"` (timeout 30 min — Juice Shop scan typically 8-15 min), (5) verify все 18 reports generated через `GET /reports/$scan_id?tier=midgard&format=html` × {midgard, asgard, valhalla} × {html, pdf, json, csv, sarif, junit}, (6) verify OAST callback received (Juice Shop has known SSRF in `/rest/products/reviews/:id` — should trigger OAST DNS callback), (7) verify `cosign verify --certificate-identity-regexp ... ghcr.io/<org>/argus-kali-{web,cloud,browser,full,recon,network}:latest` exit 0 inside CI, (8) verify Prometheus metrics — `curl http://backend:8000/metrics | rg 'argus_findings_total > 0'` + `argus_scan_duration_seconds_bucket{le="600"} > 0`, (9) verify min N findings (Juice Shop expected ≥ 50 findings: SQLi, XSS, broken auth, SSRF, deprecated libs, exposed metadata), (10) tear down (`docker compose -f infra/docker-compose.e2e.yml down -v`), (11) archive results — bundle generated reports + Prometheus snapshot + Tempo trace export как single tarball `e2e-results-$(date -u +%Y%m%dT%H%M%SZ).tar.gz`. **CI integration** — new GitHub Actions workflow `e2e-full-scan.yml` (manual `workflow_dispatch` trigger + nightly cron `0 2 * * *` UTC); `runs-on: ubuntu-latest-large` (для Docker daemon); requires repository secret `E2E_GHCR_PULL_TOKEN`; results uploaded as job artifact (retention 30 days). **Flake prevention** — explicit timeout per phase (health=120s, scan=1800s, report-gen=300s, oast-callback=600s); retries только на network operations (max 3); deterministic Juice Shop seed (если Juice Shop supports `--config <fixed-seed>` иначе version pin). **Acceptance:** all 18 reports byte-stable (text formats) + structurally valid (PDF), all sandbox images verifiable, OAST callback received, no secret leak в any report (re-run security gate против actual scan output).

**Acceptance criteria:**

- [ ] `infra/docker-compose.e2e.yml` (new) — services: `argus-backend`, `argus-celery-worker`, `argus-frontend`, `argus-mcp-server`, `postgres:15-alpine`, `redis:7-alpine`, `minio/minio:latest`, `ghcr.io/<org>/argus-kali-{web,cloud,browser,full}:latest`, `bkimminich/juice-shop:latest`; healthchecks для каждого; depends_on с `condition: service_healthy`
- [ ] `scripts/e2e_full_scan.sh` (new) — POSIX shell wrapper, ≥ 11 phases (up, health-wait, trigger-scan, poll-scan, verify-reports, verify-oast, verify-cosign, verify-metrics, verify-findings-count, tear-down, archive-results); explicit per-phase timeouts; structured output (JSON status report)
- [ ] `scripts/e2e_full_scan.ps1` (new) — PowerShell wrapper для Windows (calls `bash scripts/e2e_full_scan.sh` if WSL2 доступен, иначе native PowerShell port)
- [ ] `scripts/e2e/verify_reports.py` (new) — helper script: poll все 18 report endpoints, assert HTTP 200 + sha256 stable + content-type valid; called from `e2e_full_scan.sh`
- [ ] `scripts/e2e/verify_oast.py` (new) — helper: poll OAST callback DB / API endpoint, assert ≥ 1 callback с payload_class in {ssrf, xss, sqli}; max wait 600s
- [ ] `scripts/e2e/verify_cosign.sh` (new) — helper: cosign verify per image; exit 0 если все 6 images verifiable
- [ ] `scripts/e2e/verify_prometheus.py` (new) — helper: scrape `/metrics`, assert `argus_findings_total > 0`, `argus_scan_duration_seconds_bucket{le="600"} > 0`, `argus_tool_runs_total > 50`
- [ ] `scripts/e2e/archive_results.sh` (new) — helper: tar.gz {reports/, prometheus-snapshot/, tempo-traces/, scan-summary.json}
- [ ] `.github/workflows/e2e-full-scan.yml` (new) — workflow: triggers (workflow_dispatch + cron `0 2 * * *`); jobs: `e2e-juice-shop` (`runs-on: ubuntu-latest-large`); steps: checkout → install Docker → login GHCR → run `scripts/e2e_full_scan.sh http://juice-shop:3000` → upload artifact (results tarball)
- [ ] `backend/tests/integration/e2e/test_e2e_health_endpoints.py` (new) — Cycle 5 self-test: assert health endpoints respond per ARG-041 schema (without docker-compose stack — uses TestClient)
- [ ] `backend/tests/integration/e2e/test_e2e_scan_lifecycle.py` (new) — Cycle 5 self-test: mock e2e flow с in-memory MinIO + sqlite + mocked Celery (≥ 8 cases — happy path, timeout handling, partial report failure recovery)
- [ ] `infra/docker-compose.e2e.yml` validate — `docker compose -f infra/docker-compose.e2e.yml config --quiet` exit 0
- [ ] `bash -n scripts/e2e_full_scan.sh` clean syntax
- [ ] `shellcheck scripts/e2e_full_scan.sh scripts/e2e/*.sh` (если установлен) — clean (severity ≥ warning)
- [ ] Local smoke run — operator runs `bash scripts/e2e_full_scan.sh http://juice-shop:3000` локально (если Docker daemon доступен) → all 11 phases complete + results tarball generated
- [ ] CI workflow validation — `.github/workflows/e2e-full-scan.yml` parses через `yaml.safe_load(...)` exit 0; `actionlint .github/workflows/e2e-full-scan.yml` (если установлен) clean
- [ ] `docs/e2e-testing.md` (new) — section `## Local run` (prerequisites: Docker daemon, GHCR pull access; command: `bash scripts/e2e_full_scan.sh http://juice-shop:3000`), `## CI lane` (workflow_dispatch + nightly schedule, artifact retrieval recipe), `## Troubleshooting` (common failure modes: Juice Shop slow startup, OAST callback timeout, Cosign verify failure, GHCR rate limit)
- [ ] `CHANGELOG.md` — `### Added (ARG-047 — Cycle 5: DoD §19.4 e2e capstone scan against Juice Shop)` block

**Files to create / modify:**

```
infra/docker-compose.e2e.yml                              (new)
scripts/e2e_full_scan.sh                                  (new)
scripts/e2e_full_scan.ps1                                 (new — Windows wrapper)
scripts/e2e/verify_reports.py                             (new)
scripts/e2e/verify_oast.py                                (new)
scripts/e2e/verify_cosign.sh                              (new)
scripts/e2e/verify_prometheus.py                          (new)
scripts/e2e/archive_results.sh                            (new)
.github/workflows/e2e-full-scan.yml                       (new)
backend/tests/integration/e2e/__init__.py                 (new)
backend/tests/integration/e2e/test_e2e_health_endpoints.py (new)
backend/tests/integration/e2e/test_e2e_scan_lifecycle.py  (new)
docs/e2e-testing.md                                       (new)
CHANGELOG.md                                              (modify: +ARG-047 entry)
```

**Workflow:** Worker → Test-writer → Test-runner → Reviewer

---

### ARG-048 — Cycle 4 known-gap closure (sandbox profiles + LaTeX Phase-2 + Slack callbacks)

- **Status:** ⏸ Pending
- **Backlog reference:** §15 (Reports — PDF parity), §13 (MCP — Slack action handlers), §16.13 (Sandbox image profiles `kali-recon` + `kali-network`)
- **Priority:** MEDIUM
- **Complexity:** moderate
- **Hours:** 6
- **Dependencies:** ARG-036 ✅ (PDF backend chain — Phase-1 done); ARG-035 ✅ (Slack notifier эмиттит pending events — Phase-1 done); ARG-026 ✅ (Cosign signing скелет для new sandbox images); ARG-040 ✅ (per-image coverage column в `docs/tool-catalog.md` — `argus-kali-recon` помечен «pending», `argus-kali-network` отсутствует)

**Description:**  
Закрыть три known-gap из Cycle 4 sign-off, каждый — небольшой, но independent surface. **Gap 1 — Sandbox image profiles `argus-kali-recon` + `argus-kali-network`:** `docs/tool-catalog.md::Image coverage` секция (added ARG-040) ссылается на `argus-kali-recon` как «pending» (1 pending image), и аналогично нет `argus-kali-network`. Эти два профиля нужны для full Backlog §4 coverage (recon-heavy tools требуют unique deps типа `nuclei` + `subfinder` + `amass` + `dnsrecon` + `fierce`; network-heavy — `nmap` + `masscan` + `naabu` + `dnsx` + `unicornscan`). Создать два Dockerfile mirror'ом existing `argus-kali-{web,cloud,browser,full}` структуры (USER 65532, no SUID, HEALTHCHECK, SBOM-stable, multi-stage build), добавить в CI workflow `.github/workflows/sandbox-images.yml::build-images::matrix.profile` arrays. **Gap 2 — LaTeX Phase-2 wiring:** Cycle 4 ARG-036 land'нул LaTeX backend как Phase-1 stub (HTML stripped → minimal LaTeX preamble → `latexmk -pdf`). Phase-2 wires existing `_latex/<tier>/main.tex.j2` template'ы (created в ARG-036, currently unused) через `jinja2-latex` rendering pipeline, давая layout parity с WeasyPrint output. Без этого — LaTeX backend produces minimal-style PDF без branded headers/footers, не matching production PDF aesthetics. **Gap 3 — Slack interactive callbacks:** Cycle 4 ARG-035 эмиттит `approval.pending` events в Slack, но Slack interactive button payloads (`approve::<id>` / `deny::<id>`) — ingested не были (out-of-scope per ARG-035 worker report). Создать FastAPI endpoint `POST /api/mcp/notifications/slack/callback` принимающий Slack interactive payload (signature verified через `X-Slack-Signature` header + `SLACK_SIGNING_SECRET` env), parses `actions[].action_id` (`approve::<approval_id>` или `deny::<approval_id>`), routes к existing `ApprovalService.decide(approval_id, decision, actor_id, comment)`. Audit log entry с `actor=slack_user_<slack_user_id>`. Closes Cycle 4 ARG-035 §outOfScopeFollowUps[0].

**Acceptance criteria:**

- [ ] `infra/sandbox/images/Dockerfile.argus-kali-recon` (new) — multi-stage build от `kalilinux/kali-rolling`, install recon tools (nuclei + subfinder + amass + dnsrecon + fierce + assetfinder + findomain + chaos), USER 65532, no SUID, HEALTHCHECK, размер < 800 MB
- [ ] `infra/sandbox/images/Dockerfile.argus-kali-network` (new) — same структура, network tools (nmap + masscan + naabu + dnsx + unicornscan + zmap), USER 65532, no SUID, HEALTHCHECK, размер < 600 MB
- [ ] `infra/sandbox/images/sbom-recon.cdx.json` (new) — CycloneDX SBOM, generated via `syft argus-kali-recon:latest -o cyclonedx-json`
- [ ] `infra/sandbox/images/sbom-network.cdx.json` (new) — same для network
- [ ] `.github/workflows/sandbox-images.yml` — extend `build-images::matrix.profile` array с `recon` + `network` (теперь 6 profiles total); extend `sign-images` + `verify-images` matrix аналогично
- [ ] `backend/tests/integration/sandbox/test_image_security_contract.py` — extend параметризацию на новые 2 profiles (USER 65532, no SUID, HEALTHCHECK, SBOM присутствует)
- [ ] `backend/scripts/docs_tool_catalog.py` — поднимает coverage для `recon` + `network` images; `python -m scripts.docs_tool_catalog --check` exit 0 (drift = 0; per-image coverage column updated с 4 → 6 built images)
- [ ] `backend/src/reports/pdf_backend.py` — `LatexBackend.render(...)` теперь использует `jinja2-latex` для rendering existing `backend/templates/reports/_latex/<tier>/main.tex.j2`; previous Phase-1 minimal stub deprecated с graceful fallback
- [ ] `backend/templates/reports/_latex/midgard/main.tex.j2` (modify) — full template body: `\documentclass{article}` + branded `\usepackage{argus-styles}` (или inline preamble) + cover page + TOC + sections (executive-summary, findings-table, evidence-appendix), Jinja2 placeholders для `{{ tenant }}`, `{{ scan_id }}`, `{{ findings }}`, `{{ generated_at }}`
- [ ] `backend/templates/reports/_latex/asgard/main.tex.j2` (modify) — full template body, Asgard tier (full findings + remediation + reproducer)
- [ ] `backend/templates/reports/_latex/valhalla/main.tex.j2` (modify) — full template body, Valhalla executive lens
- [ ] `backend/pyproject.toml` — добавить `jinja2-latex>=0.3` в dev deps (sustained from ARG-036 partial)
- [ ] Tests — `backend/tests/integration/reports/test_latex_phase2_parity.py` (new) — ≥ 8 cases: rendered LaTeX output contains branded headers/footers, page layout parity с WeasyPrint output (structural snapshot через `pdftotext` text extraction); skipped if `latexmk` not on PATH (`requires_latex` marker)
- [ ] `backend/src/api/routers/mcp_slack_callbacks.py` (new) — FastAPI router; `POST /api/mcp/notifications/slack/callback` endpoint; signature verification (`X-Slack-Signature` HMAC SHA-256 через `SLACK_SIGNING_SECRET`); parse `actions[].action_id`; route to `ApprovalService`
- [ ] `backend/src/api/main.py` (modify) — register `mcp_slack_callbacks` router
- [ ] Tests — `backend/tests/unit/api/routers/test_mcp_slack_callbacks.py` (new) — ≥ 18 cases: signature valid, signature invalid, action_id format correct, action_id malformed, approval_id valid, approval_id not found, decide success, decide blocked by policy
- [ ] Tests — `backend/tests/integration/mcp/test_slack_interactive_flow.py` (new) — ≥ 5 cases: end-to-end (Slack notify → callback simulated → approval decided → audit log entry created)
- [ ] Tests — `backend/tests/security/test_slack_callback_signature_replay_protection.py` (new) — ≥ 8 cases: timestamp-based replay protection (Slack `X-Slack-Request-Timestamp` ≤ 5 minutes ago), signature timing-safe comparison, no body parsing before signature verify
- [ ] `mypy --strict` clean для new modules
- [ ] `ruff check + ruff format --check` clean для touched files
- [ ] `docs/sandbox-images.md` — extend `## Image profiles` секция с `argus-kali-recon` + `argus-kali-network` rows (deps, size, intended tool families)
- [ ] `docs/report-service.md` — Phase-2 LaTeX completion note + recipe для local visual diff (`pdftotext output.pdf -` text comparison)
- [ ] `docs/mcp-server.md` — section `## Slack interactive callbacks` (signing recipe, action_id format, audit log integration)
- [ ] `CHANGELOG.md` — `### Added (ARG-048 — Cycle 5: Cycle 4 known-gap closure — sandbox recon/network profiles + LaTeX Phase-2 + Slack callbacks)` block

**Files to create / modify:**

```
infra/sandbox/images/Dockerfile.argus-kali-recon          (new)
infra/sandbox/images/Dockerfile.argus-kali-network        (new)
infra/sandbox/images/sbom-recon.cdx.json                  (new)
infra/sandbox/images/sbom-network.cdx.json                (new)
.github/workflows/sandbox-images.yml                      (modify: matrix +2 profiles)
backend/src/reports/pdf_backend.py                        (modify: LatexBackend Phase-2)
backend/templates/reports/_latex/midgard/main.tex.j2      (modify: full body)
backend/templates/reports/_latex/asgard/main.tex.j2       (modify: full body)
backend/templates/reports/_latex/valhalla/main.tex.j2     (modify: full body)
backend/src/api/routers/mcp_slack_callbacks.py            (new)
backend/src/api/main.py                                   (modify: register router)
backend/pyproject.toml                                    (modify: +jinja2-latex)
backend/tests/integration/sandbox/test_image_security_contract.py (modify: +2 profiles)
backend/scripts/docs_tool_catalog.py                      (modify: 4→6 images)
backend/tests/integration/reports/test_latex_phase2_parity.py (new)
backend/tests/unit/api/routers/test_mcp_slack_callbacks.py (new)
backend/tests/integration/mcp/test_slack_interactive_flow.py (new)
backend/tests/security/test_slack_callback_signature_replay_protection.py (new)
docs/sandbox-images.md                                    (modify: +recon/network sections)
docs/report-service.md                                    (modify: Phase-2 note)
docs/mcp-server.md                                        (modify: +Slack callback section)
CHANGELOG.md                                              (modify: +ARG-048 entry)
```

**Workflow:** Worker → Test-writer → Security-auditor (Slack signature replay protection!) → Test-runner → Reviewer

---

### ARG-049 — Cycle 5 capstone (coverage matrix 14→16, docs regen, sign-off, Cycle 6 carry-over)

- **Status:** ⏸ Pending
- **Backlog reference:** §17 (testing — coverage matrix evolution), §19 (DoD — Cycle close acceptance), §0 (orchestration discipline)
- **Priority:** CRITICAL
- **Complexity:** complex
- **Hours:** 7
- **Dependencies:** ARG-041..ARG-048 (все 8 предыдущих задач Cycle 5 должны быть Completed; capstone — последний шаг цикла)

**Description:**  
Capstone Cycle 5 — финальный шаг, mirror ARG-040 / ARG-030 структуры. Расширяет coverage matrix с **14 → 16** контрактов, регенерирует документацию, пишет sign-off report, готовит Cycle 6 carry-over. **C15 — `tool-yaml-version-monotonic`:** ratchet test, что `version: <semver>` field (added в ARG-040) на каждом tool YAML может только расти (semver bumps только вверх, не вниз); current baseline locked (157 YAMLs × `1.0.0` после ARG-040 backfill); test verifies каждый PR не понижает версию. Хранение baseline — `backend/tests/snapshots/tool_versions_baseline.json` (committed, не auto-update). **C16 — `image-coverage-completeness`:** каждый tool_id обязан быть pinned в ≥1 sandbox image profile; после ARG-048 (added `argus-kali-recon` + `argus-kali-network`) — coverage должно быть 100 % (157/157 tools mapped к ≥1 image). Test reads `infra/sandbox/images/Dockerfile.argus-kali-*` (regex `RUN apt-get install ... <package>` + manual mapping `tool_id → package_name` в `infra/sandbox/images/tool_to_package.json`); fails если хотя бы один tool_id не покрыт. **Регенерация `docs/tool-catalog.md`** — после ARG-048 new images added; per-image coverage column updated (now 6/6 built — `web`, `cloud`, `browser`, `full`, `recon`, `network`); ratchet baseline updated (mapped 98 → 98 sustained, heartbeat 59 → 59 sustained, total YAMLs 157 → 157 sustained). **`scripts/argus_validate.py`** — meta-script, runs все DoD §19 acceptance gates locally (используется для local pre-merge sanity check + CI smoke); calls catalog signing verify + docs drift + coverage matrix + parser suites + reports + MCP + security suite + cosign verify (если cosign installed). **Sign-off report `ai_docs/develop/reports/2026-04-20-argus-finalization-cycle5.md`** — mirror Cycle 4 sign-off structure: per-task summaries, headline metrics (catalog signing 186 verifiable; coverage matrix 16/16 contracts × 157 = 2 540+ cases; full pytest suite count; Helm chart smoke test; e2e capstone result), architectural impact (cloud_iam landed; observability landed; Helm landed; LaTeX Phase-2 landed; Slack callbacks landed), known gaps (Admin Frontend; tenant kill-switch UI; Sigstore policy controller in-cluster admission; PDF/A-2u archival), acceptance gates results, sign-off criteria checklist. **Cycle 6 carry-over `ai_docs/develop/issues/ISS-cycle6-carry-over.md`** — primed: Admin Frontend (Backlog §14 — XL), Tenant kill-switch UI (Backlog §8 — M), Sigstore policy controller for in-cluster admission (Backlog §16.13 — L), PDF/A-2u archival profile (Backlog §15 — S), advanced KEV-aware autoscaling (Backlog §6 — M), maintenance window cron + scheduled scan UI (Backlog §1.4 — M).

**Acceptance criteria:**

- [ ] `backend/tests/test_tool_catalog_coverage.py` — добавить C15 `test_tool_yaml_version_monotonic` (≥ 157 parametric cases — read current YAML version vs baseline JSON, assert `>=`); fail-fast если PR попытается downgrade
- [ ] `backend/tests/test_tool_catalog_coverage.py` — добавить C16 `test_image_coverage_completeness` (≥ 157 parametric cases — assert каждый tool_id mapped в ≥ 1 image); coverage matrix bump 14 → **16 contracts**
- [ ] `backend/tests/snapshots/tool_versions_baseline.json` (new) — locked baseline (157 entries × `"1.0.0"`); committed; auto-update НЕ allowed (manual bump only через explicit version-bump PR)
- [ ] `infra/sandbox/images/tool_to_package.json` (new) — manual mapping (157 tool_id → package name в Kali apt repo); used by C16 test для verification
- [ ] `backend/scripts/docs_tool_catalog.py` — modify generator для использования new images (`recon` + `network`); per-image coverage column shows 6/6 built; total mapped count sustained 98; heartbeat sustained 59
- [ ] `docs/tool-catalog.md` — regenerated (header summary updated с total 157 / mapped 98 / heartbeat 59 / built images 6 / pending images 0); `python -m scripts.docs_tool_catalog --check` exit 0 (drift = 0)
- [ ] `scripts/argus_validate.py` (new) — meta-script (Python): runs `tools_sign verify`, `payloads_sign verify`, `prompts_sign verify`, `docs_tool_catalog --check`, `pytest test_tool_catalog_coverage`, `pytest tests/unit/sandbox/parsers tests/integration/sandbox/parsers`, `pytest tests/unit/reports tests/unit/mcp tests/integration/reports tests/integration/mcp`, `pytest tests/security`, `mypy --strict src/sandbox src/sandbox/parsers src/reports src/mcp src/policy/cloud_iam src/findings src/core`, `ruff check src tests`, `bandit -q -r src`, optional `helm lint infra/helm/argus`; structured JSON output with per-gate status + total elapsed
- [ ] `scripts/argus_validate.py` exit code: 0 если все gates pass, non-zero with structured failure summary
- [ ] `ai_docs/develop/reports/2026-04-20-argus-finalization-cycle5.md` (new) — sign-off report (mirror Cycle 4 structure, ≥ 800 LoC): exec summary, per-task summaries (ARG-041..049 — 9 tasks), headline metrics table, architectural impact, known gaps, acceptance gates results, Cycle 6 candidates, sign-off
- [ ] `ai_docs/develop/issues/ISS-cycle6-carry-over.md` (new) — primed для Cycle 6 (≥ 6 items, mirror `ISS-cycle5-carry-over.md` structure)
- [ ] `CHANGELOG.md` — `### Added (ARG-049 — Cycle 5 capstone: Coverage matrix 14→16 + Cycle 5 sign-off + Cycle 6 carry-over)` block + Cycle 5 closure rollup section
- [ ] `pytest backend/tests/test_tool_catalog_coverage.py -q` — pass (≥ 2 540 cases — 16 contracts × ~157, with C13/C14 retained from Cycle 4 + new C15/C16)
- [ ] `pytest backend/tests -q` (full backend test suite) — pass (≥ 12 500 cases sustained, no regressions vs Cycle 4 baseline 11 934)
- [ ] `mypy --strict --follow-imports=silent src/sandbox src/sandbox/parsers src/reports src/mcp src/policy/cloud_iam src/findings src/core` — clean
- [ ] `ruff check src tests` — clean
- [ ] `bandit -q -r src` — clean (или only pre-existing LOW issues, documented)
- [ ] `python -m scripts.tools_sign verify` + `payloads_sign verify` + `prompts_sign verify` — все pass (186 verifiable)
- [ ] `python -m scripts.docs_tool_catalog --check` — exit 0
- [ ] `python scripts/argus_validate.py` — exit 0 (all gates green)
- [ ] `helm lint infra/helm/argus -f values-prod.yaml` — exit 0 (sustained from ARG-045)
- [ ] Catalog signing инвариант сохранён: 157 + 23 + 5 + 1 = 186 Ed25519-verifiable; 0 drift после full pytest run

**Files to create / modify:**

```
backend/tests/test_tool_catalog_coverage.py               (modify: +C15 +C16, ratchet 14→16)
backend/tests/snapshots/tool_versions_baseline.json       (new)
infra/sandbox/images/tool_to_package.json                 (new)
backend/scripts/docs_tool_catalog.py                      (modify: 4→6 images)
docs/tool-catalog.md                                      (regenerate)
scripts/argus_validate.py                                 (new)
ai_docs/develop/reports/2026-04-20-argus-finalization-cycle5.md (new — sign-off report)
ai_docs/develop/issues/ISS-cycle6-carry-over.md           (new — Cycle 6 carry-over)
CHANGELOG.md                                              (modify: +ARG-049 entry + Cycle 5 closure rollup)
```

**Workflow:** Worker → Test-writer → Test-runner → Documenter → Reviewer (final cycle close)

---

## 4. Dependencies graph

```
Cycle 4 (ARG-031..040) ✅ closed — все foundations готовы (ReportService 18/18, supply-chain prod, MCP webhooks/rate-limiter/OpenAPI/TS SDK, parsers 98/59, coverage 14 contracts, Cycle 5 carry-over primed)
  │
  ├──→ ARG-041 (Observability — OTel + Prometheus + health) ──┐
  │                                                            │
  ├──→ ARG-042 (Frontend MCP integration) ────────────────────┤
  │                                                            │
  ├──→ ARG-043 (Real cloud_iam — AWS/GCP/Azure) ──────────────┤
  │                                                            │
  ├──→ ARG-044 (EPSS + KEV + SSVC v2.1) ──────────────────────┤
  │                                                            │
  ├──→ ARG-045 (Helm chart + Alembic migrations) ─────────────┤───→ ARG-047 (e2e capstone scan) ─┐
  │                                                            │                                  │
  ├──→ ARG-046 (hexstrike full purge) ────────────────────────┤                                  │
  │                                                            │                                  │
  └──→ ARG-048 (Cycle 4 known-gap closure: sandbox profiles + LaTeX Phase-2 + Slack callbacks) ─┤
                                                               ↓                                  │
                                                          ARG-049 (CAPSTONE — coverage 14→16, docs, sign-off, Cycle 6 carry-over)
                                                               ↑                                  │
                                                               └──────────────────────────────────┘
```

**Critical path (longest dependency chain):**

```
ARG-045 (16h) ──→ ARG-047 (12h) ──→ ARG-049 (7h)  =  35 hours wall-time
```

(Альтернативные chain'ы: ARG-043 (16h) → ARG-049 (7h) = 23h; ARG-041 (12h) → ARG-049 (7h) = 19h; ARG-044 (12h) → ARG-049 (7h) = 19h. Все короче.)

**Parallel-safe groups (могут стартовать одновременно с t=0):**

- **Group A** (no deps, start immediately): ARG-041, ARG-042, ARG-043, ARG-044, ARG-045, ARG-046, ARG-048 — **7 tasks параллельно** (ARG-044 опционально может стартовать после ARG-045 если предпочесть Postgres tables через Alembic; baseline — параллельно через in-memory persistence + later migration)
- **Group B** (start after Group A subset finishes): ARG-047 (требует ARG-045 docker-compose stack либо ARG-041 metrics для verification step + ARG-044 для SSVC integration test step)
- **Group C** (start after all 8): ARG-049 capstone (requires every other task Completed)

---

## 5. Status table (updated by orchestrator)

| ID | Title | Priority | Hours | Status | Notes |
|---|---|---|---|---|---|
| ARG-041 | Observability (OTel + Prometheus + health endpoints) | HIGH | 12 | ⏸ Pending | Завершает scaffold Cycle 4 → production-grade (Backlog §15) |
| ARG-042 | Frontend MCP integration (consume TS SDK + interactive UI) | MEDIUM | 8 | ⏸ Pending | Подключает ARG-039 SDK + React hooks + `/mcp` page |
| ARG-043 | Real cloud_iam ownership (AWS STS / GCP SA / Azure MI) | HIGH | 16 | ✅ Completed (2026-04-21) | Multi-cloud `OwnershipMethod` extension (Backlog §10); 156/156 tests PASS, ruff/mypy/sync_requirements green |
| ARG-044 | EPSS + KEV catalog ingest + полный CISA SSVC v2.1 | HIGH | 12 | ⏸ Pending | Завершает Cycle 3+4 scaffold; integrate в FindingPrioritizer + Valhalla (Backlog §6) |
| ARG-045 | Helm chart + Alembic migrations 019..023 | HIGH | 16 | ⏸ Pending | Production deployment infra (Backlog §16.13/§16.16/§19) |
| ARG-046 | Полный hexstrike purge из active source/tests/docs | MEDIUM | 5 | ⏸ Pending | Closes Cycle 0/1 legacy carryover (~50 stale refs) |
| ARG-047 | DoD §19.4 e2e capstone (`scripts/e2e_full_scan.sh juice-shop:3000`) | HIGH | 12 | ⏸ Pending | Full stack proof against live Juice Shop target |
| ARG-048 | Cycle 4 known-gap closure (sandbox profiles + LaTeX Phase-2 + Slack callbacks) | MEDIUM | 6 | ⏸ Pending | Closes 3 explicit Cycle 4 sign-off gaps |
| ARG-049 | CAPSTONE (coverage 14→16, docs regen, Cycle 5 sign-off, Cycle 6 carry-over) | CRITICAL | 7 | ⏸ Pending | Cycle 5 close + Cycle 6 priming |

**Total estimated hours:** **94 hours** (sum of all task estimates).  
**Critical path wall-time:** **35 hours** (ARG-045 → ARG-047 → ARG-049; assuming ample parallel worker capacity).

---

## 6. Architecture invariants — что НЕ ломаем (carry-over из Cycle 1+2+3+4)

Каждая Cycle 5 задача **обязана** сохранить guardrails из Cycle 1+2+3+4 + **добавляет** новые invariants для Cycle 5 surfaces (observability / cloud_iam / Helm / Alembic / EPSS+KEV).

### Sandbox runtime (Cycle 1+2)

- Non-root pod (`runAsNonRoot=true`, UID/GID 65532), read-only root filesystem, dropped capabilities, seccomp `RuntimeDefault`, `automountServiceAccountToken=false`, `restartPolicy=Never`, `backoffLimit=0`
- ARG-048 новые images `argus-kali-recon` + `argus-kali-network` **обязаны** проходить existing `tests/integration/sandbox/test_image_security_contract.py` (USER 65532, no SUID, HEALTHCHECK, SBOM присутствует)
- ARG-045 Helm chart **обязан** применять security context на каждом sandbox-pod (`securityContext.runAsNonRoot=true`, `securityContext.runAsUser=65532`, `securityContext.readOnlyRootFilesystem=true`); НЕ опционально

### Templating (Cycle 1)

- Allowlisted placeholders only (`src.pipeline.contracts._placeholders.ALLOWED_PLACEHOLDERS`)
- ARG-044 EPSS/KEV/SSVC enrichment **никогда** не embed'ит CVE description как placeholder (только structured fields `epss_score`, `kev_listed`, `ssvc_decision` — все typed)
- ARG-048 LaTeX Phase-2 `_latex/<tier>/main.tex.j2` template'ы используют **только** allowlisted placeholders + sanitized `tenant`/`scan_id`/`findings` (`replay_command_sanitizer` thread'ится через)

### Signing (Cycle 1+2+3+4)

- 157 tool YAMLs остаются Ed25519-signed (тот же dev key Cycle 1: `b618704b19383b67`); 23 payloads (key `8b409d74bef23aaf`); 5 prompts (key `681a1d103f2d8759`); MCP manifest (key `1d9876d6be68a494`); Cycle 4 ARG-040 backfill keys preserved
- **ARG-049 capstone** НЕ модифицирует tool YAMLs (если C15 baseline допускает только monotonic version bumps — actual bumps только через explicit version-bump PR'ы, не capstone)
- **ARG-045 Helm chart** ссылается на Cosign-signed images через immutable digest (`@sha256:<digest>`), НЕ tag (`:latest`); init-container проверяет signature перед main container start

### NetworkPolicy (Cycle 3+4)

- Ingress **always** denied (для всех 11 templates, включая cloud-aws/gcp/azure)
- DNS pinned (Cycle 3 wired override но defaults Cloudflare/Quad9 остаются)
- Private ranges (10/8, 172.16/12, 192.168/16, 169.254.169.254/32) blocked
- **ARG-043 cloud_iam** добавляет egress allowlist для AWS STS / GCP IAM / Azure Login FQDNs — **explicitly named** в `infra/k8s/networkpolicies/cloud-{aws,gcp,azure}.yaml`; **НЕ** wildcard egress
- **ARG-041 OTel exporter** egress (OTLP к Tempo/Jaeger) — добавить в `infra/k8s/networkpolicies/backend.yaml` **whitelisted** к `tempo.observability.svc.cluster.local:4317`; НЕ public OTLP collector
- **ARG-044 EPSS/KEV fetchers** egress — whitelisted FQDNs `api.first.org` (EPSS) + `www.cisa.gov` (KEV); НЕ wildcard egress

### Approval & dual-control (Cycle 1+2+4)

- `risk_level in {high, destructive}` → `requires_approval=true` (Coverage matrix Contract 10 enforces; не нарушаем)
- ARG-048 Slack callback handler **обязан** вызвать `ApprovalService.decide(...)` через audit log; не bypass'ить через direct DB UPDATE; signature verification — **mandatory** (no dry-run mode для production callbacks)

### Audit chain (Cycle 1+2)

- ApprovalService + AuditChain (Cycle 1 ARG-006) остаются source of truth
- ARG-043 cloud_iam verifications логируются в AuditChain с `actor=cloud_iam_verifier`, `event_type=AuditEventType.OWNERSHIP_VERIFY`, closed-taxonomy `failure_summary` (без raw cloud responses) — **PII protection**
- ARG-048 Slack interactive callbacks логируются в AuditChain с `actor=slack_user_<slack_user_id_hash>`, `event_type=AuditEventType.APPROVAL_DECIDED`, `args_hash=hash(approval_id|decision)`

### Findings & evidence (Cycle 1+3+4)

- FindingDTO имеет `root_cause_hash` для дедупликации (Cycle 1)
- ARG-044 EPSS/KEV/SSVC enrichment **расширяет** FindingDTO с 5 фич (`epss_score`, `epss_percentile`, `kev_listed`, `kev_added_date`, `ssvc_decision`) — **backward-compatible** (Pydantic Optional fields, default None)
- Redaction (`src.evidence.redaction`) применяется до persist в S3 (C12 enforces — extends на enriched FindingDTOs автоматически)
- ARG-031 Valhalla — **mandatory** прохождение sanitizer pipeline (sustained from Cycle 4 — ARG-044 prioritizer integration НЕ затрагивает sanitizer chain)

### Test infrastructure (Cycle 3+4)

- pytest markers (`requires_postgres/redis/oast/docker/weasyprint_pdf/latex/mutates_catalog`) discipline сохранена
- ARG-047 e2e capstone → новый marker `requires_docker_e2e` (skipped если `docker` not on PATH или `juice-shop:3000` not reachable)
- ARG-045 Alembic migrations smoke-test → новый marker `requires_postgres_e2e` (sustained from Cycle 3 `requires_postgres`, но specifically for migration smoke flows)
- Coverage matrix ratchet: `MAPPED_PARSER_COUNT` ≥ 98 (sustained from Cycle 4); `HEARTBEAT_PARSER_COUNT` ≤ 59 (sustained); `COVERAGE_MATRIX_CONTRACTS` 14 → **16** (ARG-049 enforces); `IMAGE_PROFILES_BUILT` 4 → **6** (ARG-048 + ARG-049 enforces); `TOOL_YAML_VERSIONS_BASELINE` locked в `tests/snapshots/tool_versions_baseline.json` (ARG-049 enforces monotonic)

### MCP server (Cycle 3+4)

- 15 tools / 4 resources / 3 prompts surface — стабильно (Cycle 5 НЕ добавляет новые tools)
- ARG-042 Frontend integration — **read-only** consumer SDK (НЕ модифицирует MCP server)
- ARG-048 Slack callback handler — **separate** FastAPI router (`backend/src/api/routers/mcp_slack_callbacks.py`), **НЕ** часть MCP tool surface
- Tenant isolation enforced (cross-tenant tests из ARG-023 остаются зелёными)
- mypy --strict clean (Cycle 4 baseline 39 source files; ARG-041 + ARG-043 + ARG-044 + ARG-045 + ARG-048 добавят ~30 новых modules — все strict-clean)
- signed manifest `backend/config/mcp/server.yaml` — **НЕ** нужен re-sign (Cycle 5 не добавляет MCP tools/resources/prompts)

### ReportService (Cycle 3+4)

- `ReportService.generate(tenant_id, scan_id, tier, format) → ReportBundle` — единственный public API; не ломаем
- `ReportBundle.sha256` обязательно
- Byte-stable текстовые форматы (HTML / JSON / CSV / SARIF / JUnit); PDF — structural snapshot (Cycle 4 ARG-036 фикс fixed creation_date — но всё равно structural test, не byte-equal)
- ARG-044 SSVC integration в Valhalla `top_findings_by_business_impact` НЕ ломает byte-stability (deterministic sort по KEV → SSVC outcome → CVSSv3 → EPSS)
- ARG-048 LaTeX Phase-2 — sustained snapshot strategy (structural через `pdftotext` text extraction, не byte-equal)

### Observability cardinality (NEW — Cycle 5 invariant)

- Prometheus labels — **whitelist enforcement**: `tenant_id` всегда хэшируется через SHA-256[:16] (никогда raw в labels); запрет per-call UUIDs в labels; max label values per metric < 1000 (Coverage matrix C-future или explicit assertion в `tests/security/test_observability_cardinality.py`)
- OpenTelemetry span attributes — `tenant_id_hash` (НЕ raw `tenant_id`); span events для long-running operations (>1s) — обязательно
- Structured logging — `trace_id` / `span_id` injected via processor (НЕ manual в каждом log call); logs в JSON format (NDJSON), НЕ plaintext

### Helm chart (NEW — Cycle 5 invariant)

- Helm chart use immutable image refs (`@sha256:<digest>`), НЕ tags (`:latest`, `:v1.0`)
- Cosign verify-init container — **mandatory** для каждого sandbox-pod в production (`values.yaml::cosign.verify.enabled=true` для prod); может быть disabled только для dev (`values-dev.yaml::cosign.verify.enabled=false`)
- Никаких plain-text secrets в `values.yaml` — **only** sealed/external references
- NetworkPolicies применяются автоматически (Helm chart applies relevant из Cycle 3 templates per Deployment); НЕ optional

### Alembic migrations (NEW — Cycle 5 invariant)

- Каждая migration — **backwards-compatible** (no destructive ops без explicit `op.execute("ALTER ... DROP COLUMN")` guard); reversible via `downgrade()` (round-trip schema diff = 0)
- Zero-downtime where possible (online schema change strategy: add column nullable → backfill → make NOT NULL в separate migration); explicit comment если migration требует maintenance window
- RLS policies preserved (`ALTER TABLE ... ENABLE ROW LEVEL SECURITY` в каждой new table); FK constraints preserved
- Migration smoke-test (`infra/scripts/migrate_smoke.sh`) — pre-merge gate (CI workflow `migrations-smoke` job)

### Cloud IAM verifiers (NEW — Cycle 5 invariant)

- AWS / GCP / Azure SDK clients — **dependency-injected** через Protocol (`StsClientProtocol`, `GcpIamProtocol`, `AzureCredentialProtocol`); НЕ direct boto3.client(...) instantiation в production code (для testability + mockability)
- Closed-taxonomy `failure_summary` — расширение existing `OWNERSHIP_FAILURE_REASONS` frozenset; НЕ ad-hoc string formatting
- Audit log payload **никогда** не embed'ит raw cloud responses (only sanitized closed-taxonomy summary)
- TTL = 10 minutes sliding window (sustained per cloud; `OwnershipProof.valid_until` field controlled через method-specific TTL config)

---

## 7. Risks + mitigations

### Risk 1: ARG-045 Helm chart underestimated (XL scope, first time greenfield Helm chart for ARGUS)

**Likelihood:** High (Helm charts requiring sub-charts dependencies (Postgres + Redis + MinIO) + cert-manager + sealed-secrets + ServiceMonitor + OTel Operator + HPA — много moving parts; первый production Helm для ARGUS, baseline отсутствует).

**Impact:** ARG-045 не close'ится за 16h → блокирует ARG-047 (e2e capstone требует docker-compose stack как fallback) → блокирует ARG-049 capstone.

**Mitigation:** Worker'у разделить ARG-045 на **3 independent sub-deliverables** (sub-A: Helm chart skeleton + Chart.yaml + 4 deployments + 3 statefulsets через bitnami subcharts; sub-B: Cosign verify-init + ingress + cert-manager + sealed-secrets; sub-C: Alembic 5 migrations + smoke test). Каждый sub-deliverable — independent acceptance criteria; sub-A блокирует ARG-047 ПОЛНОСТЬЮ если не закроется (e2e fallback на existing `infra/docker-compose.yml`); sub-B + sub-C — defer на ARG-049 если timeboxed. **Hard stop:** sub-A complete (Chart.yaml + 4 deployments + lint pass) — иначе блокируем capstone.

### Risk 2: ARG-043 cloud_iam testing without real cloud credentials (testability via mocks может пропустить real-world edge cases)

**Likelihood:** Medium (mocks через injected Protocols покрывают happy path + closed-taxonomy failures, но real-world cloud SDK behavior — eventual consistency, throttling, MFA prompts — не симулируется).

**Impact:** Production deployment с ARG-043 hits cloud SDK edge cases (например AWS STS rate-limiting `Throttling` exception) которые не покрыты unit tests; cloud_iam verification fails in production.

**Mitigation:** Unit tests **обязательно** покрывают closed-taxonomy failures (timeout, auth_invalid, throttling, MFA_required, cross_account_denied) с **real exception types** из cloud SDKs (`botocore.exceptions.ClientError(error_code='Throttling')`, `google.auth.exceptions.RefreshError`, `azure.core.exceptions.ClientAuthenticationError`); integration tests **рекомендованы** через [LocalStack](https://github.com/localstack/localstack) для AWS (Pro tier supports STS) — но НЕ blocking gate (can be deferred to Cycle 6 если LocalStack setup занимает > 4h). Operator runbook (`docs/cloud-iam-ownership.md`) включает **first-deploy smoke** procedure: AWS account + role + trust policy provisioning + manual `OwnershipChallenge` issue + verify outcome.

### Risk 3: ARG-047 e2e flakiness (long-running e2e tests prone to timing issues, network failures, Juice Shop slow startup)

**Likelihood:** High (e2e tests наиболее flaky test category; Juice Shop startup ~30-60s; OAST callback delivery 30-300s wall-time; full scan 8-15 min — много moving parts).

**Impact:** ARG-047 nightly cron CI lane fails periodically (10-20 % failure rate без mitigation), team loses trust in e2e gate, ignores failures, real regressions slip through.

**Mitigation:** Explicit per-phase timeouts (health=120s, scan=1800s, report-gen=300s, oast-callback=600s) **должны** быть generous (3x expected wall-time); retries только на network operations (`curl --retry 3 --retry-delay 5`); deterministic Juice Shop (version pin `bkimminich/juice-shop:v17.0.0` в `infra/docker-compose.e2e.yml`); explicit health probe wait (`docker compose wait juice-shop` если supported); structured failure output (per-phase status в JSON для diagnosability). Если flake rate > 5 % после 2 weeks production — **escalate**: split e2e в 3 smaller tests (health-only, scan-only, report-verification-only) или introduce stable e2e target (custom mock target вместо Juice Shop). **Acceptance:** e2e green 5/5 consecutive runs локально + 3/3 в CI lane перед merging.

### Risk 4: ARG-041 OTel cardinality explosion (`tool_id × tenant_id_hash × status` могут blow Prometheus storage)

**Likelihood:** Medium (157 tools × 1000s tenants × 3 status values = 471 000 unique label combinations — ниже cardinality limits типичных Prometheus deployments [~1M], но без discipline может расти).

**Impact:** Prometheus OOM в production deployments с large tenant counts; storage cost explosion; query latency increase.

**Mitigation:** **Cardinality discipline enforced** через `backend/tests/security/test_observability_cardinality.py` — assertion ≤ 1000 unique values per label (auto-fail если new metric exceeds); `tenant_id` всегда хэшируется через SHA-256[:16] (16 hex chars = 65 536 unique values, bounded); запрет per-call UUIDs в labels (use `trace_id` в OTel attributes, не Prometheus labels); high-cardinality dimensions (per-tool per-tenant breakdowns) — exposed только через OTel spans (хранятся в Tempo, не Prometheus). Operator runbook (`docs/observability.md`) включает Prometheus retention recipe (5d hot + 30d cold через Thanos) и query patterns для tenant-specific dashboards (use Grafana Loki+Tempo correlation вместо Prometheus aggregation).

### Risk 5: ARG-044 EPSS/KEV API rate limits + offline deployment requirement

**Likelihood:** Medium (FIRST.org EPSS API rate-limited ~60 req/min; CISA KEV catalog 1 req/day limit; offline-first deployments — air-gapped customers — не имеют egress к external APIs).

**Impact:** EPSS batch refresh fails при > 10 000 CVE backlog (167 minutes wall-time @ 60 rpm); air-gapped deployments не могут populate `epss_scores` / `kev_catalog` tables → SSVC decision tree degrades к CVSSv3-only fallback.

**Mitigation:** Celery beat schedules **rate-limit aware** (`epss_batch_refresh_task` chunks по 100 CVEs × 60s sleep между chunks → 6000 CVEs/hour; KEV — single batch daily); **distributed lock** (Redis SET NX EX) prevents concurrent refresh conflicts. Air-gapped deployments — `docs/intel-prioritization.md` включает **offline bundle** recipe: `argus-intel-bundle-<date>.tar.gz` (pre-fetched EPSS + KEV snapshots) + import script (`scripts/import_offline_intel.sh bundle.tar.gz`); FindingPrioritizer **gracefully degrades** (если `epss_scores` empty → use SSVC tree only; если `kev_catalog` empty → KEV-listed boost = false; если SSVC inputs missing → CVSSv3-only fallback).

**Deferred to Cycle 6 (per task-budget cap):**

- **ARG-051** Admin Frontend (Backlog §14) — отдельная Next.js admin app (tenants / users / subscriptions / providers health / policies / audit logs / usage metering); XL scope, отдельный frontend track
- **ARG-052** Tenant kill-switch UI (Backlog §8) — kill-switch backend существует (Cycle 1+2), UI tooling нет; M scope
- **ARG-053** Sigstore policy controller for in-cluster admission (Backlog §16.13) — требует ARG-045 Helm chart + Sigstore Policy Controller installation; L scope
- **ARG-054** PDF/A-2u archival profile (Backlog §15) — long-term archival format; S scope
- **ARG-055** Advanced KEV-aware autoscaling (Backlog §6) — HPA custom metric `kev_listed_active_findings` для scale-up; M scope
- **ARG-056** Maintenance window cron + scheduled scan UI (Backlog §1.4) — periodic scans on schedule; M scope
- **ARG-057** Webhook delivery DLQ (Cycle 4 ARG-035 §outOfScopeFollowUps[1]) — failed-after-retries → persisted queue для manual replay; M scope

---

## 8. Verification command (DoD checklist для Cycle 5)

После завершения всех 9 задач оператор может запустить:

```powershell
cd backend

# Catalog signing invariants (sustained from Cycle 1-4)
python -m scripts.tools_sign verify --tools-dir config/tools --signatures config/tools/SIGNATURES --keys-dir config/tools/_keys
python -m scripts.payloads_sign verify --payloads-dir config/payloads --signatures config/payloads/SIGNATURES --keys-dir config/payloads/_keys
python -m scripts.prompts_sign verify --prompts-dir config/prompts --signatures config/prompts/SIGNATURES --keys-dir config/prompts/_keys

# Docs drift (Cycle 5 — расширено: per-image coverage 6/6 + version baseline)
python -m scripts.docs_tool_catalog --check
python -m scripts.export_mcp_openapi --check

# Coverage matrix (16 contracts × 157 tools = 2 540+ cases)
python -m pytest tests/test_tool_catalog_coverage.py -q --tb=short

# Observability suites (Cycle 5 — новые)
python -m pytest tests/unit/core/test_observability.py tests/unit/api/routers/test_providers_health.py tests/unit/api/routers/test_queues_health.py tests/integration/observability tests/security/test_observability_cardinality.py -q --tb=short

# Cloud IAM suites (Cycle 5 — новые)
python -m pytest tests/unit/policy/cloud_iam tests/integration/policy/test_cloud_iam_ownership.py tests/security/test_cloud_iam_no_secret_leak.py -q --tb=short

# EPSS/KEV/SSVC suites (Cycle 5 — новые)
python -m pytest tests/unit/findings/test_epss_persistence.py tests/unit/findings/test_kev_client.py tests/unit/findings/test_kev_persistence.py tests/unit/findings/test_ssvc_full.py tests/unit/findings/test_prioritizer.py tests/unit/celery/tasks/test_intel_refresh.py tests/integration/findings/test_enrichment_pipeline_with_epss_kev_ssvc.py -q --tb=short

# Alembic migration smoke test (Cycle 5 — новый)
python -m pytest tests/integration/migrations/test_alembic_smoke.py -q --tb=short

# MCP Slack callback suite (Cycle 5 — новый)
python -m pytest tests/unit/api/routers/test_mcp_slack_callbacks.py tests/integration/mcp/test_slack_interactive_flow.py tests/security/test_slack_callback_signature_replay_protection.py -q --tb=short

# Hexstrike regression gate (Cycle 5 — новый)
python -m pytest tests/test_no_hexstrike_active_imports.py -q

# LaTeX Phase-2 parity (Cycle 5 — новый, requires_latex marker)
python -m pytest tests/integration/reports/test_latex_phase2_parity.py -q

# Sandbox image profile contracts (Cycle 5 — расширено: +recon +network)
python -m pytest tests/integration/sandbox/test_image_security_contract.py -q

# Lint + type-check + sec scan (Cycle 5 — расширено на cloud_iam + observability)
python -m mypy --strict --follow-imports=silent src/sandbox src/sandbox/parsers src/reports src/mcp src/policy src/policy/cloud_iam src/findings src/core
python -m ruff check src tests
python -m bandit -q -r src

# Frontend
cd ../Frontend
npm run sdk:check
npm run lint
npx tsc --noEmit
npm run build
npm run test  # vitest unit tests
npx playwright test tests/e2e/mcp-tool-runner.spec.ts  # Playwright E2E

# Helm chart validation
cd ..
helm lint infra/helm/argus -f infra/helm/argus/values-dev.yaml
helm lint infra/helm/argus -f infra/helm/argus/values-staging.yaml
helm lint infra/helm/argus -f infra/helm/argus/values-prod.yaml
helm template argus infra/helm/argus -f infra/helm/argus/values-prod.yaml | kubectl apply --dry-run=client -f -

# Image signing verification (sustained from Cycle 4 + расширено на recon/network)
cosign verify --certificate-identity-regexp '^https://github\.com/[^/]+/[^/]+/\.github/workflows/sandbox-images\.yml@refs/heads/main$' --certificate-oidc-issuer https://token.actions.githubusercontent.com ghcr.io/<org>/argus-kali-recon:<latest-tag>
cosign verify --certificate-identity-regexp ... ghcr.io/<org>/argus-kali-network:<latest-tag>

# E2E capstone (опционально, requires_docker_e2e)
bash scripts/e2e_full_scan.sh http://juice-shop:3000

# Meta-validate (Cycle 5 — новый)
python scripts/argus_validate.py
```

Все 18+ команд должны завершиться с **exit code 0**.

---

## 9. Sign-off criteria (Cycle 5 DoD)

Cycle 5 считается закрытым только если:

- [ ] Все 9 задач (ARG-041..ARG-049) ✅ Completed
- [ ] **Observability** — `/health`, `/ready`, `/providers/health`, `/queues/health`, `/metrics` endpoints production-ready; 9 Prometheus metrics families exposed; OTel traces propagate через FastAPI → Celery → sandbox → MCP → ReportService; cardinality bounded (label whitelist enforced)
- [ ] **Frontend MCP integration** — `/mcp` page live (gated за `NEXT_PUBLIC_MCP_ENABLED`); типизированные React hooks работают; E2E test green (Playwright)
- [ ] **Real cloud_iam** — AWS STS / GCP SA JWT / Azure Managed Identity verifiers landed; closed-taxonomy failure summaries (расширены 6 cloud reasons); NetworkPolicy egress allowlist для cloud SDK endpoints
- [ ] **EPSS + KEV + SSVC v2.1** — Celery beat tasks daily refresh; Postgres `epss_scores` + `kev_catalog` tables (через Alembic 023); FindingDTO enrichment populates 5 new fields; FindingPrioritizer KEV-aware ranking; Valhalla executive summary uses prioritizer
- [ ] **Helm chart** — `infra/helm/argus/` Chart 0.1.0 lints clean per all 3 environment values (dev/staging/prod); `kubectl apply --dry-run` clean; CI workflow `helm-lint` job passing
- [ ] **Alembic migrations** — 5 new migrations (019_reports / 020_mcp_audit / 021_mcp_notification_dispatch_log / 022_rate_limiter_state / 023_epss_kev_tables) round-trip clean (upgrade head → downgrade -5 → upgrade head → schema diff = 0); smoke test passing in CI
- [ ] **Hexstrike purge** — `rg -i hexstrike backend/src backend/tests docs ai_docs/develop/plans/2026-04-21* ai_docs/develop/reports/2026-04-20*` → 0 hits (immutable Cycle 1-4 artifacts whitelisted); regression gate test passing
- [ ] **e2e capstone** — `scripts/e2e_full_scan.sh http://juice-shop:3000` runs successfully локально (если Docker available); CI workflow `e2e-full-scan.yml` defined (manual + nightly trigger); 18 reports verified + OAST callback received + Cosign verify exit 0
- [ ] **Cycle 4 known-gap closure** — `argus-kali-recon` + `argus-kali-network` Dockerfiles built + signed + verified; LaTeX Phase-2 wires `_latex/<tier>/main.tex.j2` через `jinja2-latex`; Slack interactive callbacks endpoint live (с signature verify + replay protection)
- [ ] **Coverage matrix** — 16 contracts × 157 tools = **2 540 параметризованных кейсов**, все зелёные (включая C13 + C14 sustained from Cycle 4 + new C15 `tool-yaml-version-monotonic` + C16 `image-coverage-completeness`)
- [ ] **Sandbox image profiles** — 6 / 6 built (`web`, `cloud`, `browser`, `full`, `recon`, `network`); pending images = 0; `docs/tool-catalog.md::Image coverage` section sustained
- [ ] **Catalog signing invariants** — 157 tools / 23 payloads / 5 prompts / 1 MCP manifest = 186 Ed25519-verifiable; 0 drift после full pytest run; sandbox images все Cosign keyless verified
- [ ] **`pytest -q`** (dev-default, no docker) ≥ **12 500 cases PASS** (Cycle 4 baseline 11 934 + Cycle 5 additions ≥ 600)
- [ ] **`mypy --strict`** clean для всех новых модулей (ARG-041 observability + ARG-043 cloud_iam + ARG-044 epss/kev/ssvc + ARG-045 alembic + ARG-048 slack callbacks)
- [ ] **`ruff check`** + **`ruff format --check`** clean для touched files; **`bandit -q`** clean для new modules
- [ ] **`helm lint`** clean для все 3 environment values; **`kubectl apply --dry-run`** clean
- [ ] **`docs/tool-catalog.md`** — синхронен (mapped 98 sustained, heartbeat 59 sustained, built images 6, pending 0)
- [ ] **Sign-off report `ai_docs/develop/reports/2026-04-20-argus-finalization-cycle5.md`** создан (mirror Cycle 4 sign-off структуры; ≥ 800 LoC)
- [ ] **`CHANGELOG.md`** updated с Cycle 5 разделом (per-task entries + cycle closure rollup)
- [ ] **`ai_docs/develop/issues/ISS-cycle6-carry-over.md`** создан с 6-7 ARG-051..ARG-057 priming tasks
- [ ] **Production deployment readiness** — Helm chart можно deploy на real Kubernetes cluster (verified through `kubectl apply --dry-run` + helm lint); cloud_iam verifiers могут validate real AWS/GCP/Azure credentials (verified through unit tests с realistic mock SDKs); observability stack может scrape real Prometheus + Tempo (verified through OTel trace propagation integration test)

**Cycle 5 → Cycle 6 handoff:** ARG-049 capstone генерирует `ai_docs/develop/issues/ISS-cycle6-carry-over.md` с приоритизированным списком: Admin Frontend (XL), Tenant kill-switch UI (M), Sigstore policy controller для in-cluster admission (L), PDF/A-2u archival profile (S), advanced KEV-aware autoscaling (M), maintenance window cron + scheduled scan UI (M), webhook delivery DLQ (M).

---

## 10. Ссылки

- **Backlog (источник истины):** [`Backlog/dev1_.md`](../../../Backlog/dev1_.md)
- **Cycle 4 plan (predecessor):** [`ai_docs/develop/plans/2026-04-19-argus-finalization-cycle4.md`](2026-04-19-argus-finalization-cycle4.md)
- **Cycle 4 report (predecessor):** [`ai_docs/develop/reports/2026-04-19-argus-finalization-cycle4.md`](../reports/2026-04-19-argus-finalization-cycle4.md)
- **Cycle 5 carry-over backlog:** [`ai_docs/develop/issues/ISS-cycle5-carry-over.md`](../issues/ISS-cycle5-carry-over.md)
- **CHANGELOG:** [`CHANGELOG.md`](../../../CHANGELOG.md)
- **Tool catalog (auto-generated):** [`docs/tool-catalog.md`](../../../docs/tool-catalog.md)
- **Coverage gate:** [`backend/tests/test_tool_catalog_coverage.py`](../../../backend/tests/test_tool_catalog_coverage.py)
- **Tool-catalog generator:** [`backend/scripts/docs_tool_catalog.py`](../../../backend/scripts/docs_tool_catalog.py)
- **MCP server doc:** [`docs/mcp-server.md`](../../../docs/mcp-server.md)
- **Report service doc:** [`docs/report-service.md`](../../../docs/report-service.md)
- **Sandbox images doc:** [`docs/sandbox-images.md`](../../../docs/sandbox-images.md)
- **Network policies doc:** [`docs/network-policies.md`](../../../docs/network-policies.md)
- **Testing strategy doc:** [`docs/testing-strategy.md`](../../../docs/testing-strategy.md)
- **CI workflow:** [`.github/workflows/ci.yml`](../../../.github/workflows/ci.yml)
- **Sandbox images CI workflow:** [`.github/workflows/sandbox-images.yml`](../../../.github/workflows/sandbox-images.yml)
- **OpenAPI MCP spec:** [`docs/mcp-server-openapi.yaml`](../../../docs/mcp-server-openapi.yaml)
- **Frontend MCP SDK:** [`Frontend/src/sdk/argus-mcp/`](../../../Frontend/src/sdk/argus-mcp/)
- **Existing OwnershipVerifier (extended in ARG-043):** [`backend/src/policy/ownership.py`](../../../backend/src/policy/ownership.py)
- **Existing observability scaffold (extended in ARG-041):** [`backend/src/core/observability.py`](../../../backend/src/core/observability.py)
- **Existing EPSS client (extended in ARG-044):** [`backend/src/findings/epss_client.py`](../../../backend/src/findings/epss_client.py)
- **Existing SSVC scaffold (extended in ARG-044):** [`backend/src/findings/ssvc.py`](../../../backend/src/findings/ssvc.py)
