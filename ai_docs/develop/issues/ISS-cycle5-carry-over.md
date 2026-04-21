# ISS — Cycle 5 Carry-over Backlog (ARG-041..ARG-047)

**Issue ID:** ISS-cycle5-carry-over
**Owner:** ARGUS Cycle 4 → Cycle 5 transition
**Source:** ARG-040 capstone (`ai_docs/develop/plans/2026-04-19-argus-finalization-cycle4.md` §3 ARG-040)
**Sign-off report:** [`ai_docs/develop/reports/2026-04-19-argus-finalization-cycle4.md`](../reports/2026-04-19-argus-finalization-cycle4.md)
**Status:** In progress — Cycle 5 active (ARG-043 & ARG-044 ✅ Closed; остальные см. plan)
**Priority:** mixed (см. per-item)
**Date filed:** 2026-04-20
**Last updated:** 2026-04-21 (ARG-044 closed)

---

## Context

Cycle 4 (ARG-031..ARG-040) закрыл все шесть направлений плана: ReportService matrix 12/18 → **18/18** (Valhalla tier + branded PDF), heartbeat parsers 89 → **59** (mapped 68 → **98**, catalog coverage 43.3 % → **62.4 %**), supply-chain в production (keyless cosign + GH OIDC + Rekor + verify-gate в CI + GHCR push + blocking Trivy), MCP webhooks (Slack/Linear/Jira) + per-LLM rate-limiter + OpenAPI 3.1 export + auto-generated TS SDK, infra-долги Cycle 3 (4 stale-import follow-ups + apktool drift root-cause), capstone (coverage matrix 12 → **14** контрактов с C13 signature-mtime-stability + C14 tool-yaml-version-field-presence). Final state — 11 934 PASS / 165 SKIP / 0 FAIL на полном backend test suite; 2 230 PASS на coverage matrix gate; 0 raw-secret leak'ов на 1 056 security cases.

Этот документ собирает 7 carry-over пунктов (ARG-041..ARG-047), которые **выявлены и задокументированы внутри Cycle 4 plan §7 Risks → Deferred to Cycle 5**, либо surfaced в per-task worker reports как explicit «Cycle 5 candidate». Сознательно отложены до Cycle 5 (либо для соблюдения task-budget cap = 10, либо потому что требуют отдельных архитектурных решений или внешних интеграций — например, real cloud STS / EPSS API).

Каждый пункт содержит: **title**, **description**, **complexity estimate** (S / M / L / XL), **dependencies**, **source** (какой Cycle 4 task'ой surfaced).

---

## ARG-041 — Observability (OTel spans + Prometheus `/metrics` + health endpoints)

- **Description:** Добавить production-grade observability stack:
  1. **OpenTelemetry tracing** — instrument backend (FastAPI + Celery + sandbox runtime + MCP server + ReportService) через `opentelemetry-instrumentation-{fastapi,celery,sqlalchemy,httpx,asgi}`; OTLP exporter к Tempo / Jaeger; trace propagation через `traceparent` header; per-tool span `argus.sandbox.tool_run` с attributes `tool_id, tenant_id, scan_id, exit_code, duration_ms, finding_count`.
  2. **Prometheus metrics** — четыре counter'а + два histogram'а:
     - `argus_tool_runs_total{tool, category, status}` (counter)
     - `argus_findings_total{severity, category, owasp_top10}` (counter)
     - `argus_oast_callbacks_total{provider, payload_class}` (counter)
     - `argus_llm_tokens_total{provider, model, role}` (counter)
     - `argus_scan_duration_seconds{tier}` (histogram)
     - `argus_report_generation_seconds{tier, format}` (histogram)
  3. **Health endpoints** — `/health` (liveness, no deps), `/ready` (readiness, full deps probe), `/providers/health` (LLM provider health: OpenAI / Anthropic / Gemini availability + circuit breaker state), `/queues/health` (Celery + Redis broker queue depth + worker count), `/metrics` (Prometheus-format).
  4. **Structured logging enhancements** — добавить `trace_id` / `span_id` в каждый log record (через `structlog` processor + OTel context propagator), correlate logs ↔ traces через Tempo/Loki integration.
- **Complexity:** L (≈ 4-5 дней worker-time; OTel instrumentation требует careful trace context propagation через async-await boundaries; Prometheus metrics — boilerplate, но требуют корректной cardinality discipline для `tool_id` × `tenant_id` фактора).
- **Dependencies:** ARG-035 (rate-limiter — `argus_rate_limit_rejections_total` это +1 counter), ARG-039 (MCP server — `mcp_tools_calls_total{tool, tenant}` это +1 counter); все Cycle 4 ✅.
- **Source:** Cycle 4 plan §7 Risk 3 «Observability deferred to Cycle 5»; sign-off report «Known Gaps / Cycle 5 Candidates §1»; Backlog/dev1_md §15.

## ARG-042 — Frontend MCP integration (consume generated TS SDK, replace mock)

- **Description:** Подключить auto-generated TypeScript SDK из ARG-039 (`Frontend/src/sdk/argus-mcp/`) в Frontend pipeline: replace mock'и в `Frontend/src/services/mcp/*.ts`, добавить React hooks (`useMcpTool`, `useMcpResource`, `useMcpPrompt` через `@tanstack/react-query` или `useSWR`), wire bearer-auth + per-tenant headers, добавить interactive tool-runner UI в `/mcp` page (list tools → form-render input schema → invoke → render output). Backward compatibility с существующим REST-based UI сохраняется (MCP — opt-in feature flag `NEXT_PUBLIC_MCP_ENABLED=true`).
- **Complexity:** M (≈ 2-3 дня; SDK уже работает (`tsc --noEmit` clean), задача — wire через React state management; интерактивный UI через `react-jsonschema-form` или custom dispatcher).
- **Dependencies:** ARG-039 (TS SDK ✅), ARG-035 (опционально — для notifications UI).
- **Source:** Cycle 4 plan §7 Risk Deferred §1 «Frontend MCP integration»; ARG-039 worker report «Out-of-scope: Frontend integration → Cycle 5».

## ARG-043 — Real cloud_iam ownership для AWS / GCP / Azure (`OwnershipProof` через STS / IAM)

- **Description:** Заменить `OwnershipProof.cloud_iam` placeholder на real STS / IAM token validation:
  - **AWS:** `OwnershipProof(provider="aws", method="sts_assume_role", arn="arn:aws:iam::<account>:role/<role>", external_id="<uuid>", session_token=...)` — оператор assume-role'нет ARGUS audit role, ARGUS подтверждает identity через `sts:GetCallerIdentity` + verifies trust policy contains tenant_id condition;
  - **GCP:** `OwnershipProof(provider="gcp", method="service_account_jwt", project_id="<id>", audience="argus-prod", jwt=...)` — JWT signed `service_account@<project>.iam.gserviceaccount.com`, audience pin'нут на ARGUS audience, ARGUS validates через `googleapiclient.discovery.build('iamcredentials', ...)`;
  - **Azure:** `OwnershipProof(provider="azure", method="managed_identity", subscription_id="<uuid>", oauth_token=...)` — Managed Identity OAuth token, ARGUS validates через `azure.identity.DefaultAzureCredential` + verifies subscription ownership через `azure-mgmt-resource`.
  Каждый method имеет TTL (sliding window 10 minutes), refresh через operator UI, audit log entry на каждом `OwnershipProof.verify()` call.
- **Complexity:** XL (≈ 5-7 дней; три cloud providers × full SDK integration + STS/IAM trust policy template'ы + UI flow для operator + audit log integration).
- **Dependencies:** Cycle 1+2 `OwnershipProof` Pydantic-модель ✅; cloud SDK deps (`boto3`, `google-cloud-iam`, `azure-identity`) — добавить в `pyproject.toml`.
- **Source:** Cycle 4 plan §7 Risk Deferred §3 «Real cloud_iam ownership»; Backlog/dev1_md §10.

## ARG-044 — EPSS percentile + KEV catalog ingest (full CISA SSVC v2.1 prioritizer)

- **Status:** ✅ Completed (2026-04-21)
- **Plan:** [`ai_docs/develop/plans/2026-04-21-argus-finalization-cycle5.md`](../plans/2026-04-21-argus-finalization-cycle5.md) §ARG-044
- **Worker report:** [`ai_docs/develop/reports/2026-04-21-arg-044-epss-kev-ssvc-prioritizer-report.md`](../reports/2026-04-21-arg-044-epss-kev-ssvc-prioritizer-report.md)

- **Description:** Заменить current severity prioritizer (CVSSv3 + custom heuristics) на full **CISA SSVC v2.1**:
  1. **EPSS (Exploit Prediction Scoring System) ingest** — fetch `https://api.first.org/data/v1/epss?cve=<id>` (1 API call per CVE, batch до 100), cache в Postgres `epss_scores` table с 24h TTL; expose `EPSS.percentile`, `EPSS.score` в `FindingDTO.epss`.
  2. **KEV (Known Exploited Vulnerabilities) catalog** — fetch `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` (single batch, daily refresh), cache в Postgres `kev_catalog` table; mark `FindingDTO.kev_listed: bool` + `FindingDTO.kev_added_date: date`.
  3. **SSVC decision tree** — implement `src/scoring/ssvc.py` с four-axis prioritizer (Exploitation × Automatable × Technical Impact × Mission/Well-being); output `SSVCDecision(action="Track" | "Track*" | "Attend" | "Act", priority="Defer" | "Scheduled" | "Out-of-Cycle" | "Immediate")`; integrate в `FindingPrioritizer` (override CVSSv3-only logic).
  4. **UI integration** — add SSVC badge в Frontend finding cards (4 colors per action), filter/sort findings by SSVC priority, expose в Valhalla executive summary (top-10 findings ranked by SSVC, не по composite score).
- **Complexity:** L (≈ 4 дня; EPSS/KEV ingest — boilerplate + caching strategy; SSVC decision tree — formal algorithm, требует careful unit tests на 4-axis matrix; UI — additional badge component).
- **Dependencies:** Cycle 1 `FindingDTO` ✅; Postgres migrations для `epss_scores` + `kev_catalog` tables; ARG-031 Valhalla executive summary (для SSVC integration).
- **Source:** Cycle 4 plan §7 Risk Deferred §4 «EPSS percentile + KEV catalog ingest»; Backlog/dev1_md §6.

## ARG-045 — Helm chart для production deployment + Alembic migrations для Cycle 4 tables

- **Description:** Production-ready Helm chart `argus/charts/argus/`:
  1. **Three deployments** — `argus-backend` (FastAPI + Celery worker, separate pods), `argus-frontend` (Next.js SSR), `argus-mcp-server` (separate pod для MCP stdio + streamable-http transports);
  2. **Stateful services** — Postgres 15 + pgvector (PVC + StatefulSet), Redis 7 (Sentinel или Cluster для HA), MinIO (S3-compatible для evidence storage);
  3. **Sandbox image references** — values.yaml pin'ит `ghcr.io/<org>/argus-kali-{web,cloud,browser,full}:<sha>` (immutable refs из ARG-034), Cosign verify-init container для каждого sandbox-pod (defence-in-depth — sandbox не стартует, если signature не проверилась);
  4. **Ingress + cert-manager** — automatic Let's Encrypt cert через `cert-manager.io/v1.ClusterIssuer`, NGINX Ingress / Traefik;
  5. **Secrets management** — Sealed Secrets (Bitnami) или External Secrets Operator (Vault / AWS Secrets Manager); никаких plain-text secrets в values.yaml;
  6. **Alembic migrations** — для new Cycle 4 tables: `reports` (ReportBundle persistence — пока in-memory), `mcp_audit` (per-call audit log), `mcp_notification_log` (webhook delivery log), `epss_scores` + `kev_catalog` (если ARG-044 land'ит до этого), `tool_yaml_versions` (history of `version` field bumps).
- **Complexity:** XL (≈ 6-8 дней; Helm chart с 3 deployments + 3 statefulsets + ingress + cert-manager + secrets management — много moving parts; Alembic migrations требуют careful schema design + backward-compat миграционная стратегия для existing dev databases).
- **Dependencies:** ARG-033 (cosign verify ✅, для sandbox-pod init container); ARG-034 (GHCR images ✅); все Cycle 1-4 deployment infra; в идеале ARG-041 (для Prometheus ServiceMonitor / OTel Operator integration).
- **Source:** Cycle 4 plan §7 Risk Deferred §5 «Helm chart + Alembic migrations»; sign-off report «Known Gaps §5».

## ARG-046 — Полный hexstrike purge из docs/tests/code

- **Description:** Cycle 0/1 наследие — ~50 stale references на legacy `hexstrike` tooling в `docs/`, `tests/`, и нескольких `src/recon/*.py` модулях. Cycle 4 ARG-037 закрыл четыре related cleanup'а, но hexstrike-references — отдельный класс. Задача:
  1. **Audit pass** — `rg -i 'hexstrike' --type-add 'cfg:*.{yaml,yml,toml,ini,cfg}' --type=md --type=py --type=ts --type=cfg` → enumerate all references;
  2. **Categorize** — (a) docs comments referencing hexstrike as historical context (keep, mark "deprecated"), (b) tests importing hexstrike modules (delete or rewrite), (c) `src/recon/*.py` modules that wrap hexstrike CLI (delete — replaced by ARG-021/022/029/032 native parsers);
  3. **Delete dead code** — `src/recon/hexstrike_*.py` modules + corresponding tests + fixtures;
  4. **Update docs** — replace hexstrike references in `docs/architecture.md`, `docs/recon-pipeline.md` со ссылкой на current parser-driven pipeline;
  5. **Regression gate** — add `test_no_hexstrike_imports.py` integration test: `assert "hexstrike" not in importlib.metadata.metadata("argus-backend").get_all("Requires-Dist", [])`; `pytest --collect-only -q | rg -c hexstrike == 0`.
- **Complexity:** M (≈ 2-3 дня; audit + careful deletion + docs rewrite; основной риск — accidental deletion работающего legacy code, потому что hexstrike иногда был entry-point для current pipeline).
- **Dependencies:** ARG-032 (parsers batch 4 ✅ — hexstrike functionality fully replaced); ARG-037 (stale-import discipline ✅ — workflow для cleanup batch'ей established).
- **Source:** Cycle 4 plan §7 Risk Deferred §6 «hexstrike purge — Cycle 6 capstone candidate»; sign-off report «Known Gaps §6».

## ARG-047 — DoD §19.4 e2e capstone (`scripts/e2e_full_scan.sh http://juice-shop:3000`)

- **Description:** Final integration test, доказывающий что full ARGUS stack работает end-to-end на live target:
  1. **`scripts/e2e_full_scan.sh <target_url>`** — wrapper script:
     - `docker compose -f infra/docker-compose.e2e.yml up -d` (backend + frontend + Postgres + Redis + MinIO + 4 sandbox images + OWASP Juice Shop как target);
     - Wait for health (`curl backend:8000/ready`, `curl frontend:3000/api/health`);
     - Trigger scan через `POST /scans` с `target_url=$1`, capture `scan_id`;
     - Poll `GET /scans/$scan_id` until `status="completed"` (timeout 30 min);
     - Verify все 18 reports generated через `GET /reports/$scan_id?tier=midgard&format=html` × {midgard, asgard, valhalla} × {html, pdf, json, csv, sarif, junit};
     - Verify OAST callback received (Juice Shop has known SSRF — should trigger OAST DNS callback);
     - Verify `cosign verify ghcr.io/<org>/argus-kali-web:<sha>` exit 0 inside CI (proves keyless signature verifiable from clean checkout);
     - Verify Prometheus `argus_findings_total > 0`, `argus_scan_duration_seconds_bucket{le="600"} > 0`;
     - Tear down (`docker compose down -v`).
  2. **CI integration** — new GitHub Actions job `e2e-full-scan` (manual trigger или nightly cron); requires `requires_docker` runner; results archived as job artifact.
  3. **Acceptance:** all 18 reports byte-stable (text formats) + structurally valid (PDF), all 4 sandbox images verifiable, OAST callback received, no secret leak в any report (re-run security gate против actual scan output).
- **Complexity:** XL (≈ 6-8 дней; full e2e infrastructure setup + Juice Shop target + OAST callback verification + 18-report verification matrix + CI integration; основная сложность — flaky-test prevention в long-running e2e).
- **Dependencies:** **все Cycle 1-4** (full stack должен быть production-ready); ARG-031 ✅ (18/18 reports), ARG-033 ✅ (cosign verify), ARG-034 ✅ (GHCR images), ARG-041 (Prometheus metrics — для verification step), ARG-045 (Helm chart — опционально, можно через docker-compose).
- **Source:** Cycle 4 plan §7 Risk Deferred §7 «e2e capstone — Cycle 6»; sign-off report «Known Gaps §7»; Backlog/dev1_md §19.4.

---

## Suggested Cycle 5 phasing

Если Cycle 5 идёт ~5 недель (как Cycle 3 и Cycle 4), грубое разбиение:

- **Week 1:** ARG-041 (observability OTel + Prometheus, L, primary) + ARG-042 (Frontend MCP, M, parallel) + ARG-046 (hexstrike purge, M, parallel) — три задачи параллельно, относительно независимые.
- **Week 2:** ARG-044 (EPSS + KEV + SSVC, L, primary) — нужен после ARG-041 для full observability на новых ingester'ах; ARG-043 (cloud_iam, XL, can start parallel но требует careful design week).
- **Week 3:** ARG-043 (cloud_iam продолжается, XL) + ARG-045 (Helm chart + Alembic, XL, primary) — обе требуют senior infra time.
- **Week 4:** ARG-045 завершается + ARG-047 (e2e capstone, XL) — нужен полный stack ARG-041/045 для e2e.
- **Week 5:** ARG-047 e2e capstone + Cycle 5 capstone (mirror ARG-040 / ARG-030 структуры) — coverage matrix expansion (14 → 16 контрактов? кандидаты: **C15 — `tool-yaml-version-monotonic`** (semver bumps только вверх, не вниз), **C16 — `image-coverage-completeness`** (каждый tool_id обязан быть pinned в ≥1 sandbox image)); регенерация `docs/tool-catalog.md`; Cycle 5 sign-off report; CHANGELOG rollup; Cycle 6 carry-over.

**Total estimated hours:** L (4-5d) + M (2-3d) + L (4d) + XL (5-7d) + XL (6-8d) + M (2-3d) + XL (6-8d) ≈ **40-50 person-days** (sum of all task estimates). Параллелизация уменьшает critical-path до **~25 days wall-time** при 3-4 параллельных worker'ах.

---

## Cycle 5 entry conditions (gate from Cycle 4 sign-off)

✅ **All preconditions met as of 2026-04-20:**

- ✅ Все 10 Cycle 4 задач (ARG-031..ARG-040) Completed
- ✅ ReportService 18 / 18 ячеек матрицы
- ✅ Mapped parsers ≥ 98 / heartbeat ≤ 59 (DoD §19.6 catalog coverage > 60 % — target hit at 62.4 %)
- ✅ Coverage matrix 14 контрактов × 157 tools = 2 198+ кейсов (с C13 + C14)
- ✅ Supply-chain: GHCR push live, cosign keyless live, verify-job blocking, Trivy blocking
- ✅ MCP webhooks + rate-limiter live (feature-gated)
- ✅ MCP OpenAPI spec published + TS SDK auto-generated + 3 CI gates
- ✅ Test infra cleanup: 4 stale-import issues + 1 apktool-drift issue closed
- ✅ Read-only catalog session fixture enforced (защита от Cycle-3-style mid-run mutation)
- ✅ Все 157 tool YAMLs имеют `version: <semver>` field
- ✅ `pytest -q` dev-default (no docker) — 11 934 PASS / 165 SKIP / 0 FAIL
- ✅ Catalog signing инвариант: 157 + 23 + 5 = 185 Ed25519-verifiable; 0 drift после full pytest run

Cycle 5 готов стартовать на следующей неделе. ARG-041 (Observability) — рекомендуемый primary первой недели.
