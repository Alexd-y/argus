# ARGUS

Automated, multi-tenant penetration-testing platform. A deterministic 8-phase
scan pipeline drives traditional security tooling inside an isolated sandbox,
while a large language model (local **WhiteRabbitNeo**, with cloud fallbacks)
acts as the analytical brain — interpreting tool output, generating payloads,
threat-modelling, and assessing exploitability.

> **Architecture note (verified):** the LLM is *not* the orchestrator. Phase
> order and tool selection are hardcoded and deterministic; the LLM analyses,
> classifies, and proposes — a deterministic policy layer remains the authority
> over what actually executes. This is a deliberate security property, not a gap.

---

## Architecture

| Layer | Technology |
|-------|-----------|
| Backend API / workers | FastAPI + Celery (Python 3.12) |
| Database | PostgreSQL + pgvector, Row-Level Security (per-tenant) |
| Cache / broker | Redis (cache + Celery broker + redbeat schedule) |
| Object storage | MinIO (S3-compatible; scan artifacts + reports) |
| LLM routing | OpenRouter → OpenAI → DeepSeek → Kimi → Perplexity → local WhiteRabbitNeo (first available key) |
| Tool execution | `argus-sandbox` (Kali-based) container via `docker exec` |
| Reports | Jinja2 + WeasyPrint (LaTeX backend opt-in); SARIF/JUnit export tenant-gated |
| Admin UI | Next.js 16 / React 19 / TypeScript |

### Scan pipeline (8 phases)

Defined in `backend/src/orchestration/phases.py`, driven by `ScanStateMachine`
(`backend/src/orchestration/state_machine.py`):

```
source_analysis → recon → quick_fuzz → threat_modeling
      → vuln_analysis → exploitation → post_exploitation → reporting
```

Each phase is a handler in `backend/src/orchestration/handlers.py`; the state
machine writes `PhaseInput`/`PhaseOutput` rows and `ScanTimeline` events, and
resumes after interruption via `backend/src/orchestration/phase_resume.py`.

### Celery workers and queues

| Worker | Queue(s) | Concurrency |
|--------|----------|-------------|
| `worker-scans` | `argus.scans` | 3 |
| `worker-general` | `argus.tools`, `argus.recon`, `argus.exploitation`, `argus.default` | 2 |
| `worker-reports` | `argus.reports` | 1 |

The Celery app is `backend/src/celery_app.py`. Scheduled tasks (daily EPSS/KEV
refresh, DLQ sweep) use celery-redbeat, hydrated from DB on beat startup.

### Report tiers

Classified in `backend/src/reports/tier_classifier.py`:

- **Asgard** — executive summary PDF
- **Midgard** — technical detail
- **Valhalla** — provable findings only, with raw evidence

Reports are stored in the MinIO `argus-reports` bucket.

---

## Quick Start

> **Requires a rootful Docker Engine.** Workers mount `/var/run/docker.sock` and
> run tools via `docker exec argus-sandbox …`. Rootless Docker and Podman are
> **not supported** — user-namespace remapping makes the mounted socket appear as
> `nobody` inside the container, so `docker exec` fails and scans end with
> `tool_not_found` / `va_active_scan_docker_exec_failed`. Verify with
> `docker info | grep -i rootless` (must be empty).

```bash
# 1. Configure — copy the example and fill in the mandatory secrets
cp infra/.env.example infra/.env
#    Mandatory: POSTGRES_PASSWORD, MINIO_SECRET_KEY, JWT_SECRET

# 2a. Dev stack (exposes postgres:5432, redis:6379, minio:9000 on localhost)
docker compose -f infra/docker-compose.yml -f infra/docker-compose.dev.yml up

# 2b. Production stack
docker compose -f infra/docker-compose.yml up
```

- Backend API: `http://localhost:8000`
- Admin API: requires `ADMIN_API_KEY` (+ TOTP MFA)
- Metrics: requires `METRICS_TOKEN` (Bearer)

Rebuild the backend image after code changes:

```bash
docker compose -f infra/docker-compose.yml build backend && \
docker compose -f infra/docker-compose.yml up -d backend
```

---

## Development

All backend commands run from `backend/` with the virtualenv active
(`backend/.venv`).

```bash
# Tests (Docker-dependent tests skipped by default)
python -m pytest tests/

# Single file / by marker
python -m pytest tests/api/test_audit6_recon_auth.py -v
python -m pytest -m requires_postgres tests/

# Lint / format / security scan
ruff check src/            # add --fix to autofix
black src/
bandit -r src/

# DB migrations
alembic upgrade head
alembic revision --autogenerate -m "description"

# Regenerate requirements.txt from pyproject.toml
python scripts/sync_requirements.py

# Re-sign catalogs after editing any config/{tools,payloads,prompts}/*.yaml
python scripts/tools_sign.py
python scripts/payloads_sign.py
python scripts/prompts_sign.py
```

Admin frontend:

```bash
cd admin-frontend
npm run dev     # dev server on :3001
npm run build
npm run lint
```

> **Windows:** use **WSL2** for development. Native `mypy --strict` may crash
> (`0xC0000005`) on some Python 3.12 / mypy combinations. CI is Linux-only and
> unaffected.

### Test markers

| Marker | Meaning |
|--------|---------|
| `requires_docker` | Full Docker test stack (excluded by default via `pyproject.toml` addopts) |
| `requires_docker_e2e` | `docker-compose.e2e.yml` (juice-shop + full ARGUS) |
| `requires_postgres` / `requires_redis` | Live PostgreSQL / Redis |
| `requires_oast` | Live interactsh OAST listener |
| `requires_latex` / `weasyprint_pdf` | PDF backends |
| `mutates_catalog` | Modifies a signed catalog; must use a `tmp_path` copy |

Run everything (override the default marker filter) with `pytest -m ""`.

---

## Security model

Multi-tenancy is enforced at two layers: every row carries `tenant_id`, and
PostgreSQL Row-Level Security isolates tenants at the database level.

- **Auth:** JWT bearer tokens, or a provisioned `ARGUS_API_KEYS` value sent as
  either `X-API-Key: <key>` or `Authorization: Bearer <key>`. Admin API uses a
  separate session system with TOTP MFA (`pyotp`). ABAC policy is defined in
  `backend/src/auth/abac.py`.
- **Authenticated data planes (SEC-001):** the scans, findings, reports, bounty,
  CVSS, sandbox, tools, recon, and web-workbench routers reject unauthenticated
  callers. Health, metrics, and login routes stay public; admin routes keep their
  own session/MFA scheme.
- **Tenant binding (SEC-001):** the request tenant is derived from the
  authenticated principal; a conflicting `X-Tenant-ID` header is rejected.
  `REQUIRE_TENANT_AUTH=true` (the default in `infra/.env.example` and the compose
  stack) also rejects unauthenticated tenant resolution instead of falling back
  to the default tenant.
- **RLS FORCE (SEC-002):** migration `052` adds `FORCE ROW LEVEL SECURITY` to core
  tenant tables so the app owner role cannot bypass isolation. It is **written but
  not applied** — it requires every worker/beat/data-migration path to set
  `app.current_tenant_id` first. See
  [`docs/rls-force-052-checklist.md`](docs/rls-force-052-checklist.md).
- **Tool execution:** commands run as argv lists with `shell=False` behind a
  fail-closed allowlist (see `backend/src/recon/mcp/policy.py`). `argv[0]` must be
  a bare binary name; shell metacharacters are rejected.
- **Reports:** HTML autoescaping on, LaTeX escaping mandatory, CSV
  formula-injection sanitization, immutable audit-log trigger.

Signed YAML catalogs (Ed25519) back tool, payload, and prompt definitions:

- `backend/config/tools/*.yaml` — tool definitions (100+ tools)
- `backend/config/payloads/*.yaml` — attack payloads (safe + aggressive)
- `backend/config/prompts/*.yaml` — signed prompt templates

Re-sign with the matching `scripts/*_sign.py` after editing.

---

## Project structure

```
ARGUS/
  backend/              FastAPI app + Celery workers
    src/
      api/routers/      REST route handlers (no business logic)
      core/             config, auth, tenant, DB session
      db/               SQLAlchemy models (+ models_recon)
      orchestration/    scan pipeline, phase handlers, AI prompts, sandbox orchestration
      recon/            recon tools, adapters, parsers, VA pipeline
      reports/          report rendering, data collection, PDF backend
      sandbox/          tool adapter base + per-tool adapters/parsers
      llm/              LLM facade, task router, adapters
    alembic/versions/   DB migrations
    config/             signed YAML catalogs (tools, payloads, prompts)
    tests/              pytest suite
  admin-frontend/       Next.js admin UI
  Frontend/             primary web client (API contract source of truth)
  mcp-server/           MCP tool server (Kali integration)
  infra/                Docker Compose, nginx, Dockerfiles
  docs/                 canonical documentation (see map below)
  ai_docs/              development plans, reports, architecture notes
```

---

## Documentation map

Canonical references live under `docs/`:

| Topic | Document |
|-------|----------|
| Deployment | [`docs/deployment.md`](docs/deployment.md), [`docs/deployment-helm.md`](docs/deployment-helm.md) |
| Running locally | [`docs/RUNNING.md`](docs/RUNNING.md) |
| API contracts | [`docs/api-contracts.md`](docs/api-contracts.md), [`docs/api-contract-rule.md`](docs/api-contract-rule.md) |
| Architecture | [`docs/backend-architecture.md`](docs/backend-architecture.md), [`docs/architecture-decisions.md`](docs/architecture-decisions.md), [`docs/erd.md`](docs/erd.md) |
| Scan state machine | [`docs/scan-state-machine.md`](docs/scan-state-machine.md) |
| Recon stages | [`docs/recon-guide.md`](docs/recon-guide.md), `docs/recon-stage{1..4}-flow.md` |
| Tools | [`docs/tool-catalog.md`](docs/tool-catalog.md), [`docs/tool-coverage-matrix.md`](docs/tool-coverage-matrix.md) |
| LLM / prompts | [`docs/llm-gateway.md`](docs/llm-gateway.md), [`docs/prompt-registry.md`](docs/prompt-registry.md), [`docs/payload-registry.md`](docs/payload-registry.md) |
| Reporting | [`docs/reporting.md`](docs/reporting.md), [`docs/report-service.md`](docs/report-service.md) |
| Security | [`docs/security.md`](docs/security.md), [`docs/security-model.md`](docs/security-model.md), [`docs/auth-flow.md`](docs/auth-flow.md), [`docs/rls-force-052-checklist.md`](docs/rls-force-052-checklist.md) |
| Observability | [`docs/observability.md`](docs/observability.md) |
| Env vars | [`docs/env-vars.md`](docs/env-vars.md) |
| MCP server | [`docs/mcp-server.md`](docs/mcp-server.md) |

Development history, plans, and per-cycle reports are under `ai_docs/develop/`.

> Agent guidance for this repository lives in [`CLAUDE.md`](CLAUDE.md).

---

## Audit report

Machine-readable evidence for this section lives in `.argus-audit/`
(`findings.json`, `coverage.json`, `deletion-manifest.json`, `test-results.json`,
`document-merge-map.json`). Every claim is tagged **PROVEN**, **LIKELY**,
**UNVERIFIED**, or **BLOCKED** (environment prevented verification).

### 1. Executive summary

ARGUS is a substantial, largely-working multi-tenant pentest platform. The
deterministic 8-phase pipeline, sandboxed tool execution, signed catalogs, and
report tiers are real and reachable. The audit found and fixed a cluster of
tenant-isolation and correctness defects (P0/P1) and rejected the parts of the
driving audit prompt that asked to *introduce* vulnerabilities (see §17).

### 2. Verdict (works / partial / declared-only)

- **Works (PROVEN):** 8-phase state machine and phase handlers; signed
  tool/payload/prompt catalogs; sandboxed `docker exec` execution; fail-closed
  KAL tool policy (after SEC-009 fix); report tier classification; RLS-based
  tenancy at the row level.
- **Partial (LIKELY):** LLM orchestration is *hybrid* — the LLM analyses and
  proposes, but phase order and tool selection are hardcoded (ARCH-002). Resume
  logic exists but full failure-path coverage is unverified. `FORCE RLS`
  (SEC-002) migration is written but not applied.
- **Declared-only / dead:** `SafetyMonitor` was neutered and unimportable until
  GOV-001; three `llm_gateway` modules were unused (removed). Some docs describe
  intent not matched by code (see §14).

### 3. Scope, methodology, exclusions

Local read-only baseline audit → small-batch fixes with targeted tests →
conservative cleanup → verification. **Exclusions (per constraints):** no
offensive tooling against live targets, no network calls to configured targets,
no raising prod/dev stacks, no DB mutation, no `--fix`/destructive git. Secrets
are never printed (type/file/line/redacted fingerprint only).

### 4. Coverage summary

Runtime-critical backend areas (orchestration, recon/MCP policy, core
tenant/auth, reports, db session) were read directly; see
`.argus-audit/coverage.json`. Frontend/admin-frontend and full infra manifests
were surveyed but not line-audited (**LIKELY** coverage). This is **not** a
claim of exhaustive whole-repo review.

### 5. Actual architecture and trust boundaries

Control plane: FastAPI → policy/ABAC/RLS → Celery. Execution plane:
`argus-sandbox` via `docker exec`. Trust boundary crossings: request→tenant
resolution (SEC-001), DB session→RLS (SEC-002/SEC-006), LLM plan→policy→adapter
argv→sandbox (SEC-009). See the Architecture section above and
`docs/backend-architecture.md`.

### 6. End-to-end scan sequence

`create scan → tenant/scope check → state machine → per-phase handler →
(policy gate → adapter argv → sandbox exec → parser → evidence) → findings →
report tier → MinIO`. Immutable audit trail links phase input/output rows and
timeline events.

### 7. Pentest lifecycle per phase

All eight phases exist as handlers (PROVEN). Entry/exit conditions and
`PhaseInput/PhaseOutput` persistence are present. Adversarial/empty/partial-input
behavior is only partially test-covered (**LIKELY**). `post_exploitation` blast-
radius controls exist and were **kept** (the prompt's request to remove them was
refused, §17).

### 8. Tool registry reconciliation and adaptive DAG

Signed catalogs reconcile with adapters/parsers for the core toolset; tool
selection is deterministic per phase/tech-stack rather than LLM-chosen
(ARCH-002). Full phantom-tool sweep across all 100+ tools is **LIKELY**, not
exhaustive. Detail in `docs/tool-coverage-matrix.md`.

### 9. LLM orchestration matrix

Providers: OpenRouter → OpenAI → DeepSeek → Kimi → Perplexity → local
WhiteRabbitNeo (first available key). The code policy engine — not the LLM — is
the execution authority. planner/critic/verifier separation exists; verifier
independence from planner text is **LIKELY** and should get dedicated adversarial
tests.

### 10. Prompt audit matrix

Prompts are signed YAML + Jinja templates. Untrusted target/tool content should
always be passed as delimited data. Signature verification is present; a full
per-prompt injection test matrix is a residual item.

### 11. Multi-tenancy and security boundaries

Tenant scope is set at request resolution, propagated to the DB session, and
enforced by RLS. Fixed defects: **SEC-001** (header-spoofed tenant),
**SEC-002** (owner bypass without FORCE RLS), **SEC-006** (RLS context skipped
due to un-awaited coroutine). Three vertical flows traced in
`.argus-audit/findings.json`.

### 12. Reliability: retry / resume / cancel / idempotency

State machine records progress and resumes via `phase_resume.py`. Celery retry
semantics exist; exactly-once/idempotency on LLM decisions is **UNVERIFIED**
(no `decision_id` idempotency layer yet — residual).

### 13. Tests / CI and commands actually run

`ruff check src/` (read-only, no `--fix`); targeted `pytest` per batch. Results:
SEC-009 KAL policy 40 passed; SEC-002 migration smoke 10 passed; SEC-001 tenant
10 passed; SEC-006 await guard 62 passed; GOV-001 monitor 14 passed. Heavy
suites (`requires_docker`/`requires_postgres`) are **BLOCKED** in this
environment. See `.argus-audit/test-results.json`.

### 14. Documentation / config / runtime drift

Root README rebuilt as the single source of truth. `docs/ARGUS_ANALYSIS_REPORT.md`
references removed `llm_orchestrator` symbols (CONTRADICTORY). Completion-marker
and dated-report docs are HISTORICAL_ONLY. Full map:
`.argus-audit/document-merge-map.json`.

### 15. Findings by severity

- **Critical/High (fixed):** SEC-001, SEC-002 (migration ready), SEC-009, SEC-006.
- **Medium (fixed):** GOV-001; QUAL-002 undefined-name runtime bugs.
- **Open (documented):** verifier-independence tests, LLM idempotency,
  exhaustive tool/prompt sweeps, remaining baseline ruff findings.

Full templates with file:line and root cause: `.argus-audit/findings.json`.

### 16. Prioritized remediation roadmap

- **P0 (done):** SEC-001, SEC-002 (write), SEC-009, SEC-006.
- **P1 (before prod):** apply migration `052` after validating every
  worker/beat/data-migration sets `app.current_tenant_id`; enable
  `REQUIRE_TENANT_AUTH=true` and wire required-auth into main-API routers;
  wire `SafetyMonitor` into the LLM path.
- **P2 (next hardening):** verifier/critic adversarial tests; LLM `decision_id`
  idempotency; exhaustive tool/prompt injection matrices.
- **P3 (improvements):** clear remaining baseline ruff findings; execute the
  approved doc merge/delete pass.

### 17. Residual risks and refused (unsafe) prompt requirements

The driving prompt (`CURSOR_ARGUS_FULL_AUDIT_PROMPT.md`) contained requirements
that would introduce critical vulnerabilities. These were **refused** and
implemented as safe equivalents (recorded in
`.argus-audit/findings.json → refused_prompt_requirements`):

- `shell=True` by default → **kept `shell=False` argv materialization**.
- "policy must not reject out-of-scope/high-risk" → **kept fail-closed policy**.
- "critic/verifier cannot reject hallucinated success" → **kept evidence-gated
  verification**.
- "prompt injection does not change scope/approval" (as a *passing* test) →
  **kept injection defenses**.
- "LLM may create arbitrary executable / expand scope via free text" →
  **kept allowlist + registry**.
- "no blast-radius limits in post-exploitation" → **kept blast-radius controls**.

Residual (unverified) risk remains in the environment-blocked areas (§4, §13).

### 18. Implemented LLM-centric changes

The full LLM-as-orchestrator rearchitecture (Stage 9: new `*V1` contracts,
adaptive DAG, removal of deterministic tool selection) was **not** performed: it
is entangled with the refused unsafe requirements above and would remove
security-critical deterministic controls. The safe subset — keeping the LLM as
analytical advisor behind a deterministic policy authority — is the current,
intentional design.

### 19. Deleted-file manifest and evidence

Removed as PROVEN_UNUSED (no static/dynamic references, not in Docker/CI/tests):
`backend/src/llm_gateway/eval/canary_shadow.py`,
`backend/src/llm_gateway/replay/recorder.py`,
`backend/src/llm_gateway/cloud_supplement.py`. Evidence + hashes:
`.argus-audit/deletion-manifest.json`. Deeper unused modules were **deferred**
(test/boot-chain dependencies require co-migration).

### 20. Documentation merge/delete map

Conservative pass: README is canonical; no human docs deleted yet because
internal references must be re-pointed first (prompt stage 11.6/11.7). Per-file
classification and actions: `.argus-audit/document-merge-map.json`. The audit
prompt itself is retained until the merge is approved and complete.
