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

- **Auth:** JWT bearer tokens or `X-API-Key`. Admin API uses a separate session
  system with TOTP MFA (`pyotp`). ABAC policy is defined in `backend/src/auth/abac.py`.
- **Tenant binding (SEC-001):** the request tenant is derived from the
  authenticated principal; a conflicting `X-Tenant-ID` header is rejected. Set
  `REQUIRE_TENANT_AUTH=true` in production to reject unauthenticated main-API
  requests instead of falling back to the default tenant.
- **RLS FORCE (SEC-002):** core tenant tables enforce `FORCE ROW LEVEL SECURITY`
  so the app owner role cannot bypass isolation (migration `052`). Applying it
  requires that every worker/beat/data-migration path sets `app.current_tenant_id`.
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
| Security | [`docs/security.md`](docs/security.md), [`docs/security-model.md`](docs/security-model.md), [`docs/auth-flow.md`](docs/auth-flow.md) |
| Observability | [`docs/observability.md`](docs/observability.md) |
| Env vars | [`docs/env-vars.md`](docs/env-vars.md) |
| MCP server | [`docs/mcp-server.md`](docs/mcp-server.md) |

Development history, plans, and per-cycle reports are under `ai_docs/develop/`.

> Agent guidance for this repository lives in [`CLAUDE.md`](CLAUDE.md).
