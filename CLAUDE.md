# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Backend (Python 3.12, FastAPI)

All backend commands run from inside `backend/` with the virtualenv active (`backend/.venv`).

```bash
# Run tests (Docker-dependent tests skipped by default)
cd backend && python -m pytest tests/

# Run a single test file
cd backend && python -m pytest tests/api/test_audit6_recon_auth.py -v

# Run tests by marker (e.g. only postgres-required)
cd backend && python -m pytest -m requires_postgres tests/

# Lint
cd backend && ruff check src/
cd backend && ruff check src/ --fix

# Format
cd backend && black src/

# Security scan
cd backend && bandit -r src/

# DB migrations (apply)
cd backend && alembic upgrade head

# DB migrations (create new revision)
cd backend && alembic revision --autogenerate -m "description"

# Regenerate requirements.txt from pyproject.toml
cd backend && python scripts/sync_requirements.py

# Sign payload/tool/prompt catalogs after editing YAML
cd backend && python scripts/payloads_sign.py
cd backend && python scripts/tools_sign.py
cd backend && python scripts/prompts_sign.py
```

### Infrastructure (Docker Compose)

All compose commands run from the repo root; compose files live in `infra/`.

```bash
# Dev stack (exposes postgres:5432, redis:6379, minio:9000 on localhost)
docker compose -f infra/docker-compose.yml -f infra/docker-compose.dev.yml up

# Production stack
docker compose -f infra/docker-compose.yml up

# Rebuild backend image after code changes
docker compose -f infra/docker-compose.yml build backend && docker compose -f infra/docker-compose.yml up -d backend

# Run e2e tests (requires full stack from docker-compose.e2e.yml)
docker compose -f infra/docker-compose.e2e.yml up -d
cd backend && python -m pytest -m requires_docker_e2e tests/
```

Required `infra/.env`: copy from `infra/.env.example`. Mandatory vars: `POSTGRES_PASSWORD`, `MINIO_SECRET_KEY`, `JWT_SECRET`.

### Admin Frontend (Next.js 16 / React 19 / TypeScript)

```bash
cd admin-frontend && npm run dev    # dev server on :3001
cd admin-frontend && npm run build  # production build
cd admin-frontend && npm run lint   # ESLint
```

## Architecture

### Scan Pipeline (8 Phases)

The core abstraction is a linear 8-phase pentest pipeline defined in `backend/src/orchestration/phases.py`:

```
source_analysis → recon → quick_fuzz → threat_modeling → vuln_analysis → exploitation → post_exploitation → reporting
```

`ScanStateMachine` (`backend/src/orchestration/state_machine.py`) drives phase transitions, writes `PhaseInput`/`PhaseOutput` rows, and records `ScanTimeline` events. Each phase is implemented as a handler function in `backend/src/orchestration/handlers.py`. Phase resume after interruption is handled in `backend/src/orchestration/phase_resume.py`.

### Celery Workers and Queues

Tasks are routed to dedicated Celery queues; workers are split by concern in `docker-compose.yml`:

| Worker | Queue(s) | Concurrency |
|--------|----------|-------------|
| `worker-scans` | `argus.scans` | 3 |
| `worker-general` | `argus.tools`, `argus.recon`, `argus.exploitation`, `argus.default` | 2 |
| `worker-reports` | `argus.reports` | 1 |
| `worker-intruder` | `argus.intruder.highvol` | 2 |

Queues `argus.intel` and `argus.notifications` are consumed by the beat process for scheduled housekeeping (EPSS/KEV refresh, DLQ replay, metrics). The complete routing table is defined in `backend/src/celery_app.py` `task_routes` (9 queues total).

The Celery app is defined in `backend/src/celery_app.py`. Scheduled tasks (daily EPSS/KEV refresh, DLQ sweep) use celery-redbeat with schedule hydrated from DB on beat startup.

### Sandbox Execution

Active scan tools (nmap, nuclei, dalfox, ffuf, sqlmap, etc.) run inside an `argus-sandbox` container (Kali-based). The `backend`, `worker-scans`, and `worker-general` services mount `/var/run/docker.sock:ro` to run tools via `docker exec`. The `:ro` flag protects the socket file only — the Docker API behind it stays fully capable, so socket access is still host-level privilege (see `docs/security.md`). Each tool has:
- An **adapter** in `backend/src/sandbox/adapters/` — builds the command
- A **parser** in `backend/src/sandbox/parsers/` — parses stdout into findings

VA active scan adapters live in `backend/src/recon/vulnerability_analysis/active_scan/`.

### LLM Integration

LLM routing is handled by `backend/src/llm/facade.py` (`call_llm_unified`). Routing priority (WRB-001):

- **WhiteRabbitNeo (WRB)** — PRIMARY for all pentest analysis tasks (orchestration, threat modeling, vuln analysis, exploitation, validation). Runs locally via vLLM (`argus-whiterabbitneo` container), zero-cost.
- **Cloud models (DeepSeek, OpenAI, OpenRouter)** — FALLBACK for report generation, executive summaries, cost summaries only. Pentest analysis tasks have NO cloud fallback.
- **Perplexity** — OSINT tasks only (WRB has no internet access).

### Report Tiers

Reports are generated in three tiers (classified in `backend/src/reports/tier_classifier.py`):
- **Asgard** — executive summary PDF (`backend/src/reports/asgard_tier_renderer.py`)
- **Midgard** — technical detail
- **Valhalla** — provable findings only, raw evidence (`backend/src/reports/valhalla_tier_renderer.py`)

PDF generation uses WeasyPrint by default; LaTeX backend is opt-in via `REPORT_PDF_BACKEND=latex`. SARIF and JUnit export are tenant-gated. Reports are stored in MinIO (`argus-reports` bucket).

### Database

PostgreSQL with pgvector. SQLAlchemy async (asyncpg driver). Core models are in `backend/src/db/models.py`; recon-specific models in `backend/src/db/models_recon.py`. All tables use `String(36)` UUIDs (not native Postgres UUID type). Row-level security is enabled — see migration `002_rls_and_audit_immutable.py`.

Migrations in `backend/alembic/versions/` (44+ revisions). The alembic env uses `async_engine_from_config`; the smoke test requires `aiosqlite`.

### YAML Catalogs

Tool definitions, payload sets, and LLM prompts are stored as signed YAML catalogs:
- `backend/config/tools/*.yaml` — tool definitions (100+ tools)
- `backend/config/payloads/*.yaml` — attack payloads (safe + aggressive variants)
- `backend/config/prompts/*.yaml` — signed prompt templates (planner, critic, verifier, etc.)

After editing any catalog file, re-sign with the corresponding `scripts/*_sign.py` script. Tests in `backend/tests/integration/payloads/test_signatures_no_drift.py` verify catalog integrity.

### Auth

JWT-based auth with `X-API-Key` header alternative. Admin API uses a separate session system with TOTP MFA (`pyotp`). ABAC policy enforcement is in `backend/src/auth/abac.py`. Multi-tenancy: every DB row carries `tenant_id`; RLS enforces isolation at the Postgres level.

### Key Module Boundaries

- `backend/src/api/routers/` — FastAPI route handlers (no business logic)
- `backend/src/orchestration/` — scan pipeline, phase handlers, AI prompts, sandbox orchestration
- `backend/src/recon/` — reconnaissance tools, adapters (intel + security), parsers, VA pipeline
- `backend/src/reports/` — report rendering, data collection, PDF backend
- `backend/src/sandbox/` — tool adapter base + individual tool adapters/parsers for sandbox exec
- `backend/src/db/` — SQLAlchemy models and session management
- `backend/app/schemas/` — Pydantic schemas shared with the `app/` layer
- `backend/config/` — YAML catalogs (tools, payloads, prompts)
- `admin-frontend/src/app/` — Next.js App Router pages (admin UI)

### Exploitation Orchestration Components

**ReAct Agent** (`backend/src/orchestration/react_agent.py`): Multi-step "Thought → Action → Observation" iterative reasoning loop used in VULN_ANALYSIS and EXPLOITATION phases. Replaces single-shot LLM calls with 5-10 iteration cycles where the agent thinks about next steps, invokes tools, observes results, and repeats until confident. Controlled by `use_react=True` in scan options; defaults to 0.85 confidence threshold (stops early when exceeded) and 10 max iterations. Produces a `ReActResult` with answer, confidence, tools used, and trace of `ReActStep` records. Uses regex-based parsing of LLM responses for Thought/Action/Final Answer blocks with graceful fallback.

**Exploitation Queue** (`backend/src/orchestration/exploitation_queue.py`): Pydantic-based structured contract between vuln analysis and exploitation phases. Each `ExploitHypothesis` carries strongly-typed, machine-readable fields: vulnerability type (`FindingCategory` → auto-derived to OWASP `VulnClass`), location, HTTP method/parameter, evidence snippet, suggested payload, confidence (0.0–1.0), `EvidenceTier`, and optional code location/taint path. The `ExploitationQueue` supports filtering by vulnerability class, evidence tier (`filter_by_evidence_tier`), and confidence threshold (`filter_by_confidence`). `from_vuln_analysis_output()` provides backward compatibility for legacy dict-based findings. JSON Schema export enables LLM `response_format` enforcement.

**Aggressive Exploit Tools** (`backend/src/orchestration/aggressive_exploit_tools.py`): Auto-enqueues `run_sqlmap` as a Celery task for SQL injection findings when policy allows. Detects CWE-89 patterns via heuristic matching on finding title/description (keywords: "sql injection", "sqli", "sql-injection", "blind sql"). Gated by three checks: (1) findings must contain SQLi signal, (2) target must be http/https, (3) `evaluate_tool_approval_policy("sqlmap")` must pass and `settings.sqlmap_va_enabled` must be true. Skips silently with structured log events on any gate failure.

**Exploitation Executor** (`backend/src/orchestration/exploitation_executor.py`): The main exploitation runtime — connects `PayloadBuilder`, WRB, and sandbox tools. Hardcoded vulnerability-to-tool mapping (`_VULN_TOOL_MAP`) covers 25+ vulnerability types: XSS → dalfox/xsstrike, SQLi → sqlmap, SSRF → ffuf/nuclei, LFI/RFI/IDOR → ffuf, CMDi → commix, SSTI/NoSQLi/XXE → nuclei, AD attacks → impacket/crackmapexec/enum4linux-ng, cloud → prowler/scoutsuite, K8s → kube-hunter/kube-bench, SAST/secrets → semgrep/bandit/gitleaks. Unknown vuln types default to nuclei + ffuf. All tools run in the `argus-sandbox` container via `docker exec`. Payloads are built through `PayloadBuilder` with WRB augmentation fallback. WRB re-assesses exploitability from sandbox stdout/stderr after each tool run. Supports authenticated sessions via cookie/header propagation (`_auth_argv_flags`). Capped at 10 findings per execution; stops per-finding when exploitation succeeds at >0.7 confidence.

## Test Markers

| Marker | Meaning |
|--------|---------|
| `requires_docker` | Needs the full Docker test stack |
| `requires_docker_e2e` | Needs `docker-compose.e2e.yml` (juice-shop + full ARGUS) |
| `requires_postgres` | Needs live PostgreSQL |
| `requires_redis` | Needs live Redis |
| `requires_oast` | Needs live interactsh OAST listener |
| `requires_latex` | Needs `latexmk` on PATH |
| `weasyprint_pdf` | Needs WeasyPrint/Pango/Cairo |
| `mutates_catalog` | Test modifies the signed catalog; must use `tmp_path` copy |

Default `pytest` run excludes `requires_docker` markers (set in `pyproject.toml` `addopts`).
