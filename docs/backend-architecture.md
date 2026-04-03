# ARGUS Backend Architecture

**Version:** 0.1  
**Source:** ARGUS backend implementation, TZ.md, frontend-api-contract.md

---

## 1. Overview

ARGUS backend — multitenant FastAPI application для AI-driven пентест-платформы. Стек: Python 3.12+, FastAPI, SQLAlchemy 2, PostgreSQL, Redis, Celery, MinIO/S3, OpenTelemetry, Prometheus.

---

## 2. Layer Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         HTTP / SSE / MCP                                │
├─────────────────────────────────────────────────────────────────────────┤
│  Routers (API layer)                                                    │
│  /api/v1/scans, /reports, /tools, /auth, /health, /metrics               │
├─────────────────────────────────────────────────────────────────────────┤
│  Services (business logic)                                               │
│  ScanService, ReportService, AuthService, ProviderService                 │
├─────────────────────────────────────────────────────────────────────────┤
│  Orchestration (state machine, phase handlers)                           │
│  run_scan_state_machine, run_recon, run_threat_modeling, ...             │
├─────────────────────────────────────────────────────────────────────────┤
│  Tasks (Celery workers)                                                  │
│  scan_task, report_generation_task                                       │
├─────────────────────────────────────────────────────────────────────────┤
│  Storage (DB + Object Store)                                             │
│  PostgreSQL (SQLAlchemy), MinIO/S3 (reports, screenshots, evidence)      │
├─────────────────────────────────────────────────────────────────────────┤
│  Observability                                                          │
│  Prometheus, OpenTelemetry, structured JSON logging                     │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Routers

| Router | Prefix | Purpose |
|--------|--------|---------|
| `health` | `/api/v1` | `/health`, `/ready` — health checks |
| `metrics` | — | `/metrics` — Prometheus scrape |
| `auth` | `/api/v1` | Login, register, token refresh |
| `scans` | `/api/v1` | `POST /scans`, `GET /scans/:id`, `GET /scans/:id/events` (SSE) |
| `reports` | `/api/v1` | `GET /reports`, `GET /reports/:id`, `GET /reports/:id/download` |
| `tools` | `/api/v1` | Tool execution endpoints (allowlisted) |

**Auth:** JWT; scans/reports — optional auth (текущая политика). Middleware: CORS, security headers, exception handlers.

---

## 4. Services

| Service | Responsibility |
|---------|-----------------|
| **ScanService** | Create scan, enqueue Celery task, poll status, emit SSE events |
| **ReportService** | Fetch report by ID/target, generate report (HTML/PDF/JSON/CSV), persist to MinIO |
| **AuthService** | Auth, validation, session management |
| **ProviderService** | LLM provider config, health, fallback routing |
| **StorageService** | MinIO upload/download, metadata, presigned URLs |

---

## 5. Tasks (Celery)

| Task | Queue | Purpose |
|------|-------|---------|
| `scan_task` | `argus.scans` | Run full scan pipeline (6-phase state machine) |
| `report_generation_task` | `argus.reports` | Generate report artifacts, upload to MinIO |

**Broker:** Redis. **Result backend:** Redis (optional). **Concurrency:** configurable per worker.

---

## 6. Storage

### 6.1 PostgreSQL

- **Метаданные:** tenants, users, subscriptions, targets, scans, scan_steps, scan_events, scan_timeline, assets, findings, tool_runs, evidence, reports, audit_logs, policies, usage_metering, provider_configs, provider_health, phase_inputs, phase_outputs, report_objects, screenshots.
- **RLS:** tenant-scoped tables have `tenant_id`; RLS policies enforce row-level isolation.
- **Audit log:** immutable append-only; `UPDATE`/`DELETE` forbidden.

### 6.2 MinIO / S3

| Object type | Path pattern | Example |
|-------------|--------------|---------|
| Raw outputs | `{tenant_id}/{scan_id}/raw/{filename}` | nmap output, tool stdout |
| Screenshots | `{tenant_id}/{scan_id}/screenshots/{filename}` | page captures |
| Evidence | `{tenant_id}/{scan_id}/evidence/{filename}` | PoC files |
| Reports | `{tenant_id}/{scan_id}/reports/{filename}` | report.pdf, report.html |
| Attachments | `{tenant_id}/{scan_id}/attachments/{filename}` | user uploads |

**Path validation:** reject `..`, `/`, `\`; sanitize all components.

---

## 7. Observability

| Component | Purpose |
|-----------|---------|
| **Prometheus** | `argus_scans_total`, `argus_phase_duration_seconds`, `argus_tool_runs_total` |
| **OpenTelemetry** | Optional spans for scan phases (`scan.phase.{phase}`) |
| **Structured logging** | JSON format; no `traceback` or secrets in logs |
| **Correlation IDs** | `X-Request-ID` propagated through request lifecycle |
| **Health** | `/health` (liveness), `/ready` (DB, Redis, storage) |

---

## 8. Directory Structure

```
backend/
├── main.py                 # FastAPI app, lifespan, routers
├── src/
│   ├── api/
│   │   ├── routers/        # health, metrics, auth, scans, reports, tools
│   │   └── schemas.py      # Pydantic request/response models
│   ├── core/
│   │   ├── config.py       # Settings (env)
│   │   ├── auth.py        # JWT, auth
│   │   ├── exception_handlers.py
│   │   ├── security_headers.py
│   │   ├── logging_config.py
│   │   └── observability.py
│   ├── db/
│   │   ├── models.py      # SQLAlchemy models
│   │   └── session.py     # Async session
│   ├── orchestration/
│   │   ├── state_machine.py
│   │   ├── phases.py      # Phase enums, input/output contracts
│   │   ├── handlers.py    # Phase handlers
│   │   ├── ai_prompts.py
│   │   └── prompt_registry.py
│   ├── llm/
│   │   ├── adapters.py    # Provider adapters (OpenAI, DeepSeek, etc.)
│   │   └── router.py      # LLM routing
│   ├── reports/
│   │   ├── generators.py  # HTML, PDF, JSON, CSV
│   │   └── storage.py     # MinIO upload/download
│   ├── tools/
│   │   ├── executor.py    # Guarded tool execution
│   │   └── guardrails/    # IP, domain, rate validators
│   ├── data_sources/      # NVD, ExploitDB, Shodan, etc.
│   ├── tasks.py           # Celery task definitions
│   └── celery_app.py
├── alembic/               # Migrations
└── tests/
```

---

## 9. Security

- **Input validation:** Pydantic models; whitelist for tool params.
- **Path traversal:** Reject `..`, `/`, `\` in all path components.
- **Error handling:** No stack traces in API responses; structured logs only.
- **Secrets:** Env vars; no hardcoded keys.
- **RLS:** Tenant isolation enforced at DB level.

---

## 10. Related Documents

- [frontend-api-contract.md](./frontend-api-contract.md)
- [erd.md](./erd.md)
- [scan-state-machine.md](./scan-state-machine.md)
