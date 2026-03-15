# Plan: ARGUS Production-Ready Pentest Platform

**Created:** 2026-03-09  
**Orchestration:** orch-2026-03-09-argus-implementation  
**Status:** ✅ **Completed** (11/11 core tasks + Stage 1 Enrichment advancement)  
**Goal:** Доработать ARGUS до production-ready платформы с полной совместимостью Frontend, 6-фазным lifecycle, AI-оркестрацией, MCP, multitenant backend.

---

## Context

- **Workspace:** d:\Developer\Pentest_test
- **ARGUS path:** d:\Developer\Pentest_test\ARGUS
- **Source of truth:** TZ.md, ARGUS/Frontend (API contracts)
- **Existing:** backend partial (main.py, orchestration, tools, core), Frontend complete
- **Constraint:** Frontend — source of truth, DO NOT modify

---

## Frontend API Contracts (Source of Truth)

| Endpoint | Method | Request | Response | Notes |
|----------|--------|---------|----------|-------|
| `/api/v1/scans` | POST | CreateScanRequest: { target, email, options: ScanOptions } | CreateScanResponse: { scan_id, status, message? } | |
| `/api/v1/scans/:id` | GET | — | ScanStatus: { id, status, progress, phase, target, created_at } | Polling every 3s |
| `/api/v1/scans/:id/events` | GET | — | SSE stream, JSON events: { event?, phase?, progress?, message?, data?, error? } | Events: complete, error |
| `/api/v1/reports?target=X` | GET | target query param | Report[] | |
| `/api/v1/reports/:id` | GET | — | Report | |
| `/api/v1/reports/:id/download?format=pdf\|html\|json\|csv` | GET | — | Binary download | |

**Env:** NEXT_PUBLIC_API_URL default `/api/v1`

**Scan lifecycle (6 phases):** recon → threat_modeling → vuln_analysis → exploitation → post_exploitation → reporting

---

## Tasks Overview

| ID | Task | Priority | Dependencies | Est. Time |
|----|------|----------|--------------|-----------|
| CONTRACT-001 | Create docs/frontend-api-contract.md | Critical | — | 2h |
| ARCH-002 | Create docs/backend-architecture.md, erd.md, scan-state-machine.md | High | CONTRACT-001 | 4h |
| BACKEND-003 | Backend core — DB, queues, storage, RLS | High | ARCH-002 | 12h |
| PHASES-004 | Implement 6-phase scan state machine | High | BACKEND-003 | 16h |
| AI-005 | Provider adapters, prompt registry, intel/tool adapters | High | PHASES-004 | 10h |
| REPORTS-006 | Report generation — HTML, JSON, PDF, CSV | High | PHASES-004 | 8h |
| SSE-MCP-007 | SSE compatible with Frontend, ARGUS MCP server | High | BACKEND-003 | 6h |
| TESTS-008 | Unit, integration, contract, RLS, migration, security P0 | High | PHASES-004, REPORTS-006, SSE-MCP-007 | 10h |
| INFRA-009 | Docker, docker-compose, CI/CD | Medium | BACKEND-003 | 6h |
| ADMIN-010 | admin-frontend UI | Medium | BACKEND-003 | 12h |
| DOCS-011 | prompt-registry, provider-adapters, security-model, deployment | Medium | AI-005, REPORTS-006 | 4h |

---

## Dependencies Graph

```
CONTRACT-001
    └── ARCH-002
            └── BACKEND-003
                    ├── PHASES-004 ──┬── AI-005
                    │               └── REPORTS-006 ── DOCS-011
                    ├── SSE-MCP-007
                    ├── INFRA-009
                    └── ADMIN-010

PHASES-004 + REPORTS-006 + SSE-MCP-007 ── TESTS-008
```

---

## Task Details

### CONTRACT-001: Create docs/frontend-api-contract.md

**Priority:** Critical  
**Dependencies:** None  
**Files:** ARGUS/docs/frontend-api-contract.md

**Acceptance criteria:**
- [ ] Full table: endpoint, method, request schema, response schema, error schema
- [ ] Auth expectations (if any)
- [ ] Polling/SSE behavior (3s poll, SSE events: complete, error)
- [ ] Report formats: pdf, html, json, csv
- [ ] Env: NEXT_PUBLIC_API_URL default /api/v1
- [ ] ScanOptions, CreateScanRequest, CreateScanResponse, ScanStatus, SSEEventPayload, Report, Finding, ReportSummary — полные схемы
- [ ] Frontend declared as source of truth

**Implementation notes:**
- Use ARGUS/Frontend/src/lib/types.ts, api.ts, scans.ts, reports.ts as source
- Merge with existing ARGUS/docs/api-contracts.md, api-contract-rule.md, sse-polling.md
- No hexstrike or other source project names

---

### ARCH-002: Create docs/backend-architecture.md, docs/erd.md, docs/scan-state-machine.md

**Priority:** High  
**Dependencies:** CONTRACT-001  
**Files:** ARGUS/docs/backend-architecture.md, ARGUS/docs/erd.md, ARGUS/docs/scan-state-machine.md

**Acceptance criteria:**
- [ ] backend-architecture.md: FastAPI layers, routers, services, tasks, storage, observability
- [ ] erd.md: ERD with all entities: tenants, users, subscriptions, targets, scans, scan_steps, scan_events, scan_timeline, assets, findings, tool_runs, evidence, reports, audit_logs, policies, usage_metering, provider_configs, provider_health, phase_inputs, phase_outputs, report_objects, screenshots
- [ ] scan-state-machine.md: 6-phase state machine (recon, threat_modeling, vuln_analysis, exploitation, post_exploitation, reporting), transitions, failure handling
- [ ] All tenant-scoped tables have tenant_id
- [ ] RLS policy descriptions
- [ ] No hexstrike naming

**Implementation notes:**
- Adapt from test/ai_docs/develop/plans/2026-03-08-pentest-base-analysis.md
- Reference ARGUS/backend/src/db/models.py, src/orchestration/state_machine.py

---

### BACKEND-003: Backend core — FastAPI, SQLAlchemy 2, Alembic, PostgreSQL, RLS, Redis, Celery/Dramatiq/RQ, MinIO/S3

**Priority:** High  
**Dependencies:** ARCH-002  
**Files:** ARGUS/backend/src/db/models.py, alembic/versions/*, src/core/*, src/tasks.py, src/celery_app.py, src/reports/storage.py

**Acceptance criteria:**
- [ ] PostgreSQL models: tenants, users, subscriptions, targets, scans, scan_steps, scan_events, scan_timeline, assets, findings, tool_runs, evidence, reports, audit_logs, policies, usage_metering, provider_configs, provider_health, phase_inputs, phase_outputs, report_objects, screenshots
- [ ] RLS for tenant-scoped tables
- [ ] Alembic migrations for all tables
- [ ] Redis for cache/queue
- [ ] Celery/Dramatiq/RQ for async scan tasks
- [ ] MinIO/S3 for raw outputs, screenshots, evidence, reports
- [ ] audit_logs immutable append-only
- [ ] Volumes for persistence when containers stop

**Implementation notes:**
- Extend existing ARGUS/backend/src/db/models.py
- Use SQLAlchemy 2 style, async session
- Reference test/hexstrike-ai patterns (adapted, no naming)

---

### PHASES-004: Implement 6-phase scan state machine

**Priority:** High  
**Dependencies:** BACKEND-003  
**Files:** ARGUS/backend/src/orchestration/phases.py, state_machine.py, handlers.py, ai_prompts.py

**Acceptance criteria:**
- [ ] Per phase: definition, input contract, output contract, DB persistence, timeline/events, AI prompt, strict JSON schema for LLM output, retry/fixer prompt, report inclusion, failure handling
- [ ] Phases: recon, threat_modeling, vuln_analysis, exploitation, post_exploitation, reporting
- [ ] phase_inputs, phase_outputs persisted
- [ ] scan_events emitted for SSE
- [ ] Policy/approval gates for destructive steps
- [ ] Phase outputs flow into report

**Implementation notes:**
- Extend ARGUS/backend/src/orchestration/state_machine.py, phases.py
- Adapt prompts from test projects (Zen-Ai, Strix, hexstrike) — no source naming

---

### AI-005: Provider adapters, prompt registry, intel adapters, tool adapters

**Priority:** High  
**Dependencies:** PHASES-004  
**Files:** ARGUS/backend/src/llm/adapters.py, router.py, src/orchestration/prompt_registry.py, src/data_sources/*, src/tools/*

**Acceptance criteria:**
- [ ] Provider adapters: OpenAI, DeepSeek, OpenRouter, Gemini, Kimi, Perplexity (activate by API key in env)
- [ ] Prompt registry with per-phase prompts, strict JSON schemas, retry/fixer prompts, fallback strategy
- [ ] Intel adapters: Shodan, NVD, GitHub, Exploit-DB + optional (Censys, crt.sh, etc.)
- [ ] Tool adapters: allowlisted (nmap, nuclei, nikto, gobuster, sqlmap, etc.), no shell=True
- [ ] Graceful degradation when no LLM provider available

**Implementation notes:**
- Extend ARGUS/backend/src/llm/, src/data_sources/, src/tools/
- No command injection, no arbitrary shell execution

---

### REPORTS-006: Report generation — HTML, JSON, PDF, CSV

**Priority:** High  
**Dependencies:** PHASES-004  
**Files:** ARGUS/backend/src/reports/generators.py, storage.py

**Acceptance criteria:**
- [ ] Formats: HTML, JSON, PDF, CSV
- [ ] Include: metadata, timeline, phase outputs, findings, evidence, screenshots, AI conclusions, remediation, executive summary
- [ ] Object storage for reports
- [ ] Regeneration support
- [ ] Compatible with GET /reports/:id/download?format=pdf|html|json|csv

**Implementation notes:**
- Extend ARGUS/backend/src/reports/generators.py
- Frontend expects pdf, html, json, csv (not xml in download)

---

### SSE-MCP-007: SSE /api/v1/scans/:id/events compatible with Frontend, ARGUS MCP server

**Priority:** High  
**Dependencies:** BACKEND-003  
**Files:** ARGUS/backend/src/api/routers/scans.py, ARGUS/plugins/mcp/ or ARGUS/backend/src/mcp/

**Acceptance criteria:**
- [ ] GET /api/v1/scans/:id/events returns SSE stream
- [ ] JSON events: { event?, phase?, progress?, message?, data?, error? }
- [ ] Events: complete, error (Frontend handles these)
- [ ] ARGUS MCP server: stdio transport, typed schemas, auth, tenant awareness
- [ ] MCP tools → backend API pattern

**Implementation notes:**
- ARGUS/backend/src/api/routers/scans.py already has SSE — verify Frontend compatibility
- Frontend: subscribeScanEvents, onmessage parses JSON, handles event complete/error
- No hexstrike naming in MCP

---

### TESTS-008: Unit, integration, contract tests, OpenAPI, RLS, migration, security P0

**Priority:** High  
**Dependencies:** PHASES-004, REPORTS-006, SSE-MCP-007  
**Files:** ARGUS/backend/tests/*

**Acceptance criteria:**
- [ ] Unit tests for core logic
- [ ] Integration tests for API endpoints
- [ ] Contract tests (Frontend expectations)
- [ ] OpenAPI schema for all endpoints
- [ ] RLS tests
- [ ] Migration tests
- [ ] Security P0: no command injection, no traceback leak, no path traversal

**Implementation notes:**
- Extend ARGUS/backend/tests/
- Reference test_argus015_security_p0.py, test_argus003_api_contract.py

---

### INFRA-009: Docker, docker-compose, CI/CD

**Priority:** Medium  
**Dependencies:** BACKEND-003  
**Files:** ARGUS/infra/docker-compose.yml, Dockerfile, .github/workflows/ or .gitlab-ci.yml

**Acceptance criteria:**
- [ ] Docker images for backend, workers, optional admin-frontend
- [ ] docker-compose with PostgreSQL, Redis, MinIO, backend, worker
- [ ] Volumes for persistence
- [ ] CI/CD: lint, format, tests, security scans, build, helm lint

**Implementation notes:**
- Create ARGUS/infra/ if not exists
- Reference TZ.md deployment requirements

---

### ADMIN-010: admin-frontend UI

**Priority:** Medium  
**Dependencies:** BACKEND-003  
**Files:** ARGUS/admin-frontend/*

**Acceptance criteria:**
- [ ] UI for: tenants, users, subscriptions, providers, policies, audit logs, usage metering, queue/storage health
- [ ] Auth for admin
- [ ] Read/write for config entities

**Implementation notes:**
- Create ARGUS/admin-frontend/ if not exists
- React/Next.js or similar, consistent with project stack

---

### DOCS-011: Create docs/prompt-registry.md, provider-adapters.md, security-model.md, deployment.md

**Priority:** Medium  
**Dependencies:** AI-005, REPORTS-006  
**Files:** ARGUS/docs/prompt-registry.md, ARGUS/docs/provider-adapters.md, ARGUS/docs/security-model.md, ARGUS/docs/deployment.md

**Acceptance criteria:**
- [ ] prompt-registry.md: structure, per-phase prompts, JSON schemas, retry/fixer
- [ ] provider-adapters.md: OpenAI, DeepSeek, OpenRouter, Gemini, Kimi, Perplexity, env activation
- [ ] security-model.md: RLS, auth, no command injection, no traceback leak, path traversal protection
- [ ] deployment.md: Docker, env vars, volumes, CI/CD

**Implementation notes:**
- TZ.md requires these docs explicitly

---

## Progress (updated by orchestrator)

- ✅ CONTRACT-001: Create docs/frontend-api-contract.md (Completed)
- ✅ ARCH-002: Create docs/backend-architecture.md, erd.md, scan-state-machine.md (Completed)
- ✅ BACKEND-003: Backend core (Completed)
- ✅ PHASES-004: 6-phase scan state machine (Completed)
- ✅ AI-005: Provider adapters, prompt registry (Completed)
- ✅ REPORTS-006: Report generation (Completed)
- ✅ SSE-MCP-007: SSE + MCP server (Completed)
- ✅ TESTS-008: Tests + security P0 (Completed)
- ✅ INFRA-009: Docker + CI/CD (Completed)
- ✅ ADMIN-010: admin-frontend (Completed)
- ✅ DOCS-011: Additional docs (Completed)

---

## Architecture Decisions

- **6-phase lifecycle:** recon → threat_modeling → vuln_analysis → exploitation → post_exploitation → reporting (TZ.md mandatory)
- **Frontend source of truth:** All API contracts from ARGUS/Frontend, backend implements exactly
- **No shell=True:** Tool execution via allowlisted adapters only
- **Multitenant:** tenant_id on all scoped tables, RLS
- **Object storage:** MinIO/S3 for large objects (reports, screenshots, evidence)
- **Queue:** Celery/Dramatiq/RQ for async scan execution
- **Naming:** No hexstrike or source project names in code, API, logs, docs, env

---

## Reference Materials

- test/hexstrike-ai (DOCUMENTATION_hexstrike-ai.md) — patterns to adapt
- test/ai_docs/develop/plans/2026-03-08-pentest-base-analysis.md
- test/ai_docs/develop/reports/2026-03-08-pentest-analysis-implementation.md
- ARGUS/docs/api-contracts.md, sse-polling.md
- ARGUS/Frontend/src/lib/types.ts, scans.ts, reports.ts

---

## Execution Order (Recommended)

1. CONTRACT-001
2. ARCH-002
3. BACKEND-003
4. PHASES-004, SSE-MCP-007, INFRA-009, ADMIN-010 (can parallelize after BACKEND-003)
5. AI-005, REPORTS-006
6. TESTS-008
7. DOCS-011
