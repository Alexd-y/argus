# ARGUS

Automated penetration testing platform combining AI-driven analysis with traditional security tools.

## Status

- **Current Cycle:** Cycle 4 (closed 2026-04-20)
- **Last Sign-off:** 2026-04-20 — All 10 tasks completed (ARG-031..ARG-040)
- **Sign-off Report:** [Cycle 4 Finalization](ai_docs/develop/reports/2026-04-19-argus-finalization-cycle4.md)
- **Cycle 5 Backlog:** [ISS-cycle5-carry-over.md](ai_docs/develop/issues/ISS-cycle5-carry-over.md) (7 priming tasks ARG-041..047)
- **Headline metrics:** ReportService matrix 18/18 · Parser coverage 75.2 % (mapped 118 / heartbeat 39, post–Cycle 6 T05) · Coverage matrix 16 contracts × 2 512+ cases · Supply chain Cosign keyless prod · MCP webhooks + rate-limiter + OpenAPI 3.1 + TS SDK · Branded deterministic PDF
- **Predecessor:** [Cycle 3 Finalization](ai_docs/develop/reports/2026-04-19-argus-finalization-cycle3.md) (closed 2026-04-19)

## Architecture

- **Backend**: FastAPI + Celery workers (Python 3.12)
- **Database**: PostgreSQL with pgvector, Row-Level Security
- **Cache/Queue**: Redis (caching, Celery broker)
- **Storage**: MinIO (S3-compatible, scan artifacts)
- **AI**: Multi-provider LLM facade (OpenAI, DeepSeek, Anthropic)
- **Tools**: MCP server with 100+ Kali Linux tool integrations
- **Reports**: Jinja2 templates, HTML/PDF output via WeasyPrint

## Quick Start

```bash
# Clone and configure
cp infra/.env.example infra/.env
# Edit infra/.env with your API keys and secrets

# Start all services
cd infra
docker compose up -d

# Backend API: http://localhost:8000
# Admin API: requires ADMIN_API_KEY
# Metrics: requires METRICS_TOKEN (Bearer auth)
```

## Project Structure

```
ARGUS/
  backend/           # FastAPI application + Celery workers
    src/
      api/           # REST API routers and schemas
      core/          # Configuration, auth, database session
      db/            # SQLAlchemy models, Alembic migrations
      llm/           # LLM facade, task router, adapters
      orchestration/ # Scan state machine, AI prompts
      recon/         # Reconnaissance, VA, exploitation pipelines
      reports/       # Jinja2 templates, PDF generation
      services/      # Business logic (reporting, etc.)
    tests/           # pytest test suite
  docs/              # Deployment, API contracts, architecture notes
  infra/             # Docker Compose, nginx, Dockerfiles
  Frontend/          # Primary web client (contract source of truth)
  admin-frontend/    # Admin UI
  mcp-server/        # MCP tool server (Kali integration)
  plugins/           # Optional integrations
  tests/             # Cross-cutting or E2E tests (when present)
  ai_docs/           # Plans, reports, internal development docs
```

## Development

```bash
# Run tests
cd backend
python -m pytest tests/ -q

# Lint
python -m ruff check src/

# Database migrations (from backend directory, where alembic.ini lives)
alembic upgrade head
```

> **Windows users:** `mypy --strict` may crash with `Windows fatal exception: access violation` (`0xC0000005`) on some Python 3.12 / mypy 1.10+ combinations — see [`ai_docs/develop/troubleshooting/mypy-windows-access-violation.md`](ai_docs/develop/troubleshooting/mypy-windows-access-violation.md). The supported development environment for Windows is **WSL2** — see [`ai_docs/develop/wsl2-setup.md`](ai_docs/develop/wsl2-setup.md) for the full runbook. CI is unaffected (Linux-only).

## Documentation

- [Deployment Guide](docs/deployment.md)
- [API Contracts](docs/api-contracts.md)
- [Architecture and development notes](ai_docs/develop/)
