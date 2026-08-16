# ARGUS Security Guide

## Authentication

All API endpoints (except `/health` and `/metrics`) require authentication via:
- **JWT Bearer token** — for interactive users
- **X-API-Key header** — for MCP/service accounts

Tenant isolation enforced via JWT `tenant_id` claim. `X-Tenant-ID` header override
is only permitted for API-key authenticated service accounts.

## MCP Server Security

- Auth: Bearer token via `MCP_AUTH_TOKEN` environment variable
- Binding: `127.0.0.1` when no token set; `0.0.0.0` permitted only with token
- Error responses sanitized — no internal details leaked to clients

## Docker Compose Secrets

- All secrets require explicit env vars (`${VAR:?required}` syntax in compose)
- See `infra/.env.example` for complete list with descriptions
- When `REDIS_PASSWORD` is set, `REDIS_URL` and `CELERY_BROKER_URL` must include it

## CORS

- Nginx: dynamic CORS via `envsubst` template (`ARGUS_CORS_ALLOWED_ORIGINS`)
- Backend: configurable via `CORS_ORIGINS` env var
- Wildcard `*` raises `ValueError` in production mode

## MinIO

- Credentials required (no defaults in production)
- Reports bucket separated from scan artifacts
- Access restricted to backend/worker services only

## Docker Socket Mount

The `backend`, `worker-scans`, and `worker-general` services mount
`/var/run/docker.sock:ro` (3 mount points) to orchestrate the argus-sandbox container for
security tool execution. The `sandbox` service itself does **not** receive the socket.

### Risk
The `:ro` flag applies to the socket *file*, not to the Docker API reachable through it:
`docker exec`, container creation, and image operations all still work over a read-only
mounted socket. Socket access therefore remains equivalent to host-level privilege — a
compromised container can enumerate, control, or create other containers. Treat `:ro` as
defence-in-depth (it blocks tampering with the socket inode), never as a capability limit.

### Mitigations (production)
- Use rootless Docker or Podman
- Run behind a Docker socket proxy (e.g., tecnativa/docker-socket-proxy)
- Use gVisor or Kata Containers for sandbox isolation
- Network-segment the sandbox from production databases
- Monitor Docker API calls with audit logging

### Why Not Remove It?
The socket is required for `docker exec` into argus-sandbox for VA active scan tool execution.
Without it, the vulnerability analysis pipeline cannot run security tools.

## Quick execution mode

`execution_mode=quick` is a third immutable profile next to `production` and `lab_unrestricted`. It is **fail-closed** and **does not inherit LAB**:

- Feature flag `ARGUS_QUICK_MODE_ENABLED` defaults to **false**. Flag off + `execution_mode=quick` → `400 quick_mode_disabled` (no silent fallback to a full scan).
- Tool approval uses `evaluate_tool_approval_policy(..., lab_lease_active=False)` and `production_evaluator`. Unknown mode raises; it must not fall through to `LAB_ALLOW_ALL`.
- Forbidden in Quick: `LAB_ALLOW_ALL`, Nuclei signature-gate skip, unsigned remote templates, `LAB_RESEARCH` RAG, destructive tools, password spray, clusterbomb, post-exploitation.
- `execution_mode=lab_unrestricted` combined with a `quick` payload → `400 conflicting_execution_mode`.
- Out-of-scope targets: zero network requests. Absence of a finding is not evidence that a vulnerability is absent.

See `docs/runbooks/quick-mode.md` and `ai_docs/develop/architecture/2026-08-16-adr-quick-execution-mode.md`.
