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

The backend and worker containers mount `/var/run/docker.sock:ro` to orchestrate
the argus-sandbox container for security tool execution.

### Risk
Read-only mount reduces but does not eliminate host escape risk.
A compromised container with socket access can enumerate and control other containers.

### Mitigations (production)
- Use rootless Docker or Podman
- Run behind a Docker socket proxy (e.g., tecnativa/docker-socket-proxy)
- Use gVisor or Kata Containers for sandbox isolation
- Network-segment the sandbox from production databases
- Monitor Docker API calls with audit logging

### Why Not Remove It?
The socket is required for `docker exec` into argus-sandbox for VA active scan tool execution.
Without it, the vulnerability analysis pipeline cannot run security tools.
