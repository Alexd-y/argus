# Deploying ARGUS on AWS

Practical deployment guide for the ARGUS stack on AWS. All secrets are shown as
placeholders — store real values in **AWS Secrets Manager / SSM Parameter Store**,
never in the repo or images. Use IaC (Terraform/CloudFormation) for everything
below; the snippets are illustrative.

## 1. Service mapping

| Local (docker-compose)     | AWS                                              |
|----------------------------|--------------------------------------------------|
| `postgres` (pgvector)      | **RDS PostgreSQL 16** with the `vector` extension (or Aurora PostgreSQL) |
| `redis`                    | **ElastiCache for Redis 7** (broker + leases + cache) |
| `minio`                    | **S3** buckets (`argus-reports`, artifacts)      |
| `backend` (FastAPI)        | **ECS Fargate** service behind an **ALB**        |
| `worker-scans` / `worker-general` / `worker-reports` / `worker-intruder` / `beat` | **ECS services** (Fargate) |
| `argus-sandbox` (Kali) + tool exec via `docker exec` | **ECS on EC2** (or dedicated EC2 ASG) — see §6 |
| image registry             | **ECR**                                          |
| secrets                    | **Secrets Manager** (JWT, DB, MinIO/S3, LLM keys)|

## 2. Prerequisites

- VPC with private subnets (RDS, ElastiCache, ECS tasks) + public subnets (ALB, NAT).
- ECR repositories: `argus-backend`, `argus-sandbox`.
- Security groups: ALB→backend (443/80→8000); backend/workers→RDS (5432),
  →ElastiCache (6379); egress to S3 via VPC endpoint.
- IAM task roles with least privilege: S3 (bucket-scoped), Secrets Manager
  (specific secret ARNs), CloudWatch Logs.

## 3. Build & push images

```bash
aws ecr get-login-password --region <REGION> | docker login --username AWS --password-stdin <ACCT>.dkr.ecr.<REGION>.amazonaws.com

docker build -t argus-backend:$(git rev-parse --short HEAD) -f infra/backend/Dockerfile backend
docker tag argus-backend:<SHA> <ACCT>.dkr.ecr.<REGION>.amazonaws.com/argus-backend:<SHA>
docker push <ACCT>.dkr.ecr.<REGION>.amazonaws.com/argus-backend:<SHA>

# Sandbox (Kali runner) — same flow for argus-sandbox.
```

Pin image tags by git SHA (deterministic, reproducible builds).

## 4. Managed data services

- **RDS PostgreSQL 16**: enable `vector` (pgvector). ARGUS uses Row-Level
  Security — keep the app DB role **non-superuser and without `BYPASSRLS`**.
  Multi-AZ for prod; automated backups + PITR.
- **ElastiCache Redis 7**: single primary + replica; in-transit + at-rest
  encryption; used as the Celery broker AND the §8 distributed-lease store.

Store connection strings in Secrets Manager:

```
DATABASE_URL   = postgresql+asyncpg://<user>:<PLACEHOLDER>@<rds-endpoint>:5432/argus
REDIS_URL      = rediss://<elasticache-endpoint>:6379/0
JWT_SECRET     = <PLACEHOLDER>
S3_ENDPOINT / AWS creds via task role (preferred) or MINIO_* placeholders
```

## 5. Run migrations (one-off ECS task)

Run BEFORE routing traffic to a new backend version:

```bash
# ECS RunTask overriding the command on the backend image:
#   cd backend && alembic upgrade head
aws ecs run-task --cluster argus --task-definition argus-migrate \
  --launch-type FARGATE --network-configuration <...>
```

`alembic upgrade head` applies the full chain including `064` (budget ledger)
and `065` (durable agent-task store + outbox). Verified end-to-end on pgvector.

Rollout order (matches `docs/architecture/platform-hardening-a.md`):
migrate → deploy backend → restart workers. Rollback: `alembic downgrade 063`
+ redeploy previous image.

## 6. Sandbox execution (security-critical)

Active tools run inside the `argus-sandbox` container via `docker exec`, so the
worker needs access to a Docker daemon. **Fargate cannot nest Docker**, so run
`worker-scans` / `worker-general` and the sandbox on an **ECS-on-EC2** capacity
provider (or a dedicated EC2 ASG):

- Mount the host Docker socket **read-only** on those workers only
  (`/var/run/docker.sock:/var/run/docker.sock:ro`). Note: `:ro` protects the
  socket file, not the Docker API — treat socket access as host-level privilege.
- Isolate the sandbox on its own EC2 subnet/security group; deny egress except
  to in-scope targets + DNS.
- Do NOT give the sandbox container `--privileged`, the Docker socket, or access
  to other tenants' workspaces. Keep resource limits, read-only rootfs, and
  `--no-new-privileges` (already enforced by `EphemeralWorkerPool`).
- The API/report/beat services have no tool-exec needs and stay on Fargate.

## 7. ECS task env (platform-hardening flags)

New features are **opt-in** — enable only after validating in staging:

```
BUDGET_LEDGER_ENABLED = false   # §7 durable budget accounting
LEASE_ENABLED         = false   # §8 distributed concurrency leases
LEASE_TTL_SECONDS     = 120
LEASE_PROVIDER_CAPACITY = 4
LEASE_BROWSER_CAPACITY  = 2
LEASE_HOST_CAPACITY     = 1
AGENT_TASK_LEASE_SECONDS = 180
AGENT_TASK_MAX_ATTEMPTS  = 3
MAX_COST_PER_SCAN_USD    = 10.0
```

When `LEASE_ENABLED=true`, workers share ElastiCache Redis so the pool caps are
enforced across every ECS task (not just per-process).

## 8. Observability

- Ship container logs to **CloudWatch Logs**; structured JSON events
  (`argus.agent.events`) carry `tenant_id/scan_id/task_id` for correlation.
- Scrape Prometheus metrics (`argus_budget_events_total`,
  `argus_lease_events_total`, `argus_agent_task_events_total`, …) via an ADOT
  collector → **Amazon Managed Prometheus / Grafana**. High-cardinality IDs are
  intentionally NOT in metric labels (they live in logs).

## 9. Autoscaling & HA

- Backend: ECS target-tracking on ALB request count / CPU.
- Workers: scale on Celery queue depth (custom CloudWatch metric) or CPU.
- Keep sandbox/EC2 workers on a bounded ASG — do not autoscale target load
  aggressively; the §8 leases cap concurrency per provider/host regardless.

## 10. CI/CD (GitHub Actions → ECR/ECS)

Pipeline stages (fail the build on any gate): lint (`ruff`) + SAST (CodeQL/
semgrep) → tests (`pytest`, incl. `requires_postgres`/`requires_redis` jobs with
service containers) → SCA (`pip-audit`/Dependabot) → build & push to ECR →
`alembic upgrade head` one-off task → ECS deploy (blue/green via CodeDeploy) with
automatic rollback on health-check failure.
