# ARGUS — Helm chart operator runbook (ARG-045)

> **Status**: Cycle 5, ARG-045. Production-ready Helm chart
> `infra/helm/argus/` (chart `argus`, version `0.1.0`,
> `appVersion v1.0.0-cycle5`) wired with Bitnami sub-charts for
> PostgreSQL, Redis, and MinIO. Pre-merge gates: `helm-lint` +
> `migrations-smoke` (see `.github/workflows/ci.yml`).
>
> This runbook is the operator-facing companion to the Backlog §16.13
> production-deployment requirements (`Backlog/dev1_.md`) and the Cycle 5
> finalization plan (`ai_docs/develop/plans/2026-04-21-argus-finalization-cycle5.md`).
> It assumes the reader is comfortable with `kubectl`, basic Helm
> mechanics, Kubernetes RBAC, and Sigstore/cosign supply-chain
> verification.

---

## 0. Audience and how to read this document

The runbook is structured so an on-call SRE can follow it linearly the
first time and then jump to a specific section (e.g. **§9 disaster
recovery**) when a real incident lands. Every command is reproducible
from the repository root unless explicitly stated. Windows operators
will find PowerShell variants alongside POSIX commands wherever
behaviour differs.

Sections:

| §  | Topic                                                        |
| -- | ------------------------------------------------------------ |
| 1  | Prerequisites — cluster, controllers, CLI tooling            |
| 2  | Quick start (one cluster, one namespace, three commands)     |
| 3  | Per-environment overlays — dev / staging / prod              |
| 4  | Image immutability discipline (`@sha256:<digest>`)           |
| 5  | Cosign verify-init flow (sequence diagram)                   |
| 6  | SealedSecrets generation procedure                           |
| 7  | NetworkPolicies — default-deny baseline                      |
| 8  | Alembic migration runbook                                    |
| 9  | Disaster recovery — backup, restore, RPO/RTO                 |
| 10 | Helm release upgrade procedure (canary, blue/green)          |
| 11 | Observability — metrics, traces, dashboards                  |
| 12 | Capacity planning — CPU / memory / storage projections       |
| 13 | Troubleshooting — top 10 issues + resolutions                |
| 14 | Reference appendix — file map and value-table cheatsheet     |

---

## 1. Prerequisites

### 1.1. Kubernetes cluster

| Requirement                  | Minimum                                                          |
| ---------------------------- | ---------------------------------------------------------------- |
| Kubernetes API server        | `>= 1.27.0` (matches `kubeVersion` in `infra/helm/argus/Chart.yaml`) |
| Worker node CPU              | 4 cores per AZ in dev, 16+ cores per AZ in prod                  |
| Worker node memory           | 8 GiB in dev, 32+ GiB in prod                                    |
| Default StorageClass         | `standard` (dev) or `gp3` / `csi-cinder-high` (staging + prod)   |
| Container runtime            | `containerd` ≥ 1.7 (the cosign verify-init container assumes OCI 1.1) |
| Multi-AZ placement           | At least 2 AZs with topology key `topology.kubernetes.io/zone`   |
| Egress Internet              | TLS 443 to GHCR, Sigstore (Fulcio + Rekor), and LLM providers    |

### 1.2. In-cluster controllers

| Controller                                          | Used by                                              | Required in prod |
| --------------------------------------------------- | ---------------------------------------------------- | ---------------- |
| `cert-manager` (≥ 1.14)                             | Ingress TLS via `cert-manager.io/cluster-issuer`     | Yes              |
| `sealed-secrets-controller`                         | Encrypted secret material in Git                     | Yes              |
| `prometheus-operator` (kube-prometheus-stack)       | `ServiceMonitor` resources                           | Yes              |
| `opentelemetry-operator`                            | Auto-instrumentation `Instrumentation` CR            | Yes              |
| `ingress-nginx` (or any compatible ingress class)   | Ingress termination                                  | Yes              |
| `metrics-server`                                    | HPA on CPU / memory                                  | Yes              |
| `prometheus-adapter`                                | HPA on `argus_celery_queue_depth` custom metric      | Recommended      |
| Kyverno or OPA Gatekeeper                           | Optional: enforce signed-image policy                | Recommended      |

For staging the controllers may be optional; in dev all are off by
default (`values-dev.yaml` keeps `prometheus`, `otel`, `cert-manager`,
`sealedSecrets`, and `networkPolicies` disabled to ease local testing
on `kind` / `minikube`).

### 1.3. Operator-side CLI tooling

| Tool         | Minimum         | Purpose                                                |
| ------------ | --------------- | ------------------------------------------------------ |
| `helm`       | 3.13            | Install / upgrade chart, render templates              |
| `kubectl`    | 1.27            | Apply manifests, debug pods                            |
| `cosign`     | 2.4             | Sign images during release; verify-init uses it too    |
| `kubeseal`   | 0.26            | Encrypt Secrets against the cluster's public key       |
| `kubeconform`| 0.6.7           | CI-side schema validation of rendered manifests        |
| `jq` / `yq`  | recent          | Inspect rendered manifests in scripts                  |
| `psql`       | 15              | Manual database operations (only for break-glass)      |
| `alembic`    | 1.13            | Run migrations (already pinned in `backend/requirements.txt`) |

Operator workstations should run on a hardened laptop (FileVault /
LUKS / BitLocker) because `kubeseal --fetch-cert` and Cosign keys are
trust-sensitive material.

---

## 2. Quick start

The fastest path from "fresh cluster" to "ARGUS responding on
`https://argus.example.invalid`":

```bash
# 1) Pull the Bitnami sub-charts (postgresql / redis / minio).
helm dependency update infra/helm/argus

# 2) Render + lint locally before touching the cluster (mirrors CI).
bash infra/scripts/helm_lint.sh

# 3) Install into the dev namespace with the dev overlay.
helm install argus infra/helm/argus \
  --namespace argus-dev --create-namespace \
  -f infra/helm/argus/values-dev.yaml
```

Windows / PowerShell:

```powershell
helm dependency update infra/helm/argus
.\infra\scripts\helm_lint.ps1
helm install argus infra/helm/argus `
  --namespace argus-dev --create-namespace `
  -f infra/helm/argus/values-dev.yaml
```

The release will:

1. Create `argus-dev` namespace if missing.
2. Install Postgres / Redis / MinIO via the Bitnami sub-charts.
3. Roll out backend / Celery worker / frontend / MCP server
   `Deployment`s wired against the `argus-config` `ConfigMap` and the
   secret references declared under `secrets.*`.
4. Skip Cosign verify-init (`values-dev.yaml` sets
   `cosign.verify.enabled: false`).
5. Skip `NetworkPolicies`, HPA, ServiceMonitor, Ingress, OTel
   `Instrumentation`, `cert-manager`, and `SealedSecrets` (all gated
   off in dev).

For staging or prod, swap the values file and add explicit `--values`
files for any secret references that are not picked up automatically
(see **§6**):

```bash
helm upgrade --install argus infra/helm/argus \
  --namespace argus-prod --create-namespace \
  -f infra/helm/argus/values-prod.yaml \
  --set image.backend.digest=sha256:<real-digest> \
  --set image.celery.digest=sha256:<real-digest> \
  --set image.frontend.digest=sha256:<real-digest> \
  --set image.mcp.digest=sha256:<real-digest>
```

In production the CI pipeline injects the four `image.*.digest` values
from the Cosign-signed release artifact, so the operator never has to
type a digest by hand. The chart `_helpers.tpl` `argus.imageRef` helper
**fails the render** if any production deploy still has the all-zero
placeholder (`sha256:0000…`).

---

## 3. Per-environment overlays

The chart ships with three opinionated overlays. Each overlay only
overrides the *delta* from `values.yaml`; never copy the entire
defaults file when editing an overlay — Helm's strategic merge will
take care of the rest.

| Setting                                    | dev                            | staging                                | prod                                              |
| ------------------------------------------ | ------------------------------ | -------------------------------------- | ------------------------------------------------- |
| `replicaCount.backend`                     | 1                              | 2                                      | 3                                                 |
| `replicaCount.celery`                      | 1                              | 2                                      | 4                                                 |
| `replicaCount.frontend`                    | 1                              | 2                                      | 3                                                 |
| `replicaCount.mcp`                         | 1                              | 1                                      | 2                                                 |
| `cosign.verify.enabled`                    | `false`                        | `true`                                 | `true` (chart fails to render if `false`)         |
| `ingress.enabled`                          | `false`                        | `true`                                 | `true`                                            |
| `certManager.enabled`                      | `false`                        | `true` (`letsencrypt-staging`)         | `true` (`letsencrypt-prod`)                       |
| `prometheus.serviceMonitor.enabled`        | `false`                        | `true` (interval `30s`)                | `true` (interval `15s`)                           |
| `otelInstrumentation.enabled`              | `false`                        | `true` (sample 25%)                    | `true` (sample 5%)                                |
| `hpa.enabled`                              | `false`                        | `true` (backend 2-5, celery 2-8)       | `true` (backend 3-20, celery 4-40 + custom metric) |
| `pdb.enabled`                              | `false`                        | `true`, `minAvailable: 1`              | `true`, `minAvailable: 2`                          |
| `networkPolicies.enabled`                  | `false`                        | `true` (default-deny + egress)         | `true` (default-deny + egress + cloudIam.aws)     |
| `sealedSecrets.enabled`                    | `false`                        | `true`                                 | `true`                                            |
| `postgresql.primary.persistence.size`      | 5 GiB                          | 50 GiB                                 | 200 GiB                                           |
| `redis.master.persistence.size`            | 1 GiB                          | 8 GiB                                  | 16 GiB (with replication)                         |
| `minio.persistence.size`                   | 5 GiB                          | 100 GiB                                | 500 GiB (4× replicas, distributed mode)           |

The production invariant `cosign.verify.enabled = true` is **chart-side
enforced** — see `templates/_helpers.tpl::argus.cosignAssertProd`. Even
if a misconfigured overlay tries to flip the flag, the render will fail
with a clear error before any manifest reaches the API server.

---

## 4. Image immutability discipline

ARGUS deploys exclusively with image references of the form

```
ghcr.io/your-org/argus-backend@sha256:0123…ABCD
```

never with floating tags such as `:latest` or `:v1.0.0-cycle5`. The
contract is enforced in three layers:

1. **Chart helper** (`_helpers.tpl::argus.imageRef`) renders
   `<repo>@<digest>` and **fails** when the `digest` field is the
   all-zero placeholder while `config.environment == "production"`.
2. **CI release pipeline** (Cycle 4 ARG-033 + ARG-034) signs every
   image with Cosign keyless OIDC and emits the resulting digest into
   the chart values via `--set image.*.digest=…` overrides at install
   time.
3. **Deployment annotation** — every Pod template stamps
   `argus.image.digest/<svc>: "sha256:…"` so `kubectl describe pod`
   reveals which immutable image the workload is actually running.

If the chart ever deploys a tag-only reference, raise a P1 ticket and
roll back; this is a supply-chain regression.

---

## 5. Cosign verify-init flow

Each Pod (`backend`, `celery`, `frontend`, `mcp`) runs an init
container `verify-<svc>` that calls `cosign verify` against Sigstore
*before* the main container starts. The flow:

```
┌──────────────┐    1) kubelet pulls cosign image
│ kubelet      │──────────────────────────────────┐
└──────┬───────┘                                  ▼
       │ 2) starts initContainer            ┌──────────────┐
       │                                    │ verify-<svc> │
       │ 3) cosign verify                   │  (cosign)    │
       │    --certificate-identity-regexp   └──────┬───────┘
       │    --certificate-oidc-issuer              │ 4) Fulcio cert
       │    <repo>@<digest>                        │ 5) Rekor entry
       │                                           ▼
       │                                ┌──────────────────┐
       │                                │ Sigstore (Fulcio │
       │                                │ + Rekor public)  │
       │                                └──────┬───────────┘
       │ 6) verify ok → exit 0                 │
       │                                       │
       ▼                                       │
┌──────────────┐                               │
│ main container│ <───── 7) start ─────────────┘
└──────────────┘
```

Key invariants:

* **Keyless mode is the default**. The chart points
  `--certificate-identity-regexp` at the GitHub Actions
  `release.yml@refs/tags/v*` workflow identity and
  `--certificate-oidc-issuer` at
  `https://token.actions.githubusercontent.com`. Forks must update
  the regex in `values-prod.yaml`.
* **Fallback to keyed mode** is supported for break-glass via
  `cosign.verify.keyed.enabled = true` and a ConfigMap holding
  `cosign.pub`. This is intentionally disabled in `values-prod.yaml`
  so that the keyless invariant is the production happy path.
* **Failure semantics**: when `cosign verify` exits non-zero the
  init container fails, preventing the Pod from starting. Kubelet
  surfaces this as `Init:Error` and the Deployment freezes the
  rollout (because we use `maxUnavailable: 0`). On-call should
  inspect `kubectl logs -c verify-backend …` immediately.
* **Network egress** for the verify-init must reach
  `fulcio.sigstore.dev` and `rekor.sigstore.dev` over TLS 443. The
  default-deny `NetworkPolicy` allows this implicitly because the
  init container shares the Pod's egress allowlist.

---

## 6. SealedSecrets generation procedure

ARGUS forbids plain-text Secret manifests in Git. The procedure
operators MUST follow:

```bash
# 1. Generate a temporary plain Secret (never commit).
cat <<'EOF' > /tmp/argus-postgres.yaml
apiVersion: v1
kind: Secret
metadata:
  name: argus-postgres
  namespace: argus-prod
type: Opaque
stringData:
  password: "<rotate-me>"
EOF

# 2. Seal against the cluster's public key.
kubeseal \
  --controller-namespace=kube-system \
  --controller-name=sealed-secrets-controller \
  --format=yaml \
  < /tmp/argus-postgres.yaml \
  > infra/secrets/argus-postgres-sealed.yaml

# 3. Commit ONLY the sealed manifest.
git add infra/secrets/argus-postgres-sealed.yaml
git commit -m "infra(secrets): rotate argus-postgres (sealed)"

# 4. Apply.
kubectl apply -f infra/secrets/argus-postgres-sealed.yaml

# 5. Wipe the plaintext.
shred -u /tmp/argus-postgres.yaml      # POSIX
Remove-Item /tmp/argus-postgres.yaml   # PowerShell
```

The example file
[`infra/helm/argus/templates/sealedsecrets.yaml.example`](../infra/helm/argus/templates/sealedsecrets.yaml.example)
ships next to the live templates as a hands-on reference. Helm
ignores it because the suffix is `.yaml.example`, not `.yaml`.

The names operators MUST seal:

| SealedSecret name        | Keys                                            |
| ------------------------ | ----------------------------------------------- |
| `argus-postgres`         | `password`                                      |
| `argus-redis`            | `password`                                      |
| `argus-minio`            | `rootUser`, `rootPassword`                      |
| `argus-llm`              | `openai_api_key`, `anthropic_api_key`           |
| `argus-webhooks`         | `slack_signing_secret` (optional)               |
| `argus-tls`              | `tls.crt`, `tls.key` (skip if cert-manager)     |

Each key above maps 1:1 to an `existingSecretName` / `existingSecretKey`
field under `secrets.*` in `values.yaml`. Mismatched names surface as
`CreateContainerConfigError` on Pod start.

---

## 7. NetworkPolicies — default-deny baseline

The chart renders six classes of NetworkPolicy:

1. **`default-deny`** — empty `podSelector: {}` with both
   `Ingress` and `Egress` listed under `policyTypes`. Any pod that does
   not match a more specific allow policy is fully isolated.
2. **`allow-dns`** — egress to `kube-system/k8s-app=kube-dns` on
   UDP/TCP 53. Required so that all other policies can resolve cluster
   service names.
3. **`backend-egress`** — backend pods ingress from frontend/mcp on
   the API port + monitoring namespace on the metrics port; egress to
   Postgres, Redis, MinIO, and the LLM provider FQDNs declared under
   `networkPolicies.llmProviders`.
4. **`celery-egress`** — celery pods ingress from monitoring on the
   metrics port; egress to Postgres, Redis, MinIO, and (when
   `sandbox.enabled=true`) sandbox pods on TCP 8443.
5. **`mcp-egress`** — MCP server pods ingress from any source on the
   tool port + monitoring namespace on the metrics port; egress to
   Postgres, Redis, and LLM provider FQDNs.
6. **`frontend-egress`** — frontend ingress from any source on
   the HTTP port; egress to backend only.

Sandbox profiles get one NetworkPolicy each, generated from
`.Values.sandbox.profiles[*].egress`. Profile pods MUST be labelled
`argus.dev/sandbox-profile=<profile-name>`; unlabeled pods get isolated
by the default-deny baseline.

For CNIs without FQDN support the egress block ships an `ipBlock` of
`0.0.0.0/0` with an `except:` carve-out for RFC1918 ranges and
link-local addresses, plus a YAML comment naming the intended FQDN.
For Cilium / Calico Enterprise the FQDN can be enforced natively by
swapping the `ipBlock` for a `dnsName` selector.

---

## 8. Alembic migration runbook

### 8.1. Migration chain

```
001 → 002 → 003 → 004 → 005 → 006 → 007 → 008 → 009 → 010
  → 011 → 012 → 013 → 014 → 015 → 016 → 017
  → 019 → 020 → 021 → 022 → 023 (head)
```

ARG-045 contributes the trailing five revisions:

| Rev | Purpose                                          | RLS   |
| --- | ------------------------------------------------ | ----- |
| 019 | `report_bundles` — per-format report catalogue   | Yes   |
| 020 | `mcp_audit` — per-call MCP audit trail           | Yes   |
| 021 | `notification_dispatch_log` — webhook dispatch   | Yes   |
| 022 | `rate_limiter_state` — token bucket persistence  | No    |
| 023 | `epss_scores` + `kev_catalog` — global intel     | No    |

Note that revision `018` is intentionally absent from the main
history; it was carried in a worktree only and never landed on
`main`. Migration `019` chains directly from `017`.

### 8.2. Round-trip schema diff

The smoke script proves migrations are reversible:

```bash
# POSIX (Linux + macOS)
DATABASE_URL=postgresql+asyncpg://argus:argus@localhost:5432/argus_test \
  bash infra/scripts/migrate_smoke.sh
```

```powershell
# Windows / PowerShell
$env:DATABASE_URL = "postgresql+asyncpg://argus:argus@localhost:5432/argus_test"
.\infra\scripts\migrate_smoke.ps1
```

The script:

1. Runs `alembic upgrade head`.
2. Snapshots the schema via `python -m scripts.dump_alembic_schema`.
3. Runs `alembic downgrade -5` (rolls back the ARG-045 chain).
4. Runs `alembic upgrade head` again.
5. Snapshots the schema a second time.
6. Asserts that the two snapshots are byte-identical.

Any drift exits with a non-zero status code and a unified diff. The
script is the source of truth for the `migrations-smoke` CI job (see
`.github/workflows/ci.yml`).

### 8.3. Production migration procedure

```bash
# 1) Enable maintenance window for canary.
kubectl scale deployment argus-celery --replicas=0 -n argus-prod
kubectl scale deployment argus-backend --replicas=1 -n argus-prod

# 2) Run migrations with the freshly built image.
kubectl run argus-migrate-$(date +%s) \
  --image=ghcr.io/your-org/argus-backend@sha256:<digest> \
  --restart=Never --rm -i \
  --env=DATABASE_URL=$(kubectl get secret argus-postgres-url -o jsonpath='{.data.url}' | base64 -d) \
  -- alembic upgrade head

# 3) Restore replica counts.
kubectl scale deployment argus-celery --replicas=4 -n argus-prod
kubectl scale deployment argus-backend --replicas=3 -n argus-prod
```

Migrations are additive and reversible, but on-call should still
take a Postgres backup snapshot (PITR or `pg_basebackup`) before
running `alembic upgrade head` against prod. See **§9** for the
backup procedure.

### 8.4. Rollback

```bash
kubectl run argus-migrate-rollback-$(date +%s) \
  --image=ghcr.io/your-org/argus-backend@sha256:<previous-digest> \
  --restart=Never --rm -i \
  --env=DATABASE_URL=… \
  -- alembic downgrade -1
```

Rolling back **multiple** revisions (`alembic downgrade -5`) is safe
in staging but should be paired with a logical or PITR restore in
prod because the chart's RLS policies expect the matching schema.

---

## 9. Disaster recovery — backup, restore, RPO/RTO

Targets:

| Class                     | RPO    | RTO    | Backup mechanism                                  |
| ------------------------- | ------ | ------ | ------------------------------------------------- |
| Postgres data plane       | 5 min  | 30 min | Continuous archiving + 6-hour `pg_basebackup`     |
| MinIO objects (evidence)  | 1 hour | 1 hour | Cross-region replication via MinIO `mc mirror`     |
| Redis cache               | n/a    | n/a    | Ephemeral; rebuilt from Postgres + MinIO          |
| Configuration (manifests) | 0      | 5 min  | GitOps mirror in `infra/k8s` + `infra/helm/argus` |
| Secrets (sealed)          | 0      | 5 min  | Sealed manifests in `infra/secrets/`              |

### 9.1. Postgres backup

```bash
# Inside the kube cluster, on a privileged jumpbox.
kubectl exec -n argus-prod argus-postgresql-0 -- \
  pg_basebackup --pgdata=- --format=tar --gzip --verbose \
  > /backups/argus-pg-$(date -u +%Y%m%dT%H%M%SZ).tar.gz

# Encrypt with the operator key, then ship to the off-cluster bucket.
gpg --encrypt --recipient sre@example.invalid \
  /backups/argus-pg-*.tar.gz
aws s3 cp /backups/argus-pg-*.tar.gz.gpg \
  s3://argus-dr-backups/postgres/ \
  --sse=AES256
```

For PITR enable `wal_level=replica`, `archive_mode=on`, and
`archive_command='aws s3 cp %p s3://argus-dr-wal/%f'` via the
`postgresql.primary.extendedConfiguration` value.

### 9.2. Postgres restore

```bash
helm uninstall argus -n argus-prod-restore  # idempotent
helm install argus infra/helm/argus \
  --namespace argus-prod-restore --create-namespace \
  -f infra/helm/argus/values-prod.yaml \
  --set postgresql.primary.persistence.existingClaim=argus-pg-restore-pvc

# Restore base backup into the new PVC, replay WAL up to target time.
kubectl exec -n argus-prod-restore argus-postgresql-0 -- \
  bash -c 'pg_basebackup --pgdata=$PGDATA …'
```

After the data is restored, run `alembic upgrade head` to bring the
schema to the same revision as the backup donor.

### 9.3. MinIO replication

Production `values-prod.yaml` enables `minio.mode: distributed` with
4 replicas. The DR procedure adds `mc mirror` to a secondary cluster:

```bash
mc alias set primary    https://minio-primary.example.invalid <user> <pw>
mc alias set secondary  https://minio-dr.example.invalid       <user> <pw>
mc mirror --watch primary/argus-evidence secondary/argus-evidence
mc mirror --watch primary/argus-reports  secondary/argus-reports
```

### 9.4. GitOps recovery

Because every chart value, sealed secret, and CI workflow lives in
Git, a complete cluster loss is recoverable in three steps:

1. `helm dependency update infra/helm/argus`
2. `kubectl apply -f infra/secrets/`
3. `helm upgrade --install argus infra/helm/argus -f infra/helm/argus/values-prod.yaml`

…followed by the Postgres + MinIO restore procedures above.

---

## 10. Helm release upgrade procedure

ARGUS supports two upgrade strategies.

### 10.1. Rolling upgrade (default)

```bash
helm upgrade argus infra/helm/argus \
  --namespace argus-prod \
  -f infra/helm/argus/values-prod.yaml \
  --atomic --timeout 10m
```

The default `Deployment` strategy is `RollingUpdate` with
`maxSurge: 1`, `maxUnavailable: 0`. Combined with PDBs at
`minAvailable: 2` this guarantees zero downtime.

### 10.2. Canary

```bash
helm upgrade argus-canary infra/helm/argus \
  --namespace argus-prod-canary \
  -f infra/helm/argus/values-prod.yaml \
  --set replicaCount.backend=1 \
  --set ingress.host=canary.argus.example.invalid
```

Direct ~5% of traffic via the ingress controller's canary annotation
(`nginx.ingress.kubernetes.io/canary-weight: "5"`) and watch the
`/metrics` SLO for at least one full business hour before scaling up.

### 10.3. Blue/green

When a release contains a destructive Alembic migration (forbidden
by ARG-045 invariants but possible in future cycles), an operator
can deploy `argus-blue` and `argus-green` side-by-side, point a
fraction of the ingress at `green`, then flip 100% once the schema
soak completes.

---

## 11. Observability — metrics, traces, dashboards

* **Metrics**: Prometheus scrapes `/metrics` on every pod via the
  rendered `ServiceMonitor` resources (only when
  `prometheus.serviceMonitor.enabled=true`). Default labels: chart
  recommended set + `argus.image.digest/<svc>` for forensic correlation.
* **Traces**: the OpenTelemetry Operator picks up the
  `Instrumentation` CR (`templates/otel-instrumentation.yaml`) and
  injects auto-instrumentation into Python and Node.js workloads.
* **Logs**: backend uses structlog NDJSON; `OTEL_PYTHON_LOG_CORRELATION`
  is set to `"true"` so trace + span IDs land in every log line.
* **Dashboards**: see `docs/observability.md` (ARG-041) for the
  Grafana dashboard JSON files; the Helm chart only emits the
  scrape configuration.

---

## 12. Capacity planning — projections

Baseline numbers from internal load tests (`tests/load/baseline_p99.json`):

| Component  | Per replica         | Notes                                         |
| ---------- | ------------------- | --------------------------------------------- |
| Backend    | ~120 RPS @ p99 250ms| FastAPI + asyncpg + Redis cache               |
| Celery     | ~30 scans/h         | 4 workers per replica, profile-aware sandbox  |
| Frontend   | ~500 RPS            | Next.js standalone, mostly static             |
| MCP server | ~50 RPS             | LLM-bound; throughput governed by upstream    |

For each ARGUS tenant assume ~2 backend RPS at steady state and one
scan every five minutes. The default prod overlay (3 backend, 4
celery, 3 frontend) supports ~15 active tenants before HPA kicks in.

Storage:

* Postgres ~1 GiB per 10k findings + JSONB envelopes.
* MinIO ~50 MiB per scan (evidence + reports).
* Redis ~256 MiB working set per 100 active scans.

---

## 13. Troubleshooting — top 10 issues

1. **`Init:Error` on `verify-backend`** — Cosign verify failed.
   Inspect `kubectl logs <pod> -c verify-backend`. Common causes:
   - wrong identity regex in `values-prod.yaml`,
   - clock drift on the node (Sigstore TUF expects ≤5 minute skew),
   - egress block to `fulcio.sigstore.dev`.
2. **`CreateContainerConfigError` referencing `argus-postgres`** —
   sealed secret missing or under wrong name. Re-seal per **§6**.
3. **`ImagePullBackOff` with `manifest unknown`** — the chart
   resolved a digest that GHCR cannot serve. Confirm the digest is
   from a Cosign-signed release artifact, not a manual rebuild.
4. **`alembic upgrade head` hangs** — Postgres is mid-`VACUUM FULL`
   or there is an open transaction holding `ACCESS EXCLUSIVE`.
   `select pg_terminate_backend(pid) from pg_stat_activity where state='idle in transaction';`
5. **HPA never scales celery** — `prometheus-adapter` is not
   serving the `argus_celery_queue_depth` metric. Check the
   `APIService` for `external.metrics.k8s.io/v1beta1`.
6. **`PodDisruptionBudgetViolation` on node drain** — reduce
   `pdb.minAvailable` temporarily (e.g. `kubectl patch pdb …`) and
   restore after the drain. Never disable PDBs in prod.
7. **NetworkPolicy blocks LLM provider** — your CNI does not
   enforce FQDN allowlists. Either deploy an egress proxy and point
   `networkPolicies.llmProviders[].host` at it, or migrate to a
   FQDN-aware CNI (Cilium ≥ 1.14 or Calico Enterprise).
8. **`certificate not yet valid`** — `cert-manager` issuer mismatch
   between staging and prod. Confirm
   `cert-manager.io/cluster-issuer` annotation matches a
   `ClusterIssuer` that exists.
9. **Migrations succeed in staging but fail in prod** — RLS
   policies often surface only when a tenant context is set. Run
   `alembic upgrade head` in a `psql` session with
   `SET app.current_tenant_id = '00000000-0000-0000-0000-000000000001'`.
10. **MinIO disk fills up** — bucket retention is not configured.
    Apply `mc ilm add --expiry-days 90` per bucket and prune with
    `mc rm --recursive --force --older-than 90d`.

---

## 14. Reference appendix

### 14.1. File map

```
infra/helm/argus/
├── Chart.yaml
├── values.yaml
├── values-dev.yaml
├── values-staging.yaml
├── values-prod.yaml
├── templates/
│   ├── _helpers.tpl
│   ├── backend-deployment.yaml
│   ├── celery-worker-deployment.yaml
│   ├── frontend-deployment.yaml
│   ├── mcp-server-deployment.yaml
│   ├── postgres-statefulset.yaml
│   ├── redis-statefulset.yaml
│   ├── minio-statefulset.yaml
│   ├── services.yaml
│   ├── ingress.yaml
│   ├── networkpolicies.yaml
│   ├── servicemonitor.yaml
│   ├── otel-instrumentation.yaml
│   ├── hpa.yaml
│   ├── pdb.yaml
│   ├── configmap.yaml
│   ├── serviceaccount.yaml
│   └── sealedsecrets.yaml.example
infra/scripts/
├── helm_lint.sh / helm_lint.ps1
└── migrate_smoke.sh / migrate_smoke.ps1
backend/
├── alembic/versions/019_reports_table.py
├── alembic/versions/020_mcp_audit_table.py
├── alembic/versions/021_mcp_notification_dispatch_log.py
├── alembic/versions/022_rate_limiter_state_table.py
├── alembic/versions/023_epss_kev_tables.py
├── scripts/dump_alembic_schema.py
└── tests/integration/migrations/test_alembic_smoke.py
.github/workflows/ci.yml   # adds helm-lint + migrations-smoke jobs
```

### 14.2. Value-table cheatsheet

The most operator-relevant knobs:

| Path                                                | Default                                | Override hint                                         |
| --------------------------------------------------- | -------------------------------------- | ----------------------------------------------------- |
| `image.<svc>.digest`                                | placeholder zero digest                | CI injects `--set image.<svc>.digest=sha256:…`        |
| `cosign.verify.enabled`                             | `true`                                 | NEVER `false` in prod                                 |
| `cosign.verify.keyless.certificateIdentityRegexp`   | GitHub Actions `release.yml@refs/tags` | Update for forks                                      |
| `secrets.<area>.existingSecretName`                 | `argus-…`                              | Match SealedSecret names                              |
| `networkPolicies.llmProviders[]`                    | OpenAI + Anthropic                     | Add new providers as you wire them                    |
| `hpa.celery.customMetrics.metricName`               | `argus_celery_queue_depth`             | Requires Prometheus adapter; fall back to CPU only    |
| `postgresql.primary.persistence.size`               | 50 GiB                                 | Bump per tenant projection                            |
| `minio.mode`                                        | `standalone` (dev) / `distributed`     | Distributed needs ≥4 nodes                            |
| `pdb.minAvailable`                                  | 1 (dev/staging) / 2 (prod)             | Match cluster blast-radius                            |

### 14.3. CI gates

The chart and migrations are protected by three CI jobs in
`.github/workflows/ci.yml`:

1. **`helm-lint`** — runs `infra/scripts/helm_lint.sh` against
   `dev`, `staging`, `prod` overlays. Pulls Bitnami sub-charts via
   `helm dependency update`. Validates rendered manifests with
   `kubeconform --strict --skip CustomResourceDefinition` plus the
   datreeio CRDs schema mirror.
2. **`migrations-smoke`** — spins up a `pgvector/pgvector:pg15`
   service container, runs the Layer-A pure-Python tests via
   `pytest tests/integration/migrations/test_alembic_smoke.py`, then
   runs the round-trip shell smoke script.
3. **`build`** — gated on `helm-lint` and `migrations-smoke`; only
   then are the production images built and pushed.

Both gates are required checks for the `main` branch.

---

## 15. Change log pointer

Every change to the chart or migrations MUST be reflected in
`CHANGELOG.md` under the corresponding ARG ticket. ARG-045 itself is
documented under the Cycle 5 heading; future tweaks (e.g. ARG-047
e2e wiring) will append additive entries.

---

_Last updated: 2026-04-21 — ARG-045._
