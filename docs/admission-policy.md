# Kyverno admission — signed images (operator runbook)

> **Status**: Cycle 6 Batch 5, ARG-054. DevOps / platform audience.
> **Policy name**: `argus-require-signed-images` (Kyverno `ClusterPolicy`).

This document explains **what** the policy enforces, **how** it is shipped (standalone YAML vs Helm), **where** it is tested in CI, and **how** to roll it out without pasting credentials or other secrets into documentation or chat logs.

If anything here disagrees with the checked-in YAML, **the repository wins** — keep this file aligned when the policy or workflows change.

---

## 1. Purpose

The ClusterPolicy in `infra/kyverno/cluster-policy-require-signed-images.yaml` is the **supply-chain admission gate** for ARGUS workloads:

- Every workload image must be **Sigstore Cosign keyless**-signed (identity bound to **GitHub Actions OIDC** for the organisation and repository workflow you configure in the attestation `subject` regex).
- Every image reference must use an **immutable digest** (`@sha256:…`). Tag-only references are rejected together with unsigned images.
- The policy matches core workload kinds (Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob) and enforces with `validationFailureAction: Enforce` and `failurePolicy: Fail`.

**Before production:** replace the placeholder `https://github.com/ARGUS-org/ARGUS/.github/workflows/.+` in the YAML (and the Helm template copy) with your real GitHub `org/repo` so signatures match your build pipeline. Do **not** commit real org secrets — only the public identity string that Cosign will attest.

---

## 2. Helm opt-in (`policy.enabled`)

The chart `infra/helm/argus` gates rendering of the same policy with **`policy.enabled`** (default **`false`**) in `infra/helm/argus/values.yaml`. When `true`, `templates/kyverno-cluster-policy.yaml` emits **one** `ClusterPolicy` document; when `false`, it emits **none**, so existing clusters can keep upgrading the chart before every image is signed and digest-pinned.

Drift between the standalone file and the Helm template is blocked in CI by `infra/scripts/check_policy_drift.sh` (also invoked from `admission-policy-kind.yml`).

**Operator checklist:**

1. Ensure cluster has **Kyverno** installed and healthy (version compatible with `policies.kyverno.io/minversion` on the policy).
2. Ensure **Cosign** signing in CI and **digest** promotion for release images.
3. In a **non-prod** namespace or cluster, set `policy.enabled: true` (values overlay or `--set policy.enabled=true`) and validate workloads.
4. Roll forward to production only when all required images are signed and referenced by digest.

---

## 3. CI: behavioural gate (kind + Kyverno)

Workflow: **`.github/workflows/admission-policy-kind.yml`**

- Spins up **kind** with a pinned Kubernetes version, installs the **Kyverno** Helm chart, applies **`infra/kyverno/cluster-policy-require-signed-images.yaml`**.
- **Negative test**: `kubectl run` with an **unsigned, tag-only** public image (`nginx:1.27.0` in the workflow) must be **denied** at server-side dry-run; the denial must reference the policy name.
- **Positive test**: a **built, digest-pinned** fixture image in GHCR, **Cosign keyless**-signed in the job, must be **allowed**.
- Verifies the **Helm** toggle: `policy.enabled=false` → zero `ClusterPolicy` documents; `policy.enabled=true` → exactly one.

This is the behavioural regression net for “unsigned vs signed+digest” **before** you rely on the gate in a live cluster.

---

## 4. CI: Helm + Kyverno CRD schema validation

The **`helm-validation.yml`** workflow includes a job that **renders** the chart with `policy.enabled=true` and validates the rendered ClusterPolicy document against the **Kyverno `ClusterPolicy` v1** JSON schema (from the public CRD catalogue used in that job). That job is the **static** complement to the kind-based workflow: it catches invalid policy shape without a cluster.

**Cross-reference:** open `.github/workflows/helm-validation.yml` and locate the job named **Helm policy.enabled toggle + Kyverno CRD validation** (comments in that file describe the schema URL and pass/fail echo markers).

---

## 5. Security and operational notes

- **No secrets in docs or in policy YAML** — the policy uses **keyless** identity strings and public Rekor; store no tokens in the repo.
- **Rollout order**: pre-prod image signing and digest adoption → enable `policy.enabled` on a staging cluster → monitor Kyverno admission logs and failed Pod events → only then production.
- **Failure to verify images** (network to Rekor/Sigstore, policy mis-config) will **block** workload admission — plan Kyverno controller capacity and webhook timeouts; keep a documented rollback: set `policy.enabled` back to `false` in Helm and upgrade, or remove the `ClusterPolicy` in emergencies (platform procedure, not repeated here to avoid duplicating your internal change control).
- For **troubleshooting**, use `kubectl` events, Kyverno admission controller logs, and the artefacts uploaded by the admission workflow (when debugging CI), not end-user error pages with stack traces.

---

## 6. File map (quick)

| Path | Role |
| ---- | ---- |
| `infra/kyverno/cluster-policy-require-signed-images.yaml` | Source-of-truth ClusterPolicy |
| `infra/helm/argus/templates/kyverno-cluster-policy.yaml` | Helm-rendered copy (gated by `policy.enabled`) |
| `infra/helm/argus/values.yaml` | Default `policy.enabled: false` |
| `.github/workflows/admission-policy-kind.yml` | kind + Kyverno + signed / unsigned tests |
| `.github/workflows/helm-validation.yml` | Helm render + Kyverno CRD schema check |
| `infra/scripts/check_policy_drift.sh` | Ensures standalone vs Helm stay identical |
