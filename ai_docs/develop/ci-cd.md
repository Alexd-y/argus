# ARGUS CI / CD pipeline

**Audience:** ARGUS engineers maintaining or extending the GitHub Actions pipeline.
**First filed:** 2026-04-21 (Cycle 6, T07 — Helm chart kubeconform schema validation gate).
**Last updated:** 2026-04-21 (T09 sandbox Renovate + advisory SBOM drift check).
**Source-of-truth:** workflow YAML files under `.github/workflows/`. This document describes intent, conventions, and operator runbooks; the code in the workflow files is authoritative for behaviour.

---

## TL;DR

ARGUS CI is built on GitHub Actions. Every PR runs the fast quality bar in `ci.yml` (lint, unit + integration tests, security audit, npm audit, Helm chart lint, Alembic round-trip smoke, MCP OpenAPI drift). Long-running or specialized validations live in dedicated workflow files so they can run on their own cadence (e2e capstone nightly, sandbox image build / scan / sign on chart-only PRs, Helm chart kubeconform on chart-only PRs).

The local meta-runner `scripts/argus_validate.py` mirrors the CI gate matrix so a developer can reproduce the cycle-close DoD §19 sweep on their own laptop.

---

## Workflow inventory

| Workflow file | Trigger | Purpose | Blocking? |
|--------------|---------|---------|-----------|
| `.github/workflows/ci.yml` | push (main, develop), PR (main, develop) | Lint, unit + integration tests, Bandit, Safety, npm audit, Helm chart lint, Alembic round-trip smoke, MCP OpenAPI drift, build. | Yes — required for merge. |
| `.github/workflows/helm-validation.yml` | push (main), PR (main, develop), workflow_dispatch — chart-paths only | Multi-K8s kubeconform validation of all three Helm overlays (T07, this doc). | Yes — required for chart-changing PRs. |
| `.github/workflows/sandbox-images.yml` | push (main), PR — sandbox-paths only | Build / SBOM / Cosign sign / Trivy scan for all 6 sandbox image profiles (ARG-033 / ARG-034 / ARG-048) + **advisory** SBOM fingerprint vs optional baseline ([`infra/scripts/sbom_drift_check.py`](../../infra/scripts/sbom_drift_check.py), T09). | Yes — required for sandbox-changing PRs (SBOM drift step is `continue-on-error`). |
| `.github/workflows/e2e-full-scan.yml` | nightly cron, push (main) on e2e-paths, workflow_dispatch | Full e2e capstone scan against OWASP Juice Shop (12-phase orchestrator, ARG-047). | No — informational; long-running. |
| `.github/workflows/advisory-gates.yml` | PR (path-filtered), nightly `cron: 0 2 * * *` | T08 advisory bundle: `scripts/argus_validate.py --only-advisory` (helm_kubeconform, pip_audit, npm_audit, trivy_fs, bandit). | No — `continue-on-error: true` on the meta-runner step; workflow always exits 0. |

> The list grows on every Cycle close. Prefer separate workflow files over more jobs in `ci.yml` when the new gate has a different cadence or trigger surface — `ci.yml` is on the critical path of every PR.

### Why two helm gates?

`helm-lint` (job in `.github/workflows/ci.yml`, ARG-045) runs on **every** PR — even backend-only ones — as the cheap "did we break the chart at all?" smoke. It validates the **prod** overlay only against kubeconform's bundled latest Kubernetes schema.

`helm-validation.yml` (this section) runs **only when the chart changes** (path-filtered to `infra/helm/argus/**` and the helper scripts) as the comprehensive matrix: **all 3 overlays × 3 explicit Kubernetes versions** (`1.27.0` chart floor, `1.29.0` LTS-ish, `1.31.0` latest stable). It catches API-deprecation drift and per-overlay regressions.

The redundancy on the prod overlay is **intentional**:
- `helm-lint` validates against the latest kubeconform-bundled schema → catches "I broke today's prod-cluster contract".
- `helm-validation` pins explicit K8s versions → catches "this manifest will start failing on the 1.31 cluster six months from now because we used a deprecated API".

**Removing either weakens the gate.** Future consolidation requires moving the always-on smoke responsibility into the path-filtered workflow, which would re-introduce the every-PR cost the original split avoided. Don't do this without buy-in from the operations team.

---

## Helm chart kubeconform validation (T07)

**Workflow file:** [`.github/workflows/helm-validation.yml`](../../.github/workflows/helm-validation.yml).
**Bash script:** [`infra/scripts/helm_kubeconform.sh`](../../infra/scripts/helm_kubeconform.sh).
**PowerShell script:** [`infra/scripts/helm_kubeconform.ps1`](../../infra/scripts/helm_kubeconform.ps1).
**Local meta-runner gate:** `helm_kubeconform` in [`scripts/argus_validate.py`](../../scripts/argus_validate.py) (advisory).
**Closes:** carry-over item #7 in [`ai_docs/develop/issues/ISS-cycle6-carry-over.md`](issues/ISS-cycle6-carry-over.md) §"Known limitations carry-over".

### What it validates

Every PR or push that touches `infra/helm/argus/**`, the helper scripts, or the workflow file itself triggers kubeconform validation against three Kubernetes API versions, in parallel matrix legs:

| Matrix leg | Rationale |
|-----------|-----------|
| `1.27.0` | Chart `kubeVersion: ">=1.27.0-0"` floor — drops the moment a template starts needing 1.28-only fields. |
| `1.29.0` | Mid-range LTS-ish target representing the "boring stable" production cluster. |
| `1.31.0` | Latest stable target for forward-looking production clusters; catches API deprecations early. |

For each leg, the gate:

1. Installs Helm v3.14.4 and kubeconform v0.6.7 (both pinned — never `:latest`, supply-chain hygiene per ARG-033 / ARG-034 conventions).
2. Runs `helm dependency update` so Bitnami sub-charts (postgresql, redis, minio) are present on disk.
3. For each overlay (`values-dev.yaml`, `values-staging.yaml`, `values-prod.yaml`):
   - Renders the chart with `helm template argus infra/helm/argus -f <overlay>` (prod also receives fake-but-syntactically-valid image digests so the `cosignAssertProd` self-protect helper does not bail at render time).
   - Pipes the manifest stream into `kubeconform --strict --summary --output json --kubernetes-version <VER> --skip CustomResourceDefinition --schema-location default --schema-location <datreeio CRDs catalog>`.
4. Aggregates per-overlay verdicts; the leg fails if any overlay reports a schema violation.
5. Uploads the per-leg log as a 14-day artefact and writes a digest into the GitHub Actions job summary.

### Why it matters

`helm lint` only catches Helm-template-level errors (Sprig syntax, missing values, malformed YAML). It does *not* know what a `Deployment` or `ServiceMonitor` is supposed to look like at the Kubernetes API surface. Real schema breakage that `helm lint` will accept silently includes:

* **Typos in field names** — `containers.imagePullPolcy: Always` (note the missing `i`) renders fine, lints fine, deploys fine, and silently uses the cluster default.
* **Field types** — `replicas: "3"` (string instead of int) renders, lints, and is rejected by the API server only at apply time.
* **Deprecated / removed APIs** — `policy/v1beta1 PodDisruptionBudget` was removed in Kubernetes 1.25; a chart written before the removal will pass `helm lint` indefinitely but fail in any modern cluster. The matrix leg targeting 1.31 catches such drift the moment it lands.
* **Custom resources at wrong version** — a `monitoring.coreos.com/v1alpha1 ServiceMonitor` (where the operator only knows `v1`) renders cleanly via Helm but is rejected by the cluster.

By running this gate on every chart-touching PR, the failure surfaces in CI rather than in the operator's terminal halfway through `helm upgrade --install`.

### How to run locally

The same validation that CI runs is one script away on a developer laptop. Pre-requisites (one-time):

* `helm` — see [https://helm.sh/docs/intro/install/](https://helm.sh/docs/intro/install/).
* `kubeconform` v0.6.7+ — see [https://github.com/yannh/kubeconform#installation](https://github.com/yannh/kubeconform#installation).

#### Bash (Linux / macOS / WSL2 / Git Bash on Windows)

```bash
# Default — validates against k8s 1.29.0
bash infra/scripts/helm_kubeconform.sh

# Pin to a specific cluster version
bash infra/scripts/helm_kubeconform.sh --kube-version 1.31.0

# Or via env var
KUBE_VERSION=1.27.0 bash infra/scripts/helm_kubeconform.sh

# Switch to human-readable text output (default is JSON for parseability)
KUBECONFORM_OUTPUT=text bash infra/scripts/helm_kubeconform.sh
```

#### PowerShell (Windows native)

```powershell
# Default — validates against k8s 1.29.0
pwsh infra/scripts/helm_kubeconform.ps1

# Pin to a specific cluster version
pwsh infra/scripts/helm_kubeconform.ps1 -KubeVersion 1.31.0

# Switch to human-readable text output
pwsh infra/scripts/helm_kubeconform.ps1 -Output text

# Via env var (matches bash semantics)
$env:KUBE_VERSION = "1.27.0"
pwsh infra/scripts/helm_kubeconform.ps1
```

#### As part of the local meta-runner sweep

```powershell
# Just the kubeconform gate
python scripts/argus_validate.py --only-gate helm_kubeconform

# Full DoD §19 sweep (kubeconform is one of ~13 gates)
python scripts/argus_validate.py
```

The gate is registered as `required=False` (advisory) until it has been stable in CI for a few weeks. T08 adds a **non-blocking** advisory workflow that runs `helm_kubeconform` together with `pip_audit`, `npm_audit`, `trivy_fs`, and `bandit` via `--only-advisory` (promotion to merge-blocking is a separate, explicit change).

### How to read the CI output / debug a failure

When a leg fails, the GitHub Actions UI shows three layers of detail:

1. **Job summary** (the page that opens by default) — emits a section per matrix leg with a 200-line `kubeconform` tail. Skim this first; the failing resource and its line number are usually called out verbatim.
2. **Step log** ("Run helm_kubeconform.sh ...") — full stdout/stderr including the `helm template` rendering output. Search for `FAIL:` to jump to the failing overlay.
3. **Artefact** (`helm-kubeconform-k8s-<version>`, 14-day retention) — full per-leg log file. Download when the in-line summary truncated something interesting.

Failures usually fall into one of four classes; remediation differs:

| Failure class | Symptom in log | Fix |
|---------------|---------------|-----|
| **Typo / wrong field type** | `unknown field "imagePullPolcy"` or `expected integer, got string` | Fix the field in the chart template; commit to the same PR. |
| **Deprecated API** | `policy/v1beta1 is not valid` against k8s 1.25+ | Upgrade the API version in the chart template (`policy/v1` for PDB). If the chart MUST keep supporting the deprecated version for an old cluster, narrow the matrix temporarily and document the carry-over in the next cycle's ISS file. |
| **Unknown CRD** | `could not find schema for monitoring.coreos.com/v1, Kind=ServiceMonitor` | The CRD is not in the schema catalogue. See "Extending --schema-location" below. |
| **Render-time error** | `helm template exited 1` before kubeconform runs | Render-time bug in the chart (Sprig template error, missing required value). Reproduce locally with `helm template ...` and fix in the chart. |

If the failure is a clear false positive (e.g. a brand-new CRD that no schema source yet documents) and you cannot extend the schema-location array, document the skip in the chart-only PR with the exact `--skip <Kind>` flag added to `helm_kubeconform.sh` and a one-line rationale. Skips are technical debt — track removal in `ai_docs/develop/issues/`.

### Known limitations

* **Schema downloads are network-dependent.** kubeconform fetches CRD schemas from raw.githubusercontent.com on first use. A flaky GitHub Pages ↔ raw.githubusercontent.com link will surface as "could not download schema" for CRD kinds (the default Kubernetes schemas are bundled in the binary and are network-free). The current implementation does not cache schema downloads — for three matrix legs the cold cost is ≤30s, well below the budget.
* **`v1alpha1` / `v1beta1` operator CRDs may be missing from the catalogue.** The datreeio catalogue is community-maintained and lags new operator releases. If a CRD `apiVersion` is not present, kubeconform reports it as unknown — see "Extending --schema-location" below for the workaround.
* **`CustomResourceDefinition` resources themselves are skipped.** The chart does not currently author CRDs (only references them). If a future template starts shipping a CRD definition, drop the `--skip CustomResourceDefinition` flag in `helm_kubeconform.sh` so the meta-schema validates the new manifest.
* **Render-time invariants are not exercised.** `helm template` renders with the values overlay as-is; complex `cosignAssertProd`-style helpers that fail-loud on misconfigured prod values are validated, but cluster-side admission policies (Kyverno, OPA Gatekeeper) are out of scope. Those land in T44 (Cycle 6 Batch 5) under a separate `policy-test` workflow.
* **Only AMD64 Linux runners.** The kubeconform binary download is hard-coded to `linux-amd64`. If the CI fleet ever switches to ARM runners, update the install step in `.github/workflows/helm-validation.yml` to pick the right tarball based on `runner.arch`.

### Extending `--schema-location` for a new CRD

If a chart template starts using a CRD whose schema is not in the datreeio catalogue (or any other catalogue), kubeconform will emit `could not find schema for <Group>/<Version>, Kind=<Kind>`. To fix:

1. **Find an authoritative schema URL.** Most operator projects publish their CRDs as YAML in a `config/crd/` directory in their main repo. Convert the YAML CRD to a JSON OpenAPI v3 schema. Tools like [`crd-extractor`](https://github.com/datreeio/CRDs-catalog#how-to-add-a-new-crd) automate this; the output is one JSON file per `Group/ResourceKind_ResourceAPIVersion.json` triple (matches kubeconform's templated location syntax).
2. **Host the schemas somewhere stable.** Either:
   - Submit a PR to the [datreeio CRDs catalogue](https://github.com/datreeio/CRDs-catalog) — preferred for upstream-maintained CRDs that benefit the whole community.
   - Host inside the ARGUS repo (e.g. `infra/helm/argus/crd-schemas/`), and add the local path as a third `--schema-location`.
3. **Update `infra/scripts/helm_kubeconform.sh` and `.ps1`.** Append the new templated location to the existing `--schema-location` arguments. For the local-fallback case, the path is templated the same way as the URL: `--schema-location 'infra/helm/argus/crd-schemas/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'`.
4. **Verify the new CRD validates clean** — re-run the script locally, confirm no `could not find schema` warnings, then push the chart change + script change in the same commit.

If the CRD is genuinely unschemable (rare — usually it just means the operator never published an OpenAPI spec), add `--skip <Kind>` to the script with a one-line rationale and track the unschemable kind as a `Cycle N+1` debt entry in `ai_docs/develop/issues/`.

---

## Advisory SCA / IaC gates (T08)

**Workflow:** [`.github/workflows/advisory-gates.yml`](../../.github/workflows/advisory-gates.yml).  
**Local entrypoints:** [`scripts/run_advisory_gates.sh`](../../scripts/run_advisory_gates.sh), [`scripts/run_advisory_gates.ps1`](../../scripts/run_advisory_gates.ps1) (repo root → `python scripts/argus_validate.py --only-advisory`).  
**Meta-runner:** [`scripts/argus_validate.py`](../../scripts/argus_validate.py) flag `--only-advisory`.  
**Closes:** ARG-063 extension + SCA carry-over expectations documented in [`ai_docs/develop/issues/ISS-cycle6-carry-over.md`](issues/ISS-cycle6-carry-over.md).

### Advisory gate set (`required=False`)

| Gate | Command surface (fixed argv) | Skip when |
|------|------------------------------|-----------|
| `helm_kubeconform` | `bash infra/scripts/helm_kubeconform.sh` | `kubeconform` / `helm` / `bash` missing, or chart path missing |
| `pip_audit` | `python -m pip_audit --strict --vulnerability-service osv --format json -r …` | `pip_audit` module not installed, or `backend/requirements.txt` missing |
| `npm_audit` | `python scripts/run_npm_audit_gate.py` → `npm audit --audit-level=high --json` per Node package | `npm` missing |
| `trivy_fs` | `trivy fs --severity HIGH,CRITICAL --exit-code 1 --format json --scanners vuln,secret,license --skip-dirs … .` | `trivy` missing |
| `bandit` | `bandit -r src -f json -ll` (cwd `backend/`) | `bandit` missing |

**Kubeval substitution:** T08 does **not** add `kubeval` as a separate fourth tool. Kubernetes YAML schema validation is already covered by `helm_kubeconform` (T07). The fourth net-new gate is **`bandit`** (Python SAST, JSON) so the batch stays complementary without duplicating kubeconform.

### Why `required=False`

These gates collect supply-chain and static-analysis signal without blocking PR merge. Required gates (`ruff_capstone`, `catalog_drift`, `coverage_matrix`) are unchanged. Promotion to blocking status needs a dedicated change + operator sign-off (green streak in CI, noise triage, pinned-tool stability).

### Install commands (local dev)

Pinned versions match the advisory workflow where applicable:

```bash
python -m pip install "pip-audit==2.7.3" "bandit==1.8.6"
# Trivy — pick the same minor as CI (see advisory-gates.yml TRIVY_VERSION)
curl -sSL "https://github.com/aquasecurity/trivy/releases/download/v0.59.1/trivy_0.59.1_Linux-64bit.tar.gz" | sudo tar -xz -C /usr/local/bin trivy
# helm + kubeconform — same pins as ci.yml / helm-validation.yml (v3.14.4, v0.6.7)
```

Node: install Node 20 + run `npm ci` in `Frontend/` and `admin-frontend/` before expecting `npm_audit` to reflect lockfile-resolved trees.

### Operator commands

```powershell
python scripts/argus_validate.py --only-gate pip_audit
python scripts/argus_validate.py --only-advisory
bash scripts/run_advisory_gates.sh
```

### CI behaviour (non-blocking)

The workflow sets **`continue-on-error: true`** on the step that runs `argus_validate.py`. The **job completes successfully** even when individual advisory gates fail; per-gate logs and `advisory_gates_results.json` are uploaded as an artefact, and a short markdown digest is appended to the GitHub Actions job summary.

### Promotion criteria (informal)

- Two to four weeks of nightly + PR runs with acceptable noise (no systemic false positives without a documented waiver).
- Tool pins updated only via reviewed PRs (supply-chain hygiene).
- Optional: flip selected gates to `required=True` in `argus_validate.py` **and** move enforcement into `ci.yml` if merge-blocking behaviour is desired (not done in T08).

---

## Sandbox Renovate + SBOM drift (T09)

**Renovate:** [`renovate.json`](../../renovate.json) at repo root scopes the **dockerfile** manager to the six `sandbox/images/argus-kali-*/Dockerfile` files, groups `kalilinux/kali-rolling` bumps into one weekly PR, applies digest pinning, and adds supply-chain labels. The Renovate GitHub App must be installed for PRs to appear. Full operator runbook: [`ai_docs/develop/sandbox-sbom-renovate.md`](sandbox-sbom-renovate.md).

**Drift check:** After each image build, CI runs `python3 infra/scripts/sbom_drift_check.py --profile <leg> --built-sbom <extracted CycloneDX>` with `continue-on-error: true`. Optional committed baselines live under `sandbox/images/sbom-baselines/<profile>.json`; without them the step only logs fingerprints (bootstrap path). To make drift visible but still non-blocking, add baselines after a reviewed build.

**Closes:** carry-over item §“Sandbox SBOM auto-update on dependency bump” in [`ai_docs/develop/issues/ISS-cycle6-carry-over.md`](issues/ISS-cycle6-carry-over.md).

---

## CI gate registry — `scripts/argus_validate.py`

The local meta-runner `scripts/argus_validate.py` mirrors the CI gate matrix so a developer can reproduce the cycle-close DoD §19 sweep on their laptop without GitHub round-tripping. Each gate is a `Gate` dataclass with:

* `name` — kebab-snake stable identifier (used by `--only-gate` / `--skip-gate`).
* `description` — one-sentence purpose printed by `--list-gates`.
* `argv` — fully-resolved argv list (`shell=False`, no shell metacharacters).
* `cwd` — working directory.
* `timeout_seconds` — hard wall-clock cap.
* `required` — `True` blocks the cycle close on failure; `False` is advisory.
* `requires_binary` / `requires_path` — preconditions for skip semantics.

To add a new gate, append a `Gate(...)` entry to the registry in `_build_gate_registry()` and update the module docstring. New gates start as `required=False` so they cannot block a cycle close until proven stable in CI for a few weeks (the same "deferred-required" promotion pattern used by `helm_kubeconform`, `mypy_capstone`, and the four T08 gates).

---

## Conventions and operator runbooks

* **Pin every binary version.** `kubeconform v0.6.7`, `helm v3.14.4`, `cosign v2.4.1`, `trivy-action 0.28.0`, etc. Version drift is a supply-chain risk; never use `:latest`.
* **Path-filter every dedicated workflow.** Don't waste runner minutes on PRs that don't touch the relevant area. Mirror the path filters in `paths:` for both `pull_request` and `push` triggers.
* **Permissions are read-only by default.** Only escalate (`packages: write`, `id-token: write`) where the workflow specifically needs them (image push, Sigstore keyless OIDC).
* **Add a `concurrency:` group** to each workflow so that stacked pushes on the same ref don't waste runner minutes. Be careful not to cancel scheduled runs.
* **Always emit a job summary on failure.** Per-step logs are noisy; the summary is what the on-call engineer reads first.
* **Upload artefacts on failure** with a finite retention (14-30 days). Forensic value drops sharply after that.

---

## References

* [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) — Fast quality bar (lint, tests, helm-lint, mcp-openapi-drift, etc.).
* [`.github/workflows/helm-validation.yml`](../../.github/workflows/helm-validation.yml) — Multi-K8s kubeconform gate (T07).
* [`.github/workflows/sandbox-images.yml`](../../.github/workflows/sandbox-images.yml) — Sandbox image build / SBOM / Cosign / Trivy.
* [`.github/workflows/e2e-full-scan.yml`](../../.github/workflows/e2e-full-scan.yml) — Nightly + on-demand e2e capstone.
* [`.github/workflows/advisory-gates.yml`](../../.github/workflows/advisory-gates.yml) — T08 advisory SCA/SAST meta-runner (non-blocking).
* [`infra/scripts/helm_kubeconform.sh`](../../infra/scripts/helm_kubeconform.sh) — Bash validator (CI primary).
* [`infra/scripts/helm_kubeconform.ps1`](../../infra/scripts/helm_kubeconform.ps1) — PowerShell validator (Windows dev).
* [`infra/scripts/helm_lint.sh`](../../infra/scripts/helm_lint.sh) — Pre-existing helm lint + render gate (ARG-045).
* [`scripts/argus_validate.py`](../../scripts/argus_validate.py) — Local DoD §19 meta-runner.
* [`ai_docs/develop/issues/ISS-cycle6-carry-over.md`](issues/ISS-cycle6-carry-over.md) — Cycle 6 carry-over backlog (items closed by T07, T08, T09 as noted in-file).
* [`ai_docs/develop/sandbox-sbom-renovate.md`](sandbox-sbom-renovate.md) — Renovate + SBOM baseline runbook (T09).
* [`ai_docs/develop/troubleshooting/mypy-windows-access-violation.md`](troubleshooting/mypy-windows-access-violation.md) — Sister troubleshooting doc for the cross-platform `mypy_capstone` advisory gate.
* [kubeconform README](https://github.com/yannh/kubeconform) — Official tool docs; flag reference.
* [datreeio CRDs catalogue](https://github.com/datreeio/CRDs-catalog) — CRD schema source used by the gate.
