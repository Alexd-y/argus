#!/usr/bin/env bash
# infra/scripts/helm_kubeconform.sh
# ──────────────────────────────────────────────────────────────────────────────
# T07 — Helm chart kubeconform schema validation (multi-overlay, multi-K8s).
#
# Renders every value overlay (dev / staging / prod) of `infra/helm/argus/`
# and validates the rendered manifest stream against Kubernetes API schemas
# for a configurable target version. Built CRDs (Prometheus operator,
# OpenTelemetry operator, …) resolve through the datreeio CRDs catalogue.
#
# Differs from `helm_lint.sh` (ARG-045) in three ways:
#   * Pinned `--kubernetes-version` so the gate fails on API-deprecation
#     drift (e.g. `policy/v1beta1` once 1.25 dropped it). `helm_lint.sh`
#     uses kubeconform's default (latest), which masks such drift.
#   * Validates ALL three overlays, not just `prod`.
#   * Emits machine-parseable JSON output so the CI summary step can build
#     a digest table without regex-ing human-readable lines.
#
# Designed to be invoked from:
#   * `.github/workflows/helm-validation.yml` matrix legs (set KUBE_VERSION
#     per leg; the workflow installs helm + kubeconform);
#   * `scripts/argus_validate.py` Gate `helm_kubeconform` (advisory);
#   * developer laptop (`bash infra/scripts/helm_kubeconform.sh`).
#
# Usage:
#   bash infra/scripts/helm_kubeconform.sh [--kube-version 1.31.0]
#   KUBE_VERSION=1.27.0 bash infra/scripts/helm_kubeconform.sh
#
# Exit codes:
#   0 → all overlays render and validate cleanly.
#   2 → helm or kubeconform missing on PATH (operator error).
#   3 → at least one overlay failed schema validation.
#
# The script is intentionally `set -euo pipefail` end-to-end so a silent
# failure mid-pipeline cannot mask a real schema violation.
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# Configuration — every knob has a safe default; override via env or argv.
# ──────────────────────────────────────────────────────────────────────────────

# Default Kubernetes version targets the chart's declared minimum
# (`Chart.yaml::kubeVersion: ">=1.27.0-0"`). Override per CI matrix leg.
KUBE_VERSION="${KUBE_VERSION:-1.29.0}"
KUBECONFORM_OUTPUT="${KUBECONFORM_OUTPUT:-json}"
RELEASE_NAME="${RELEASE_NAME:-argus}"

# Parse one optional flag: --kube-version <X.Y.Z>. Keeps the script
# scriptable from CI matrix legs that prefer flags over env vars.
while [[ $# -gt 0 ]]; do
  case "$1" in
    --kube-version)
      KUBE_VERSION="$2"
      shift 2
      ;;
    --kube-version=*)
      KUBE_VERSION="${1#--kube-version=}"
      shift
      ;;
    -h|--help)
      sed -n '2,30p' "$0"
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART_DIR="${ROOT_DIR}/infra/helm/argus"

# Fake-but-syntactically-valid digests used for render only — never deployed.
# Mirrors helm_lint.sh; production uses CI-injected real digests.
FAKE_DIGEST="sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
PROD_DIGEST_OVERRIDES=(
  --set "image.backend.digest=${FAKE_DIGEST}"
  --set "image.celery.digest=${FAKE_DIGEST}"
  --set "image.frontend.digest=${FAKE_DIGEST}"
  --set "image.mcp.digest=${FAKE_DIGEST}"
)

# Remote CRDs catalogue covers Prometheus operator (ServiceMonitor),
# OpenTelemetry operator (Instrumentation), cert-manager, Argo, and ~600
# other community CRDs. Templated so kubeconform fetches the correct
# schema per `apiVersion` / `kind` pair.
CRD_SCHEMA_LOCATION='https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json'

# CustomResourceDefinition resources themselves (kind: CustomResourceDefinition)
# carry an OpenAPI v3 meta-schema that kubeconform validates loosely; we skip
# them because the chart does not author CRDs (only references them via the
# catalogue above). If the chart starts shipping CRD manifests, drop this skip.
SKIP_KINDS="CustomResourceDefinition"

# ──────────────────────────────────────────────────────────────────────────────
# Pre-flight: required binaries on PATH.
# ──────────────────────────────────────────────────────────────────────────────

if ! command -v helm >/dev/null 2>&1; then
  echo "ERROR: helm not on PATH" >&2
  exit 2
fi
if ! command -v kubeconform >/dev/null 2>&1; then
  echo "ERROR: kubeconform not on PATH" >&2
  echo "       Install: https://github.com/yannh/kubeconform#installation" >&2
  exit 2
fi

cd "${ROOT_DIR}"

echo "==> helm_kubeconform: chart=${CHART_DIR}"
echo "==> helm_kubeconform: kubernetes-version=${KUBE_VERSION}"
echo "==> helm_kubeconform: output-format=${KUBECONFORM_OUTPUT}"
echo "==> helm_kubeconform: helm $(helm version --short 2>/dev/null || echo unknown)"
echo "==> helm_kubeconform: kubeconform $(kubeconform -v 2>&1 | head -n1)"

echo "==> helm_kubeconform: dependency update"
helm dependency update "${CHART_DIR}"

# ──────────────────────────────────────────────────────────────────────────────
# Validation loop — one render+validate pass per overlay. Aggregate failures
# instead of bailing on first to give the operator the full failure surface
# in a single CI run (cheaper feedback loop on multi-overlay drift).
# ──────────────────────────────────────────────────────────────────────────────

OVERLAYS=("dev" "staging" "prod")
FAILED_OVERLAYS=()

for overlay in "${OVERLAYS[@]}"; do
  values_file="${CHART_DIR}/values-${overlay}.yaml"
  if [[ ! -f "${values_file}" ]]; then
    echo "WARN: values-${overlay}.yaml not found at ${values_file} — skipping" >&2
    continue
  fi

  echo
  echo "──────────────────────────────────────────────────────────────────"
  echo "==> helm_kubeconform: validating overlay '${overlay}' (k8s ${KUBE_VERSION})"
  echo "──────────────────────────────────────────────────────────────────"

  # Prod overlay enforces mandatory image digests via `cosignAssertProd`
  # (templates/_helpers.tpl); inject fake digests so render does not bail.
  template_args=(
    template "${RELEASE_NAME}" "${CHART_DIR}"
    -f "${values_file}"
  )
  if [[ "${overlay}" = "prod" ]]; then
    template_args+=("${PROD_DIGEST_OVERRIDES[@]}")
  fi

  # PIPESTATUS captures kubeconform's exit code even when helm template
  # exits 0 — guarding against the silent-failure trap in piped commands.
  set +e
  helm "${template_args[@]}" \
    | kubeconform \
        --strict \
        --summary \
        --output "${KUBECONFORM_OUTPUT}" \
        --kubernetes-version "${KUBE_VERSION}" \
        --skip "${SKIP_KINDS}" \
        --schema-location default \
        --schema-location "${CRD_SCHEMA_LOCATION}" \
        -
  helm_ec="${PIPESTATUS[0]}"
  kubeconform_ec="${PIPESTATUS[1]}"
  set -e

  if [[ "${helm_ec}" -ne 0 ]]; then
    echo "FAIL: helm template exited ${helm_ec} for overlay '${overlay}'" >&2
    FAILED_OVERLAYS+=("${overlay}(helm:${helm_ec})")
    continue
  fi
  if [[ "${kubeconform_ec}" -ne 0 ]]; then
    echo "FAIL: kubeconform exited ${kubeconform_ec} for overlay '${overlay}'" >&2
    FAILED_OVERLAYS+=("${overlay}(kubeconform:${kubeconform_ec})")
    continue
  fi
  echo "PASS: overlay '${overlay}' validated against k8s ${KUBE_VERSION}"
done

echo
echo "──────────────────────────────────────────────────────────────────"
if [[ "${#FAILED_OVERLAYS[@]}" -eq 0 ]]; then
  echo "==> helm_kubeconform: OK (all overlays valid against k8s ${KUBE_VERSION})"
  exit 0
fi

echo "==> helm_kubeconform: FAILED overlays: ${FAILED_OVERLAYS[*]}" >&2
exit 3
