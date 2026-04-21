#!/usr/bin/env bash
# infra/scripts/helm_lint.sh
# ──────────────────────────────────────────────────────────────────────────────
# Helm chart lint + render gate.
#
# Steps:
#   1. helm dependency update         — pull bitnami sub-charts.
#   2. helm lint dev / staging / prod — must be clean.
#   3. helm template prod | kubeconform --strict --summary -
#      (only if kubeconform is on PATH)
#
# This is the gating script for the `helm-lint` CI job. It exits non-zero on
# any lint error or kubeconform schema violation.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART_DIR="${ROOT_DIR}/infra/helm/argus"

# Fake-but-syntactically-valid digests used for lint/template rendering only.
# Production uses CI-injected real digests; these never reach a deployed pod.
FAKE_DIGEST="sha256:abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234"
DIGEST_OVERRIDES=(
  --set "image.backend.digest=${FAKE_DIGEST}"
  --set "image.celery.digest=${FAKE_DIGEST}"
  --set "image.frontend.digest=${FAKE_DIGEST}"
  --set "image.mcp.digest=${FAKE_DIGEST}"
)

cd "${ROOT_DIR}"

if ! command -v helm >/dev/null; then
  echo "ERROR: helm not on PATH" >&2
  exit 2
fi

echo "==> helm_lint: dependency update"
helm dependency update "${CHART_DIR}"

for env in dev staging prod; do
  echo "==> helm_lint: lint values-${env}.yaml"
  if [ "${env}" = "prod" ]; then
    helm lint "${CHART_DIR}" -f "${CHART_DIR}/values-${env}.yaml" "${DIGEST_OVERRIDES[@]}"
  else
    helm lint "${CHART_DIR}" -f "${CHART_DIR}/values-${env}.yaml"
  fi
done

echo "==> helm_lint: template render values-prod.yaml"
helm template argus "${CHART_DIR}" -f "${CHART_DIR}/values-prod.yaml" \
  "${DIGEST_OVERRIDES[@]}" >/dev/null

if command -v kubeconform >/dev/null; then
  echo "==> helm_lint: kubeconform --strict"
  helm template argus "${CHART_DIR}" -f "${CHART_DIR}/values-prod.yaml" \
    "${DIGEST_OVERRIDES[@]}" \
    | kubeconform --strict --summary --skip CustomResourceDefinition \
        --schema-location default \
        --schema-location 'https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json' \
        -
else
  echo "WARN: kubeconform not on PATH — skipping CRD schema validation" >&2
fi

echo "==> helm_lint: OK"
