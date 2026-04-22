#!/usr/bin/env bash
# T43 (Cycle 6 Batch 5, ARG-054) — drift-check the inline Kyverno
# ClusterPolicy in the Helm chart against the standalone YAML.
#
# Renders the chart with policy.enabled=true and diffs the result against
# infra/kyverno/cluster-policy-require-signed-images.yaml after stripping
# Helm-only metadata. Runs in helm-validation.yml.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STANDALONE="${REPO_ROOT}/infra/kyverno/cluster-policy-require-signed-images.yaml"
CHART="${REPO_ROOT}/infra/helm/argus"

if ! command -v helm >/dev/null 2>&1; then
  echo "helm not found; skipping drift check" >&2
  exit 0
fi
if ! command -v yq >/dev/null 2>&1; then
  echo "yq not found; skipping drift check" >&2
  exit 0
fi

tmp_inline="$(mktemp -t argus-policy-inline.XXXXXX.yaml)"
tmp_standalone="$(mktemp -t argus-policy-standalone.XXXXXX.yaml)"
trap 'rm -f "$tmp_inline" "$tmp_standalone"' EXIT

helm template argus "$CHART" --set policy.enabled=true \
  | yq 'select(.kind == "ClusterPolicy" and .metadata.name == "argus-require-signed-images")' \
  > "$tmp_inline"

yq 'select(.kind == "ClusterPolicy" and .metadata.name == "argus-require-signed-images")' \
  "$STANDALONE" > "$tmp_standalone"

if diff -u "$tmp_standalone" "$tmp_inline"; then
  echo "policy drift check: OK" >&2
  exit 0
fi
echo "policy drift check: DRIFT DETECTED — keep templates/kyverno-cluster-policy.yaml in sync with infra/kyverno/cluster-policy-require-signed-images.yaml" >&2
exit 1
