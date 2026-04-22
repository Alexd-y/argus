#!/usr/bin/env bash
# T44 (Cycle 6 Batch 5, ARG-054) — build + Cosign-sign the positive fixture image
# used by .github/workflows/admission-policy-kind.yml.
#
# Requires: docker, cosign (keyless via OIDC token; in CI the
# sigstore/cosign-installer action provides that — locally you'll need to be
# logged into Sigstore via `cosign login` or use `--key` against a local key).
#
# Usage:
#   FIXTURE_REPO=ghcr.io/<org>/argus-policy-fixture bash infra/scripts/build_policy_fixture.sh
#
# Optional env:
#   TAG       — image tag (default: short git HEAD SHA)
#   COSIGN_KEY — when set, signs with `--key <COSIGN_KEY>` instead of keyless

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
: "${FIXTURE_REPO:?FIXTURE_REPO env var required (e.g. ghcr.io/<org>/argus-policy-fixture)}"
TAG="${TAG:-$(git -C "$REPO_ROOT" rev-parse --short HEAD)}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi
if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign is required" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cat > "${WORK}/Dockerfile" <<'EOF'
# Distroless static base — no shell, no userland, ~2 MB. The container is
# never executed (CI only uses kubectl --dry-run=server admission), so the
# entrypoint exists purely to satisfy the Dockerfile schema.
FROM gcr.io/distroless/static-debian12
ENTRYPOINT ["/sleep"]
CMD ["infinity"]
EOF

IMG_REF="${FIXTURE_REPO}:${TAG}"
docker build -t "${IMG_REF}" "${WORK}"
docker push "${IMG_REF}"

DIGEST_REF="$(docker inspect --format '{{ index .RepoDigests 0 }}' "${IMG_REF}")"
echo "Pushed: ${DIGEST_REF}" >&2

if [[ -n "${COSIGN_KEY:-}" ]]; then
  cosign sign --key "${COSIGN_KEY}" --yes "${DIGEST_REF}"
else
  cosign sign --yes "${DIGEST_REF}"
fi
echo "Signed: ${DIGEST_REF}" >&2
