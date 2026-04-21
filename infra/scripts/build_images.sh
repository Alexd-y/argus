#!/usr/bin/env bash
# =============================================================================
# build_images.sh — local build helper for the 6 ARGUS sandbox images.
# Cycle 3 / ARG-026 (initial 4 profiles); Cycle 4 / ARG-034 (--push); Cycle 5 /
# ARG-048 (recon + network profiles → 6 total).
#
# Iterates argus-kali-{web,cloud,browser,full,recon,network}, builds each
# Dockerfile, and tags it with the resolved version (default: image-internal
# ARG). Optionally pushes both the explicit tag and :latest to the configured
# registry when `--push` is supplied (CI workflow uses this for GHCR delivery).
#
# Usage:
#   infra/scripts/build_images.sh                       # builds all 6 locally
#   infra/scripts/build_images.sh --profile web         # builds only web
#   infra/scripts/build_images.sh --profile all         # explicit all
#   infra/scripts/build_images.sh --tag 1.2.3 --profile cloud
#   infra/scripts/build_images.sh --registry ghcr.io/argus            # tag for push (manual push needed)
#   infra/scripts/build_images.sh --registry ghcr.io/argus --push     # build + push (CI flow)
#
# Flags:
#   --profile {web,cloud,browser,full,recon,network,all}   default: all
#   --tag <version>                          default: 1.0.0
#   --registry <prefix>                      default: "" (local-only)
#   --push                                   push both tags after each build
#                                            (no-op without --registry)
#   --no-cache                               passes through to docker build
#   --dry-run                                print commands, don't execute
#
# Exit codes:
#   0 — all requested builds (and pushes, if any) succeeded
#   1 — argument parsing error
#   2 — docker not available, or --push without --registry
#   3 — at least one build or push failed
# =============================================================================

set -Eeuo pipefail

PROFILE="all"
TAG="1.0.0"
REGISTRY=""
NO_CACHE=""
DRY_RUN=0
PUSH_AFTER_BUILD=0

# ---- flag parsing -----------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="${2:-}"
      shift 2
      ;;
    --tag)
      TAG="${2:-}"
      shift 2
      ;;
    --registry)
      REGISTRY="${2:-}"
      shift 2
      ;;
    --push)
      PUSH_AFTER_BUILD=1
      shift
      ;;
    --no-cache)
      NO_CACHE="--no-cache"
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      sed -n '2,32p' "$0"
      exit 0
      ;;
    *)
      echo "ERROR: unknown flag: $1" >&2
      exit 1
      ;;
  esac
done

# ---- validation -------------------------------------------------------------
case "$PROFILE" in
  web|cloud|browser|full|recon|network|all) ;;
  *)
    echo "ERROR: --profile must be one of {web,cloud,browser,full,recon,network,all}; got: $PROFILE" >&2
    exit 1
    ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is not on PATH; install Docker before running this script." >&2
  exit 2
fi

# --push without --registry would silently push to docker.io/library, which is
# almost never what the operator wants. Refuse early with a clear message.
if [[ "$PUSH_AFTER_BUILD" -eq 1 && -z "$REGISTRY" ]]; then
  echo "ERROR: --push requires --registry <prefix> (e.g. ghcr.io/<org>); refusing implicit docker.io push." >&2
  exit 2
fi

# Resolve repo root (script may be invoked from any cwd).
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SANDBOX_DIR="${REPO_ROOT}/sandbox"

if [[ ! -d "${SANDBOX_DIR}/images" ]]; then
  echo "ERROR: ${SANDBOX_DIR}/images not found; run from a populated repo." >&2
  exit 2
fi

# ---- build matrix -----------------------------------------------------------
# ARG-048 (Cycle 5) extends the matrix with the recon + network profiles.
# Order is alphabetical *modulo cycle introduction* — the four ARG-026
# profiles come first so legacy log greps continue to match the old prefix.
ALL_PROFILES=("web" "cloud" "browser" "full" "recon" "network")
if [[ "$PROFILE" == "all" ]]; then
  PROFILES=("${ALL_PROFILES[@]}")
else
  PROFILES=("$PROFILE")
fi

# Compose final tag prefix. Empty REGISTRY means local-only tag.
if [[ -n "$REGISTRY" ]]; then
  TAG_PREFIX="${REGISTRY}/"
else
  TAG_PREFIX=""
fi

FAILED=()
echo "Building ${#PROFILES[@]} sandbox image(s) at tag ${TAG} (registry='${REGISTRY:-<none>}')"
echo

for profile in "${PROFILES[@]}"; do
  IMAGE_NAME="argus-kali-${profile}"
  DOCKERFILE="${SANDBOX_DIR}/images/${IMAGE_NAME}/Dockerfile"
  TAG_FULL="${TAG_PREFIX}${IMAGE_NAME}:${TAG}"
  TAG_LATEST="${TAG_PREFIX}${IMAGE_NAME}:latest"

  if [[ ! -f "$DOCKERFILE" ]]; then
    echo "WARN: Dockerfile not found for profile=${profile} (${DOCKERFILE}); skipping."
    FAILED+=("$profile (missing Dockerfile)")
    continue
  fi

  echo "─── Building ${IMAGE_NAME} (${TAG_FULL}) ─────────────────────────────"

  CMD=(docker build
       --build-arg "ARGUS_IMAGE_VERSION=${TAG}"
       -f "$DOCKERFILE"
       -t "$TAG_FULL"
       -t "$TAG_LATEST")
  if [[ -n "$NO_CACHE" ]]; then
    CMD+=("$NO_CACHE")
  fi
  CMD+=("$SANDBOX_DIR/images")

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[dry-run] ${CMD[*]}"
  else
    if ! "${CMD[@]}"; then
      echo "ERROR: build failed for profile=${profile}" >&2
      FAILED+=("$profile (build failed)")
      continue
    fi
    echo "OK: built ${TAG_FULL}"
  fi

  # Optional push: registry-prefixed images get both :<tag> and :latest
  # pushed so downstream consumers (compose-smoke, sign-images, trivy-scan)
  # can address the build either by content (sha) or by floating tag.
  if [[ "$PUSH_AFTER_BUILD" -eq 1 ]]; then
    PUSH_REFS=("$TAG_FULL" "$TAG_LATEST")
    PUSH_FAILED=0
    for ref in "${PUSH_REFS[@]}"; do
      if [[ "$DRY_RUN" -eq 1 ]]; then
        echo "[dry-run] docker push ${ref}"
        continue
      fi
      if ! docker push "$ref"; then
        echo "ERROR: docker push ${ref} failed for profile=${profile}" >&2
        PUSH_FAILED=1
        break
      fi
    done
    if [[ "$PUSH_FAILED" -eq 1 ]]; then
      FAILED+=("$profile (push failed)")
      continue
    fi
    if [[ "$DRY_RUN" -ne 1 ]]; then
      echo "OK: pushed ${TAG_FULL} and ${TAG_LATEST}"
    fi
  fi
  echo
done

if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo
  echo "FAILED:"
  for entry in "${FAILED[@]}"; do
    echo "  - $entry"
  done
  exit 3
fi

echo
if [[ "$PUSH_AFTER_BUILD" -eq 1 ]]; then
  echo "All requested image builds + pushes succeeded."
else
  echo "All requested image builds succeeded."
fi
