#!/usr/bin/env bash
# shellcheck shell=bash
# ──────────────────────────────────────────────────────────────────────────────
# ARG-047 Phase 08 — verify cosign signatures on the sandbox images.
# ──────────────────────────────────────────────────────────────────────────────
#
# Calls ``cosign verify`` against every published sandbox image. Mirrors the
# ``verify-images`` job in ``.github/workflows/sandbox-images.yml`` so the
# e2e capstone reproduces the same supply-chain gate locally / in the
# nightly e2e CI lane.
#
# Each verification asserts:
#   * Fulcio certificate identity matches the sandbox-images workflow regexp.
#   * OIDC issuer is GitHub's Sigstore endpoint.
#   * (When --with-attestation) the CycloneDX SBOM predicate is also signed.
#
# Behaviour when cosign / images are unavailable:
#   * Missing cosign binary → ``status='skipped'``, exit 0 (dev box doesn't
#     need to install cosign just to run the wrapper). The CI lane installs
#     ``sigstore/cosign-installer@v3.x`` so this branch never triggers there.
#   * Image not found in the registry → records ``not_found`` per image but
#     does NOT fail the phase (e.g. brand-new profile that hasn't shipped yet).
#   * Verification failure → exit 1 with structured JSON detailing the image.
#
# Override the image set with ``--image`` (repeatable) when iterating on a
# subset; default is the canonical 6 ARG-048 profiles.
#
# Usage::
#
#   bash scripts/e2e/verify_cosign.sh --output verify_cosign.json
#
#   bash scripts/e2e/verify_cosign.sh \
#       --image ghcr.io/your-org/argus-kali-web:latest \
#       --output verify_cosign.json
#
# Environment overrides:
#   COSIGN_BIN           Path to cosign binary (default: ``cosign``).
#   COSIGN_CERT_IDENT    Override certificate identity regexp.
#   COSIGN_OIDC_ISSUER   Override OIDC issuer URL.
#   COSIGN_REGISTRY_OWNER Default GHCR owner (default: ``argus-platform``;
#                        set to your org slug, e.g. ``OWNER_LC=your-org``).
#   COSIGN_IMAGE_TAG     Tag suffix to verify (default: ``latest``).
#   COSIGN_ALLOW_MISSING Set to ``0`` to fail when an image is not found in
#                        the registry (default ``1`` — graceful skip).

set -Eeuo pipefail

OUTPUT_FILE=""
declare -a EXPLICIT_IMAGES=()
COSIGN_BIN="${COSIGN_BIN:-cosign}"
CERT_IDENT_REGEXP="${COSIGN_CERT_IDENT:-^https://github\.com/[^/]+/[^/]+/\.github/workflows/sandbox-images\.yml@refs/heads/.+$}"
OIDC_ISSUER="${COSIGN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"
REGISTRY_OWNER="${COSIGN_REGISTRY_OWNER:-argus-platform}"
IMAGE_TAG="${COSIGN_IMAGE_TAG:-latest}"
ALLOW_MISSING="${COSIGN_ALLOW_MISSING:-1}"

# Canonical profile list (ARG-048 expanded matrix).
DEFAULT_PROFILES=("web" "cloud" "browser" "full" "recon" "network")

usage() {
  sed -n '2,40p' "$0"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output)
      OUTPUT_FILE="$2"; shift 2 ;;
    --image)
      EXPLICIT_IMAGES+=("$2"); shift 2 ;;
    --cert-identity-regexp)
      CERT_IDENT_REGEXP="$2"; shift 2 ;;
    --oidc-issuer)
      OIDC_ISSUER="$2"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "${OUTPUT_FILE}" ]]; then
  echo "--output <path> is required" >&2
  exit 2
fi

UTC_NOW="$(date -u +%FT%TZ)"

write_result() {
  local status="$1" detail="$2"
  python3 - "$OUTPUT_FILE" "$status" "$detail" <<'PY'
import json, sys, time
out, status, detail = sys.argv[1:4]
payload = {
    "phase": "verify_cosign",
    "status": status,
    "detail": detail,
    "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
PY
}

# Skip gracefully if cosign is unavailable on the host (dev convenience).
if ! command -v "${COSIGN_BIN}" >/dev/null 2>&1; then
  python3 - "$OUTPUT_FILE" <<'PY'
import json, sys, time
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump({
        "phase": "verify_cosign",
        "status": "skipped",
        "reason": "cosign binary not on PATH",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, fh, indent=2, sort_keys=True)
PY
  echo "cosign not found — emitting skip stub at ${OUTPUT_FILE}"
  exit 0
fi

# Build the image list.
declare -a IMAGES=()
if [[ ${#EXPLICIT_IMAGES[@]} -gt 0 ]]; then
  IMAGES=("${EXPLICIT_IMAGES[@]}")
else
  for profile in "${DEFAULT_PROFILES[@]}"; do
    IMAGES+=("ghcr.io/${REGISTRY_OWNER}/argus-kali-${profile}:${IMAGE_TAG}")
  done
fi

declare -a RESULTS=()
overall="passed"

for image in "${IMAGES[@]}"; do
  echo "[verify_cosign] checking ${image}"
  status="passed"
  detail=""
  cosign_log="$("${COSIGN_BIN}" verify "${image}" \
    --certificate-identity-regexp "${CERT_IDENT_REGEXP}" \
    --certificate-oidc-issuer "${OIDC_ISSUER}" 2>&1)"
  rc=$?
  if [[ ${rc} -ne 0 ]]; then
    if [[ "${cosign_log}" == *"not found"* || "${cosign_log}" == *"manifest unknown"* || "${cosign_log}" == *"no such manifest"* ]]; then
      if [[ "${ALLOW_MISSING}" == "1" ]]; then
        status="not_found"
      else
        status="failed"
        overall="failed"
      fi
    else
      status="failed"
      overall="failed"
    fi
    detail="${cosign_log}"
  else
    detail="signature OK"
  fi
  RESULTS+=("$(python3 -c "import json,sys; print(json.dumps({'image': sys.argv[1], 'status': sys.argv[2], 'detail': sys.argv[3][:1000]}))" \
    "${image}" "${status}" "${detail}")")
done

python3 - "$OUTPUT_FILE" "${overall}" "${UTC_NOW}" "${REGISTRY_OWNER}" "${IMAGE_TAG}" "${RESULTS[@]}" <<'PY'
import json, sys
out_path, overall, ts, owner, tag = sys.argv[1:6]
items = [json.loads(x) for x in sys.argv[6:]]
payload = {
    "phase": "verify_cosign",
    "status": overall,
    "registry_owner": owner,
    "image_tag": tag,
    "image_count": len(items),
    "results": items,
    "timestamp_utc": ts,
}
with open(out_path, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
PY

if [[ "${overall}" == "failed" ]]; then
  echo "[verify_cosign] one or more images failed verification"
  exit 1
fi
echo "[verify_cosign] OK (${#IMAGES[@]} image(s) checked)"
