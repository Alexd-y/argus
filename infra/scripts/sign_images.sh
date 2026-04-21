#!/usr/bin/env bash
# =============================================================================
# infra/scripts/sign_images.sh — Cosign keyless production signing pipeline.
# Cycle 4 / ARG-033 (rewrite of the Cycle 3 / ARG-026 dry-run skeleton).
#
# Default mode (since ARG-033): KEYLESS via Sigstore Fulcio + Rekor transparency
# log, authenticated through GitHub Actions OIDC. No long-lived keys are
# required at the call site — Fulcio mints an ephemeral X.509 certificate
# bound to the workflow identity, cosign signs the image, and the signature
# (plus the certificate) lands in Rekor for public, append-only audit.
#
# Rollback mode: if the env var COSIGN_KEY is set (and --dry-run is NOT set),
# the script falls back to keyed signing with a long-lived PEM key (or KMS
# reference). The transparency-log upload is forced OFF in this mode, because
# (a) Sigstore is presumed degraded, and (b) keyed signatures don't have an
# OIDC identity to bind. This is an emergency lever — see
# docs/sandbox-images.md §4e "Rollback to keyed mode" for the runbook and
# the post-incident re-sign procedure.
#
# Usage:
#   infra/scripts/sign_images.sh                                # keyless, all 6
#   infra/scripts/sign_images.sh --profile web                  # only web
#   infra/scripts/sign_images.sh --profile cloud --tag 1.2.3
#   infra/scripts/sign_images.sh --image ghcr.io/x/argus-kali-web:abc123
#   COSIGN_KEY=cosign.key infra/scripts/sign_images.sh          # rollback mode
#   infra/scripts/sign_images.sh --dry-run                      # smoke print
#
# Flags:
#   --profile {web,cloud,browser,full,recon,network,all}   default: all
#   --tag <version>                          default: 1.0.0
#   --registry <prefix>                      default: ""    (local-only tag)
#   --image <full-ref>                       explicit image:tag (overrides
#                                            --profile/--tag/--registry; can
#                                            be repeated to sign N images;
#                                            useful for CI matrix legs)
#   --sbom <path>                            CycloneDX 1.5 JSON SBOM to attest;
#                                            if omitted, the SBOM is extracted
#                                            from the running image at the
#                                            canonical path
#                                            /usr/share/doc/sbom.cdx.json
#   --output-bundle <path>                   default: ./cosign-bundle.json
#   --dry-run                                print commands, do not execute
#                                            (works in BOTH keyless and keyed
#                                            modes; useful for PR validation)
#
# Environment variables:
#   COSIGN_KEY        keyed-rollback signal — when set AND --dry-run is NOT,
#                     the script uses --key <COSIGN_KEY> and disables Rekor
#                     uploads (--tlog-upload=false).
#   COSIGN_PASSWORD   passphrase for the keyed PEM (only used in rollback).
#   COSIGN_EXPERIMENTAL  honoured if you happen to invoke a cosign v1.x; v2.x
#                        treats keyless as default and ignores this flag.
#
# Exit codes:
#   0 — all signing operations succeeded (or printed in dry-run mode)
#   1 — argument parsing error
#   2 — cosign CLI not found
#   3 — at least one signing or attestation operation failed
# =============================================================================

set -Eeuo pipefail

# ---- defaults ---------------------------------------------------------------
PROFILE="all"
TAG="1.0.0"
REGISTRY=""
SBOM_OVERRIDE=""
OUTPUT_BUNDLE="./cosign-bundle.json"
FORCE_DRY_RUN=0
EXPLICIT_IMAGES=()

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
    --image)
      EXPLICIT_IMAGES+=("${2:-}")
      shift 2
      ;;
    --sbom)
      SBOM_OVERRIDE="${2:-}"
      shift 2
      ;;
    --output-bundle)
      OUTPUT_BUNDLE="${2:-}"
      shift 2
      ;;
    --dry-run)
      FORCE_DRY_RUN=1
      shift
      ;;
    -h|--help)
      sed -n '2,60p' "$0"
      exit 0
      ;;
    *)
      echo "ERROR: unknown flag: $1" >&2
      exit 1
      ;;
  esac
done

case "$PROFILE" in
  web|cloud|browser|full|recon|network|all) ;;
  *)
    echo "ERROR: --profile must be one of {web,cloud,browser,full,recon,network,all}; got: $PROFILE" >&2
    exit 1
    ;;
esac

# ---- mode resolution --------------------------------------------------------
# Three modes:
#   DRY_RUN=1                      : print only; safe everywhere
#   DRY_RUN=0, KEYED_ROLLBACK=1    : --key flow (Sigstore down emergency)
#   DRY_RUN=0, KEYED_ROLLBACK=0    : keyless flow (default since ARG-033)
DRY_RUN=0
KEYED_ROLLBACK=0
if [[ "$FORCE_DRY_RUN" -eq 1 ]]; then
  DRY_RUN=1
elif [[ -n "${COSIGN_KEY:-}" ]]; then
  KEYED_ROLLBACK=1
fi

if [[ "$DRY_RUN" -eq 0 ]]; then
  if ! command -v cosign >/dev/null 2>&1; then
    echo "ERROR: cosign CLI not found on PATH; install via the sigstore/cosign-installer GitHub action or 'brew install cosign'." >&2
    exit 2
  fi
  COSIGN_VERSION="$(cosign version 2>/dev/null | awk -F': *v?' '/GitVersion/ {print $2; exit}' || echo unknown)"
  echo "INFO: cosign version: ${COSIGN_VERSION:-unknown}"
fi

# ---- build matrix -----------------------------------------------------------
# ARG-048 (Cycle 5) extends the sign matrix with the recon + network profiles
# so the keyless / keyed signing pipeline now covers all 6 sandbox images.
ALL_PROFILES=("web" "cloud" "browser" "full" "recon" "network")
if [[ "$PROFILE" == "all" ]]; then
  PROFILES=("${ALL_PROFILES[@]}")
else
  PROFILES=("$PROFILE")
fi

if [[ -n "$REGISTRY" ]]; then
  TAG_PREFIX="${REGISTRY}/"
else
  TAG_PREFIX=""
fi

# Compose the final image-ref list. Explicit --image entries win; otherwise
# the (profile × tag × registry) cross-product is used.
IMAGE_REFS=()
if [[ ${#EXPLICIT_IMAGES[@]} -gt 0 ]]; then
  IMAGE_REFS=("${EXPLICIT_IMAGES[@]}")
else
  for profile in "${PROFILES[@]}"; do
    IMAGE_REFS+=("${TAG_PREFIX}argus-kali-${profile}:${TAG}")
  done
fi

# ---- header -----------------------------------------------------------------
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "Cosign signing pipeline — DRY-RUN mode (no commands executed)."
elif [[ "$KEYED_ROLLBACK" -eq 1 ]]; then
  echo "Cosign signing pipeline — KEYED ROLLBACK mode (Sigstore degraded path)."
  echo "  WARNING: transparency-log upload disabled (--tlog-upload=false)."
  echo "  WARNING: signatures bound to long-lived key, NOT to GH OIDC identity."
  echo "  See docs/sandbox-images.md §4e for the post-incident re-sign procedure."
  echo "  key:           ${COSIGN_KEY}"
  echo "  output bundle: ${OUTPUT_BUNDLE}"
else
  echo "Cosign signing pipeline — KEYLESS mode (Sigstore Fulcio + Rekor + GH OIDC)."
  echo "  output bundle: ${OUTPUT_BUNDLE}"
fi
if [[ ${#EXPLICIT_IMAGES[@]} -gt 0 ]]; then
  echo "  source:    --image (explicit refs)"
else
  echo "  profiles:  ${PROFILES[*]}"
  echo "  tag:       ${TAG}"
  echo "  registry:  ${REGISTRY:-<none>}"
fi
echo "  images:    ${#IMAGE_REFS[@]}"
echo

# ---- helpers ----------------------------------------------------------------
# Resolve the SBOM for a given image:
#   1. If --sbom <path> was supplied, return that path.
#   2. Otherwise, in non-dry-run mode, extract /usr/share/doc/sbom.cdx.json
#      from the image into a temp file; print path on stdout.
#   3. In dry-run mode, just echo the canonical path placeholder.
# Sets SBOM_TMP_PATH globally so the caller can rm -f it after attestation.
SBOM_TMP_PATH=""
resolve_sbom_for_image() {
  local image_ref="$1"

  if [[ -n "$SBOM_OVERRIDE" ]]; then
    echo "$SBOM_OVERRIDE"
    return 0
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "<extracted from $image_ref:/usr/share/doc/sbom.cdx.json>"
    return 0
  fi

  if ! command -v docker >/dev/null 2>&1; then
    echo ""
    return 1
  fi

  SBOM_TMP_PATH="$(mktemp -t argus-sbom-XXXXXX.cdx.json)"
  if ! docker run --rm --entrypoint cat "$image_ref" /usr/share/doc/sbom.cdx.json > "$SBOM_TMP_PATH" 2>/dev/null; then
    rm -f "$SBOM_TMP_PATH"
    SBOM_TMP_PATH=""
    echo ""
    return 1
  fi
  echo "$SBOM_TMP_PATH"
}

# Per-image worker. Returns 0 on success, 1 on sign failure, 2 on attest fail.
sign_one() {
  local image_ref="$1"

  echo "─── ${image_ref} ─────────────────────────────────────────────────"

  local sbom_path
  if ! sbom_path="$(resolve_sbom_for_image "$image_ref")"; then
    echo "WARN: could not resolve SBOM for ${image_ref}; attestation will be skipped." >&2
    sbom_path=""
  fi

  if [[ "$DRY_RUN" -eq 1 ]]; then
    if [[ "$KEYED_ROLLBACK" -eq 1 || -n "${COSIGN_KEY:-}" ]]; then
      cat <<EOF
[dry-run] cosign sign \\
  --key "\${COSIGN_KEY}" \\
  --tlog-upload=false \\
  --yes \\
  ${image_ref}
EOF
      if [[ -n "$sbom_path" ]]; then
        cat <<EOF
[dry-run] cosign attest \\
  --key "\${COSIGN_KEY}" \\
  --predicate ${sbom_path} \\
  --type cyclonedx \\
  --tlog-upload=false \\
  --yes \\
  ${image_ref}
EOF
      fi
    else
      cat <<EOF
[dry-run] cosign sign --yes ${image_ref}
EOF
      if [[ -n "$sbom_path" ]]; then
        cat <<EOF
[dry-run] cosign attest --predicate ${sbom_path} --type cyclonedx --yes ${image_ref}
EOF
      fi
    fi
    echo
    return 0
  fi

  # ---- real signing ---------------------------------------------------------
  if [[ "$KEYED_ROLLBACK" -eq 1 ]]; then
    if ! cosign sign \
          --key "${COSIGN_KEY}" \
          --tlog-upload=false \
          --yes \
          "$image_ref"; then
      echo "ERROR: cosign sign (keyed) failed for ${image_ref}" >&2
      return 1
    fi

    if [[ -n "$sbom_path" ]]; then
      if ! cosign attest \
            --key "${COSIGN_KEY}" \
            --predicate "$sbom_path" \
            --type cyclonedx \
            --tlog-upload=false \
            --yes \
            "$image_ref"; then
        echo "ERROR: cosign attest (keyed) failed for ${image_ref}" >&2
        return 2
      fi
    fi
  else
    # Keyless. cosign v2.x treats --tlog-upload=true as default and emits the
    # Rekor entry automatically. We pass --yes to silence the interactive
    # prompt (CI is non-interactive). Identity is supplied transparently by
    # the ambient GH OIDC token (id-token: write).
    if ! cosign sign --yes "$image_ref"; then
      echo "ERROR: cosign sign (keyless) failed for ${image_ref}" >&2
      return 1
    fi

    if [[ -n "$sbom_path" ]]; then
      if ! cosign attest \
            --predicate "$sbom_path" \
            --type cyclonedx \
            --yes \
            "$image_ref"; then
        echo "ERROR: cosign attest (keyless) failed for ${image_ref}" >&2
        return 2
      fi
    fi
  fi

  # Best-effort cleanup of the temp SBOM (only when we created it ourselves).
  if [[ -n "$SBOM_TMP_PATH" && -f "$SBOM_TMP_PATH" ]]; then
    rm -f "$SBOM_TMP_PATH"
    SBOM_TMP_PATH=""
  fi

  echo "OK: signed ${image_ref}"
  echo
  return 0
}

# ---- main loop --------------------------------------------------------------
FAILED=()
SIGNATURES_EMITTED=()

for image_ref in "${IMAGE_REFS[@]}"; do
  if sign_one "$image_ref"; then
    if [[ "$DRY_RUN" -eq 1 ]]; then
      SIGNATURES_EMITTED+=("$image_ref (dry-run)")
    else
      SIGNATURES_EMITTED+=("$image_ref")
    fi
  else
    rc=$?
    case "$rc" in
      1) FAILED+=("$image_ref (sign failed)") ;;
      2) FAILED+=("$image_ref (attest failed)") ;;
      *) FAILED+=("$image_ref (rc=$rc)") ;;
    esac
  fi
done

# ---- summary bundle ---------------------------------------------------------
if [[ "$DRY_RUN" -eq 0 && -n "$OUTPUT_BUNDLE" && ${#SIGNATURES_EMITTED[@]} -gt 0 ]]; then
  MODE="keyless"
  if [[ "$KEYED_ROLLBACK" -eq 1 ]]; then
    MODE="keyed-rollback"
  fi
  printf '{"mode":"%s","signatures":[\n' "$MODE" > "$OUTPUT_BUNDLE"
  FIRST=1
  for entry in "${SIGNATURES_EMITTED[@]}"; do
    if [[ $FIRST -eq 1 ]]; then
      FIRST=0
    else
      printf ',\n' >> "$OUTPUT_BUNDLE"
    fi
    printf '  {"image":"%s","timestamp":"%s"}' "$entry" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$OUTPUT_BUNDLE"
  done
  printf '\n]}\n' >> "$OUTPUT_BUNDLE"
  echo "Bundle written: ${OUTPUT_BUNDLE}"
fi

if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo
  echo "FAILED operations:"
  for entry in "${FAILED[@]}"; do
    echo "  - $entry"
  done
  exit 3
fi

echo
if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "Dry-run complete. ${#SIGNATURES_EMITTED[@]} image(s) would be signed."
elif [[ "$KEYED_ROLLBACK" -eq 1 ]]; then
  echo "Keyed-rollback signing complete. ${#SIGNATURES_EMITTED[@]} image(s) signed (NO Rekor upload)."
else
  echo "Keyless signing complete. ${#SIGNATURES_EMITTED[@]} image(s) signed via Sigstore Fulcio + Rekor."
fi
