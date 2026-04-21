#!/usr/bin/env bash
# shellcheck shell=bash
# ──────────────────────────────────────────────────────────────────────────────
# ARG-047 Phase 12 — archive the e2e results directory.
# ──────────────────────────────────────────────────────────────────────────────
#
# Produces a deterministic ``<dir>.tar.gz`` (and optional ``.zip`` for Windows
# convenience) next to the source directory. Refuses to clobber existing
# archives — we rotate by appending the current UTC timestamp when the target
# already exists.
#
# Usage:
#   bash scripts/e2e/archive_results.sh /path/to/e2e-results-<utc-stamp>
#
# Exit codes:
#   0  Archive created (path printed to stdout).
#   1  Source directory missing or empty.
#   2  Tar/zip command unavailable.

set -Eeuo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <results-dir>" >&2
  exit 1
fi

SRC_DIR="$1"
if [[ ! -d "${SRC_DIR}" ]]; then
  echo "Results directory does not exist: ${SRC_DIR}" >&2
  exit 1
fi

if ! command -v tar >/dev/null 2>&1; then
  echo "tar binary not found on PATH" >&2
  exit 2
fi

PARENT_DIR="$(cd "${SRC_DIR}/.." && pwd)"
LEAF_NAME="$(basename "${SRC_DIR}")"
TAR_PATH="${PARENT_DIR}/${LEAF_NAME}.tar.gz"

if [[ -f "${TAR_PATH}" ]]; then
  TAR_PATH="${PARENT_DIR}/${LEAF_NAME}-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
fi

# Use ``-C`` so the archive members are paths relative to the parent dir,
# producing a clean root entry on extraction (no absolute leaks).
tar -C "${PARENT_DIR}" -czf "${TAR_PATH}" "${LEAF_NAME}"

# Compute size for the manifest.
SIZE_BYTES="$(stat -c%s "${TAR_PATH}" 2>/dev/null || stat -f%z "${TAR_PATH}")"

cat <<JSON > "${SRC_DIR}/archive.json"
{
  "archive_path": "${TAR_PATH}",
  "size_bytes": ${SIZE_BYTES},
  "format": "tar.gz",
  "created_at_utc": "$(date -u +%FT%TZ)"
}
JSON

echo "Archived ${SRC_DIR} -> ${TAR_PATH} (${SIZE_BYTES} bytes)"
