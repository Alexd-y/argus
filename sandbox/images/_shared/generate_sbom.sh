#!/bin/sh
# =============================================================================
# ARGUS sandbox image — shared SBOM generator (CycloneDX 1.5 JSON).
# Cycle 3 / ARG-026.
#
# Contract:
#   - Emits a CycloneDX 1.5 JSON document at the path given as $1 (default:
#     /usr/share/doc/sbom.cdx.json).
#   - Prefers `syft` if installed (real package graph + license + CPE).
#   - Falls back to a `dpkg-query`-driven envelope when syft is absent —
#     enough metadata for Trivy / Grype to do CVE matching against the
#     installed apt packages, without bloating the image with the syft Go
#     binary on every layer.
#   - MUST be runnable at build time (root) AND at runtime (uid 65532), so
#     no chown / chmod beyond what the destination directory already allows.
#   - MUST be hermetic — no network, no /tmp writes outside the wrapper, no
#     dependency on Python.
#
# Usage:
#   /usr/local/bin/generate_sbom.sh [/usr/share/doc/sbom.cdx.json]
#
# Exit codes:
#   0 — SBOM written successfully (either via syft or fallback).
#   1 — destination path is not writable.
#   2 — fallback path failed (dpkg-query missing).
# =============================================================================

set -eu

OUTPUT="${1:-/usr/share/doc/sbom.cdx.json}"
OUTPUT_DIR="$(dirname "$OUTPUT")"

# Make sure the output directory exists. This is idempotent and safe even
# when the script is re-run from a CI step against a pre-existing image.
mkdir -p "$OUTPUT_DIR"

# Prefer syft when present — it produces a complete CycloneDX 1.5 doc with
# package licences, CPEs, and PURL identifiers.
if command -v syft >/dev/null 2>&1; then
  syft dir:/ -o cyclonedx-json="$OUTPUT" --quiet
  echo "SBOM written via syft: $OUTPUT"
  exit 0
fi

# Fallback: dpkg-query envelope. CycloneDX 1.5 minimum schema (bomFormat,
# specVersion, version, components[]). Every apt-installed package becomes a
# component with a deterministic PURL (`pkg:deb/debian/<name>@<version>`),
# which is enough for Trivy / Grype to do CVE matching.
if ! command -v dpkg-query >/dev/null 2>&1; then
  echo "ERROR: neither syft nor dpkg-query is available; cannot emit SBOM." >&2
  exit 2
fi

TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SERIAL="urn:uuid:$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo '00000000-0000-0000-0000-000000000000')"

# Emit the CycloneDX envelope. We intentionally avoid jq (not always
# installed) and build the JSON manually with shell-quoted dpkg fields.
{
  printf '{\n'
  printf '  "bomFormat": "CycloneDX",\n'
  printf '  "specVersion": "1.5",\n'
  printf '  "serialNumber": "%s",\n' "$SERIAL"
  printf '  "version": 1,\n'
  printf '  "metadata": {\n'
  printf '    "timestamp": "%s",\n' "$TIMESTAMP"
  printf '    "tools": [{"vendor": "ARGUS", "name": "generate_sbom.sh", "version": "cycle3-arg026"}],\n'
  printf '    "component": {"type": "container", "name": "%s", "version": "latest"}\n' "${ARGUS_IMAGE_NAME:-argus-kali-image}"
  printf '  },\n'
  printf '  "components": [\n'

  FIRST=1
  # `dpkg-query -W -f=…` is the canonical way to enumerate apt packages.
  # Format: name|version|architecture (newline-separated).
  dpkg-query -W -f='${Package}|${Version}|${Architecture}\n' 2>/dev/null | \
    while IFS='|' read -r name ver arch; do
      [ -z "$name" ] && continue
      if [ "$FIRST" -eq 1 ]; then
        FIRST=0
      else
        printf ',\n'
      fi
      # Escape JSON: double-quote and backslash get escaped; everything else
      # is plain ASCII for apt-installed package names.
      ename="$(printf '%s' "$name" | sed 's/\\/\\\\/g; s/"/\\"/g')"
      ever="$(printf '%s' "$ver" | sed 's/\\/\\\\/g; s/"/\\"/g')"
      earch="$(printf '%s' "$arch" | sed 's/\\/\\\\/g; s/"/\\"/g')"
      printf '    {"type": "library", "name": "%s", "version": "%s", "purl": "pkg:deb/debian/%s@%s?arch=%s"}' \
        "$ename" "$ever" "$ename" "$ever" "$earch"
    done
  printf '\n  ]\n'
  printf '}\n'
} > "$OUTPUT"

# Verify we wrote something non-empty so the next layer fails loudly if the
# fallback misfires (e.g. dpkg-query exited 0 with empty output).
if [ ! -s "$OUTPUT" ]; then
  echo "ERROR: SBOM at $OUTPUT is empty after fallback emission." >&2
  exit 1
fi

echo "SBOM written via dpkg-query fallback: $OUTPUT"
exit 0
