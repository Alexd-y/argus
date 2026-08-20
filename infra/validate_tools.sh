#!/usr/bin/env sh
# validate_tools.sh — fail-closed build-time check that every REQUIRED tool
# executable declared by the signed ARGUS catalog is present on PATH inside a
# sandbox image.
#
# The manifest (infra/sandbox/expected_executables.json) is generated from the
# 162 signed tool descriptors by backend/scripts/generate_tool_executables.py.
# This script is meant to run as a build stage inside each sandbox image
# (P0.3 of the ARGUS overhaul: "проверка наличия каждого исполняемого файла из
# списка 162 дескрипторов через command -v ... и падает, если что-то
# отсутствует").
#
# Usage:
#   validate_tools.sh [--manifest PATH] [--profile IMAGE] [--strict]
#
#   --manifest PATH   Path to expected_executables.json
#                     (default: $ARGUS_EXPECTED_EXECUTABLES or
#                      /opt/argus/expected_executables.json)
#   --profile IMAGE   Only validate executables whose descriptor targets this
#                     image profile (e.g. argus-kali-web). Empty = all.
#   --strict          Also fail when an ARGUS wrapper script is missing
#                     (default: missing wrappers are a non-fatal warning).
#
# Exit codes:
#   0 — all required executables present
#   1 — at least one required binary (or, under --strict, wrapper) missing
#   2 — usage / environment error (no jq, manifest not found)
set -u

MANIFEST="${ARGUS_EXPECTED_EXECUTABLES:-/opt/argus/expected_executables.json}"
PROFILE=""
STRICT=0

usage() {
    echo "usage: validate_tools.sh [--manifest PATH] [--profile IMAGE] [--strict]" >&2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --manifest) MANIFEST="$2"; shift 2 ;;
        --profile) PROFILE="$2"; shift 2 ;;
        --strict) STRICT=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "validate_tools: unknown argument: $1" >&2; usage; exit 2 ;;
    esac
done

if ! command -v jq >/dev/null 2>&1; then
    echo "validate_tools: jq is required but not found on PATH" >&2
    exit 2
fi
if [ ! -f "$MANIFEST" ]; then
    echo "validate_tools: manifest not found: $MANIFEST" >&2
    exit 2
fi

# Emit "kind<TAB>name" rows for the selected scope. Reading from a temp file
# (not a pipe) keeps the counters in the current shell under POSIX sh.
rows_file="$(mktemp)"
trap 'rm -f "$rows_file"' EXIT
if [ -n "$PROFILE" ]; then
    jq -r --arg p "$PROFILE" \
        '.executables[] | select(.images | index($p)) | "\(.kind)\t\(.name)"' \
        "$MANIFEST" > "$rows_file"
else
    jq -r '.executables[] | "\(.kind)\t\(.name)"' "$MANIFEST" > "$rows_file"
fi

ok=0
missing_binary=0
missing_wrapper=0

echo "=== ARGUS tool validation (profile=${PROFILE:-ALL}, strict=${STRICT}) ==="
while IFS="$(printf '\t')" read -r kind name; do
    [ -z "$name" ] && continue
    if command -v "$name" >/dev/null 2>&1; then
        ok=$((ok + 1))
    elif [ "$kind" = "wrapper" ]; then
        echo "WARN    missing wrapper: $name" >&2
        missing_wrapper=$((missing_wrapper + 1))
    else
        echo "MISSING binary: $name" >&2
        missing_binary=$((missing_binary + 1))
    fi
done < "$rows_file"

echo "validate_tools: ok=${ok} missing_binary=${missing_binary} missing_wrapper=${missing_wrapper}"

rc=0
if [ "$missing_binary" -gt 0 ]; then
    rc=1
fi
if [ "$STRICT" -eq 1 ] && [ "$missing_wrapper" -gt 0 ]; then
    rc=1
fi
exit "$rc"
