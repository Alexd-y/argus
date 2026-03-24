#!/usr/bin/env sh
# Optional helper: run XSStrike from the vendor clone (POSIX).
set -e
ROOT="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="${ROOT}/vendor/XSStrike/xsstrike.py"
if [ ! -f "$SCRIPT" ]; then
  echo "Missing $SCRIPT — clone XSStrike into vendor/XSStrike (see README)." >&2
  exit 1
fi
exec python3 "$SCRIPT" "$@"
