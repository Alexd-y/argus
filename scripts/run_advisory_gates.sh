#!/usr/bin/env bash
# T08 — run advisory SCA/SAST gates via the local DoD meta-runner.
# Same surface as .github/workflows/advisory-gates.yml (informational locally).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
exec python scripts/argus_validate.py --only-advisory "$@"
