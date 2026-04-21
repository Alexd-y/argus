#!/usr/bin/env bash
# infra/scripts/migrate_smoke.sh
# ──────────────────────────────────────────────────────────────────────────────
# Round-trip Alembic migration smoke test.
#
# Steps:
#   1. alembic upgrade head        — apply every migration
#   2. snapshot schema (S1)
#   3. alembic downgrade -5        — roll back the last 5 migrations
#   4. alembic upgrade head        — re-apply
#   5. snapshot schema (S2)
#   6. assert(S1 == S2)            — round-trip is byte-identical
#
# This is the gating script for the `migrations-smoke` CI job. It MUST exit
# non-zero on any drift so the merge is blocked.
#
# Usage:
#   DATABASE_URL=postgresql+psycopg2://argus:argus@localhost:5432/argus_test \
#     ./infra/scripts/migrate_smoke.sh
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BACKEND_DIR="${ROOT_DIR}/backend"
PYTHON_BIN="${PYTHON_BIN:-${BACKEND_DIR}/.venv/bin/python}"

if [ ! -x "${PYTHON_BIN}" ]; then
  PYTHON_BIN="$(command -v python3)"
fi

if [ -z "${DATABASE_URL:-}" ]; then
  echo "ERROR: DATABASE_URL is required" >&2
  exit 2
fi

cd "${BACKEND_DIR}"

echo "==> migrate_smoke: upgrade head (round 1)"
"${PYTHON_BIN}" -m alembic upgrade head

SNAP1="$(mktemp)"
SNAP2="$(mktemp)"
trap 'rm -f "${SNAP1}" "${SNAP2}"' EXIT

echo "==> migrate_smoke: snapshot S1 → ${SNAP1}"
"${PYTHON_BIN}" -m scripts.dump_alembic_schema > "${SNAP1}"

echo "==> migrate_smoke: downgrade -5"
"${PYTHON_BIN}" -m alembic downgrade -5

echo "==> migrate_smoke: upgrade head (round 2)"
"${PYTHON_BIN}" -m alembic upgrade head

echo "==> migrate_smoke: snapshot S2 → ${SNAP2}"
"${PYTHON_BIN}" -m scripts.dump_alembic_schema > "${SNAP2}"

echo "==> migrate_smoke: diff S1 vs S2"
if ! diff -u "${SNAP1}" "${SNAP2}"; then
  echo "ERROR: schema drift detected between round 1 and round 2" >&2
  exit 3
fi

echo "==> migrate_smoke: OK (round-trip schema diff = 0)"
