#!/usr/bin/env bash
# shellcheck shell=bash
# ──────────────────────────────────────────────────────────────────────────────
# ARG-047 — End-to-end capstone wrapper (Backlog/dev1_md §19.4).
# ──────────────────────────────────────────────────────────────────────────────
#
# Drives the full ARGUS stack against a live OWASP Juice Shop and asserts the
# 11-phase contract documented in ``docs/e2e-testing.md``:
#
#   01  Bring up Docker Compose stack (``docker compose up -d --wait``).
#   02  Poll backend ``/ready`` until 200.
#   03  POST  /api/v1/scans  — trigger scan against juice-shop.
#   04  GET   /api/v1/scans/<id> — poll until ``status=completed``.
#   05  POST  /api/v1/scans/<id>/reports/generate-all — enqueue report bundle.
#   06  Verify reports via ``scripts/e2e/verify_reports.py``.
#   07  Verify OAST callbacks via ``scripts/e2e/verify_oast.py``.
#   08  Verify cosign signatures via ``scripts/e2e/verify_cosign.sh`` (best-
#       effort — sandbox images may not be GHCR-published in dev).
#   09  Verify Prometheus metrics via ``scripts/e2e/verify_prometheus.py``.
#   10  Assert findings count >= ``E2E_MIN_FINDINGS`` (default 50).
#   11  Tear down the stack and archive results.
#
# Every phase has an explicit timeout (3× expected wall-time per Backlog §17
# flake-prevention guidance) and writes a structured JSON status block to
# ``${RESULTS_DIR}/phase-<NN>-<name>.json``. A consolidated
# ``${RESULTS_DIR}/summary.json`` is produced at the end (success or failure).
#
# Required runtime env:
#   E2E_TOKEN         API key for the backend (defaults to the e2e-only
#                     ``e2e-api-key-not-for-production`` baked into the
#                     compose file). DO NOT use a production key.
#
# Optional env:
#   E2E_TARGET            Scan target URL (default ``http://juice-shop:3000``).
#                         When invoking from the host shell, prefer
#                         ``http://localhost:3000`` so the host can reach it.
#                         Inside the docker network, ``juice-shop:3000`` is
#                         resolved by Docker's embedded DNS.
#   E2E_BACKEND_URL       Backend base URL (default ``http://localhost:8000``).
#   E2E_PROM_URL          Prometheus base URL (default ``http://localhost:9090``).
#   E2E_MIN_FINDINGS      Minimum total findings expected (default 50).
#   E2E_EXPECTED_REPORTS  Expected report count per scan; default 12 (3 tiers
#                         × 4 formats per current ``DEFAULT_GENERATE_ALL_FORMATS``).
#                         The Backlog §19.4 long-term invariant is 18 reports
#                         (3 × 6) once SARIF/JUNIT are exposed via the API.
#                         Override to 18 in the CI lane that drives the
#                         extended bundle.
#   E2E_SCAN_MODE         ``quick`` | ``standard`` | ``deep`` (default
#                         ``standard`` to balance coverage and CI wall-time).
#   E2E_RESULTS_DIR       Where to write phase JSON / archive (default:
#                         ``./e2e-results-<utc-stamp>``).
#   E2E_KEEP_STACK        Set to ``1`` to skip Phase 10 teardown (debug only).
#   E2E_VERBOSE           Set to ``1`` for ``set -x``-style tracing.
#   E2E_COMPOSE_FILE      Override compose file path (default
#                         ``infra/docker-compose.e2e.yml``).
#
# Exit codes:
#   0   All phases passed.
#   1   Pre-flight check failed (docker / curl / jq / python missing).
#   2   Phase failed (see ``summary.json::failed_phase``).
#   3   Internal wrapper error (programming bug — file an issue).
#
# Style:
#   * POSIX-compatible bash; tested on macOS bash 3.2 + Ubuntu 24.04 bash 5.x.
#   * No GNU-only flags. ``date -u +%FT%TZ`` is the only modern flag used and
#     it is supported on every platform we target (Linux, macOS, WSL).
# ──────────────────────────────────────────────────────────────────────────────

set -Eeuo pipefail

# ── Constants ──────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${E2E_COMPOSE_FILE:-${REPO_ROOT}/infra/docker-compose.e2e.yml}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

# Defaults — every override is explicit so the wrapper's behaviour is
# deterministic when invoked from CI (no surprises from an exported env).
E2E_TARGET="${E2E_TARGET:-http://juice-shop:3000}"
E2E_BACKEND_URL="${E2E_BACKEND_URL:-http://localhost:8000}"
E2E_PROM_URL="${E2E_PROM_URL:-http://localhost:9090}"
E2E_TOKEN="${E2E_TOKEN:-e2e-api-key-not-for-production}"
E2E_MIN_FINDINGS="${E2E_MIN_FINDINGS:-50}"
E2E_EXPECTED_REPORTS="${E2E_EXPECTED_REPORTS:-12}"
E2E_SCAN_MODE="${E2E_SCAN_MODE:-standard}"
E2E_KEEP_STACK="${E2E_KEEP_STACK:-0}"
E2E_VERBOSE="${E2E_VERBOSE:-0}"

# Phase timeouts (seconds) — generous per Backlog §17.
TIMEOUT_COMPOSE_UP=300       # docker compose up --wait
TIMEOUT_BACKEND_READY=180    # /ready polling
TIMEOUT_SCAN_COMPLETE=2400   # full scan: 40 min
TIMEOUT_REPORT_GEN=600       # report bundle: 10 min
TIMEOUT_VERIFY=120           # each verify_* helper

UTC_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RESULTS_DIR="${E2E_RESULTS_DIR:-${REPO_ROOT}/e2e-results-${UTC_STAMP}}"

# Internal state — populated as the run progresses.
SCAN_ID=""
BUNDLE_ID=""
FINDINGS_COUNT=0
START_EPOCH="$(date +%s)"

if [[ "${E2E_VERBOSE}" == "1" ]]; then
  set -x
fi

# ── Helpers ────────────────────────────────────────────────────────────────

log() {
  printf '%s [%s] %s\n' "$(date -u +%FT%TZ)" "${1}" "${2}"
}

info()  { log "INFO " "$*"; }
warn()  { log "WARN " "$*" >&2; }
error() { log "ERROR" "$*" >&2; }

die() {
  error "$*"
  write_summary "${PHASE_NAME:-pre_flight}" "$*"
  exit 2
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required tool: ${1}"
}

# Write a phase JSON status block.
write_phase() {
  local name="$1" status="$2" duration="$3" detail="$4"
  local out="${RESULTS_DIR}/phase-${name}.json"
  ${PYTHON_BIN} - "$out" "$name" "$status" "$duration" "$detail" <<'PY'
import json, sys, time
out, name, status, duration, detail = sys.argv[1:6]
payload = {
    "phase": name,
    "status": status,
    "duration_seconds": float(duration),
    "detail": detail,
    "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
PY
}

# Write the consolidated summary file. ``failed_phase`` is empty when all
# phases passed.
write_summary() {
  local failed_phase="$1" failure_detail="${2:-}"
  local end_epoch
  end_epoch="$(date +%s)"
  local total=$((end_epoch - START_EPOCH))
  ${PYTHON_BIN} - "${RESULTS_DIR}/summary.json" \
    "${failed_phase}" "${failure_detail}" \
    "${SCAN_ID}" "${BUNDLE_ID}" \
    "${FINDINGS_COUNT}" "${total}" \
    "${E2E_TARGET}" "${E2E_SCAN_MODE}" \
    "${E2E_MIN_FINDINGS}" "${E2E_EXPECTED_REPORTS}" <<'PY'
import json, os, sys, time
(out, failed_phase, failure_detail, scan_id, bundle_id,
 findings, total, target, scan_mode, min_findings, exp_reports) = sys.argv[1:12]
payload = {
    "schema": "argus.e2e.summary/v1",
    "stack": "argus-e2e",
    "task": "ARG-047",
    "target": target,
    "scan_mode": scan_mode,
    "scan_id": scan_id or None,
    "bundle_id": bundle_id or None,
    "findings_count": int(findings or 0),
    "min_findings_threshold": int(min_findings or 0),
    "expected_reports": int(exp_reports or 0),
    "duration_seconds": int(total or 0),
    "failed_phase": failed_phase or None,
    "failure_detail": failure_detail or None,
    "status": "passed" if not failed_phase else "failed",
    "completed_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
}
os.makedirs(os.path.dirname(out), exist_ok=True)
with open(out, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2, sort_keys=True)
PY
}

# Run a phase: name (snake_case for filename), description, timeout, and
# the body command. Captures duration + stdout into the phase JSON.
run_phase() {
  local name="$1" desc="$2" timeout_s="$3"
  shift 3
  PHASE_NAME="${name}"
  info "Phase ${name}: ${desc} (timeout ${timeout_s}s)"
  local start end status detail
  start="$(date +%s)"
  set +e
  if [[ "${timeout_s}" -gt 0 ]]; then
    detail="$(timeout --preserve-status "${timeout_s}" "$@" 2>&1)"
    status=$?
  else
    detail="$("$@" 2>&1)"
    status=$?
  fi
  set -e
  end="$(date +%s)"
  local dur=$((end - start))
  if [[ ${status} -ne 0 ]]; then
    write_phase "${name}" "failed" "${dur}" "${detail}"
    error "Phase ${name} FAILED after ${dur}s (rc=${status})"
    error "${detail}"
    write_summary "${name}" "exit_code=${status}; ${detail}"
    teardown_on_failure
    exit 2
  fi
  write_phase "${name}" "passed" "${dur}" "${detail}"
  info "Phase ${name} OK (${dur}s)"
}

teardown_on_failure() {
  if [[ "${E2E_KEEP_STACK}" == "1" ]]; then
    warn "E2E_KEEP_STACK=1 — leaving stack running for inspection"
    return 0
  fi
  warn "Capturing diagnostics before teardown..."
  capture_diagnostics || true
  warn "Tearing down compose stack..."
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans >/dev/null 2>&1 || true
}

capture_diagnostics() {
  mkdir -p "${RESULTS_DIR}/diagnostics"
  local svc
  for svc in juice-shop argus-backend argus-celery argus-mcp postgres redis minio prometheus; do
    docker compose -f "${COMPOSE_FILE}" logs --no-color --tail 500 "${svc}" \
      > "${RESULTS_DIR}/diagnostics/${svc}.log" 2>&1 || true
  done
  docker compose -f "${COMPOSE_FILE}" ps --format json \
    > "${RESULTS_DIR}/diagnostics/ps.json" 2>&1 || true
}

# ── Phase implementations ──────────────────────────────────────────────────

phase_compose_up() {
  pushd "${REPO_ROOT}" >/dev/null
  docker compose -f "${COMPOSE_FILE}" pull --quiet 2>&1 || true
  docker compose -f "${COMPOSE_FILE}" up -d --wait --wait-timeout 240
  docker compose -f "${COMPOSE_FILE}" ps
  popd >/dev/null
}

phase_backend_ready() {
  local deadline=$(( $(date +%s) + TIMEOUT_BACKEND_READY ))
  while [[ "$(date +%s)" -lt "${deadline}" ]]; do
    if curl -sf -o /dev/null -w "%{http_code}" \
        "${E2E_BACKEND_URL}/ready" 2>/dev/null | grep -qx "200"; then
      info "Backend /ready returned 200"
      return 0
    fi
    sleep 3
  done
  echo "Backend /ready did not return 200 within ${TIMEOUT_BACKEND_READY}s"
  return 1
}

phase_trigger_scan() {
  local body
  body=$(${PYTHON_BIN} -c "import json,sys; print(json.dumps({'target': sys.argv[1], 'email':'e2e@example.com', 'scan_mode': sys.argv[2]}))" \
    "${E2E_TARGET}" "${E2E_SCAN_MODE}")
  local resp
  resp="$(curl -sf -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${E2E_TOKEN}" \
    -d "${body}" \
    "${E2E_BACKEND_URL}/api/v1/scans")"
  SCAN_ID="$(${PYTHON_BIN} -c "import json,sys; print(json.loads(sys.stdin.read())['scan_id'])" <<<"${resp}")"
  if [[ -z "${SCAN_ID}" ]]; then
    echo "Failed to extract scan_id from response: ${resp}"
    return 1
  fi
  echo "scan_id=${SCAN_ID}"
  echo "${SCAN_ID}" > "${RESULTS_DIR}/scan_id.txt"
}

phase_poll_scan() {
  local deadline=$(( $(date +%s) + TIMEOUT_SCAN_COMPLETE ))
  local prev_status="" cur_status="" cur_progress="" cur_phase=""
  while [[ "$(date +%s)" -lt "${deadline}" ]]; do
    local resp
    resp="$(curl -sf -H "Authorization: Bearer ${E2E_TOKEN}" \
      "${E2E_BACKEND_URL}/api/v1/scans/${SCAN_ID}")" || true
    if [[ -n "${resp}" ]]; then
      cur_status="$(${PYTHON_BIN} -c "import json,sys; print(json.loads(sys.stdin.read()).get('status',''))" <<<"${resp}")"
      cur_progress="$(${PYTHON_BIN} -c "import json,sys; print(json.loads(sys.stdin.read()).get('progress',0))" <<<"${resp}")"
      cur_phase="$(${PYTHON_BIN} -c "import json,sys; print(json.loads(sys.stdin.read()).get('phase',''))" <<<"${resp}")"
      if [[ "${cur_status}" != "${prev_status}" ]]; then
        info "scan ${SCAN_ID}: status=${cur_status} progress=${cur_progress}% phase=${cur_phase}"
        prev_status="${cur_status}"
      fi
      case "${cur_status}" in
        completed)
          echo "Scan completed (final phase=${cur_phase})"
          return 0
          ;;
        failed|cancelled)
          echo "Scan terminated with status=${cur_status} phase=${cur_phase}: ${resp}"
          return 1
          ;;
      esac
    fi
    sleep 10
  done
  echo "Scan did not reach 'completed' within ${TIMEOUT_SCAN_COMPLETE}s (last status=${cur_status} progress=${cur_progress}% phase=${cur_phase})"
  return 1
}

phase_generate_reports() {
  # Trigger generate-all bundle (3 tiers × 4 formats = 12 reports default).
  # Per Backlog §19.4 the long-term invariant is 18 (3 × 6) — when SARIF/JUNIT
  # are exposed via the API the verifier env ``E2E_EXPECTED_REPORTS`` can be
  # raised to 18 without touching this script.
  local resp
  resp="$(curl -sf -X POST \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer ${E2E_TOKEN}" \
    -d '{}' \
    "${E2E_BACKEND_URL}/api/v1/scans/${SCAN_ID}/reports/generate-all")"
  BUNDLE_ID="$(${PYTHON_BIN} -c "import json,sys; print(json.loads(sys.stdin.read()).get('bundle_id',''))" <<<"${resp}" || true)"
  echo "${resp}"
  if [[ -n "${BUNDLE_ID}" ]]; then
    echo "${BUNDLE_ID}" > "${RESULTS_DIR}/bundle_id.txt"
  fi

  # Wait for the pipeline to flip the rows to ``ready`` (or failed).
  local deadline=$(( $(date +%s) + TIMEOUT_REPORT_GEN ))
  while [[ "$(date +%s)" -lt "${deadline}" ]]; do
    local pending
    pending="$(curl -sf -H "Authorization: Bearer ${E2E_TOKEN}" \
      "${E2E_BACKEND_URL}/api/v1/reports?target=${E2E_TARGET}" | \
      ${PYTHON_BIN} -c "import json,sys; rows=json.loads(sys.stdin.read()); print(sum(1 for r in rows if r.get('generation_status') in ('pending','processing')))" \
      2>/dev/null || echo "999")"
    if [[ "${pending}" == "0" ]]; then
      info "All reports moved out of pending/processing"
      return 0
    fi
    sleep 5
  done
  echo "Reports did not finish generating within ${TIMEOUT_REPORT_GEN}s"
  return 1
}

phase_verify_reports() {
  ${PYTHON_BIN} "${SCRIPT_DIR}/e2e/verify_reports.py" \
    --backend-url "${E2E_BACKEND_URL}" \
    --token "${E2E_TOKEN}" \
    --scan-id "${SCAN_ID}" \
    --target "${E2E_TARGET}" \
    --expected-count "${E2E_EXPECTED_REPORTS}" \
    --output "${RESULTS_DIR}/verify_reports.json"
}

phase_verify_oast() {
  ${PYTHON_BIN} "${SCRIPT_DIR}/e2e/verify_oast.py" \
    --backend-url "${E2E_BACKEND_URL}" \
    --token "${E2E_TOKEN}" \
    --scan-id "${SCAN_ID}" \
    --output "${RESULTS_DIR}/verify_oast.json"
}

phase_verify_cosign() {
  bash "${SCRIPT_DIR}/e2e/verify_cosign.sh" \
    --output "${RESULTS_DIR}/verify_cosign.json"
}

phase_verify_prometheus() {
  ${PYTHON_BIN} "${SCRIPT_DIR}/e2e/verify_prometheus.py" \
    --prometheus-url "${E2E_PROM_URL}" \
    --output "${RESULTS_DIR}/verify_prometheus.json"
}

phase_min_findings() {
  local resp count
  resp="$(curl -sf -H "Authorization: Bearer ${E2E_TOKEN}" \
    "${E2E_BACKEND_URL}/api/v1/scans/${SCAN_ID}/findings/statistics")"
  count="$(${PYTHON_BIN} -c "import json,sys; d=json.loads(sys.stdin.read()); print(d.get('total', 0))" <<<"${resp}")"
  FINDINGS_COUNT="${count}"
  echo "{\"findings_count\": ${count}, \"threshold\": ${E2E_MIN_FINDINGS}}" \
    > "${RESULTS_DIR}/findings_count.json"
  if [[ "${count}" -lt "${E2E_MIN_FINDINGS}" ]]; then
    echo "Insufficient findings: got ${count}, need >= ${E2E_MIN_FINDINGS}"
    return 1
  fi
  echo "Findings count OK: ${count} (threshold ${E2E_MIN_FINDINGS})"
}

phase_teardown() {
  capture_diagnostics
  if [[ "${E2E_KEEP_STACK}" == "1" ]]; then
    echo "E2E_KEEP_STACK=1 — skipping teardown"
    return 0
  fi
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans
}

phase_archive() {
  bash "${SCRIPT_DIR}/e2e/archive_results.sh" "${RESULTS_DIR}"
}

# ── Main ───────────────────────────────────────────────────────────────────

main() {
  info "ARG-047 e2e capstone — UTC ${UTC_STAMP}"
  info "Repo root:      ${REPO_ROOT}"
  info "Compose file:   ${COMPOSE_FILE}"
  info "Target:         ${E2E_TARGET}"
  info "Backend URL:    ${E2E_BACKEND_URL}"
  info "Scan mode:      ${E2E_SCAN_MODE}"
  info "Min findings:   ${E2E_MIN_FINDINGS}"
  info "Expected reps:  ${E2E_EXPECTED_REPORTS}"
  info "Results dir:    ${RESULTS_DIR}"

  # Pre-flight tooling check — fail fast with a clear message if the
  # operator's environment is missing a hard dependency.
  for tool in docker curl ${PYTHON_BIN}; do
    require_cmd "${tool}"
  done
  # docker compose v2 plugin — accept either the integrated subcommand or
  # the legacy ``docker-compose`` binary, whichever resolves first.
  if ! docker compose version >/dev/null 2>&1; then
    if ! command -v docker-compose >/dev/null 2>&1; then
      die "docker compose v2 (or legacy docker-compose) is required"
    fi
  fi

  mkdir -p "${RESULTS_DIR}"
  info "Wrote run metadata to ${RESULTS_DIR}/"

  trap 'teardown_on_failure' ERR

  run_phase "01_compose_up"        "Bring up Docker Compose stack"     "${TIMEOUT_COMPOSE_UP}"      phase_compose_up
  run_phase "02_backend_ready"     "Wait for backend /ready"            "${TIMEOUT_BACKEND_READY}"   phase_backend_ready
  run_phase "03_trigger_scan"      "POST /api/v1/scans"                 "${TIMEOUT_VERIFY}"          phase_trigger_scan
  run_phase "04_poll_scan"         "Poll scan until completed"          "${TIMEOUT_SCAN_COMPLETE}"   phase_poll_scan
  run_phase "05_generate_reports"  "Generate report bundle"             "${TIMEOUT_REPORT_GEN}"      phase_generate_reports
  run_phase "06_verify_reports"    "Verify report matrix"               "${TIMEOUT_VERIFY}"          phase_verify_reports
  run_phase "07_verify_oast"       "Verify OAST evidence (best effort)" "${TIMEOUT_VERIFY}"          phase_verify_oast
  run_phase "08_verify_cosign"     "Verify cosign signatures"           "${TIMEOUT_VERIFY}"          phase_verify_cosign
  run_phase "09_verify_prometheus" "Verify Prometheus metrics"          "${TIMEOUT_VERIFY}"          phase_verify_prometheus
  run_phase "10_min_findings"      "Assert findings >= threshold"       "${TIMEOUT_VERIFY}"          phase_min_findings
  run_phase "11_teardown"          "Tear down stack & archive"          "${TIMEOUT_VERIFY}"          phase_teardown
  run_phase "12_archive"           "Archive results"                    "${TIMEOUT_VERIFY}"          phase_archive

  trap - ERR
  write_summary ""
  info "All phases passed. Summary at ${RESULTS_DIR}/summary.json"
}

main "$@"
