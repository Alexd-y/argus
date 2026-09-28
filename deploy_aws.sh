#!/usr/bin/env bash
#
# deploy_aws.sh — idempotent ARGUS deploy for the AWS host.
#
# Safe to re-run. Order: validate .env -> build -> validate settings ->
# migrate DB -> up -d -> health checks. Fails fast on config typos (e.g.
# CAIRN_ENABLED=ture) BEFORE the long image build, so you never chase a
# 90s build only to hit a pydantic bool_parsing error.
#
# Usage:
#   bash deploy_aws.sh
#
# Lab-only override (enables host-process / CLI-parity Cairn drivers):
#   ALLOW_LAB_UNRESTRICTED=1 bash deploy_aws.sh
#
set -euo pipefail

# --- Resolve repo root (script lives at repo root) -------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

COMPOSE_FILE="infra/docker-compose.yml"
ENV_FILE="infra/.env"
DC=(docker compose -f "$COMPOSE_FILE")
ALLOW_LAB_UNRESTRICTED="${ALLOW_LAB_UNRESTRICTED:-0}"
HEALTH_RETRIES="${HEALTH_RETRIES:-40}"
HEALTH_SLEEP="${HEALTH_SLEEP:-3}"

PG_USER="${POSTGRES_USER:-argus}"
PG_DB="${POSTGRES_DB:-argus}"

# --- Pretty logging --------------------------------------------------------
log()  { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m    OK: %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m    WARN: %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# --- 0. Preconditions ------------------------------------------------------
log "Checking prerequisites"
command -v docker >/dev/null 2>&1 || die "docker not found on PATH"
docker compose version >/dev/null 2>&1 || die "docker compose v2 plugin required"
[ -f "$COMPOSE_FILE" ] || die "missing $COMPOSE_FILE — run this from the repo root"
[ -f "$ENV_FILE" ]     || die "missing $ENV_FILE"
ok "docker + compose + files present"

# --- 1. Ensure the CAIRN_* block exists (idempotent, secure defaults) ------
if ! grep -q '^CAIRN_ENABLED=' "$ENV_FILE"; then
  log "CAIRN_* block absent — appending secure defaults to $ENV_FILE"
  cat >> "$ENV_FILE" <<'EOF'

# --- Cairn blackboard engine (OFF by default) ---
CAIRN_ENABLED=false
CAIRN_DEFAULT_ENGINE=pipeline
CAIRN_TICK_INTERVAL_SEC=10
CAIRN_INTENT_TIMEOUT_SEC=900
CAIRN_REASON_TIMEOUT_SEC=900
CAIRN_MAX_WORKERS=8
CAIRN_MAX_RUNNING_PROJECTS=3
CAIRN_MAX_PROJECT_WORKERS=4
CAIRN_MAX_INTENTS_PER_REASON=3
CAIRN_BOOTSTRAP_TIMEOUT_SEC=1800
CAIRN_BOOTSTRAP_CONCLUDE_TIMEOUT_SEC=300
CAIRN_REASON_TIMEOUT_TASK_SEC=600
CAIRN_EXPLORE_TIMEOUT_SEC=1800
CAIRN_EXPLORE_CONCLUDE_TIMEOUT_SEC=300
CAIRN_WORKER_HEALTHCHECK=startup_only
CAIRN_HEALTHCHECK_TIMEOUT_SEC=20
CAIRN_UNHEALTHY_BACKOFF_SEC=5
CAIRN_REJECTED_BACKOFF_SEC=5
CAIRN_CONTAINER_COMPLETED_ACTION=remove
CAIRN_MAX_GRAPH_FACTS=500
CAIRN_MAX_GRAPH_DEPTH=25
CAIRN_PROMPT_GROUP=default
CAIRN_CLI_DRIVERS_ENABLED=false
CAIRN_LOCAL_EXECUTION_ENABLED=false
EOF
  ok "appended CAIRN_* defaults"
fi

# --- 2. Sanitize env (CRLF from Windows edits + trailing spaces) -----------
log "Sanitizing $ENV_FILE (CRLF / trailing whitespace)"
sed -i 's/\r$//' "$ENV_FILE"
sed -i '/^CAIRN_/ s/[[:space:]]\+$//' "$ENV_FILE"
ok "env sanitized"

# --- 3. Validate .env values (fail fast, before the build) -----------------
log "Validating .env"

env_val() {
  # last occurrence wins, strip surrounding whitespace
  grep -E "^$1=" "$ENV_FILE" | tail -n1 | cut -d= -f2- | tr -d '[:space:]'
}

require_bool() {
  local key="$1" val
  val="$(env_val "$key")"
  case "$val" in
    true|false) ;;
    "") die "$key is missing in $ENV_FILE" ;;
    *)  die "$key must be 'true' or 'false' — got '$val' in $ENV_FILE (typo?)" ;;
  esac
  printf '%s' "$val"
}

require_int() {
  local key="$1" val
  val="$(env_val "$key")"
  [ -n "$val" ] || die "$key is missing in $ENV_FILE"
  [[ "$val" =~ ^[0-9]+$ ]] || die "$key must be an integer — got '$val' in $ENV_FILE"
}

CAIRN_ENABLED_VAL="$(require_bool CAIRN_ENABLED)"
CLI_VAL="$(require_bool CAIRN_CLI_DRIVERS_ENABLED)"
LOCAL_VAL="$(require_bool CAIRN_LOCAL_EXECUTION_ENABLED)"

for k in \
  CAIRN_TICK_INTERVAL_SEC CAIRN_INTENT_TIMEOUT_SEC CAIRN_REASON_TIMEOUT_SEC \
  CAIRN_MAX_WORKERS CAIRN_MAX_RUNNING_PROJECTS CAIRN_MAX_PROJECT_WORKERS \
  CAIRN_MAX_INTENTS_PER_REASON CAIRN_BOOTSTRAP_TIMEOUT_SEC \
  CAIRN_BOOTSTRAP_CONCLUDE_TIMEOUT_SEC CAIRN_REASON_TIMEOUT_TASK_SEC \
  CAIRN_EXPLORE_TIMEOUT_SEC CAIRN_EXPLORE_CONCLUDE_TIMEOUT_SEC \
  CAIRN_HEALTHCHECK_TIMEOUT_SEC CAIRN_UNHEALTHY_BACKOFF_SEC \
  CAIRN_REJECTED_BACKOFF_SEC CAIRN_MAX_GRAPH_FACTS CAIRN_MAX_GRAPH_DEPTH; do
  require_int "$k"
done

# Lease timeouts MUST exceed the dispatcher tick (mirrors the startup validator,
# so we catch it here instead of after the build).
TICK="$(env_val CAIRN_TICK_INTERVAL_SEC)"
for k in CAIRN_INTENT_TIMEOUT_SEC CAIRN_REASON_TIMEOUT_SEC; do
  v="$(env_val "$k")"
  [ "$v" -gt "$TICK" ] || die "$k ($v) must be > CAIRN_TICK_INTERVAL_SEC ($TICK)"
done

# Guard the dangerous, lab-only drivers.
if { [ "$CLI_VAL" = "true" ] || [ "$LOCAL_VAL" = "true" ]; }; then
  if [ "$ALLOW_LAB_UNRESTRICTED" != "1" ]; then
    die "CAIRN_CLI_DRIVERS_ENABLED / CAIRN_LOCAL_EXECUTION_ENABLED are lab-only (execution_mode=lab_unrestricted). \
Set them to false for production, or re-run with: ALLOW_LAB_UNRESTRICTED=1 bash deploy_aws.sh"
  fi
  warn "Lab-unrestricted Cairn drivers ENABLED (host-process execution). Ensure this host is an isolated lab."
fi
ok "env valid (cairn_enabled=$CAIRN_ENABLED_VAL, cli_drivers=$CLI_VAL, local_exec=$LOCAL_VAL)"

# --- 4. Build the shared backend image + admin frontend --------------------
log "Building images (backend, admin-frontend)"
"${DC[@]}" build backend admin-frontend
ok "images built"

# --- 5. Validate settings actually load (runs every pydantic validator) ----
log "Validating backend settings load"
"${DC[@]}" run --rm --no-deps backend \
  python -c "from src.core.config import settings; print('settings OK; cairn_enabled=', settings.cairn_enabled)" \
  || die "backend settings failed to load — inspect $ENV_FILE"
ok "settings load cleanly"

# --- 6. Database migrations (066/067/068 + any others) ---------------------
log "Applying DB migrations (alembic upgrade head)"
"${DC[@]}" run --rm backend alembic upgrade head
"${DC[@]}" run --rm backend alembic current
ok "migrations applied"

# --- 7. Start / recreate the stack -----------------------------------------
log "Starting stack (up -d)"
"${DC[@]}" up -d
ok "compose up issued"

# --- 8. Wait for backend health -------------------------------------------
log "Waiting for backend to become healthy"
backend_healthy=0
for i in $(seq 1 "$HEALTH_RETRIES"); do
  status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}nohealthcheck{{end}}' argus-backend 2>/dev/null || echo missing)"
  case "$status" in
    healthy)       backend_healthy=1; break ;;
    nohealthcheck) warn "backend has no healthcheck; skipping wait"; backend_healthy=1; break ;;
    missing)       die "argus-backend container not found (compose up failed)" ;;
    *)             printf '    [%s/%s] backend status=%s\n' "$i" "$HEALTH_RETRIES" "$status"; sleep "$HEALTH_SLEEP" ;;
  esac
done
[ "$backend_healthy" = 1 ] || die "backend not healthy in time — check: ${DC[*]} logs backend"
ok "backend healthy"

# --- 9. Post-deploy checks -------------------------------------------------
log "Post-deploy checks"
"${DC[@]}" ps

echo
log "Cairn tables"
"${DC[@]}" exec -T postgres psql -U "$PG_USER" -d "$PG_DB" -c "\dt cairn*" || warn "could not list cairn tables"

echo
log "worker-cairn recent logs"
"${DC[@]}" logs --tail=20 worker-cairn 2>/dev/null | grep -Ei 'ready|argus\.cairn' || warn "no cairn queue lines yet (may still be starting)"

echo
ok "Deploy finished. cairn_enabled=$CAIRN_ENABLED_VAL"
