#!/usr/bin/env bash
# Deploy a fine-tuned WhiteRabbitNeo GGUF into the live CPU serving container.
#
# Why this exists: training (scripts/training/train_lora_cpu.py) produces a LoRA
# adapter, merges it, and a human converts/quantizes it to GGUF — but nothing
# wired the result into the container ARGUS actually serves. argus-whiterabbitneo
# loads the GGUF named by its --model (Dockerfile CMD), and
# infra/whiterabbitneo/ensure_gguf.py SKIPS the HuggingFace download whenever a
# >=500MB file already exists at that path. So deploying a fine-tune is:
#   (1) convert+quantize the merged model to Q4_K_M GGUF (skipped if already built),
#   (2) back up the genuine base GGUF once (for rollback),
#   (3) copy the fine-tuned GGUF over the served path inside the volume,
#   (4) restart the container and health-check it (auto-rollback on failure).
# No image rebuild and no compose edit are needed, and ensure_gguf's self-heal
# (re-fetch the base if the file ever vanishes) keeps working because the served
# filename is unchanged.
#
# Robustness notes (why it does NOT use `podman exec` for file ops): a bad GGUF
# makes llama_cpp.server exit, so the container stops / crash-loops under its
# restart:unless-stopped policy — and then `podman exec` fails exactly when the
# rollback is needed. All in-volume file operations therefore run in a throwaway
# helper container (`podman run --rm --volumes-from <ctr>`), which works
# regardless of the serving container's state.
#
# Run this ON THE SERVER as the user that owns the rootless podman stack (ubuntu).
# The facade needs no change: llama_cpp.server serves whatever single GGUF it
# loaded; the "model" label the backend sends is cosmetic.
#
# Usage:
#   scripts/deploy_wrb_finetune.sh [--gguf FILE | --merged-dir DIR] [options]
#
# Options:
#   --gguf FILE        Ready Q4_K_M GGUF to deploy.
#                      Default: $HOME/ARGUS/wrb7b-argus-Q4_K_M.gguf (if present).
#   --merged-dir DIR   Merged HF model dir to convert+quantize when no --gguf is
#                      available (e.g. training_data/output/wrb7b_phase_merged).
#   --llama-cpp DIR    llama.cpp checkout (for convert/quantize). Autodetected.
#   --quant Q          Quant type for conversion. Default: Q4_K_M.
#   --container NAME   Serving container. Default: argus-whiterabbitneo.
#   --served-path P    Path inside the container the server loads. Autodetected
#                      from the running --model; falls back to the known default.
#   --rollback         Restore the saved base GGUF and restart (undo a deploy).
#   --dry-run          Validate prerequisites and print the plan; change nothing.
#   --yes              Do not prompt for confirmation.
#   -h, --help         This help.
#
# Env:
#   WRB_HEALTH_TIMEOUT  seconds to wait for health after (re)start. Default 600.
#
# Exit codes: 0 ok, 1 usage/precondition error, 2 health/deploy failed (rolled back).
set -Eeuo pipefail

# ---------- defaults ----------
CONTAINER="argus-whiterabbitneo"
QUANT="Q4_K_M"
GGUF=""
MERGED_DIR=""
LLAMA_CPP=""
SERVED_PATH=""
DO_ROLLBACK=0
DRY_RUN=0
ASSUME_YES=0
HEALTH_TIMEOUT="${WRB_HEALTH_TIMEOUT:-600}"
MINBYTES=$((500*1024*1024))

log()  { printf '\033[1;36m[deploy]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[deploy:warn]\033[0m %s\n' "$*" >&2; }
err()  { printf '\033[1;31m[deploy:err]\033[0m %s\n' "$*" >&2; }
die()  { err "$*"; exit 1; }

usage() { sed -n '2,/^set -/p' "$0" | sed 's/^# \{0,1\}//; s/^#//' | sed '$d'; exit "${1:-0}"; }

# ---------- args ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --gguf)        GGUF="${2:?}"; shift 2 ;;
    --merged-dir)  MERGED_DIR="${2:?}"; shift 2 ;;
    --llama-cpp)   LLAMA_CPP="${2:?}"; shift 2 ;;
    --quant)       QUANT="${2:?}"; shift 2 ;;
    --container)   CONTAINER="${2:?}"; shift 2 ;;
    --served-path) SERVED_PATH="${2:?}"; shift 2 ;;
    --rollback)    DO_ROLLBACK=1; shift ;;
    --dry-run)     DRY_RUN=1; shift ;;
    --yes)         ASSUME_YES=1; shift ;;
    -h|--help)     usage 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done

command -v podman >/dev/null 2>&1 || die "podman not found on PATH"
podman inspect "$CONTAINER" >/dev/null 2>&1 || die "container '$CONTAINER' not found (is the stack up?)"
IMG="$(podman inspect -f '{{.ImageName}}' "$CONTAINER")"
[ -n "$IMG" ] || die "could not resolve image of $CONTAINER"

# Run a shell in a throwaway container that mounts the serving container's volumes.
# Works whether or not the serving container is running (unlike `podman exec`).
vrun() { podman run --rm --volumes-from "$CONTAINER" --entrypoint sh "$IMG" -c "$1"; }
vsize()   { vrun "stat -c%s '$1' 2>/dev/null || echo 0"; }
vsha()    { vrun "sha256sum '$1' 2>/dev/null | awk '{print \$1}'"; }
vexists() { vrun "[ -f '$1' ] && echo 1 || echo 0"; }

# Resolve the exact path the server loads (so we overwrite the right file).
autodetect_served_path() {
  local p
  p="$(podman exec "$CONTAINER" sh -c '
        for f in /proc/[0-9]*/cmdline; do tr "\0" "\n" < "$f" 2>/dev/null; done |
        awk "prev==\"--model\"{print; exit} {prev=\$0}"
      ' 2>/dev/null || true)"
  [ -n "$p" ] && { printf '%s' "$p"; return; }
  printf '/models/WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-%s.gguf' "$QUANT"
}
[ -n "$SERVED_PATH" ] || SERVED_PATH="$(autodetect_served_path)"
case "$SERVED_PATH" in
  *.gguf) ;;
  *) die "served path does not end in .gguf: '$SERVED_PATH' (refusing: backup name would collide)";;
esac
BASE_BACKUP="${SERVED_PATH%.gguf}.base-orig.gguf"
MANIFEST="/models/.wrb_deploy.json"

# wait until the container is healthy after a (re)start. $1 = StartedAt captured
# BEFORE the restart (so a stale pre-restart 'healthy' is not mistaken for success).
wait_healthy() {
  local prev="${1:-}" deadline="$HEALTH_TIMEOUT" st started
  while [ "$deadline" -gt 0 ]; do
    started="$(podman inspect -f '{{.State.StartedAt}}' "$CONTAINER" 2>/dev/null || echo '')"
    if [ -n "$prev" ] && [ "$started" = "$prev" ]; then
      sleep 5; deadline=$((deadline-5)); continue   # not actually restarted yet
    fi
    st="$(podman inspect -f '{{if .State.Healthcheck}}{{.State.Healthcheck.Status}}{{end}}' "$CONTAINER" 2>/dev/null || echo '')"
    if [ "$st" = "healthy" ]; then return 0; fi
    if [ -z "$st" ] || [ "$st" = "none" ]; then
      podman exec "$CONTAINER" sh -c 'curl -sf http://localhost:8000/v1/models >/dev/null 2>&1' && return 0 || true
    fi
    sleep 6; deadline=$((deadline-6))
  done
  return 1
}

restore_base() {   # stop (halt crash-loop) -> restore via helper -> start -> health
  local prev
  prev="$(podman inspect -f '{{.State.StartedAt}}' "$CONTAINER" 2>/dev/null || echo '')"
  podman stop "$CONTAINER" >/dev/null 2>&1 || true
  vrun "cp -f '$BASE_BACKUP' '$SERVED_PATH'" || { err "RESTORE COPY FAILED — manual action needed"; return 1; }
  vrun "rm -f '$MANIFEST'" || true
  podman start "$CONTAINER" >/dev/null 2>&1 || podman restart "$CONTAINER" >/dev/null 2>&1 || true
  if wait_healthy "$prev"; then log "Base restored and healthy."; return 0; fi
  err "Base restored but container not healthy within ${HEALTH_TIMEOUT}s — check: podman logs --tail 80 $CONTAINER"
  return 1
}

# ---------- rollback mode ----------
if [ "$DO_ROLLBACK" -eq 1 ]; then
  [ "$(vexists "$BASE_BACKUP")" = 1 ] || die "no base backup at $BASE_BACKUP — nothing to roll back to"
  bsz="$(vsize "$BASE_BACKUP")"; [ "$bsz" -ge "$MINBYTES" ] || die "base backup looks truncated ($bsz bytes) — refusing to roll back to it"
  log "Rollback: restore $BASE_BACKUP -> $SERVED_PATH (base backup $bsz bytes)"
  if [ "$DRY_RUN" -eq 1 ]; then log "(dry-run) would stop, restore base via helper container, start, health-check."; exit 0; fi
  restore_base && exit 0 || exit 2
fi

# ---------- resolve source GGUF (convert+quantize if needed) ----------
: "${GGUF:=$HOME/ARGUS/wrb7b-argus-$QUANT.gguf}"

autodetect_llama_cpp() {
  local d
  for d in "$LLAMA_CPP" "$HOME/ARGUS/llama.cpp" "$HOME/llama.cpp" /opt/llama.cpp; do
    [ -n "$d" ] && [ -f "$d/convert_hf_to_gguf.py" ] && { printf '%s' "$d"; return; }
  done
  return 1
}
find_quantize_bin() {
  local d="$1" c
  for c in "$d/llama-quantize" "$d/build/bin/llama-quantize" "$d/quantize" "$d/build/bin/quantize"; do
    [ -x "$c" ] && { printf '%s' "$c"; return; }
  done
  command -v llama-quantize 2>/dev/null && return
  return 1
}

if [ ! -f "$GGUF" ]; then
  [ -n "$MERGED_DIR" ] || die "no GGUF at '$GGUF' and no --merged-dir given to build one"
  [ -d "$MERGED_DIR" ] || die "--merged-dir '$MERGED_DIR' is not a directory"
  LLAMA_CPP="$(autodetect_llama_cpp)" || die "llama.cpp not found (pass --llama-cpp DIR with convert_hf_to_gguf.py)"
  QBIN="$(find_quantize_bin "$LLAMA_CPP")" || die "llama-quantize not found under $LLAMA_CPP (build it: cmake --build build -t llama-quantize)"
  F16="${GGUF%.gguf}-f16.gguf"
  log "No ready GGUF; will convert+quantize from $MERGED_DIR via $LLAMA_CPP"
  if [ "$DRY_RUN" -eq 1 ]; then
    log "(dry-run) would: python3 '$LLAMA_CPP/convert_hf_to_gguf.py' '$MERGED_DIR' --outfile '$F16'"
    log "(dry-run) would: '$QBIN' '$F16' '$GGUF' '$QUANT'"
  else
    python3 "$LLAMA_CPP/convert_hf_to_gguf.py" "$MERGED_DIR" --outfile "$F16"
    "$QBIN" "$F16" "$GGUF" "$QUANT"
    log "Built $GGUF"
  fi
fi

# Validate source GGUF (skip hard-fail only in dry-run when it must still be built).
SRC_BYTES=0; SRC_SHA=""
if [ -f "$GGUF" ]; then
  [ "$(head -c4 "$GGUF" 2>/dev/null)" = "GGUF" ] || die "source is not a GGUF (bad magic): $GGUF"
  SRC_BYTES="$(stat -c%s "$GGUF")"
  [ "$SRC_BYTES" -ge "$MINBYTES" ] || die "source GGUF suspiciously small ($SRC_BYTES bytes): $GGUF"
  log "Hashing source (${SRC_BYTES} bytes)…"
  SRC_SHA="$(sha256sum "$GGUF" | awk '{print $1}')"
elif [ "$DRY_RUN" -ne 1 ]; then
  die "source GGUF missing after build: $GGUF"
fi

# ---------- state / plan ----------
CUR_DESC="$(vrun "ls -l '$SERVED_PATH' 2>/dev/null" || true)"; [ -n "$CUR_DESC" ] || CUR_DESC="(served file not found)"
HAVE_BACKUP=0; [ "$(vexists "$BASE_BACKUP")" = 1 ] && HAVE_BACKUP=1
HAVE_MANIFEST=0; [ "$(vexists "$MANIFEST")" = 1 ] && HAVE_MANIFEST=1
AVAIL_KB="$(vrun "df -Pk /models | awk 'NR==2{print \$4}'" 2>/dev/null || echo 0)"

log "Plan:"
log "  container     : $CONTAINER   (image $IMG)"
log "  served path   : $SERVED_PATH"
log "  base backup   : $BASE_BACKUP  ($([ "$HAVE_BACKUP" -eq 1 ] && echo present || echo 'will create from current file'))"
log "  prior deploy  : $([ "$HAVE_MANIFEST" -eq 1 ] && echo 'yes (served file is already a fine-tune)' || echo 'no (served file is the genuine base)')"
log "  source GGUF   : $GGUF"
[ "$SRC_BYTES" -gt 0 ] && log "  source        : $SRC_BYTES bytes, sha256 ${SRC_SHA:0:16}…"
log "  current serve : $CUR_DESC"
log "  volume free   : $((AVAIL_KB/1024)) MiB"

if [ "$DRY_RUN" -eq 1 ]; then
  log "(dry-run) no changes made. Re-run without --dry-run to deploy."
  exit 0
fi

# free space: need room for the backup (first time) + the new copy alongside the old.
NEED_KB=$(( SRC_BYTES/1024 + (HAVE_BACKUP==0 ? SRC_BYTES/1024 : 0) + 1024*1024 ))
[ "$AVAIL_KB" -ge "$NEED_KB" ] || die "not enough space in /models: avail $((AVAIL_KB/1024))MiB < need $((NEED_KB/1024))MiB"

if [ "$ASSUME_YES" -ne 1 ]; then
  printf '\033[1;33mProceed? This swaps the served model and restarts %s. [y/N] \033[0m' "$CONTAINER"
  read -r ans; case "$ans" in y|Y|yes) ;; *) die "aborted by user" ;; esac
fi

# ---------- error handling: once backed up, any failure restores base ----------
BACKED_UP=0; DEPLOY_DONE=0
on_err() {
  local code=$?; trap - ERR
  if [ "$BACKED_UP" -eq 1 ] && [ "$DEPLOY_DONE" -eq 0 ]; then
    err "Failure (exit $code) mid-deploy — restoring base."
    restore_base || true
    exit 2
  fi
  exit "$code"
}
trap on_err ERR

# ---------- 1) back up the genuine base once (atomic, idempotency-safe) ----------
if [ "$HAVE_BACKUP" -eq 1 ]; then
  bsz="$(vsize "$BASE_BACKUP")"
  [ "$bsz" -ge "$MINBYTES" ] || die "existing base backup is truncated ($bsz bytes). Refusing to overwrite it with the (possibly fine-tuned) current served file. Restore a known-good base to $BASE_BACKUP (or re-pull the base GGUF) and retry."
  log "Base backup already present ($bsz bytes); keeping it."
else
  if [ "$HAVE_MANIFEST" -eq 1 ]; then
    die "No base backup, but a prior-deploy manifest exists → the current served file is a FINE-TUNE, not the base. Refusing to save a fine-tune as 'base'. Restore the genuine base GGUF to $SERVED_PATH (re-pull from HF) before deploying."
  fi
  cur="$(vsize "$SERVED_PATH")"; [ "$cur" -ge "$MINBYTES" ] || die "current served file missing/too small ($cur bytes) — cannot back up"
  log "Backing up base GGUF -> $BASE_BACKUP (atomic)…"
  vrun "cp '$SERVED_PATH' '$BASE_BACKUP.tmp' && sync"
  tsz="$(vsize "$BASE_BACKUP.tmp")"
  [ "$tsz" = "$cur" ] && [ "$tsz" -ge "$MINBYTES" ] || { vrun "rm -f '$BASE_BACKUP.tmp'" || true; die "base backup copy incomplete ($tsz/$cur bytes)"; }
  vrun "mv '$BASE_BACKUP.tmp' '$BASE_BACKUP'"
  log "Base backed up ($tsz bytes)."
fi
BACKED_UP=1

# ---------- 2) copy fine-tuned GGUF over the served path (in the volume) ----------
log "Copying fine-tuned GGUF into $CONTAINER:$SERVED_PATH (~$((SRC_BYTES/1024/1024)) MiB)…"
podman cp "$GGUF" "$CONTAINER:$SERVED_PATH"
DST_SHA="$(vsha "$SERVED_PATH")"
if [ "$DST_SHA" != "$SRC_SHA" ]; then
  err "sha mismatch after copy (src ${SRC_SHA:0:16}… != dst ${DST_SHA:0:16}…) — rolling back."
  DEPLOY_DONE=1; trap - ERR; restore_base || true; exit 2
fi
log "Copy verified (sha256 matches)."

# record manifest (write host-side, copy in — avoids in-container quoting)
TMPJSON="$(mktemp)"; printf '{"deployed_sha256":"%s","deployed_bytes":%s,"source":"%s"}\n' "$SRC_SHA" "$SRC_BYTES" "$(basename "$GGUF")" > "$TMPJSON"
podman cp "$TMPJSON" "$CONTAINER:$MANIFEST" || true; rm -f "$TMPJSON"

# ---------- 3) restart + health check (auto-rollback on failure) ----------
PREV_STARTED="$(podman inspect -f '{{.State.StartedAt}}' "$CONTAINER" 2>/dev/null || echo '')"
log "Restarting $CONTAINER…"
podman restart "$CONTAINER" >/dev/null
log "Waiting up to ${HEALTH_TIMEOUT}s for health…"
if wait_healthy "$PREV_STARTED"; then
  DEPLOY_DONE=1; trap - ERR
  log "✅ Deployed and healthy. Serving fine-tuned model from $SERVED_PATH."
  log "   served now : $(vrun "ls -l '$SERVED_PATH'" 2>/dev/null || true)"
  log "   rollback   : $0 --rollback"
else
  err "Container did not become healthy in ${HEALTH_TIMEOUT}s — AUTO-ROLLBACK to base."
  DEPLOY_DONE=1; trap - ERR   # prevent double-rollback via ERR trap
  restore_base || true
  err "Rolled back to base. Inspect the fine-tune failure: podman logs --tail 80 $CONTAINER"
  exit 2
fi
