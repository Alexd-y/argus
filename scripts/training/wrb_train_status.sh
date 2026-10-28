#!/usr/bin/env bash
# ARGUS WRB v2 training status probe (read-only).
cd /home/ubuntu/ARGUS || exit 1
LOG=training_data/output/train_full2.log
P=$(pgrep -f "scripts/training/train_lora" | head -1)
echo "== $(date -u) =="
if [ -n "$P" ]; then
  read -r ET RSS <<<"$(ps -o etime=,rss= -p "$P")"
  echo "STATE: RUNNING pid=$P elapsed=$ET rss=$((RSS/1024))MB"
else
  echo "STATE: NOT RUNNING"
  echo "-- last log lines --"; tail -4 "$LOG"
fi
echo "-- progress (last 2 tqdm lines) --"
grep -aoE "[0-9]+/[0-9]+ \[[0-9:]+<[^]]*\]" "$LOG" 2>/dev/null | tail -2
echo "-- last train loss --"; grep -aoE "\{'loss':[^}]*\}" "$LOG" 2>/dev/null | tail -1
echo "-- last eval --";       grep -aoE "\{'eval_loss':[^}]*\}" "$LOG" 2>/dev/null | tail -1
echo "-- trainable params --"; grep -a "trainable params" "$LOG" 2>/dev/null | tail -1
echo "-- checkpoints --"; ls -1dt training_data/output/wrb7b_full2/checkpoint-* 2>/dev/null | head -3
echo "-- finished marker --"; grep -a "FINISHED" "$LOG" 2>/dev/null | tail -1
echo "-- disk / load --"; df -h / | tail -1; uptime | grep -oE "load average.*"
