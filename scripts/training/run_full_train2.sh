#!/usr/bin/env bash
# ARGUS WRB CPU LoRA — v2 full run (regenerated dataset, 73 payload families).
# Detached-safe: self-redirects all output to the log so nohup/tmux both work.
set -o pipefail
cd /home/ubuntu/ARGUS || exit 1
LOG=training_data/output/train_full2.log
exec >>"$LOG" 2>&1
export OMP_NUM_THREADS=32 MKL_NUM_THREADS=32
echo "[launch] $(date -u) FULL v2 train: 1 epoch, all tasks (task_filter=''), --no-merge, dataset=final_v2 (train=3719/valid=573/test=654), 73 payload families"
.venv-train/bin/python -u scripts/training/train_lora_cpu.py \
  --config training_data/training_config/sft_lora_cpu_full2.yaml \
  --task-filter '' \
  --num-epochs 1 \
  --no-merge \
  --output-dir training_data/output/wrb7b_full2 \
  --merged-dir training_data/output/wrb7b_full2_merged
rc=$?
echo "[launch] $(date -u) FINISHED exit=$rc"
