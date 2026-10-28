#!/usr/bin/env bash
# Convert merged HF (checkpoint-150) -> GGUF f16 -> quantize Q4_K_M.
# Distinct output names (wrb7b-argus-v2-*) to avoid the default --gguf trap.
set -o pipefail
cd /home/ubuntu/ARGUS || exit 1
LOG=training_data/output/convert_v2.log
exec >>"$LOG" 2>&1
MERGED=training_data/output/wrb7b_full2_merged
F16=wrb7b-argus-v2-f16.gguf
Q4=wrb7b-argus-v2-Q4_K_M.gguf

echo "[conv] $(date -u) convert_hf_to_gguf -> $F16 (f16)"
.venv-train/bin/python -u llama.cpp/convert_hf_to_gguf.py "$MERGED" --outfile "$F16" --outtype f16
rc1=$?
echo "[conv] convert rc=$rc1 $(date -u)"
if [ $rc1 -ne 0 ]; then echo "[conv] ABORT: convert failed"; exit $rc1; fi

echo "[quant] $(date -u) quantize -> $Q4 (Q4_K_M)"
llama.cpp/build/bin/llama-quantize "$F16" "$Q4" Q4_K_M
rc2=$?
echo "[quant] quantize rc=$rc2 $(date -u)"
if [ $rc2 -ne 0 ]; then echo "[quant] ABORT: quantize failed"; exit $rc2; fi

echo "[verify] artifacts:"
ls -la wrb7b-argus-v2-*.gguf
echo "[verify] magic:"; head -c 4 "$Q4" | od -c | head -1
echo "[verify] sha256:"; sha256sum "$Q4"
echo "[conv] ALL DONE $(date -u)"
