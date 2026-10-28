#!/usr/bin/env python3
"""Memory-frugal LoRA merge for CPU: load base in its native (bf16) dtype so the
fp32 7B OOM is avoided. Output feeds llama.cpp convert->Q4_K_M, where fp32 gives
nothing, so bf16 merge is lossless for the target. Usage: merge_ckpt.py <adapter> <out>"""
import sys
import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

BASE = "WhiteRabbitNeo/WhiteRabbitNeo-V3-7B"
ADAPTER = sys.argv[1]
OUT = sys.argv[2]

print(f"[merge] loading base {BASE} (dtype=auto, low_cpu_mem_usage)...", flush=True)
try:
    base = AutoModelForCausalLM.from_pretrained(BASE, dtype="auto", low_cpu_mem_usage=True)
except TypeError:
    base = AutoModelForCausalLM.from_pretrained(BASE, torch_dtype="auto", low_cpu_mem_usage=True)
print(f"[merge] base param dtype: {next(base.parameters()).dtype}", flush=True)
print(f"[merge] applying adapter {ADAPTER} and merging...", flush=True)
merged = PeftModel.from_pretrained(base, ADAPTER).merge_and_unload()
print(f"[merge] saving merged model -> {OUT}", flush=True)
merged.save_pretrained(OUT, safe_serialization=True)
AutoTokenizer.from_pretrained(BASE).save_pretrained(OUT)
print(f"[merge] DONE -> {OUT}", flush=True)
