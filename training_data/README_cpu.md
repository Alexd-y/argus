# ARGUS local-LLM fine-tuning on a CPU server (8-phase, report-aligned)

This is the **CPU** training path for the local models served on the CPU server
(**WhiteRabbitNeo-V3-7B** + **qwythos-9b**). The GPU pipeline
(`training_config/sft_qlora.yaml`, Axolotl, 4-bit QLoRA + flash-attention) is
**CUDA-only and will not run on CPU** — use the files below instead.

## What the model learns

Two complementary datasets, both merged into `final/{train,valid,test}.jsonl`:

1. **8-phase runtime-aligned** (`phase_training.jsonl`) — records whose
   `(system, user, assistant)` match the **real** `prompt_registry.PHASE_PROMPTS`
   / `PHASE_SCHEMAS` contracts, so the model emits exactly the JSON each ARGUS
   phase consumes and that flows into Asgard/Midgard/Valhalla reports:

   | Phase | task type | output |
   |-------|-----------|--------|
   | source_analysis | `phase_source_analysis` | `{missed_sinks,cross_file_taint,auth_gaps}` |
   | recon | `phase_recon` | `{assets,subdomains,ports}` |
   | quick_fuzz | — | *no LLM call (deterministic); nothing to train* |
   | threat_modeling | `phase_threat_modeling` | `{threat_model:{attack_surface,threats,cves,mitigations}}` |
   | vuln_analysis | `phase_vuln_analysis` | `{findings:[…cwe,cvss,confidence,evidence_type,evidence_refs…]}` |
   | exploitation | `phase_exploitation` | `{exploits:[finding_id,target,…],evidence,evidence_gaps}` |
   | post_exploitation | `phase_post_exploitation` | `{lateral,persistence}` (empty when no verified exploit) |
   | reporting | `phase_report_section` | `{section:{…}}` per phase |
   | reporting | `phase_report_assembly` | `{report:{summary,executive_summary,findings_detail,…}}` |
   | reporting | `phase_report_prose` | grounded prose w/ mandatory `[CL-…]`/`[E-…]` citations |

2. **Offensive command generator** (`pentest_commands.jsonl`,
   `shell_command_generation`) — the cross-phase bash-command skill (15 stages +
   40 categories). See `scripts/training/pentest_command_catalog.py`.

### Report-correctness guarantees baked into the data
- Provable findings use a **non-inference** `evidence_type` + `confidence`
  ∈ {confirmed,likely} + populated `evidence_refs` → land in the **Valhalla main
  body** (passes `evidence_partition.is_provable_from_raw`).
- Inference/low-confidence findings are **never** labelled confirmed/likely →
  teaches the downgrade to *Unconfirmed Observations* instead of fabrication.
- `phase_exploitation` exploits always carry `finding_id`+`target`
  (EXPLOITATION_SCHEMA required fields).
- `phase_post_exploitation` emits **empty** `lateral`/`persistence` when no
  verified exploit exists (fail-closed, matches handler Block 1.5).
- `phase_report_prose` cites `[CL-<finding>]`/`[E-<evidence>]` on every factual
  paragraph → passes `reports/prose_gate._REFERENCE_RE`.

## Build / refresh the dataset

```bash
py scripts/training/generate_phase_training.py --count 1400       # 8-phase records
py scripts/training/generate_pentest_commands.py --count 1500     # command records
py scripts/training/convert_to_jsonl.py --input-dir training_data/ --output-dir training_data/final/
```

`generate_phase_training.py` prefers the **real** `prompt_registry` (byte-exact
prompts) when run inside the backend venv; otherwise it uses the faithful
embedded copy in `phase_prompt_catalog.py`. Run it in the backend venv for an
exact match with inference.

## Train the LoRA adapter on CPU

```bash
# CPU PyTorch wheels (no CUDA):
pip install "torch>=2.2" --index-url https://download.pytorch.org/whl/cpu
pip install transformers peft datasets pyyaml

# sanity: build + tokenize only (no model download / no training)
py scripts/training/train_lora_cpu.py --config training_data/training_config/sft_lora_cpu.yaml --dry-run

# train (fp32 LoRA, adapter-only, base frozen)
py scripts/training/train_lora_cpu.py --config training_data/training_config/sft_lora_cpu.yaml
```

Key CPU adaptations vs the GPU config: no bitsandbytes 4-bit, no flash-attention,
`optim=adamw_torch`, `attn_implementation=eager`, `torch_dtype=float32`,
`lora_r=16`, `sequence_len=2048`, gradient checkpointing on. `task_filter`
defaults to `phase_,shell_command_generation` so you train the ARGUS-relevant
subset (faster). Hyperparams honour the spec: 3 epochs (raise `num_epochs` to
4-5 if time allows), LR 2e-4.

**Expect it to be slow**: fp32 LoRA on a 7B base on CPU is hours→days/epoch and
needs ~32-40 GB RAM. To iterate: lower `sequence_len`, cut `num_epochs`, or
narrow `task_filter` (e.g. only `phase_vuln_analysis,phase_report_prose`).
`qwythos-9b`: set `base_model`/`tokenizer_config` to it (≈1.3× the 7B cost).

## Merge + export to GGUF for CPU serving

```bash
# merge adapter into the base (also runs automatically when merge_adapter: true)
py scripts/training/train_lora_cpu.py --config training_data/training_config/sft_lora_cpu.yaml --merge-only

# convert + quantize for llama.cpp
python llama.cpp/convert_hf_to_gguf.py training_data/output/wrb7b_argus_merged --outfile wrb7b-argus-f16.gguf
./llama.cpp/llama-quantize wrb7b-argus-f16.gguf wrb7b-argus-Q4_K_M.gguf Q4_K_M

# serve (OpenAI-compatible endpoint on CPU)
./llama.cpp/llama-server -m wrb7b-argus-Q4_K_M.gguf -c 4096 --port 8080
# or Ollama:  ollama create wrb7b-argus -f Modelfile  (FROM ./wrb7b-argus-Q4_K_M.gguf)
```

## Point ARGUS at the CPU-served model

ARGUS routes pentest-analysis tasks to WhiteRabbitNeo via `src/llm/facade.py`
(`call_llm_unified`). The served GGUF exposes an OpenAI-compatible API
(llama.cpp `llama-server` / Ollama), so set the WRB provider base URL/model
alias to the CPU endpoint (e.g. `http://<cpu-host>:8080/v1`, model
`wrb7b-argus`). No prompt changes are needed — the training used the exact
`PHASE_PROMPTS` the runtime sends.
