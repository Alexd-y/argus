#!/usr/bin/env python3
"""
ARGUS — CPU LoRA fine-tuning runner (no CUDA / no bitsandbytes / no flash-attn).

Trains a LoRA adapter on the messages-format dataset (training_data/final/*.jsonl)
on CPU, for the local WhiteRabbitNeo-V3-7B (or qwythos-9b) served on the CPU
server. Base weights stay frozen fp32; only the adapter is trained. Optionally
merges the adapter back into the base for GGUF export (llama.cpp / Ollama).

This is the CPU counterpart to the GPU Axolotl pipeline (sft_qlora.yaml). It is
deliberately dependency-light: transformers + peft + datasets (+ pyyaml). No trl,
no bitsandbytes, no accelerate-GPU.

Install (CPU wheels):
    pip install "torch>=2.2" --index-url https://download.pytorch.org/whl/cpu
    pip install transformers peft datasets pyyaml

Train (reads the CPU config):
    python scripts/training/train_lora_cpu.py \
        --config training_data/training_config/sft_lora_cpu.yaml

Dry-run (build dataset + tokenize a few, no training — works without a model):
    python scripts/training/train_lora_cpu.py --config <cfg> --dry-run

Merge a trained adapter into the base (for GGUF):
    python scripts/training/train_lora_cpu.py --config <cfg> --merge-only
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _load_cfg(path: str) -> dict:
    import yaml  # lazy
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    # accept either the wrapped {cpu_lora_config: {...}} or a flat dict
    return doc.get("cpu_lora_config", doc)


def _read_jsonl(path: Path) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _task_allowed(task: str, task_filter: str | None) -> bool:
    if not task_filter:
        return True
    return any(task.startswith(p.strip()) for p in task_filter.split(","))


def build_examples(cfg: dict, split_path: str) -> list[dict]:
    """Return [{messages:[...]}] filtered by task_filter."""
    rows = _read_jsonl(Path(split_path))
    tf = cfg.get("task_filter")
    out = []
    for r in rows:
        if "messages" not in r:
            continue
        task = r.get("metadata", {}).get("task", "")
        if _task_allowed(task, tf):
            out.append(r)
    return out


def _render_and_tokenize(examples: list[dict], tokenizer, max_len: int,
                         train_on_inputs: bool) -> "Dataset":  # noqa: F821
    from datasets import Dataset

    def encode(ex: dict) -> dict:
        msgs = ex["messages"]
        # full conversation
        full = tokenizer.apply_chat_template(msgs, tokenize=True,
                                             add_generation_prompt=False)
        labels = list(full)
        if not train_on_inputs:
            # mask everything up to the assistant turn (prompt tokens = -100)
            prompt_msgs = msgs[:-1]
            prompt_ids = tokenizer.apply_chat_template(
                prompt_msgs, tokenize=True, add_generation_prompt=True)
            n = min(len(prompt_ids), len(labels))
            for i in range(n):
                labels[i] = -100
        full = full[:max_len]
        labels = labels[:max_len]
        return {"input_ids": full, "labels": labels,
                "attention_mask": [1] * len(full)}

    return Dataset.from_list([encode(e) for e in examples])


def do_train(cfg: dict, dry_run: bool) -> None:
    train_examples = build_examples(cfg, cfg["datasets"][0]["path"])
    val_examples = build_examples(cfg, cfg["val_datasets"][0]["path"]) if cfg.get("val_datasets") else []
    print(f"[data] train={len(train_examples)} valid={len(val_examples)} "
          f"(task_filter={cfg.get('task_filter')!r})")
    if not train_examples:
        sys.exit("[error] no training examples after task_filter")

    import torch  # noqa: F401
    from transformers import AutoModelForCausalLM, AutoTokenizer

    tok = AutoTokenizer.from_pretrained(cfg["tokenizer_config"], use_fast=True)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    max_len = int(cfg.get("sequence_len", 2048))
    train_ds = _render_and_tokenize(train_examples, tok, max_len,
                                    bool(cfg.get("train_on_inputs", False)))
    val_ds = (_render_and_tokenize(val_examples, tok, max_len,
                                   bool(cfg.get("train_on_inputs", False)))
              if val_examples else None)
    print(f"[tokenize] train tokens/example avg="
          f"{sum(len(x) for x in train_ds['input_ids'])//max(1,len(train_ds))}")

    if dry_run:
        print("[dry-run] dataset built + tokenized OK; skipping model load/training.")
        return

    import torch
    from peft import LoraConfig, get_peft_model
    from transformers import (DataCollatorForSeq2Seq, Trainer,
                              TrainingArguments)

    dtype = {"float32": torch.float32, "bfloat16": torch.bfloat16,
             "float16": torch.float16}.get(cfg.get("torch_dtype", "float32"), torch.float32)
    model = AutoModelForCausalLM.from_pretrained(
        cfg["base_model"], torch_dtype=dtype,
        low_cpu_mem_usage=bool(cfg.get("low_cpu_mem_usage", True)),
        attn_implementation=cfg.get("attn_implementation", "eager"),
        trust_remote_code=bool(cfg.get("trust_remote_code", False)),
    )
    model.config.use_cache = False
    lora = LoraConfig(
        r=int(cfg.get("lora_r", 16)), lora_alpha=int(cfg.get("lora_alpha", 32)),
        lora_dropout=float(cfg.get("lora_dropout", 0.05)),
        target_modules=cfg.get("lora_target_modules"),
        bias="none", task_type="CAUSAL_LM",
    )
    model = get_peft_model(model, lora)
    model.print_trainable_parameters()
    if cfg.get("gradient_checkpointing"):
        model.gradient_checkpointing_enable()

    args = TrainingArguments(
        output_dir=cfg.get("output_dir", "training_data/output/sft_lora_cpu"),
        per_device_train_batch_size=int(cfg.get("micro_batch_size", 1)),
        gradient_accumulation_steps=int(cfg.get("gradient_accumulation_steps", 16)),
        num_train_epochs=float(cfg.get("num_epochs", 3)),
        learning_rate=float(cfg.get("learning_rate", 2e-4)),
        lr_scheduler_type=cfg.get("lr_scheduler", "cosine"),
        warmup_ratio=float(cfg.get("warmup_ratio", 0.05)),
        weight_decay=float(cfg.get("weight_decay", 0.01)),
        max_grad_norm=float(cfg.get("max_grad_norm", 1.0)),
        logging_steps=int(cfg.get("logging_steps", 10)),
        save_steps=int(cfg.get("save_steps", 200)),
        save_total_limit=int(cfg.get("save_total_limit", 2)),
        eval_strategy="steps" if val_ds is not None else "no",
        eval_steps=int(cfg.get("eval_steps", 200)),
        optim=cfg.get("optimizer", "adamw_torch"),
        bf16=False, fp16=False, use_cpu=True,
        dataloader_num_workers=int(cfg.get("dataloader_num_workers", 2)),
        report_to=[],
    )
    collator = DataCollatorForSeq2Seq(tok, padding=True, label_pad_token_id=-100)
    trainer = Trainer(model=model, args=args, train_dataset=train_ds,
                      eval_dataset=val_ds, data_collator=collator)
    trainer.train()
    trainer.save_model(args.output_dir)
    tok.save_pretrained(args.output_dir)
    print(f"[done] adapter saved -> {args.output_dir}")

    if cfg.get("merge_adapter"):
        merge_adapter(cfg, args.output_dir)


def merge_adapter(cfg: dict, adapter_dir: str) -> None:
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    out = cfg.get("merged_output_dir", "training_data/output/merged")
    base = AutoModelForCausalLM.from_pretrained(
        cfg["base_model"], torch_dtype=torch.float32, low_cpu_mem_usage=True)
    merged = PeftModel.from_pretrained(base, adapter_dir).merge_and_unload()
    merged.save_pretrained(out)
    AutoTokenizer.from_pretrained(cfg["tokenizer_config"]).save_pretrained(out)
    q = cfg.get("gguf_quantization", "Q4_K_M")
    print(f"[merge] merged model -> {out}")
    print("[gguf] next (llama.cpp):")
    print(f"  python llama.cpp/convert_hf_to_gguf.py {out} --outfile wrb7b-argus-f16.gguf")
    print(f"  ./llama.cpp/llama-quantize wrb7b-argus-f16.gguf wrb7b-argus-{q}.gguf {q}")
    print("  # serve: ./llama.cpp/llama-server -m wrb7b-argus-%s.gguf -c 4096" % q)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default="training_data/training_config/sft_lora_cpu.yaml")
    ap.add_argument("--dry-run", action="store_true",
                    help="Build + tokenize dataset only (no model load / training).")
    ap.add_argument("--merge-only", action="store_true",
                    help="Merge an already-trained adapter into the base, then exit.")
    ap.add_argument("--adapter-dir", default=None,
                    help="Adapter dir for --merge-only (default: cfg.output_dir).")
    # Per-run overrides (so one config serves several model/scope runs).
    ap.add_argument("--base-model", default=None, help="Override cfg.base_model.")
    ap.add_argument("--tokenizer", default=None, help="Override cfg.tokenizer_config.")
    ap.add_argument("--task-filter", default=None,
                    help="Override cfg.task_filter. Pass '' (empty) to train on ALL of final/.")
    ap.add_argument("--output-dir", default=None, help="Override cfg.output_dir.")
    ap.add_argument("--merged-dir", default=None, help="Override cfg.merged_output_dir.")
    ap.add_argument("--num-epochs", type=float, default=None, help="Override cfg.num_epochs.")
    ap.add_argument("--sequence-len", type=int, default=None, help="Override cfg.sequence_len.")
    args = ap.parse_args()

    cfg = _load_cfg(args.config)
    # apply overrides (None = keep config value; '' is a real value for task_filter)
    if args.base_model is not None:
        cfg["base_model"] = args.base_model
        cfg["tokenizer_config"] = args.tokenizer or args.base_model
    if args.tokenizer is not None:
        cfg["tokenizer_config"] = args.tokenizer
    if args.task_filter is not None:
        cfg["task_filter"] = args.task_filter or None  # '' -> no filter (all tasks)
    if args.output_dir is not None:
        cfg["output_dir"] = args.output_dir
    if args.merged_dir is not None:
        cfg["merged_output_dir"] = args.merged_dir
    if args.num_epochs is not None:
        cfg["num_epochs"] = args.num_epochs
    if args.sequence_len is not None:
        cfg["sequence_len"] = args.sequence_len

    if args.merge_only:
        merge_adapter(cfg, args.adapter_dir or cfg.get("output_dir"))
        return
    do_train(cfg, args.dry_run)


if __name__ == "__main__":
    main()
