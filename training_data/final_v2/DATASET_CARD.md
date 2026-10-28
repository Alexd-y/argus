# ARGUS WRB fine-tune dataset — v2 (2026-10-25)

Regenerated SFT dataset for the WhiteRabbitNeo-V3-7B CPU LoRA run. Supersedes the
2026-10-12 deployed split by incorporating the updated payload catalogs.

## Provenance
- Repo branch: `feat/dark-web-monitoring`
- Commit: `0e66c31aa22540d45e65ed6ec109ef106369fdbd`
- Working tree: DIRTY — 34 modified files under `backend/config/payloads/` (uncommitted).
- payload-index content hash: `ec030fb960f585780d0272bdaef14fea814412a1`
- Generated on the dev host with `backend/.venv` (Python 3.12.13), seed=42.

## Composition (sources)
| source | rows | generator | changed vs deployed |
|---|---|---|---|
| payload_augmented.jsonl | 1825 | augment_payloads.py --variations 10 | **+475** (new families) |
| argus_internal.jsonl    | 636  | generate_argus_training.py            | +88 |
| pentest_commands.jsonl  | 1500 | generate_pentest_commands.py (static) | 0 (byte-identical) |
| phase_training.jsonl     | 956  | generate_phase_training.py (REAL registry) | 0 (byte-identical) |
| methodology_supplement.jsonl | 29 | generate_methodology_supplement.py (static) | 0 (byte-identical) |
| **total** | **4946** | | +563 |

Static sources (pentest_commands / phase_training / methodology) are the exact
committed files — regeneration verified byte-identical, so the only change from
the deployed dataset is the payload catalog update.

## Split (stratified by task+family, seed=42, 80/10/10, dedup by user-content)
- train: 3719  (deployed was 3339, +380)
- valid: 573
- test:  654
- validation: 4946/4946 valid, 0 errors, 0 duplicates removed.

## Payload families: 54 -> 73 (+19 new)
account_takeover, api_bfla, api_bola, api_bopla, business_logic_transition,
clickjacking, client_side_path_traversal, dns_rebinding, file_upload_polyglot,
grpc_misconfig, host_header_injection, http_parameter_pollution,
llm_prompt_injection, resource_consumption_safe, saml_validation,
unsafe_api_consumption, web_cache_deception, websocket_hijacking, xs_leak.
None removed.

## Training
- Config: `training_data/training_config/sft_lora_cpu_full2.yaml`
- Launch: `run_full_train2.sh` → CPU LoRA, 1 epoch, all tasks, r=16, fp32, seq 2048, `--no-merge`.
- Adapter out: `training_data/output/wrb7b_full2/`
- Merge (separate, needs swap): `--merge-only --adapter-dir wrb7b_full2 --merged-dir wrb7b_full2_merged`.

## Notes / caveats
- Deployed-at-training model stays `local_wrb` (GGUF `wrb7b-argus-full-Q4_K_M.gguf`).
  New GGUF deploys under a distinct name with `deploy_wrb_finetune.sh --rollback` as the rollback path.
- Offensive payloads are authorized-pentest training content for the ARGUS platform;
  execution is gated by ScopeEngine / execution mode, not by model output.
