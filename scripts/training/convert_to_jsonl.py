"""
ARGUS WhiteRabbitNeo Training Data — JSONL Converter & Validator

Reads raw JSONL files (from extract_repos.py and generate_argus_training.py),
validates against the schema specification, deduplicates, merges, and produces
the final train/valid/test split JSONL files.

No sanitization — all content preserved as-is.

Usage:
    python scripts/training/convert_to_jsonl.py --input-dir training_data/ --output-dir training_data/final/
    python scripts/training/convert_to_jsonl.py --input training_data/raw_repos.jsonl training_data/argus_internal.jsonl --output-dir training_data/final/
"""

import argparse
import hashlib
import json
import os
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional


VALID_TASK_TYPES = [
    "tool_command_generation", "payload_generation", "payload_family_selection",
    "tool_selection", "finding_triage", "validation_plan",
    "methodology_checklist", "finding_to_remediation", "attack_chain_summary",
    "report_section",
]

VALID_PHASES = ["recon", "vuln_analysis", "exploitation", "post_exploitation", "cross_phase", "reporting"]

VALID_SOURCES = [
    "zha0_pentest_playbook", "dievus_internal_pentest_playbook",
    "ag_rodriguez_penetration_testing_playbook", "enaqx_awesome_pentest",
    "ianonymous3000_awesome_pentest_checklist", "hackedbyagirl_offensive_kali_ansible",
    "argus_tool_catalog", "argus_payload_registry", "argus_prompt_registry",
    "argus_internal", "synthetic",
]

VALID_LICENSES = ["mit", "apache2", "cc_by_sa", "cc_by_4", "gpl3", "agpl3", "internal"]

MIN_USER_CONTENT_LEN = 20

VALIDATION_REPORT = []

ALL_54_FAMILIES = [
    "auth_bypass", "buffer_overflow", "cache_poisoning", "command_injection_safe",
    "cors_misconfig", "crlf", "crlf_safe", "csrf_safe", "csrf_token_bypass",
    "deserialization", "format_string", "graphql", "graphql_safe", "http_smuggling",
    "idor", "integer_overflow", "jwt", "jwt_none_alg", "jwt_safe",
    "ldap_injection", "ldapi", "ldapi_safe", "lfi_rfi", "mass_assignment",
    "mass_assignment_safe", "nosqli", "nosqli_safe", "oauth", "oauth_misconfig",
    "open_redirect", "open_redirect_safe", "path_traversal", "proto_smuggle",
    "prototype_pollution", "prototype_pollution_safe", "race_condition",
    "rce", "smtp_injection", "sqli", "sqli_safe", "ssrf", "ssrf_oast_safe",
    "ssti", "ssti_safe", "traversal_safe", "type_juggling", "xpath_injection",
    "xpathi_safe", "xss", "xss_contextual", "xss_dom", "xss_stored",
    "xxe", "xxe_oast_safe",
]

SPLIT_RATIOS = {"train": 0.80, "valid": 0.10, "test": 0.10}

MIN_EXAMPLES_PER_TASK = {
    "tool_command_generation": {"train": 800, "valid": 100, "test": 100},
    "payload_generation": {"train": 540, "valid": 108, "test": 108},
    "payload_family_selection": {"train": 432, "valid": 54, "test": 54},
    "tool_selection": {"train": 300, "valid": 40, "test": 40},
    "finding_triage": {"train": 300, "valid": 40, "test": 40},
    "validation_plan": {"train": 200, "valid": 25, "test": 25},
    "methodology_checklist": {"train": 100, "valid": 15, "test": 15},
    "finding_to_remediation": {"train": 200, "valid": 25, "test": 25},
    "attack_chain_summary": {"train": 100, "valid": 15, "test": 15},
    "report_section": {"train": 100, "valid": 15, "test": 15},
}


def validate_record(record: dict, line_num: int) -> list[str]:
    errors = []

    if "messages" not in record:
        errors.append(f"Line {line_num}: missing 'messages' key")
        return errors

    if "metadata" not in record:
        errors.append(f"Line {line_num}: missing 'metadata' key")
        return errors

    messages = record["messages"]
    if not isinstance(messages, list) or len(messages) != 3:
        errors.append(f"Line {line_num}: 'messages' must have exactly 3 entries, got {len(messages) if isinstance(messages, list) else 'non-list'}")
    else:
        roles = [m.get("role", "") for m in messages]
        if roles != ["system", "user", "assistant"]:
            errors.append(f"Line {line_num}: message roles must be [system, user, assistant], got {roles}")
        for m in messages:
            if "content" not in m:
                errors.append(f"Line {line_num}: message missing 'content'")
            elif not isinstance(m["content"], str) or len(m["content"].strip()) == 0:
                errors.append(f"Line {line_num}: message content is empty")

    metadata = record["metadata"]

    if "task" not in metadata:
        errors.append(f"Line {line_num}: metadata missing 'task'")
    elif metadata["task"] not in VALID_TASK_TYPES:
        errors.append(f"Line {line_num}: invalid task type '{metadata['task']}'")

    if "source" not in metadata:
        errors.append(f"Line {line_num}: metadata missing 'source'")

    if "argus_phase" not in metadata:
        errors.append(f"Line {line_num}: metadata missing 'argus_phase'")
    elif metadata["argus_phase"] not in VALID_PHASES:
        errors.append(f"Line {line_num}: invalid phase '{metadata['argus_phase']}'")

    user_content = ""
    if isinstance(messages, list) and len(messages) >= 2:
        user_content = messages[1].get("content", "")
    if len(user_content) < MIN_USER_CONTENT_LEN:
        errors.append(f"Line {line_num}: user content too short ({len(user_content)} chars, min {MIN_USER_CONTENT_LEN})")

    assistant_content = ""
    if isinstance(messages, list) and len(messages) >= 3:
        assistant_content = messages[2].get("content", "")

    if metadata.get("task") != "report_section":
        try:
            if isinstance(assistant_content, str):
                json.loads(assistant_content)
        except json.JSONDecodeError:
            errors.append(f"Line {line_num}: assistant content is not valid JSON (task type requires JSON output)")

    return errors


def compute_dedup_hash(record: dict) -> str:
    user_content = record["messages"][1].get("content", "") if len(record["messages"]) > 1 else ""
    return hashlib.sha256(user_content.encode("utf-8")).hexdigest()


def stratified_split(records: list[dict], ratios: dict[str, float], seed: int = 42) -> dict[str, list[dict]]:
    rng = random.Random(seed)

    by_task = defaultdict(list)
    for r in records:
        task = r["metadata"].get("task", "unknown")
        by_task[task].append(r)

    splits = {"train": [], "valid": [], "test": []}

    for task, task_records in by_task.items():
        rng.shuffle(task_records)

        by_family = defaultdict(list)
        for r in task_records:
            families = r["metadata"].get("argus_payload_families", [])
            family_key = families[0] if families else "__no_family__"
            by_family[family_key].append(r)

        for family, family_records in by_family.items():
            rng.shuffle(family_records)
            n = len(family_records)
            n_train = max(1, int(n * ratios["train"]))
            n_valid = max(1, int(n * ratios["valid"]))

            splits["train"].extend(family_records[:n_train])
            splits["valid"].extend(family_records[n_train:n_train + n_valid])
            splits["test"].extend(family_records[n_train + n_valid:])

    return splits


def main():
    parser = argparse.ArgumentParser(description="Convert and validate training data JSONL files")
    parser.add_argument("--input", nargs="+", help="Input JSONL file paths")
    parser.add_argument("--input-dir", type=str, help="Directory containing raw JSONL files")
    parser.add_argument("--output-dir", type=str, default="training_data/final", help="Output directory")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for splits")
    parser.add_argument("--skip-validation", action="store_true", help="Skip validation checks")
    parser.add_argument("--strict", action="store_true", help="Exit on validation error")
    args = parser.parse_args()

    input_files = []
    if args.input:
        input_files = [Path(f) for f in args.input]
    elif args.input_dir:
        input_dir = Path(args.input_dir)
        input_files = sorted(input_dir.glob("*.jsonl"))
    else:
        input_files = [Path("training_data/raw_repos.jsonl"), Path("training_data/argus_internal.jsonl")]

    if not input_files:
        print("[error] No input files found")
        sys.exit(1)

    print(f"[1/6] Reading {len(input_files)} input files...")
    all_records = []
    for fpath in input_files:
        if not fpath.exists():
            print(f"  [warn] File not found: {fpath}")
            continue
        count = 0
        with open(fpath, encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    record["_source_file"] = str(fpath)
                    record["_line_num"] = line_num
                    all_records.append(record)
                    count += 1
                except json.JSONDecodeError as e:
                    print(f"  [warn] JSON error in {fpath.name}:{line_num}: {e}")
        print(f"  {fpath.name}: {count} records")

    print(f"\n  Total records loaded: {len(all_records)}")

    if not args.skip_validation:
        print("\n[2/6] Validating records...")
        total_errors = 0
        valid_records = []
        for record in all_records:
            errors = validate_record(record, record.get("_line_num", 0))
            if errors:
                total_errors += len(errors)
                if args.strict:
                    for e in errors:
                        print(f"  [ERROR] {e}")
            else:
                for e in errors:
                    VALIDATION_REPORT.append(("WARN", e))
            if not errors:
                valid_records.append(record)

        print(f"  Valid: {len(valid_records)}/{len(all_records)}")
        print(f"  Warnings/Errors: {total_errors}")

        if args.strict and total_errors > 0:
            print("[error] Strict mode: validation errors found, exiting")
            sys.exit(1)

        all_records = valid_records
    else:
        print("\n[2/6] Validation skipped (--skip-validation)")

    print("\n[3/6] Deduplicating records...")
    seen_hashes = set()
    unique_records = []
    duplicates = 0
    for record in all_records:
        h = compute_dedup_hash(record)
        if h not in seen_hashes:
            seen_hashes.add(h)
            unique_records.append(record)
            duplicates_seen = False
        else:
            duplicates += 1

    print(f"  Unique: {len(unique_records)}, Duplicates removed: {duplicates}")

    print("\n[4/6] Splitting dataset...")
    splits = stratified_split(unique_records, SPLIT_RATIOS, seed=args.seed)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n[5/6] Writing split files...")
    split_stats = {}
    for split_name, split_records in splits.items():
        output_file = output_dir / f"{split_name}.jsonl"
        with open(output_file, "w", encoding="utf-8") as f:
            for record in split_records:
                clean = {k: v for k, v in record.items() if k != "_source_file" and k != "_line_num"}
                f.write(json.dumps(clean, ensure_ascii=False) + "\n")

        task_dist = defaultdict(int)
        family_dist = defaultdict(int)
        for r in split_records:
            task = r["metadata"].get("task", "unknown")
            task_dist[task] += 1
            for fam in r["metadata"].get("argus_payload_families", []):
                family_dist[fam] += 1

        split_stats[split_name] = {
            "count": len(split_records),
            "task_distribution": dict(task_dist),
            "family_distribution": dict(family_dist),
        }
        print(f"  {split_name}.jsonl: {len(split_records)} records")
        for task, count in sorted(task_dist.items()):
            print(f"    {task}: {count}")

    print("\n[6/6] Checking minimum example targets...")
    all_shortfalls = []
    for task_type, mins in MIN_EXAMPLES_PER_TASK.items():
        for split_name, min_count in mins.items():
            actual = split_stats.get(split_name, {}).get("task_distribution", {}).get(task_type, 0)
            if actual < min_count:
                shortfall = min_count - actual
                all_shortfalls.append(f"  {task_type}/{split_name}: {actual}/{min_count} (need {shortfall} more)")

    if all_shortfalls:
        print("  Shortfalls (below minimum targets):")
        for s in all_shortfalls:
            print(s)
        print(f"\n  Total shortfalls: {len(all_shortfalls)}")
        print("  * Consider running extract_repos.py to add more repo-sourced data")
        print("  * Or generate additional synthetic examples with generate_argus_training.py --augment")
    else:
        print("  All minimum targets met!")

    metadata_file = output_dir / "dataset_metadata.json"
    with open(metadata_file, "w", encoding="utf-8") as f:
        json.dump({
            "total_records": len(unique_records),
            "splits": split_stats,
            "split_ratios": SPLIT_RATIOS,
            "seed": args.seed,
            "validation_warnings": len(VALIDATION_REPORT),
            "all_54_families": ALL_54_FAMILIES,
            "task_types": VALID_TASK_TYPES,
        }, f, indent=2, ensure_ascii=False)

    print(f"\n[done] Dataset written to {output_dir}/")
    print(f"  train.jsonl: {split_stats['train']['count']} records")
    print(f"  valid.jsonl: {split_stats['valid']['count']} records")
    print(f"  test.jsonl:  {split_stats['test']['count']} records")
    print(f"  dataset_metadata.json: summary statistics")
    print(f"\n  Total: {len(unique_records)} records")


if __name__ == "__main__":
    main()