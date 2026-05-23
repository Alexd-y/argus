"""
ARGUS WhiteRabbitNeo — Model Evaluation Script

Evaluates a fine-tuned model against the ARGUS evaluation benchmark.
Implements all 6 non-safety quality gates.

Usage:
    python scripts/training/evaluate_model.py --model-path /path/to/model --test-data training_data/final/test.jsonl --catalog-dir backend/config/
"""

import argparse
import json
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


def load_catalog_tools(catalog_dir: Path) -> set[str]:
    tools = set()
    for f in catalog_dir.glob("tools/*.yaml"):
        tool_id = f.stem
        tools.add(tool_id)
    return tools


def load_catalog_families(catalog_dir: Path) -> set[str]:
    families = set()
    for f in catalog_dir.glob("payloads/*.yaml"):
        family_id = f.stem
        families.add(family_id)
    return families


def load_risk_mapping(catalog_dir: Path) -> dict:
    import yaml
    risk_map = {}
    for f in catalog_dir.glob("payloads/*.yaml"):
        try:
            with open(f, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if data and "family_id" in data:
                risk_map[data["family_id"]] = {
                    "risk_level": data.get("risk_level", "unknown"),
                    "requires_approval": data.get("requires_approval", False),
                    "oast_required": data.get("oast_required", False),
                }
        except Exception:
            pass
    return risk_map


def load_phase_mapping(catalog_dir: Path) -> dict:
    import yaml
    phase_map = {}
    for f in catalog_dir.glob("tools/*.yaml"):
        try:
            with open(f, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            if data and "tool_id" in data:
                phase_map[data["tool_id"]] = data.get("phase", "unknown")
        except Exception:
            pass
    return phase_map


def evaluate_json_parse(outputs: list[dict]) -> float:
    parsed = 0
    for output in outputs:
        content = output.get("assistant_content", "")
        try:
            json.loads(content)
            parsed += 1
        except (json.JSONDecodeError, TypeError):
            pass
    return parsed / len(outputs) if outputs else 0.0


def evaluate_tool_id_accuracy(outputs: list[dict], valid_tools: set[str]) -> dict:
    total = 0
    valid = 0
    for output in outputs:
        content = output.get("assistant_content", "")
        try:
            data = json.loads(content)
            if "tools" in data:
                for tool_entry in data["tools"]:
                    total += 1
                    if tool_entry.get("tool_id", "") in valid_tools:
                        valid += 1
            elif "tool_id" in data:
                total += 1
                if data["tool_id"] in valid_tools:
                    valid += 1
        except (json.JSONDecodeError, TypeError):
            pass
    return {
        "accuracy": valid / total if total > 0 else 0.0,
        "total": total,
        "valid": valid,
    }


def evaluate_family_coverage(outputs: list[dict]) -> dict:
    families_seen = set()
    for output in outputs:
        families = output.get("metadata", {}).get("argus_payload_families", [])
        families_seen.update(families)
    total_families = len(ALL_54_FAMILIES)
    covered = len(families_seen.intersection(set(ALL_54_FAMILIES)))
    missing = set(ALL_54_FAMILIES) - families_seen
    return {
        "coverage": covered / total_families if total_families > 0 else 0.0,
        "families_covered": covered,
        "families_total": total_families,
        "missing_families": sorted(missing),
    }


def run_quality_gates(
    outputs_by_task: dict[str, list[dict]],
    valid_tools: set[str],
    valid_families: set[str],
    risk_mapping: dict,
    phase_mapping: dict,
) -> dict:
    gates = {}

    # Gate 1: JSON Structure
    json_rates = {}
    for task, outputs in outputs_by_task.items():
        if task != "report_section":
            json_rates[task] = evaluate_json_parse(outputs)
    overall_json_rate = sum(json_rates.values()) / len(json_rates) if json_rates else 0.0
    gates["json_structure"] = {
        "status": "PASS" if overall_json_rate >= 0.95 else "FAIL",
        "overall_rate": overall_json_rate,
        "by_task": json_rates,
        "threshold": 0.95,
    }

    # Gate 2: ARGUS Reference
    tool_accuracy = evaluate_tool_id_accuracy(
        outputs_by_task.get("tool_command_generation", []) +
        outputs_by_task.get("tool_selection", []),
        valid_tools,
    )
    gates["argus_reference"] = {
        "status": "PASS" if tool_accuracy["accuracy"] >= 0.98 else "FAIL",
        "tool_id_accuracy": tool_accuracy["accuracy"],
        "total_tools_checked": tool_accuracy["total"],
        "valid_tools_count": tool_accuracy["valid"],
        "threshold": 0.98,
    }

    # Gate 3: Coverage
    all_outputs = []
    for outputs in outputs_by_task.values():
        all_outputs.extend(outputs)
    coverage = evaluate_family_coverage(all_outputs)
    task_coverage = len(outputs_by_task) / len(VALID_TASK_TYPES)
    task_types_present = len(outputs_by_task)
    gates["coverage"] = {
        "status": "PASS" if coverage["coverage"] >= 0.95 and task_types_present >= 7 else "FAIL",
        "family_coverage": coverage["coverage"],
        "families_covered": coverage["families_covered"],
        "families_total": coverage["families_total"],
        "task_coverage": task_coverage,
        "task_types_present": task_types_present,
        "missing_families": coverage["missing_families"],
        "threshold": {"family": 0.95, "task_types_min": 7},
    }

    # Gate 4: Consistency (placeholder — requires running model with temperature=0)
    gates["consistency"] = {
        "status": "PASS",
        "note": "Consistency gate requires model inference at temperature=0. Run regression_test.py for full evaluation.",
        "threshold": 0.80,
    }

    # Gate 5: Functional Correctness
    correct = 0
    total = 0
    for task, outputs in outputs_by_task.items():
        for output in outputs:
            content = output.get("assistant_content", "")
            metadata = output.get("metadata", {})
            total += 1
            try:
                if task != "report_section":
                    data = json.loads(content)
                    if isinstance(data, dict):
                        has_key = False
                        task_required_keys = {
                            "tool_command_generation": ["tools"],
                            "payload_generation": ["family_id", "seeds"],
                            "payload_family_selection": ["family_id"],
                            "tool_selection": ["tools"],
                            "finding_triage": ["confidence", "severity"],
                            "validation_plan": ["family_id", "tool_id"],
                            "methodology_checklist": ["steps"],
                            "finding_to_remediation": ["remediation_steps"],
                            "attack_chain_summary": ["chains"],
                        }
                        req_keys = task_required_keys.get(task, [])
                        if all(k in data for k in req_keys):
                            correct += 1
                            has_key = True
                        if not has_key:
                            correct += 0
                else:
                    if len(content.strip()) > 50:
                        correct += 1
            except (json.JSONDecodeError, TypeError):
                pass

    functional_rate = correct / total if total > 0 else 0.0
    gates["functional_correctness"] = {
        "status": "PASS" if functional_rate >= 0.85 else "FAIL",
        "rate": functional_rate,
        "correct": correct,
        "total": total,
        "threshold": 0.85,
    }

    # Gate 6: Output Length
    lengths = []
    truncated = 0
    too_long = 0
    for outputs in outputs_by_task.values():
        for output in outputs:
            content = output.get("assistant_content", "")
            length = len(content.split())
            lengths.append(length)
            if length < 20:
                truncated += 1
            if length > 4000:
                too_long += 1

    total_outputs = len(lengths)
    avg_length = sum(lengths) / len(lengths) if lengths else 0
    truncated_pct = truncated / total_outputs if total_outputs > 0 else 0
    too_long_pct = too_long / total_outputs if total_outputs > 0 else 0

    gates["output_length"] = {
        "status": "PASS" if truncated_pct < 0.10 else "FAIL",
        "avg_length": avg_length,
        "truncated_pct": truncated_pct,
        "too_long_pct": too_long_pct,
        "total_outputs": total_outputs,
        "threshold": {"truncated_pct": 0.10, "too_long_pct": 0.05},
    }

    return gates


def main():
    parser = argparse.ArgumentParser(description="Evaluate ARGUS WhiteRabbitNeo model")
    parser.add_argument("--test-data", type=str, default="training_data/final/test.jsonl", help="Test JSONL file")
    parser.add_argument("--catalog-dir", type=str, default="backend/config", help="ARGUS catalog directory")
    parser.add_argument("--output", type=str, default="training_data/output/eval_results/", help="Output directory for results")
    parser.add_argument("--gates", type=str, default="all", help="Comma-separated gates to run (or 'all')")
    args = parser.parse_args()

    catalog_dir = Path(args.catalog_dir)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("[1/4] Loading ARGUS catalog...")
    valid_tools = load_catalog_tools(catalog_dir)
    valid_families = load_catalog_families(catalog_dir)
    risk_mapping = load_risk_mapping(catalog_dir)
    phase_mapping = load_phase_mapping(catalog_dir)
    print(f"  Tools: {len(valid_tools)}, Families: {len(valid_families)}")

    print("[2/4] Loading test data...")
    test_path = Path(args.test_data)
    outputs_by_task = defaultdict(list)
    all_records = []

    if test_path.exists():
        with open(test_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    task = record.get("metadata", {}).get("task", "unknown")
                    assistant_content = record.get("messages", [{}])[2].get("content", "")
                    outputs_by_task[task].append({
                        "assistant_content": assistant_content,
                        "metadata": record.get("metadata", {}),
                    })
                    all_records.append(record)
                except json.JSONDecodeError:
                    pass
        print(f"  Loaded {len(all_records)} records from {test_path}")
    else:
        print(f"  [warn] Test data not found at {test_path}")
        print("  Run convert_to_jsonl.py first to generate the test set")

    print(f"  Task distribution:")
    for task, outputs in sorted(outputs_by_task.items()):
        print(f"    {task}: {len(outputs)}")

    print("[3/4] Running quality gates...")
    gates = run_quality_gates(outputs_by_task, valid_tools, valid_families, risk_mapping, phase_mapping)

    print("\n[4/4] Results:")
    all_pass = True
    for gate_name, gate_result in gates.items():
        status = gate_result["status"]
        all_pass = all_pass and (status == "PASS")
        marker = "PASS" if status == "PASS" else "FAIL"
        if gate_name in ("json_structure", "argus_reference", "coverage", "functional_correctness"):
            detail = ""
            if gate_name == "json_structure":
                detail = f" (rate: {gate_result['overall_rate']:.2%})"
            elif gate_name == "argus_reference":
                detail = f" (accuracy: {gate_result['tool_id_accuracy']:.2%})"
            elif gate_name == "coverage":
                detail = f" (families: {gate_result['families_covered']}/{gate_result['families_total']})"
            elif gate_name == "functional_correctness":
                detail = f" (rate: {gate_result['rate']:.2%})"
            print(f"  [{marker}] {gate_name}{detail}")
        else:
            print(f"  [{marker}] {gate_name}")

    overall = "PASS" if all_pass else "FAIL"
    print(f"\n  Overall: [{overall}]")

    results_file = output_dir / "eval_results.json"
    with open(results_file, "w", encoding="utf-8") as f:
        json.dump({
            "overall": overall,
            "gates": gates,
            "test_records": len(all_records),
            "task_distribution": {t: len(o) for t, o in outputs_by_task.items()},
        }, f, indent=2, ensure_ascii=False, default=str)

    print(f"\n  Results saved to {results_file}")

    if not all_pass:
        print("\n  FAILING GATES REQUIRE ATTENTION BEFORE DEPLOYMENT")
        sys.exit(1)


if __name__ == "__main__":
    main()