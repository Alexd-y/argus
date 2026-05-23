# ARGUS WhiteRabbitNeo — Evaluation Benchmark & Non-Safety Quality Gates

**Created:** 2026-05-23
**Task:** TRN-008

---

## 1. Evaluation Benchmark Overview

The evaluation benchmark measures model quality across 5 dimensions:
1. **Functional Correctness** — Does the model output valid, parseable content?
2. **ARGUS Compliance** — Does the output conform to ARGUS schemas (tool_id, family_id, etc.)?
3. **Factual Accuracy** — Are the tool commands, payload templates, and technical details correct?
4. **Consistency** — Are outputs consistent across similar inputs?
5. **Coverage** — Does the model cover all 54 payload families and 162 tools?

**No safety gates.** All quality gates are functional, not safety-related.

---

## 2. Benchmark Datasets

### 2.1 Static Test Set

Located at `training_data/final/test.jsonl` (produced by `convert_to_jsonl.py`).

Stratified by task type and payload family. Each task type has minimum examples per split.

### 2.2 Hand-Crafted Evaluation Set

Located at `training_data/eval_benchmark/` with structured test cases for each task type.

---

## 3. Evaluation Metrics Per Task Type

### 3.1 tool_command_generation

| Metric | Description | Threshold |
|--------|-------------|-----------|
| `json_parse_rate` | % of outputs that parse as valid JSON | >= 0.95 |
| `tool_id_accuracy` | % of tool_id values that exist in ARGUS catalog | >= 0.98 |
| `command_format_accuracy` | % of commands with correct structure | >= 0.90 |
| `phase_accuracy` | % of phase assignments that match the input | >= 0.95 |
| `risk_level_accuracy` | % of risk_level values that match tool YAML | >= 0.90 |

**Evaluation:** Run model on test set, parse JSON output, compare tool_id against `backend/config/tools/*.yaml`.

### 3.2 payload_generation

| Metric | Description | Threshold |
|--------|-------------|-----------|
| `json_parse_rate` | % of outputs that parse as valid JSON | >= 0.95 |
| `family_id_accuracy` | % of family_id values that match requested family | >= 0.98 |
| `family_coverage` | % of 54 families that produce valid output | >= 0.95 |
| `seed_count` | Average seeds per family (min 2, target 4+) | >= 2.0 |
| `template_nonempty` | % of seed templates that are non-empty strings | >= 0.98 |
| `cwe_id_accuracy` | % of CWE IDs that match family definition | >= 0.95 |
| `risk_level_accuracy` | % of risk_level values matching family definition | >= 0.90 |
| `oast_flag_accuracy` | % of oast_required flags matching family definition | >= 0.95 |

**Evaluation:** Generate payloads for all 54 families, check coverage and correctness.

### 3.3 payload_family_selection

| Metric | Description | Threshold |
|--------|-------------|-----------|
| `json_parse_rate` | % of outputs that parse as valid JSON | >= 0.95 |
| `family_selection_accuracy` | % of correct primary family selections | >= 0.90 |
| `alternative_relevance` | % of alternative families that are actually related | >= 0.80 |
| `risk_level_accuracy` | % of correct risk level assignments | >= 0.90 |
| `approval_flag_accuracy` | % of correct requires_approval flags | >= 0.95 |
| `oast_flag_accuracy` | % of correct oast_required flags | >= 0.95 |

### 3.4 tool_selection

| Metric | Description | Threshold |
|--------|-------------|-----------|
| `json_parse_rate` | % of outputs that parse as valid JSON | >= 0.95 |
| `tool_id_validity` | % of selected tool_ids that exist in catalog | >= 0.98 |
| `phase_consistency` | % of tools selected that match the given phase | >= 0.90 |
| `ordering_quality` | % of cases where tool ordering makes logical sense | >= 0.80 |
| `dependency_handling` | % of cases where tool dependencies are respected | >= 0.75 |

### 3.5 finding_triage

| Metric | Description | Threshold |
|--------|-------------|-----------|
| `json_parse_rate` | % of outputs that parse as valid JSON | >= 0.95 |
| `severity_appropriateness` | % of severity ratings that match evidence strength | >= 0.80 |
| `confidence_calibration` | % of confidence levels that match evidence | >= 0.80 |
| `evidence_referencing` | % of rationales that reference specific evidence | >= 0.75 |

### 3.6 validation_plan

| Metric | Description | Threshold |
|--------|-------------|-----------|
| `json_parse_rate` | % of outputs that parse as valid JSON | >= 0.95 |
| `family_selection_accuracy` | % of correct family_id selections for findings | >= 0.85 |
| `tool_selection_accuracy` | % of correct tool_id selections | >= 0.85 |
| `strategy_appropriateness` | % of validation strategies that match the vulnerability | >= 0.80 |
| `step_completeness` | % of plans with all necessary verification steps | >= 0.75 |

### 3.7 methodology_checklist

| Metric | Description | Threshold |
|--------|-------------|-----------|
| `json_parse_rate` | % of outputs that parse as valid JSON | >= 0.95 |
| `step_count` | Average steps per phase (target 5-10) | 5-10 |
| `tool_id_validity` | % of referenced tool_ids that exist | >= 0.95 |
| `phase_coverage` | % of phases with complete methodology | >= 0.80 |
| `ordering_quality` | % of step orderings that make logical sense | >= 0.80 |

### 3.8 finding_to_remediation

| Metric | Description | Threshold |
|--------|-------------|-----------|
| `json_parse_rate` | % of outputs that parse as valid JSON | >= 0.95 |
| `cwe_match` | % of remediation steps that match the CWE | >= 0.90 |
| `step_count` | Average remediation steps (target 3-5) | 3-5 |
| `severity_appropriateness` | % of severity levels matching the finding | >= 0.85 |

### 3.9 attack_chain_summary

| Metric | Description | Threshold |
|--------|-------------|-----------|
| `json_parse_rate` | % of outputs that parse as valid JSON | >= 0.90 |
| `chain_completeness` | % of chains with 3+ steps | >= 0.80 |
| `technique_accuracy` | % of MITRE ATT&CK technique IDs that are valid | >= 0.70 |
| `step_connectivity` | % of steps that logically connect (previous step enables next) | >= 0.75 |
| `finding_references` | % of chains that reference actual findings | >= 0.80 |

### 3.10 report_section

| Metric | Description | Threshold |
|--------|-------------|-----------|
| `nonempty_output` | % of non-empty output strings | >= 0.98 |
| `evidence_grounding` | % of claims that reference specific evidence | >= 0.80 |
| `severity_coverage` | % of findings that are addressed in the report | >= 0.90 |
| `no_speculation` | % of output that avoids unverifiable claims | >= 0.90 |
| `section_structure` | % of reports with proper heading structure | >= 0.85 |

---

## 4. Non-Safety Quality Gates

These gates are **functional correctness** checks, NOT safety restrictions. They ensure the model produces high-quality, technically accurate output.

### 4.1 Gate 1: JSON Structure Gate

```
PASS if:
  - All structured task types produce parseable JSON
  - JSON contains required fields for the task type
  - json_parse_rate >= 0.95

FAIL if:
  - json_parse_rate < 0.90
  - Missing required fields in >5% of outputs
```

### 4.2 Gate 2: ARGUS Reference Gate

```
PASS if:
  - All tool_id values exist in backend/config/tools/*.yaml (157+ tools)
  - All family_id values exist in backend/config/payloads/*.yaml (54 families)
  - tool_id_accuracy >= 0.98
  - family_id_accuracy >= 0.98

FAIL if:
  - tool_id_accuracy < 0.95
  - family_id_accuracy < 0.95
  - Any hallucinated tool_id or family_id in >5% of outputs
```

### 4.3 Gate 3: Coverage Gate

```
PASS if:
  - All 54 payload families produce valid output in payload_generation
  - All 10 task types produce valid output
  - family_coverage >= 0.95
  - task_coverage == 1.0 (10/10)

FAIL if:
  - family_coverage < 0.90
  - Any task type has 0 valid outputs
  - Missing 3+ payload families
```

### 4.4 Gate 4: Consistency Gate

```
PASS if:
  - Same input produces same output >=80% of the time (temperature=0)
  - Similar inputs produce similar outputs
  - No contradictory outputs for same family/tool
  - consistency_score >= 0.80

FAIL if:
  - consistency_score < 0.70
  - Contradictory risk levels for same payload family
  - Tool assigned to wrong phase in >10% of cases
```

### 4.5 Gate 5: Functional Correctness Gate

```
PASS if:
  - Command templates use correct ARGUS format
  - Payload templates are syntactically valid for their injection type
  - CWE/OWASP mappings are correct
  - Phase assignments match tool definitions
  - Overall functional_correctness >= 0.85

FAIL if:
  - functional_correctness < 0.75
  - Invalid command syntax in >15% of outputs
  - Incorrect CWE mapping in >10% of outputs
```

### 4.6 Gate 6: Output Length Gate

```
PASS if:
  - Average output length is within 50-2000 tokens
  - No truncated outputs that cut off mid-JSON
  - No excessively verbose outputs (>4000 tokens)

FAIL if:
  - >10% of outputs are truncated
  - >5% of outputs exceed 4000 tokens
  - Average output <20 tokens (model not generating enough)
```

---

## 5. Evaluation Script

### 5.1 Running Evaluation

```bash
# Stage evaluation after SFT
python scripts/training/evaluate_model.py \
  --model-path training_data/output/argus-whiterabbitneo-v3-7b-sft \
  --test-data training_data/final/test.jsonl \
  --benchmark-dir training_data/eval_benchmark/ \
  --catalog-dir backend/config/ \
  --output training_data/output/eval_results/ \
  --gates functional_correctness,argus_reference,coverage,consistency,output_length

# Full evaluation with all gates
python scripts/training/evaluate_model.py \
  --model-path training_data/output/argus-whiterabbitneo-v3-7b-sft \
  --test-data training_data/final/test.jsonl \
  --benchmark-dir training_data/eval_benchmark/ \
  --catalog-dir backend/config/ \
  --output training_data/output/eval_results/ \
  --gates all
```

### 5.2 Gate Decision Logic

A training run PASSES evaluation if ALL of the following are true:
1. All 6 quality gates pass
2. Overall json_parse_rate >= 0.95
3. Family coverage >= 52/54 (96%)
4. Tool catalog reference accuracy >= 0.95
5. No single task type has json_parse_rate < 0.90

A training run FAILS evaluation if ANY gate fails, and requires:
- Hyperparameter adjustment (learning rate, epochs, LoRA rank)
- Data quality review (check for malformed examples)
- Architecture adjustment (sequence length, attention type)

---

## 6. Regression Testing

### 6.1 Regression Test Suite

After each training run, compare against baseline (untuned WhiteRabbitNeo-V3-7B):

```bash
python scripts/training/regression_test.py \
  --baseline-model WhiteRabbitNeo/WhiteRabbitNeo-V3-7B \
  --candidate-model training_data/output/argus-whiterabbitneo-v3-7b-sft \
  --test-data training_data/final/test.jsonl \
  --catalog-dir backend/config/ \
  --output training_data/output/regression_results/
```

### 6.2 Regression Criteria

The candidate model must NOT regress compared to baseline on:
- JSON parse rate (must be >= baseline - 5%)
- Factual accuracy on tool commands (must be >= baseline)
- Payload family coverage (must be >= baseline)

The candidate model MUST improve on baseline for:
- ARGUS schema compliance (must be > baseline)
- Tool_id accuracy (must be > baseline)
- Structure of output (must be more consistent than baseline)

---

## 7. Quality Gate Rollup

| Gate | Threshold | Rollup |
|------|-----------|--------|
| JSON Structure | json_parse_rate >= 0.95 | Blocking |
| ARGUS Reference | tool_id/family_id accuracy >= 0.98 | Blocking |
| Coverage | family_coverage >= 0.95, task_coverage = 1.0 | Blocking |
| Consistency | consistency_score >= 0.80 | Advisory |
| Functional Correctness | >= 0.85 | Blocking |
| Output Length | < 10% truncated, < 5% >4000 tokens | Advisory |

**Blocking** = must pass before deployment
**Advisory** = should investigate and fix before deployment, but not a hard block