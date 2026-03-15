# Plan: Stage 3 Vulnerability Analysis Upgrade — Confirmed-Findings-Ready

**Created:** 2026-03-14  
**Orchestration:** orch-2026-03-14-stage3-upgrade  
**Goal:** Upgrade Stage 3 from hypothesis-heavy to evidence-driven, confirmed-findings-ready with explicit status model, evidence sufficiency, hard gate, and MCP/AI integration.  
**Total Tasks:** 10  
**Priority:** High

---

## Current State (Gap Analysis)

| Component | Exists | Notes |
|-----------|--------|-------|
| Stage 1/2/3 modules | ✅ | `vulnerability_analysis/pipeline.py`, `dependency_check.py`, `input_loader.py` |
| Artifact storage | ✅ | DB + MinIO, `artifact_service`, `storage.py` |
| MCP integration | ✅ | `mcp/client.py`, `mcp/policy.py`, `mcp_enrichment.py` |
| AI orchestration | ✅ | 15 tasks in `ai_task_registry.py`, sequential execution |
| Report builders | ✅ | `artifacts.py` → `vulnerability_analysis.md`, CSVs |
| Finding models | ⚠️ | `ConfirmedFinding`, `RejectedHypothesis`, `PartiallyConfirmedHypothesis` in schemas — **not used in pipeline** |
| Gate logic | ⚠️ | 4 blocking reasons (stage1/2/unlinked/not_ready) — **no post-Stage3 next-phase gate** |
| Finding status model | ❌ | No explicit `hypothesis | partially_confirmed | confirmed | rejected` |
| Evidence sufficiency | ❌ | No evaluator |
| Evidence bundle | ❌ | No builder |
| Contradiction analysis | ❌ | None |
| Duplicate correlation | ⚠️ | `finding_correlation` exists but is correlation, not deduplication |
| Scenario/boundary/asset mapping | ❌ | None |
| Confirmation policy | ❌ | None |
| 7 new AI tasks | ❌ | Spec tasks differ from current 15 |

---

## Tasks Overview

### VA3UP-001: Finding Lifecycle Model
- **Priority:** Critical
- **Dependencies:** None
- **Scope:** Add `FindingStatus` enum (`hypothesis`, `partially_confirmed`, `confirmed`, `rejected`) to schemas; extend `ValidationWeakness`, `ConfirmedFinding`, `RejectedHypothesis`, `PartiallyConfirmedHypothesis` with `finding_status`; add `FindingLifecycle` model for transitions.
- **Files:** `app/schemas/vulnerability_analysis/schemas.py`, `app/schemas/ai/common.py`
- **Acceptance:** All check types and findings carry explicit status; schema exports valid.

### VA3UP-002: Evidence Sufficiency Evaluator
- **Priority:** High
- **Dependencies:** VA3UP-001
- **Scope:** Implement `EvidenceSufficiencyEvaluator` — rules for min evidence count, evidence types (direct/indirect), coverage per finding. Output `evidence_sufficiency.json` schema.
- **Files:** `src/recon/vulnerability_analysis/evidence_sufficiency.py`, `app/schemas/vulnerability_analysis/evidence_sufficiency.py`
- **Acceptance:** Evaluator returns sufficiency score per finding; rules configurable.

### VA3UP-003: Evidence Bundle Builder
- **Priority:** High
- **Dependencies:** VA3UP-001
- **Scope:** Implement `EvidenceBundleBuilder` — aggregates Stage 1/2 evidence refs per finding, builds `evidence_bundles.json` with `finding_id`, `evidence_refs`, `artifact_refs`, `coverage_summary`.
- **Files:** `src/recon/vulnerability_analysis/evidence_bundle_builder.py`, `app/schemas/vulnerability_analysis/evidence_bundles.py`
- **Acceptance:** Bundle links findings to Stage 1/2 artifacts; output schema valid.

### VA3UP-004: Contradiction Analysis + Duplicate Finding Correlation
- **Priority:** High
- **Dependencies:** VA3UP-001, VA3UP-003
- **Scope:** `ContradictionAnalyzer` — detect conflicting evidence/statements per finding; `DuplicateFindingCorrelator` — group duplicates by semantic similarity, route/param/asset overlap. Output structures for both.
- **Files:** `src/recon/vulnerability_analysis/contradiction_analysis.py`, `src/recon/vulnerability_analysis/duplicate_correlation.py`
- **Acceptance:** Contradictions and duplicate groups identified; output schemas defined.

### VA3UP-005: Scenario/Boundary/Asset Mapping
- **Priority:** Medium
- **Dependencies:** VA3UP-001
- **Scope:** Implement `FindingToScenarioMapper` — map findings to threat scenarios, trust boundaries, critical assets. Output `finding_to_scenario_map.json`.
- **Files:** `src/recon/vulnerability_analysis/scenario_mapping.py`, `app/schemas/vulnerability_analysis/scenario_mapping.py`
- **Acceptance:** Each finding has scenario_ids, boundary_ids, asset_ids; mapping auditable.

### VA3UP-006: Confirmation Policy Module
- **Priority:** High
- **Dependencies:** VA3UP-001, VA3UP-002, VA3UP-004
- **Scope:** Implement `ConfirmationPolicy` — rules for when hypothesis → partially_confirmed → confirmed; when to reject; integration with evidence sufficiency and contradiction resolution.
- **Files:** `src/recon/vulnerability_analysis/confirmation_policy.py`
- **Acceptance:** Policy evaluates findings; status transitions defined; no exploit/brute-force logic.

### VA3UP-007: Hard Next-Phase Gate
- **Priority:** Critical
- **Dependencies:** VA3UP-002, VA3UP-004, VA3UP-006
- **Scope:** Implement `NextPhaseGate` — block if: `blocked_missing_stage1`, `blocked_missing_stage2`, `blocked_missing_stage3`, `blocked_no_confirmed_findings`, `blocked_insufficient_evidence`, `blocked_unlinked_findings`, `blocked_unresolved_contradictions`; pass if `ready_for_next_phase`. Output `next_phase_gate.json`.
- **Files:** `src/recon/vulnerability_analysis/next_phase_gate.py`, `app/schemas/recon/next_phase_gate.py`, extend `dependency_check.py` / `stage3_readiness.py`
- **Acceptance:** Gate blocks pipeline when criteria not met; gate result persisted.

### VA3UP-008: 7 AI Tasks + Pipeline Integration
- **Priority:** High
- **Dependencies:** VA3UP-001–VA3UP-007
- **Scope:** Add/refactor AI tasks: `evidence_bundle_assembly`, `finding_confirmation_assessment`, `contradiction_analysis`, `duplicate_finding_correlation`, `finding_to_scenario_mapping`, `remediation_generation`, `stage3_confirmation_summary`. Integrate into pipeline after existing 15 tasks (or replace overlapping ones). Prompts, registry, validation.
- **Files:** `app/schemas/ai/common.py`, `app/prompts/vulnerability_analysis_prompts.py`, `ai_task_registry.py`, `pipeline.py`, `app/schemas/vulnerability_analysis/ai_tasks.py`
- **Acceptance:** 7 tasks run in pipeline; outputs feed gate and artifacts.

### VA3UP-009: Stage 3 MCP Allowlist + New Artifacts
- **Priority:** Medium
- **Dependencies:** VA3UP-003, VA3UP-007
- **Scope:** Extend `VULNERABILITY_ANALYSIS_ALLOWED_OPERATIONS` for evidence correlation (e.g. `evidence_correlation`, `finding_deduplication`). Generate `evidence_bundles.json`, `evidence_sufficiency.json`, `finding_confirmation_matrix.csv`, `next_phase_gate.json` in artifact generation.
- **Files:** `src/recon/mcp/policy.py`, `src/recon/vulnerability_analysis/artifacts.py`
- **Acceptance:** MCP policy allows new ops; all 4 artifacts produced.

### VA3UP-010: API/CLI Endpoints + Report Updates
- **Priority:** Medium
- **Dependencies:** VA3UP-007, VA3UP-009
- **Scope:** Add API endpoints: `GET .../next-phase-gate`, `GET .../evidence-bundles`, `GET .../evidence-sufficiency`, `GET .../finding-confirmation-matrix`. CLI subcommands for inspection. Update `vulnerability_analysis.md` structure: add Evidence Sufficiency, Finding Confirmation Matrix, Next Phase Gate Status, Contradictions, Duplicate Groups.
- **Files:** `src/api/routers/recon/vulnerability_analysis.py`, `src/recon/cli/commands/vulnerability_analysis.py`, `artifacts.py` (report generator)
- **Acceptance:** Endpoints return new artifacts; report includes new sections.

---

## Dependencies Graph

```
VA3UP-001 (Finding Lifecycle)
    ├── VA3UP-002 (Evidence Sufficiency)
    ├── VA3UP-003 (Evidence Bundle)
    ├── VA3UP-005 (Scenario Mapping)
    └── VA3UP-006 (Confirmation Policy)

VA3UP-002, VA3UP-003 ──► VA3UP-004 (Contradiction + Duplicate)
VA3UP-001, VA3UP-002, VA3UP-004 ──► VA3UP-006 (Confirmation Policy)
VA3UP-002, VA3UP-004, VA3UP-006 ──► VA3UP-007 (Next Phase Gate)

VA3UP-001..007 ──► VA3UP-008 (7 AI Tasks)
VA3UP-003, VA3UP-007 ──► VA3UP-009 (MCP + Artifacts)
VA3UP-007, VA3UP-009 ──► VA3UP-010 (API + Report)
```

---

## Progress (updated by orchestrator)

- ⏳ VA3UP-001: Finding Lifecycle Model (Pending)
- ⏳ VA3UP-002: Evidence Sufficiency Evaluator (Pending)
- ⏳ VA3UP-003: Evidence Bundle Builder (Pending)
- ⏳ VA3UP-004: Contradiction Analysis + Duplicate Correlation (Pending)
- ⏳ VA3UP-005: Scenario/Boundary/Asset Mapping (Pending)
- ⏳ VA3UP-006: Confirmation Policy Module (Pending)
- ⏳ VA3UP-007: Hard Next-Phase Gate (Pending)
- ⏳ VA3UP-008: 7 AI Tasks + Pipeline Integration (Pending)
- ⏳ VA3UP-009: Stage 3 MCP Allowlist + New Artifacts (Pending)
- ⏳ VA3UP-010: API/CLI Endpoints + Report Updates (Pending)

---

## Architecture Decisions

- **Finding status:** Explicit enum `hypothesis | partially_confirmed | confirmed | rejected` on all finding-like entities.
- **Evidence sufficiency:** Rule-based evaluator; thresholds configurable via config/env.
- **Gate:** Hard block before next phase; no bypass for authorized assessment workflow.
- **7 AI tasks:** Integrate alongside or replace overlapping tasks (e.g. `finding_correlation` → `duplicate_finding_correlation`, `remediation_note_generation` → `remediation_generation`).
- **MCP:** Fail-closed; only allowlisted tools/operations; no exploit, brute-force, credential attacks.
- **Constraints:** Authorized assessment only; evidence-driven; non-destructive; auditable; scope-bound.

---

## Implementation Notes

- Preserve backward compatibility: existing 15 tasks continue to run; new tasks run after or in parallel where safe.
- All new modules must have unit tests.
- Logging: structured JSON; no secrets/PII in logs.
- Error handling: no stack traces to end user; exceptions caught and mapped to safe messages.
