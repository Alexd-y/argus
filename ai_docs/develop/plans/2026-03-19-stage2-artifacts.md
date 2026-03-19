# Plan: Stage 2 Threat Modeling Data Collection Improvements

**Created:** 2026-03-19  
**Orchestration:** orch-2026-03-19-16-00-stage2-artifacts  
**Goal:** Modify Stage 2 pipeline to generate structured machine-readable artifacts for Stage 3 (Vulnerability Analysis), save to `artifacts/stage2/{scan_id}/` and MinIO `stage2-artifacts` bucket.

**Total Tasks:** 10  
**Priority:** High  
**Estimated Time:** 8–10 hours

---

## Tasks Overview

| ID | Task | Priority | Dependencies | Est. |
|----|------|----------|--------------|------|
| TM2-001 | Pydantic models for Stage 3 artifacts | High | None | 1.5h |
| TM2-002 | Parsing functions: AI outputs → typed models | High | TM2-001 | 1.5h |
| TM2-003 | threat_model.json generator | High | TM2-002 | 1h |
| TM2-004 | ai_tm_priority_hypotheses.json generator | Medium | TM2-001, TM2-002 | 0.5h |
| TM2-005 | ai_tm_application_flows.json (normalized) | Medium | TM2-001 | 0.5h |
| TM2-006 | stage2_inputs.json (traceability copy) | Medium | None | 0.5h |
| TM2-007 | stage2-artifacts MinIO bucket + storage module | High | None | 1h |
| TM2-008 | Pipeline integration: generate + persist 4 artifacts | High | TM2-003..TM2-007 | 1.5h |
| TM2-009 | File-based path: artifacts/stage2/{scan_id}/ | Medium | TM2-008 | 0.5h |
| TM2-010 | Update docs/recon-stage2-flow.md | Medium | TM2-008 | 0.5h |

---

## Required Artifacts (Stage 3 Input Contract)

### 1. threat_model.json
Unified JSON:
- **critical_assets**: list of {id, name (subdomain), type (observation/hypothesis), source (Stage 1 artifact ref)}
- **trust_boundaries**: list of {id, name, components (asset IDs), source}
- **entry_points**: list of {id, name, component_id, type (hypothesis), source}
- **attacker_profiles**: list of profiles
- **threat_scenarios**: list of {id, priority, entry_point_id, attacker_profile_id, description}

### 2. ai_tm_priority_hypotheses.json
Prioritized hypotheses:
- Each: id, hypothesis_text, priority (high/medium/low), confidence (0.0–1.0), related_asset_id, source_artifact

### 3. ai_tm_application_flows.json
Normalized JSON with data flows between components.

### 4. stage2_inputs.json
Copy of Stage 1 inputs used for this run (traceability).

---

## Dependencies Graph

```
TM2-001 ─┬─► TM2-002 ─► TM2-003 ─┐
         │              TM2-004   │
         └─► TM2-005 ─────────────┼─► TM2-008 ─► TM2-009
                                 │              TM2-010
TM2-006 ─────────────────────────┘
TM2-007 ─────────────────────────┘
```

---

## Architecture Decisions

1. **scan_id = job_id** for Stage 2 path and MinIO keys — aligns with Stage 1 job linkage.
2. **Separate stage2-artifacts bucket** — mirrors stage1-artifacts; clear separation for Stage 3 consumption.
3. **Pydantic-first** — all JSON artifacts validated via Pydantic before persist; parsing functions handle AI output variability.
4. **source field** — references Stage 1 artifact (e.g. `stage1/scan_id/recon_results.json`) for traceability.

---

## Related Files

- Pipeline: `backend/src/recon/threat_modeling/pipeline.py`
- Schemas: `backend/app/schemas/threat_modeling/schemas.py`
- Stage 1 storage: `backend/src/recon/stage1_storage.py`
- Docs: `docs/recon-stage2-flow.md`
