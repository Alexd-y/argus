# ARGUS Strix-Based Enhancements Report (ENH-V3)

**Date:** 2026-04-02  
**Orchestration ID:** orch-strix-enhance  
**Source:** strix_argus_analysis_cursor_prompt_v3.md  
**Status:** Completed

---

## Summary

Implemented 5 new enhancements based on Strix (usestrix/strix, 20.5k stars) analysis:

| Enhancement | Status | Files Created/Modified |
|-------------|--------|----------------------|
| A: Skills System | ✅ | 22 files (1 __init__.py + 21 .md skills) |
| B: LLM Deduplication | ✅ | 4 files (module + model/schema updates) |
| C: Multi-Agent VA Orchestrator | ✅ | 2 files |
| D: Memory Compression | ✅ | 1 file |
| E: Scan Modes + Report | ✅ | 5 files modified + 1 migration |

**Tests:** 67 tests passed (59 new + 8 existing enrichment pipeline)

---

## Enhancement A: Skills System

**Path:** `backend/src/skills/`

Created a knowledge injection system with 21 skill files across 3 categories:

- **Vulnerabilities (16):** sql_injection, xss, ssrf, csrf, idor, xxe, rce, authentication_jwt, business_logic, race_conditions, path_traversal, open_redirect, mass_assignment, file_upload, information_disclosure, subdomain_takeover
- **Technologies (2):** graphql, jwt
- **Recon (3):** subdomain_enum, port_scanning, js_analysis

Each skill file contains:
- YAML frontmatter (name, description, applicable_contexts)
- Detailed methodology with specific tool commands and flags
- Payload progressions from basic to advanced
- WAF/filter bypass techniques
- Validation requirements (how to confirm exploitation)
- Business impact assessment guidance

**API:** `load_skill()`, `load_skills()`, `get_available_skills()`, `get_skills_for_category()`, `build_skills_prompt_block()`

---

## Enhancement B: LLM Deduplication

**Path:** `backend/src/dedup/`

Replaced difflib-based dedup with semantic LLM analysis using Strix XML response pattern:

- `DEDUPE_SYSTEM_PROMPT` — expert dedup instructions with clear duplicate/non-duplicate criteria
- `DEDUPE_USER_TEMPLATE` — structured comparison template
- `DedupResult` frozen dataclass: is_duplicate, confidence, duplicate_id, reason
- `check_duplicate()` — single finding comparison via `LLMTask.DEDUP_ANALYSIS`
- `check_duplicates_batch()` — sequential batch processing with confidence threshold (0.7)
- Safe-by-default: returns `is_duplicate=False` on any error

**DB:** Added `dedup_status` column to `findings` table (VARCHAR(20), default 'unchecked')
**Migration:** `016_scan_mode_finding_dedup_status.py`

---

## Enhancement C: Multi-Agent VA Orchestrator

**Path:** `backend/src/agents/va_orchestrator.py`

Implemented Strix-style multi-agent vulnerability assessment:

- `VAMultiAgentOrchestrator` — main orchestrator class
- `CATEGORY_SKILL_MAP` — 14 vulnerability categories mapped to skills
- `ScanMode` enum: QUICK, STANDARD, DEEP
- `REASONING_EFFORT` — temperature adjustment per mode (quick=0.3, standard=0.2, deep=0.1)
- Parallel discovery agents with bounded concurrency (semaphore=5)
- Skills content injected into LLM system prompts
- JSON response parsing with markdown fence handling
- `OrchestratorStats` — tracking noise_reduction_pct, owasp_coverage_pct

**Scan Modes:**
- quick: 4 categories (sqli, xss, auth, idor) — ~15min
- standard: 8 categories (+ssrf, rce, race, csrf) — ~45min  
- deep: all 14 categories — exhaustive

---

## Enhancement D: Memory Compression

**Path:** `backend/src/agents/memory_compressor.py`

Strix-style history compression for long-running scans:

- `ScanMemoryCompressor` — tracks call count, compresses when history exceeds 20K chars
- `COMPRESSION_SYSTEM_PROMPT` — preserves vulns, endpoints, hypotheses, tokens, tech stack
- Feature flag: `MEMORY_COMPRESSION_ENABLED` env var
- `build_compressed_history()` — replaces verbose history with [summary + last 5 messages]
- Uses cheapest LLM task type (`DEDUP_ANALYSIS`)
- Graceful degradation on compression failure

---

## Enhancement E: Scan Modes + Valhalla Report

### Config/DB/API Changes:
- `Settings.scan_mode` — quick|standard|deep (default: standard)
- `Settings.llm_dedup_enabled` — feature flag
- `Settings.memory_compression_enabled` — feature flag
- `Scan.scan_mode` — ORM column (VARCHAR(20), default 'standard')
- `ScanCreateRequest.scan_mode` — API field (Literal["quick", "standard", "deep"])
- `.env.example` — 3 new ENH-V3 variables

### Valhalla Report:
- `ScanMetadataModel` — scan_mode, agents_spawned, categories_tested, categories_not_tested, skills_used, noise_reduction_pct, owasp_coverage_pct, findings counts
- Added to `ValhallaReportContext.scan_metadata`
- `build_ai_input_payload()` now includes `scan_mode`

---

## Pipeline Integration

`enrichment_pipeline.py` updated with Step 2.5 — LLM Dedup between Adversarial Scoring and Perplexity:

```
Shodan → Adversarial Score → LLM Dedup → Perplexity → Validation → PoC
```

Stats now include `llm_dedup_run` and `findings_deduplicated`.

---

## Files Created

```
backend/src/skills/__init__.py
backend/src/skills/vulnerabilities/sql_injection.md
backend/src/skills/vulnerabilities/xss.md
backend/src/skills/vulnerabilities/ssrf.md
backend/src/skills/vulnerabilities/csrf.md
backend/src/skills/vulnerabilities/idor.md
backend/src/skills/vulnerabilities/xxe.md
backend/src/skills/vulnerabilities/rce.md
backend/src/skills/vulnerabilities/authentication_jwt.md
backend/src/skills/vulnerabilities/business_logic.md
backend/src/skills/vulnerabilities/race_conditions.md
backend/src/skills/vulnerabilities/path_traversal.md
backend/src/skills/vulnerabilities/open_redirect.md
backend/src/skills/vulnerabilities/mass_assignment.md
backend/src/skills/vulnerabilities/file_upload.md
backend/src/skills/vulnerabilities/information_disclosure.md
backend/src/skills/vulnerabilities/subdomain_takeover.md
backend/src/skills/technologies/graphql.md
backend/src/skills/technologies/jwt.md
backend/src/skills/recon/subdomain_enum.md
backend/src/skills/recon/port_scanning.md
backend/src/skills/recon/js_analysis.md
backend/src/dedup/__init__.py
backend/src/dedup/llm_dedup.py
backend/src/agents/__init__.py
backend/src/agents/va_orchestrator.py
backend/src/agents/memory_compressor.py
backend/alembic/versions/016_scan_mode_finding_dedup_status.py
backend/tests/test_skills_loader.py
backend/tests/test_llm_dedup.py
backend/tests/test_va_orchestrator.py
backend/tests/test_memory_compressor.py
```

## Files Modified

```
backend/src/core/config.py — scan_mode, llm_dedup_enabled, memory_compression_enabled
backend/src/db/models.py — Scan.scan_mode, Finding.dedup_status
backend/src/api/schemas.py — ScanCreateRequest.scan_mode, Finding.dedup_status
backend/src/intel/enrichment_pipeline.py — LLM dedup step
backend/src/reports/valhalla_report_context.py — ScanMetadataModel
backend/src/services/reporting.py — scan_mode in payload
backend/.env.example — ENH-V3 variables
infra/.env.example — ENH-V3 variables
infra/.env — ENH-V3 variables
```

## Next Steps

1. `docker-compose build` — rebuild with new code
2. `alembic upgrade head` — apply migration 016
3. Run full test suite: `pytest tests/ -v`
4. Canary deployment → monitoring → full rollout
