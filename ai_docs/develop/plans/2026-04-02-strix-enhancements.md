# ARGUS Strix-Based Enhancements Plan

**Orchestration ID:** orch-strix-enhance  
**Created:** 2026-04-02  
**Source:** strix_argus_analysis_cursor_prompt_v3.md  
**Status:** ✅ Completed

---

## Tasks

### TASK-01: Skills System — Core + Vulnerability Skill Files ✅ Completed
Create `backend/src/skills/` package with `__init__.py` (load_skill, get_available_skills, load_skills).
Create 16 vulnerability skill files in `backend/src/skills/vulnerabilities/`:
sql_injection.md, xss.md, ssrf.md, csrf.md, idor.md, xxe.md, rce.md,
authentication_jwt.md, business_logic.md, race_conditions.md,
path_traversal.md, open_redirect.md, mass_assignment.md,
file_upload.md, information_disclosure.md, subdomain_takeover.md.
Create tech skills in `backend/src/skills/technologies/`: graphql.md, jwt.md.
Create recon skills in `backend/src/skills/recon/`: subdomain_enum.md, port_scanning.md, js_analysis.md.
Each file: YAML frontmatter + detailed methodology, commands, payloads, WAF bypasses, validation.

**Files:** backend/src/skills/__init__.py, backend/src/skills/vulnerabilities/*.md (16), backend/src/skills/technologies/*.md (2), backend/src/skills/recon/*.md (3)

### TASK-02: LLM Deduplication Module ✅ Completed
Create `backend/src/dedup/` package.
Create `backend/src/dedup/__init__.py` and `backend/src/dedup/llm_dedup.py`.
DedupResult dataclass, check_duplicate() with XML response parsing.
Add DEDUP_ANALYSIS task to LLM router if not exist.
Add dedup_status field to Finding ORM model and API schema.

**Files:** backend/src/dedup/__init__.py, backend/src/dedup/llm_dedup.py, backend/src/db/models.py, backend/src/api/schemas.py

### TASK-03: Scan Modes — Config, DB, API, Env ✅ Completed
Add scan_mode (quick/standard/deep) to Settings, Scan ORM model, ScanCreateRequest schema.
Add SCAN_MODE env var to .env.example.
Add REASONING_EFFORT mapping and temperature adjustment per mode.
Alembic migration for scan_mode column.

**Files:** backend/src/core/config.py, backend/src/db/models.py, backend/src/api/schemas.py, backend/.env.example, backend/alembic/versions/016_*.py

### TASK-04: Multi-Agent VA Orchestrator ✅ Completed
Create `backend/src/agents/` package.
Create `backend/src/agents/__init__.py` and `backend/src/agents/va_orchestrator.py`.
VAMultiAgentOrchestrator: CATEGORY_SKILL_MAP, _determine_categories(scan_mode), 
parallel discovery agents (semaphore=5), integration with ExploitabilityValidator and scoring.

**Files:** backend/src/agents/__init__.py, backend/src/agents/va_orchestrator.py

### TASK-05: Memory Compression for Long Scans ✅ Completed
Create `backend/src/agents/memory_compressor.py`.
ScanMemoryCompressor with compression prompt, threshold logic, cheapest LLM task.
Integration point with VAMultiAgentOrchestrator.

**Files:** backend/src/agents/memory_compressor.py

### TASK-06: Valhalla Report Enhancements + Skills Integration ✅ Completed
Update Valhalla report context with scan metadata:
  - scan_mode, agents_spawned, categories_tested, skills_used, noise_reduction %, coverage %
Add "Scope Confirmation" to Executive Summary.
Add "Validated By" column to findings table.
Integrate skills into VA-phase prompts (prompt_registry.py).

**Files:** backend/src/reports/valhalla_report_context.py, backend/src/orchestration/prompt_registry.py, backend/src/services/reporting.py, templates

### TASK-07: Pipeline Integration + Env Sync ✅ Completed
Wire all new modules into enrichment_pipeline.py.
Add new feature flags to config.py.
Sync env vars to infra/.env and infra/.env.example.
Alembic migration if needed.
Final integration testing.

**Files:** backend/src/intel/enrichment_pipeline.py, backend/src/core/config.py, backend/.env.example, infra/.env, infra/.env.example
