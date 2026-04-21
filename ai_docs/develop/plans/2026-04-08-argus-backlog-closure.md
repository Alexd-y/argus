# Plan: ARGUS Backlog Closure — Critical + Medium Fixes

**Created:** 2026-04-08
**Orchestration:** orch-2026-04-08-14-00-backlog-closure
**Status:** 🟢 Ready
**Goal:** Close critical and medium backlog items across VA pipeline, reports, scan lifecycle, LLM layer, infrastructure, and unused DB models
**Total Tasks:** 9
**Priority:** Critical

## Constraints (HARD)

- Do NOT change authentication or multi-tenancy code (`core/auth.py`, `core/tenant.py`)
- Do NOT change frontend (`Frontend/`, `admin-frontend/`)
- Max 10 tasks
- No stubs, TODO, `pass`-as-body, `return []` as stub

---

## Tasks Overview

### BKL-001: Vuln flags — add csrf/rce/idor override specs (CRITICAL)

**Priority:** Critical
**Dependencies:** None
**Estimated complexity:** Simple (~30 min)
**Files affected:**
- `backend/src/recon/vulnerability_analysis/active_scan/planner.py`

**Problem:**
`_VULN_OVERRIDE_SPECS` (line 460) currently has specs for `xss_enabled`, `sqli_enabled`, `ssrf_enabled`, `lfi_enabled` only. The scan options schema allows `csrf`, `rce`, `idor` flags, but they are silently ignored because:
1. No override specs exist for `csrf_enabled`, `rce_enabled`, `idor_enabled`
2. The loop at line 554 iterates `_VULN_OVERRIDE_SPECS.items()` — missing keys = no tools scheduled

**Implementation:**
1. Add `csrf_enabled` spec tuple to `_VULN_OVERRIDE_SPECS`:
   - `_ModeToolSpec("csrf_testing", "curl_cors", "deep", "curl_cors", "curl", custom_command="curl -s -I -H 'Origin: https://evil.com' {target}")` (reuse existing cors/csrf curl probe)
   - `_ModeToolSpec("csrf_testing", "nuclei", "deep", "nuclei_csrf", "nuclei", custom_command="nuclei -u {target} -tags csrf,token -silent")`
2. Add `rce_enabled` spec tuple:
   - `_ModeToolSpec("rce_testing", "commix", "deep", "commix", "commix")` (commix is already in `_OWASP2_TAIL`)
   - `_ModeToolSpec("rce_testing", "nuclei", "deep", "nuclei_rce", "nuclei", custom_command="nuclei -u {target} -tags rce,command-injection -silent")`
3. Add `idor_enabled` spec tuple:
   - `_ModeToolSpec("idor_testing", "nuclei", "deep", "nuclei_idor", "nuclei", custom_command="nuclei -u {target} -tags idor,broken-access -silent")`
   - `_ModeToolSpec("idor_testing", "ffuf", "deep", "ffuf_idor", "ffuf")` (fuzz param values for IDOR detection)

**Acceptance criteria:**
- `plan_tools_by_scan_mode("standard", {"vulnerabilities": {"csrf_enabled": True}}, url)` returns non-empty plan with csrf-targeted tools
- Same for rce_enabled, idor_enabled
- No regressions in existing xss/sqli/ssrf/lfi paths
- All `_ModeToolSpec` entries reference real tool binaries available in sandbox

---

### BKL-002: VA fallback outputs + task input for missing tasks (CRITICAL)

**Priority:** Critical
**Dependencies:** None
**Estimated complexity:** Moderate (~1.5h)
**Files affected:**
- `backend/src/recon/vulnerability_analysis/pipeline.py`

**Problem:**
1. `_build_va_fallback_output` (line 246) returns `{}` at the end (line 746) for any task not explicitly handled — this means tasks like `web_scan_planning`, `generic_web_finding` get empty fallback. This causes downstream consumers to fail or produce empty sections.
2. `_build_va_task_input` (line 749) returns only `{"meta": meta.model_dump()}` (line 815) for tasks not listed in the explicit branches — missing the `bundle` that tasks need for meaningful processing.

**Implementation:**
1. In `_build_va_fallback_output`:
   - Add `web_scan_planning` fallback: return `{"plans": [{"target_url": <first entry_point or "unknown">, "rationale": "Fallback: web scan planning from bundle entry points", "priority": "medium"}]}`
   - Add `generic_web_finding` fallback: return `{"findings": [{"description": "Fallback: no generic web findings extracted from bundle", "confidence": 0.3, "severity": "info"}]}`
   - Replace final `return {}` with a structured default: `return {"status": "fallback", "task": task_name, "message": "No specific fallback handler for this task", "data": {}}` — so callers can distinguish "empty result" from "no handler"
2. In `_build_va_task_input`:
   - Add `web_scan_planning` and `generic_web_finding` to the main branch at line 761 that returns `{"meta": ..., "bundle": ...}`
   - Log a warning for the final fallback path (line 815) to flag any future tasks falling through without bundle

**Acceptance criteria:**
- `_build_va_fallback_output("web_scan_planning", bundle, {})` returns non-empty dict with `plans` key
- `_build_va_fallback_output("generic_web_finding", bundle, {})` returns non-empty dict with `findings` key
- `_build_va_fallback_output("unknown_future_task", bundle, {})` returns dict with `status: "fallback"`, not `{}`
- `_build_va_task_input("web_scan_planning", ...)` includes full `bundle` in output
- No regressions for existing 15+ task handlers

---

### BKL-003: Report templates — cost_summary partial + executive dedup + English + stubs (CRITICAL)

**Priority:** Critical
**Dependencies:** None
**Estimated complexity:** Complex (~2h)
**Files affected:**
- `backend/src/reports/templates/reports/partials/valhalla/sections_01_02_title_executive.html.j2`
- `backend/src/reports/templates/reports/partials/valhalla/sections_10_12_remediation_conclusion.html.j2`
- `backend/src/reports/templates/reports/partials/valhalla/sections_03_05_objectives_methodology.html.j2`
- `backend/src/reports/templates/reports/partials/valhalla/sections_07_08_threat_findings.html.j2`
- `backend/src/reports/templates/reports/partials/valhalla/section_06_results_overview.html.j2`
- `backend/src/reports/templates/reports/partials/valhalla/section_09_exploit_chains.html.j2`
- `backend/src/reports/templates/reports/partials/valhalla/appendices.html.j2`
- `backend/src/reports/templates/reports/partials/valhalla/findings_table.html.j2`
- `backend/src/reports/templates/reports/partials/active_web_scan.html.j2` (if Russian text present)

**Sub-problems:**

**3a. cost_summary section missing:**
- `LLMTask.COST_SUMMARY` exists in `llm/task_router.py` (line 29)
- AI text is presumably generated via `ai_text_generation.py`
- But NO Valhalla partial template reads `ai_sections.get("cost_summary")`
- **Fix:** Add a `cost_summary` block in `sections_10_12_remediation_conclusion.html.j2` between "Zero-day потенциал" and "Заключение", displaying `ai_sections.get("cost_summary")` with a header "LLM Cost Summary" and fallback

**3b. executive_summary_valhalla duplication:**
- Same AI key `executive_summary_valhalla` is rendered in:
  - `sections_01_02` line 17 — Executive Summary section
  - `sections_10_12` line 54 — Conclusion → "Итоговая оценка (ИИ)"
- **Fix:** In `sections_10_12` line 54, replace `executive_summary_valhalla` with a dedicated conclusion key. Options:
  - Use `ai_sections.get("conclusion_assessment")` if a separate AI section exists, or
  - Generate a distinct short summary from the conclusion prompt, or
  - Remove duplication by referencing "see Executive Summary above" with an anchor link

**3c. Russian text → English:**
Audit ALL Valhalla templates. Replace Russian strings while preserving the Jinja2 structure. Key translations:
- "Нет данных" → "No data available"
- "Не найдено" → "Not found"
- "Плейсхолдер" → remove, replace with actual content or proper "N/A"
- "при отдельном согласовании" → "Available upon separate agreement based on detection data"
- Titles: "Резюме для руководства" → "Executive Summary", "Рекомендации и приоритизация" → "Recommendations and Prioritization", etc.
- Use the `i18n.py` module from `reports/i18n.py` if available for template string management

**3d. APT appendix D placeholder:**
- Line 50 of `appendices.html.j2`: static placeholder text
- **Fix:** Make it data-driven: check if `vc.apt_indicators` or similar context exists. If yes, render. If no, show "No APT indicators detected during this assessment."

**3e. "Ответственные и сроки" table stub:**
- Lines 21-35 of `sections_10_12`: hardcoded single placeholder row
- **Fix:** Generate rows from findings data. For each Critical/High finding: show finding title, "Security Team" as default responsible, and SLA-based deadline (Critical: 24h, High: 7 days, Medium: 30 days). Fall back to "No findings require tracking" if empty.

**Acceptance criteria:**
- `cost_summary` AI section renders in Valhalla report when present
- `executive_summary_valhalla` appears in sections 1-2 ONLY; conclusion uses different key or anchor
- Zero Russian strings remain in any Valhalla `.html.j2` template
- APT appendix shows real data when available, clean "N/A" when not
- Remediation table auto-populates from findings by severity

---

### BKL-004: Scan lifecycle — cancel_scan Celery revoke + exploitation error handling (CRITICAL)

**Priority:** Critical
**Dependencies:** None
**Estimated complexity:** Moderate (~1h)
**Files affected:**
- `backend/src/api/routers/scans.py`
- `backend/src/tasks/__init__.py` (or wherever celery_app is defined)

**Problem 4a: cancel_scan doesn't revoke Celery task**
- `cancel_scan` (line 321) updates DB to `status="cancelled"` but the Celery worker continues executing the scan phase task
- The scan consumes resources (tool sandboxes, LLM calls) until natural completion

**Implementation 4a:**
1. Read `scan.celery_task_id` from DB (if stored) or derive from scan_id
2. Import `celery_app` and call `celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")`
3. If `celery_task_id` is not stored in DB, add a `celery_task_id` column to `Scan` model and populate it when `scan_phase_task.delay()` is called — then use that for revocation
4. Wrap revoke in try/except to handle cases where worker is unreachable (log warning, still mark cancelled in DB)

**Problem 4b: Exploitation endpoint silent failure**
- Celery `send_task` can fail silently — need to verify the exploitation endpoint returns appropriate errors
- If `send_task` raises, the 202 should become 500 or 503

**Implementation 4b:**
1. Locate the exploitation trigger endpoint (likely in `scans.py` or a separate router)
2. Wrap `celery_app.send_task(...)` in try/except
3. On failure: return HTTP 503 with `{"detail": "Task submission failed", "retry_after": 30}`
4. Log the failure with structured context (scan_id, error type)

**Acceptance criteria:**
- POST `/{scan_id}/cancel` both marks DB cancelled AND revokes running Celery task
- If Celery is unreachable, cancel still succeeds (DB update) with warning in logs
- Exploitation task submission failure returns 503 instead of silent 202
- No breaking changes to existing cancel/exploitation API contracts

---

### BKL-005: Infrastructure — nginx config + alembic verification (MEDIUM)

**Priority:** Medium
**Dependencies:** None
**Estimated complexity:** Simple (~30 min)
**Files affected:**
- `infra/nginx/conf.d/api.conf` (rename to `default.conf` or add `default.conf`)
- `infra/docker-compose.yml` (verify)
- `backend/` alembic config (verify)

**Current state:**
- `infra/nginx/conf.d/api.conf` exists and has `listen 80 default_server` — technically functional
- `docker-compose.yml` (line 278) mounts `./nginx/conf.d:/etc/nginx/conf.d:ro` — will include `api.conf` automatically
- Alembic was NOT found referenced anywhere in the codebase — no `alembic.ini`, no `migrations/` folder, no `alembic upgrade head` in `main.py`

**Implementation:**
1. **nginx**: Rename `api.conf` → `default.conf` (nginx convention). Docker-compose mount stays the same. Verify health check passes.
2. **alembic**: Since no alembic config exists, create minimal setup:
   - `backend/alembic.ini` pointing to `migrations/`
   - `backend/migrations/env.py` with async SQLAlchemy engine from `db.session`
   - `backend/migrations/versions/` (empty — initial migration will be generated when needed)
   - Import `Base.metadata` from `db.models` for autogenerate support
   - Add alembic to `requirements.txt` / `pyproject.toml` if not present
   - **NOTE:** Do NOT add `alembic upgrade head` to main.py lifespan unless the user explicitly requests it — currently the app uses `Base.metadata.create_all()` or similar

**Acceptance criteria:**
- `docker-compose up nginx` starts successfully with the renamed config
- `alembic check` runs without config errors
- `alembic revision --autogenerate -m "initial"` can generate migration from existing models
- No changes to existing startup behavior

---

### BKL-006: LLM unification — single facade through task_router (MEDIUM)

**Priority:** Medium
**Dependencies:** None
**Estimated complexity:** Complex (~2h)
**Files affected:**
- `backend/src/llm/router.py`
- `backend/src/llm/task_router.py`
- `backend/src/core/llm_config.py`
- `backend/src/llm/__init__.py`
- All callers of the old paths (orchestration, intelligence, agents, reports, VA)

**Current state — three parallel strategies:**

| Path | Type | Used by |
|------|------|---------|
| `llm/router.call_llm` | async, fallback chain | orchestration, intelligence |
| `llm/task_router.call_llm_for_task` | async, task-based routing | agents/va_orchestrator |
| `core/llm_config.get_llm_client` | sync, OpenAI-only | reports, VA pipeline |

**Implementation:**
1. **Designate `task_router.call_llm_for_task` as the canonical entry point.** It already has:
   - Task-based routing with per-task model/temperature
   - Fallback chain across providers
   - Cost tracking hooks
   - Structured response with token counts

2. **Create unified facade in `llm/__init__.py`:**
   ```python
   # Async entry point (preferred)
   async def call_llm(prompt, *, task=LLMTask.ORCHESTRATION, system_prompt=None):
       return await call_llm_for_task(task, prompt, system_prompt=system_prompt)
   
   # Sync wrapper for contexts that can't await (Celery tasks, reports)
   def call_llm_sync(prompt, context=None, *, task=LLMTask.REPORT_SECTION):
       import asyncio
       loop = asyncio.new_event_loop()
       try:
           resp = loop.run_until_complete(call_llm_for_task(task, prompt))
           return resp.text
       finally:
           loop.close()
   ```

3. **Convert `llm/router.py:call_llm` to thin wrapper:**
   - Delegate to `call_llm_for_task(LLMTask.ORCHESTRATION, prompt, system_prompt=system_prompt)`
   - Keep function signature for backward compatibility
   - Add deprecation warning in docstring

4. **Convert `core/llm_config.py:get_llm_client` to thin wrapper:**
   - Return `call_llm_sync` with `LLMTask.REPORT_SECTION` default
   - Keep `Callable[[str, dict], str]` signature for backward compatibility
   - Add deprecation warning in docstring

5. **Update direct callers** (search for `from src.llm.router import`, `from src.core.llm_config import`):
   - Prefer importing from `src.llm` directly
   - Map each call site to the appropriate `LLMTask` enum value

**Acceptance criteria:**
- All LLM calls route through `task_router.call_llm_for_task` under the hood
- `call_llm_sync` works from Celery worker context (sync)
- `llm/router.call_llm` still works (backward compat) but delegates to task_router
- `core/llm_config.get_llm_client` still works (backward compat) but delegates to task_router
- Cost tracking applies to ALL LLM calls, not just task_router direct callers
- No import cycles introduced

---

### BKL-007: Code stubs — use_cache wiring + tier_stubs cleanup (MEDIUM)

**Priority:** Medium
**Dependencies:** BKL-006 (LLM unification needed if tier_stubs touch LLM)
**Estimated complexity:** Moderate (~1.5h)
**Files affected:**
- `backend/src/tools/executor.py`
- `backend/src/cache/tool_cache.py`
- `backend/src/services/reporting.py`

**Problem 7a: `use_cache` parameter is a no-op**
- `execute_command` (line 26) accepts `use_cache: bool = True` but line 46 does `_ = use_cache`
- `cache/tool_cache.py` has a full `ToolResultCache` implementation with per-tool TTL, Redis-backed cache, scan-scoped keys

**Implementation 7a:**
1. Import `tool_cache` functions into `executor.py`
2. Before running subprocess: check cache with `tool_cache.get_cached_result(command, scan_id=...)`
3. If hit and `use_cache=True`: return cached result, add `"cached": True` to response dict
4. After successful execution: store result with `tool_cache.set_cached_result(command, result, scan_id=...)`
5. Respect `use_cache=False` by skipping cache entirely
6. Handle Redis unavailability gracefully (tool_cache already handles this)

**Problem 7b: `tier_stubs` in reporting.py**
- Line 1505: `tier_stubs` is a static dict with hardcoded Midgard/Asgard/Valhalla metadata
- It's passed to Jinja context but no template uses it for conditional rendering

**Implementation 7b:**
1. Check if any template reads `tier_stubs` — if yes, keep the data but rename to `tier_metadata`
2. If no template uses it: remove from context, clean up dead code
3. If templates DO use it for conditional sections: verify the data is correct and remove "stubs" naming

**Acceptance criteria:**
- `execute_command("nmap -sV target", use_cache=True)` returns cached result on second call within TTL
- `execute_command("nmap -sV target", use_cache=False)` always runs the command
- `tier_stubs` is either fully implemented or removed — no intermediate state
- No changes to the executor's external API signature

---

### BKL-008: DB models activation — ScanStep, FindingNote, Evidence (MEDIUM)

**Priority:** Medium
**Dependencies:** BKL-004 (scan lifecycle changes needed for ScanStep)
**Estimated complexity:** Complex (~2h)
**Files affected:**
- `backend/src/db/models.py` (already defined, verify complete)
- `backend/src/tasks/` (scan phase task — write ScanStep records)
- `backend/src/api/routers/scans.py` (expose ScanStep/Evidence API)
- `backend/src/api/routers/findings.py` (expose FindingNote CRUD)
- `backend/src/api/schemas.py` (add response schemas)
- `backend/src/recon/` (Evidence storage during scan phases)

**Models to activate (already in `db/models.py`):**

| Model | Table | Purpose | Wire into |
|-------|-------|---------|-----------|
| `ScanStep` | `scan_steps` | Phase tracking sub-steps | Scan phase task: create/update steps per phase |
| `FindingNote` | (check) | Analyst comments on findings | CRUD API on findings router |
| `Evidence` | `evidence` | PoC files in MinIO | Store during exploitation/VA; link to findings |
| `ReportObject` | (check) | Report artifacts in MinIO | Report pipeline: store generated PDF/HTML refs |
| `Screenshot` | `screenshots` | Screenshot metadata | VA active scan / exploitation phases |

**Implementation:**
1. **ScanStep**: In scan phase task, create a `ScanStep` record at phase start (`status="running"`) and update at phase end (`status="completed"` or `"failed"`). Expose `GET /scans/{id}/steps` endpoint returning ordered steps.

2. **FindingNote**: Add CRUD endpoints:
   - `POST /findings/{finding_id}/notes` — create note (body: `{text: str}`)
   - `GET /findings/{finding_id}/notes` — list notes
   - `DELETE /findings/{finding_id}/notes/{note_id}` — delete note
   Tenant-scoped, uses same auth pattern as existing finding endpoints.

3. **Evidence**: When exploitation phase or VA active scan produces PoC output:
   - Upload to MinIO via existing `storage/s3.py`
   - Create `Evidence` record linked to finding_id + scan_id
   - Expose `GET /findings/{finding_id}/evidence` endpoint

4. **ReportObject**: In report pipeline, after rendering PDF/HTML:
   - Create `ReportObject` record with MinIO key, format, size
   - Already partially done in `reports/storage.py` — wire the model

5. **Screenshot**: During VA active scan or exploitation when screenshot tools run:
   - Store screenshot in MinIO
   - Create `Screenshot` record linked to scan_id + optional finding_id

**Acceptance criteria:**
- `GET /scans/{id}/steps` returns ordered list of phase sub-steps with status/timestamps
- `POST /findings/{id}/notes` creates and returns note; `GET` lists them
- Evidence records are created during exploitation phase
- ReportObject records are created when reports are generated
- All new endpoints are tenant-scoped and follow existing auth pattern
- No orphaned records (cascade deletes via FK constraints already in models)

---

### BKL-009: Integration tests for all changes (HIGH)

**Priority:** High
**Dependencies:** All of BKL-001 through BKL-008
**Estimated complexity:** Complex (~2h)
**Files affected:**
- `backend/tests/test_vuln_flags.py` (new)
- `backend/tests/test_va_fallback.py` (new)
- `backend/tests/test_report_templates.py` (new or extend)
- `backend/tests/test_scan_lifecycle.py` (new or extend)
- `backend/tests/test_llm_unification.py` (new)
- `backend/tests/test_executor_cache.py` (new)
- `backend/tests/test_db_models_activation.py` (new)

**Test plan:**

1. **BKL-001 tests:**
   - `test_csrf_override_specs_exist` — verify `_VULN_OVERRIDE_SPECS["csrf_enabled"]` is non-empty
   - `test_plan_tools_with_csrf_flag` — call `plan_tools_by_scan_mode` with csrf_enabled=True, assert tools scheduled
   - Same pattern for rce_enabled, idor_enabled
   - `test_existing_flags_unchanged` — regression test for xss/sqli/ssrf/lfi

2. **BKL-002 tests:**
   - `test_fallback_web_scan_planning` — verify non-empty fallback output
   - `test_fallback_generic_web_finding` — verify non-empty fallback output
   - `test_fallback_unknown_task_returns_status` — verify structured fallback instead of `{}`
   - `test_task_input_web_scan_planning_has_bundle` — verify bundle included

3. **BKL-003 tests:**
   - `test_no_russian_in_valhalla_templates` — scan all `.html.j2` files for Cyrillic characters
   - `test_executive_summary_not_duplicated` — verify `executive_summary_valhalla` appears in exactly one template
   - `test_cost_summary_partial_exists` — verify template reads `cost_summary` AI section
   - `test_remediation_table_data_driven` — render template with findings, verify table rows

4. **BKL-004 tests:**
   - `test_cancel_scan_revokes_celery_task` — mock celery_app.control.revoke, verify called
   - `test_cancel_scan_succeeds_when_celery_unreachable` — verify DB still updated
   - `test_exploitation_send_task_failure_returns_503` — mock send_task to raise, verify 503

5. **BKL-005 tests:**
   - `test_nginx_config_valid` — run `nginx -t -c ...` in docker or validate syntax
   - `test_alembic_config_loads` — verify alembic.ini is parseable

6. **BKL-006 tests:**
   - `test_call_llm_sync_returns_string` — verify sync wrapper works
   - `test_router_call_llm_delegates_to_task_router` — mock task_router, verify delegation
   - `test_get_llm_client_delegates_to_task_router` — mock task_router, verify delegation

7. **BKL-007 tests:**
   - `test_execute_command_caches_result` — verify second call returns cached
   - `test_execute_command_use_cache_false_skips` — verify cache bypass
   - `test_tier_stubs_resolved` — verify no dead code in reporting context

8. **BKL-008 tests:**
   - `test_scan_steps_created_during_phase` — verify ScanStep records
   - `test_finding_notes_crud` — full CRUD cycle
   - `test_evidence_linked_to_finding` — verify FK integrity

**Acceptance criteria:**
- All new tests pass
- No regressions in existing test suite
- Test coverage for each BKL task includes happy path + edge cases
- Mocks used appropriately (no real LLM calls, no real Celery in unit tests)

---

## Dependencies Graph

```
BKL-001 ──────┐
BKL-002 ──────┤
BKL-003 ──────┤
BKL-004 ──┬───┤
           │   ├──→ BKL-009 (tests)
BKL-005 ──┤   │
BKL-006 ──┼───┤
           │   │
BKL-007 ←─┘   │
BKL-008 ←─────┘
```

**Parallel execution groups:**
- **Group 1 (parallel):** BKL-001, BKL-002, BKL-003, BKL-005 — no interdependencies
- **Group 2 (parallel after G1):** BKL-004, BKL-006
- **Group 3 (after G2):** BKL-007 (needs BKL-006), BKL-008 (needs BKL-004)
- **Group 4 (last):** BKL-009 (needs all)

## Progress (updated by orchestrator)

- ⏳ BKL-001: Vuln flags csrf/rce/idor (Pending)
- ⏳ BKL-002: VA fallback stubs (Pending)
- ⏳ BKL-003: Report templates (Pending)
- ⏳ BKL-004: Scan lifecycle (Pending)
- ⏳ BKL-005: Infrastructure (Pending)
- ⏳ BKL-006: LLM unification (Pending)
- ⏳ BKL-007: Code stubs (Pending)
- ⏳ BKL-008: DB models activation (Pending)
- ⏳ BKL-009: Integration tests (Pending)

## Architecture Decisions

1. **LLM facade pattern over wholesale replacement:** Keep backward-compatible wrappers in `llm/router.py` and `core/llm_config.py` to avoid mass-refactoring all callers in one commit. Callers can migrate to direct `task_router` imports incrementally.

2. **Sync LLM wrapper via `asyncio.new_event_loop()`:** Celery workers don't have a running event loop, so `asyncio.run()` or `new_event_loop().run_until_complete()` is the safest approach. `run_in_executor` is not applicable here because the target is async code that needs an event loop.

3. **ScanStep granularity:** One ScanStep per scan phase (recon, threat_modeling, vuln_analysis, exploitation, post_exploitation, reporting). Not per-tool — that would create too many records. Tool-level tracking stays in ScanEvent.

4. **Template English migration:** One-pass find-and-replace with human review. Not using i18n/gettext for now — the entire report is English-only per requirement. If future i18n is needed, templates are already structured for it.

5. **nginx config naming:** Rename to `default.conf` for clarity, though `api.conf` with `default_server` is technically valid. Convention matters for maintainability.

6. **Cache integration in executor:** Opt-in by default (`use_cache=True`). Tool-specific TTLs already defined in `tool_cache.py`. Cache miss = normal execution + store. Redis down = normal execution (no-op cache).

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Celery revoke doesn't terminate long-running tool in sandbox | Scan resources wasted | Add SIGTERM handler in sandbox runner; timeout as backstop |
| LLM sync wrapper deadlocks in certain contexts | Report generation hangs | Use `asyncio.new_event_loop()` (dedicated loop); add timeout |
| Template English migration misses dynamic content | Mixed language in reports | Grep for Cyrillic in all templates + rendered output validation |
| DB model activation without alembic migration | Tables may not exist | Verify tables via `Base.metadata.create_all()` or add migration |
| Cache returning stale results after target changes | False scan results | Cache key includes scan_id (already in tool_cache.py design) |
