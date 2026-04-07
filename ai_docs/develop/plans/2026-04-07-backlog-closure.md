# Plan: ARGUS Backlog Closure — Wiring Bug Fixes

**Created:** 2026-04-07
**Orchestration:** orch-2026-04-07-backlog-closure
**Status:** 🟢 Ready
**Goal:** Fix 8 concrete wiring bugs that break deep scanning and reports after 5 orchestration cycles
**Total Tasks:** 9
**Priority:** Critical
**Estimated Time:** 4–6 hours

---

## Context

After 5 orchestration cycles the ARGUS backend has wiring bugs in already-written code. No new features — only bug fixes. Three critical bugs break the entire deep scan + report pipeline; five additional issues affect tool execution, i18n, caching, and repo hygiene.

**Constraints:**
- No stubs, `pass`, `return []`, or `TODO`
- Reports in English ONLY
- Do NOT change frontend
- Do NOT break existing API contracts
- After each block: `ruff check .` + `pytest tests/ -x --tb=short -q`

---

## Tasks

- [x] FIX-001: Wire scan_mode/scan_options to run_va_active_scan_phase in handlers.py (✅ Completed)
- [x] FIX-002: Wire scan_mode/scan_options through pipeline.py (✅ Completed)
- [x] FIX-003: Add _VULN_FLAG_MAP for API→planner flag mapping (✅ Completed)
- [x] FIX-004: Add AITextDeduplicator in Celery path (✅ Completed)
- [x] FIX-005: Fix shell pipes in tool_configs.json (✅ Completed)
- [x] FIX-006: Strip i18n to English-only (✅ Completed)
- [x] FIX-007: Verify/fix cache invalidation on re-scan (✅ Completed)
- [x] FIX-008: Cleanup uncommitted files — .gitignore update (✅ Completed)
- [x] FIX-009: Write tests for all fixes (✅ Completed)

## Dependencies

```
FIX-001 ──┐
           ├──→ FIX-009
FIX-002 ──┤
FIX-003 ──┤
FIX-004 ──┤
FIX-005 ──┘

FIX-006, FIX-007, FIX-008 — independent, parallelizable
```

---

## Task Details

### FIX-001: Wire scan_mode/scan_options to run_va_active_scan_phase in handlers.py
**Priority:** 🔴 Critical | **Complexity:** Simple | **Est:** 30 min

**Bug:** `backend/src/orchestration/handlers.py` line ~1010: `run_va_active_scan_phase()` is called WITHOUT `scan_mode` and `scan_options` — deep scan mode never activates from the API handler path.

**Current code (broken):**
```python
result_bundle = await run_va_active_scan_phase(
    bundle,
    tenant_id_raw=tenant_id,
    scan_id_raw=scan_id or "",
    va_raw_log=lambda msg: logger.info(...),
    password_audit_opt_in=bool(kal_flags["password_audit_opt_in"]),
    va_network_capture_opt_in=bool(kal_flags["va_network_capture_opt_in"]),
)
```

**Fix:**
1. Extract `scan_mode` from `scan_options` (the `scan_options` dict is already a parameter of `run_vuln_analysis` at line ~947):
   ```python
   effective_scan_mode = (scan_options or {}).get("scan_mode") or "standard"
   ```
2. Pass both to `run_va_active_scan_phase`:
   ```python
   result_bundle = await run_va_active_scan_phase(
       bundle,
       tenant_id_raw=tenant_id,
       scan_id_raw=scan_id or "",
       va_raw_log=lambda msg: logger.info(...),
       password_audit_opt_in=bool(kal_flags["password_audit_opt_in"]),
       va_network_capture_opt_in=bool(kal_flags["va_network_capture_opt_in"]),
       scan_mode=effective_scan_mode,
       scan_options=scan_options,
   )
   ```

**Files:**
- `backend/src/orchestration/handlers.py` (~line 1010)

**Acceptance criteria:**
- `scan_mode=` and `scan_options=` appear as kwargs in the `run_va_active_scan_phase()` call in handlers.py
- `ruff check backend/src/orchestration/handlers.py` passes

---

### FIX-002: Wire scan_mode/scan_options through pipeline.py
**Priority:** 🔴 Critical | **Complexity:** Moderate | **Est:** 45 min
**Depends on:** FIX-001

**Bug:** `backend/src/recon/vulnerability_analysis/pipeline.py` line ~1139: `run_va_active_scan_phase()` is called without `scan_mode`/`scan_options`. Also, `execute_vulnerability_analysis_run()` (line ~972) doesn't accept these parameters at all, so callers cannot pass them.

**Fix:**
1. Add `scan_mode: str | None = None` and `scan_options: dict[str, Any] | None = None` as keyword params to `execute_vulnerability_analysis_run()` function signature (line ~972).
2. Pass them through to `run_va_active_scan_phase()` at line ~1139:
   ```python
   bundle = await run_va_active_scan_phase(
       bundle,
       tenant_id_raw=tenant_id_raw,
       scan_id_raw=scan_id_raw,
       va_raw_log=_va_raw_log,
       scan_mode=scan_mode,
       scan_options=scan_options,
   )
   ```
3. Find ALL callers of `execute_vulnerability_analysis_run` across the codebase and update them to pass `scan_mode`/`scan_options` if available. Key callers to check:
   - `backend/src/recon/jobs/runner.py`
   - `backend/src/recon/cli/commands/vulnerability_analysis.py`
   - Any Celery task wrappers

**Files:**
- `backend/src/recon/vulnerability_analysis/pipeline.py` (signature + call site)
- All callers of `execute_vulnerability_analysis_run` (grep to find)

**Acceptance criteria:**
- `execute_vulnerability_analysis_run` signature includes `scan_mode` and `scan_options`
- `run_va_active_scan_phase` call inside pipeline passes both through
- All callers updated (new optional kwargs, backward compatible)
- `ruff check .` passes

---

### FIX-003: Add _VULN_FLAG_MAP to va_active_scan_phase.py
**Priority:** 🔴 Critical | **Complexity:** Simple | **Est:** 30 min

**Bug:** `backend/src/recon/vulnerability_analysis/active_scan/va_active_scan_phase.py`: The planner (`plan_tools_by_scan_mode`) expects vulnerability flags named `xss_enabled`, `sqli_enabled`, `ssrf_enabled`, `lfi_enabled` — but the API sends shorter names like `xss`, `sqli`, `ssrf`, `lfi`. Result: vulnerability overrides are silently ignored.

**Current code (line ~1040):**
```python
vuln_opts = (scan_options or {}).get("vulnerabilities") or {}
has_vuln_overrides = any(vuln_opts.get(k) for k in ("xss_enabled", "sqli_enabled", ...))
```

**Fix:**
1. Add mapping constant at module level:
   ```python
   _VULN_FLAG_MAP: dict[str, str] = {
       "xss": "xss_enabled",
       "sqli": "sqli_enabled",
       "ssrf": "ssrf_enabled",
       "lfi": "lfi_enabled",
       "rce": "rce_enabled",
       "idor": "idor_enabled",
   }
   ```
2. Add a helper function `_map_vuln_flags(raw: dict) -> dict` that copies `raw`, then for each `(api_key, planner_key)` in `_VULN_FLAG_MAP`: if `api_key` is in `raw` and `planner_key` is NOT in `raw`, copy the value over.
3. Apply the mapping in BOTH places where `plan_tools_by_scan_mode` is called (line ~1026 and ~1049):
   ```python
   mapped_scan_options = dict(scan_options or {})
   mapped_vuln = _map_vuln_flags((mapped_scan_options.get("vulnerabilities") or {}))
   mapped_scan_options["vulnerabilities"] = mapped_vuln
   mode_steps = plan_tools_by_scan_mode(
       effective_scan_mode,
       scan_options=mapped_scan_options,
       target_url=_mode_target,
   )
   ```

**Files:**
- `backend/src/recon/vulnerability_analysis/active_scan/va_active_scan_phase.py`

**Acceptance criteria:**
- `_VULN_FLAG_MAP` dict exists
- `_map_vuln_flags` function exists and is called before both `plan_tools_by_scan_mode` calls
- API flag `xss=True` → planner sees `xss_enabled=True`
- `ruff check .` passes

---

### FIX-004: Add AITextDeduplicator in Celery path
**Priority:** 🔴 Critical | **Complexity:** Moderate | **Est:** 45 min

**Bug:** `backend/src/services/reporting.py`: `AITextDeduplicator` is called in the sync path (`run_ai_sections_sync`, line ~1302) but NOT in the Celery path. When Celery is used, `schedule_ai_sections_celery()` returns task IDs, then `ai_results_to_text_map()` is called on `ai_results` at line ~1499 — but at that point `ai_results` is an empty dict `{}` because Celery hasn't finished yet. The dedup never runs.

**Root cause analysis:**
- Line 1487: `sync_ai` path → `ai_results` populated → dedup applied ✅
- Line 1497: Celery path → `celery_ids` set, `ai_results` stays `{}` → `texts` empty → no dedup ❌
- Celery results are collected later (the caller retrieves them by task ID). The dedup must happen wherever Celery results are collected and assembled into the final report context.

**Fix:**
1. Find where Celery results are collected into `ai_results` / `texts` (likely in `report_pipeline.py` or wherever `ReportContextBuildResult.celery_task_ids` are resolved).
2. At that resolution point, after converting Celery results to text map, apply:
   ```python
   from src.reports.ai_text_generation import AITextDeduplicator
   if len(texts) > 1:
       deduplicator = AITextDeduplicator()
       texts = deduplicator.deduplicate_sections(texts)
   ```
3. If `AITextDeduplicator` doesn't exist yet in `ai_text_generation.py`, it must be implemented (check if it already exists).
4. Also add dedup in `reporting.py` right after the Celery branch to handle the case where `ai_results` gets populated later within the same method — defensive dedup after line 1499.

**Files:**
- `backend/src/services/reporting.py` (primary)
- `backend/src/reports/report_pipeline.py` (Celery result collection point)
- `backend/src/reports/ai_text_generation.py` (verify AITextDeduplicator exists)

**Acceptance criteria:**
- Both sync and Celery paths apply AITextDeduplicator before rendering
- grep confirms `AITextDeduplicator` / `deduplicate_sections` appears in Celery collection code
- `ruff check .` passes

---

### FIX-005: Fix shell pipes in tool_configs.json
**Priority:** 🟡 Medium | **Complexity:** Simple | **Est:** 20 min

**Bug:** `backend/data/tool_configs.json` contains 3 entries with shell operators (`|`, `&&`) that won't work with `shell=False` in subprocess:
1. **kxss** (line 266): `"echo {target} | kxss"` — already has `"requires_shell": true` ✅ OK
2. **curl_race** (line 805): `"seq 1 10 | xargs -P 10 ..."` — already has `"requires_shell": true` ✅ OK
3. **cloudsplaining** (line 781): `"cloudsplaining download && cloudsplaining scan ..."` — NO `requires_shell` flag ❌

**Fix:**
1. Add `"requires_shell": true` to the `cloudsplaining` entry in `tool_configs.json`.
2. Verify the sandbox tool runner respects `requires_shell` flag — if it does, this is sufficient. If not, wrap the command in `sh -c "..."`.
3. Scan for any other entries with shell metacharacters that lack the flag.

**Files:**
- `backend/data/tool_configs.json` (cloudsplaining entry)
- `backend/src/recon/sandbox_tool_runner.py` (verify `requires_shell` handling)

**Acceptance criteria:**
- All commands with `|`, `&&`, `;` have `"requires_shell": true`
- No shell metacharacters in commands without the flag
- `ruff check .` passes (N/A for JSON, but runner may change)

---

### FIX-006: Strip i18n to English-only
**Priority:** 🟡 Medium | **Complexity:** Moderate | **Est:** 45 min

**Bug:** Reports should be English-only. Currently:
1. `backend/src/reports/i18n.py` has `"ru"` translations block
2. `backend/src/orchestration/prompt_registry.py` has `report_language` placeholder in 12+ prompts, defaulting to `"en"` but allowing language switching
3. Templates may have language-conditional blocks

**Fix:**
1. **`i18n.py`**: Remove the entire `"ru": {...}` block from `TRANSLATIONS`. Remove `SUPPORTED_LANGUAGES` or set to `frozenset({"en"})`. Simplify `get_translations()` to always return EN. Simplify `t()` accordingly.
2. **`prompt_registry.py`**: Replace all `{report_language}` template references with hardcoded `"en"` or "English". Remove `"report_language": "en"` from the defaults dict (or keep as constant `"en"`). Update every `REPORT_AI_USER_TEMPLATES` entry to say "LANGUAGE: Write in English." instead of referencing a variable.
3. **Templates**: Search all `.j2` files for `language` conditionals. Remove any `{% if language == "ru" %}` blocks (grep found zero — but verify).
4. Keep backward compatibility: `get_translations("ru")` should fall back to EN (already does after removing `"ru"` key).

**Files:**
- `backend/src/reports/i18n.py`
- `backend/src/orchestration/prompt_registry.py`
- `backend/src/reports/templates/**/*.j2` (verify, likely no changes needed)

**Acceptance criteria:**
- `grep -rn "ru" backend/src/reports/i18n.py` → no Russian translations
- `grep -rn "report_language" backend/src/orchestration/prompt_registry.py` → either removed or always "en"
- No language-conditional template blocks
- `ruff check .` passes

---

### FIX-007: Verify/fix cache invalidation on re-scan
**Priority:** 🟡 Medium | **Complexity:** Simple | **Est:** 20 min

**Bug:** When re-scanning the same target, cached AI text / tool results may be stale.

**Current state (after analysis):**
- `backend/src/cache/tool_cache.py` line 83: Cache key is SHA-256 of `(command, use_sandbox, timeout_sec)` — **scan_id is NOT part of the key**.
- However, `invalidate_scan_cache(scan_id)` exists (line 163) and deletes keys matching `argus:*:{scan_id}:*`. This pattern won't match the `argus:sandbox:exec:{hash}` keys since they don't contain scan_id.
- `invalidate_target_cache(target)` also exists (line 200).

**Fix options:**
1. **Option A (recommended):** The cache key doesn't include scan_id, meaning two scans with the same command get the same cached result. For re-scans this is correct behavior (idempotent tool runs). But if the user WANTS fresh results on re-scan, either:
   - Include `scan_id` in cache key (breaks sharing), OR
   - Call `invalidate_target_cache(target)` at the start of each scan
2. **Option B:** Add a per-target version counter in Redis (`argus:cache_version:{target_hash}`) and include it in the cache key. Bump on re-scan.

**Decision needed:** Analyze whether `invalidate_scan_cache` or `invalidate_target_cache` is already called at scan start. If yes → cache invalidation works. If not → add the call.

**Files:**
- `backend/src/cache/tool_cache.py` (verify / minor fix)
- `backend/src/orchestration/handlers.py` or `backend/src/recon/jobs/runner.py` (add invalidation call at scan start if missing)

**Acceptance criteria:**
- Re-scan of same target gets fresh tool results (not stale cache)
- Documented decision on approach chosen

---

### FIX-008: Cleanup uncommitted files — .gitignore update
**Priority:** 🟢 Low | **Complexity:** Simple | **Est:** 10 min

**Bug:** Cursor prompt files (`*_cursor_prompt*.md`, `argus_backlog_closure_cursor_prompt.md`) are untracked and cluttering the repo root.

**Fix:**
1. Add to `ARGUS/.gitignore`:
   ```
   # AI/Cursor prompt files (not part of codebase)
   *_cursor_prompt*.md
   argus_backlog_closure_cursor_prompt.md
   ```
2. Or move them to `ai_docs/prompts/` and add that path to gitignore if they shouldn't be tracked.

**Files:**
- `ARGUS/.gitignore`

**Acceptance criteria:**
- `git status` no longer shows cursor prompt files as untracked (after gitignore update)
- `.env` files already covered by `.gitignore`

---

### FIX-009: Write tests for all fixes
**Priority:** 🔴 High | **Complexity:** Complex | **Est:** 1.5 hours
**Depends on:** FIX-001 through FIX-005

**Scope:** Two test files covering the critical fixes.

**File 1: `backend/tests/test_va_scan_mode_wiring.py`**
- **TestScanModeWiring**: Mock `run_va_active_scan_phase` in handlers.py, call `run_vuln_analysis` with `scan_options={"scan_mode": "deep"}`, verify `scan_mode="deep"` and `scan_options=...` are passed as kwargs
- **TestPipelineScanModeWiring**: Same for `execute_vulnerability_analysis_run` in pipeline.py
- **TestVulnFlagMapping**: Create `_map_vuln_flags({"xss": True, "sqli": False})`, assert result has `xss_enabled=True`, `sqli_enabled=False`
- **TestVulnFlagPassthrough**: Flags already in `_enabled` format pass through unchanged
- **TestAIDedup**: Import `AITextDeduplicator`, give it two sections with identical paragraph, verify second section's duplicate is replaced/removed

**File 2: `backend/tests/test_tool_configs_no_pipes.py`**
- Load `tool_configs.json`
- For every command in every tool entry: if command contains `|`, `&&`, or `;` → assert `requires_shell` is `true`
- Verify at least one tool has `requires_shell` (sanity check)

**Files:**
- `backend/tests/test_va_scan_mode_wiring.py` (new)
- `backend/tests/test_tool_configs_no_pipes.py` (new)

**Acceptance criteria:**
- All tests pass: `pytest backend/tests/test_va_scan_mode_wiring.py backend/tests/test_tool_configs_no_pipes.py -v`
- No mocks with `pass` or `return []` — real assertions
- `ruff check backend/tests/` passes

---

## Execution Strategy

### Recommended Order (sequential with parallel opportunities):

**Phase 1 — Critical wiring (sequential):**
1. FIX-001 (handlers.py scan_mode wiring)
2. FIX-002 (pipeline.py scan_mode wiring) — depends on FIX-001 pattern
3. FIX-003 (vuln flag mapping) — independent but related

**Phase 2 — Critical report fix:**
4. FIX-004 (AI dedup in Celery path)

**Phase 3 — Medium fixes (parallelizable):**
5. FIX-005 (tool_configs shell pipes) ← can run in parallel with 6, 7, 8
6. FIX-006 (English-only i18n) ← independent
7. FIX-007 (cache invalidation) ← independent
8. FIX-008 (.gitignore cleanup) ← independent

**Phase 4 — Verification:**
9. FIX-009 (tests for all fixes)

### Suggested Subagents per Task:
| Task | Agent | Model |
|------|-------|-------|
| FIX-001 | worker | default |
| FIX-002 | worker | default |
| FIX-003 | worker | default |
| FIX-004 | worker | default |
| FIX-005 | worker | fast |
| FIX-006 | worker | default |
| FIX-007 | worker | fast |
| FIX-008 | worker | fast |
| FIX-009 | test-writer | default |

### Verification after each task:
```powershell
cd d:\Developer\Pentest_test\ARGUS
python -m ruff check backend/src/ --fix
python -m pytest backend/tests/ -x --tb=short -q
```

---

## Architecture Decisions

- **No new parameters added to API contracts** — `scan_options` already flows from API to handlers; we only wire it deeper
- **Flag mapping is defensive** — `_map_vuln_flags` copies both short and `_enabled` forms, never overwrites existing values
- **AI dedup placement** — at Celery result collection point, not at scheduling time (results don't exist yet at scheduling)
- **Cache strategy** — verify existing invalidation paths first; avoid breaking cache sharing across scans unless explicitly needed
- **English-only** — keep `get_translations("ru")` falling back to EN for backward compat, just remove the RU dict

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| FIX-002 callers missed | scan_mode doesn't propagate from CLI/jobs | grep all callers before PR |
| FIX-004 Celery collection point unclear | AI text still duplicated | trace full Celery result flow |
| FIX-006 hidden language refs in templates | report partially in wrong language | grep all .j2 files |
| FIX-007 cache invalidation too aggressive | performance regression | measure cache hit rate before/after |
