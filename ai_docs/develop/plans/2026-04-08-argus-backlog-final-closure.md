# Plan: ARGUS Backlog Final Closure

**Created:** 2026-04-08
**Orchestration:** orch-2026-04-08-18-00-backlog-final
**Status:** ✅ Completed
**Goal:** Close all remaining audit items (C-3, H-1, R-3, R-5, R-11–R-18, M-18, L-*)
**Total Tasks:** 9
**Constraints:** No auth/multi-tenancy changes, no frontend changes, max 10 tasks

---

## Tasks

- [x] REM-001: Fix `app.schemas.*` / `app.prompts.*` broken imports (✅ Completed)
- [x] REM-002: Security config — jwt_secret validator + docker-compose CORS (✅ Completed)
- [x] REM-003: Translate remaining Russian strings in `reporting.py` (✅ Completed)
- [x] REM-004: Clean `requirements.txt` — remove unused deps (✅ Completed)
- [x] REM-005: Reconcile `config.py` Settings with `.env.example` (✅ Completed)
- [x] REM-006: Remove duplicate `backend/Dockerfile` (✅ Completed)
- [x] REM-007: API polish — EmailStr, severity whitelist, response_model, status_filter (✅ Completed)
- [x] REM-008: Code cleanup — dead vars, FindingNote DELETE/PUT, resolved_by, Kali docs (✅ Completed)
- [x] REM-009: Tests for all changes (✅ Completed)

---

## Dependencies Graph

```
REM-001 ──┐
REM-002 ──┤
REM-003 ──┤
REM-004 ──┤
REM-005 ──┼──→ REM-009 (tests)
REM-006 ──┤
REM-007 ──┤  (depends on REM-001 for import paths)
REM-008 ──┘
```

**Parallel groups:**
- Group A (independent, can run in any order): REM-001, REM-002, REM-003, REM-004, REM-005, REM-006, REM-008
- Group B (after REM-001): REM-007
- Group C (after all): REM-009

---

## Detailed Task Breakdown

### REM-001: Fix `app.schemas.*` / `app.prompts.*` broken imports — CRITICAL

**Audit refs:** C-3, R-1
**Priority:** Critical
**Complexity:** Complex
**Files affected (5):**

| File | Broken imports |
|------|---------------|
| `backend/src/recon/vulnerability_analysis/pipeline.py:19-24` | `app.prompts.vulnerability_analysis_prompts`, `app.schemas.ai.common`, `app.schemas.vulnerability_analysis.schemas` |
| `backend/src/api/routers/recon/exploitation.py:9` | `app.schemas.exploitation.requests` |
| `backend/src/recon/vulnerability_analysis/active_scan/va_active_scan_phase.py:18` | `app.schemas.vulnerability_analysis.schemas` |
| `backend/src/recon/vulnerability_analysis/active_scan/planner.py:20` | `app.schemas.vulnerability_analysis.schemas` |
| `backend/src/orchestration/handlers.py:16` | `app.schemas.vulnerability_analysis.schemas` |

**Investigation findings:**
- `backend/app/` directory does NOT exist — 0 files found with `Glob("ARGUS/backend/app/**/*.py")`
- `app.schemas.*` and `app.prompts.*` packages do NOT exist anywhere under `ARGUS/`
- These are **broken imports** — not a PYTHONPATH aliasing issue
- The referenced types (`VulnerabilityAnalysisInputBundle`, `VulnerabilityAnalysisAiTask`, etc.) must already be defined in `backend/src/api/schemas.py` or adjacent modules, or need to be created

**Implementation plan:**
1. Identify all referenced symbols: `VulnerabilityAnalysisInputBundle`, `VulnerabilityAnalysisAiTask`, `build_va_task_metadata`, `AIReasoningTrace`, `MCPInvocationTrace`, `VulnerabilityAnalysisArtifact`, `get_vulnerability_analysis_prompt`, and exploitation request schemas
2. Check if these types exist elsewhere in `src/` — search for class definitions
3. **Option A (preferred):** If types exist in `src/api/schemas.py` or adjacent modules → rewrite imports to `src.` paths
4. **Option B:** If types only exist in `app/` stubs (worktree) → create proper modules under `src/schemas/` and wire imports
5. Update all 5 files to use correct import paths

**Acceptance criteria:**
- `python -c "from src.recon.vulnerability_analysis.pipeline import *"` succeeds
- All 5 files import from `src.*` paths only
- No `app.` imports remain in codebase

---

### REM-002: Security config — jwt_secret validator + docker-compose CORS — HIGH

**Audit refs:** H-1, R-3
**Priority:** High
**Complexity:** Simple
**Files affected (2):**

| File | Change |
|------|--------|
| `backend/src/core/config.py:31` | Add `@field_validator("jwt_secret")` that raises `ValueError` if empty and `debug=False` |
| `infra/docker-compose.yml:157` | Change `CORS_ORIGINS: ${CORS_ORIGINS:-*}` → `CORS_ORIGINS: ${CORS_ORIGINS:-http://localhost:3000}` |

**Implementation plan:**
1. In `config.py`, add a `model_validator(mode="after")` (needs access to both `jwt_secret` and `debug`):
   ```python
   @model_validator(mode="after")
   def validate_jwt_secret_in_prod(self) -> "Settings":
       if not self.jwt_secret and not self.debug:
           raise ValueError(
               "JWT_SECRET must be set in production (debug=False). "
               "Generate with: openssl rand -hex 32"
           )
       return self
   ```
2. In `docker-compose.yml:157`, replace `${CORS_ORIGINS:-*}` with `${CORS_ORIGINS:-http://localhost:3000}`

**Acceptance criteria:**
- `Settings(jwt_secret="", debug=False)` raises `ValidationError`
- `Settings(jwt_secret="", debug=True)` succeeds (dev mode)
- `Settings(jwt_secret="some-secret", debug=False)` succeeds
- docker-compose default for CORS is `http://localhost:3000`, not `*`

---

### REM-003: Translate remaining Russian strings in `reporting.py` — MEDIUM

**Audit refs:** R-5
**Priority:** Medium
**Complexity:** Simple
**Files affected (1):** `backend/src/services/reporting.py`

**Lines to translate (415–422):**
```python
# Current (Russian):
p_label = ... else "параметр"
f"В параметре «{p_label}» передана полезная нагрузка; отражение зафиксировано в контексте «{rc}»."
f"Полезная нагрузка была передана через параметр «{param.strip()}»."

# Target (English):
p_label = ... else "parameter"
f"A payload was injected via the «{p_label}» parameter; reflection detected in «{rc}» context. See Verification line."
f"Payload was delivered through the «{param.strip()}» parameter."
```

**Acceptance criteria:**
- No Cyrillic strings remain in `reporting.py`
- English text is grammatically correct and technically accurate

---

### REM-004: Clean `requirements.txt` — remove unused deps — MEDIUM

**Audit refs:** R-11..R-16
**Priority:** Medium
**Complexity:** Simple
**Files affected (1):** `backend/requirements.txt`

**Investigation findings (grep for imports):**
- `typer` — **not imported** anywhere in `src/` → REMOVE
- `tldextract` — **not imported** → REMOVE
- `dnspython` — **not imported** → REMOVE
- `netaddr` — **not imported** → REMOVE
- `rich` — **not imported** → REMOVE
- `beautifulsoup4` — **not imported** (no `from bs4` anywhere) → REMOVE
- `shodan` — **not imported** in src/ — however `shodan_api_key` is in config; Shodan is used via API calls through `httpx`, not the `shodan` SDK → REMOVE
- `openai` — kept: `openai>=1.0.0` is used by `src/llm/adapters.py` (confirmed used)

**Lines to remove (6 packages):**
```
typer>=0.9.0
tldextract>=5.1.0
dnspython>=2.6.0
netaddr>=1.0.0
rich>=13.0.0
beautifulsoup4>=4.12.0
shodan>=1.31.0
```

**Acceptance criteria:**
- Removed packages not imported anywhere in `backend/src/`
- `pip install -r requirements.txt` still succeeds
- Application imports don't break

---

### REM-005: Reconcile `config.py` Settings with `.env.example` — MEDIUM

**Audit refs:** R-17, R-18
**Priority:** Medium
**Complexity:** Simple
**Files affected (1):** `backend/src/core/config.py`

**Missing from Settings (declared in `.env.example` but not in Settings class):**

| Env var | Type | Default |
|---------|------|---------|
| `CENSYS_API_SECRET` | `str \| None` | `None` |
| `NVD_API_KEY` | `str \| None` | `None` |
| `EXPLOITDB_API_KEY` | `str \| None` | `None` |
| `URLSCAN_API_KEY` | `str \| None` | `None` |
| `ABUSEIPDB_API_KEY` | `str \| None` | `None` |
| `GREYNOISE_API_KEY` | `str \| None` | `None` |
| `OTX_API_KEY` | `str \| None` | `None` |
| `GITHUB_TOKEN` | `str \| None` | `None` |
| `SHODAN_API_KEY` | `str \| None` | `None` |

**Note:** `CENSYS_API_KEY`, `SECURITYTRAILS_API_KEY`, `VIRUSTOTAL_API_KEY`, `HIBP_API_KEY` — already in Settings.

**Implementation:**
1. Add missing fields to `Settings` class in the "Data Sources" section
2. Add to `_sync_llm_api_keys_to_environ()` if any code reads them via `os.environ`

**Acceptance criteria:**
- Every env var declared in `.env.example` (API key section) has a corresponding field in `Settings`
- No runtime `KeyError` / silent misses for declared env vars

---

### REM-006: Remove duplicate `backend/Dockerfile` — MEDIUM

**Audit refs:** M-18
**Priority:** Medium
**Complexity:** Simple
**Files affected (1):** Delete `ARGUS/backend/Dockerfile` (if it exists)

**Investigation:** `Glob("ARGUS/backend/Dockerfile*")` returned 0 files. The only Dockerfile for backend is at `infra/backend/Dockerfile`. This task may already be resolved.

**Implementation:**
1. Verify no `backend/Dockerfile` exists
2. If it does → delete it
3. Confirm `infra/docker-compose.yml` references `infra/backend/Dockerfile` (already does)

**Acceptance criteria:**
- Only one backend Dockerfile exists: `infra/backend/Dockerfile`
- `docker compose build backend` still works

---

### REM-007: API polish — EmailStr, severity whitelist, response_model, status_filter — LOW

**Audit refs:** L-1, L-2, L-5, L-12, L-13
**Priority:** Low
**Complexity:** Moderate
**Depends on:** REM-001 (import paths must work)
**Files affected (3):**

| File | Change | Ref |
|------|--------|-----|
| `backend/src/api/schemas.py:90` | `email: str` → `email: EmailStr` (add `from pydantic import EmailStr`) | L-1 |
| `backend/src/api/routers/findings.py` | Add `severity: Literal[...] \| None` query param with whitelist (`critical`, `high`, `medium`, `low`, `info`) | L-2 |
| `backend/src/api/routers/findings.py:202,242` | Change `response_model=None` to proper typed response on `post_validate_finding` and `post_generate_poc` | L-5 |
| `backend/src/api/routers/recon/exploitation.py:328` | `resolved_by = "operator"` → read from settings or request param | L-12 |
| `backend/src/api/routers/recon/exploitation.py:173` | Add `Literal` whitelist for `status_filter` | L-13 |
| `backend/src/api/routers/scans.py:135` | Add `Literal` whitelist for `status_filter` | L-13 |

**Acceptance criteria:**
- `ScanCreateRequest.email` validates email format
- severity/status_filter params reject unknown values (422)
- `response_model` is typed on all endpoints that return structured data

---

### REM-008: Code cleanup — dead vars, FindingNote CRUD, resolved_by, Kali docs — LOW

**Audit refs:** L-4, L-6..L-10
**Priority:** Low
**Complexity:** Moderate
**Files affected (4+):**

| File | Change | Ref |
|------|--------|-----|
| `backend/src/recon/vulnerability_analysis/active_scan/va_active_scan_phase.py:1186` | Remove `_ = float(settings.va_active_scan_tool_timeout_sec)` | L-6 |
| `backend/src/api/routers/findings.py` | Add `DELETE /{finding_id}/notes/{note_id}` and `PUT /{finding_id}/notes/{note_id}` endpoints | L-4 |
| Kali registry docs | Fix "150+" → actual count or remove outdated comment | L-10 |

**Acceptance criteria:**
- No dead `_ = ` assignments remain
- FindingNote has full CRUD (POST + GET + PUT + DELETE)
- Documentation matches reality

---

### REM-009: Tests for all changes — HIGH

**Audit refs:** (covers all above)
**Priority:** High
**Complexity:** Complex
**Depends on:** All REM-001..REM-008
**Files affected (1 new):** `backend/tests/test_fix_010_backlog_final.py`

**Test coverage plan:**

| Test | Validates |
|------|-----------|
| `test_no_app_imports_remain` | Grep `src/` for `from app.` — assert 0 matches | REM-001 |
| `test_jwt_secret_empty_prod_raises` | `Settings(jwt_secret="", debug=False)` → `ValidationError` | REM-002 |
| `test_jwt_secret_empty_dev_ok` | `Settings(jwt_secret="", debug=True)` → OK | REM-002 |
| `test_docker_compose_cors_no_wildcard` | Parse `docker-compose.yml` for CORS default | REM-002 |
| `test_no_russian_in_reporting` | Regex scan `reporting.py` for Cyrillic chars | REM-003 |
| `test_requirements_no_unused` | Assert removed packages not in `requirements.txt` | REM-004 |
| `test_settings_has_env_keys` | Assert Settings has fields for all `.env.example` API keys | REM-005 |
| `test_no_duplicate_dockerfile` | Assert `backend/Dockerfile` does not exist | REM-006 |
| `test_email_validation` | `ScanCreateRequest(email="not-email")` → `ValidationError` | REM-007 |
| `test_severity_whitelist` | Invalid severity → 422 | REM-007 |
| `test_dead_var_removed` | `_ = float(settings...)` not in code | REM-008 |

**Acceptance criteria:**
- All tests pass with `pytest backend/tests/test_fix_010_backlog_final.py -v`
- No regressions in existing tests

---

## Execution Strategy

**Recommended order:**
1. **REM-001** (critical path — unblocks REM-007)
2. **REM-002** + **REM-003** + **REM-004** + **REM-005** + **REM-006** + **REM-008** (parallel, independent)
3. **REM-007** (after REM-001)
4. **REM-009** (final — tests everything)

**Subagent mapping:**
- REM-001: `worker` (complex refactor)
- REM-002..REM-006, REM-008: `worker` (simple changes, can batch)
- REM-007: `worker` (API changes)
- REM-009: `test-writer` → `test-runner`

**Estimated time:** ~3–4 hours total

---

## Architecture Decisions

- **Import strategy (REM-001):** Create `src/schemas/` package hierarchy mirroring what `app.schemas.*` expected, OR inline the types into existing `src/api/schemas.py`. Decision depends on how many types are needed — if >10 schemas, create subpackages; if ≤5, inline.
- **jwt_secret validation (REM-002):** Use `model_validator(mode="after")` (not `field_validator`) because the check needs cross-field access (`jwt_secret` + `debug`).
- **Test file naming (REM-009):** Follow existing convention `test_fix_NNN_*.py` → `test_fix_010_backlog_final.py`.

---

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| REM-001 types don't exist anywhere | High — need to define from scratch | Check worktree stubs, extract types |
| jwt_secret validator breaks CI | Medium — CI uses `debug=True` | Ensure validator only fires when `debug=False` |
| Removing `shodan` breaks runtime | Low — Shodan calls are via httpx | Verify no `import shodan` in entire backend |
| REM-007 breaks frontend API contract | Medium | Keep backward-compatible defaults |
