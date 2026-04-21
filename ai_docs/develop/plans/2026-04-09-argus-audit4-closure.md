# Plan: ARGUS Audit-4 Backlog Closure

**Created:** 2026-04-09
**Orchestration:** orch-2026-04-09-16-00-audit4-closure
**Status:** ✅ Complete
**Goal:** Close 37 remaining audit-4 items (C-1..C-4 confirmed false alarms)
**Total Tasks:** 10
**Estimated Time:** 8–12 hours

## Constraints

- Do NOT change frontend
- Do NOT break existing API contracts
- English-only code/comments
- Max 10 tasks

## Dependencies Graph

```
AUD4-001 (security)  ──┐
AUD4-002 (nginx/llm) ──┤
                        ├──→ AUD4-003 (LLM facade) ──┐
AUD4-004 (RU→EN)     ──┤                             │
                        ├──→ AUD4-005 (reporting)     │
AUD4-006 (err handling)─┤                             │
AUD4-007 (infra/quality)┤                             │
AUD4-008 (config/polish)┤                             │
                        └──→ AUD4-009 (tests) ────────┘──→ AUD4-010 (docs)
```

Parallelizable: AUD4-001, AUD4-002, AUD4-004, AUD4-006, AUD4-007, AUD4-008 have no inter-dependencies.

---

## Tasks

- [x] AUD4-001: Security: intelligence auth + docker security (✅ Completed)
- [x] AUD4-002: Nginx CORS dynamic + LLM client fix (✅ Completed)
- [x] AUD4-003: LLM facade + docstrings (✅ Completed)
- [x] AUD4-004: Russian text translation (✅ Completed)
- [x] AUD4-005: Reporting quality (✅ Completed)
- [x] AUD4-006: Error handling fixes (✅ Completed)
- [x] AUD4-007: Infrastructure + code quality (✅ Completed)
- [x] AUD4-008: Config + polish (✅ Completed)
- [x] AUD4-009: Tests for all changes (✅ Completed)
- [x] AUD4-010: Documentation (✅ Completed)

---

## AUD4-001 — HIGH: Security: intelligence auth + docker security

**Priority:** High | **Items:** H-1, H-2, H-3, H-4, H-5, H-8 | **Est:** 1.5h
**Dependencies:** None

### H-1: Intelligence router auth

**File:** `backend/src/api/routers/intelligence.py`
**Action:** Add `dependencies=[Depends(get_required_auth)]` to the `APIRouter()` constructor.
Import `get_required_auth` from `src.core.auth`.

```python
from src.core.auth import get_required_auth

router = APIRouter(
    prefix="/intelligence",
    tags=["intelligence"],
    dependencies=[Depends(get_required_auth)],
)
```

**Verify:** All `/intelligence/*` endpoints return 401/403 without valid credentials.

### H-2: Docker socket accepted-risk documentation

**File:** `infra/docker-compose.yml`
**Action:** Add `profiles: ["privileged"]` to the `volumes` service that mounts docker.sock. Add clear warning comment block explaining:
- Docker socket mount is required for container orchestration
- This is an accepted risk for self-hosted deployment
- Production should use rootless Docker or Podman

### H-3: Remove `user: "0:0"` from worker

**File:** `infra/docker-compose.yml`
**Action:** Remove `user: "0:0"` from the worker service. If docker.sock access is needed, use group-based access (`user: "1000:docker"`) or document the requirement.

### H-4: Replace `:-fallback` defaults with `${VAR:?}` for secrets

**File:** `infra/docker-compose.yml`
**Action:** For all secret-related env vars (`POSTGRES_PASSWORD`, `MINIO_ROOT_PASSWORD`, `MINIO_SECRET_KEY`, `JWT_SECRET`, `REDIS_PASSWORD`), replace `:-fallback` with `${VAR:?VAR is required}`:

```yaml
POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}
JWT_SECRET: ${JWT_SECRET:?JWT_SECRET is required}
```

Keep non-secret defaults (like `POSTGRES_USER:-argus`, `POSTGRES_DB:-argus`).

### H-5: MCP auth middleware + bind restriction

**File:** `mcp-server/argus_mcp.py`
**Action:**
1. Add `MCP_AUTH_TOKEN` env var check
2. If token is set: validate `Authorization: Bearer <token>` on incoming HTTP requests
3. If token is NOT set: bind to `127.0.0.1` instead of `0.0.0.0` and log a warning

```python
MCP_AUTH_TOKEN = os.environ.get("MCP_AUTH_TOKEN")
bind_host = "0.0.0.0" if MCP_AUTH_TOKEN else "127.0.0.1"
if not MCP_AUTH_TOKEN:
    logger.warning("MCP_AUTH_TOKEN not set — binding to 127.0.0.1 only")
```

### H-8: Safe VA defaults in .env.example

**File:** `infra/.env.example`
**Action:** Set:
```
SQLMAP_VA_ENABLED=false
VA_EXPLOIT_AGGRESSIVE_ENABLED=false
VA_ACTIVE_SCAN_DRY_RUN=true
```

### Acceptance Criteria
- [x] `/intelligence/*` returns 401 without auth
- [x] `docker compose config` succeeds with all secrets in `.env`
- [x] `docker compose config` fails with clear error if `JWT_SECRET` is missing
- [x] MCP server binds to 127.0.0.1 when `MCP_AUTH_TOKEN` is unset
- [x] `.env.example` has safe defaults

---

## AUD4-002 — HIGH: Nginx CORS dynamic + LLM client fix

**Priority:** High | **Items:** H-6, H-7 | **Est:** 1.5h
**Dependencies:** None

### H-6: Nginx envsubst for dynamic CORS

**Files:**
- `infra/nginx/conf.d/api.conf` → rename to `api.conf.template`
- Create `infra/nginx/docker-entrypoint.sh` (envsubst entrypoint)
- Update `infra/docker-compose.yml` nginx service

**Action:**
1. Replace hardcoded CORS origins in `api.conf` with `${CORS_ALLOWED_ORIGINS}` placeholder
2. Create entrypoint script that runs `envsubst` on template → actual config
3. Mount template, expose `CORS_ALLOWED_ORIGINS` env var
4. Keep localhost defaults for dev

```bash
#!/bin/sh
envsubst '${CORS_ALLOWED_ORIGINS}' < /etc/nginx/conf.d/api.conf.template > /etc/nginx/conf.d/api.conf
exec nginx -g 'daemon off;'
```

### H-7: Fix `get_llm_client()` to propagate `task` and `scan_id`

**File:** `backend/src/core/llm_config.py`
**Action:**
1. Add `task: LLMTask | None = None` and `scan_id: str | None = None` parameters to `get_llm_client()`
2. Thread them through to the returned client configuration
3. Update all callers in VA pipeline, exploitation, and report modules to pass the correct `task` and `scan_id`

**Verify:** Cost tracking by scan is accurate after changes.

### Acceptance Criteria
- [x] `CORS_ALLOWED_ORIGINS=https://app.example.com` works in nginx
- [x] `get_llm_client(task=..., scan_id=...)` propagates correctly
- [x] Existing callers updated — no regressions

---

## AUD4-003 — MEDIUM: LLM facade + docstrings

**Priority:** Medium | **Items:** M-1, M-2, M-3, M-4 | **Est:** 1h
**Dependencies:** AUD4-002 (H-7 changes `get_llm_client` signature)

### M-1: Require `task` param in facade, prefer `response.usage`

**File:** `backend/src/llm/facade.py`
**Action:**
1. Make `task` a required parameter in `call_llm_unified()`
2. Always use `response.usage` for token counting when available
3. Fall back to tiktoken estimation only when `response.usage` is `None`

### M-2: Pass `scan_id` in intelligence calls

**File:** `backend/src/api/routers/intelligence.py`
**Action:** All `call_llm_unified()` calls must pass `scan_id`. When called outside a scan context, use `"intelligence-adhoc"`.

### M-3: Fix docstring "retry once"

**File:** `backend/src/orchestration/ai_prompts.py`
**Action:** Change docstring from "retry once" to "Retry up to MAX_JSON_RETRIES (3) times with exponential backoff".

### M-4: Fix "150+" in argus_mcp.py

**File:** `mcp-server/argus_mcp.py`
**Action:** Update `_register_kali_tools` docstring — count actual tools registered and replace "150+".

### Acceptance Criteria
- [x] `call_llm_unified()` requires `task` — no caller omits it
- [x] Intelligence calls include `scan_id="intelligence-adhoc"`
- [x] Docstrings match actual behavior

---

## AUD4-004 — MEDIUM: Russian text translation

**Priority:** Medium | **Items:** M-5, M-6, M-7, M-8 | **Est:** 2h
**Dependencies:** None

### M-5: Translate `_PHASE_LABELS`

**File:** `backend/src/reports/jinja_minimal_context.py`
**Action:** Replace Russian phase labels (`Разведка`, `Моделирование угроз`, etc.) with English equivalents (`Reconnaissance`, `Threat Modeling`, etc.).

### M-6: Translate all RU strings in valhalla_report_context.py

**File:** `backend/src/reports/valhalla_report_context.py`
**Action:** Translate all Russian recommendation text, `notes_ru`, fallback strings to English. Remove `_ru` suffix from variable names where applicable.

### M-7: Translate RU comments in data_collector.py

**File:** `backend/src/reports/data_collector.py`
**Action:** Translate Russian comments and docstrings at lines ~15, ~323 and any others to English.

### M-8: Replace RU regex patterns

**File:** `backend/src/reports/report_data_validation.py`
**Action:** Replace Russian-language regex patterns (`критич`, `высок`, etc.) with English equivalents (`critical`, `high`, etc.) at lines ~150-153, ~214.

### Acceptance Criteria
- [x] `rg -c '[а-яА-Я]' backend/src/reports/` returns 0 matches in target files
- [x] Report generation produces English output for `report_language="en"`

---

## AUD4-005 — MEDIUM: Reporting quality

**Priority:** Medium | **Items:** M-9, M-10 | **Est:** 0.5h
**Dependencies:** AUD4-004 (needs translated labels)

### M-9: Rename TIER_STUBS → TIER_METADATA

**File:** `backend/src/services/reporting.py`
**Action:**
1. Rename `TIER_STUBS` to `TIER_METADATA`
2. Add `TIER_STUBS = TIER_METADATA` deprecated alias with a comment
3. Update all internal references

### M-10: Ensure EN phase labels when `report_language="en"`

**File:** `backend/src/services/reporting.py`
**Action:** When building report context, use the English `_PHASE_LABELS` dict (from AUD4-004 M-5 fix). Verify the language selection logic respects `report_language` setting.

### Acceptance Criteria
- [x] `TIER_METADATA` is the canonical name
- [x] `TIER_STUBS` still works as alias (backward compat)
- [x] Phase labels in report match `report_language` setting

---

## AUD4-006 — MEDIUM: Error handling fixes

**Priority:** Medium | **Items:** M-11, M-12, M-13, M-14 | **Est:** 1h
**Dependencies:** None

### M-11: Log exception on cache delete failure

**File:** `backend/src/reports/ai_text_generation.py` (~line 292)
**Action:** Replace `except Exception: pass` with `except Exception: logger.warning("Cache key delete failed", exc_info=True)`.

### M-12: Add exc_info in ai_text_generation.py

**File:** `backend/src/reports/ai_text_generation.py` (~line 338)
**Action:** Add `exc_info=True` to the `logger.error()` call in the generation exception handler.

### M-13: Fix asyncio.run in MCP client

**File:** `backend/src/recon/mcp/client.py` (~line 145)
**Action:** Replace `asyncio.run()` with proper async pattern:
```python
try:
    loop = asyncio.get_running_loop()
    future = asyncio.ensure_future(coro)
    # ...
except RuntimeError:
    return asyncio.run(coro)
```
Or refactor the caller to be `async def` and use `await` directly.

### M-14: Log urlparse failure in exploitation pipeline

**File:** `backend/src/recon/exploitation/pipeline.py` (~line 443)
**Action:** Replace `except Exception: pass` with `except Exception: logger.warning("Failed to parse URL for domain extraction", exc_info=True)`.

### Acceptance Criteria
- [x] No `except Exception: pass` remains in these files
- [x] MCP client works both inside and outside running event loops
- [x] All exception paths produce log output

---

## AUD4-007 — MEDIUM: Infrastructure + code quality

**Priority:** Medium | **Items:** M-15..M-22 | **Est:** 2h
**Dependencies:** None

### M-15: MCP Dockerfile non-root user

**File:** `mcp-server/Dockerfile`
**Action:** Add non-root user:
```dockerfile
RUN addgroup --system mcp && adduser --system --ingroup mcp mcp
USER mcp
```

### M-16: SSL block template

**File:** `infra/nginx/conf.d/api.conf` (or template after H-6)
**Action:** Add a commented-out SSL server block template with instructions for enabling TLS:
```nginx
# --- SSL template (uncomment and configure for production) ---
# server {
#     listen 443 ssl http2;
#     ssl_certificate /etc/nginx/ssl/cert.pem;
#     ssl_certificate_key /etc/nginx/ssl/key.pem;
#     ...
# }
```

### M-17: CSP header in nginx

**File:** `infra/nginx/conf.d/api.conf`
**Action:** Add `Content-Security-Policy` header for API responses:
```nginx
add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'" always;
```

### M-18: Fix empty src/cache/ and src/dedup/ dirs

**Files:** `backend/src/cache/`, `backend/src/dedup/`
**Action:** If no code exists, add `__init__.py` with a brief module docstring, or remove the dirs if no references exist. Check `git ls-files` and imports first.

### M-19: CORS wildcard + non-debug → raise ValueError

**File:** `backend/src/core/config.py`
**Action:** In the CORS parsing logic: when `cors_origins="*"` and `debug=False`, raise `ValueError("CORS wildcard '*' is not allowed in production (debug=False)")` instead of silently returning `[]`.

### M-20: Update stale schema comments

**File:** `backend/src/api/schemas.py`
**Action:** Update comments at lines ~561-567, ~580 that say "reserved/not active" — intelligence router is now active.

### M-21: Extract VA prompt magic numbers to settings

**File:** `backend/src/recon/vulnerability_analysis/pipeline.py`
**Action:** Extract hardcoded `15000` and `20000` char limits to `Settings` fields:
```python
va_prompt_max_chars: int = Field(default=15000, ...)
va_context_max_chars: int = Field(default=20000, ...)
```

### M-22: Remove conditional pytest.skip from audit3 tests

**Files:** `backend/tests/test_audit3_*.py`
**Action:** Remove `pytest.skip()` calls that skip when files are missing. Tests should either run fully or be marked `@pytest.mark.skipif` with a clear reason at the module level.

### Acceptance Criteria
- [x] MCP container runs as non-root user
- [x] Nginx config includes CSP header and SSL template
- [x] `ValueError` raised on CORS wildcard in production
- [x] Schema comments updated
- [x] VA magic numbers configurable
- [x] Test skips are explicit `@pytest.mark.skipif` decorators

---

## AUD4-008 — LOW: Config + polish

**Priority:** Low | **Items:** L-1..L-7 | **Est:** 1h
**Dependencies:** None

### L-1: Remove change-me-in-production defaults

**File:** `backend/src/core/config.py`
**Action:** For `database_url` and `minio_*` settings, remove `"change-me-in-production"` defaults. Make them required fields (`...` as default) or use `${VAR:?}` pattern so app fails fast on startup.

### L-2: Replace CWE-XXX with CWE-79 example

**File:** `backend/src/agents/va_orchestrator.py`
**Action:** Replace `CWE-XXX` placeholder at ~line 120 with `CWE-79` (Cross-site Scripting) as a concrete example in the LLM prompt format.

### L-3: Replace lru_cache with explicit cache + reset

**File:** `backend/src/reports/template_env.py`
**Action:** Replace `@lru_cache` on Jinja Environment creation with an explicit module-level cache variable and a `reset_template_cache()` function for testing/hot-reload.

### L-4: Extract max_length 5000 to settings

**File:** `backend/src/recon/mcp/client.py`
**Action:** Move hardcoded `max_length=5000` to a `Settings` field (e.g., `mcp_fetch_max_length: int = 5000`).

### L-5: Add docstring to prompts/__init__.py

**File:** `backend/src/prompts/__init__.py`
**Action:** Add module docstring and export the actual prompt modules:
```python
"""Prompt templates for LLM-powered analysis tasks."""
__all__ = ["threat_modeling_prompts", "vulnerability_analysis_prompts"]
```

### L-6: Add Literal/regex validators to exploitation schemas

**File:** `backend/src/schemas/exploitation/requests.py`
**Action:** Add `Literal` type for `action` field and regex `Pattern` validator for `engagement_id`.

### L-7: Nginx ports via env with non-conflicting defaults

**File:** `infra/docker-compose.yml`
**Action:** Replace hardcoded `80:80` and `443:443` with:
```yaml
ports:
  - "${NGINX_HTTP_PORT:-8080}:80"
  - "${NGINX_HTTPS_PORT:-8443}:443"
```

### Acceptance Criteria
- [x] App fails with clear error if required config is missing
- [x] No placeholder CWE-XXX in prompts
- [x] Template cache can be reset in tests
- [x] Exploitation schemas validate input strictly
- [x] Nginx ports configurable, default non-conflicting

---

## AUD4-009 — HIGH: Tests for all changes

**Priority:** High | **Est:** 2h
**Dependencies:** AUD4-001 through AUD4-008

### Test Plan

| Area | Test Description | Type |
|------|-----------------|------|
| H-1 | Intelligence endpoints require auth (401 without, 200 with) | Integration |
| H-4 | Docker compose rejects missing secrets | Shell/config |
| H-5 | MCP auth middleware blocks unauthenticated requests | Unit |
| H-7 | `get_llm_client()` propagates task/scan_id | Unit |
| M-1 | `call_llm_unified()` requires task param | Unit |
| M-5/M-6 | Report context returns EN labels for en locale | Unit |
| M-9 | `TIER_METADATA` works, `TIER_STUBS` alias works | Unit |
| M-11..14 | Exception handlers produce log output | Unit |
| M-13 | MCP client works in both sync/async contexts | Unit |
| M-19 | CORS wildcard in prod raises ValueError | Unit |
| M-21 | VA prompt lengths use settings values | Unit |
| L-1 | App startup fails without required config | Unit |
| L-3 | Template cache reset works | Unit |
| L-6 | Exploitation schemas reject invalid input | Unit |

**File:** `backend/tests/test_audit4_closure.py`

### Acceptance Criteria
- [x] All new tests pass
- [x] Existing 257 tests still pass
- [x] No `pytest.skip` without explicit `@pytest.mark.skipif`
- [x] Coverage on modified files ≥80%

---

## AUD4-010 — Documentation

**Priority:** Medium | **Est:** 0.5h
**Dependencies:** AUD4-009

### Actions
1. Update `ARGUS/ai_docs/changelog/CHANGELOG.md` with audit-4 closure summary
2. Create completion report at `ARGUS/ai_docs/develop/reports/2026-04-09-argus-audit4-closure-report.md`
3. Update this plan file — mark all tasks ✅

### Acceptance Criteria
- [x] CHANGELOG has audit-4 entry
- [x] Completion report lists all 37 items resolved
- [x] Plan tasks all marked completed

---

## Implementation Notes

### Execution Order (recommended)

**Wave 1 (parallel, no deps):**
- AUD4-001 (security hardening)
- AUD4-002 (nginx + llm client)
- AUD4-004 (RU→EN translation)
- AUD4-006 (error handling)
- AUD4-007 (infra + code quality)
- AUD4-008 (config + polish)

**Wave 2 (depends on Wave 1):**
- AUD4-003 (LLM facade — needs H-7 from AUD4-002)
- AUD4-005 (reporting — needs M-5 from AUD4-004)

**Wave 3 (after all code changes):**
- AUD4-009 (comprehensive tests)

**Wave 4 (final):**
- AUD4-010 (documentation)

### Risk Mitigation
- **H-4 (required secrets):** Will break `docker compose up` without `.env`. Mitigated by clear error messages and `.env.example`.
- **H-7 (get_llm_client signature change):** Multiple callers. Run full test suite after each caller update.
- **M-6 (valhalla translation):** Large file with hundreds of strings. Verify no RU text remains with `rg '[а-яА-Я]'`.
- **M-13 (asyncio.run fix):** Event-loop sensitive. Test in both sync and async contexts.

### Subagent Strategy
- **worker:** AUD4-001 through AUD4-008
- **test-writer:** AUD4-009
- **test-runner:** Verify after AUD4-009
- **documenter:** AUD4-010
- **reviewer:** Final pass before commit
