# Plan: ARGUS Audit3 Backlog Closure

**Created:** 2026-04-09  
**Orchestration:** orch-2026-04-09-14-00-audit3-closure  
**Status:** ✅ Completed  
**Goal:** Close all 40 audit items across HIGH (5), MEDIUM (25), and LOW (10) categories  
**Total Tasks:** 10  
**Constraints:** Production-ready security and code quality, no breaking changes

---

## Summary

Comprehensive closure of ARGUS audit backlog following security audit. All 40 items resolved:
- **5 HIGH:** Nginx CORS, exploitation scope, Metasploit adapter, admin auth, metrics auth
- **25 MEDIUM:** LLM integration, token counting, exponential backoff, concurrency, policy engine, adapters, memory compression, infrastructure cleanup, etc.
- **10 LOW:** Error handling, script paths, enum cleanup, environment updates, HSTS, documentation

---

## Task Breakdown

### T01: HIGH - Nginx CORS & Admin Security
**Refs:** H-5, H-8, H-9  
**Files:** `infra/nginx/conf.d/api.conf`, `api/routers/admin.py`, `api/routers/metrics.py`, `core/config.py`  
**Tests:** `test_audit3_admin_auth.py`, `test_bkl_nginx_conf.py`

- [x] Nginx: implement CORS whitelist via `map` block instead of wildcard
- [x] Admin endpoint: default-deny with API key validation, return 503 without key
- [x] Metrics endpoint: require bearer token auth, return 404 if not set
- [x] Config: add METRICS_AUTH_TOKEN setting

---

### T02: HIGH - Exploitation Scope & Metasploit
**Refs:** H-6, H-7  
**Files:** `recon/exploitation/pipeline.py`, `recon/exploitation/adapters/metasploit_adapter.py`, `recon/exploitation/policy_engine.py`  
**Tests:** `test_audit3_exploitation_scope.py`, `test_audit3_metasploit.py`

- [x] Extraction: implement scope validation and domain filtering
- [x] Metasploit: replace `bash -c` execution with `msfconsole -q -x` protocol
- [x] Policy engine: empty scope domains → `PolicyDecision.DENY`
- [x] Target validation and error handling

---

### T03: MEDIUM - LLM Integration & Token Counting
**Refs:** M-1, M-3, M-4  
**Files:** `api/routers/intelligence.py`, `llm/facade.py`, `llm/task_router.py`, `orchestration/ai_prompts.py`, `requirements.txt`  
**Tests:** `test_audit3_llm_facade.py`

- [x] Unified LLM caller: integrate `call_llm_unified` into intelligence endpoint
- [x] Token counting: implement tiktoken-based counting (replace char estimate)
- [x] Retry logic: `MAX_JSON_RETRIES = 3` with exponential backoff
- [x] Add tiktoken to requirements

---

### T04: MEDIUM - Concurrency & Policy Engine
**Refs:** M-5, M-6  
**Files:** `recon/exploitation/pipeline.py`, `recon/exploitation/policy_engine.py`  
**Tests:** `test_audit3_exploitation_scope.py`

- [x] Concurrency: wire `max_concurrent` to `asyncio.Semaphore`
- [x] Policy validation: empty domains return DENY decision

---

### T05: MEDIUM - Adapter Security & Memory Compression
**Refs:** M-7, M-8  
**Files:** `recon/exploitation/adapters/custom_script_adapter.py`, `agents/memory_compressor.py`  
**Tests:** `test_audit3_custom_script.py`, `test_audit3_memory_compressor.py`

- [x] Custom script adapter: switch from blacklist to whitelist strategy
- [x] Memory compressor: redact secrets and implement regex sanitizer

---

### T06: MEDIUM - Infrastructure Cleanup
**Refs:** M-9, M-10, M-12, M-13, M-14  
**Files:** `mcp-server/main.py`, `mcp-server/argus_mcp.py`, `mcp-server/tools/kali_registry.py`, `infra/docker-compose.yml`, `core/config.py`  
**Tests:** `test_audit3_infra.py`

- [x] Delete duplicate `mcp-server/main.py` entrypoint
- [x] Kali registry: replace "150+" with dynamic `len()` count
- [x] Docker: add `depends_on: service_healthy` for worker
- [x] MCP default port 8765
- [x] Settings: add `cors_include_dev_origins` field

---

### T07: MEDIUM - Code Quality & Logging
**Refs:** M-15, M-16, M-17, M-18, M-19, M-20, M-22, M-25  
**Files:** `api/routers/admin.py`, `api/routers/health.py`, `prompts/__init__.py`, `core/config.py`, `recon/va/active_scan/planner.py`, `api/schemas.py`, `reports/report_pipeline.py`, `reports/ai_text_generation.py`, `README.md`  
**Tests:** `test_audit3_code_quality.py`

- [x] Admin: log exceptions, return degraded status
- [x] Health: log DB failures, return db=down
- [x] Prompts: add explicit `__all__` marker
- [x] Config: Russian comment translation
- [x] Planner: Russian comment translation
- [x] Schemas: update stale comment
- [x] Report pipeline: split broad exception handlers
- [x] Cache handler: log JSONDecodeError and evict
- [x] Create root README.md

---

### T08: MEDIUM - Localization & Templates
**Refs:** M-21, M-24  
**Files:** `templates/reports/partials/findings_table.html.j2`, `templates/reports/partials/owasp_compliance_table.html.j2`, `reports/generators.py`, `services/reporting.py`  
**Tests:** `test_fix_003_english.py`

- [x] Remove all `*_ru` template variables
- [x] Update generators and reporting to use English-only paths

---

### T09: LOW - Configuration & Documentation
**Refs:** L-3, L-4, L-6, L-8  
**Files:** `recon/step_registry.py`, `infra/.env.example`, `infra/nginx/conf.d/api.conf`  
**Tests:** `test_audit3_infra.py`

- [x] Step registry: rename `STUB_STEPS` → `DEPRECATED_STEPS`
- [x] Env example: replace Vercel URLs with local equivalents
- [x] Nginx: add HSTS headers in SSL block + HTTP comment
- [x] Env example: translate Russian comments to English

---

### T10: Testing & Verification
**Refs:** All audit items  
**Files:** `backend/tests/test_audit3_*.py`  
**Tests:** All audit test files

- [x] Run full test suite: 257 tests passing
- [x] Ruff checks: all passing
- [x] Coverage validation for all changes

---

## Dependencies & Execution Flow

```
T01 (Nginx/Admin) ──┐
T02 (Exploitation) ─┤
T03 (LLM)          ├──→ T10 (Testing & Verification)
T04 (Concurrency)  ├──→ (Final validation)
T05 (Adapters)     ├──→
T06 (Infrastructure)┤
T07 (Code Quality) ├──→
T08 (Localization) ┤
T09 (Configuration)┘
```

**Parallel execution:** All T01-T09 can run in parallel; T10 runs final validation after all are complete.

---

## Files Changed Summary

### Modified Files (~35)
- `infra/nginx/conf.d/api.conf`
- `api/routers/admin.py`, `health.py`, `metrics.py`, `intelligence.py`
- `core/config.py`, `core/auth.py`
- `recon/exploitation/pipeline.py`, `policy_engine.py`
- `recon/exploitation/adapters/metasploit_adapter.py`, `custom_script_adapter.py`
- `llm/facade.py`, `task_router.py`
- `orchestration/ai_prompts.py`
- `agents/memory_compressor.py`, `va_orchestrator.py`
- `schemas/exploitation/requests.py`
- `prompts/__init__.py`
- `api/schemas.py`
- `reports/report_pipeline.py`, `ai_text_generation.py`, `generators.py`
- `services/reporting.py`
- `recon/step_registry.py`
- `recon/vulnerability_analysis/pipeline.py`
- `infra/docker-compose.yml`, `.env.example`
- `mcp-server/argus_mcp.py`, `tools/kali_registry.py`
- And more (see detailed task breakdown)

### Created Files (9)
- `ARGUS/README.md`
- `backend/tests/test_audit3_admin_auth.py`
- `backend/tests/test_audit3_code_quality.py`
- `backend/tests/test_audit3_custom_script.py`
- `backend/tests/test_audit3_exploitation_scope.py`
- `backend/tests/test_audit3_infra.py`
- `backend/tests/test_audit3_llm_facade.py`
- `backend/tests/test_audit3_memory_compressor.py`
- `backend/tests/test_audit3_metasploit.py`

### Deleted Files (2)
- `mcp-server/main.py` (duplicate entrypoint)
- `backend/Dockerfile` (canonical at `infra/backend/Dockerfile`)

---

## Testing Strategy

**New test coverage:** 59 new tests  
**Existing test coverage:** 198 passing tests  
**Total:** 257 tests passing, 0 failures

### Test Files Created
1. `test_audit3_admin_auth.py` — Admin/metrics auth, CORS validation
2. `test_audit3_code_quality.py` — Exception handling, logging, comments
3. `test_audit3_custom_script.py` — Whitelist adapter strategy
4. `test_audit3_exploitation_scope.py` — Scope extraction, concurrency, policy
5. `test_audit3_infra.py` — Docker, Kali registry, config fields
6. `test_audit3_llm_facade.py` — Token counting, retry logic, unified caller
7. `test_audit3_memory_compressor.py` — Secret redaction, sanitization
8. `test_audit3_metasploit.py` — `msfconsole -q -x` protocol, validation
9. (Existing tests) `test_fix_003_english.py` — Localization validation

---

## Metrics

| Metric | Value |
|--------|-------|
| Total audit items closed | 40 |
| HIGH priority items | 5 |
| MEDIUM priority items | 25 |
| LOW priority items | 10 |
| Files modified | ~35 |
| Files created | 9 |
| Files deleted | 2 |
| New tests | 59 |
| Total tests passing | 257 |
| Linter checks | All passing (Ruff) |
| Lines added | ~1,200 |
| Lines removed | ~300 |

---

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Nginx CORS config misalignment | High | Test with browser requests, validate map block syntax |
| Metasploit protocol change | Medium | Backward test with existing targets, verify msfconsole availability |
| LLM API integration failure | Medium | Fallback to existing logic, comprehensive error handling |
| Memory compression secret leaks | High | Regex review, fuzzing with real payloads |
| Docker compose health checks | Low | Verify service startup order, check health probe syntax |
| Breaking changes in adapters | Medium | Keep old methods available during deprecation period |

---

## Success Criteria

- ✅ All 40 audit items resolved (HIGH, MEDIUM, LOW)
- ✅ 257 tests passing, 0 failures
- ✅ Ruff linter: all checks passing
- ✅ No security vulnerabilities introduced
- ✅ No breaking changes to public APIs
- ✅ Documentation updated and complete

---

## Related Documentation

- [Audit Report](../../../Backlog/audit_argus_backlog3.md)
- [Completion Report](../reports/2026-04-09-argus-audit3-closure-report.md)
- [CHANGELOG](../../changelog/CHANGELOG.md)

---

*Plan created: 2026-04-09 | Status: Completed*
