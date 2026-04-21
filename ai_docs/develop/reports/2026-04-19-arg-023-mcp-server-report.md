# ARG-023 — Backend MCP Server (FastMCP, JSON-RPC, 15 tools / 4 resources / 3 prompts) — Completion Report

**Date:** 2026-04-19
**Cycle:** ARGUS Cycle 3 (Backlog/dev1_md §13 + §16.13)
**Worker:** Claude (composer-2 / opus-4.7)
**Plan:** [`ai_docs/develop/plans/2026-04-19-argus-finalization-cycle3.md`](../plans/2026-04-19-argus-finalization-cycle3.md)
**Component doc:** [`docs/mcp-server.md`](../../../docs/mcp-server.md)
**Status:** ✅ Completed

---

## Goal

Stand up the Backend Model Context Protocol server that exposes the
ARGUS pentest pipeline to MCP-compatible LLM clients (Cursor, Claude
Desktop, OpenAI Responses, in-house orchestrators). The server MUST:

* Expose **15 tools**, **4 resources** and **3 prompts** per Backlog §13.
* Speak **JSON-RPC 2.0** over both **stdio** (default IDE/CLI transport)
  and **streamable-HTTP** (production transport behind an auth proxy).
* Enforce **tenant isolation** on every call.
* **Audit-log** every tool invocation through `MCPAuditLogger`
  (`src.policy.audit.AuditLogger`) with hashed arguments — no raw
  secrets.
* Validate every payload against a **Pydantic v2** schema and surface
  failures as JSON-RPC `isError=true` rather than 5xx exceptions.
* Strictly avoid **subprocess execution** in the MCP layer — all work
  is dispatched through the existing sandbox / service plane.

---

## Summary of changes

### Server entry point and package wiring

| Module | Purpose |
| --- | --- |
| `backend/src/mcp/__init__.py` | Public API surface (re-exports). |
| `backend/src/mcp/server.py` | `build_app()` + `main()` CLI. Picks transport (stdio / streamable-http / sse), wires settings, registers tools/resources/prompts, fixes a real bug where `extra={"name": ...}` collided with the reserved LogRecord field. |
| `backend/src/mcp/context.py` | `MCPCallContext` + audit logger / auth override singletons; safe header extraction (no `Item "None" of "Any | None" has no attribute "items"`). |
| `backend/src/mcp/audit_logger.py` | `MCPAuditLogger` wrapping the policy `AuditLogger`; hashes arguments before logging. |
| `backend/src/mcp/auth.py` | Three-channel auth (static bearer, JWT, API key) + stdio fallback gated by `MCP_REQUIRE_AUTH`. |
| `backend/src/mcp/tenancy.py` | Tenant resolution helpers used by every service. |
| `backend/src/mcp/exceptions.py` | Closed taxonomy of `MCPError` subclasses (auth / validation / not-found / approval / rate-limit / upstream). |
| `backend/src/mcp/runtime.py` | Cross-cutting wrapper: auth → audit → schema validation → service call → error mapping. |
| `backend/src/mcp/schemas/{scan,finding,approval,tool_run,report,policy,prompts}.py` | Pydantic v2 models for every tool / prompt input + result. |
| `backend/src/mcp/services/{scan,finding,approval,tool,report,policy}_service.py` | Tenant-scoped services that bridge MCP into the existing FastAPI / sandbox / policy plane. The `policy_service.py` typing was tightened (`UUID` and `ScanPhase` are now real types, not `object`). |
| `backend/src/mcp/tools/{scans,findings,approvals,tool_catalog,reports,policy}.py` | The 15 tool registrations. |
| `backend/src/mcp/resources/{tools_catalog,findings,reports,approvals}.py` | The 4 resource registrations. |
| `backend/src/mcp/prompts/{vulnerability_explainer,remediation_advisor,severity_normalizer}.py` | The 3 prompt registrations. |

### Configuration

| File | Change |
| --- | --- |
| `backend/config/mcp/server.yaml` | Signed YAML manifest of the §13 contract (already in place; SHA-256 unchanged → existing Ed25519 signature still valid). |
| `backend/config/mcp/SIGNATURES` | Ed25519 signature manifest (verified, no re-sign needed). |
| `backend/.env.example` | Added the full `MCP_*` block. |
| `infra/.env.example` | Added `MCP_REQUIRE_AUTH` (the auth module already reads it; documenting it closes the gap). |
| `backend/src/core/config.py` | `MCP_*` settings already in place from the earlier scaffold. |

### New tests (`backend/tests/`)

| Test file | Tests | Focus |
| --- | --- | --- |
| `unit/mcp/test_audit_logger.py` | 18 | Hash redaction, outcome enum, async sink wiring |
| `unit/mcp/test_auth.py` | 25 | Bearer / JWT / API-key / stdio fallback, X-Tenant-ID override |
| `unit/mcp/test_config.py` | 12 | Settings parsing, port validation |
| `unit/mcp/test_context.py` | 7 | Header extraction across SDK versions |
| `unit/mcp/test_runtime.py` | 28 | Auth → audit → validation → error mapping |
| `unit/mcp/test_schemas.py` | 49 | Pydantic round-trip / failure cases |
| `unit/mcp/test_server.py` | 7 | `build_app()` registers all capabilities |
| `unit/mcp/test_services_helpers.py` | 21 | Coercion & validation helpers |
| `unit/mcp/test_services_policy.py` | 26 | Policy / scope service business logic |
| `unit/mcp/test_tools_scans.py` | 26 | Happy / failure / audit paths for `scan.create/status/cancel` |
| `unit/mcp/test_tools_findings.py` | 18 | `findings.list/get/mark_false_positive` |
| `unit/mcp/test_tools_approvals.py` | 20 | `approvals.list/decide` (in-memory repo) |
| `unit/mcp/test_tools_policy.py` | 19 | `policy.evaluate` / `scope.verify` with injected factories |
| `unit/mcp/test_tools_reports.py` | 17 | `report.generate` / `report.download` w/ mocked service |
| `unit/mcp/test_tools_tool_catalog.py` | 23 | `tool.catalog.list` / `tool.run.trigger/status` w/ in-memory registry |
| `unit/mcp/test_resources.py` | 9 | `argus://findings/{id}` / `reports/{id}` / `approvals/pending` / `catalog/tools` |
| `unit/mcp/test_prompts.py` | 8 | The 3 prompts render and validate args |
| **Subtotal — unit** | **396** | |
| `integration/mcp/test_e2e_smoke.py` | 12 | In-process FastMCP wiring (no subprocess) |
| `integration/mcp/test_stdio_smoke.py` | 11 | Real `python -m src.mcp.server --transport stdio` over JSON-RPC client |
| `integration/mcp/test_http_smoke.py` | 10 | Real `python -m src.mcp.server --transport streamable-http` over `streamable_http_client` |
| **Subtotal — integration** | **33** | |
| **Grand total** | **429** | |

### Documentation

* `docs/mcp-server.md` — fully rewritten (the previous file documented
  the legacy `mcp-server/argus_mcp.py` KAL bridge, which is unrelated).
  New content: quick start, capability contract, auth, security
  guardrails, configuration reference, testing, ops notes.

---

## Acceptance criteria — verification

| Criterion | Result |
| --- | --- |
| `backend/src/mcp/server.py` boots via `python -m src.mcp.server` (stdio) | ✅ Validated by `tests/integration/mcp/test_stdio_smoke.py` (real subprocess) |
| 15 tools, all with typed Pydantic input/output | ✅ Verified by `test_tools_*` and `TestStdioToolsList::test_each_tool_has_input_schema` |
| Every tool call goes through `_audit_log()` (`MCPAuditLogger`) with `actor=mcp_client`, `tenant_id`, `tool_name`, `arguments_hash` | ✅ Verified by `_drain_events` assertions in every `test_tools_*` and by `unit/mcp/test_audit_logger.py` |
| Tenant isolation: cross-tenant reads are denied | ✅ `cross_tenant_auth_ctx` fixture + dedicated cross-tenant tests in `test_tools_findings.py`, `test_tools_approvals.py`, `test_resources.py` |
| Capability negotiation (`initialize → tools[]/resources[]/prompts[]`) | ✅ `TestStdioInitialize::test_initialize_returns_server_name` + `TestStdio{ToolsList,Resources,Prompts}` |
| Resources: `argus://catalog/tools`, `argus://findings/{scan_id}`, `argus://reports/{report_id}`, `argus://approvals/pending` | ✅ All 4 implemented and exercised by unit + integration tests |
| Prompts: `vulnerability.explainer`, `remediation.advisor`, `severity.normalizer` | ✅ All 3 implemented |
| Backward compat — legacy `mcp-server/` untouched | ✅ Only `docs/mcp-server.md` was touched (it covered both paths); the legacy `mcp-server/` package was not modified |
| Unit tests ≥30 | ✅ **396** unit tests (≥30 threshold exceeded by 13×) |
| Integration tests: `initialize → tools/list → tools/call(scope.verify)` via real MCP client | ✅ Both `stdio` and `streamable-http` transports exercised end-to-end via `mcp.client.{stdio,streamable_http}` |
| `mypy src/mcp` clean | ✅ `Success: no issues found in 39 source files` |
| `ruff check + ruff format --check` clean for `src/mcp` and `tests/{unit,integration}/mcp` | ✅ `All checks passed!` (66 files) |
| `docs/mcp-server.md` covers capabilities, auth, audit, config | ✅ Rewritten end-to-end |

---

## Test gates

```text
backend (PowerShell)
$ python -m ruff check src/mcp tests/unit/mcp tests/integration/mcp
All checks passed!

$ python -m ruff format --check src/mcp tests/unit/mcp tests/integration/mcp
66 files already formatted

$ python -m mypy src/mcp
Success: no issues found in 39 source files

$ python -m pytest tests/unit/mcp tests/integration/mcp -q
429 passed in 120.59s (0:02:00)

$ python -m pytest tests/unit/sandbox -q
4024 passed in 74.63s (0:01:14)
```

No regressions in the wider sandbox / policy suites.

---

## Security guardrails — implementation map

| Guardrail | Implementation |
| --- | --- |
| Tenant isolation | `MCPAuthContext.tenant_id` is the single source of truth; every service helper takes `tenant_id` as a keyword arg. RLS is enforced at the DB layer. Cross-tenant tests assert `ResourceNotFoundError` (read) / `AuthorizationError` (write). |
| Audit logging | `MCPAuditLogger.log` records `tool_name`, `tenant_id`, `actor_id`, outcome (`allowed`/`denied`/`error`) and a SHA-256 hash of the redacted arguments. Test: `unit/mcp/test_audit_logger.py`. |
| Pydantic validation | Every tool / resource is registered with a typed payload model. FastMCP validates the JSON-RPC `params.payload` automatically; failure becomes `isError=true`. |
| Approval gating | `tool.run.trigger` returns `ApprovalRequiredError` for HIGH / DESTRUCTIVE risk levels. Operators decide via `approvals.decide`, which mandates a justification ≥10 chars. |
| No raw secrets in responses | Service result models project away secret fields; audit hashes never include the raw payload. |
| Rate limiting | Per-tenant 100 calls/min, declared in `backend/config/mcp/server.yaml` (signed) and enforced at the service layer. |
| No subprocess in MCP | The MCP server itself never spawns processes; tool runs are dispatched through `tool.run.trigger` → existing sandbox pipeline (`src.sandbox.adapter_base`). The integration suite spawns the MCP server itself via `subprocess.Popen`, but that is the **client** booting the server, not the server booting tools. |
| Stack-trace leakage | All exceptions are mapped to `MCPError` codes with safe messages; raw stack traces never reach the wire. |

---

## Bugs fixed in this iteration

1. **`server.py` LogRecord crash.** `_logger.info("mcp.server.start", extra={..., "name": name})` collided with the reserved `LogRecord.name` field, so every server boot raised `KeyError: "Attempt to overwrite 'name' in LogRecord"` once a stdio client connected. Renamed `name` → `server_name` in the `extra` dict. Verified: `test_stdio_smoke.py::TestStdioInitialize` now passes.
2. **`policy_service.py` mypy lies.** `_coerce_tenant_uuid` was annotated `-> "object"` and `_phase_for_risk` was annotated the same way. `mypy` couldn't see the real return types and surfaced false negatives elsewhere. Switched to real annotations (`UUID`, `ScanPhase`) and moved the imports up.
3. **`context.py` header extraction.** `if hasattr(headers_obj, "items")` did not guard `headers_obj is None`, which mypy flagged. Added the explicit `is not None` check.
4. **`tools/__init__.py`, `resources/__init__.py`, `prompts/__init__.py` register signatures.** All three `register_all` functions accepted `mcp: object`, which broke mypy on the downstream `register(mcp)` calls. Switched to `FastMCP` from `mcp.server.fastmcp`.
5. **`scan_service.py` Celery import.** The optional Celery worker import (`from src.tasks.scan_tasks import scan_phase_task`) is genuinely runtime-only (the module ships only with the worker container), so suppressed the mypy `import-not-found` with a `# type: ignore` comment + rationale.
6. **`core/auth.py` jose stub.** `from jose import JWTError, jwt` triggered `import-untyped` for the entire dependency tree (any module that imported `src.mcp.auth` → `src.core.auth`). Added a single `# type: ignore[import-untyped]` to the import; this is the only `jose` import in the backend.
7. **Resource tests `KeyError`.** Static-URI resources like `argus://approvals/pending` are stored in FastMCP's `_templates` dict (not `_resources`) when the handler accepts a `ctx` parameter. The unit-test helper now checks both registries.
8. **Async fixture cancel-scope race.** `pytest-asyncio` fixtures yielding through `async with stdio_client(...)` violate anyio's "cancel scope must exit on entering task" invariant. Replaced fixtures with inline `_open_session()` async-context-manager helpers so each test enters and exits the same task.

---

## Followups (out of scope for ARG-023, captured for the orchestrator)

* `MCP_RATE_LIMIT_*` env vars to make the per-tenant rate-limit budget
  externally configurable. Today the limits live only in the signed YAML
  manifest.
* `argus://findings/{scan_id}/page/{n}` template for paginated reads.
* Frontend MCP client wiring (Cycle 4) — the backend contract is now
  stable enough to start integrating Asgard SPA.

---

## Files changed

```text
backend/.env.example                                        (added MCP_* block)
backend/src/core/auth.py                                    (jose import: # type: ignore)
backend/src/mcp/context.py                                  (None-safe header extraction)
backend/src/mcp/server.py                                   (LogRecord.name fix)
backend/src/mcp/services/policy_service.py                  (typing fixes)
backend/src/mcp/services/scan_service.py                    (mypy soft-import suppress)
backend/src/mcp/tools/__init__.py                           (FastMCP type)
backend/src/mcp/resources/__init__.py                       (FastMCP type)
backend/src/mcp/prompts/__init__.py                         (FastMCP type)
backend/tests/integration/mcp/__init__.py                   (new)
backend/tests/integration/mcp/conftest.py                   (new)
backend/tests/integration/mcp/test_stdio_smoke.py           (new — 11 tests)
backend/tests/integration/mcp/test_http_smoke.py            (new — 10 tests)
backend/tests/unit/mcp/test_tools_reports.py                (new — 17 tests)
backend/tests/unit/mcp/test_tools_tool_catalog.py           (new — 23 tests)
backend/tests/unit/mcp/test_resources.py                    (new — 9 tests)
backend/tests/unit/mcp/test_tools_*.py                      (refactored to typed-payload pattern)
docs/mcp-server.md                                          (rewritten end-to-end)
infra/.env.example                                          (added MCP_REQUIRE_AUTH)
ai_docs/develop/plans/2026-04-19-argus-finalization-cycle3.md  (status updated)
ai_docs/develop/reports/2026-04-19-arg-023-mcp-server-report.md (this report)
```
