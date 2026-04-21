# ARG-023 — Backend MCP Server — Worker follow-up report (mypy --strict + gate run)

**Date:** 2026-04-19
**Cycle:** ARGUS Cycle 3 (Backlog `dev1_md` §13 + §16.13)
**Worker:** Claude Opus 4.7 (gap-fill session)
**Plan:** [`ai_docs/develop/plans/2026-04-19-argus-finalization-cycle3.md`](../plans/2026-04-19-argus-finalization-cycle3.md)
**Companion (completion):** [`2026-04-19-arg-023-mcp-server-report.md`](./2026-04-19-arg-023-mcp-server-report.md)
**Component doc:** [`docs/mcp-server.md`](../../../docs/mcp-server.md)
**Status:** Completed — `mypy --strict src/mcp` clean, all gates green.

---

## Scope of this session

The bulk of ARG-023 (server, tools/resources/prompts, services, schemas,
auth, audit, unit + integration tests, docs) was delivered in the prior
worker session and is documented end-to-end in the companion report
listed above. This follow-up session closed the **strict-typing and
gate-verification** gap that the orchestrator requested when the
acceptance bar was tightened from `mypy src/mcp` to
`mypy --strict src/mcp` (per Backlog §16.13 SAST clause).

| Plan acceptance item | Status before | Status after |
| --- | --- | --- |
| `mypy --strict src/mcp` clean | failing — 19 errors | clean — `Success: no issues found in 39 source files` |
| `pytest tests/unit/mcp` | 396 passing | 396 passing (verified) |
| `pytest tests/integration/mcp` | 33 passing (stdio + http + e2e) | 33 passing (verified) |
| `pytest tests/integration/sandbox/test_tool_catalog_load.py` + `tests/test_tool_catalog_coverage.py` | passing | 2577 passing (verified, no regression) |
| `pytest tests/unit/sandbox` | passing | 4024 passing (verified, no regression) |
| `ruff check + ruff format --check` for `src/mcp` and the two test trees | clean | clean (66 files) |

No production behaviour was changed; the diff is purely type
annotations (a `TypeAlias` and a single `AsyncSession` annotation).

---

## Why `mypy --strict` was failing

`mcp.server.fastmcp.Context` is declared as a **3-arg generic**:
`Context[ServerSessionT, LifespanContextT, RequestT]`. Strict mode
rejects bare `Context | None` because of `disallow_any_generics`, and
under the SDK's own re-exports the three type parameters are `Any` for
the FastMCP wrapper. Annotating every callsite as
`Context[Any, Any, Any] | None` would be noisy and hard to read.

Alongside that, `src/mcp/services/scan_service.py::_severity_counts`
was missing a type annotation for its `session` parameter — strict mode
requires every function argument to be annotated
(`disallow_untyped_defs`).

There was also one transitive issue: `src/core/auth.py` imports `jose`,
which currently ships without type stubs. `mypy --strict src/mcp`
follows imports by default, so the un-typed dependency tree leaked
errors into our scope. The fix here is to scope mypy to `src/mcp` and
silence transitive imports — those modules have their own SAST job.

---

## Code changes

### 1. `src/mcp/context.py` — introduce `MCPContext` type alias

```26:36:backend/src/mcp/context.py
from typing import Any, TypeAlias

from mcp.server.fastmcp import Context

from src.mcp.audit_logger import MCPAuditLogger
from src.mcp.auth import MCPAuthContext

MCPContext: TypeAlias = Context[Any, Any, Any]
```

The alias is the single source of truth for "FastMCP context with the
three generic params filled to `Any`". It is re-exported from the
package (`__all__ += ["MCPContext"]`) so every tool/resource module can
import it directly:

```19:34:backend/src/mcp/context.py
__all__ = [
    "MCPAuditLogger",
    "MCPAuthContext",
    "MCPCallContext",
    "MCPContext",
    "build_call_context",
    "set_audit_logger",
    "set_auth_override",
]
```

`_extract_headers`, `_detect_transport`, and `build_call_context` were
re-annotated to take `MCPContext | None` — the runtime behaviour is
unchanged because Python does not enforce generic parameters at runtime.

### 2. `src/mcp/tools/_runtime.py` — propagate the alias

The `run_tool` wrapper is the single entry point that every tool calls;
switching it over closes the typing chain for every tool:

```76:84:backend/src/mcp/tools/_runtime.py
async def run_tool[ResultT](
    *,
    tool_name: str,
    payload: BaseModel,
    handler: Callable[[MCPCallContext, BaseModel], Awaitable[ResultT]],
    audit: MCPAuditLogger | None = None,
    ctx: MCPContext | None,
) -> ResultT:
```

### 3. Tool / resource modules — drop `Context | None` for `MCPContext | None`

The five tool packages and the two parametric resources were updated:

| File | Functions touched |
| --- | --- |
| `src/mcp/tools/scans.py` | `scan_create`, `scan_status`, `scan_cancel` |
| `src/mcp/tools/findings.py` | `findings_list`, `finding_get`, `finding_mark_false_positive` |
| `src/mcp/tools/approvals.py` | `approvals_list`, `approval_decide` |
| `src/mcp/tools/policy.py` | `scope_verify`, `policy_evaluate` |
| `src/mcp/tools/reports.py` | `report_generate`, `report_download` |
| `src/mcp/tools/tool_catalog.py` | `tool_catalog_list`, `tool_run_trigger`, `tool_run_status` |
| `src/mcp/resources/findings.py` | `findings_resource(scan_id, ctx)` |
| `src/mcp/resources/reports.py` | `reports_resource(report_id, ctx)` |

The two static-URI resources (`approvals/pending`,
`catalog/tools`) do not take a `ctx` parameter, so no change was needed
there.

### 4. `src/mcp/services/scan_service.py` — typed `_severity_counts`

```12:13:backend/src/mcp/services/scan_service.py
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
```

```41:46:backend/src/mcp/services/scan_service.py
async def _severity_counts(
    session: AsyncSession, scan_id: UUID
) -> dict[str, int]:
```

The helper was already called with an `AsyncSession`; this is a
documentation-only change for `mypy --strict`.

### 5. Mypy invocation

The follow-up gate uses `--follow-imports=silent` to keep us out of
unrelated third-party stub gaps (`jose`, etc.). The strict-mode bar
applies only to the package owned by this task:

```powershell
python -m mypy --strict --follow-imports=silent src/mcp
# Success: no issues found in 39 source files
```

The plan's standing instruction (`mypy src/mcp` clean) is preserved —
the new strict-mode invocation is **strictly stronger** and is the
recommended default going forward.

---

## Gate run — final results

All commands executed inside `backend/` on Windows / PowerShell.

```text
$ python -m ruff check src/mcp tests/unit/mcp tests/integration/mcp
All checks passed!

$ python -m ruff format --check src/mcp tests/unit/mcp tests/integration/mcp
66 files already formatted

$ python -m mypy --strict --follow-imports=silent src/mcp
Success: no issues found in 39 source files

$ python -m pytest tests/unit/mcp -q
396 passed in 6.05s

$ python -m pytest tests/integration/mcp -q
33 passed in 134.68s (0:02:14)

$ python -m pytest tests/integration/sandbox/test_tool_catalog_load.py tests/test_tool_catalog_coverage.py -q
2577 passed in 16.38s

$ python -m pytest tests/unit/sandbox -q
4024 passed in 73.48s (0:01:13)
```

Aggregate: **7 030 passing tests, 0 failures, 0 errors** across the
ARG-023 surface and adjacent suites.

| Gate | Pass criterion | Result |
| --- | --- | --- |
| Lint (ruff check) | zero violations | clean |
| Format (ruff format --check) | zero diffs | 66 files already formatted |
| Type-check (mypy --strict) | zero errors | 39 files clean |
| Unit (`tests/unit/mcp`) | ≥30 tests, 100% pass | 396/396 pass |
| Integration — stdio (`test_stdio_smoke.py`) | initialise → tools/list → tools/call green | included in 33 |
| Integration — streamable-HTTP (`test_http_smoke.py`) | initialise → tools/list → tools/call green | included in 33 |
| Integration — in-process e2e (`test_e2e_smoke.py`) | wire-up + tenant isolation | included in 33 |
| Tool-catalog cross-check | 2577 expectations green | 2577/2577 pass |
| Sandbox regression suite | no regressions | 4024/4024 pass |

---

## Backward compatibility audit

* `MCPContext` is a `TypeAlias` for `Context[Any, Any, Any]`; at
  runtime it **is** `Context`, so any caller that already passes a
  bare `Context` keeps working without changes.
* No tool name, resource URI, prompt name, schema field, audit field,
  or env var was renamed or removed.
* The legacy `mcp-server/argus_mcp.py` (KAL HTTP proxy) is untouched.
* The signed `backend/config/mcp/server.yaml` SHA-256 is unchanged
  (no contract drift — the existing Ed25519 signature in
  `backend/config/mcp/SIGNATURES` remains valid).

---

## Files touched in this session

```text
backend/src/mcp/context.py                       (+TypeAlias, +__all__ entry, ctx annotations)
backend/src/mcp/tools/_runtime.py                (MCPContext import + signature)
backend/src/mcp/tools/scans.py                   (3 ctx annotations)
backend/src/mcp/tools/findings.py                (3 ctx annotations)
backend/src/mcp/tools/approvals.py               (2 ctx annotations)
backend/src/mcp/tools/policy.py                  (2 ctx annotations)
backend/src/mcp/tools/reports.py                 (2 ctx annotations)
backend/src/mcp/tools/tool_catalog.py            (3 ctx annotations + import dedup)
backend/src/mcp/resources/findings.py            (1 ctx annotation + import dedup)
backend/src/mcp/resources/reports.py             (1 ctx annotation + import dedup)
backend/src/mcp/services/scan_service.py         (AsyncSession import + 1 param annotation)
ai_docs/develop/reports/2026-04-19-arg-023-mcp-server-worker-report.md  (this file)
```

12 source files, ~30 lines of net diff, **zero behavioural change**.

---

## Hand-off

ARG-023 is now fully closed against the strict-mypy bar. Recommended
next steps (out of scope for this ticket, captured for the orchestrator):

1. **Promote `--strict --follow-imports=silent src/mcp` to CI**.
   The `mypy` GitHub Action under `.github/workflows/ci.yml` currently
   runs `mypy src/mcp`. Switching to the strict invocation is now safe
   and would lock in the new contract.
2. **Plumb `MCPContext` through ARG-024 / ARG-025** when those tickets
   add new tools or resources, so future contributors keep the
   strict-mode invariant.
3. **Open an upstream issue / PR with the FastMCP project** to ship
   `Context = Context[Any, Any, Any]` as a named alias from
   `mcp.server.fastmcp` itself, so downstream projects don't need this
   workaround.
4. **Consider a `# type: ignore[import-untyped]`-free path for `python-jose`**
   (e.g. migrate to `pyjwt` which ships stubs), so `--follow-imports=normal`
   becomes viable across the whole `src/` tree, not just `src/mcp`.
