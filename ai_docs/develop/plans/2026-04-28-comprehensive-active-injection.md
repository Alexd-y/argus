# Plan: Comprehensive active injection testing (backend)

**Created:** 2026-04-28  
**Orchestration:** `orch-2026-04-28-12-00-active-injection`  
**Status:** Ready to execute  

## Goal

Upgrade backend **comprehensive active injection testing**: `active_scan`, vulnerability analysis (VA), MCP policy, configuration, payloads, reports, quality gate, and tests — **without** Frontend changes and **preserving** the existing API contract.

## Safety (non-negotiable)

- Do **not** allow unrestricted OS-shell, bulk data-dump, brute-force, or exfiltration paths.
- Destructive or high-risk tools **fail closed** unless **signed approval** (existing approval flags / tenant policy) permits them.
- **No AI-invented destructive payload strings** on the execution path; LLM planning may suggest tool IDs only where already constrained by allowlists.
- **`safe_active`** (or equivalent scan mode) is the **default** for broad pentests; stricter modes opt-in.

## Phase 1 — Policy, quality gate, report hooks, tests (max 8 tasks)

| ID | Task | Priority | Depends on | Primary areas |
|----|------|----------|------------|-----------------|
| ACT-001 | MCP policy: destructive fail-closed + approval gate | Critical | — | MCP tool policy, sandbox execute guards |
| ACT-002 | Config & `safe_active` scan_mode defaults | High | ACT-001 | `settings`, scan options, env templates |
| ACT-003 | Payload library: curated sets; block LLM output as executable | High | ACT-001 | Payload modules, planner → executor boundary |
| ACT-004 | active_scan dispatch: enforce policy before sandbox/MCP | Critical | ACT-001–003 | `va_active_scan_phase`, planner, sandbox runner |
| ACT-005 | VA pipeline hooks (handlers + phase alignment) | High | ACT-004 | `orchestration/handlers.py`, VA bundle merge |
| ACT-006 | Quality gate: pre/post active injection checks | High | ACT-004 | Scan phase transitions, gating signals |
| ACT-007 | Report hooks: active injection metadata & evidence | Medium | ACT-005, ACT-006 | Report builders, raw artifacts refs |
| ACT-008 | Tests: contract-safe API + policy + fail-closed paths | High | ACT-007 | Pytest, existing contract tests pattern |

### Dependency graph (Phase 1)

```
ACT-001 ──┬──► ACT-002 ──┐
          └──► ACT-003 ──┼──► ACT-004 ──┬──► ACT-005 ──┐
                         │              └──► ACT-006 ──┼──► ACT-007 ──► ACT-008
```

### Reference modules (indicative)

- `backend/src/recon/vulnerability_analysis/active_scan/va_active_scan_phase.py`
- `backend/src/recon/vulnerability_analysis/active_scan_planner.py`, `active_scan/planner.py`
- `backend/src/orchestration/handlers.py` (VA / `run_vuln_analysis`)
- Sandbox / MCP policy modules used by `run_va_active_scan` and execute endpoints

## Phase 2 — Full tool parsers

| ID | Task | Depends on |
|----|------|------------|
| ACT-P2-001 | Tool parser framework (stdout/stderr → normalized events) | ACT-008 |
| ACT-P2-002 | Full tool parsers rollout + finding schema merge/dedup | ACT-P2-001 |

## Acceptance (Phase 1)

- Default scan behavior remains **safe_active**-aligned; dangerous capabilities require explicit approval + config.
- Contract tests and public API shapes **unchanged** from Frontend expectations (`docs/api-contracts.md`).
- Automated tests cover: policy denial, approval path, and absence of executable LLM payload strings.

## Progress (orchestrator)

Tracked in `.cursor/workspace/active/orch-2026-04-28-12-00-active-injection/tasks.json`.
