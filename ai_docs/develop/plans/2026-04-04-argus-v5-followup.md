# ARGUS v5-followup — plan mirror

**Orchestration:** `orch-argus-v5-followup`  
**Canonical plan (absolute):** `d:\Developer\Pentest_test\.cursor\workspace\active\orch-argus-v5-followup\plan.md`  
**Spec:** `ARGUS/argus_v5_followup_cursor_prompt.md`  

## Tasks T01–T10 (one cycle, max 10)

| ID | Blocks | Summary |
|----|--------|---------|
| T01 | 1 | Docstrings/comments (14 edits) |
| T02 | 2 | Auth + admin secure-by-default |
| T03 | 3 | PoC `_run_poc_safe` |
| T04 | 4 | Data sources ×4 |
| T05 | 5 | Security adapters ×5 |
| T06 | 6 | `va_http_audit` rename |
| T07 | 7 | New endpoints ×4 |
| T08 | 8 | MCP tools + `argus-mcp.json` + `argus-mcp.md` |
| T09 | 9 | All spec tests |
| T10 | policy | Wording grep / ARGUS scope; legacy → **orch-argus-v5-followup-2** |

## Deferred to cycle 2

Repo-wide cleanup of forbidden wording outside ARGUS deliverable paths; unrelated legacy strings.

## Strict wording policy (summary)

Delivered source must follow the **Strict wording policy** in canonical `plan.md`: no unfinished-work markers or early-phase product labels, except the reporting template key ``tier_stubs`` (tier section hints, not an API placeholder).
