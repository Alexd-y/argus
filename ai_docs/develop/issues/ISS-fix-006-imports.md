# ISS — FIX-006 stale imports across `src/recon/`, `src/sandbox/`, `src/dedup/`

**Issue ID:** ISS-fix-006-imports
**Owner:** Backend / Recon + Sandbox parsers
**Source task:** ARG-037 (cycle 4 finalization, stale-import cleanup batch)
**Status:** **RESOLVED** in ARG-037 PR
**Priority:** LOW (lint hygiene; no runtime impact)
**Date filed:** 2026-04-19
**Date closed:** 2026-04-19

---

## Context

`ruff check src --select F401,F811` reported **17 unused imports**
across the production tree, plus a stale test scaffold under
`backend/tests/test_fix_006_recon.py` that imported two recon helpers
which no longer exist (`_extract_ssl_info`,
`_extract_outdated_components` from `src.recon.summary_builder`).

### Affected files (production)

| File | Unused symbol |
| --- | --- |
| `src/dedup/llm_dedup.py` | `dataclasses.field` |
| `src/recon/exploitation/input_loader.py` | `app.schemas.vulnerability_analysis.exploitation_candidates.ExploitationCandidate` |
| `src/recon/exploitation/pipeline.py` | `app.schemas.exploitation.models.ExploitationPlan` |
| `src/recon/reporting/intel_builder.py` | `json`, `datetime.UTC`, `datetime.datetime`, `pathlib.Path` |
| `src/recon/schemas/job.py` | `src.recon.schemas.base.ReconStage` |
| `src/recon/schemas/scope.py` | `netaddr.IPNetwork` |
| `src/recon/services/target_service.py` | `sqlalchemy.func`, `src.db.models_recon.NormalizedFinding`, `src.db.models_recon.ScanJob` |
| `src/sandbox/parsers/amass_passive_parser.py` | `collections.abc.Iterable` |
| `src/sandbox/parsers/chrome_csp_probe_parser.py` | `src.sandbox.parsers._base.SENTINEL_CVSS_VECTOR` |
| `src/sandbox/parsers/dnsrecon_parser.py` | `collections.abc.Iterable`, `src.sandbox.parsers._base.SENTINEL_CVSS_VECTOR` |
| `src/sandbox/parsers/fierce_parser.py` | `src.sandbox.parsers._base.SENTINEL_CVSS_VECTOR` |

All 17 entries are pure leftovers (no consumer module imports them
through the affected file — verified via repo-wide grep). The shared
`SENTINEL_CVSS_VECTOR` re-export through `src/sandbox/parsers/__init__.py`
remains intact.

### Affected file (tests)

`backend/tests/test_fix_006_recon.py` imported and tested two helpers
that were removed when `src/recon/summary_builder.py` was refactored to
return empty `ssl_info` / `outdated_components` lists in
`build_recon_summary_document(...)`. The third class in the same file
(`TestVaFallbackUnknownTask`) duplicated existing coverage in
`backend/tests/test_bkl_va_fallback.py::TestBuildVaFallbackOutputOtherTasks::test_unknown_task_returns_structured_fallback`
with weaker assertions.

## Why this matters

* `ruff` runs in CI; even though `F401`/`F811` are not failure-grade by
  policy today, every drift accumulates noise that hides real signal.
* The unused `pathlib.Path`, `datetime`, `json`, `IPNetwork` imports
  loaded modules at import time for no reason — minor cold-start cost.
* The broken test scaffold blocked clean `pytest --collect-only` runs
  on the local dev workstation.

## Resolution (ARG-037 PR)

1. Removed all 17 unused imports via `ruff check src --select F401,F811 --fix`.
2. Verified each removal manually: no symbol is re-exported from any
   `__init__.py` that would have lost coverage.
3. Deleted `backend/tests/test_fix_006_recon.py` (broken + redundant).

## Out-of-scope follow-ups

* Implement `_extract_ssl_info` / `_extract_outdated_components` in
  `src/recon/summary_builder.py` so the `ssl_info` and
  `outdated_components` keys actually carry data extracted from
  `testssl`, `httpx --tls`, and `whatweb` outputs. The scaffold in the
  deleted test file documented sensible behaviour and can be revived
  once the implementations land. Tracked as part of the recon-summary
  enrichment backlog.

## Verification

```powershell
python -m ruff check src --select F401,F811
# → All checks passed!
```
