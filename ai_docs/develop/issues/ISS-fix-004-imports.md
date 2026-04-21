# ISS — FIX-004 stale imports / missing cost-tracker registry helpers

**Issue ID:** ISS-fix-004-imports
**Owner:** Backend / LLM facade
**Source task:** ARG-037 (cycle 4 finalization, stale-import cleanup batch)
**Status:** **RESOLVED** in ARG-037 PR
**Priority:** MEDIUM (silent production bug behind a `try/except` swallow)
**Date filed:** 2026-04-19
**Date closed:** 2026-04-19

---

## Context

`backend/tests/test_fix_004_cost_tracking.py` (untracked scaffold left
over from a previous cycle) attempted to import three names from
`src.llm.cost_tracker`:

```python
from src.llm.cost_tracker import (
    ScanCostTracker,
    _tracker_registry,
    get_tracker,
    pop_tracker,
)
```

Only `ScanCostTracker` actually existed. The other three were never
restored after a refactor, so:

1. `pytest --collect-only` in CI raised `ImportError` for that file.
2. `src/llm/facade.py::_record_llm_cost` performs a **lazy** import of
   `get_tracker` inside a broad `try/except Exception:` block. The call
   silently fails on every LLM invocation that supplies `scan_id`, which
   means **per-scan LLM cost tracking has been a no-op since the
   refactor that dropped these helpers** — every breakdown returned by
   `GET /scans/{scan_id}/cost` shows `total_cost_usd: 0`.

```python
# src/llm/facade.py — _record_llm_cost (existing code)
try:
    from src.llm.cost_tracker import get_tracker  # ImportError → swallowed
    tracker = get_tracker(scan_id)
    tracker.record(...)
except Exception:
    logger.warning("cost_tracking_record_failed", exc_info=True)
```

`api/routers/scans.py::_cost_endpoint` then constructs a fresh empty
`ScanCostTracker(scan_id).breakdown()` as a fallback — masking the
issue from anyone who only looks at the API surface.

## Why this matters

* OWASP A09 (Security Logging & Monitoring Failures): observability
  primitive that other dashboards depend on returned wrong data.
* Budget enforcement (`MAX_COST_PER_SCAN_USD`) was effectively disabled
  for every scan that goes through the unified facade.
* Six untracked test scaffolds in `backend/tests/test_fix_*.py` failed
  collection, hiding the real signal behind noise.

## Resolution (ARG-037 PR)

1. **Restored** the three helpers in `backend/src/llm/cost_tracker.py`
   with thread-safe semantics:
   * `_tracker_registry: dict[str, ScanCostTracker]`
   * `get_tracker(scan_id, *, max_cost_usd=None) -> ScanCostTracker`
   * `pop_tracker(scan_id) -> ScanCostTracker | None`
2. **Re-exported** `get_tracker` and `pop_tracker` from
   `backend/src/llm/__init__.py` to keep the public LLM API consistent
   (`ScanCostTracker` is already exported alongside).
3. **Relocated** the test scaffold to its proper home:
   * `backend/tests/test_fix_004_cost_tracking.py` → deleted.
   * `backend/tests/unit/llm/test_cost_tracker_registry.py` → new file
     with the test suite, prefixed class names
     (`TestCostTrackerGet`, `TestCostTrackerPop`,
     `TestCostTrackerRecord`, `TestCostTrackerFacadeIntegration`)
     to comply with ISS-pytest-test-prefix-collisions.

## Verification

```powershell
# Imports clean
python -m ruff check src --select F401,F811

# New test suite passes
python -m pytest tests/unit/llm/test_cost_tracker_registry.py -q
# → 13 passed in ~1s

# No regression in facade
python -m pytest tests/ -q -k "facade or cost_tracker"
```

## Out-of-scope follow-ups

* Add a Prometheus counter on every successful `tracker.record(...)`
  call so the silent-no-op condition would have shown up earlier.
  Tracked separately as part of the observability backlog.
* Add an end-to-end test that runs a tiny LLM-driven scan and asserts
  `GET /scans/{scan_id}/cost` returns a non-zero `total_cost_usd`.
  Requires a stub LLM provider — out of scope for this cleanup.
