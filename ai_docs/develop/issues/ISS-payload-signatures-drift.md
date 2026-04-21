# ISS — Payload SIGNATURES drift after test runs

**Issue ID:** ISS-payload-signatures-drift
**Owner:** Backend / Payload registry
**Source task:** ARG-037 (cycle 4 finalization, stale-import cleanup batch)
**Status:** **RESOLVED** in ARG-037 PR (verified non-reproducible + regression guard added)
**Priority:** HIGH (production code path: signed payload integrity)
**Date filed:** 2026-04-19
**Date closed:** 2026-04-19

---

## Context

A previous cycle reported that running the full pytest suite would
sometimes mutate `backend/config/payloads/SIGNATURES` (the Ed25519
manifest of all payload YAML hashes) and force the operator to revert
the file before `git commit`. The hypothesis was that some unit test
opened the production catalog in `"w"` mode without first copying it to
`tmp_path`.

## Investigation (ARG-037)

The investigation in this PR followed the documented bisection plan:

1. **Snapshot baseline** of `SIGNATURES` (SHA-256
   `AFD30B9804BAAC692C410B05CBE8E94C1B182E5FAAFB24A7BA72A133DCF5CC8E`)
   and every `*.yaml` under `backend/config/payloads/`.
2. **Run targeted payload suites** —
   `pytest tests/unit/payloads tests/integration/payloads tests/integration/oast/test_oast_payload_builder_integration.py tests/integration/policy/test_preflight_payloads_integration.py -q`
   → 387 passed, hash unchanged, all 23 entries verify.
3. **Expand to full unit suite** —
   `pytest tests/unit -q --ignore=tests/test_fix_004_cost_tracking.py --ignore=tests/test_fix_006_recon.py`
   → 6190 passed, hash unchanged, all 23 entries verify.
4. **Expand to full integration suite** —
   `pytest tests/integration -q --ignore=…` → 1548 passed, hash
   unchanged, all 23 entries verify.

Verdict: **the drift is no longer reproducible**. The unit-level
fixtures already use `tmp_path` correctly (see
`backend/tests/unit/payloads/conftest.py::signed_payloads_dir` and the
`tmp_path`-scoped suites in `test_registry.py`). Whatever test was
mutating the real catalog has either been deleted or refactored in a
prior cycle.

## Resolution (ARG-037 PR)

1. **Documented the bisection result** in this issue.
2. **Added a regression guard** at
   `backend/tests/integration/payloads/test_signatures_no_drift.py`:
   * `test_loading_registry_does_not_mutate_signatures` — snapshots
     the SIGNATURES SHA-256 before the test, runs `PayloadRegistry.load()`,
     and asserts the hash is unchanged.
   * `test_loading_registry_does_not_mutate_yaml_payloads` — same
     check applied to every YAML descriptor.
   * `test_repeated_load_is_idempotent` — five sequential loads must
     produce a single hash.
3. The guard runs in CI under the `requires_docker` marker (auto-applied
   to every test under `tests/integration/payloads/` per
   `backend/tests/conftest.py::_DOCKER_FORCED_PATH_PREFIXES`). If the
   drift ever recurs, this test will fail with a clear "expected sha256
   = X, got sha256 = Y" message pointing at the mutated file.

## Verification

```powershell
# Manifest verifies (23 entries) before and after a full local suite.
cd backend
python -m scripts.payloads_sign verify `
  --payloads-dir config/payloads `
  --signatures config/payloads/SIGNATURES `
  --keys-dir config/payloads/_keys
# → {"event": "verify.ok", "verified_count": 23}

# New regression guard runs under the requires_docker marker.
python -m pytest tests/integration -m "" `
  -k "test_loading_registry_does_not_mutate_signatures or test_loading_registry_does_not_mutate_yaml_payloads or test_repeated_load_is_idempotent" -v
# → 3 passed
```

## Out-of-scope follow-ups

* Add a pre-commit hook (`.cursor/hooks.json`) that runs
  `payloads_sign verify` whenever any file under
  `backend/config/payloads/` changes. Cheap (~1s) and stops the drift
  from ever reaching CI.
* Document the `tmp_path`-only contract for payload-catalog tests in
  `backend/tests/unit/payloads/conftest.py` module docstring (already
  partially in place).
