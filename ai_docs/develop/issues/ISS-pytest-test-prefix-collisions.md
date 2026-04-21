# ISS — `Test*` class name collisions across the test suite

**Issue ID:** ISS-pytest-test-prefix-collisions
**Owner:** Backend / Test infrastructure
**Source task:** ARG-037 (cycle 4 finalization, stale-import cleanup batch)
**Status:** **RESOLVED** in ARG-037 PR
**Priority:** LOW (cosmetic + reporting hygiene; pytest tolerates collisions but reports get noisy)
**Date filed:** 2026-04-19
**Date closed:** 2026-04-19

---

## Context

`pytest` collects tests by file but reports them by qualified name
(e.g. `tests/.../test_foo.py::TestBar::test_baz`). When two unrelated
modules both declare `class TestBar`, the qualified names share the
same class fragment which:

1. Confuses IDE "run this test" affordances that index by class name.
2. Breaks naive grep-based filtering (`pytest -k TestBar` runs both).
3. Hides selection ambiguity in JUnit XML reports consumed by CI
   dashboards.

A repo-wide scan turned up **11 distinct collisions** across **23
files**:

| Class name | Files |
| --- | --- |
| `TestAdapterRegistry` | `tests/test_exploitation_adapters.py`, `tests/test_recon_adapters.py` |
| `TestApprovalRequest` | `tests/test_exploitation_schemas.py`, `tests/unit/policy/test_approval.py` |
| `TestAssertAllowed` | `tests/unit/policy/test_preflight.py`, `tests/unit/policy/test_scope.py` |
| `TestDeterminism` | `tests/test_junit_generator.py`, `tests/test_report_service.py`, `tests/test_sarif_generator.py` |
| `TestFullPipeline` | `tests/test_enrichment_pipeline.py`, `tests/test_xss_integration.py` |
| `TestHappyPath` | `tests/unit/policy/test_policy_engine.py`, `tests/unit/policy/test_preflight.py` |
| `TestImmutability` | `tests/test_report_bundle.py`, `tests/unit/orchestrator/test_validation_plan_v1_schema.py` |
| `TestModels` | `tests/unit/policy/test_ownership.py`, `tests/unit/policy/test_policy_engine.py` |
| `TestPurgeExpired` | `tests/unit/oast/test_correlator.py`, `tests/unit/oast/test_provisioner.py` |
| `TestRunExploitation` | `tests/test_argus004_handlers.py`, `tests/test_argus005_exploit_verify.py` |
| `TestToolRunStatus` | `tests/unit/mcp/test_schemas.py`, `tests/unit/mcp/test_tools_tool_catalog.py` |

## Resolution (ARG-037 PR)

Renamed one or more of each colliding pair so that **every `Test*`
class in the suite is uniquely named**. Naming convention: prefix the
generic class name with the file/domain context.

| Before | After |
| --- | --- |
| `TestAdapterRegistry` (recon_adapters) | `TestReconAdapterRegistry` |
| `TestAdapterRegistry` (exploitation_adapters) | `TestExploitationAdapterRegistry` |
| `TestApprovalRequest` (exploitation_schemas) | `TestExploitationApprovalRequest` |
| `TestApprovalRequest` (policy/approval) | `TestPolicyApprovalRequest` |
| `TestAssertAllowed` (preflight) | `TestPreflightAssertAllowed` |
| `TestAssertAllowed` (scope) | `TestScopeAssertAllowed` |
| `TestDeterminism` (junit) | `TestJunitDeterminism` |
| `TestDeterminism` (report_service) | `TestReportServiceDeterminism` |
| `TestDeterminism` (sarif) | `TestSarifDeterminism` |
| `TestFullPipeline` (enrichment) | `TestEnrichmentFullPipeline` |
| `TestFullPipeline` (xss_integration) | `TestXssFullPipeline` |
| `TestHappyPath` (policy_engine) | `TestPolicyEngineHappyPath` |
| `TestHappyPath` (preflight) | `TestPreflightHappyPath` |
| `TestImmutability` (report_bundle) | `TestReportBundleImmutability` |
| `TestImmutability` (validation_plan_v1) | `TestValidationPlanImmutability` |
| `TestModels` (ownership) | `TestOwnershipModels` |
| `TestModels` (policy_engine) | `TestPolicyEngineModels` |
| `TestPurgeExpired` (correlator) | `TestCorrelatorPurgeExpired` |
| `TestPurgeExpired` (provisioner) | `TestProvisionerPurgeExpired` |
| `TestRunExploitation` (argus004_handlers) | `TestArgus004RunExploitation` |
| `TestRunExploitation` (argus005_exploit_verify) | `TestArgus005RunExploitation` |
| `TestToolRunStatus` (mcp/schemas) | `TestMcpSchemasToolRunStatus` |
| `TestToolRunStatus` (mcp/tools_tool_catalog) | `TestMcpToolCatalogToolRunStatus` |

Each rename was a single-class edit per file (no internal references
needed updating — no test inherited from these classes, no `isinstance`
check used them, no docstring referenced them). Verified by repo-wide
grep before applying.

## Verification

```powershell
# Single-line collision check.
cd backend
python - <<'PY'
import collections, pathlib, re
classes = collections.defaultdict(list)
for p in pathlib.Path("tests").rglob("test_*.py"):
    for m in re.finditer(r"^class (Test\w+)", p.read_text(encoding="utf-8", errors="ignore"), re.M):
        classes[m.group(1)].append(str(p))
dups = {k: v for k, v in classes.items() if len(v) > 1}
print("COLLISIONS REMAINING:", len(dups))
PY
# → COLLISIONS REMAINING: 0

# Full unit + integration suites still green after the renames.
python -m pytest tests/unit -q
python -m pytest tests/integration -q
```

## Out-of-scope follow-ups

* Add a `tests/conftest.py` `pytest_collection_modifyitems` check that
  fails fast if a duplicate `cls.__qualname__` ever lands again.
  Trivial implementation (~10 LOC), but deferred to keep this PR
  focused.
