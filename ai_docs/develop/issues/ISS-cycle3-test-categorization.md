# ISS — Cycle 3 Test Categorization Triage (ARG-028)

**Issue ID:** ISS-cycle3-test-categorization
**Owner:** Backend / Test infra
**Source task:** ARG-028 (`ai_docs/develop/plans/2026-04-19-argus-finalization-cycle3.md` lines 406-446)
**Status:** Resolved by ARG-028 Part B (auto-marker hook + CI split)
**Date:** 2026-04-19

---

## Context

Cycle 2 capstone left ARGUS with two compounding problems against the
`pytest -q` workflow on a developer laptop with **no Docker stack** running:

1. **Hard collection failure in `src/db/session.py`.** SQLAlchemy raised
   `TypeError: Invalid argument(s) 'pool_size','max_overflow' sent to
   create_engine()` because the engine constructor unconditionally passed
   `QueuePool` knobs even when the test conftest pointed `DATABASE_URL` at
   `sqlite+aiosqlite:///:memory:`. Every test that transitively imported
   `main.app` therefore failed at collection time with a `ConnectionRefusedError`-
   shaped traceback (it actually bottomed out in `aiosqlite` setup, not in a
   socket call, but the user-visible noise was indistinguishable from a real
   "Postgres is down" failure). Cycle 2 capstone counted **~3170** failing
   items in this state.
2. **No marker discipline.** Even after fixing the engine constructor, a
   substantial chunk of the legacy `tests/test_*.py` suite reaches into the
   FastAPI app via the autouse `override_auth(app)` fixture and exercises
   real endpoints / Celery tasks / S3 — work that genuinely requires a live
   Postgres + Redis pair. There was no way to tell pytest "skip the ones
   that need Docker", so the developer experience was a wall of errors.

ARG-028 closes both gaps:

* **Part A** (`backend/src/db/session.py`): dialect-aware pooling — `StaticPool`
  for SQLite, `QueuePool` (size 5, overflow 10, pre-ping) for Postgres.
  Production behaviour is byte-identical.
* **Part B** (this issue): a `pytest_collection_modifyitems` hook adds
  `requires_postgres` / `requires_redis` / `requires_oast` / `requires_docker`
  markers automatically; `pytest.ini` skips `requires_docker` by default in
  dev; the CI workflow splits into `test-no-docker` (no services) and
  `test-docker-required` (Postgres + Redis service containers) jobs.

---

## Final breakdown (2026-04-19, post-fix)

Counts taken from `python -m pytest --collect-only -q` after the session.py
fix and the marker hook landed. The two stale-import files are excluded
(unrelated `_tracker_registry` / `_extract_outdated_components` symbols, see
"Out-of-scope follow-ups" below).

| Selection                                | Items collected | % of total |
| ---------------------------------------- | ---------------:| ----------:|
| **Total** (no marker filter)             |          12 184 |     100.00 |
| **Default dev** (`-m "not requires_docker"`) |       9 278 |      76.15 |
| **`requires_docker`** (CI Docker job)    |           2 906 |      23.85 |
| **`requires_postgres`**                  |           2 906 |      23.85 |
| **`requires_redis`**                     |           2 896 |      23.77 |
| **`requires_oast`**                      |              11 |       0.09 |

> Only 11 items carry `requires_oast`. The marker is set both by path
> (`tests/integration/oast/`) and by content scan (`interactsh`,
> `OAST_LISTENER_URL`, `RealOASTListener`). Most ARGUS OAST tests today
> still drive `FakeOASTListener` and therefore do not need a live
> interactsh container — the dedicated marker exists so that the next
> wave of "real interactsh" tests can be tagged automatically.

### Why ~2 906 instead of the original ~3 170

* **2 668 root-level legacy tests** under `tests/test_*.py` — each is pulled
  through the autouse `override_auth(app)` chain. These are the "true"
  full-stack tests that historically blew up on connection refused.
* **228 `tests/integration/<subtree>/`** items (mcp, oast, findings,
  orchestrator_runtime, policy, payloads, reports). These mostly pass with
  in-process fakes today, but per ARG-028 spec the entire `integration/`
  tree (except `sandbox/`) is treated as Docker-required so CI exercises
  them against the real stack.
* **10 `tests/api/` audit tests** — picked up by the `client`-fixture
  detector (they explicitly test auth on real routes).
* **The remaining ~270** items come from the regex-based content scan
  (hard-coded `localhost:5432`, `redis://`, `apply_async(`, etc.) catching
  oddly-located tests outside the bulk paths above.

The drop from the original 3 170 estimate is explained by:

* `tests/test_tool_catalog_coverage.py` (1 572 parametrised items) is on
  the explicit offline allowlist per spec — it loads a signed YAML catalog
  with no I/O.
* The session.py fix removed ~250 collection-time failures that were
  double-counted as "connection refused" against tests that never actually
  needed Postgres.

---

## Top files by `requires_docker` weight

```
  119  tests/integration/payloads/test_catalog_load.py
   79  tests/test_mcp_policy_va_active_scan.py
   64  tests/test_stage4_infrastructure.py
   57  tests/test_threat_modeling_schemas.py
   54  tests/test_s3_raw_phase_artifact.py
   52  tests/test_exploitation_adapters.py
   47  tests/test_exploitation_policy_engine.py
   43  tests/test_exploitation_planner.py
   37  tests/test_argus003_api_contract.py
   35  tests/integration/reports/test_midgard_tier_all_formats.py
   35  tests/test_argus007_guardrails.py
   35  tests/test_rpt010_reporting_coverage.py
   34  tests/test_stage1_enrichment_builder.py
   33  tests/test_argus009_reports.py
   33  tests/test_bkl_vuln_flags.py
```

Total: **2 906 items across 232 files**.

---

## Categorisation policy (codified in `backend/tests/conftest.py`)

The hook `pytest_collection_modifyitems` walks each collected item and
applies markers additively:

1. **Offline allowlist** (never marked):
   * `tests/unit/**` — pure unit suite.
   * `tests/integration/sandbox/**` — signed YAML catalog + on-disk fixtures.
   * `tests/schemas/**`, `tests/reports/**`, `tests/recon/**`,
     `tests/storage/**` — pure parser / contract / pydantic suites.
   * `tests/test_tool_catalog_coverage.py` — explicit per-file override.
2. **Path-forced `requires_postgres + requires_redis`**:
   * `tests/integration/mcp/**`
   * `tests/integration/oast/**`
   * `tests/integration/findings/**`
   * `tests/integration/orchestrator_runtime/**`
   * `tests/integration/policy/**`
   * `tests/integration/payloads/**`
   * `tests/integration/reports/**`
3. **Root-level legacy `tests/test_*.py`** — every file directly under
   `tests/` (no subdirectory) that isn't on the offline allowlist gets
   `requires_postgres + requires_redis`. Reasoning: the parent autouse
   `override_auth(app)` fixture pulls `main.app` into every such test, and
   the historical intent is "exercise a FastAPI route".
4. **Fixture-based `requires_postgres`** — any test pulling the `client`
   fixture, even from a future subdirectory.
5. **Module-content scan** — regex-based detection of:
   * `requires_postgres`: hard-coded Postgres DSNs / `localhost:5432` / etc.
   * `requires_redis`: `redis://`, `REDIS_URL`, `CELERY_BROKER_URL`,
     `celery_app.send_task`, `apply_async(`.
   * `requires_oast`: `interactsh` (excluding `Fake*`), `OAST_LISTENER_URL`,
     `oast_callback_url`, `oast_token`, `RealOASTListener`.
6. **Union marker** — any specific `requires_*` automatically also adds
   `requires_docker` so CI can select / skip with one expression.

The hook is purely additive — it never removes markers, never reorders,
never deselects. Default test selection (`-m "not requires_docker"`) is
configured via `addopts` in `backend/pytest.ini` and mirrored in
`backend/pyproject.toml` for IDE discovery.

---

## CI integration

`.github/workflows/ci.yml` was split into two test jobs:

* **`test-no-docker`** — no service containers. Runs the developer's
  default `pytest tests --tb=short` (so `-m "not requires_docker"` from
  `pytest.ini` skips the Docker-bound suite). `DATABASE_URL` is set to
  `sqlite+aiosqlite:///:memory:` so the engine constructor uses the
  StaticPool path landed in ARG-028 Part A.
* **`test-docker-required`** — boots Postgres 15 (with pgvector) + Redis 7
  service containers, applies Alembic migrations, then runs
  `pytest tests -m "requires_docker" --tb=short -o "addopts="` (the
  `-o "addopts="` clears the dev default so `-m "requires_docker"` actually
  selects, instead of being intersected with `not requires_docker`).

`build` now depends on both jobs, so a regression in either stops the
pipeline.

---

## Out-of-scope follow-ups (track separately)

The full collection still surfaces a handful of pre-existing problems that
are *not* connection-refused and therefore outside ARG-028's remit:

* `tests/test_fix_004_cost_tracking.py` — `ImportError: cannot import name
  '_tracker_registry' from 'src.llm.cost_tracker'`. Stale test, needs to be
  updated to the current `cost_tracker` API or deleted.
* `tests/test_fix_006_recon.py` — `ImportError: cannot import name
  '_extract_outdated_components'`. Same shape; orphaned test against an
  old recon helper.
* `tests/integration/policy/test_preflight_payloads_integration.py` — every
  test errors with `PayloadSignatureError: signature verification failed
  for 'auth_bypass.yaml'`. The signed payload catalog and the test fixture
  drifted; needs payload manifest re-signing or fixture refresh.
* Several `app/schemas/threat_modeling/schemas.py::TestingRoadmapItem`
  collection warnings — pytest is trying to collect a pydantic model whose
  name happens to start with `Test`. Either rename the model or add
  `__test__ = False`.

These are tracked outside ARG-028 (suggested IDs: `ISS-fix-004-imports`,
`ISS-fix-006-imports`, `ISS-payload-signatures-drift`,
`ISS-pytest-test-prefix-collisions`).

---

## Verification commands

Run from `backend/` on Windows / PowerShell:

```powershell
# Default dev — no Docker required, no connection-refused noise.
python -m pytest -q --ignore=tests/test_fix_004_cost_tracking.py --ignore=tests/test_fix_006_recon.py

# Show only Docker-required tests (~2906 items collected).
python -m pytest --collect-only -q -m "requires_docker" `
    --ignore=tests/test_fix_004_cost_tracking.py `
    --ignore=tests/test_fix_006_recon.py

# Bring up the test stack and run them locally.
docker compose -f infra/docker-compose.test.yml up -d
python -m pytest tests -m "requires_docker" -o "addopts="
```
