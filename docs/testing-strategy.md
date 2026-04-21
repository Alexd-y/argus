# ARGUS Testing Strategy

**Status:** Stable since ARG-028 (2026-04-19)
**Owner:** Backend / Test infrastructure
**Audience:** Backend contributors, CI maintainers, on-call

---

## TL;DR

* Run `python -m pytest -q` from `backend/` and you get a green default
  suite. No Docker, no Postgres, no Redis, no OAST listener required.
* Tests that genuinely need a Docker stack are auto-tagged at collection
  time with `requires_docker` (plus the specific subset:
  `requires_postgres`, `requires_redis`, `requires_oast`) and skipped by
  default. CI runs them in a dedicated job.
* `src/db/session.py` switches the connection pool at engine-construction
  time — `StaticPool` for SQLite, `QueuePool` (size 5, overflow 10) for
  Postgres — so the SQLite DSN that the test conftests inject does not
  blow up the production code path.

---

## Test layout

```
backend/tests/
├── conftest.py                     # parent fixtures + ARG-028 marker hook
├── pytest.ini                      # default `-m "not requires_docker"`
├── unit/                           # pure-Python; offline by design
│   ├── conftest.py                 # neutralises override_auth(app)
│   └── ...
├── integration/                    # composed subsystems
│   ├── conftest.py                 # neutralises override_auth(app)
│   ├── sandbox/                    # signed YAML catalog; OFFLINE
│   ├── mcp/                        # subprocess MCP servers; DOCKER
│   ├── oast/                       # OAST flows; DOCKER
│   ├── findings/                   # findings store; DOCKER
│   ├── orchestrator_runtime/       # runtime; DOCKER
│   ├── policy/                     # policy engine; DOCKER
│   ├── payloads/                   # payload registry; DOCKER
│   └── reports/                    # report renderer; DOCKER
├── api/                            # FastAPI route auth tests; DOCKER
├── schemas/                        # pydantic schemas; OFFLINE
├── reports/                        # report bundle helpers; OFFLINE
├── recon/                          # recon parsers; OFFLINE
├── storage/                        # storage helpers; OFFLINE
└── test_*.py                       # legacy root-level; mostly DOCKER
```

The classifier in `backend/tests/conftest.py` walks every collected item
and adds the appropriate `requires_*` markers based on path, fixture
names, and module-content regex. See
`ai_docs/develop/issues/ISS-cycle3-test-categorization.md` for the full
breakdown.

---

## Markers

All four markers are registered in `backend/pytest.ini` and mirrored in
`backend/pyproject.toml`. `pytest --markers` lists them with their
descriptions.

| Marker               | When applied                                                                                                        |
| -------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `requires_postgres`  | Test needs a live PostgreSQL backend (FastAPI route, Alembic, asyncpg session).                                     |
| `requires_redis`     | Test needs Redis / Celery broker (`redis://`, `apply_async(`, `celery_app.send_task`).                              |
| `requires_oast`      | Test needs a live OAST listener — interactsh-server, `RealOASTListener`, hard-coded `OAST_LISTENER_URL`.            |
| `requires_docker`    | Union of the three above. Anything tagged with a specific `requires_*` is automatically also tagged `requires_docker`. |

Markers are added by the `pytest_collection_modifyitems` hook, never by
hand, so the source files stay clean. If you add a new test in a new
location, the hook picks the right markers automatically.

---

## Developer workflow

### Default — run everything that does not need Docker

From `backend/`:

```powershell
python -m pytest -q
```

This honours `addopts = -m "not requires_docker"` from `pytest.ini` and
runs ~9.3k items in a few minutes on a laptop. There is no
`ConnectionRefusedError` noise — `src/db/session.py` uses `StaticPool` for
the default `sqlite+aiosqlite:///:memory:` DSN that
`tests/unit/conftest.py` and `tests/integration/conftest.py` set.

### Run only the Docker-required suite

When you want to validate the full-stack tests locally:

```powershell
# Bring up Postgres + Redis + (optionally) interactsh.
docker compose -f infra/docker-compose.test.yml up -d

# Run the Docker-tagged suite. ``-o "addopts="`` clears the dev default
# so `-m "requires_docker"` actually selects rather than being intersected
# with `not requires_docker`.
python -m pytest tests -m "requires_docker" -o "addopts="
```

If `infra/docker-compose.test.yml` does not exist in your checkout, the
minimum equivalent is:

```powershell
docker run -d --name argus-pg -p 5432:5432 `
    -e POSTGRES_USER=argus -e POSTGRES_PASSWORD=argus -e POSTGRES_DB=argus `
    pgvector/pgvector:pg15
docker run -d --name argus-redis -p 6379:6379 redis:7-alpine
$env:DATABASE_URL = "postgresql+asyncpg://argus:argus@localhost:5432/argus"
$env:REDIS_URL = "redis://localhost:6379/0"
$env:CELERY_BROKER_URL = "redis://localhost:6379/0"
alembic upgrade head
python -m pytest tests -m "requires_docker" -o "addopts="
```

### Run absolutely everything (CI-equivalent)

```powershell
python -m pytest tests -o "addopts="
```

You need the Docker stack up, otherwise the docker-tagged tests will fail.

### Override per invocation

* `python -m pytest -m "requires_postgres"` — only Postgres-bound tests.
* `python -m pytest -m "not requires_redis"` — exclude Redis-bound tests.
* `python -m pytest -m ""` — clear the marker filter entirely (useful when
  you suspect the auto-classifier mis-tagged something).

### Add a new test that needs Docker

Just write the test where it logically belongs. If it uses the `client`
fixture or hard-codes a `localhost:5432` / `redis://` / `interactsh-server`
URL, the auto-classifier picks it up. If for some reason the heuristics
miss it, add an explicit decorator:

```python
import pytest

@pytest.mark.requires_postgres
@pytest.mark.requires_redis
def test_my_new_full_stack_feature(client):
    ...
```

The hook still adds `requires_docker` automatically because the test now
carries `requires_postgres`.

### Add a new test that is offline (and lives in a "danger zone")

If you put an offline test under `tests/test_*.py` (root level) the hook
will tag it as `requires_postgres + requires_redis` because of the
heuristic. Two ways out:

1. **Preferred** — move the test to the appropriate offline subtree
   (`tests/schemas/`, `tests/recon/`, etc.) so its dedicated conftest /
   path classifies it correctly.
2. **Fallback** — add the file name to `_OFFLINE_FILE_NAMES` in
   `backend/tests/conftest.py`. Used today only for
   `test_tool_catalog_coverage.py`.

---

## CI workflow

`.github/workflows/ci.yml` ships two parallel test jobs:

* **`test-no-docker`** — no service containers, runs `pytest tests --tb=short`.
  This is the smoke gate that mirrors the developer's default. Failures
  here are real bugs in pure-Python logic.
* **`test-docker-required`** — Postgres 15 (pgvector) + Redis 7 service
  containers, runs Alembic migrations, then
  `pytest tests -m "requires_docker" --tb=short -o "addopts="`. Failures
  here mean either a real integration regression or that the Docker stack
  drifted from what the test expects (DSN, env vars, etc.).

`build` depends on both, so a regression in either blocks the pipeline.

If you add a new specific marker (say `requires_minio`) follow the same
pattern: register it in `pytest.ini` + `pyproject.toml` + `conftest.py`,
update the auto-classifier, and either extend `test-docker-required` or
spin up a third job.

---

## Connection-pool architecture (ARG-028 Part A)

`backend/src/db/session.py` exposes two helpers:

* `engine` — module-level `AsyncEngine` shared by the FastAPI app and the
  `async_session_factory`.
* `create_task_engine_and_session()` — used by Celery tasks that need an
  engine bound to their own event loop (asyncpg gets unhappy when a
  `Future` crosses loops).

Both go through `_build_engine(database_url)` → `_engine_kwargs_for(database_url)`,
which dispatches on dialect:

| DSN prefix      | `poolclass`   | `pool_size` | `max_overflow` | `pool_pre_ping` | Notes                                                            |
| --------------- | ------------- | -----------:| --------------:| --------------- | ---------------------------------------------------------------- |
| `sqlite*`       | `StaticPool`  |          —  |             —  |             —   | `connect_args={"check_same_thread": False}` so async tests share the in-memory DB across sessions. |
| anything else   | (default)     |          5  |            10  |          `True` | Production / CI Postgres. Behaviour is byte-identical to the pre-ARG-028 code. |

Why this matters for tests: `tests/unit/conftest.py` and
`tests/integration/conftest.py` set
`DATABASE_URL=sqlite+aiosqlite:///:memory:` via `os.environ.setdefault`
*before* any `src.*` import. Pre-ARG-028 the engine constructor blew up
because `pool_size=5, max_overflow=10` are not valid kwargs for
`StaticPool`. Now the constructor branches on `database_url.startswith("sqlite")`
and the test harness imports cleanly.

The unit tests in `backend/tests/unit/db/test_session_pool.py` lock this
behaviour in:

* SQLite DSNs are detected across both sync (`sqlite://`) and async
  (`sqlite+aiosqlite://`) drivers.
* `_engine_kwargs_for` returns the right kwargs for each dialect.
* `_build_engine` produces a `StaticPool` for SQLite and a
  `QueuePool` / `AsyncAdaptedQueuePool` (size 5) for Postgres.
* `create_task_engine_and_session()` mirrors the same dispatch.

---

## Troubleshooting

| Symptom                                                                       | Likely cause                                                                                          | Fix                                                                                                      |
| ----------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| `pytest -q` shows ~3k `connection refused` errors                             | You are on a pre-ARG-028 commit. `src/db/session.py` still passes `pool_size` to `StaticPool`.        | Pull main / rebase. The fix is in `_engine_kwargs_for`.                                                  |
| `pytest -q` skips a test you expect to run                                    | The auto-classifier marked it `requires_docker`.                                                      | Run `pytest --collect-only -m ""` and inspect — likely it pulls `client` or its module hits a DB string.  |
| `pytest -m requires_docker` collects 0 items                                  | You forgot `-o "addopts="`. The dev default `-m "not requires_docker"` intersects with your selector. | `pytest tests -m "requires_docker" -o "addopts="`.                                                       |
| New offline test under `tests/test_*.py` is skipped in dev                    | Heuristic marks every root-level `test_*.py` as requires_docker.                                      | Move to `tests/<offline-subtree>/` or add to `_OFFLINE_FILE_NAMES`.                                       |
| `PayloadSignatureError: signature verification failed for 'auth_bypass.yaml'` | Payload manifest drifted (separate issue, see ISS-cycle3-test-categorization "Out-of-scope follow-ups"). | Re-sign the payload catalog or refresh the test fixture.                                                 |
| `ImportError: cannot import name '_tracker_registry' / '_extract_outdated_components'` | Two stale tests survived an internal API rename.                                                      | Update or delete `tests/test_fix_004_cost_tracking.py` and `tests/test_fix_006_recon.py`.                |

---

## References

* ARG-028 task: `ai_docs/develop/plans/2026-04-19-argus-finalization-cycle3.md`
* Triage / breakdown: `ai_docs/develop/issues/ISS-cycle3-test-categorization.md`
* Worker report: `ai_docs/develop/reports/2026-04-19-arg-028-sqlite-pool-pytest-markers-report.md`
* Marker hook source: `backend/tests/conftest.py`
* Pool helpers: `backend/src/db/session.py`
* Pool unit tests: `backend/tests/unit/db/test_session_pool.py`
