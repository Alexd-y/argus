# Platform Hardening A — Agent Execution Paths

Scope: reliability/correctness fixes for the AI-agent integrations listed in the
hardening brief. This document covers **only** those integrations and the
execution paths reached from them. It does not claim ARGUS is free of all
vulnerabilities, nor production-ready at arbitrary scale.

## 1. Confirmed defects (re-verified against current code)

| # | Defect | Location (before fix) |
|---|--------|-----------------------|
| 3.1 / 5 | The domain vuln analysis ran **three** times: (a) domain-specialist LLM, (b) a `SubAgentSpawner` pass that re-ran the full `ai_vuln_analysis` per domain and discarded the result as `findings_count`, (c) an `asyncio.gather` fan-out that re-ran the full `ai_vuln_analysis` per domain again and merged results back by `title` only. ~10 redundant equivalent analyses per scan; sub-agent content lost; title-only merge could fold different-asset findings together. | `backend/src/orchestration/handlers.py` (`run_vuln_analysis`, blocks at ~2695 and ~2725) |
| 3.2 | `filter_findings_by_domain` used `category in domain_lower`. With `category == ""` this is true for every domain, so empty-category findings routed to all 5 domains. CWE normalisation ignored `"CWE-79"`-style strings. | `backend/src/orchestration/vuln_agents.py:173` |
| 3.3 | ReAct fallback constructed `ReActAgent(task=...)` (constructor takes `task_description`) → `TypeError`, swallowed by `except: pass`; `run()` was never called; a false `"ReAct exploitation fallback used"` log was emitted. | `backend/src/orchestration/handlers.py:3073` |
| 3.4 | `SubAgentSpawner`: session left registered on executor exception (leak); budget checked before execution but incremented after (check-before/increment-after race); no per-task budget enforcement. | `backend/src/orchestration/sub_agent_spawner.py` |
| 3.5 | `EphemeralWorkerPool.acquire` returned a **pseudo container-ID** and registered it as active when Docker was unavailable or creation failed — "no isolation" looked like a successful isolated run. | `backend/src/orchestration/ephemeral_worker.py:194` |

## 2. Fixes and locations

### 3.2 — CWE/category routing (`vuln_agents.py`)
- `_normalize_cwes()` accepts `int`, `"89"`, `"CWE-79"`, `"cwe_918"`, lists, and
  drops `None`/non-numeric/`bool` safely.
- `_normalize_category()` normalises separators; matching is against an explicit
  per-domain phrase set (`_CATEGORY_DOMAIN_KEYWORDS`) — **no substring guessing**.
- Empty/unknown category matches no domain. Multi-domain routing happens only on
  explicit grounds (a CWE in another domain's focus set — e.g. CWE-918 is in both
  SSRF and AUTHZ by design). Identity-based dedup prevents intra-domain
  duplication while keeping genuinely distinct findings.

### 3.1 / 5 — single dispatch (`handlers.run_vuln_analysis`)
- The `SubAgentSpawner` re-analysis pass and the `asyncio.gather` fan-out were
  removed. Domain specialisation is now the single pass gated by
  `scan_options["enable_vuln_agents"]` (default `True`), which produces typed
  hypotheses and `ExploitationQueue`s and flows through the existing evidence
  gate + normaliser/dedup. Disabling the flag now disables **all** specialised
  agent calls for that feature.

### 3.3 — working ReAct (`react_agent.py` + `handlers.run_exploit_attempt`)
- `react_agent.ReActAgent.run()` hardened: explicit `require_tools` (tool mode)
  vs analysis-only mode; missing executor in tool mode is a config error
  (`ReActStopReason.NO_EXECUTOR`); bounded malformed-output repairs
  (`max_malformed_repairs`, default 2) — no infinite JSON-repair loops; repeated
  identical action stops the loop; `ReActResult.evidence_backed` is `True` only
  when a real tool observation occurred, so **model confidence alone never
  confirms a finding**; every stop has an explicit `stop_reason`.
- The handler caller now uses `task_description=`, actually calls `run()` in an
  explicitly analysis-only mode (through the LLM facade), and logs the honest
  outcome (`stop_reason`, `evidence_backed`) instead of a fabricated "used" line.

### 3.4 — `SubAgentSpawner`
- `reserve → execute → settle` discipline: `_reserve()` registers the session
  and reserves the task budget; `_settle()` (always run in `finally`) releases
  the reservation and session and books actual `tokens_used`. `can_spawn()` is
  reserve-aware (settled + reserved + this task's budget must fit the cap).
  Per-task overage is flagged. Marked in-code as **process-local, not the
  distributed budget authority**.

### 3.5 — `EphemeralWorkerPool`
- Real path (default): Docker unavailable / creation failure raises
  `EphemeralWorkerError`; no pseudo-ID, nothing registered active. The opt-in
  state-machine dispatch already wraps `acquire` in a handler that logs the
  failure, so dependent findings gain no confirmation status.
- `mock_mode=True` is the **only** way to get the old pseudo-ID behaviour and is
  intended for offline tests.

## 3. Authoritative sources of state / budget (current, post-change)

- Durable scan state: PostgreSQL (`PhaseInput`/`PhaseOutput`/`ScanTimeline`) via
  the existing state machine — unchanged.
- `SubAgentSpawner` token accounting is **process-local only** (documented in
  code) and is no longer on the scan dispatch path.
- **Agent task/attempt/result contracts**: `backend/src/orchestration/agent_contracts.py`
  (`AgentTaskSpec` / `AgentAttempt` / `AgentResult`, states
  `queued|running|succeeded|failed|cancelled|inconclusive|retry_wait`,
  `CoverageStatus` for the four §4 distinctions, deterministic input fingerprint
  + idempotency key). Logical task vs attempt are separated so retries keep the
  `task_id` and never lose per-attempt usage; empty result ≠ success.
- **Authoritative budget ledger**: `backend/src/orchestration/budget_ledger.py`
  — single `reserve → execute → settle | release | mark_uncertain` API over a
  pluggable `BudgetStore`, plus a `budgeted(...)` async context manager that
  encodes the discipline (settle on recorded usage / uncertain when started
  without usage / release when never started). `InMemoryBudgetStore` (offline)
  and **`PostgresBudgetStore`** (`budget_ledger_pg.py`, atomic
  `SELECT … FOR UPDATE`, idempotent settle via a unique `agent_budget_usage_event`
  row) implement it. Multi-scope limits (tenant/scan/task) enforced atomically;
  **no store ⇒ paid calls are denied**. Tables ship in Alembic revision `064`.
- **Distributed concurrency leases**: `backend/src/orchestration/distributed_lease.py`
  — bounded-capacity slot leases (provider/model/tenant/scan/browser/tool/host)
  over Redis `SET NX EX` + token, with owner-only release/renew (Lua CAS), TTL
  auto-recovery on holder crash, and bounded-backoff acquire. Concurrency only —
  not an rps/tpm limiter.


## 4. Configuration

| Option | Default | Effect |
|--------|---------|--------|
| `scan_options.enable_vuln_agents` | `True` | Enables the single domain-specialist agent pass. `False` disables all specialised agent calls. |
| `scan_options.react_max_iterations` | `5` | Max ReAct iterations in the exploitation fallback. |
| `scan_options.ephemeral_workers` | absent (off) | Opt-in ephemeral container verification. |
| `scan_options.max_ephemeral_containers` | `5` | Pool cap when ephemeral workers are on. |
| `EphemeralWorkerPool(mock_mode=...)` | `False` | Pseudo-container path — tests only. |

## 5. Verification

Commands (from `backend/`, venv active):

```
.\.venv\Scripts\python.exe -m pytest tests/unit/test_agent_routing_hardening.py tests/unit/test_sub_agent_spawner_hardening.py tests/unit/test_ephemeral_worker_hardening.py tests/unit/test_react_agent_hardening.py tests/unit/test_agent_contracts.py tests/unit/test_budget_ledger.py -q
.\.venv\Scripts\python.exe -m pytest tests/test_shannon_wiring.py -m "" -q
.\.venv\Scripts\python.exe -m pytest tests/unit -q
.\.venv\Scripts\python.exe -m ruff check src/orchestration/handlers.py src/orchestration/react_agent.py src/orchestration/vuln_agents.py src/orchestration/sub_agent_spawner.py src/orchestration/ephemeral_worker.py src/orchestration/agent_contracts.py src/orchestration/budget_ledger.py --select E,W,F,I,B,C4,UP,ARG,SIM --ignore E501
```

Results at time of change: 55 new regression tests pass (37 defect-fix +
18 contracts/ledger); 197 wiring tests pass (3 updated from source-presence to
corrected-invariant guards); full offline `tests/unit` lane green; ruff
(enforced ruleset) clean on all changed files.

### Real-infra tests (§7/§8)

A throwaway Postgres + Redis are enough (no full backend build):

```
docker run -d --name argus-test-pg  -e POSTGRES_PASSWORD=argus_test -e POSTGRES_USER=argus -e POSTGRES_DB=argus_test -p 55440:5432 postgres:16-alpine
docker run -d --name argus-test-redis -p 63790:6379 redis:7-alpine

$env:ARGUS_TEST_PG_DSN   = "postgresql+asyncpg://argus:argus_test@localhost:55440/argus_test"
$env:ARGUS_TEST_REDIS_URL = "redis://localhost:63790/0"
.\.venv\Scripts\python.exe -m pytest tests/integration/budget/test_budget_ledger_pg.py -m requires_postgres -p no:cacheprovider -q
.\.venv\Scripts\python.exe -m pytest tests/integration/lease/test_distributed_lease_redis.py -m requires_redis -p no:cacheprovider -q
.\.venv\Scripts\python.exe -m pytest tests/unit/test_agent_contracts.py tests/unit/test_budget_ledger.py tests/unit/test_distributed_lease.py -q
```

Verified results: budget PG suite 6/6 (two-worker atomicity, idempotent settle
across connections, durability across reconnect, stuck-reservation recovery,
multi-scope enforcement); lease real-Redis 2/2; offline contracts/ledger/lease
40/40; ruff clean.

## 6. Not implemented in this pass (assessed, needs live infra)

The following brief items are **not** done and are not claimed done. They require
a live PostgreSQL/Redis/Docker stack (auto-skipped in dev) and are a multi-step
re-architecture that would risk introducing a second authoritative budget
mechanism / unverifiable distributed code — both explicitly disallowed:

- §7 **rewiring the three existing cost trackers as adapters over `BudgetLedger`
  and calling `budgeted(...)` from the LLM facade hot path** — deferred as a
  staged rollout (opt-in) to avoid an unverifiable change to the live path in
  this offline session. The ledger core, Postgres store, migration, and the
  `budgeted(...)` integration primitive are done and tested (incl. real PG).
- §7 **full `alembic upgrade head` on a seeded DB** (clean + with existing
  scans) — the budget migration `064` chains from `063` and its schema is
  verified against real Postgres via the store tests, but the whole-chain
  upgrade needs the pgvector image used in CI, not the alpine test DB here.
- §6 durable agent-task claim/lease/heartbeat + fencing tokens + transactional
  outbox/reconciler. (The `AgentTaskSpec/Attempt/Result` contracts exist;
  persistence/claim is the next step.)
- §8 **wiring `pool_slot` into the hot call sites** (LLM provider dispatch,
  browser/sandbox acquisition) — the settings-driven helper + core lease are
  done and tested (incl. real Redis); the remaining step is the guarded call at
  each site.
- §10 **real hardened Docker/K8s `SandboxAdapter`** — the lifecycle wrapper +
  orphan cleanup logic are done and offline-tested; the real adapter and
  `requires_docker` exec test remain.
- §7 **facade reserve-before-call** — the ledger books actual usage post-hoc
  today (unified accounting); a full reserve→settle at the LLM call site is the
  next step.

## 6b. Done in this pass (verified)

- §4 typed contracts (`agent_contracts.py`).
- §7 authoritative budget ledger + in-memory + **Postgres store** (migration
  `064`) + `budgeted(...)` primitive + **item 3** ledger-backed tracker adapter
  (`budget_ledger_adapter.py`, opt-in via `BUDGET_LEDGER_ENABLED`).
- §6 durable agent-task store with atomic claim (`FOR UPDATE SKIP LOCKED`),
  lease/heartbeat, fencing token, bounded retries, transactional outbox
  (`agent_task_store.py`, migration `065`).
- §8 distributed lease (`distributed_lease.py`) + settings-driven pool helper
  (`pool_leases.py`, opt-in via `LEASE_ENABLED`).
- §10 sandbox lifecycle wrapper with cleanup on all paths + owner-scoped orphan
  cleanup (`sandbox_lifecycle.py`).
- §13 low-cardinality metrics + structured events (`observability.py`).
- §15 dispatcher load harness (`tests/unit/test_dispatch_harness.py`, 1/5/10/20
  + worker-crash recovery).

Verification: full offline suite green; real-infra suites green against a
pgvector Postgres + Redis — budget PG 6/6, agent-task PG 4/4, lease Redis 2/2;
`alembic upgrade head` applied the whole 60+ chain incl. `064`/`065`.

## 7. Migration & worker restart

No prior migrations changed. Revisions `064_agent_budget` (budget ledger) and
`065_agent_tasks` (durable agent-task store + outbox) add the new tables; apply
with `alembic upgrade head`. To roll out:

1. Apply migrations: `cd backend && alembic upgrade head` (adds `agent_budget_*`
   and `agent_task` / `agent_task_outbox`). Verified end-to-end on the full
   60+ migration chain against a pgvector Postgres.
2. Deploy the updated `backend` image.
3. Restart Celery workers so they load the new code. No queue drain required —
   the Celery payload/task contract is unchanged; new features are opt-in via
   `BUDGET_LEDGER_ENABLED` / `LEASE_ENABLED` (both default off).
4. Rollback = `alembic downgrade 063` (drops the new tables) + redeploy the
   previous image + restart workers. Tables are additive and gated off by
   default, so no scan data is affected.

## 8. Deferred follow-ups (implementation guidance)

These three items are intentionally not wired into the hot paths in this pass
(to avoid unverifiable changes to the live LLM/sandbox flow). Each is a small,
well-scoped change with a clear test.

### 8.1 Wire `pool_slot` into the hot call sites (§8)

Goal: enforce the distributed pool caps at the real acquisition points, gated by
`LEASE_ENABLED` (no-op when off).

- **LLM provider** — `backend/src/llm/facade.py`, around the provider dispatch
  (`call_llm_unified` / the WRB / cloud call). Wrap the provider call:

  ```python
  from src.orchestration.pool_leases import pool_slot  # top-level import
  # inside the async call path, offload the blocking lease to a thread so the
  # event loop is not blocked during backoff:
  import anyio
  async with await anyio.to_thread.run_sync(lambda: pool_slot("provider", provider_name).__enter__()):
      ...
  ```

  Cleaner: add an **async variant** `apool_slot(pool_type, key)` in
  `pool_leases.py` that runs `acquire_slot_blocking` via `asyncio.to_thread`
  (blocking Redis + `time.sleep` backoff must not run on the loop). Prefer this.
- **Browser** — `backend/src/sandbox/playwright_adapter.py` `_start_session()` /
  `navigate()`: `pool_slot("browser", scan_id)`.
- **Target host** — exploitation tool runs (`exploitation_executor.py`):
  `pool_slot("host", target_host)` so per-host concurrency is capped.

Handle `LeaseContendedError` as **defer/reschedule** (Celery retry with bounded
backoff + deadline), never as scan failure. Emit `LEASE_EVENTS` (already wired
in `pool_slot`).

Test: an integration test with real Redis (`requires_redis`) asserting that with
`capacity=1` two concurrent acquirers of the same key serialise (one waits/defers).

### 8.2 Real hardened Docker/K8s `SandboxAdapter` (§10)

Goal: back `run_in_sandbox` with a real adapter reusing the existing hardened
flags, so the lifecycle wrapper runs actual tools.

- New `backend/src/sandbox/docker_sandbox_adapter.py`:
  `class DockerSandboxAdapter(SandboxAdapter)`.
  - `create(task_id, owner_labels)`: `client.containers.run(image, detach=True,
    labels={"argus.owner": ..., "argus.task": task_id, "argus.tenant": ...},
    user="1000:1000", read_only=True, security_opt=["no-new-privileges"],
    mem_limit=..., nano_cpus=..., tmpfs={"/workspace": "size=2g"})`. Raise
    `SandboxCreateError` on failure (never a pseudo-ID) — mirrors the
    `EphemeralWorkerPool` fix.
  - `exec`: `container.exec_run(argv, demux=True)` → `ExecResult(exit_code,
    stdout, stderr)`. Run all blocking Docker SDK calls via
    `asyncio.to_thread(...)` so the event loop is not blocked.
  - `collect_artifacts`: `get_archive("/workspace/artifacts/")` → MinIO/S3.
  - `destroy`: `stop(timeout=10)` + `remove(force=True)`.
  - `list_owned(owner_labels)`: `client.containers.list(all=True,
    filters={"label": [f"{k}={v}" for k,v in owner_labels.items()]})` returning
    `(id, age_seconds)` from `container.attrs["Created"]` — so orphan cleanup
    NEVER touches containers we do not own.
- K8s variant: same protocol backed by a short-lived Job/Pod with the same
  security context (non-root, read-only rootfs, no privilege escalation).
- Wire `run_in_sandbox(DockerSandboxAdapter(), ...)` into the exploitation-verify
  path; a create failure must leave findings unconfirmed and surface in coverage.

Test: `backend/tests/integration/sandbox/test_docker_sandbox_adapter.py` marked
`requires_docker` — run `id` / `echo` in `argus-sandbox`, assert `exit_code == 0`,
artifact capture, cleanup on success/exception/timeout, and that `cleanup_orphans`
removes only owner-labeled, aged containers. Must run on **ECS-on-EC2**, not
Fargate (Docker socket required).

### 8.3 Facade reserve-before-call for the budget ledger (§7)

Today the ledger books **actual** usage post-hoc (unified accounting). Target:
`reserve → call → settle` at the LLM call site so limits are enforced *before*
spend and in-flight reservations are visible.

- Add a per-scan ledger registry (mirroring `get_cost_tracker`): register a
  `BudgetLedger(PostgresBudgetStore(session_factory))` for the scan in the state
  machine when `BUDGET_LEDGER_ENABLED`.
- In `facade` (async), wrap the provider call:

  ```python
  scope = BudgetScope(tenant_id=..., scan_id=..., task_id=...)
  est = input_token_estimate + max_output_tokens          # conservative upper bound
  async with ledger.budgeted(scope, tokens=est, est_cost_usd=est_cost) as run:
      run.mark_started()
      resp = await provider_call(...)
      run.record_usage(AgentUsage(                       # provider metadata = truth
          input_tokens=resp.usage.prompt_tokens,
          output_tokens=resp.usage.completion_tokens,
          cost_usd=resolved_cost, provider=..., model=..., estimated=False,
      ))
  ```

  On `BudgetDeniedError` → stop the call (do NOT proceed unbounded); on an
  ambiguous failure after `mark_started()` the CM records **uncertain** (not
  freed). Reserve uses `max_output_tokens` + a reasonable input estimate; settle
  overwrites with provider-metadata truth.
- Keep it behind `BUDGET_LEDGER_ENABLED`; when the ledger store is unavailable,
  deny new paid calls rather than falling back to unbounded local execution.

Test: `requires_postgres` — reserve blocks a call that would exceed the scan cap;
settle books provider-metadata usage; a simulated post-send failure leaves an
`uncertain` reservation for reconciliation.

