# ARG-008 — AI Orchestrator (Planner / Critic / Verifier / Reporter / Fixer) + Prompt Registry — Completion Report

**Date:** 2026-04-17
**Cycle:** `orch-2026-04-17-12-00-argus-final`
**Status:** ✅ COMPLETED
**Plan:** `ai_docs/develop/plans/2026-04-17-argus-finalization-cycle1.md`

---

## Goal

Build the AI orchestration plane that drives the ARGUS pentest pipeline:
five role-specific agents (Planner, Critic, Verifier, Reporter, Fixer)
glued by a Prompt Registry, a Retry/Fixer loop, an LLM Provider
abstraction, and per-tenant cost / quota tracking.

---

## Deliverables

### Production code (`backend/src/orchestrator/`)

| Module                | LOC | Public surface                                                                                  |
| --------------------- | --: | ----------------------------------------------------------------------------------------------- |
| `__init__.py`         |  85 | Re-exports the full ARG-008 + ARG-001 public API.                                               |
| `llm_provider.py`     | 318 | `LLMRequest`, `LLMResponse`, `ResponseFormat`, `LLMProvider` Protocol, `EchoLLMProvider`, `OpenAILLMProvider` (stub), `LLMProviderUnavailableError`, `LLMProviderError`. |
| `prompt_registry.py`  | 415 | `AgentRole`, `PromptDefinition`, `PromptRegistry`, `PromptRegistryError`. Ed25519-signed catalogs with fail-closed loading (mirrors `src.payloads.registry`). |
| `cost_tracker.py`     | 215 | `CostRecord`, `CostSummary`, `CostTracker` — per-scan / per-tenant aggregation with `since` filter. |
| `agents.py`           | 660 | `AgentContext`, `AgentError` family, `BaseAgent`, `PlannerAgent`, `CriticAgent`, `VerifierAgent`, `ReporterAgent`, `FixerAgent`, plus `CriticVerdict` and `ReportNarrative` DTOs. |
| `retry_loop.py`       | 445 | `RetryConfig`, `RetryAbortReason`, `AttemptRecord`, `AttemptLog`, `RetryLoop`. |
| `orchestrator.py`     | 420 | `Orchestrator` facade + `OrchestratorError` family (`OrchestratorPlanRejected`, `OrchestratorBudgetExceeded`, `OrchestratorParseFailure`, `OrchestratorProviderFailure`). |

All modules are `mypy --strict` clean (`Success: no issues found in 17
source files` against `src.orchestrator` + `src.pipeline`).

### Signed prompt catalog (`backend/config/prompts/`)

Five canonical prompts shipped as Ed25519-signed YAML descriptors:

* `planner_v1.yaml` → emits `ValidationPlanV1` (schema_ref → `validation_plan_v1`).
* `critic_v1.yaml` → emits `CriticVerdict` (`critic_verdict_v1`).
* `verifier_v1.yaml` → emits `list[FindingDTO]` (`finding_dto_list_v1`).
* `reporter_v1.yaml` → emits `ReportNarrative` (`report_narrative_v1`).
* `fixer_v1.yaml` → repairs malformed JSON (no schema_ref).

Catalog metadata: `SIGNATURES`, `_keys/.gitkeep`, `_keys/README.md`.
Verification artefact:

```
$ python scripts/prompts_list.py
prompt_id    version  agent_role  model_id        max_tokens  temperature
critic_v1    1.0.0    critic      gpt-5.4-medium  2048        0.00
fixer_v1     1.0.0    fixer       gpt-5.4-medium  4096        0.00
planner_v1   1.0.0    planner     gpt-5.4-medium  4096        0.20
reporter_v1  1.0.0    reporter    gpt-5.4-medium  6144        0.30
verifier_v1  1.0.0    verifier    gpt-5.4-medium  6144        0.10

5 prompts loaded.
```

### CLI helpers (`backend/scripts/`)

* `prompts_sign.py` — `genkey | sign | verify` (mirrors `payloads_sign.py`).
* `prompts_list.py` — tabular listing (mirrors `payloads_list.py`).

`.gitignore` already excludes generated `.priv` material.

### Tests

| Suite                                              | Tests | Notes                                                      |
| -------------------------------------------------- | ----: | ---------------------------------------------------------- |
| `tests/unit/orchestrator_runtime/test_llm_provider.py` |  22 | `EchoLLMProvider` determinism, token math, `OpenAILLMProvider` raises. |
| `tests/unit/orchestrator_runtime/test_prompt_registry.py` |  21 | Schema validation, signature verify, tamper / dup / wrong key paths. |
| `tests/unit/orchestrator_runtime/test_agents.py`   |  36 | Five agents + DTOs + `_prepare_kwargs` defaults + parse failure paths. |
| `tests/unit/orchestrator_runtime/test_retry_loop.py` |  14 | Happy path, fixer recovery, budget caps, max-retries, provider errors, backoff. |
| `tests/unit/orchestrator_runtime/test_cost_tracker.py` |  13 | Aggregation per-scan / per-tenant, `since` filter, sort stability. |
| `tests/unit/orchestrator_runtime/test_orchestrator.py` |  10 | Plan / verify / report flows, audit emission, error translation. |
| `tests/integration/orchestrator_runtime/test_signed_prompts_load.py` |   6 | Real `backend/config/prompts/` catalog loads & validates. |
| `tests/integration/orchestrator_runtime/test_orchestrator_e2e.py` |   2 | End-to-end `plan → verify → report` with real signed catalog. |

**Total: 124 / 124 passing for ARG-008**, plus 40 / 40 ARG-001 tests
unaffected (ran together: 164 / 164 ✅). Full project suite:
**1830 / 1830** passing (excluding the unrelated pre-existing
`tests/test_argus010_sse_observability.py` collection error caused by
missing `aiosqlite` package).

### Coverage (target ≥ 90 %)

```
src\orchestrator\__init__.py              100%
src\orchestrator\agents.py                 97%
src\orchestrator\cost_tracker.py          100%
src\orchestrator\llm_provider.py           98%
src\orchestrator\orchestrator.py           97%
src\orchestrator\prompt_registry.py        92%
src\orchestrator\retry_loop.py             99%
src\orchestrator\schemas\__init__.py      100%
src\orchestrator\schemas\loader.py         69%   (ARG-001 — out of scope)
                                       ------
TOTAL                                       94%
```

ARG-008 production modules average **97 %**; aggregate exceeds the
required 90 %. The only sub-90 module is the ARG-001 schema loader,
which is unchanged and therefore out-of-scope here.

---

## Acceptance criteria — verification

| Criterion                                                              | Status                                |
| ---------------------------------------------------------------------- | ------------------------------------- |
| All new modules pass `mypy --strict`                                   | ✅ 17 source files clean               |
| Tests pass (existing + new)                                            | ✅ 1830 / 1830                         |
| `src.orchestrator` coverage ≥ 90 %                                    | ✅ 94 % overall, 97 % new code         |
| `ruff` and `black` clean                                              | ✅ All checks passed                   |
| Zero `subprocess` / `shell=True`                                      | ✅ Only docstring mention              |
| 5 / 5 signed prompts verified                                         | ✅ `prompts_list.py` loads all 5       |
| Cost tracker per-scan / per-tenant aware                              | ✅ `total_for_scan`, `total_for_tenant(since=…)` |
| Retry loop honours budget caps                                        | ✅ `BUDGET_EXHAUSTED` path tested      |
| Pydantic models `frozen=True`, `extra="forbid"`                       | ✅ Every `BaseModel` in package        |
| Sanitised error messages (no `input_value` leak)                      | ✅ `_sanitize_pydantic_errors` + ARG-001 helper |
| No real network calls                                                  | ✅ `EchoLLMProvider` is the default; `OpenAILLMProvider` raises until wired |

---

## Architecture notes

### `_prepare_kwargs` hook

During testing the original design surfaced a structural bug: the
retry loop calls `agent.call_raw()` directly, bypassing the agents'
`run()` method where context-derived defaults (e.g. `phase`,
`target_summary`, serialised findings) were injected. This caused
template-render `KeyError`s on every fixer-driven retry.

**Fix:** extracted `_prepare_kwargs(context, kwargs) -> dict` as a
subclass hook on `BaseAgent`. Both `BaseAgent.call_raw()` and the
retry loop now invoke the same hook before rendering, so first-attempt
and fixer-attempt rendering share identical kwarg surfaces. Subclasses
moved their context-injection logic into `_prepare_kwargs`; their
`run()` methods are now thin typed wrappers using `cast(...)`. This
keeps the retry loop agnostic of agent-specific defaults while still
letting each agent describe its own input contract.

### Strict typing pattern for `**kwargs`

Mypy strict flagged `**kwargs: object` clashing with the keyword-only
`response_format: ResponseFormat | None` argument when expanding
mappings. Resolution: typed all template-rendering kwargs as `Any`
(template substitution values are by definition heterogeneous), and
used `typing.cast` for the typed return-type bridge from
`super().run()` (which returns `Any`).

### Audit trail

`Orchestrator` emits one `AuditEvent` per agent invocation
(`AuditEventType.POLICY_DECISION`) with `decision_allowed` reflecting
the retry-loop terminal state. Hash-chain integrity is exercised by
`test_full_plan_verify_report_pipeline` via `audit_logger.verify_chain`.

---

## Observability surface (per Backlog/dev1_md §13)

Each LLM call produces:

* **Structured log line** `orchestrator.llm.call` with
  `correlation_id`, `tenant_id`, `agent_role`, `prompt_id`, `attempt`,
  `prompt_tokens`, `completion_tokens`, `usd_cost`, `latency_ms`,
  `finish_reason`. Emitted from `BaseAgent` / provider implementations.
* **`CostRecord`** persisted via `CostTracker.record(...)` with
  `orchestrator.cost.recorded` log line for ingestion into Loki / Datadog.
* **`AttemptRecord`** accumulated in `AttemptLog`; sanitised
  `error_kind` + `sanitized_error` (no input values, ≤ 2000 chars).
* **`AuditEvent`** appended to the tamper-evident chain with
  `payload={"prompt_id": ..., "model_id": ..., "abort_reason": ...}`.

---

## Files created / modified

### Created (24)

```
backend/src/orchestrator/llm_provider.py
backend/src/orchestrator/prompt_registry.py
backend/src/orchestrator/cost_tracker.py
backend/src/orchestrator/agents.py
backend/src/orchestrator/retry_loop.py
backend/src/orchestrator/orchestrator.py
backend/config/prompts/planner_v1.yaml
backend/config/prompts/critic_v1.yaml
backend/config/prompts/verifier_v1.yaml
backend/config/prompts/reporter_v1.yaml
backend/config/prompts/fixer_v1.yaml
backend/config/prompts/SIGNATURES
backend/config/prompts/_keys/.gitkeep
backend/config/prompts/_keys/README.md
backend/config/prompts/_keys/<key-id>.ed25519.pub
backend/scripts/prompts_sign.py
backend/scripts/prompts_list.py
backend/tests/unit/orchestrator_runtime/__init__.py
backend/tests/unit/orchestrator_runtime/conftest.py
backend/tests/unit/orchestrator_runtime/test_llm_provider.py
backend/tests/unit/orchestrator_runtime/test_prompt_registry.py
backend/tests/unit/orchestrator_runtime/test_agents.py
backend/tests/unit/orchestrator_runtime/test_retry_loop.py
backend/tests/unit/orchestrator_runtime/test_cost_tracker.py
backend/tests/unit/orchestrator_runtime/test_orchestrator.py
backend/tests/integration/orchestrator_runtime/__init__.py
backend/tests/integration/orchestrator_runtime/test_signed_prompts_load.py
backend/tests/integration/orchestrator_runtime/test_orchestrator_e2e.py
ai_docs/develop/reports/2026-04-17-arg-008-orchestrator-report.md
```

### Modified (2)

```
backend/src/orchestrator/__init__.py    (full public API export)
backend/.gitignore                      (exclude generated .priv keys)
```

---

## Out of scope (deferred to ARG-009 and downstream)

* Real OpenAI / Anthropic HTTP integration (`OpenAILLMProvider.call`
  intentionally `NotImplementedError` — the LLM provider abstraction is
  in place; vendor wiring is a Cycle-2 concern with secrets management).
* Findings normaliser + dedup (ARG-009).
* Wiring the orchestrator into `src.pipeline.runner` (separate task).
* Persistent cost-tracking sink (Postgres / Redis) — current
  implementation is in-memory thread-safe; the protocol seam is in
  place via `CostTracker`'s public surface.

---

## Sanity recap

```
mypy --strict src/orchestrator src/pipeline   →  ✅ 17 files clean
ruff check src/orchestrator scripts/ tests/   →  ✅ All checks passed
black --check src/orchestrator scripts/ tests/→  ✅ 22 files unchanged
pytest tests/unit/orchestrator_runtime/        →  ✅ 116 / 116
pytest tests/integration/orchestrator_runtime/ →  ✅   8 /   8
pytest tests/unit/orchestrator/ (ARG-001)      →  ✅  40 /  40
pytest tests/ (full suite, sans aiosqlite)    →  ✅ 1830 / 1830
prompts_list.py                                →  ✅ 5 / 5 verified
```

ARG-008 is **DONE** and ready to be wired into the pipeline runner
(out of scope for this task).
