# ARGUS LLM Gateway

> Implementation status (2026-06): the standalone gateway service described below is
> built (`src/llm_gateway/`) but **disabled by default** (Helm `llmGateway.enabled: false`,
> not in docker-compose). In production the scan pipeline routes **in-process** through
> `src/llm/facade.py`, which calls WhiteRabbitNeo (`whiterabbitneo_adapter.py`) and cloud
> providers (`task_router.py`) directly — it does **not** currently make an HTTP hop to the
> gateway. The diagram below is the target topology; see "In-process phase-aware routing"
> for what runs today.

## 0. In-process phase-aware routing (current default path)

`facade.call_llm_unified(phase=..., task=...)` resolves a per-phase execution plan from
[`backend/config/llm/phase_routing.yaml`](../backend/config/llm/phase_routing.yaml) via
`src/llm/phase_routing.py`:

- Activation: `ARGUS_PHASE_ROUTING_ENABLED=true` (default `false` -> legacy WRB-first
  routing, fully backward compatible).
- Per phase the YAML defines `primary_alias`, `mode` (`cloud`|`wrb`), `fallback`
  (`cloud`|`wrb`|`none`), optional `reviewer_alias`, `evidence_contract`, and `degrade`.
  Alias labels are validated against the in-code registry (`model_aliases.py`).
- Execution reuses the existing cloud `task_router` and the WRB adapter (and their API-key
  plumbing); the router only decides ordering. On primary failure it walks the configured
  fallback.
- Telemetry: chosen alias, `fallback_used`, and `latency_ms` are attached to the per-scan
  `ScanCostTracker` records and emitted as the `llm_phase_routing` structured log event.
- Evidence packs: when enabled, compact digests from `src/llm/evidence_contracts.py`
  (e.g. `exploit_candidate_pack_v1`, `vuln_evidence_pack_v2`) replace raw tool dumps in the
  prompt for the relevant phases.
- Reviewer/judge: a config-gated, idempotent second pass (reusing the adversarial critic)
  runs for phases whose route declares a `reviewer_alias` (currently `vuln_analysis`).

Default routing offloads WhiteRabbitNeo from the hot path: `recon`/`threat_modeling`/
`vuln_analysis`/`reporting` run on cloud reasoners, while `exploitation`/`post_exploitation`
stay local-first on WRB with cloud fallback. Headers `X-Argus-Model-Alias`/`X-Argus-Policy`
referenced in older drafts are **not** implemented; the in-process resolver replaces them.

## 1. Architecture Overview (target: standalone gateway service)

The LLM Gateway is a standalone FastAPI service that provides an OpenAI-compatible API for
multi-model orchestration. It sits between ARGUS application code and LLM backends,
enforcing policy, routing requests, tracking usage, and redacting sensitive data.

```
                          +---------------------+
                          |  ARGUS Application  |
                          |  (facade.py)        |
                          +----------+----------+
                                     |
                    +----------------+----------------+
                    |                                  |
          +--------v--------+              +----------v----------+
          |  LLM Module     |              |  LLM Gateway        |
          |  (src/llm/)     |              |  (src/llm_gateway/) |
          |                 |   HTTP       |                     |
          |  facade.py -----+------------->+  router.py          |
          |  policy.py      |  /v1/chat/   |  policy_enforcer.py |
          |  task_router.py |  completions |  provider_clients.py|
          |  model_aliases  |              |  cost_router.py     |
          |  gateway_client |              |  usage_ledger.py    |
          |  wrb_adapter    |              |  redaction.py       |
          |                 |              |  cloud_supplement.py|
          +--------+--------+              |  health.py          |
                   |                       |  replay/            |
                   |                       |  eval/              |
                   |                       +----------+----------+
                   |                                  |
          +--------v--------+              +---------+---------+
          | WhiteRabbitNeo  |              |  Cloud Providers  |
          | (vLLM, local)   |              |  DeepSeek, Qwen,  |
          | WRB-7B-AWQ      |              |  Perplexity, etc. |
          +-----------------+              +-------------------+
```

**Data flow per request:**

1. Application calls `facade.call_llm_unified()` with a task, system/user prompt, and scan metadata.
2. Facade resolves the task role, builds an `LLMPolicy`, and sends it to the Gateway via `GatewayClient`.
3. Gateway's `router.py` receives the request, invokes `PolicyEnforcer` for compliance and budget checks.
4. `ProviderRouter` resolves the alias to a concrete provider list, filters by policy flags, and attempts providers in order (WRB first, then cloud fallbacks).
5. The first successful provider response is redacted, usage is recorded to the ledger, and a `GatewayResponse` is returned.

---

## 2. Components

### 2.1 app (app.py)

Minimal FastAPI application factory. Mounts two routers:

- `chat_router` from `router.py` — the main `/v1/chat/completions` endpoint and `/v1/models`.
- `health_router` from `health.py` — readiness, liveness, and provider status.

```python
# backend/src/llm_gateway/app.py
app = FastAPI(title="ARGUS LLM Gateway", version="1.0.0")
app.include_router(chat_router)
app.include_router(health_router)
```

### 2.2 router (router.py)

The OpenAI-compatible API surface. Defines:

| Route | Method | Purpose |
|---|---|---|
| `POST /v1/chat/completions` | POST | Main completion endpoint |
| `GET /v1/models` | GET | Lists available model aliases |

**Key models:**

- `GatewayRequest` — accepts `model` (alias), `messages`, `temperature`, `max_tokens`, `metadata` (tenant_id, scan_id, phase, task, content_class), and `policy` (the serialized LLMPolicy).
- `GatewayResponse` — returns `id`, `model`, `resolved_provider`, `resolved_model`, `choices`, `usage` (with token counts + estimated cost), and `policy_decision`.
- `PolicyDeniedError` (HTTP 403) — raised when policy evaluation blocks the request.
- `AllProvidersFailedError` (HTTP 502) — raised when every configured provider fails or is unavailable.

**Request processing pipeline:**

1. **Policy enforcement** — `PolicyEnforcer.evaluate(policy, request)` validates compliance flags, budget, routing constraints, and OSINT enablement.
2. **Provider selection & call** — `ProviderRouter.select_provider()` resolves the alias, then `call_provider()` makes the HTTP request.
3. **Usage recording** — `record_usage()` logs token counts and estimated cost to the ledger.
4. **Response redaction** — `redact_response()` strips API keys and credentials from the assistant output.

### 2.3 policy_enforcer (policy_enforcer.py)

Gate-level policy validation that runs before any provider is contacted. Checks:

| Check | Condition | Failure |
|---|---|---|
| Airgapped mode | `compliance.airgapped_only` is true and alias is not a local-only model | 403 — "Airgapped mode blocks all cloud providers" |
| Source code to cloud | `compliance.no_cloud_llm_for_source_code` is true, `content_class == "source_code"`, and alias is not `argus-pentest-primary` | 403 — "Source code cannot be sent to cloud LLM" |
| OSINT disabled | Alias is `argus-osint` and `osint.enabled` is false | 403 — "OSINT enrichment disabled by policy" |
| Budget exhausted | `budget.max_cost_usd <= 0` | 403 — "LLM budget exhausted" |
| Local-only route | `routing.<role>.local_only` is true and alias is not a local variant | 403 — "Route `<role>` requires local-only provider" |

The enforcer also maps aliases to roles for route-level checks:

```
argus-pentest-primary  → pentest
argus-planner-fast     → planner
argus-planner-deep     → planner
argus-code-cloud       → code
argus-code-local       → code
argus-devsecops-local  → devsecops
argus-report           → report
argus-osint            → osint
```

### 2.4 provider_clients (provider_clients.py)

Contains the `ALIAS_REGISTRY` and `ProviderRouter`. The registry maps each logical alias to
one or more concrete providers, each with a key, base URL, model ID, cloud-allowed flag,
and pricing information.

**ALIAS_REGISTRY entries:**

| Alias | Role | Primary Provider | Model | Cloud | Price (in/out per 1M) |
|---|---|---|---|---|---|
| `argus-pentest-primary` | pentest | whiterabbitneo-7b | `taico-ai/WhiteRabbitNeo-v3-7B` | No | $0 / $0 |
| `argus-planner-fast` | planner | deepseek-v4-flash | `deepseek-chat` | Yes | $0.14 / $0.28 |
| `argus-planner-deep` | reasoning | deepseek-v4-pro | `deepseek-v4-pro` | Yes | $0.28 / $0.56 |
| `argus-code-cloud` | code | qwen3-coder-480b | `qwen/qwen3-coder:free` | Yes | $0.15 / $0.15 |
| `argus-code-local` | code | qwen3-32b-local | `qwen3-32b` | No | $0 / $0 |
| `argus-devsecops-local` | devsecops | whiterabbitneo-7b | `taico-ai/WhiteRabbitNeo-v3-7B` | No | $0 / $0 |
| `argus-report` | report | deepseek-v4-pro | `deepseek-v4-pro` | Yes | $0.28 / $0.56 |
| `argus-osint` | osint | perplexity | `sonar` | Yes | $1.00 / $1.00 |

**ProviderRouter:**

- `select_provider(alias, policy)` — iterates the alias's provider list, skipping cloud providers when `airgapped_only` is set. Returns the first eligible provider. Tracks call counts per provider key.
- `call_provider(provider, messages, temperature, max_tokens)` — makes an OpenAI-compatible `POST /chat/completions` request with bearer auth resolved from environment variables. Uses 300s timeout for local providers, 120s for cloud.
- `_get_api_key(provider_key)` — maps provider keys to environment variable names (`WHITERABBITNEO_API_KEY`, `DEEPSEEK_API_KEY`, `OPENROUTER_API_KEY`, `PERPLEXITY_API_KEY`).

### 2.5 usage_ledger (usage_ledger.py)

In-memory usage tracking with Prometheus integration.

- `record_usage(tenant_id, scan_id, phase, task, alias, provider, model, prompt_tokens, completion_tokens, estimated_cost)` — appends a timestamped entry to `_ledger[]` and calls `src.core.observability.record_llm_tokens()` (best-effort).
- `get_usage_summary(tenant_id, scan_id)` — returns aggregated stats: total calls, total tokens, total cost (USD), and breakdowns by provider and by model.

### 2.6 redaction (redaction.py)

Sensitive content scrubbing for both prompts and responses.

| Function | Purpose |
|---|---|
| `hash_prompt(prompt)` | BLAKE2b-128 hash of the prompt text — used when `log_prompts` is `"hashed"` |
| `redact_api_keys(text)` | Replaces 11 patterns of secrets with `<REDACTED:...>` placeholders |
| `redact_response(content)` | Applies `redact_api_keys` to assistant output |
| `summary_response(content, max_length=500)` | Truncates and redacts for summary logging |
| `log_prompt(prompt, mode)` | Dispatches to `redact_api_keys` (full), `hash_prompt` (hashed), or returns a disabled sentinel |
| `log_response(response, mode)` | Dispatches to `redact_api_keys` (full), `summary_response` (summary_only), or disabled sentinel |

**Redacted patterns:** OpenAI keys (`sk-...`), OpenRouter keys (`sk-or-...`), Perplexity keys (`pplx-...`), Bearer tokens, AWS access keys (`AKIA...`), GitHub tokens (`ghp_...`, `gho_...`), inline `api_key=`, `password=`, `secret=`, `token=` params, and PEM private keys (RSA/EC/DSA/OpenSSH).

### 2.7 health (health.py)

Four health/observability endpoints:

| Endpoint | Response |
|---|---|
| `GET /health` | `{"status": "ok", "service": "argus-llm-gateway"}` |
| `GET /ready` | `{"status": "ready"}` |
| `GET /metrics` | `{"requests_total": 0, "tokens_total": 0}` (basic placeholder) |
| `GET /providers/health` | Enumerates all providers from `ALIAS_REGISTRY` with key, model, cloud flag, and status (`"configured"` or `"unconfigured"`) |

### 2.8 cost_router (cost_router.py)

Budget enforcement and cost-aware provider selection.

- `CostRouter(max_cost_usd)` — tracks `_spent` against a budget. Sets `_soft_limit` at 80% of max.
- `remaining` — remaining budget in USD.
- `over_soft_limit` — true when 80% threshold is crossed.
- `can_afford(estimated_cost)` — checks if a call fits within remaining budget.
- `select_cheapest(providers)` — sorts available providers by price, returns the cheapest one the budget can afford. Estimates per-call cost as `input_price / 500`.
- `record_spend(cost)` — increments spent, logs warnings at budget exceeded and info at soft limit.
- `build_cost_router(scan_budget)` — factory that defaults to $0.50 max if no budget dict is provided.

### 2.9 cloud_supplement (cloud_supplement.py)

A narrowly scoped cloud fallback for report-generation tasks only.

- `CLOUD_SUPPLEMENT_TASKS = {"REPORT_SECTION", "EXECUTIVE_SUMMARY", "COST_SUMMARY"}` — the whitelist of tasks allowed to use this path.
- `call_cloud_supplement(messages, model, temperature, max_tokens)` — calls DeepSeek (`deepseek-chat`) directly with a 120s timeout. Returns `{"content": "", ...}` gracefully (no exception) on failure or when `DEEPSEEK_API_KEY` is missing.

### 2.10 replay (replay/recorder.py)

Deterministic recording and replay of LLM calls for audit, debugging, and regression testing.

- `ReplayRecord` — captures model, provider, messages, response, usage, duration, and policy decision.
- `record_call(record)` — stores a record in the in-memory `_recorder_store`.
- `get_records(model, provider, limit)` — filters and returns the most recent N records.
- `replay_call(record, target_url)` — resends the recorded messages to a gateway instance at `temperature=0.0` for determinism. Returns the original and replayed responses (first 200 chars), a boolean `match`, and timing comparison.

### 2.11 eval (eval/canary_shadow.py)

Model evaluation framework for testing new providers without production impact.

**CanaryRouter** — routes a configurable fraction of traffic (default 5%) to a candidate model. Uses MD5 of the prompt to deterministically decide which requests go to the canary path.

**ShadowEvaluator** — runs a candidate model in parallel with production, comparing outputs asynchronously without affecting the user-facing response.

- `shadow_call(messages, production_response, temperature)` — sends the same messages to the candidate model's endpoint. Captures latency, response text, and computes a score delta.
- `_compare_responses(a, b)` — computes word-level overlap ratio between production and candidate responses. Baseline: 70% overlap = "same". Higher = "better", lower = "worse".
- `summary()` — aggregates results: counts of better/same/worse/error verdicts, average score delta, and candidate model ID.

**EvalResult** captures: model_a (production), model_b (candidate), prompt hash, both responses, token counts, latencies, verdict, and score delta.

---

## 3. Routing Logic

The routing system operates at two levels:

### 3.1 Facade-level routing (facade.py)

`call_llm_unified()` is the single entry point for all LLM calls in ARGUS. Its routing logic:

```
┌──────────────────────────────────────────────────────────────┐
│  call_llm_unified(system_prompt, user_prompt, task, ...)     │
│                                                              │
│  task == None?                                               │
│    └─ YES → legacy generic router (deprecation warning)      │
│                                                              │
│  task == PERPLEXITY_OSINT?                                   │
│    └─ YES → Perplexity directly (WRB has no internet)        │
│                                                              │
│  WhiteRabbitNeo configured?                                  │
│    ├─ YES → call WRB                                         │
│    │   ├─ success → return                                   │
│    │   └─ failure → is task in _CLOUD_FALLBACK_TASKS?        │
│    │       ├─ YES → task_router (cloud fallback)             │
│    │       └─ NO  → raise RuntimeError (pentest tasks)       │
│    └─ NO  → task_router (legacy cloud path)                  │
└──────────────────────────────────────────────────────────────┘
```

**Cloud fallback whitelist** (`_CLOUD_FALLBACK_TASKS`):

- `REPORT_SECTION`
- `EXECUTIVE_SUMMARY`
- `COST_SUMMARY`
- `PERPLEXITY_OSINT`

All other tasks (ORCHESTRATION, THREAT_MODELING, EXPLOIT_GENERATION, VALIDATION_ONESHOT,
ZERO_DAY_ANALYSIS, DEDUP_ANALYSIS, REMEDIATION_PLAN, POC_GENERATION) are **pentest analysis
tasks** that use WhiteRabbitNeo **exclusively** — no cloud fallback is permitted.

### 3.2 Gateway-level routing (provider_clients.py + router.py)

When a request reaches the Gateway via `GatewayClient`:

1. Alias is resolved from `ALIAS_REGISTRY`.
2. If `airgapped_only` policy flag is set, cloud providers are skipped.
3. Providers within the alias are tried in declaration order. For `argus-pentest-primary` there is a single local provider (WRB). For cloud aliases like `argus-planner-fast`, there is typically one primary cloud provider.
4. On failure, a global fallback chain in `task_router.py` attempts: OpenRouter → Kimi → Perplexity → OpenAI → DeepSeek → Gemini (skipping already-attempted keys).

### 3.3 WRB-first philosophy

WhiteRabbitNeo-7B-AWQ is the **single source of truth** for all pentest analysis.
Cloud providers (DeepSeek, Qwen via OpenRouter, Perplexity) serve only as:

- **Report supplements** — formatting and summarization when WRB is unavailable.
- **OSINT enrichment** — Perplexity for internet-connected research (WRB has no network access).

This design ensures that sensitive source code and vulnerability data never leave the
local environment for analysis tasks.

---

## 4. Policy Engine

### 4.1 LLMPolicy (policy.py)

The full policy model, stored as `policy_jsonb` per scan and passed to the Gateway on every call.

```python
class LLMPolicy(BaseModel):
    tenant_id: str
    scan_id: str
    profile: Profile                    # QUICK | STANDARD | DEEP | ENTERPRISE
    region: str                         # default "eu-central-1"
    compliance: Compliance              # airgapped_only, no_cloud_llm_for_source_code, no_third_party_osint
    budget: Budget                      # max_cost_usd, soft_limit_usd, max_input_tokens, max_output_tokens
    routing: Routing                    # per-role RouteConfig (pentest, planner, code, devsecops, report)
    osint: OSINTConfig                  # alias, enabled, max_requests, max_cost_usd
    safety: Safety                      # allow_offensive_security, pentest_scope (domains, cidrs, allow_prod)
    telemetry: Telemetry                # trace_id, log_prompts (FULL|HASHED|OFF), log_responses (FULL|SUMMARY_ONLY|OFF)
```

**Model-level validation** (`validate_constraints`):
- `soft_limit_usd` must be less than `max_cost_usd`.
- Routes with `local_only=True` must only reference local aliases (`argus-pentest-primary`, `argus-code-local`, `argus-devsecops-local`).

**RouteConfig** per role specifies:
- `preferred_aliases` / `fallback_aliases` — ordered lists of alias names.
- `local_only` — if true, cloud providers are blocked for this role.
- `max_calls`, `max_input_tokens`, `max_output_tokens`, `max_cost_usd` — per-role hard limits.

### 4.2 PROFILE_DEFAULTS

Four built-in profiles that set budget and per-role limits:

| Profile | Budget (USD) | Soft Limit | Max Input | Max Output | Planner Calls | Code Calls | Report Calls |
|---|---|---|---|---|---|---|---|
| **QUICK** | $0.15 | $0.12 | 100K | 25K | 3 | 5 | 1 |
| **STANDARD** | $0.50 | $0.40 | 400K | 100K | 10 | 15 | 3 |
| **DEEP** | $1.50 | $1.20 | 800K | 200K | 25 | 30 | 5 |
| **ENTERPRISE** | $5.00 | $4.00 | 2M | 500K | 50 | 60 | 10 |

### 4.3 Task-to-role mapping

Defined in `task_router.py`:

```
ORCHESTRATION     → planner
THREAT_MODELING   → planner
VALIDATION_ONESHOT→ planner
DEDUP_ANALYSIS    → planner
ZERO_DAY_ANALYSIS → planner
POC_GENERATION    → code
EXPLOIT_GENERATION→ code
PERPLEXITY_OSINT  → osint
REPORT_SECTION    → report
EXECUTIVE_SUMMARY → report
REMEDIATION_PLAN  → report
COST_SUMMARY      → report
```

This mapping determines which `RouteConfig` (from the `Routing` model) applies to a given call.

### 4.4 Policy construction

`build_effective_policy()` merges a profile's defaults with optional overrides:

1. Starts from `PROFILE_DEFAULTS[profile]`.
2. Merges `budget_overrides` into budget defaults.
3. Builds per-role `RouteConfig` from routing defaults.
4. Applies `routing_overrides` by setting attributes on the existing `RouteConfig` objects.
5. Sets `compliance_overrides` on the `Compliance` model.
6. Returns a fully materialized `LLMPolicy`.

---

## 5. Provider Integration

### 5.1 WhiteRabbitNeo Adapter (whiterabbitneo_adapter.py)

The primary pentest AI adapter. Communicates with WhiteRabbitNeo-7B-AWQ served via vLLM
with an OpenAI-compatible API.

**Defaults:**
- Model: `taico-ai/WhiteRabbitNeo-v3-7B`
- Max tokens: 4096
- Temperature: 0.3
- Timeout: 300 seconds

**Key methods:**
- `call(prompt, system_prompt, model, max_tokens, temperature)` — standard completion returning text only.
- `call_with_usage(prompt, ...)` — returns `(text, usage_dict)` with `prompt_tokens`, `completion_tokens`, `total_tokens`.
- `health_check()` — GETs `/models` from the WRB endpoint; returns `"available"`, `"unavailable"`, or `"unconfigured"`.
- `is_configured` — true when `WHITERABBITNEO_URL` is non-empty.

**Singleton access:** `get_whiterabbitneo_adapter()` reads `settings.whiterabbitneo_url` and
`settings.whiterabbitneo_api_key` from `src.core.config`. Thread-safe lazy initialization.

### 5.2 DeepSeek Clients

Two provider keys share the same API:

| Key | Model | Base URL | Env Var |
|---|---|---|---|
| `deepseek-v4-flash` | `deepseek-chat` | `https://api.deepseek.com/v1` | `DEEPSEEK_API_KEY` |
| `deepseek-v4-pro` | `deepseek-v4-pro` | `https://api.deepseek.com/v1` | `DEEPSEEK_API_KEY` |

Used via the Gateway's `ProviderRouter` (standard OpenAI-compatible path) and also directly
in `cloud_supplement.py` for report fallback when WRB is down.

### 5.3 Qwen Client (via OpenRouter)

| Key | Model | Base URL | Env Var |
|---|---|---|---|
| `qwen3-coder-480b` | `qwen/qwen3-coder:free` | `https://openrouter.ai/api/v1` | `OPENROUTER_API_KEY` |

Serves the `argus-code-cloud` alias. For local code tasks, `qwen3-32b-local` runs a local
Qwen3-32B instance at `http://qwen3-32b-coder.llm-serving.svc:8000/v1`.

### 5.4 Perplexity Client

| Key | Model | Base URL | Env Var |
|---|---|---|---|
| `perplexity` | `sonar` | `https://api.perplexity.ai` | `PERPLEXITY_API_KEY` |

Serves `argus-osint` for internet-connected OSINT enrichment. The highest-cost provider at
$1.00/M input and $1.00/M output tokens.

### 5.5 Gateway Client (gateway_client.py)

Typed async HTTP client that the LLM module uses to communicate with the Gateway service.

- `GatewayClient(base_url)` — wraps `POST {base_url}/v1/chat/completions`.
- `chat_completion(model, messages, policy, metadata, temperature, max_tokens)` — sends serialized `LLMPolicy` as the `policy` field and metadata as the `metadata` field. Returns a `GatewayResponse` with parsed content, token usage, cost estimate, and policy decision.
- `GatewayClientError` — typed exception with `code`, `message`, and `details` fields. Raised for timeout, connection failure, 403 (policy denied), 502 (all providers failed), and parse errors.
- Singleton via `get_gateway_client()` — reads `settings.llm_gateway_url`; returns `None` if not configured.

---

## 6. Security

### 6.1 Redaction Module

All prompts and responses flowing through the Gateway are subject to redaction (see Section 2.6).
The default telemetry mode hashes prompts and only stores truncated summaries of responses.
Full-content logging requires an explicit policy override (`LogMode.FULL`).

No raw API keys, bearer tokens, AWS access keys, GitHub tokens, private keys, or
credential parameters ever appear in logs or stored records.

### 6.2 Prompt Injection Protection

The `Safety` policy model includes `pentest_scope` (target domains, CIDR ranges, and
`allow_prod` flag) and `allow_offensive_security`. These are consumed by the ARGUS
SafetyMonitor subsystem (not within the Gateway itself) which validates LLM outputs
against scope boundaries before they reach execution pipelines.

### 6.3 API Key Management

All provider API keys are read from environment variables at call time — never hardcoded,
never stored in the database, never logged:

| Provider Key | Environment Variable |
|---|---|
| `whiterabbitneo-7b` | `WHITERABBITNEO_API_KEY` |
| `deepseek-v4-flash` | `DEEPSEEK_API_KEY` |
| `deepseek-v4-pro` | `DEEPSEEK_API_KEY` |
| `qwen3-coder-480b` | `OPENROUTER_API_KEY` |
| `qwen3-32b-local` | *(none — local service, no auth)* |
| `perplexity` | `PERPLEXITY_API_KEY` |

Keys are resolved via `ProviderRouter._get_api_key()` which returns an empty string
(not an error) when an env var is not set, allowing local providers to work without
authentication.

### 6.4 Data Isolation Guarantees

- **Airgapped mode** (`compliance.airgapped_only`) — all cloud provider aliases are blocked at the policy enforcer. Only `argus-pentest-primary`, `argus-code-local`, and `argus-devsecops-local` are permitted.
- **Source code isolation** (`compliance.no_cloud_llm_for_source_code`) — any request with `metadata.content_class == "source_code"` is blocked from all aliases except `argus-pentest-primary`. Ensures code never reaches cloud LLMs.
- **Pentest tasks** — always use WhiteRabbitNeo locally. The facade's routing logic raises `RuntimeError` if WRB is unavailable for a pentest task, preventing silent cloud fallback.

---

## 7. Observability

### 7.1 Usage Ledger

Every Gateway call records an entry with:
- Tenant ID, scan ID, phase, and task (for cost attribution).
- Alias, provider key, and resolved model.
- Prompt tokens, completion tokens, total tokens.
- Estimated cost in USD (computed from provider pricing and token counts).
- UTC timestamp.

Aggregated summaries (`get_usage_summary`) provide per-tenant/per-scan totals and
breakdowns by provider and model.

### 7.2 Cost Tracking

The facade layer integrates a per-scan `CostTracker` (`src.llm.cost_tracker`).
Every call through `call_llm_unified()` where a `scan_id` is provided records:
- Phase and task label.
- Model name.
- Prompt and completion token counts.

Token counting uses `response.usage` from the provider as the primary source and
falls back to tiktoken (`cl100k_base` encoding) when usage data is unavailable.

The `estimated_cost_usd` in the Gateway response is computed as:

```
cost = (input_price_per_million * prompt_tokens / 1_000_000)
     + (output_price_per_million * completion_tokens / 1_000_000)
```

### 7.3 Health Checks

| Endpoint | Purpose |
|---|---|
| `GET /health` | Kubernetes liveness probe |
| `GET /ready` | Kubernetes readiness probe |
| `GET /metrics` | Prometheus metrics placeholder |
| `GET /providers/health` | Provider configuration audit — lists every alias/provider with its cloud flag and whether a base URL is set |

---

## 8. Testing & Evaluation

### 8.1 Replay System (replay/)

The replay module enables deterministic regression testing of LLM behavior:

1. **Recording** — `ReplayRecord` captures the full input/output of a real Gateway call
   (messages, response, token usage, provider, duration, policy decision).

2. **Storage** — Records accumulate in an in-memory list during a session.

3. **Retrieval** — `get_records()` filters by model and/or provider, returning the
   most recent N records.

4. **Replay** — `replay_call()` re-submits the recorded messages to a target Gateway
   instance at `temperature=0.0`. It compares the original and replayed responses
   (by exact string match) and reports timing deltas.

**Use cases:**
- Verifying that provider/model changes do not degrade output quality.
- Debugging non-deterministic behavior.
- Auditing historical decisions.

### 8.2 Canary / Shadow Evaluation (eval/)

The eval framework supports safe testing of new models in production:

**Canary (CanaryRouter):**
- Configuration: `canary_ratio` (default 0.05 = 5%).
- Uses deterministic hashing (MD5 of the prompt) to decide whether a request goes to
  the candidate model. The same prompt always maps to the same decision.
- The canary path replaces the production provider for that request — the user sees
  the candidate model's output.

**Shadow (ShadowEvaluator):**
- Runs the candidate model **in parallel** with production.
- The user always receives the production response. The candidate output is captured
  asynchronously for comparison.
- Each shadow call produces an `EvalResult` with:
  - Both responses and their token counts.
  - Latency for both paths.
  - A score based on word-overlap similarity (70% baseline overlap = "same").
  - Verdict: `better`, `same`, `worse`, or `error`.

**Aggregation** (`ShadowEvaluator.summary()`):
- Total, better, same, worse, error counts.
- Better rate and average score delta.
- Candidate model identifier.

**Comparison scoring** (`_compare_responses`):
- Computes the Jaccard-like overlap of unique lowercase words.
- `score = overlap_ratio - 0.7`
- Positive → candidate response has more lexical overlap with production.
  Negative → candidate response diverges significantly.

