# ARGUS LLM Stack Rework Prompt For OpenCode/Cursor

Ты работаешь в репозитории ARGUS: `D:\Developer\Pentest_test\ARGUS`.

Твоя задача: переработать LLM-слой ARGUS в сторону policy-driven `llm-gateway`, сохранив совместимость текущего backend, Frontend API contracts, scan state machine и report pipeline. Не меняй публичный `Frontend/` и существующие response shapes без обратной совместимости.

## Контекст

ARGUS сейчас уже имеет:

- FastAPI backend: `backend/src`.
- LLM facade: `backend/src/llm/facade.py`.
- Task routing: `backend/src/llm/task_router.py`.
- Provider adapters: `backend/src/llm/adapters.py`.
- Per-scan cost tracking: `backend/src/llm/cost_tracker.py`.
- Prompt registry and JSON repair logic: `backend/src/orchestration/prompt_registry.py`, `backend/src/orchestration/ai_prompts.py`.
- Tenant policy engine: `backend/src/policy/policy_engine.py`.
- Provider health: `backend/src/api/routers/providers_health.py`, `backend/src/core/provider_health_registry.py`.
- Helm prod overlay: `infra/helm/argus/values-prod.yaml`.
- Deployment runbook: `docs/deployment-helm.md`.

Новые предложения по LLM-стеку:

- Cloud planner/reasoning: DeepSeek Flash/Pro-class models through external API.
- Cloud code worker: Qwen Coder 480B-class model through external API.
- Local code worker fallback: Qwen 32B-class model through vLLM.
- Local DevSecOps critic: WhiteRabbitNeo 7B-class model through vLLM.
- Single `llm-gateway` for routing, budget enforcement, provider health, telemetry and compliance.
- Celery remains the task queue; RabbitMQ should be supported for production while Redis remains valid for dev.
- NATS JetStream is optional event bus for LLM and scan lifecycle events.

Important: do not hardcode vendor-specific future model names as product invariants. Implement them as configurable aliases. The operator must be able to map `argus-planner-fast` to any concrete provider/model.

## Target Architecture

```text
Frontend / API / MCP
        |
        v
ARGUS backend
  - scan state machine
  - prompt registry
  - schema validation
  - policy preflight
  - findings/report persistence
        |
        v
llm-gateway
  - OpenAI-compatible internal API
  - alias routing
  - per-tenant/per-scan JSON policy enforcement
  - token and cost ledger
  - provider fallback
  - prompt/response redaction
  - provider health
        |
        +--> external cloud LLMs
        |      planner, deep reasoning, report, OSINT
        |
        +--> llm-serving namespace
               vLLM: qwen-code-local
               vLLM: devsecops-local
```

The backend keeps owning security semantics. The gateway routes and meters LLM calls, but it must not bypass scope, approvals, payload registry, exploit gates, or prompt JSON schema validation.

## Security Rules

1. Keep all offensive actions behind existing scope, ownership, approval and policy gates.
2. LLMs must not execute shell commands or tools directly.
3. LLMs must not generate arbitrary destructive payloads. They may choose payload family IDs and validation strategy IDs only.
4. Cloud LLMs must not receive source code, secrets, credentials, raw exploit payloads or tenant-private artifacts when policy says `no_cloud_llm_for_source_code` or `airgapped_only`.
5. Local "DevSecOps/offensive" models are advisory critics only. They do not bypass safety policy.
6. Full prompts/responses are not logged unless explicitly enabled by tenant policy. Default logging is `hashed` prompts and `summary_only` responses.
7. Any implementation that touches stored tenant data must preserve RLS and tenant scoping.

## Model Aliases

Implement aliases, not hardcoded vendor names:

```yaml
argus-planner-fast:
  role: planner
  default_provider: deepseek
  default_model: configurable
  cloud_allowed: true

argus-planner-deep:
  role: reasoning
  default_provider: deepseek
  default_model: configurable
  cloud_allowed: true

argus-code-cloud:
  role: code
  default_provider: openrouter_or_qwen_provider
  default_model: configurable
  cloud_allowed: true

argus-code-local:
  role: code
  default_provider: local_vllm
  default_model: configurable
  cloud_allowed: false

argus-devsecops-local:
  role: devsecops
  default_provider: local_vllm
  default_model: configurable
  cloud_allowed: false

argus-report:
  role: report
  default_provider: configurable
  default_model: configurable
  cloud_allowed: true

argus-osint:
  role: osint
  default_provider: perplexity_or_grounded_search_provider
  default_model: configurable
  cloud_allowed: true
```

## JSON Policy Contract

Create strict Pydantic models for this policy. Store a normalized copy per scan and pass the effective policy to `llm-gateway` on each call.

```json
{
  "tenant_id": "tnt_123",
  "scan_id": "scan_2026_0001",
  "profile": "standard",
  "region": "eu-central-1",
  "compliance": {
    "no_third_party_osint": false,
    "no_cloud_llm_for_source_code": false,
    "airgapped_only": false
  },
  "budget": {
    "max_cost_usd": 0.5,
    "soft_limit_usd": 0.4,
    "max_input_tokens": 400000,
    "max_output_tokens": 100000
  },
  "routing": {
    "planner": {
      "preferred_aliases": ["argus-planner-fast"],
      "fallback_aliases": ["argus-planner-deep"],
      "max_calls": 5,
      "max_input_tokens": 200000,
      "max_output_tokens": 50000,
      "max_cost_usd": 0.15
    },
    "code": {
      "preferred_aliases": ["argus-code-cloud"],
      "fallback_aliases": ["argus-code-local"],
      "local_only": false,
      "max_calls": 20,
      "max_input_tokens": 150000,
      "max_output_tokens": 50000,
      "max_cost_usd": 0.2
    },
    "devsecops": {
      "preferred_aliases": ["argus-devsecops-local"],
      "fallback_aliases": [],
      "local_only": true,
      "max_calls": 15,
      "max_input_tokens": 100000,
      "max_output_tokens": 40000,
      "max_cost_usd": 0.1
    },
    "report": {
      "preferred_aliases": ["argus-report"],
      "fallback_aliases": ["argus-planner-fast"],
      "max_calls": 2,
      "max_input_tokens": 50000,
      "max_output_tokens": 30000,
      "max_cost_usd": 0.15
    }
  },
  "osint": {
    "alias": "argus-osint",
    "enabled": true,
    "max_requests": 5,
    "max_cost_usd": 0.1
  },
  "safety": {
    "allow_offensive_security": true,
    "pentest_scope": {
      "domains": ["example.com"],
      "cidrs": ["203.0.113.0/24"],
      "allow_prod": false
    }
  },
  "telemetry": {
    "trace_id": "trace_abc",
    "log_prompts": "hashed",
    "log_responses": "summary_only"
  }
}
```

Validation requirements:

- `profile`: `quick | standard | deep | enterprise`.
- `log_prompts`: `full | hashed | off`; default `hashed`.
- `log_responses`: `full | summary_only | off`; default `summary_only`.
- `max_cost_usd` must be positive and bounded by tenant subscription limits.
- `local_only=true` must reject all aliases whose resolved provider is cloud.
- `airgapped_only=true` must reject all external cloud providers and OSINT providers.
- `no_cloud_llm_for_source_code=true` must reject cloud routes when the request has `content_class=source_code`.

## Implementation Plan

### Phase 1: Gateway contract and backend compatibility

Add:

- `backend/src/llm/policy.py`
  - Pydantic policy models.
  - Effective policy builder from tenant/scans/options.
  - Safe defaults for quick/standard/deep/enterprise profiles.

- `backend/src/llm/model_aliases.py`
  - Alias registry.
  - Alias resolution from env/config/DB.
  - No vendor model name hardcoded as an invariant.

- `backend/src/llm/gateway_client.py`
  - Async client to internal `llm-gateway`.
  - OpenAI-compatible request/response support.
  - Typed errors: budget exceeded, policy denied, provider unavailable, schema error.

Modify:

- `backend/src/llm/facade.py`
  - If `LLM_GATEWAY_URL` is configured, route all task calls through gateway.
  - Otherwise keep the current in-process `task_router` fallback.
  - Preserve `call_llm_unified(...)` public signature.

- `backend/src/llm/task_router.py`
  - Keep as legacy fallback.
  - Add mapping from existing `LLMTask` values to new route roles:
    - `ORCHESTRATION`, `THREAT_MODELING` -> `planner`
    - `VALIDATION_ONESHOT`, `DEDUP_ANALYSIS` -> `planner`
    - `POC_GENERATION`, `EXPLOIT_GENERATION` -> `code`, but only for safe template/family planning, not raw exploit payloads
    - `PERPLEXITY_OSINT` -> `osint`
    - `REPORT_SECTION`, `EXECUTIVE_SUMMARY`, `REMEDIATION_PLAN`, `COST_SUMMARY` -> `report`

Acceptance:

- Existing tests that call `call_llm_unified` still pass with no `LLM_GATEWAY_URL`.
- With `LLM_GATEWAY_URL`, backend sends one typed gateway request and records the returned usage.
- No Frontend contract changes.

### Phase 2: Standalone llm-gateway service in the backend image

Add package:

- `backend/src/llm_gateway/app.py`
- `backend/src/llm_gateway/router.py`
- `backend/src/llm_gateway/policy_enforcer.py`
- `backend/src/llm_gateway/provider_clients.py`
- `backend/src/llm_gateway/usage_ledger.py`
- `backend/src/llm_gateway/redaction.py`

Expose endpoints:

```text
POST /v1/chat/completions
GET  /health
GET  /ready
GET  /metrics
GET  /providers/health
```

Gateway request body:

```json
{
  "model": "argus-planner-fast",
  "messages": [],
  "temperature": 0.2,
  "max_tokens": 2000,
  "metadata": {
    "tenant_id": "tnt_123",
    "scan_id": "scan_123",
    "phase": "recon",
    "task": "orchestration",
    "content_class": "scan_metadata"
  },
  "policy": {}
}
```

Gateway response:

```json
{
  "id": "llmreq_...",
  "model": "argus-planner-fast",
  "resolved_provider": "deepseek",
  "resolved_model": "configured-model-name",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "{}"
      },
      "finish_reason": "stop"
    }
  ],
  "usage": {
    "prompt_tokens": 1000,
    "completion_tokens": 300,
    "total_tokens": 1300,
    "estimated_cost_usd": 0.001
  },
  "policy_decision": {
    "allowed": true,
    "reason": null
  }
}
```

Error response:

```json
{
  "error": {
    "code": "llm_policy_denied",
    "message": "LLM request denied by policy",
    "details": {
      "reason": "airgapped_only_blocks_cloud_provider",
      "alias": "argus-report"
    }
  }
}
```

Acceptance:

- Gateway enforces per-route max calls, tokens and cost.
- Gateway refuses cloud aliases when `airgapped_only=true`.
- Gateway emits Prometheus counters for requests, tokens, cost, provider errors and policy denies.
- Gateway never logs full prompts by default.

### Phase 3: Persistence and audit

Add Alembic migration and SQLAlchemy models:

- `llm_policies`
- `llm_invocations`
- `llm_usage_ledger`
- `llm_model_aliases`

Tenant-scoped tables must have `tenant_id` and RLS policies.

Suggested columns:

```text
llm_policies:
  id, tenant_id, scan_id, profile, policy_json, effective_at, created_at

llm_invocations:
  id, tenant_id, scan_id, phase, task, alias, resolved_provider,
  resolved_model, prompt_hash, response_hash, status, error_code,
  prompt_tokens, completion_tokens, estimated_cost_usd, latency_ms, created_at

llm_usage_ledger:
  id, tenant_id, scan_id, provider, model, direction, tokens,
  estimated_cost_usd, created_at

llm_model_aliases:
  id, tenant_id nullable, alias, provider_key, model, base_url,
  role, cloud_allowed, enabled, config_json, created_at, updated_at
```

Acceptance:

- Audit entries are immutable append-only.
- API keys and raw prompts are never stored in plaintext.
- RLS tests prove tenant isolation.

### Phase 4: Admin and provider configuration

Extend existing admin provider UI/API without breaking current contracts:

- Add model alias configuration.
- Add LLM policy profile view.
- Add cost per tenant/scan/provider view.
- Add provider health and fallback state view.

Files to inspect first:

- `backend/src/api/routers/admin.py`
- `admin-frontend/`
- `docs/api-contracts.md`
- `docs/frontend-api-contract.md`

Acceptance:

- Admin can disable a provider/alias without code deployment.
- Tenant can have stricter local-only policy.
- Existing provider endpoints keep working.

### Phase 5: Helm and runtime

Modify Helm chart:

- Add `llmGateway.enabled`.
- Add `replicaCount.llmGateway`.
- Add `resources.llmGateway`.
- Add NetworkPolicy egress from backend/celery to llm-gateway only.
- Add NetworkPolicy egress from llm-gateway to allowed external provider FQDNs and local vLLM services.
- Add `LLM_GATEWAY_URL` env to backend/celery when enabled.

Add optional namespace/profile:

- `llm-serving`.
- GPU node selector and tolerations.
- vLLM deployments disabled by default:
  - `qwen-code-local`
  - `devsecops-local`

Do not require GPU for normal SaaS deployment. Local models are optional enterprise/on-prem features.

Acceptance:

- `values-dev.yaml`: gateway off by default, legacy in-process LLM works.
- `values-staging.yaml`: gateway on with external providers.
- `values-prod.yaml`: gateway on, NetworkPolicies on, provider egress allowlisted.
- `helm_lint` passes for dev/staging/prod.

### Phase 6: Celery broker and event bus

Keep Redis broker compatibility. Add RabbitMQ support through config only:

- `CELERY_BROKER_URL=redis://...` remains valid.
- `CELERY_BROKER_URL=amqp://...` must work.
- Document RabbitMQ as recommended production broker.

NATS JetStream is optional. If implemented, publish:

```text
llm.requested
llm.completed
llm.denied
llm.provider.degraded
llm.budget.soft_limit
llm.budget.exceeded
scan.plan.created
scan.report.ready
```

Acceptance:

- No hard dependency on NATS for core scan completion.
- Failed event publish never fails the LLM call path.

## Tests To Add

Unit tests:

- `backend/tests/unit/llm/test_policy_models.py`
- `backend/tests/unit/llm/test_model_aliases.py`
- `backend/tests/unit/llm/test_gateway_client.py`
- `backend/tests/unit/llm_gateway/test_policy_enforcer.py`
- `backend/tests/unit/llm_gateway/test_redaction.py`

Integration tests:

- Gateway request with standard policy succeeds.
- Gateway request over max cost fails closed.
- `airgapped_only=true` blocks cloud provider.
- `local_only=true` routes only to local vLLM alias.
- Backend `call_llm_unified` uses gateway when configured and legacy fallback when not configured.
- RLS isolation for `llm_*` tables.

Contract tests:

- Existing scan/report endpoints unchanged.
- Existing provider admin endpoints unchanged.
- Existing SSE event names unchanged.

Security tests:

- Prompt logging defaults to hash-only.
- API keys are redacted in logs, DB and errors.
- Cloud route rejects `content_class=source_code` under compliance policy.
- Raw exploit payload generation is rejected unless it is a safe payload-registry family ID and existing approval gates pass.

## Documentation To Update

Create or update:

- `docs/llm-gateway.md`
- `docs/provider-adapters.md`
- `docs/deployment-helm.md`
- `docs/security-model.md`
- `docs/observability.md`
- `docs/prompt-registry.md`

Include:

- Architecture diagram.
- JSON policy examples.
- Alias mapping examples.
- Budget defaults per profile.
- Local vLLM deployment notes.
- Migration guide from legacy in-process routing.

## Recommended Defaults

Do not use a high default per-scan budget. Current `MAX_COST_PER_SCAN_USD=10.0` is too loose for SaaS defaults.



Use soft limit at 80% of hard cap.

## Definition Of Done

The rework is complete when:

1. ARGUS works with no `LLM_GATEWAY_URL` exactly as before.
2. ARGUS works with `LLM_GATEWAY_URL` and all LLM calls go through gateway.
3. Gateway enforces JSON policy, budget, route limits and compliance flags.
4. Gateway supports cloud aliases and local OpenAI-compatible vLLM aliases.
5. LLM usage is visible per tenant, scan, phase, task, provider and model.
6. Helm chart deploys llm-gateway as a separate service.
7. Optional local vLLM deployments are disabled by default and documented.
8. Tests cover fallback, policy denies, budget caps, redaction and RLS.
9. Frontend public API contracts remain compatible.
10. Security posture is stricter than before: no raw prompt leakage, no cloud-source-code leaks under policy, no LLM bypass around exploit approvals.

## External References For The Implementer

Use official docs where possible:

- Kubernetes Gateway API Inference Extension: https://gateway-api-inference-extension.sigs.k8s.io/
- vLLM serving and deployment docs: https://docs.vllm.ai/
- NATS JetStream docs: https://docs.nats.io/nats-concepts/jetstream
- Celery broker docs: https://docs.celeryq.dev/en/stable/getting-started/backends-and-brokers/

