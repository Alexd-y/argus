# ARGUS Observability Guide

> Status: production · Owners: Backend Platform · Last updated: 2026-04-21
> Tracking ticket: **ARG-041 — Observability**

This document is the contract between ARGUS and the operations world. It
covers the three observability pillars — **metrics**, **traces**, and
**logs** — plus the four health endpoints we expose for orchestrators.

The single source of truth for the metric catalogue is
`backend/src/core/observability.py::METRIC_CATALOGUE`. Tests in
`backend/tests/unit/core/test_observability.py` and
`backend/tests/security/test_observability_cardinality.py` lock the
catalogue, the label whitelists, and the cardinality cap.

---

## 1. Design principles

1. **No PII in observability data.** We never emit raw `tenant_id`,
   `user_id`, request bodies, secrets, or full headers. Tenants are
   reduced to a stable, salted SHA-256 hash (`tenant_hash`) before being
   used as a label or span attribute.
2. **Cardinality is bounded.** Each metric family enforces a hard cap of
   1 000 unique label-value combinations. Excess values collapse to the
   `_other` sentinel and we log a single warning per family. This stops
   runaway cardinality from killing Prometheus.
3. **Observability never breaks the request path.** Every recorder
   (`record_*`, `safe_set_span_attribute`, redactors) is wrapped in
   defensive `try/except` blocks. If telemetry fails the request still
   completes and we log a warning.
4. **Off by default for OTel exports.** The OTel SDK is initialised only
   when `OTEL_ENABLED=true`. The instrumented codepaths still work in a
   no-op mode, so unit tests stay fast.
5. **Single source of truth.** All metric families and label whitelists
   live in `backend/src/core/observability.py`. Tests assert the
   catalogue. New labels MUST be added there first, then mirrored in
   §3 of this document.

---

## 2. Configuration

All settings live in `backend/src/core/config.py` (Pydantic settings).
Override via environment variables — variable names match the field
names directly (the validation aliases also accept the
`OTEL_EXPORTER_OTLP_ENDPOINT` legacy name for `OTEL_OTLP_ENDPOINT`).

| Variable                       | Default                  | Description                                                                              |
| ------------------------------ | ------------------------ | ---------------------------------------------------------------------------------------- |
| `OTEL_ENABLED`                 | `false`                  | Master switch for the OpenTelemetry SDK and all auto-instrumentors.                      |
| `OTEL_OTLP_ENDPOINT`           | `http://localhost:4317`  | OTLP gRPC endpoint of the collector. HTTP/protobuf is intentionally not supported.       |
| `OTEL_INSECURE`                | `true`                   | Disables TLS for the gRPC channel (dev/local). MUST be `false` in production.            |
| `OTEL_SERVICE_NAME`            | `argus`                  | `service.name` resource attribute exported on every span.                                |
| `OTEL_ENVIRONMENT`             | `development`            | `deployment.environment` resource attribute. Use `staging` / `production` as appropriate.|
| `OTEL_SAMPLER_RATIO`           | `1.0`                    | Parent-based ratio sampler. Production typically `0.05`–`0.20`. Validated in `[0,1]`.    |
| `TENANT_HASH_SALT`             | `""` (empty)             | Salt used by `tenant_hash`. **Set to a long random secret in production.**               |

A few consequential defaults:

- `/health`, `/ready`, `/metrics`, `/providers/health`, `/queues/health`
  are excluded from FastAPI auto-instrumentation (`EXCLUDED_URLS` in
  `backend/src/core/otel_init.py`) to avoid trace self-amplification.
- The OTel sampler is `ParentBased(TraceIdRatioBased(ratio))` so inbound
  trace context is honoured verbatim and child spans never break the
  parent's sampling decision.
- The HTTP middleware (`backend/src/core/metrics_middleware.py`)
  classifies `/api/v1/scans/{scan_id}` style routes by the FastAPI route
  template, never by the literal `id`, to keep cardinality flat.

> ⚠️ Production checklist
> 1. `OTEL_ENABLED=true`
> 2. `OTEL_INSECURE=false` and a TLS-terminated collector endpoint
> 3. `TENANT_HASH_SALT` rotated like any other secret (Vault / Secrets
>    Manager). Do **not** commit the value.
> 4. `OTEL_SAMPLER_RATIO` ≤ 0.20 unless you have tail-based sampling
>    in the collector.

---

## 3. Metrics catalogue

All metrics use the `argus_` prefix and Prometheus naming conventions
(`_total` for counters, `_seconds` for histograms, base unit in name).
The catalogue is exactly **9 families**; growing it requires updating
`METRIC_CATALOGUE` and `tests/unit/core/test_observability.py`.

| Family                                  | Type      | Labels                                              | Notes                                                                  |
| --------------------------------------- | --------- | --------------------------------------------------- | ---------------------------------------------------------------------- |
| `argus_http_requests_total`             | Counter   | `method`, `route`, `status_class`, `tenant_hash`    | Emitted by `HttpMetricsMiddleware`. `status_class` ∈ {1xx…5xx,_other}. |
| `argus_http_request_duration_seconds`   | Histogram | `method`, `route`, `tenant_hash`                    | Buckets: 5 ms … 10 s (HTTP_BUCKETS in `observability.py`).             |
| `argus_celery_task_duration_seconds`    | Histogram | `task_name`, `status`                               | Buckets: 100 ms … 5 min. Set in `task_postrun` signal.                 |
| `argus_celery_task_failures_total`      | Counter   | `task_name`, `error_class`                          | Counter increments only on `status="failure"`.                         |
| `argus_sandbox_runs_total`              | Counter   | `tool_id`, `status`, `profile`                      | Recorded in the sandbox runner finally-block.                          |
| `argus_sandbox_run_duration_seconds`    | Histogram | `tool_id`, `profile`                                | Buckets: 1 s … 5 min. Wall-clock per sandboxed tool run.               |
| `argus_findings_emitted_total`          | Counter   | `tier`, `severity`, `kev_listed`                    | `severity` ∈ {info,low,medium,high,critical}. `kev_listed` is `"true"/"false"`. |
| `argus_llm_tokens_total`                | Counter   | `provider`, `model`, `direction`                    | `direction` ∈ {`in`, `out`}. Tokens consumed by LLM calls.             |
| `argus_mcp_calls_total`                 | Counter   | `tool`, `status`, `client_class`                    | `client_class` ∈ {anthropic, openai, generic}. `status` whitelist below.|

Status whitelists (`backend/src/core/observability.py`):

- `_HTTP_METHODS` = `{GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD}`
- `_HTTP_STATUS_CLASSES` = `{1xx, 2xx, 3xx, 4xx, 5xx}`
- `_CELERY_STATUSES` = `{success, failure, retry, revoked, rejected}`
- `_SANDBOX_STATUSES` = `{success, error, timeout, skipped, cancelled}`
- `_SANDBOX_PROFILES` = `{recon, active_scan, exploit, kubernetes, docker, local, stub}`
- `_FINDING_TIERS` = `{midgard, asgard, valhalla, internal}`
- `_FINDING_SEVERITIES` = `{info, low, medium, high, critical}`
- `_LLM_PROVIDERS` = `{anthropic, openai, deepseek, openrouter, google, kimi, perplexity}`
- `_LLM_DIRECTIONS` = `{in, out}`
- `_MCP_STATUSES` = `{success, error, rate_limited, unauthorized, forbidden, validation_error}`
- `_MCP_CLIENT_CLASSES` = `{anthropic, openai, generic}`

### 3.1 `tenant_hash` discipline

`tenant_hash(tenant_id)` returns
`sha256((tenant_id + salt).encode("utf-8")).hexdigest()[:16]` — 16 hex
chars ≈ 64 bits of entropy. It is deterministic across replicas as long
as `TENANT_HASH_SALT` matches. `None` / empty `tenant_id` collapses to
the `SYSTEM_TENANT_HASH` sentinel (`"system"`), so background jobs that
are not tenant-scoped never pollute the cardinality budget.

The MCP runtime maps internal status codes (`ok`, `denied`) onto the
metric whitelist via `_INTERNAL_TO_METRIC_STATUS`
(`backend/src/mcp/tools/_runtime.py`). Adding a new internal status MUST
also map it onto a value already in `_MCP_STATUSES`; the unit test
`tests/unit/mcp/test_runtime.py::TestRunToolMetricMapping` enforces
this.

### 3.2 Cardinality enforcement

The label guard works in two phases:

1. **Whitelist filter** — any label value not in the family's whitelist
   is replaced with `_other` and a single warning per offending value
   is logged (`observability.label_value_rejected`).
2. **Cap enforcement** — the first 1 000 unique value-tuples per family
   are accepted. Subsequent novel tuples are silently dropped (the
   metric is not incremented) and a single warning is logged per family
   (`observability.cardinality_cap_reached`). This is asserted in
   `tests/security/test_observability_cardinality.py`.

The cap is process-local; a Prometheus exposition replica with N worker
threads has N independent guards. Prometheus deduplicates by label set
across replicas during the scrape, so the global cap is effectively
`N × 1000`.

### 3.3 Scrape endpoint

```
GET /metrics
Content-Type: text/plain; version=0.0.4; charset=utf-8
```

Implementation: `backend/src/api/routers/metrics.py` calls
`get_metrics_content()`. The endpoint is unauthenticated by design
(Prometheus scrapes from within the cluster). Bind it to an internal
interface or restrict via NetworkPolicy in production. There is no
`tenant_hash` filter — `/metrics` is the operator's view, not a
tenant-facing API.

---

## 4. Tracing

### 4.1 Pipeline

```
FastAPI / Celery / HTTPX / Redis / SQLAlchemy
       │
       ▼
TracerProvider (ParentBased(TraceIdRatioBased(arg)))
       │
       ▼
BatchSpanProcessor → OTLPSpanExporter (gRPC) → otel-collector → Tempo / Jaeger
```

The provider is initialised once in
`backend/src/core/otel_init.py::setup_observability`, called from the
FastAPI lifespan context (`backend/main.py`), and once on each Celery
worker via `setup_celery_observability` in `backend/src/celery_app.py`.
Re-entrancy is safe — both functions are idempotent and quietly no-op
when `OTEL_ENABLED=false`.

When the OTLP wheel cannot be imported, the exporter falls back to the
console exporter and emits `otel.exporter.fallback_to_console`. The
application path is unaffected.

### 4.2 Span attribute discipline

Use **only** `safe_set_span_attribute(span, key, value)` from
`src.core.observability`. It enforces:

- A blocklist on attribute keys: `tenant_id`, `tenantid`, `tenant.id`,
  `user_id`, `userid`, `authorization`, `cookie`, `x-api-key`. These
  are silently dropped with a `observability.span_attribute_rejected`
  warning. Use `tenant.hash` instead (computed via `tenant_hash()`).
- Defensive `try/except` around `span.set_attribute` so a bad value
  (non-primitive, NaN) never breaks the request.

Custom spans currently emitted:

| Module                                  | Span name             | Key attributes                                              |
| --------------------------------------- | --------------------- | ----------------------------------------------------------- |
| `src/sandbox/runner.py`                 | `sandbox.run`         | `argus.tool_id`, `argus.scan_id`, `argus.job_id`, `argus.status`, `argus.duration_seconds` |
| `src/oast/correlator.py`                | `oast.correlate`      | `argus.token_id`, `argus.kind`                              |
| `src/reports/report_service.py`         | `report.generate`     | `tenant.hash`, `argus.tier`, `argus.format`, `argus.scan_id`|
| `src/mcp/tools/_runtime.py`             | `mcp.tool`            | `argus.tool`, `tenant.hash`, `argus.status`                 |
| `src/core/observability.py::trace_phase`| `scan.phase.<phase>`  | `argus.scan_id`, `argus.phase`, `tenant.hash`               |

### 4.3 Sampling guidance

- Local dev / CI: `OTEL_SAMPLER_RATIO=1.0` so every span lands in the
  collector (the default).
- Staging: `0.5`.
- Production: `0.05`–`0.20`. Tail-based sampling is left to the
  collector; we do not implement it in-process.

---

## 5. Logging

The logger of record is `pythonjsonlogger.jsonlogger.JsonFormatter`
configured in `backend/src/core/logging_config.py`. Every record carries:

- `timestamp` — ISO-8601 UTC.
- `level`, `logger`, `message`.
- `service.name`, `service.version`, `deployment.environment` —
  injected from settings at boot.
- `trace_id`, `span_id` — injected by `OTelTraceContextFilter` when an
  active span is present. Names follow the OTLP convention
  (lowercase, no separators) so log → trace correlation works in
  Grafana/Tempo without manual mapping.
- Anything passed via `logger.info("…", extra={…})`.

When OTel is disabled or no span is active, the trace context fields
are simply absent (no `null` placeholders).

### 5.1 Sensitive header redaction

`SensitiveHeaderRedactor` runs as a `logging.Filter`. It walks every
record's `extra` payload and replaces any value attached to a key in
`SENSITIVE_HEADER_KEYS` (`Authorization`, `Cookie`, `Set-Cookie`,
`X-Api-Key`, `Proxy-Authorization`) with `"<redacted>"`. The filter is
**idempotent** — re-running on an already-redacted record is a no-op.
This is asserted in `backend/tests/security/test_observability_cardinality.py`.

### 5.2 Forbidden log content

- ❌ Stack traces in user-visible responses (allowed in logs only at
  `ERROR` level with structured `exc_info`).
- ❌ Full request bodies, secrets, JWT contents.
- ❌ Raw `tenant_id` outside of audit logs (which live in
  `policy_audit_events` and follow a different policy).

---

## 6. Health endpoints

We expose four endpoints. All return JSON; non-200 statuses use the
shared schemas in `backend/src/api/schemas.py`.

### 6.1 `GET /health` — liveness

Always returns `200 OK`. Used by Kubernetes liveness probes; cheap and
side-effect free. Does **not** touch the database, Redis, or any
external dependency.

```jsonc
{
  "status": "ok",
  "version": "0.5.0"
}
```

### 6.2 `GET /ready` — readiness

Performs four probes, each capped at 500 ms (`_PROBE_TIMEOUT_SECONDS`):

1. **Database** — `SELECT 1` against the configured Postgres engine.
2. **Redis** — `PING` against the broker URL.
3. **Storage** — `ensure_bucket()` for both reports and artifacts buckets.
4. **LLM providers** — aggregate snapshot from
   `ProviderHealthRegistry` (no network hop; in-memory metric only).

Response shape:

```jsonc
{
  "status": "ok" | "degraded",
  "database": true,
  "redis": true,
  "storage": true,
  "llm_providers": true,
  "checks": {
    "database":      {"ok": true,  "latency_ms": 4.2},
    "redis":         {"ok": true,  "latency_ms": 1.1},
    "storage":       {"ok": true,  "latency_ms": 12.3},
    "llm_providers": {"ok": false, "error": "degraded:openai"}
  }
}
```

`status` is `degraded` if any probe fails; HTTP status is `503` in that
case. Suitable for Kubernetes readiness probes — a 503 gates traffic.

### 6.3 `GET /providers/health` — LLM provider rollup

Returns a per-provider snapshot derived from
`ProviderHealthRegistry.snapshot()`:

```jsonc
{
  "status": "ok" | "degraded",
  "providers": [
    {
      "provider": "openai",
      "state": "closed" | "open" | "half_open" | "unknown",
      "request_count_60s": 1234,
      "error_count_60s": 7,
      "error_rate_5xx": 0.0057,
      "last_success_ts": 1745212195.5
    }
  ]
}
```

A provider is reported as `degraded` when its 60 s 5xx error rate
exceeds 50 % **and** it has handled at least one request in the window,
or when its circuit breaker is `open`. Providers with zero traffic are
not penalised. The endpoint **always** returns HTTP 200 — readiness
(`/ready`) is the right signal to remove the pod from the load
balancer; `/providers/health` is informational.

### 6.4 `GET /queues/health` — Celery queue depth

Reads queue lengths via `redis.llen(queue)` for the watched queues
(`celery`, `argus.default`, `argus.scans`, `argus.tools`, `argus.recon`,
`argus.reports`, `argus.exploitation`) and active worker count via
`celery_app.control.inspect(timeout=1.0).active()`.

```jsonc
{
  "status": "ok" | "degraded",
  "queues": [
    {"queue": "celery",          "depth": 0},
    {"queue": "argus.scans",     "depth": 12}
  ],
  "worker_count": 4,
  "redis_reachable": true
}
```

Failure semantics:

- Redis unreachable → HTTP 503 + `redis_reachable=false`. We cannot
  serve queue depths without Redis.
- Redis reachable, worker introspection failed → HTTP 200 +
  `worker_count=0`. The worker introspection RPC has its own timeout
  and may fail in partially-degraded clusters; we return what we know
  rather than 503.
- `status="degraded"` when there are zero active workers.

---

## 7. Local development

```powershell
# 1. Bring up Prometheus + OTel collector + Tempo + Grafana
docker compose -f infra/observability/docker-compose.yml up -d

# 2. Backend env
$env:OTEL_ENABLED       = "true"
$env:OTEL_OTLP_ENDPOINT = "http://localhost:4317"
$env:OTEL_INSECURE      = "true"
$env:OTEL_SAMPLER_RATIO = "1.0"
$env:TENANT_HASH_SALT   = "dev-salt-do-not-use-in-prod"

# 3. Run the API
uvicorn main:app --reload --port 8000

# 4. Hit the endpoints
curl http://localhost:8000/health
curl http://localhost:8000/ready
curl http://localhost:8000/metrics | Select-Object -First 40
curl http://localhost:8000/providers/health
curl http://localhost:8000/queues/health
```

A POSIX-shell variant:

```bash
OTEL_ENABLED=true OTEL_OTLP_ENDPOINT=http://localhost:4317 \
  OTEL_INSECURE=true OTEL_SAMPLER_RATIO=1.0 \
  TENANT_HASH_SALT=dev-salt \
  uvicorn main:app --reload
```

---

## 8. Verification gates

The PR for ARG-041 is gated on:

1. `ruff check src/core/observability.py src/core/otel_init.py
   src/core/logging_config.py src/api/routers/providers_health.py
   src/api/routers/queues_health.py src/mcp/tools/_runtime.py` — clean.
2. `mypy --strict` on the same set — clean.
3. `pytest backend/tests/unit/core/test_observability.py
   backend/tests/unit/core/test_otel_init.py
   backend/tests/unit/api/routers/test_providers_health.py
   backend/tests/unit/api/routers/test_queues_health.py
   backend/tests/unit/mcp/test_runtime.py
   backend/tests/integration/observability
   backend/tests/security/test_observability_cardinality.py` — green.
4. Smoke import — `python -c "import main"` succeeds with both
   `OTEL_ENABLED=false` and `OTEL_ENABLED=true`.
5. Catalogue snapshot — the test
   `tests/unit/core/test_observability.py::test_metric_catalogue_signature`
   asserts that the registered families equal the documented set.

---

## 9. Operational runbooks

### 9.1 Cardinality alarm

Symptom: Prometheus rejects pushes / scrape size explodes.

1. Hit `/metrics` and grep for `_other` to confirm the cap triggered.
2. Check the application log for the
   `observability.cardinality_cap_reached` warning — the `metric`
   field tells you which family is hot.
3. Identify the offending dimension (often `route` or `tool_id`) using
   the `rejected_labels` payload on the warning.
4. Either tighten the whitelist (preferred — opens a dashboard review)
   or shrink the per-family cap by lowering
   `_CARDINALITY_LIMIT_PER_METRIC` for the next deploy.

### 9.2 OTel collector outage

The exporter uses a `BatchSpanProcessor` with the SDK default queue.
When the collector is unavailable:

- Spans accumulate up to the queue limit (default 2048) then drop.
- The application path is **unaffected** — exporter failures are
  swallowed by `BatchSpanProcessor`.
- Look for `opentelemetry.sdk.trace.export` warnings in the log.
- Restore the collector; no replay is performed.
- If the OTLP wheel itself becomes unavailable (image rebuild gone
  wrong), the exporter logs `otel.exporter.fallback_to_console` and
  spans are written to stderr instead of dropped.

### 9.3 Provider degradation cascade

If `/providers/health` flips to `degraded`:

- Inspect `argus_llm_tokens_total{provider="…"}` for the rate change.
- Cross-reference traces via `service.name="argus"` and the `mcp.tool`
  span attributes.
- Fail over via the provider router config; no code change required.

---

## 10. Future work

- Tail-based sampling at the collector (currently head-based only).
- Exemplars on the histograms — link a hot bucket to a representative
  trace ID.
- A managed Grafana dashboard JSON checked into
  `infra/observability/dashboards/` (RED + USE per service tier).
- Surface scan-phase progress as a Counter +
  `argus_scan_phase_duration_seconds` Histogram (planned for ARG-042).
