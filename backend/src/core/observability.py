"""ARG-041 — Observability primitives: Prometheus metrics + OTel helpers.

This module owns the *whole* metric surface of the ARGUS backend. Every
business module that wants to emit a metric MUST go through one of the
``record_*`` functions defined here — direct ``Counter.labels(...).inc()``
calls in feature code are forbidden because they bypass the cardinality
guard.

Design invariants (enforced by tests in
``tests/unit/core/test_observability.py`` +
``tests/security/test_observability_cardinality.py``):

* **9 metric families.** Adding a 10th metric requires updating both the
  catalogue here and the cardinality unit tests. This is intentional —
  /metrics endpoint scrape size grows linearly with families × series, so
  every new label combination is a long-term operational cost.
* **Cardinality cap.** No metric may grow beyond
  ``_CARDINALITY_LIMIT_PER_METRIC`` (1000) unique label-value series. The
  guard is enforced inside :class:`_LabelGuard`, *not* by relying on
  Prometheus' internal limits (which are unbounded).
* **Whitelist + ``_other`` sentinel.** Every label value is matched
  against an explicit allow-list. Unknown values are coerced to
  ``"_other"``. This blocks both accidental high-cardinality bugs (e.g.
  raw URL paths leaking through) and intentional injection
  (``Authorization`` header values, attacker-controlled tool names).
* **``tenant_hash`` discipline.** Any metric with a ``tenant_hash`` label
  MUST receive the value computed by :func:`tenant_hash` — never a raw
  ``tenant_id``. The helper salts with ``settings.tenant_hash_salt`` and
  truncates to 16 hex chars (64 bits) — enough to avoid collision in
  realistic deployments while keeping the label short.
* **Deterministic registry.** A custom :class:`prometheus_client.CollectorRegistry`
  is exposed via :func:`get_registry()` so tests can build an isolated
  registry without bleeding into the global default. The module-level
  metrics still target the global default registry for runtime use.

Failure mode discipline:

* Every guard error is caught and downgraded to a warning log — metrics
  must NEVER take down the request path. The cardinality cap is the
  single hard guarantee; everything else degrades gracefully.
* If ``prometheus_client`` is unavailable (pure-Python install w/o the
  binding), every recorder becomes a no-op so ``import`` order in tests
  stays stable. The ``/metrics`` endpoint then returns a placeholder.

Cross-references:
* ``backend/src/core/otel_init.py`` — OTel SDK setup (uses ``tenant_hash``
  helper from this module to enforce span-attribute discipline too).
* ``docs/observability.md`` — operational guide, metrics catalogue table,
  and Grafana dashboard hints.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Final

from src.core.config import settings

try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        REGISTRY,
        CollectorRegistry,
        Counter,
        Histogram,
        generate_latest,
    )

    PROMETHEUS_AVAILABLE: bool = True
except ImportError:  # pragma: no cover — prometheus is a hard dep
    PROMETHEUS_AVAILABLE = False
    REGISTRY = None  # type: ignore[assignment]
    CollectorRegistry = None  # type: ignore[assignment,misc]
    Counter = None  # type: ignore[assignment,misc]
    Histogram = None  # type: ignore[assignment,misc]
    generate_latest = None  # type: ignore[assignment]
    CONTENT_TYPE_LATEST = "text/plain; charset=utf-8"

try:
    from opentelemetry import trace
    from opentelemetry.trace import Span, Tracer

    OTEL_AVAILABLE: bool = True
except ImportError:  # pragma: no cover
    OTEL_AVAILABLE = False
    trace = None  # type: ignore[assignment]
    Span = None  # type: ignore[assignment,misc]
    Tracer = None  # type: ignore[assignment,misc]


_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants & catalogue
# ---------------------------------------------------------------------------

#: Hard cap on unique label-value combinations per metric. Anything above
#: this is rejected at recording time and logged once per warning event.
#: Tuned for the typical Prometheus scrape budget (~50KB) and the realistic
#: tenant fan-out (~250 active tenants per pod).
_CARDINALITY_LIMIT_PER_METRIC: Final[int] = 1000

#: Sentinel label value substituted in place of any non-whitelisted input.
#: Chosen to be distinguishable from any legitimate value while still being
#: a valid Prometheus label string.
OTHER_LABEL_VALUE: Final[str] = "_other"

#: Sentinel for tenant_hash when no tenant context is available (system tasks,
#: anonymous health probes). Distinct from ``OTHER_LABEL_VALUE`` so dashboards
#: can split "system" traffic from "unknown tenant" anomalies.
SYSTEM_TENANT_HASH: Final[str] = "system"

#: Characters allowed in a tenant_hash output (16-char hex prefix).
_TENANT_HASH_LEN: Final[int] = 16

# Canonical buckets — tuned for known SLOs:
# * HTTP request — sub-second to low-second; matches FastAPI default.
# * Sandbox run — long-tail; some recon tools run minutes (testssl, dnsx).
# * Celery task — generic; covers both sub-second tasks and report jobs.
_HTTP_BUCKETS: Final[tuple[float, ...]] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
)
_SANDBOX_BUCKETS: Final[tuple[float, ...]] = (1.0, 5.0, 10.0, 30.0, 60.0, 300.0)
_CELERY_BUCKETS: Final[tuple[float, ...]] = (0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0)


@dataclass(frozen=True, slots=True)
class _MetricSpec:
    """Compact metadata bundle for a single Prometheus metric definition."""

    name: str
    documentation: str
    labels: tuple[str, ...]
    kind: str  # "counter" | "histogram"
    buckets: tuple[float, ...] | None = None


#: The canonical 9-family catalogue. Tests assert this list is the source
#: of truth (any drift between this list and the module-level metric handles
#: below makes the unit suite fail).
METRIC_CATALOGUE: Final[tuple[_MetricSpec, ...]] = (
    _MetricSpec(
        name="argus_http_requests_total",
        documentation="HTTP requests handled by FastAPI (count by route + status class).",
        labels=("method", "route", "status_class", "tenant_hash"),
        kind="counter",
    ),
    _MetricSpec(
        name="argus_http_request_duration_seconds",
        documentation="HTTP request handling latency (seconds), bucketed by method/route/tenant.",
        labels=("method", "route", "tenant_hash"),
        kind="histogram",
        buckets=_HTTP_BUCKETS,
    ),
    _MetricSpec(
        name="argus_celery_task_duration_seconds",
        documentation="Celery task wall-clock duration in seconds.",
        labels=("task_name", "status"),
        kind="histogram",
        buckets=_CELERY_BUCKETS,
    ),
    _MetricSpec(
        name="argus_celery_task_failures_total",
        documentation="Celery task failures bucketed by task name + exception class.",
        labels=("task_name", "error_class"),
        kind="counter",
    ),
    _MetricSpec(
        name="argus_sandbox_runs_total",
        documentation="Sandbox tool runs (success | error | timeout) per tool + profile.",
        labels=("tool_id", "status", "profile"),
        kind="counter",
    ),
    _MetricSpec(
        name="argus_sandbox_run_duration_seconds",
        documentation="Sandbox tool run wall-clock duration (seconds).",
        labels=("tool_id", "profile"),
        kind="histogram",
        buckets=_SANDBOX_BUCKETS,
    ),
    _MetricSpec(
        name="argus_findings_emitted_total",
        documentation="Findings emitted by the normalizer, bucketed by tier/severity/KEV.",
        labels=("tier", "severity", "kev_listed"),
        kind="counter",
    ),
    _MetricSpec(
        name="argus_llm_tokens_total",
        documentation="LLM tokens consumed (direction=in|out) per provider+model.",
        labels=("provider", "model", "direction"),
        kind="counter",
    ),
    _MetricSpec(
        name="argus_mcp_calls_total",
        documentation="MCP tools/call invocations bucketed by tool + status + client class.",
        labels=("tool", "status", "client_class"),
        kind="counter",
    ),
)

# ---------------------------------------------------------------------------
# Label whitelists. Adding a new value to any whitelist is the SUPPORTED way
# of expanding cardinality — it forces a documentation review at the same time.
# ---------------------------------------------------------------------------

_HTTP_METHODS: Final[frozenset[str]] = frozenset(
    {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"},
)
_HTTP_STATUS_CLASSES: Final[frozenset[str]] = frozenset(
    {"1xx", "2xx", "3xx", "4xx", "5xx"},
)
_CELERY_STATUSES: Final[frozenset[str]] = frozenset(
    {"success", "failure", "retry", "revoked", "rejected"},
)
_SANDBOX_STATUSES: Final[frozenset[str]] = frozenset(
    {"success", "error", "timeout", "skipped", "cancelled"},
)
_SANDBOX_PROFILES: Final[frozenset[str]] = frozenset(
    {"recon", "active_scan", "exploit", "kubernetes", "docker", "local", "stub"},
)
_FINDING_TIERS: Final[frozenset[str]] = frozenset(
    {"midgard", "asgard", "valhalla", "internal"},
)
_FINDING_SEVERITIES: Final[frozenset[str]] = frozenset(
    {"info", "low", "medium", "high", "critical"},
)
_FINDING_KEV_FLAGS: Final[frozenset[str]] = frozenset({"true", "false"})
_LLM_PROVIDERS: Final[frozenset[str]] = frozenset(
    {"anthropic", "openai", "deepseek", "openrouter", "google", "kimi", "perplexity"},
)
_LLM_DIRECTIONS: Final[frozenset[str]] = frozenset({"in", "out"})
_MCP_STATUSES: Final[frozenset[str]] = frozenset(
    {"success", "error", "rate_limited", "unauthorized", "forbidden", "validation_error"},
)
_MCP_CLIENT_CLASSES: Final[frozenset[str]] = frozenset(
    {"anthropic", "openai", "generic"},
)

#: Mapping label_name → whitelist. Entry **per metric label** is checked at
#: record time. Labels not present here pass through after a length check
#: (see ``_LabelGuard.normalize``).
LABEL_VALUE_WHITELIST: Final[Mapping[str, frozenset[str]]] = {
    "method": _HTTP_METHODS,
    "status_class": _HTTP_STATUS_CLASSES,
    # Celery
    "status": _CELERY_STATUSES | _SANDBOX_STATUSES | _MCP_STATUSES,
    "profile": _SANDBOX_PROFILES,
    # Findings
    "tier": _FINDING_TIERS,
    "severity": _FINDING_SEVERITIES,
    "kev_listed": _FINDING_KEV_FLAGS,
    # LLM
    "provider": _LLM_PROVIDERS,
    "direction": _LLM_DIRECTIONS,
    # MCP
    "client_class": _MCP_CLIENT_CLASSES,
}

#: Labels that have *no* whitelist (high natural cardinality already capped
#: at the source — e.g. tool ids by the signed catalogue, route templates by
#: FastAPI). Listed explicitly so the ``_LabelGuard.normalize`` path is
#: exhaustive.
_FREEFORM_LABELS: Final[frozenset[str]] = frozenset(
    {"tool_id", "route", "task_name", "error_class", "tenant_hash", "model", "tool"},
)

#: Hard limit on label-value length to protect log/metric backends.
_MAX_LABEL_VALUE_LEN: Final[int] = 64


# ---------------------------------------------------------------------------
# Cardinality guard
# ---------------------------------------------------------------------------


class CardinalityExceededError(Exception):
    """Raised internally when a metric exceeds the per-family series cap.

    Always caught and downgraded to a warning at the call-site — metrics
    failures must NOT propagate to the request path. The exception type
    is exposed so unit tests can assert on the discipline directly.
    """


class _LabelGuard:
    """Per-metric guard that enforces whitelist + cap discipline.

    The guard tracks every distinct label-value combination it has approved
    so the cardinality cap is enforced even after metric handles are reused
    across requests. State is process-local — a Prometheus exposition pod
    serving 8 worker threads has 8 independent guards, each capped at 1000;
    that's intentional because Prometheus deduplicates by label set anyway.
    """

    __slots__ = ("_metric_name", "_seen", "_lock", "_warning_emitted")

    def __init__(self, metric_name: str) -> None:
        self._metric_name = metric_name
        self._seen: set[tuple[tuple[str, str], ...]] = set()
        self._lock = threading.Lock()
        self._warning_emitted = False

    @staticmethod
    def normalize(label: str, value: object) -> str:
        """Coerce *value* into a safe label string.

        Unknown / out-of-whitelist values get replaced with the ``_other``
        sentinel and a warning log line so dashboards stay flat. Values
        longer than 64 chars are truncated (defence-in-depth against
        attacker-controlled tool ids).
        """
        s = "" if value is None else str(value)
        s = s.strip()
        if not s:
            s = OTHER_LABEL_VALUE
        if len(s) > _MAX_LABEL_VALUE_LEN:
            s = s[:_MAX_LABEL_VALUE_LEN]
        whitelist = LABEL_VALUE_WHITELIST.get(label)
        if whitelist is not None and s not in whitelist:
            _logger.warning(
                "observability.label_value_rejected",
                extra={
                    "label": label,
                    "rejected_value": s,
                    "fallback": OTHER_LABEL_VALUE,
                },
            )
            return OTHER_LABEL_VALUE
        return s

    def admit(self, labels: Mapping[str, str]) -> bool:
        """Return True iff *labels* fits under the cardinality cap.

        Side-effect: the label combination is memoised on first acceptance,
        so re-recording the same combination later is always allowed.
        """
        # Sort to make the key deterministic regardless of caller's dict order.
        key = tuple(sorted(labels.items()))
        with self._lock:
            if key in self._seen:
                return True
            if len(self._seen) >= _CARDINALITY_LIMIT_PER_METRIC:
                if not self._warning_emitted:
                    _logger.warning(
                        "observability.cardinality_cap_reached",
                        extra={
                            "metric": self._metric_name,
                            "limit": _CARDINALITY_LIMIT_PER_METRIC,
                            "rejected_labels": dict(labels),
                        },
                    )
                    self._warning_emitted = True
                return False
            self._seen.add(key)
            return True


# ---------------------------------------------------------------------------
# Metric registry — singleton with per-test reset hook
# ---------------------------------------------------------------------------


class _MetricRegistry:
    """Owns the 9 metric families + their cardinality guards.

    Lives behind :func:`_get_metric_registry` and is rebuilt on demand —
    unit tests can call :func:`reset_metrics_registry` to drop all state
    between cases without leaking series across the suite.
    """

    def __init__(self, registry: Any | None = None) -> None:
        self.registry = registry if registry is not None else REGISTRY
        self._counters: dict[str, Any] = {}
        self._histograms: dict[str, Any] = {}
        self._guards: dict[str, _LabelGuard] = {}
        self._build_metrics()

    def _build_metrics(self) -> None:
        if not PROMETHEUS_AVAILABLE:
            return
        for spec in METRIC_CATALOGUE:
            self._guards[spec.name] = _LabelGuard(spec.name)
            if spec.kind == "counter":
                self._counters[spec.name] = Counter(
                    name=spec.name,
                    documentation=spec.documentation,
                    labelnames=spec.labels,
                    registry=self.registry,
                )
            elif spec.kind == "histogram":
                self._histograms[spec.name] = Histogram(
                    name=spec.name,
                    documentation=spec.documentation,
                    labelnames=spec.labels,
                    buckets=spec.buckets or Histogram.DEFAULT_BUCKETS,
                    registry=self.registry,
                )
            else:  # pragma: no cover — defensive, kind is whitelisted in catalogue.
                raise ValueError(f"Unknown metric kind: {spec.kind}")

    def counter(self, name: str) -> Any | None:
        return self._counters.get(name)

    def histogram(self, name: str) -> Any | None:
        return self._histograms.get(name)

    def guard(self, name: str) -> _LabelGuard | None:
        return self._guards.get(name)


_metric_registry_lock = threading.Lock()
_metric_registry: _MetricRegistry | None = None


def _get_metric_registry() -> _MetricRegistry:
    """Return the singleton metric registry, building it lazily on first call."""
    global _metric_registry
    if _metric_registry is None:
        with _metric_registry_lock:
            if _metric_registry is None:
                _metric_registry = _MetricRegistry()
    return _metric_registry


def reset_metrics_registry(registry: Any | None = None) -> _MetricRegistry:
    """Drop and rebuild the metric registry. Intended for tests only.

    When *registry* is ``None``, a fresh ``CollectorRegistry`` is allocated —
    this guarantees isolation from the global default registry that
    production code uses. Returns the new registry handle so the caller
    can introspect collected samples directly.
    """
    global _metric_registry
    with _metric_registry_lock:
        target = registry if registry is not None else (
            CollectorRegistry() if PROMETHEUS_AVAILABLE else None
        )
        _metric_registry = _MetricRegistry(registry=target)
    return _metric_registry


def get_registry() -> Any | None:
    """Return the active Prometheus registry (or ``None`` if client missing)."""
    return _get_metric_registry().registry


# ---------------------------------------------------------------------------
# tenant_hash helper (the single mandatory invariant for tenant labels)
# ---------------------------------------------------------------------------


def tenant_hash(tenant_id: str | None, *, salt: str | None = None) -> str:
    """Compute a stable 16-hex-char tenant fingerprint for metric labels.

    Implementation: ``sha256((tenant_id + salt).encode("utf-8")).hexdigest()[:16]``.

    * ``tenant_id`` may be ``None`` / empty — those collapse to the
      ``SYSTEM_TENANT_HASH`` sentinel so dashboards can split system traffic
      from anonymous user traffic.
    * ``salt`` defaults to ``settings.tenant_hash_salt``. Salts MUST be
      kept secret in production — without one, an attacker could brute-force
      the mapping back to known tenant ids by enumerating UUIDs.
    * Output length is 16 hex chars (= 64 bits of entropy). Birthday-bound
      collision probability for 250 active tenants is ~3e-15, which is fine
      for label dedup purposes.
    """
    if tenant_id is None:
        return SYSTEM_TENANT_HASH
    s = str(tenant_id).strip()
    if not s:
        return SYSTEM_TENANT_HASH
    used_salt = salt if salt is not None else settings.tenant_hash_salt
    digest = hashlib.sha256(f"{s}{used_salt}".encode()).hexdigest()
    return digest[:_TENANT_HASH_LEN]


def user_id_hash(user_id: str | None, *, salt: str | None = None) -> str:
    """Stable 16-hex fingerprint for user / operator identifiers in logs and audit metadata.

    Domain-separated from :func:`tenant_hash` via a ``uid:`` prefix so the same
    raw value cannot collide across namespaces. Empty / missing values collapse to
    :data:`SYSTEM_TENANT_HASH` (same sentinel as anonymous tenant labels).
    """
    if user_id is None:
        return SYSTEM_TENANT_HASH
    s = str(user_id).strip()
    if not s:
        return SYSTEM_TENANT_HASH
    used_salt = salt if salt is not None else settings.tenant_hash_salt
    digest = hashlib.sha256(f"uid:{s}{used_salt}".encode()).hexdigest()
    return digest[:_TENANT_HASH_LEN]


# ---------------------------------------------------------------------------
# Public recorders. Each function:
#   1. Normalises labels through `_LabelGuard.normalize`.
#   2. Admits via the cardinality cap.
#   3. Emits the metric (Counter.inc / Histogram.observe).
#   4. Catches every exception so feature code is never blocked.
# ---------------------------------------------------------------------------


def _safe_emit_counter(
    metric_name: str,
    labels: Mapping[str, object],
    *,
    amount: float = 1.0,
) -> None:
    if not PROMETHEUS_AVAILABLE:
        return
    reg = _get_metric_registry()
    counter = reg.counter(metric_name)
    guard = reg.guard(metric_name)
    if counter is None or guard is None:
        _logger.warning("observability.unknown_counter", extra={"metric": metric_name})
        return
    try:
        normalized = {k: _LabelGuard.normalize(k, v) for k, v in labels.items()}
        if not guard.admit(normalized):
            return
        counter.labels(**normalized).inc(amount)
    except Exception:  # pragma: no cover — defensive
        _logger.exception(
            "observability.counter_emit_failed",
            extra={"metric": metric_name},
        )


def _safe_emit_histogram(
    metric_name: str,
    labels: Mapping[str, object],
    *,
    value: float,
) -> None:
    if not PROMETHEUS_AVAILABLE:
        return
    reg = _get_metric_registry()
    hist = reg.histogram(metric_name)
    guard = reg.guard(metric_name)
    if hist is None or guard is None:
        _logger.warning("observability.unknown_histogram", extra={"metric": metric_name})
        return
    try:
        normalized = {k: _LabelGuard.normalize(k, v) for k, v in labels.items()}
        if not guard.admit(normalized):
            return
        hist.labels(**normalized).observe(value)
    except Exception:  # pragma: no cover — defensive
        _logger.exception(
            "observability.histogram_emit_failed",
            extra={"metric": metric_name},
        )


# --- HTTP -------------------------------------------------------------------


def _status_class(code: int) -> str:
    if 100 <= code < 200:
        return "1xx"
    if 200 <= code < 300:
        return "2xx"
    if 300 <= code < 400:
        return "3xx"
    if 400 <= code < 500:
        return "4xx"
    if 500 <= code < 600:
        return "5xx"
    return OTHER_LABEL_VALUE


def record_http_request(
    *,
    method: str,
    route: str,
    status_code: int,
    duration_seconds: float,
    tenant_id: str | None,
) -> None:
    """Record a single HTTP request: Counter + Histogram in one call.

    ``route`` MUST be the FastAPI route template (e.g. ``/api/v1/scans/{scan_id}``)
    not the raw path — the middleware layer is responsible for resolving it
    via ``request.scope["route"].path`` before calling this helper.

    Defensive contract: any input may be ``None`` / empty / out-of-range.
    The recorder NEVER raises — feature code wraps this in business-critical
    request paths, so a metric crash must never break a 200 OK.
    """
    th = tenant_hash(tenant_id)
    method_norm = (method or "").upper() or OTHER_LABEL_VALUE
    route_norm = route or OTHER_LABEL_VALUE
    try:
        sc_int = int(status_code)
    except (TypeError, ValueError):
        sc_int = 0
    sc = _status_class(sc_int)
    try:
        dur = float(duration_seconds)
        if dur != dur:  # NaN guard
            dur = 0.0
    except (TypeError, ValueError):
        dur = 0.0
    _safe_emit_counter(
        "argus_http_requests_total",
        {
            "method": method_norm,
            "route": route_norm,
            "status_class": sc,
            "tenant_hash": th,
        },
    )
    _safe_emit_histogram(
        "argus_http_request_duration_seconds",
        {"method": method_norm, "route": route_norm, "tenant_hash": th},
        value=max(0.0, dur),
    )


# --- Celery -----------------------------------------------------------------


def record_celery_task(
    *,
    task_name: str,
    status: str,
    duration_seconds: float,
    error_class: str | None = None,
) -> None:
    """Record a Celery task result + its duration.

    ``error_class`` is only used when ``status`` is ``"failure"``; the
    failures Counter receives the exception class name (e.g.
    ``"TimeoutError"``) so dashboards can rank top error classes per task.
    """
    _safe_emit_histogram(
        "argus_celery_task_duration_seconds",
        {"task_name": task_name, "status": status},
        value=max(0.0, float(duration_seconds)),
    )
    if status == "failure":
        _safe_emit_counter(
            "argus_celery_task_failures_total",
            {
                "task_name": task_name,
                "error_class": error_class or OTHER_LABEL_VALUE,
            },
        )


# --- Sandbox ----------------------------------------------------------------


def record_sandbox_run(
    *,
    tool_id: str,
    status: str,
    profile: str,
    duration_seconds: float,
) -> None:
    """Record a single sandbox tool execution (success/error/timeout)."""
    _safe_emit_counter(
        "argus_sandbox_runs_total",
        {"tool_id": tool_id, "status": status, "profile": profile},
    )
    _safe_emit_histogram(
        "argus_sandbox_run_duration_seconds",
        {"tool_id": tool_id, "profile": profile},
        value=max(0.0, float(duration_seconds)),
    )


# --- Findings ---------------------------------------------------------------


def record_finding_emitted(
    *,
    tier: str,
    severity: str,
    kev_listed: bool,
) -> None:
    """Record one finding emitted by the normalizer."""
    _safe_emit_counter(
        "argus_findings_emitted_total",
        {
            "tier": tier.lower(),
            "severity": severity.lower(),
            "kev_listed": "true" if kev_listed else "false",
        },
    )


# --- LLM tokens -------------------------------------------------------------


def record_llm_tokens(
    *,
    provider: str,
    model: str,
    direction: str,
    tokens: int,
) -> None:
    """Record LLM token usage (direction = ``in`` for prompt, ``out`` for completion)."""
    if tokens <= 0:
        return
    _safe_emit_counter(
        "argus_llm_tokens_total",
        {
            "provider": provider.lower(),
            "model": model,
            "direction": direction.lower(),
        },
        amount=float(tokens),
    )


# --- MCP --------------------------------------------------------------------


def record_mcp_call(
    *,
    tool: str,
    status: str,
    client_class: str,
) -> None:
    """Record one MCP ``tools/call`` invocation.

    ``client_class`` is bucketed (``anthropic`` / ``openai`` / ``generic``)
    so the metric stays low-cardinality regardless of how many concrete
    LLM clients connect to the MCP server.
    """
    _safe_emit_counter(
        "argus_mcp_calls_total",
        {"tool": tool, "status": status, "client_class": client_class.lower()},
    )


# ---------------------------------------------------------------------------
# OpenTelemetry helpers (used by both feature code and otel_init.py).
# ---------------------------------------------------------------------------


def get_tracer(name: str = "argus") -> Any:
    """Return an OTel ``Tracer`` (or no-op proxy when OTel is unavailable).

    The proxy implements the same context-manager surface so callers can
    write ``with get_tracer().start_as_current_span(...)`` unconditionally.
    """
    if not OTEL_AVAILABLE or trace is None:
        return _NoopTracer()
    return trace.get_tracer(name, settings.version)


def safe_set_span_attribute(span: Any, key: str, value: object) -> None:
    """Set a span attribute, blocking known PII keys (``tenant_id``, etc.).

    The discipline mirrors the metric whitelist: any key that smells like
    a raw tenant id is silently dropped with a warning. Callers MUST use
    ``tenant.hash`` instead.
    """
    if span is None:
        return
    lowered = key.lower()
    forbidden = (
        "tenant_id",
        "tenantid",
        "tenant.id",
        "user_id",
        "userid",
        "authorization",
        "cookie",
        "x-api-key",
    )
    if lowered in forbidden:
        _logger.warning(
            "observability.span_attribute_rejected",
            extra={"key": key, "reason": "PII / cardinality risk"},
        )
        return
    try:
        span.set_attribute(key, value)
    except Exception:  # pragma: no cover — defensive
        _logger.exception("observability.span_attribute_failed", extra={"key": key})


@contextmanager
def trace_phase(
    scan_id: str,
    phase: str,
    *,
    tenant_id: str | None = None,
) -> Generator[Any, None, None]:
    """Convenience span wrapper used by orchestrator phase code.

    Yields the active span so callers can attach extra attributes via
    :func:`safe_set_span_attribute`. The span is no-op when OTel is
    disabled or unavailable — a critical perf invariant.
    """
    tracer = get_tracer("argus")
    with tracer.start_as_current_span(
        f"scan.phase.{phase}",
        attributes={
            "argus.scan_id": str(scan_id),
            "argus.phase": phase,
            "tenant.hash": tenant_hash(tenant_id),
        },
    ) as span:
        yield span


# ---------------------------------------------------------------------------
# /metrics endpoint helper
# ---------------------------------------------------------------------------


def get_metrics_content() -> tuple[bytes, str]:
    """Return the Prometheus exposition body + content-type header.

    Always returns valid UTF-8; if Prometheus is unavailable the body is a
    helpful placeholder rather than empty bytes (so monitoring of the
    monitor itself stays useful).
    """
    if not PROMETHEUS_AVAILABLE or generate_latest is None:
        return (
            b"# prometheus_client unavailable; observability disabled\n",
            "text/plain; charset=utf-8",
        )
    reg = _get_metric_registry().registry
    return generate_latest(reg), CONTENT_TYPE_LATEST


# ---------------------------------------------------------------------------
# Backward-compatible legacy recorders (Cycle 4 callers). Kept so existing
# code continues to compile during the rollout — internally they delegate
# to the modern recorders above.
# ---------------------------------------------------------------------------


def record_scan_started() -> None:
    """Legacy alias kept for backward compatibility (Cycle 4 callers).

    Delegates to ``record_celery_task`` with task_name=``argus.scan_phase``.
    """
    record_celery_task(
        task_name="argus.scan_phase",
        status="success",
        duration_seconds=0.0,
    )


def record_phase_duration(phase: str, duration_seconds: float) -> None:
    """Legacy alias kept for backward compatibility (Cycle 4 callers).

    Routes through the Celery duration histogram, encoding the phase as
    the task name for backward continuity. New code should call
    :func:`record_celery_task` directly.
    """
    record_celery_task(
        task_name=f"argus.scan.{phase}",
        status="success",
        duration_seconds=duration_seconds,
    )


def record_tool_run(tool: str) -> None:
    """Legacy alias kept for backward compatibility (Cycle 4 callers)."""
    record_sandbox_run(
        tool_id=tool,
        status="success",
        profile="local",
        duration_seconds=0.0,
    )


# ---------------------------------------------------------------------------
# Internal no-op tracer used when OTel SDK is unavailable
# ---------------------------------------------------------------------------


class _NoopSpan:
    """Minimal ``Span`` lookalike — every operation is a silent no-op."""

    def set_attribute(self, _key: str, _value: object) -> None:  # noqa: D401
        return None

    def add_event(self, _name: str, **_kwargs: Any) -> None:  # noqa: D401
        return None

    def record_exception(self, _exc: BaseException) -> None:  # noqa: D401
        return None

    def end(self) -> None:  # noqa: D401
        return None

    def __enter__(self) -> _NoopSpan:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None


class _NoopTracer:
    """``Tracer`` proxy used when OTel is disabled — yields a :class:`_NoopSpan`."""

    @contextmanager
    def start_as_current_span(
        self,
        _name: str,
        attributes: Mapping[str, Any] | None = None,  # noqa: ARG002 — API parity
        **_kwargs: Any,
    ) -> Generator[_NoopSpan, None, None]:
        yield _NoopSpan()


__all__ = [
    "CONTENT_TYPE_LATEST",
    "LABEL_VALUE_WHITELIST",
    "METRIC_CATALOGUE",
    "OTHER_LABEL_VALUE",
    "OTEL_AVAILABLE",
    "PROMETHEUS_AVAILABLE",
    "SYSTEM_TENANT_HASH",
    "CardinalityExceededError",
    "get_metrics_content",
    "get_registry",
    "get_tracer",
    "record_celery_task",
    "record_finding_emitted",
    "record_http_request",
    "record_llm_tokens",
    "record_mcp_call",
    "record_phase_duration",
    "record_sandbox_run",
    "record_scan_started",
    "record_tool_run",
    "reset_metrics_registry",
    "safe_set_span_attribute",
    "tenant_hash",
    "user_id_hash",
    "trace_phase",
]
