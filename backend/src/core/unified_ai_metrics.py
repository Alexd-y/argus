"""§18 unified AI / RAG / LAB Prometheus catalogue (LAB-003).

Single source of truth for master-prompt §18 metrics. Feature code MUST emit
via the ``record_*`` helpers here — never register duplicate Prometheus
counters in domain modules.

Alias map (§18 canonical name → exported Prometheus name):

+-------------------------------+----------------------------------+
| §18 name                      | Prometheus name                  |
+-------------------------------+----------------------------------+
| llm_requests_total            | argus_llm_requests_total         |
| llm_latency_ms                | argus_llm_latency_ms             |
| llm_schema_failures_total     | argus_llm_schema_failures_total  |
| llm_fallback_total            | argus_llm_fallback_total         |
| rag_queries_total             | argus_rag_queries_total          |
| rag_retrieval_latency_ms      | argus_rag_retrieval_latency_ms   |
| rag_cross_tenant_denials_total| argus_rag_cross_tenant_denials_total |
| nuclei_templates_loaded_total | argus_nuclei_templates_loaded_total |
| nuclei_requests_total         | argus_nuclei_requests_total      |
| lab_executions_total          | argus_lab_executions_total       |
| lab_boundary_denials_total    | argus_lab_boundary_denials_total |
| coverage_requirements_total   | argus_coverage_requirements_total|
| findings_total                | argus_findings_total             |
| retests_total                 | argus_retests_total              |
| oast_interactions_total       | argus_oast_interactions_total    |
+-------------------------------+----------------------------------+

Failure mode: every emit path is fail-open — metrics never break request/scan
paths. Integer mirrors support unit tests without Prometheus.
"""

from __future__ import annotations

import logging
from threading import Lock
from typing import Any, Final

logger = logging.getLogger(__name__)

try:
    from prometheus_client import Counter as PromCounter
    from prometheus_client import Histogram as PromHistogram

    _PROMETHEUS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PROMETHEUS_AVAILABLE = False
    PromCounter = None  # type: ignore[assignment,misc]
    PromHistogram = None  # type: ignore[assignment,misc]

_LOCK = Lock()
_MAX_LABEL_LEN: Final[int] = 64

# Integer mirrors (unit tests)
_llm_requests_total: int = 0
_llm_schema_failures_total: int = 0
_llm_fallback_total: int = 0
_rag_queries_total: int = 0
_rag_cross_tenant_denials_total: int = 0
_nuclei_templates_loaded_total: int = 0
_nuclei_requests_total: int = 0
_lab_executions_total: int = 0
_lab_boundary_denials_total: int = 0
_coverage_requirements_total: int = 0
_findings_total: int = 0
_retests_total: int = 0
_oast_interactions_total: int = 0

_PROM_COUNTERS: dict[str, Any] = {}
_PROM_HISTOGRAMS: dict[str, Any] = {}
_PROM_INITIALIZED = False

METRIC_ALIAS_MAP: Final[dict[str, str]] = {
    "llm_requests_total": "argus_llm_requests_total",
    "llm_latency_ms": "argus_llm_latency_ms",
    "llm_schema_failures_total": "argus_llm_schema_failures_total",
    "llm_fallback_total": "argus_llm_fallback_total",
    "rag_queries_total": "argus_rag_queries_total",
    "rag_retrieval_latency_ms": "argus_rag_retrieval_latency_ms",
    "rag_cross_tenant_denials_total": "argus_rag_cross_tenant_denials_total",
    "nuclei_templates_loaded_total": "argus_nuclei_templates_loaded_total",
    "nuclei_requests_total": "argus_nuclei_requests_total",
    "lab_executions_total": "argus_lab_executions_total",
    "lab_boundary_denials_total": "argus_lab_boundary_denials_total",
    "coverage_requirements_total": "argus_coverage_requirements_total",
    "findings_total": "argus_findings_total",
    "retests_total": "argus_retests_total",
    "oast_interactions_total": "argus_oast_interactions_total",
}

_LLM_LATENCY_BUCKETS: Final[tuple[float, ...]] = (
    5.0,
    10.0,
    25.0,
    50.0,
    100.0,
    250.0,
    500.0,
    1000.0,
    2500.0,
    5000.0,
    15000.0,
    30000.0,
)
_RAG_LATENCY_BUCKETS: Final[tuple[float, ...]] = (
    1.0,
    5.0,
    10.0,
    25.0,
    50.0,
    100.0,
    250.0,
    500.0,
    1000.0,
    2500.0,
)

# QUICK-009 — Quick execution-mode catalogue (lives here, NOT in observability.py).
_QUICK_CARDINALITY_LIMIT: Final[int] = 1000
_QUICK_OTHER: Final[str] = "_other"

QUICK_METRIC_ALIAS_MAP: Final[dict[str, str]] = {
    "quick_scan_duration_seconds": "argus_quick_scan_duration_seconds",
    "quick_deadline_overrun_total": "argus_quick_deadline_overrun_total",
    "quick_budget_used_ratio": "argus_quick_budget_used_ratio",
    "quick_tasks_total": "argus_quick_tasks_total",
    "quick_assets_discovered_total": "argus_quick_assets_discovered_total",
    "quick_templates_selected_total": "argus_quick_templates_selected_total",
    "quick_findings_total": "argus_quick_findings_total",
    "quick_validation_rate": "argus_quick_validation_rate",
    "quick_false_positive_rate": "argus_quick_false_positive_rate",
    "quick_coverage_ratio": "argus_quick_coverage_ratio",
    "quick_plan_revisions_total": "argus_quick_plan_revisions_total",
    "quick_llm_calls_total": "argus_quick_llm_calls_total",
    "quick_llm_latency_seconds": "argus_quick_llm_latency_seconds",
    "quick_rag_latency_seconds": "argus_quick_rag_latency_seconds",
    "quick_tool_failures_total": "argus_quick_tool_failures_total",
}

_QUICK_STAGE_WHITELIST: Final[frozenset[str]] = frozenset(
    {
        "discovery",
        "fingerprint",
        "test",
        "verify",
        "triage",
        "report",
        _QUICK_OTHER,
    }
)
_QUICK_STATUS_WHITELIST: Final[frozenset[str]] = frozenset(
    {
        "queued",
        "leased",
        "running",
        "succeeded",
        "failed",
        "cancelled",
        "skipped",
        "timed_out",
        _QUICK_OTHER,
    }
)
_QUICK_TOOL_WHITELIST: Final[frozenset[str]] = frozenset(
    {
        "nuclei",
        "httpx",
        "naabu",
        "dnsx",
        "tlsx",
        "katana",
        "whatweb",
        "wappalyzer",
        "nmap",
        "testssl",
        "openssl",
        "curl",
        "wget",
        "nikto",
        _QUICK_OTHER,
    }
)
QUICK_TOOL_WHITELIST: Final[frozenset[str]] = _QUICK_TOOL_WHITELIST
_QUICK_SEVERITY_WHITELIST: Final[frozenset[str]] = frozenset(
    {"info", "low", "medium", "high", "critical", _QUICK_OTHER}
)
_QUICK_VERDICT_WHITELIST: Final[frozenset[str]] = frozenset(
    {
        "confirmed",
        "likely",
        "needs_verification",
        "hypothesis",
        "false_positive_candidate",
        _QUICK_OTHER,
    }
)
_QUICK_MODEL_WHITELIST: Final[frozenset[str]] = frozenset(
    {
        "qwythos",
        "wrb",
        "whiterabbitneo",
        "gemma",
        "qwen",
        "deterministic",
        "rules",
        "template_renderer",
        _QUICK_OTHER,
    }
)
_QUICK_PROMPT_WHITELIST: Final[frozenset[str]] = frozenset(
    {
        "quick_planner_v1",
        "quick_fingerprint_classifier_v1",
        "quick_finding_triage_v1",
        "quick_security_critic_v1",
        "quick_reporter_v1",
        "deterministic-v1",
        "rules-v1",
        "template-v1",
        _QUICK_OTHER,
    }
)
_QUICK_LLM_STATUS_WHITELIST: Final[frozenset[str]] = frozenset(
    {
        "ok",
        "error",
        "timeout",
        "schema_invalid",
        "fallback",
        "cached",
        _QUICK_OTHER,
    }
)
_QUICK_FAILURE_REASON_WHITELIST: Final[frozenset[str]] = frozenset(
    {
        "timeout",
        "error",
        "circuit_open",
        "untracked",
        "cancelled",
        "policy_denied",
        _QUICK_OTHER,
    }
)
_QUICK_LABEL_WHITELISTS: Final[dict[str, frozenset[str]]] = {
    "stage": _QUICK_STAGE_WHITELIST,
    "status": _QUICK_STATUS_WHITELIST | _QUICK_LLM_STATUS_WHITELIST,
    "tool": _QUICK_TOOL_WHITELIST,
    "severity": _QUICK_SEVERITY_WHITELIST,
    "verdict": _QUICK_VERDICT_WHITELIST,
    "model": _QUICK_MODEL_WHITELIST,
    "prompt": _QUICK_PROMPT_WHITELIST,
    "reason": _QUICK_FAILURE_REASON_WHITELIST,
}

_QUICK_SCAN_DURATION_BUCKETS: Final[tuple[float, ...]] = (
    30.0,
    60.0,
    120.0,
    300.0,
    600.0,
    900.0,
    1800.0,
    3600.0,
)
_QUICK_RATIO_BUCKETS: Final[tuple[float, ...]] = (
    0.0,
    0.1,
    0.25,
    0.5,
    0.75,
    0.9,
    0.95,
    1.0,
    1.5,
)
_QUICK_LLM_LATENCY_BUCKETS: Final[tuple[float, ...]] = (
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    20.0,
    30.0,
)
_QUICK_RAG_LATENCY_BUCKETS: Final[tuple[float, ...]] = (
    0.01,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
)

_quick_counters: dict[str, int] = {}
_quick_last_ratio: dict[str, float] = {}
_quick_seen_series: dict[str, set[tuple[tuple[str, str], ...]]] = {}
_quick_untracked_tool_executions: int = 0


def _truncate_label(value: object, *, fallback: str = "_other") -> str:
    s = "" if value is None else str(value).strip()
    if not s:
        return fallback
    if len(s) > _MAX_LABEL_LEN:
        return s[:_MAX_LABEL_LEN]
    return s


def _init_prometheus_metrics() -> None:
    global _PROM_INITIALIZED
    if _PROM_INITIALIZED or not _PROMETHEUS_AVAILABLE:
        return
    if PromCounter is None or PromHistogram is None:
        return

    specs: list[tuple[str, str, tuple[str, ...], str]] = [
        (
            "argus_llm_requests_total",
            "Unified LLM gateway requests.",
            ("alias", "provider", "model", "task", "status", "mode"),
            "counter",
        ),
        (
            "argus_llm_schema_failures_total",
            "LLM response schema validation failures.",
            ("alias", "provider", "model", "task", "mode"),
            "counter",
        ),
        (
            "argus_llm_fallback_total",
            "LLM provider failover attempts.",
            ("from_provider", "to_provider", "mode"),
            "counter",
        ),
        (
            "argus_rag_queries_total",
            "RAG retrieval queries.",
            ("mode",),
            "counter",
        ),
        (
            "argus_rag_cross_tenant_denials_total",
            "RAG cross-tenant access denials.",
            (),
            "counter",
        ),
        (
            "argus_nuclei_templates_loaded_total",
            "Nuclei templates loaded into registry.",
            ("verified", "protocol", "mode"),
            "counter",
        ),
        (
            "argus_nuclei_requests_total",
            "Nuclei profile compiler invocations.",
            ("profile", "mode"),
            "counter",
        ),
        (
            "argus_lab_executions_total",
            "LAB unrestricted policy allows.",
            ("tool", "action"),
            "counter",
        ),
        (
            "argus_lab_boundary_denials_total",
            "LAB boundary verification denials.",
            ("deny_code",),
            "counter",
        ),
        (
            "argus_coverage_requirements_total",
            "Coverage requirement status transitions.",
            ("status", "mode"),
            "counter",
        ),
        (
            "argus_findings_total",
            "Finding lifecycle state observations.",
            ("state", "mode"),
            "counter",
        ),
        (
            "argus_retests_total",
            "Finding retest outcomes.",
            ("result",),
            "counter",
        ),
        (
            "argus_oast_interactions_total",
            "OAST interaction ingest outcomes.",
            ("correlation_status",),
            "counter",
        ),
        (
            "argus_quick_deadline_overrun_total",
            "Quick scans that hit the wall-clock deadline before report.",
            (),
            "counter",
        ),
        (
            "argus_quick_tasks_total",
            "Quick tasks by stage, status, and tool (tool whitelist + _other).",
            ("stage", "status", "tool"),
            "counter",
        ),
        (
            "argus_quick_assets_discovered_total",
            "Assets discovered during a Quick scan.",
            (),
            "counter",
        ),
        (
            "argus_quick_templates_selected_total",
            "Nuclei templates selected into a Quick manifest.",
            (),
            "counter",
        ),
        (
            "argus_quick_findings_total",
            "Quick findings by severity and triage verdict.",
            ("severity", "verdict"),
            "counter",
        ),
        (
            "argus_quick_plan_revisions_total",
            "Quick plan revisions (adaptive widening; mode stays quick).",
            (),
            "counter",
        ),
        (
            "argus_quick_llm_calls_total",
            "Quick LLM calls by model, prompt, and status (whitelist + _other).",
            ("model", "prompt", "status"),
            "counter",
        ),
        (
            "argus_quick_tool_failures_total",
            "Quick tool failures by tool and reason (whitelist + _other).",
            ("tool", "reason"),
            "counter",
        ),
    ]
    hist_specs: list[tuple[str, str, tuple[str, ...], tuple[float, ...]]] = [
        (
            "argus_llm_latency_ms",
            "Unified LLM gateway request latency (milliseconds).",
            ("alias", "provider", "model", "task", "mode"),
            _LLM_LATENCY_BUCKETS,
        ),
        (
            "argus_rag_retrieval_latency_ms",
            "RAG hybrid retrieval latency (milliseconds).",
            ("mode",),
            _RAG_LATENCY_BUCKETS,
        ),
        (
            "argus_quick_scan_duration_seconds",
            "Quick scan wall-clock duration in seconds.",
            (),
            _QUICK_SCAN_DURATION_BUCKETS,
        ),
        (
            "argus_quick_budget_used_ratio",
            "Quick wall-clock budget consumed (0..1+).",
            (),
            _QUICK_RATIO_BUCKETS,
        ),
        (
            "argus_quick_validation_rate",
            "Quick selective-verification completion ratio (0..1).",
            (),
            _QUICK_RATIO_BUCKETS,
        ),
        (
            "argus_quick_false_positive_rate",
            "Quick false-positive-candidate ratio among findings (0..1).",
            (),
            _QUICK_RATIO_BUCKETS,
        ),
        (
            "argus_quick_coverage_ratio",
            "Quick coverage accounting rate (planned capability×asset).",
            (),
            _QUICK_RATIO_BUCKETS,
        ),
        (
            "argus_quick_llm_latency_seconds",
            "Quick LLM call latency in seconds.",
            ("model", "prompt"),
            _QUICK_LLM_LATENCY_BUCKETS,
        ),
        (
            "argus_quick_rag_latency_seconds",
            "Quick RAG retrieval latency in seconds.",
            (),
            _QUICK_RAG_LATENCY_BUCKETS,
        ),
    ]

    try:
        for name, doc, labels, kind in specs:
            if kind != "counter" or name in _PROM_COUNTERS:
                continue
            _PROM_COUNTERS[name] = PromCounter(name, doc, labelnames=labels)
        for name, doc, labels, buckets in hist_specs:
            if name in _PROM_HISTOGRAMS:
                continue
            _PROM_HISTOGRAMS[name] = PromHistogram(
                name,
                doc,
                labelnames=labels,
                buckets=buckets,
            )
        _PROM_INITIALIZED = True
    except Exception:  # pragma: no cover — duplicate registration guard
        logger.warning(
            "unified_ai_metrics.prometheus_init_failed",
            extra={"event": "unified_ai_metrics.prometheus_init_failed"},
        )


def _emit_counter(name: str, labels: dict[str, str] | None = None, *, amount: float = 1.0) -> None:
    if not _PROMETHEUS_AVAILABLE:
        return
    try:
        _init_prometheus_metrics()
        counter = _PROM_COUNTERS.get(name)
        if counter is None:
            return
        if labels:
            counter.labels(**labels).inc(amount)
        else:
            counter.inc(amount)
    except Exception:  # pragma: no cover
        logger.warning(
            "unified_ai_metrics.prometheus_emit_failed",
            extra={"event": "unified_ai_metrics.prometheus_emit_failed", "metric": name},
        )


def _emit_histogram(name: str, labels: dict[str, str], *, value: float) -> None:
    if not _PROMETHEUS_AVAILABLE:
        return
    try:
        _init_prometheus_metrics()
        hist = _PROM_HISTOGRAMS.get(name)
        if hist is None:
            return
        if labels:
            hist.labels(**labels).observe(max(0.0, value))
        else:
            hist.observe(max(0.0, value))
    except Exception:  # pragma: no cover
        logger.warning(
            "unified_ai_metrics.prometheus_emit_failed",
            extra={"event": "unified_ai_metrics.prometheus_emit_failed", "metric": name},
        )


def _whitelist_quick_label(label: str, value: object) -> str:
    """Coerce a Quick metric label: whitelist + length cap + ``_other``."""
    s = "" if value is None else str(value).strip().lower()
    if not s:
        return _QUICK_OTHER
    if len(s) > _MAX_LABEL_LEN:
        s = s[:_MAX_LABEL_LEN]
    allowed = _QUICK_LABEL_WHITELISTS.get(label)
    if allowed is not None and s not in allowed:
        return _QUICK_OTHER
    return s


def _admit_quick_series(metric: str, labels: dict[str, str]) -> bool:
    """Enforce per-metric cardinality cap. Fail-open: over-cap skips Prometheus."""
    key = tuple(sorted(labels.items()))
    with _LOCK:
        seen = _quick_seen_series.setdefault(metric, set())
        if key in seen:
            return True
        if len(seen) >= _QUICK_CARDINALITY_LIMIT:
            logger.warning(
                "unified_ai_metrics.quick_cardinality_capped",
                extra={
                    "event": "unified_ai_metrics.quick_cardinality_capped",
                    "metric": metric,
                },
            )
            return False
        seen.add(key)
        return True


def _inc_quick_counter(
    name: str,
    labels: dict[str, str] | None = None,
    *,
    amount: int = 1,
) -> int:
    with _LOCK:
        _quick_counters[name] = _quick_counters.get(name, 0) + amount
        total = _quick_counters[name]
    if labels and not _admit_quick_series(name, labels):
        return total
    _emit_counter(name, labels, amount=float(amount))
    return total


def _observe_quick_ratio(name: str, value: float) -> None:
    clamped = max(0.0, float(value))
    with _LOCK:
        _quick_last_ratio[name] = clamped
    _emit_histogram(name, {}, value=clamped)


def reset_unified_ai_metrics() -> None:
    """Reset integer mirrors — tests only."""
    global _llm_requests_total, _llm_schema_failures_total, _llm_fallback_total
    global _rag_queries_total, _rag_cross_tenant_denials_total
    global _nuclei_templates_loaded_total, _nuclei_requests_total
    global _lab_executions_total, _lab_boundary_denials_total
    global _coverage_requirements_total, _findings_total, _retests_total
    global _oast_interactions_total, _quick_untracked_tool_executions
    with _LOCK:
        _llm_requests_total = 0
        _llm_schema_failures_total = 0
        _llm_fallback_total = 0
        _rag_queries_total = 0
        _rag_cross_tenant_denials_total = 0
        _nuclei_templates_loaded_total = 0
        _nuclei_requests_total = 0
        _lab_executions_total = 0
        _lab_boundary_denials_total = 0
        _coverage_requirements_total = 0
        _findings_total = 0
        _retests_total = 0
        _oast_interactions_total = 0
        _quick_counters.clear()
        _quick_last_ratio.clear()
        _quick_seen_series.clear()
        _quick_untracked_tool_executions = 0


def record_llm_request(
    *,
    alias: str,
    provider: str,
    model: str,
    task: str,
    status: str,
    mode: str,
    latency_ms: float,
) -> int:
    """Record one unified LLM gateway request."""
    global _llm_requests_total
    labels = {
        "alias": _truncate_label(alias),
        "provider": _truncate_label(provider),
        "model": _truncate_label(model),
        "task": _truncate_label(task),
        "status": _truncate_label(status),
        "mode": _truncate_label(mode),
    }
    with _LOCK:
        _llm_requests_total += 1
        total = _llm_requests_total
    _emit_counter("argus_llm_requests_total", labels)
    _emit_histogram(
        "argus_llm_latency_ms",
        {k: v for k, v in labels.items() if k != "status"},
        value=float(latency_ms),
    )
    return total


def record_llm_schema_failure(
    *,
    alias: str = "_unknown",
    provider: str = "_unknown",
    model: str = "_unknown",
    task: str = "_unknown",
    mode: str = "production",
) -> int:
    """Record one LLM schema validation failure."""
    global _llm_schema_failures_total
    labels = {
        "alias": _truncate_label(alias),
        "provider": _truncate_label(provider),
        "model": _truncate_label(model),
        "task": _truncate_label(task),
        "mode": _truncate_label(mode),
    }
    with _LOCK:
        _llm_schema_failures_total += 1
        total = _llm_schema_failures_total
    _emit_counter("argus_llm_schema_failures_total", labels)
    return total


def record_llm_fallback(
    *,
    from_provider: str = "_unknown",
    to_provider: str = "_unknown",
    mode: str = "production",
) -> int:
    """Record one LLM provider failover attempt."""
    global _llm_fallback_total
    labels = {
        "from_provider": _truncate_label(from_provider),
        "to_provider": _truncate_label(to_provider),
        "mode": _truncate_label(mode),
    }
    with _LOCK:
        _llm_fallback_total += 1
        total = _llm_fallback_total
    _emit_counter("argus_llm_fallback_total", labels)
    return total


def record_rag_query(*, mode: str = "production") -> int:
    """Record one RAG retrieval query."""
    global _rag_queries_total
    labels = {"mode": _truncate_label(mode)}
    with _LOCK:
        _rag_queries_total += 1
        total = _rag_queries_total
    _emit_counter("argus_rag_queries_total", labels)
    return total


def record_rag_retrieval_latency(*, mode: str = "production", latency_ms: float = 0.0) -> None:
    """Record RAG hybrid retrieval latency."""
    labels = {"mode": _truncate_label(mode)}
    _emit_histogram("argus_rag_retrieval_latency_ms", labels, value=float(latency_ms))


def record_rag_cross_tenant_denial() -> int:
    """Record one cross-tenant RAG chunk exclusion."""
    global _rag_cross_tenant_denials_total
    with _LOCK:
        _rag_cross_tenant_denials_total += 1
        total = _rag_cross_tenant_denials_total
    _emit_counter("argus_rag_cross_tenant_denials_total")
    return total


def record_nuclei_templates_loaded(
    *,
    verified: bool,
    protocol: str,
    mode: str,
) -> int:
    """Record Nuclei template load into registry."""
    global _nuclei_templates_loaded_total
    labels = {
        "verified": "true" if verified else "false",
        "protocol": _truncate_label(protocol),
        "mode": _truncate_label(mode),
    }
    with _LOCK:
        _nuclei_templates_loaded_total += 1
        total = _nuclei_templates_loaded_total
    _emit_counter("argus_nuclei_templates_loaded_total", labels)
    return total


def record_nuclei_request(*, profile: str, mode: str) -> int:
    """Record one Nuclei profile compiler invocation."""
    global _nuclei_requests_total
    labels = {
        "profile": _truncate_label(profile),
        "mode": _truncate_label(mode),
    }
    with _LOCK:
        _nuclei_requests_total += 1
        total = _nuclei_requests_total
    _emit_counter("argus_nuclei_requests_total", labels)
    return total


def record_lab_execution(*, tool: str = "_unknown", action: str = "_unknown") -> int:
    """Record one LAB allow-all policy decision."""
    global _lab_executions_total
    labels = {
        "tool": _truncate_label(tool),
        "action": _truncate_label(action),
    }
    with _LOCK:
        _lab_executions_total += 1
        total = _lab_executions_total
    _emit_counter("argus_lab_executions_total", labels)
    return total


def record_lab_boundary_denial(*, deny_code: str = "DENY_OUTSIDE_LAB") -> int:
    """Record one LAB boundary denial."""
    global _lab_boundary_denials_total
    labels = {"deny_code": _truncate_label(deny_code, fallback="DENY_OUTSIDE_LAB")}
    with _LOCK:
        _lab_boundary_denials_total += 1
        total = _lab_boundary_denials_total
    _emit_counter("argus_lab_boundary_denials_total", labels)
    return total


def record_coverage_requirement(*, status: str, mode: str = "production") -> int:
    """Record one coverage requirement status observation."""
    global _coverage_requirements_total
    labels = {
        "status": _truncate_label(status),
        "mode": _truncate_label(mode),
    }
    with _LOCK:
        _coverage_requirements_total += 1
        total = _coverage_requirements_total
    _emit_counter("argus_coverage_requirements_total", labels)
    return total


def record_finding(*, state: str, mode: str = "production") -> int:
    """Record one finding lifecycle state observation."""
    global _findings_total
    labels = {
        "state": _truncate_label(state),
        "mode": _truncate_label(mode),
    }
    with _LOCK:
        _findings_total += 1
        total = _findings_total
    _emit_counter("argus_findings_total", labels)
    return total


def record_retest(*, result: str) -> int:
    """Record one finding retest outcome."""
    global _retests_total
    labels = {"result": _truncate_label(result)}
    with _LOCK:
        _retests_total += 1
        total = _retests_total
    _emit_counter("argus_retests_total", labels)
    return total


def record_oast_interaction(*, correlation_status: str) -> int:
    """Record one OAST interaction ingest outcome."""
    global _oast_interactions_total
    labels = {"correlation_status": _truncate_label(correlation_status)}
    with _LOCK:
        _oast_interactions_total += 1
        total = _oast_interactions_total
    _emit_counter("argus_oast_interactions_total", labels)
    return total


def get_llm_requests_total() -> int:
    with _LOCK:
        return _llm_requests_total


def get_llm_schema_failures_total() -> int:
    with _LOCK:
        return _llm_schema_failures_total


def get_llm_fallback_total() -> int:
    with _LOCK:
        return _llm_fallback_total


def get_rag_queries_total() -> int:
    with _LOCK:
        return _rag_queries_total


def get_rag_cross_tenant_denials_total() -> int:
    with _LOCK:
        return _rag_cross_tenant_denials_total


def get_nuclei_templates_loaded_total() -> int:
    with _LOCK:
        return _nuclei_templates_loaded_total


def get_nuclei_requests_total() -> int:
    with _LOCK:
        return _nuclei_requests_total


def get_lab_executions_total() -> int:
    with _LOCK:
        return _lab_executions_total


def get_lab_boundary_denials_total() -> int:
    with _LOCK:
        return _lab_boundary_denials_total


def get_coverage_requirements_total() -> int:
    with _LOCK:
        return _coverage_requirements_total


def get_findings_total() -> int:
    with _LOCK:
        return _findings_total


def get_retests_total() -> int:
    with _LOCK:
        return _retests_total


def get_oast_interactions_total() -> int:
    with _LOCK:
        return _oast_interactions_total


def record_quick_scan_duration(seconds: float) -> None:
    """Observe Quick scan wall-clock duration."""
    _emit_histogram("argus_quick_scan_duration_seconds", {}, value=max(0.0, float(seconds)))


def record_quick_deadline_overrun(*, amount: int = 1) -> int:
    """Record a Quick scan that missed the report window after deadline."""
    return _inc_quick_counter("argus_quick_deadline_overrun_total", amount=amount)


def record_quick_budget_used_ratio(ratio: float) -> None:
    """Observe wall-clock budget consumed (typically 0..1)."""
    _observe_quick_ratio("argus_quick_budget_used_ratio", ratio)


def record_quick_task(*, stage: str, status: str, tool: str, amount: int = 1) -> int:
    """Record one Quick task observation. Unknown tools collapse to ``_other``."""
    labels = {
        "stage": _whitelist_quick_label("stage", stage),
        "status": _whitelist_quick_label("status", status),
        "tool": _whitelist_quick_label("tool", tool),
    }
    return _inc_quick_counter("argus_quick_tasks_total", labels, amount=amount)


def record_quick_assets_discovered(*, amount: int = 1) -> int:
    """Record assets discovered during Quick recon."""
    return _inc_quick_counter("argus_quick_assets_discovered_total", amount=max(0, amount))


def record_quick_templates_selected(*, amount: int = 1) -> int:
    """Record Nuclei templates selected into a Quick manifest."""
    return _inc_quick_counter("argus_quick_templates_selected_total", amount=max(0, amount))


def record_quick_finding(*, severity: str, verdict: str, amount: int = 1) -> int:
    """Record one Quick finding by severity and triage verdict."""
    labels = {
        "severity": _whitelist_quick_label("severity", severity),
        "verdict": _whitelist_quick_label("verdict", verdict),
    }
    return _inc_quick_counter("argus_quick_findings_total", labels, amount=amount)


def record_quick_validation_rate(ratio: float) -> None:
    """Observe selective-verification completion ratio."""
    _observe_quick_ratio("argus_quick_validation_rate", ratio)


def record_quick_false_positive_rate(ratio: float) -> None:
    """Observe false-positive-candidate ratio among findings."""
    _observe_quick_ratio("argus_quick_false_positive_rate", ratio)


def record_quick_coverage_ratio(ratio: float) -> None:
    """Observe coverage accounting rate for planned capability×asset pairs."""
    _observe_quick_ratio("argus_quick_coverage_ratio", ratio)


def record_quick_plan_revision(*, amount: int = 1) -> int:
    """Record one Quick plan revision (mode stays quick)."""
    return _inc_quick_counter("argus_quick_plan_revisions_total", amount=amount)


def record_quick_llm_call(
    *,
    model: str,
    prompt: str,
    status: str,
    latency_seconds: float = 0.0,
) -> int:
    """Record one Quick LLM call and its latency."""
    labels = {
        "model": _whitelist_quick_label("model", model),
        "prompt": _whitelist_quick_label("prompt", prompt),
        "status": _whitelist_quick_label("status", status),
    }
    total = _inc_quick_counter("argus_quick_llm_calls_total", labels)
    hist_labels = {"model": labels["model"], "prompt": labels["prompt"]}
    if _admit_quick_series("argus_quick_llm_latency_seconds", hist_labels):
        _emit_histogram(
            "argus_quick_llm_latency_seconds",
            hist_labels,
            value=max(0.0, float(latency_seconds)),
        )
    return total


def record_quick_rag_latency(seconds: float) -> None:
    """Observe Quick RAG retrieval latency."""
    _emit_histogram("argus_quick_rag_latency_seconds", {}, value=max(0.0, float(seconds)))


def record_quick_tool_failure(*, tool: str, reason: str, amount: int = 1) -> int:
    """Record a Quick tool failure. Unknown tools/reasons collapse to ``_other``."""
    global _quick_untracked_tool_executions
    labels = {
        "tool": _whitelist_quick_label("tool", tool),
        "reason": _whitelist_quick_label("reason", reason),
    }
    normalized_reason = str(reason or "").strip().lower()
    if normalized_reason == "untracked":
        with _LOCK:
            _quick_untracked_tool_executions += amount
    return _inc_quick_counter("argus_quick_tool_failures_total", labels, amount=amount)


def get_quick_counter(name: str) -> int:
    with _LOCK:
        return int(_quick_counters.get(name, 0))


def get_quick_last_ratio(name: str) -> float:
    with _LOCK:
        return float(_quick_last_ratio.get(name, 0.0))


def get_quick_deadline_overrun_total() -> int:
    return get_quick_counter("argus_quick_deadline_overrun_total")


def get_quick_tasks_total() -> int:
    return get_quick_counter("argus_quick_tasks_total")


def get_quick_assets_discovered_total() -> int:
    return get_quick_counter("argus_quick_assets_discovered_total")


def get_quick_templates_selected_total() -> int:
    return get_quick_counter("argus_quick_templates_selected_total")


def get_quick_findings_total() -> int:
    return get_quick_counter("argus_quick_findings_total")


def get_quick_plan_revisions_total() -> int:
    return get_quick_counter("argus_quick_plan_revisions_total")


def get_quick_llm_calls_total() -> int:
    return get_quick_counter("argus_quick_llm_calls_total")


def get_quick_tool_failures_total() -> int:
    return get_quick_counter("argus_quick_tool_failures_total")


def get_quick_untracked_tool_executions() -> int:
    with _LOCK:
        return _quick_untracked_tool_executions


def get_quick_cardinality_series_count(metric: str) -> int:
    with _LOCK:
        return len(_quick_seen_series.get(metric, set()))


__all__ = [
    "METRIC_ALIAS_MAP",
    "QUICK_METRIC_ALIAS_MAP",
    "QUICK_TOOL_WHITELIST",
    "get_coverage_requirements_total",
    "get_findings_total",
    "get_lab_boundary_denials_total",
    "get_lab_executions_total",
    "get_llm_fallback_total",
    "get_llm_requests_total",
    "get_llm_schema_failures_total",
    "get_nuclei_requests_total",
    "get_nuclei_templates_loaded_total",
    "get_oast_interactions_total",
    "get_quick_assets_discovered_total",
    "get_quick_cardinality_series_count",
    "get_quick_counter",
    "get_quick_deadline_overrun_total",
    "get_quick_findings_total",
    "get_quick_last_ratio",
    "get_quick_llm_calls_total",
    "get_quick_plan_revisions_total",
    "get_quick_tasks_total",
    "get_quick_templates_selected_total",
    "get_quick_tool_failures_total",
    "get_quick_untracked_tool_executions",
    "get_rag_cross_tenant_denials_total",
    "get_rag_queries_total",
    "get_retests_total",
    "record_coverage_requirement",
    "record_finding",
    "record_lab_boundary_denial",
    "record_lab_execution",
    "record_llm_fallback",
    "record_llm_request",
    "record_llm_schema_failure",
    "record_nuclei_request",
    "record_nuclei_templates_loaded",
    "record_oast_interaction",
    "record_quick_assets_discovered",
    "record_quick_budget_used_ratio",
    "record_quick_coverage_ratio",
    "record_quick_deadline_overrun",
    "record_quick_false_positive_rate",
    "record_quick_finding",
    "record_quick_llm_call",
    "record_quick_plan_revision",
    "record_quick_rag_latency",
    "record_quick_scan_duration",
    "record_quick_task",
    "record_quick_templates_selected",
    "record_quick_tool_failure",
    "record_quick_validation_rate",
    "record_rag_cross_tenant_denial",
    "record_rag_query",
    "record_rag_retrieval_latency",
    "record_retest",
    "reset_unified_ai_metrics",
]
