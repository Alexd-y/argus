"""Unit tests for ``src.core.observability`` — ARG-041.

Coverage focus:

* Catalogue invariant — exactly 9 metric families with the required label sets.
* Cardinality cap (``_CARDINALITY_LIMIT_PER_METRIC``) is enforced per metric.
* ``tenant_hash`` is a sha256-derived 16-char fingerprint and never echoes
  the raw ``tenant_id``.
* Whitelisted labels reject unknown values and degrade to ``_other`` while
  emitting a warning log.
* Public recorders never raise on bad inputs (defence-in-depth — feature
  code MUST NOT break because metrics broke).

Each test calls :func:`reset_metrics_registry` so series state never leaks
across cases (Prometheus globals are otherwise persistent).
"""

from __future__ import annotations

import hashlib
import re
from typing import Final

import pytest
from prometheus_client import CollectorRegistry

from src.core import observability as obs
from src.core.observability import (
    LABEL_VALUE_WHITELIST,
    METRIC_CATALOGUE,
    OTHER_LABEL_VALUE,
    SYSTEM_TENANT_HASH,
    record_celery_task,
    record_finding_emitted,
    record_http_request,
    record_llm_tokens,
    record_mcp_call,
    record_sandbox_run,
    reset_metrics_registry,
    tenant_hash,
    user_id_hash,
)


_HEX16: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{16}$")


@pytest.fixture(autouse=True)
def _isolated_registry() -> CollectorRegistry:
    """Each test runs against a private CollectorRegistry."""
    reg = CollectorRegistry()
    reset_metrics_registry(registry=reg)
    return reg


def _samples(reg: CollectorRegistry, name: str) -> list[tuple[dict[str, str], float]]:
    """Return ``[(labels, value), ...]`` for the named metric.

    Counter exposition uses ``<name>_total``; histogram exposition uses
    ``<base>_count`` / ``<base>_sum`` / ``<base>_bucket``. We accept any of
    those terminal suffixes so callers don't need to know the metric kind."""
    out: list[tuple[dict[str, str], float]] = []
    suffixes = ("", "_total", "_count")
    for family in reg.collect():
        for sample in family.samples:
            if any(sample.name == name + s for s in suffixes):
                out.append((dict(sample.labels), float(sample.value)))
    return out


# ---------------------------------------------------------------------------
# Catalogue / structural invariants
# ---------------------------------------------------------------------------


def test_catalogue_has_exactly_nine_families() -> None:
    """The plan locks the public surface to 9 metric families."""
    assert len(METRIC_CATALOGUE) == 9


def test_catalogue_names_are_prefixed_and_unique() -> None:
    names = [s.name for s in METRIC_CATALOGUE]
    assert len(names) == len(set(names)), "duplicate metric names"
    for n in names:
        assert n.startswith("argus_"), n


@pytest.mark.parametrize(
    "metric_name, required_labels",
    [
        ("argus_http_requests_total", {"method", "route", "status_class", "tenant_hash"}),
        ("argus_http_request_duration_seconds", {"method", "route", "tenant_hash"}),
        ("argus_celery_task_duration_seconds", {"task_name", "status"}),
        ("argus_celery_task_failures_total", {"task_name", "error_class"}),
        ("argus_sandbox_runs_total", {"tool_id", "status", "profile"}),
        ("argus_sandbox_run_duration_seconds", {"tool_id", "profile"}),
        ("argus_findings_emitted_total", {"tier", "severity", "kev_listed"}),
        ("argus_llm_tokens_total", {"provider", "model", "direction"}),
        ("argus_mcp_calls_total", {"tool", "status", "client_class"}),
    ],
)
def test_each_metric_has_required_labels(
    metric_name: str, required_labels: set[str]
) -> None:
    spec = next((s for s in METRIC_CATALOGUE if s.name == metric_name), None)
    assert spec is not None, f"missing metric in catalogue: {metric_name}"
    assert set(spec.labels) == required_labels


def test_label_value_whitelist_keys_are_subset_of_catalogue_labels() -> None:
    """Every whitelisted label MUST appear in at least one metric spec."""
    catalogue_labels = {label for spec in METRIC_CATALOGUE for label in spec.labels}
    for label in LABEL_VALUE_WHITELIST:
        assert label in catalogue_labels, label


# ---------------------------------------------------------------------------
# tenant_hash discipline
# ---------------------------------------------------------------------------


def test_tenant_hash_is_sha256_truncated_to_16_hex() -> None:
    h = tenant_hash("tenant-42", salt="")
    assert _HEX16.fullmatch(h)
    digest = hashlib.sha256(b"tenant-42").hexdigest()
    assert h == digest[:16]


def test_tenant_hash_is_deterministic_per_input() -> None:
    assert tenant_hash("alpha", salt="x") == tenant_hash("alpha", salt="x")


def test_tenant_hash_changes_with_salt() -> None:
    assert tenant_hash("alpha", salt="x") != tenant_hash("alpha", salt="y")


def test_tenant_hash_none_collapses_to_system_sentinel() -> None:
    assert tenant_hash(None) == SYSTEM_TENANT_HASH
    assert tenant_hash("") == SYSTEM_TENANT_HASH
    assert tenant_hash("   ") == SYSTEM_TENANT_HASH


def test_tenant_hash_never_echoes_raw_value() -> None:
    raw = "supersecret-tenant-id"
    h = tenant_hash(raw, salt="")
    assert raw not in h
    assert len(h) == 16


def test_user_id_hash_matches_uid_prefix_discipline() -> None:
    h = user_id_hash("sub-123", salt="")
    assert _HEX16.fullmatch(h)
    expected = hashlib.sha256(b"uid:sub-123".encode()).hexdigest()[:16]
    assert h == expected


def test_user_id_hash_empty_collapses_to_system_sentinel() -> None:
    assert user_id_hash(None) == SYSTEM_TENANT_HASH
    assert user_id_hash("") == SYSTEM_TENANT_HASH


# ---------------------------------------------------------------------------
# Whitelist enforcement / `_other` fallback
# ---------------------------------------------------------------------------


def test_unknown_method_falls_back_to_other(
    _isolated_registry: CollectorRegistry, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("WARNING", logger="src.core.observability")
    record_http_request(
        method="ATTACK",
        route="/api/v1/scans",
        status_code=200,
        duration_seconds=0.01,
        tenant_id="t-1",
    )
    samples = _samples(_isolated_registry, "argus_http_requests_total")
    assert any(lbls.get("method") == OTHER_LABEL_VALUE for lbls, _ in samples)
    assert any("label_value_rejected" in r.message for r in caplog.records)


def test_celery_status_unknown_value_replaced(
    _isolated_registry: CollectorRegistry,
) -> None:
    record_celery_task(
        task_name="t.sample",
        status="exploding-burrito",  # not whitelisted
        duration_seconds=0.5,
    )
    samples = _samples(_isolated_registry, "argus_celery_task_duration_seconds")
    statuses = {lbls["status"] for lbls, _ in samples}
    assert OTHER_LABEL_VALUE in statuses


def test_finding_kev_flag_normalised_to_string_true_false(
    _isolated_registry: CollectorRegistry,
) -> None:
    record_finding_emitted(tier="midgard", severity="high", kev_listed=True)
    record_finding_emitted(tier="midgard", severity="low", kev_listed=False)
    samples = _samples(_isolated_registry, "argus_findings_emitted_total")
    flags = {lbls["kev_listed"] for lbls, _ in samples}
    assert flags == {"true", "false"}


def test_mcp_client_class_unknown_replaced(
    _isolated_registry: CollectorRegistry,
) -> None:
    record_mcp_call(tool="scan.start", status="success", client_class="evil-bot")
    samples = _samples(_isolated_registry, "argus_mcp_calls_total")
    assert any(
        lbls["client_class"] == OTHER_LABEL_VALUE for lbls, _ in samples
    )


# ---------------------------------------------------------------------------
# Cardinality cap
# ---------------------------------------------------------------------------


def test_cardinality_cap_per_metric_holds(
    _isolated_registry: CollectorRegistry,
) -> None:
    """Spam 1500 unique tool_ids — only 1000 series should land."""
    for idx in range(1500):
        record_sandbox_run(
            tool_id=f"tool-{idx:05d}",
            status="success",
            profile="kubernetes",
            duration_seconds=0.01,
        )
    samples = _samples(_isolated_registry, "argus_sandbox_runs_total")
    assert len(samples) <= obs._CARDINALITY_LIMIT_PER_METRIC


def test_cardinality_warning_emitted_only_once_per_metric(
    _isolated_registry: CollectorRegistry,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``cardinality_cap_reached`` MUST log at most once per metric per process.

    ``record_sandbox_run`` writes to two metric families (counter +
    histogram), each with its own guard, so we expect exactly one warning
    per metric family — not per recorder call. The cap is the discipline;
    log spam is what we are guarding against.
    """
    caplog.set_level("WARNING", logger="src.core.observability")
    for idx in range(2000):
        record_sandbox_run(
            tool_id=f"flood-{idx}",
            status="success",
            profile="kubernetes",
            duration_seconds=0.0,
        )
    cap_msgs = [r for r in caplog.records if "cardinality_cap_reached" in r.message]
    metrics_warned = {
        getattr(r, "metric", None) for r in cap_msgs if hasattr(r, "metric")
    }
    # 2000 calls produced AT MOST one warning per affected metric.
    assert len(cap_msgs) == len(metrics_warned)
    assert len(cap_msgs) <= 2


# ---------------------------------------------------------------------------
# Recorder behaviour
# ---------------------------------------------------------------------------


def test_record_http_request_emits_counter_and_histogram(
    _isolated_registry: CollectorRegistry,
) -> None:
    record_http_request(
        method="GET",
        route="/api/v1/scans/{scan_id}",
        status_code=200,
        duration_seconds=0.123,
        tenant_id="tenant-x",
    )
    counter = _samples(_isolated_registry, "argus_http_requests_total")
    histo = _samples(_isolated_registry, "argus_http_request_duration_seconds")
    assert counter, "no counter sample recorded"
    assert histo, "no histogram sample recorded"


def test_record_http_request_status_class_buckets() -> None:
    assert obs._status_class(200) == "2xx"
    assert obs._status_class(404) == "4xx"
    assert obs._status_class(503) == "5xx"
    assert obs._status_class(999) == OTHER_LABEL_VALUE


def test_record_llm_tokens_zero_is_noop(
    _isolated_registry: CollectorRegistry,
) -> None:
    record_llm_tokens(provider="openai", model="gpt-4o", direction="in", tokens=0)
    record_llm_tokens(provider="openai", model="gpt-4o", direction="in", tokens=-5)
    samples = _samples(_isolated_registry, "argus_llm_tokens_total")
    assert samples == []


def test_record_llm_tokens_positive_emits(
    _isolated_registry: CollectorRegistry,
) -> None:
    record_llm_tokens(
        provider="anthropic", model="claude-3.5-sonnet", direction="in", tokens=120
    )
    samples = _samples(_isolated_registry, "argus_llm_tokens_total")
    assert samples
    _, value = samples[0]
    assert value == pytest.approx(120.0)


def test_record_celery_task_failure_emits_failure_counter(
    _isolated_registry: CollectorRegistry,
) -> None:
    record_celery_task(
        task_name="scans.run",
        status="failure",
        duration_seconds=2.5,
        error_class="TimeoutError",
    )
    failures = _samples(_isolated_registry, "argus_celery_task_failures_total")
    assert failures
    lbls, _ = failures[0]
    assert lbls["task_name"] == "scans.run"
    assert lbls["error_class"] == "TimeoutError"


def test_record_finding_emitted_severity_lowered(
    _isolated_registry: CollectorRegistry,
) -> None:
    record_finding_emitted(tier="MIDGARD", severity="HIGH", kev_listed=False)
    samples = _samples(_isolated_registry, "argus_findings_emitted_total")
    assert any(lbls["severity"] == "high" and lbls["tier"] == "midgard"
               for lbls, _ in samples)


def test_record_mcp_call_status_validation_error_admitted(
    _isolated_registry: CollectorRegistry,
) -> None:
    record_mcp_call(
        tool="scan.start", status="validation_error", client_class="anthropic"
    )
    samples = _samples(_isolated_registry, "argus_mcp_calls_total")
    assert samples


def test_record_http_request_with_none_tenant_uses_system_hash(
    _isolated_registry: CollectorRegistry,
) -> None:
    record_http_request(
        method="GET",
        route="/health",
        status_code=200,
        duration_seconds=0.0,
        tenant_id=None,
    )
    samples = _samples(_isolated_registry, "argus_http_requests_total")
    assert any(lbls["tenant_hash"] == SYSTEM_TENANT_HASH for lbls, _ in samples)


# ---------------------------------------------------------------------------
# Defensive properties — recorders never raise
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fn,kwargs",
    [
        (
            record_http_request,
            {
                "method": None,
                "route": "",
                "status_code": -1,
                "duration_seconds": float("nan"),
                "tenant_id": None,
            },
        ),
        (
            record_celery_task,
            {"task_name": "", "status": "", "duration_seconds": -1.0},
        ),
        (
            record_sandbox_run,
            {
                "tool_id": "x" * 1024,
                "status": "💥",
                "profile": "🦄",
                "duration_seconds": 0.0,
            },
        ),
        (
            record_finding_emitted,
            {"tier": "", "severity": "🚨", "kev_listed": False},
        ),
        (
            record_llm_tokens,
            {"provider": "", "model": "", "direction": "", "tokens": 1},
        ),
        (
            record_mcp_call,
            {"tool": "x" * 1024, "status": "x" * 64, "client_class": "x" * 64},
        ),
    ],
)
def test_recorders_never_raise_on_garbage(
    _isolated_registry: CollectorRegistry, fn, kwargs
) -> None:
    """Calling any recorder with adversarial input MUST be a no-op, not crash."""
    fn(**kwargs)
