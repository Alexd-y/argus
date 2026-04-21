"""Security: cardinality + redaction discipline of observability — ARG-041.

Threats covered:

* **Metric explosion via tenant_id flooding.** An attacker emitting
  10 000 unique tenant ids must NOT inflate the series count past the
  per-metric cap (1000).
* **Raw tenant_id leak via direct API.** ``record_http_request`` MUST
  hash ``tenant_id`` before it leaves the function.
* **Header secret leak.** ``Authorization`` / ``Cookie`` / ``X-Api-Key``
  values present anywhere in a log record's payload MUST be redacted by
  :class:`SensitiveHeaderRedactor` before the JSON formatter sees them.

These are not “unit tests” — they are invariants that defend against
real-world abuse vectors (DOS-by-cardinality, secret leak via logs).
"""

from __future__ import annotations

import logging
from typing import Any

import pytest
from prometheus_client import CollectorRegistry

from src.core import observability as obs
from src.core.logging_config import (
    OTelTraceContextFilter,
    SensitiveHeaderRedactor,
)
from src.core.observability import (
    SYSTEM_TENANT_HASH,
    record_http_request,
    record_llm_tokens,
    reset_metrics_registry,
    tenant_hash,
)


# This module is intentionally decoupled from the FastAPI app — the test
# suite stays offline (no DB / Redis dependency) so it can run on a bare
# CI worker. Marking with ``no_auth_override`` short-circuits the autouse
# fixture in ``backend/tests/conftest.py`` that pulls ``main.app`` (which
# in turn imports SQLAlchemy + drivers we don't need here).
pytestmark = pytest.mark.no_auth_override


@pytest.fixture(autouse=True)
def _isolated_registry() -> CollectorRegistry:
    reg = CollectorRegistry()
    reset_metrics_registry(registry=reg)
    return reg


def _tenant_hash_series(reg: CollectorRegistry) -> set[str]:
    """Return the unique tenant_hash label values present in the registry."""
    out: set[str] = set()
    for family in reg.collect():
        for sample in family.samples:
            th = sample.labels.get("tenant_hash") if sample.labels else None
            if th is not None:
                out.add(th)
    return out


def test_tenant_id_flood_capped_at_1000_series(
    _isolated_registry: CollectorRegistry,
) -> None:
    for idx in range(10_000):
        record_http_request(
            method="GET",
            route="/api/v1/scans",
            status_code=200,
            duration_seconds=0.001,
            tenant_id=f"attacker-tenant-{idx:06d}",
        )
    series = _tenant_hash_series(_isolated_registry)
    # The cap is per-metric; HTTP counter shares its guard with the
    # histogram. Worst case both deplete the cap independently.
    assert len(series) <= obs._CARDINALITY_LIMIT_PER_METRIC


def test_raw_tenant_id_never_appears_in_metric_labels(
    _isolated_registry: CollectorRegistry,
) -> None:
    record_http_request(
        method="GET",
        route="/api/v1/scans",
        status_code=200,
        duration_seconds=0.0,
        tenant_id="acme-corp-secret-ID",
    )
    series = _tenant_hash_series(_isolated_registry)
    assert "acme-corp-secret-ID" not in series
    expected = tenant_hash("acme-corp-secret-ID")
    assert expected in series


def test_none_tenant_collapses_to_system_sentinel(
    _isolated_registry: CollectorRegistry,
) -> None:
    record_http_request(
        method="GET",
        route="/health",
        status_code=200,
        duration_seconds=0.0,
        tenant_id=None,
    )
    series = _tenant_hash_series(_isolated_registry)
    assert SYSTEM_TENANT_HASH in series


def test_label_value_truncated_to_64_chars(
    _isolated_registry: CollectorRegistry,
) -> None:
    long_tool = "x" * 1024
    record_llm_tokens(
        provider="openai", model=long_tool, direction="in", tokens=1
    )
    seen_models: set[str] = set()
    for family in _isolated_registry.collect():
        for sample in family.samples:
            label = sample.labels.get("model") if sample.labels else None
            if label is not None:
                seen_models.add(label)
    for label in seen_models:
        assert len(label) <= 64


# ---------------------------------------------------------------------------
# SensitiveHeaderRedactor — secrets in log records
# ---------------------------------------------------------------------------


def _record(payload: dict[str, Any]) -> logging.LogRecord:
    rec = logging.LogRecord(
        name="argus", level=logging.INFO, pathname=__file__, lineno=1,
        msg="event", args=(), exc_info=None,
    )
    for k, v in payload.items():
        setattr(rec, k, v)
    return rec


def test_authorization_header_value_redacted_in_log_record() -> None:
    rec = _record({"headers": {"Authorization": "Bearer sk-abcdef-secret-token"}})
    SensitiveHeaderRedactor().filter(rec)
    serialised = repr(getattr(rec, "headers", {}))
    assert "sk-abcdef-secret-token" not in serialised


def test_cookie_header_value_redacted() -> None:
    rec = _record({"headers": {"Cookie": "sessionid=topsecret"}})
    SensitiveHeaderRedactor().filter(rec)
    serialised = repr(getattr(rec, "headers", {}))
    assert "topsecret" not in serialised


def test_x_api_key_header_redacted() -> None:
    rec = _record({"headers": {"X-Api-Key": "pk_test_12345678901234567890123456"}})
    SensitiveHeaderRedactor().filter(rec)
    serialised = repr(getattr(rec, "headers", {}))
    assert "pk_test_12345678901234567890123456" not in serialised


def test_redactor_is_idempotent() -> None:
    rec = _record({"headers": {"Authorization": "Bearer abc"}})
    rd = SensitiveHeaderRedactor()
    rd.filter(rec)
    first = repr(getattr(rec, "headers", {}))
    rd.filter(rec)
    second = repr(getattr(rec, "headers", {}))
    assert first == second


def test_otel_filter_does_not_inject_when_no_active_span() -> None:
    rec = _record({})
    OTelTraceContextFilter().filter(rec)
    if hasattr(rec, "trace_id"):
        assert rec.trace_id in (None, "", "0", "00000000000000000000000000000000")


def test_record_http_request_does_not_embed_authorization_header(
    _isolated_registry: CollectorRegistry,
) -> None:
    """Defence-in-depth: the recorder must not accept arbitrary kwargs."""
    record_http_request(
        method="GET",
        route="/api/v1/scans",
        status_code=200,
        duration_seconds=0.0,
        tenant_id="test",
    )
    body = b""
    for family in _isolated_registry.collect():
        for sample in family.samples:
            body += repr(sample.labels).encode("utf-8")
    assert b"Authorization" not in body
    assert b"Bearer " not in body
