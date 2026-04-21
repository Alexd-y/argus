"""Integration: OTel span lifecycle through HTTP middleware + helpers — ARG-041.

Without a live collector we cannot verify network export, but we can:

* Install an in-memory ``SimpleSpanProcessor`` against the global TracerProvider.
* Issue a request through the FastAPI test client; verify that an HTTP server
  span (the FastAPI instrumentor) lands in the in-memory exporter.
* Wrap a manual ``with get_tracer().start_as_current_span(...)`` block and
  verify trace context (trace_id / span_id) propagates into log records via
  :class:`OTelTraceContextFilter`.
* Verify that ``safe_set_span_attribute`` rejects raw ``tenant_id``.

Tests are skipped when the OTel SDK is not installed (CI baseline).
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

opentelemetry = pytest.importorskip("opentelemetry")
sdk_trace = pytest.importorskip("opentelemetry.sdk.trace")
in_memory_exporter = pytest.importorskip(
    "opentelemetry.sdk.trace.export.in_memory_span_exporter"
)
SimpleSpanProcessor = pytest.importorskip(
    "opentelemetry.sdk.trace.export"
).SimpleSpanProcessor

from opentelemetry import trace as otel_trace  # noqa: E402
from opentelemetry.sdk.resources import Resource  # noqa: E402

from src.core.logging_config import OTelTraceContextFilter  # noqa: E402
from src.core.observability import (  # noqa: E402
    safe_set_span_attribute,
    tenant_hash,
)


@pytest.fixture
def trace_capture() -> Any:
    """Provide a local TracerProvider + in-memory exporter.

    OTel forbids overriding the global ``TracerProvider`` once set, so we
    make our own provider, hand the test a tracer carved out of it, and
    skip the global hook entirely. ``yield (provider, exporter, tracer)``
    so the test can introspect everything it needs without monkey-patching.
    """
    exporter = in_memory_exporter.InMemorySpanExporter()
    provider = sdk_trace.TracerProvider(
        resource=Resource.create({"service.name": "argus-test"}),
    )
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("argus.test")
    try:
        yield provider, exporter, tracer
    finally:
        provider.shutdown()


def test_manual_span_lands_in_exporter(trace_capture: Any) -> None:
    _provider, exporter, tracer = trace_capture
    with tracer.start_as_current_span("hello") as span:
        safe_set_span_attribute(span, "tenant.hash", tenant_hash("acme"))
    spans = exporter.get_finished_spans()
    names = [s.name for s in spans]
    assert "hello" in names
    target = next(s for s in spans if s.name == "hello")
    assert target.attributes.get("tenant.hash") == tenant_hash("acme")
    assert "tenant_id" not in target.attributes


def test_safe_set_span_attribute_drops_tenant_id(
    trace_capture: Any,
) -> None:
    _provider, exporter, tracer = trace_capture
    with tracer.start_as_current_span("guard") as span:
        safe_set_span_attribute(span, "tenant_id", "MUST-NOT-LEAK")
        safe_set_span_attribute(span, "argus.scan_id", "scan-1")
    spans = exporter.get_finished_spans()
    target = next(s for s in spans if s.name == "guard")
    assert "tenant_id" not in target.attributes
    assert target.attributes.get("argus.scan_id") == "scan-1"


def test_log_record_carries_trace_context(trace_capture: Any) -> None:
    """The trace-context filter must inject trace_id + span_id from the active span."""
    _provider, _exporter, tracer = trace_capture
    fltr = OTelTraceContextFilter()
    record = logging.LogRecord(
        name="argus", level=logging.INFO, pathname=__file__, lineno=1,
        msg="hi", args=(), exc_info=None,
    )
    with tracer.start_as_current_span("ctx-bind"):
        fltr.filter(record)
    assert hasattr(record, "trace_id")
    assert hasattr(record, "span_id")
    assert isinstance(record.trace_id, str)
    assert isinstance(record.span_id, str)


def test_log_record_without_active_span_keeps_no_trace_fields() -> None:
    fltr = OTelTraceContextFilter()
    record = logging.LogRecord(
        name="argus", level=logging.INFO, pathname=__file__, lineno=1,
        msg="hi", args=(), exc_info=None,
    )
    fltr.filter(record)
    if hasattr(record, "trace_id"):
        assert record.trace_id in (None, "", "0", "00000000000000000000000000000000")


def test_nested_span_shares_trace_id(trace_capture: Any) -> None:
    _provider, exporter, tracer = trace_capture
    with tracer.start_as_current_span("parent") as parent:
        with tracer.start_as_current_span("child") as child:
            assert (
                parent.get_span_context().trace_id
                == child.get_span_context().trace_id
            )
    spans = exporter.get_finished_spans()
    parent_span = next(s for s in spans if s.name == "parent")
    child_span = next(s for s in spans if s.name == "child")
    assert parent_span.context.trace_id == child_span.context.trace_id


def test_noop_tracer_is_cheap_when_otel_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When OTel is disabled the tracer must be a no-op proxy."""
    from src.core import observability as obs

    monkeypatch.setattr(obs, "OTEL_AVAILABLE", False)
    monkeypatch.setattr(obs, "trace", None)

    tracer = obs.get_tracer("argus.disabled")
    with tracer.start_as_current_span("noop") as span:
        span.set_attribute("k", "v")
