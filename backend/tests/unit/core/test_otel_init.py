"""Unit tests for ``src.core.otel_init`` — ARG-041.

The module is mostly side-effect plumbing: it registers a TracerProvider,
attaches an exporter, and patches third-party clients. Tests therefore
focus on:

* Boolean toggle — when ``OTEL_ENABLED=false`` setup is a true no-op.
* Idempotency — calling setup twice does not produce a second provider.
* Resource attributes match the operational dashboard contract
  (service.name / service.version / deployment.environment).
* Excluded URLs include all health/probe endpoints (FastAPI instrumentor
  must not flood Tempo with /health spans).
* ``safe_set_span_attribute`` blocks raw ``tenant_id``.
"""

from __future__ import annotations

import importlib
from typing import Any

import pytest

from src.core import otel_init
from src.core.observability import safe_set_span_attribute


@pytest.fixture(autouse=True)
def _reset_otel_state() -> None:
    """Wipe module-level state so each test starts from a clean slate."""
    otel_init._setup_done = False
    otel_init._provider = None
    yield
    otel_init.shutdown_observability()
    otel_init._setup_done = False
    otel_init._provider = None


@pytest.fixture
def fake_app() -> Any:
    """A bare object with the attributes the instrumentor reads."""

    class _App:
        user_middleware: list = []
        middleware_stack = None

        def add_middleware(self, *_a: Any, **_k: Any) -> None:  # pragma: no cover
            return None

    return _App()


def test_excluded_urls_includes_all_health_probes() -> None:
    excluded = otel_init.EXCLUDED_URLS.split(",")
    for endpoint in (
        "/health",
        "/ready",
        "/metrics",
        "/providers/health",
        "/queues/health",
    ):
        assert endpoint in excluded


def test_setup_skipped_when_disabled(
    monkeypatch: pytest.MonkeyPatch, fake_app: Any
) -> None:
    monkeypatch.setattr(otel_init.settings, "otel_enabled", False)
    result = otel_init.setup_observability(fake_app)
    assert result is None
    assert otel_init.is_initialized() is False


@pytest.mark.skipif(
    not otel_init.OTEL_SDK_AVAILABLE,
    reason="OTel SDK not installed",
)
def test_setup_installs_provider_when_enabled(
    monkeypatch: pytest.MonkeyPatch, fake_app: Any
) -> None:
    monkeypatch.setattr(otel_init.settings, "otel_enabled", True)
    monkeypatch.setattr(otel_init.settings, "otel_otlp_endpoint", "http://localhost:4317")
    monkeypatch.setattr(otel_init.settings, "otel_insecure", True)

    provider = otel_init.setup_observability(fake_app)
    assert provider is not None
    assert otel_init.is_initialized() is True


@pytest.mark.skipif(
    not otel_init.OTEL_SDK_AVAILABLE,
    reason="OTel SDK not installed",
)
def test_setup_is_idempotent(
    monkeypatch: pytest.MonkeyPatch, fake_app: Any
) -> None:
    monkeypatch.setattr(otel_init.settings, "otel_enabled", True)
    first = otel_init.setup_observability(fake_app)
    second = otel_init.setup_observability(fake_app)
    assert first is second


@pytest.mark.skipif(
    not otel_init.OTEL_SDK_AVAILABLE,
    reason="OTel SDK not installed",
)
def test_resource_carries_service_attributes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(otel_init.settings, "otel_service_name", "argus")
    monkeypatch.setattr(otel_init.settings, "otel_environment", "test")
    monkeypatch.setattr(otel_init.settings, "version", "1.2.3")

    resource = otel_init._build_resource()
    assert resource is not None
    attrs = dict(resource.attributes)
    assert attrs["service.name"] == "argus"
    assert attrs["service.version"] == "1.2.3"
    assert attrs["deployment.environment"] == "test"


def test_safe_set_span_attribute_blocks_raw_tenant_id() -> None:
    """The helper must reject ``tenant_id`` to keep raw IDs out of traces."""

    captured: dict[str, object] = {}

    class _SpyVerifySpan:
        def set_attribute(self, key: str, value: object) -> None:
            captured[key] = value

    span = _SpyVerifySpan()
    safe_set_span_attribute(span, "tenant_id", "should-be-rejected")
    assert "tenant_id" not in captured


def test_safe_set_span_attribute_allows_tenant_hash() -> None:
    captured: dict[str, object] = {}

    class _SpyVerifySpan:
        def set_attribute(self, key: str, value: object) -> None:
            captured[key] = value

    span = _SpyVerifySpan()
    safe_set_span_attribute(span, "tenant.hash", "abcdef0123456789")
    assert captured["tenant.hash"] == "abcdef0123456789"


def test_get_tracer_returns_noop_when_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``get_tracer`` must return a context-manager-shaped no-op when OTel is off."""
    from src.core import observability as obs

    monkeypatch.setattr(obs, "OTEL_AVAILABLE", False)
    monkeypatch.setattr(obs, "trace", None)

    tracer = obs.get_tracer("argus.test")
    with tracer.start_as_current_span("noop") as span:
        # Setting attributes must be a no-op (no AttributeError, no exception).
        span.set_attribute("k", "v")


def test_module_can_be_reloaded_without_state_corruption() -> None:
    """Defensive — re-importing the module must not blow up the singleton."""
    importlib.reload(otel_init)
    assert otel_init.is_initialized() is False
