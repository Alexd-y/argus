"""ARG-041 — OpenTelemetry initialisation: SDK, exporters, instrumentation.

This module is intentionally thin: it owns the *single* lifecycle hook
(``setup_observability``) and a Celery-side mirror (``setup_celery_observability``).
Every business module reaches into the OTel context via the helpers in
:mod:`src.core.observability` (``get_tracer``, ``safe_set_span_attribute``);
this module never defines its own tracer or attribute conventions.

Discipline (mirrors metric module):

* When ``settings.otel_enabled`` is ``False`` the module installs a no-op
  tracer provider — *zero* runtime overhead for the common dev / CI path.
  The boolean is checked *once* at startup; flipping it at runtime is not
  supported.
* The OTLP gRPC exporter is the only supported transport; HTTP/protobuf is
  intentionally out of scope to keep the dependency surface small.
* Resource attributes are lockstep with operational dashboards
  (``service.name``, ``service.version``, ``deployment.environment``).
* Instrumentors are wired one-by-one inside ``try/except`` so a missing
  optional binding (e.g. when redis-py is not installed in a non-broker
  build) never blocks startup.
* All FastAPI excluded URLs go through a single constant so the same list
  is shared between the instrumentor and the metrics middleware.

Public API:

* :func:`setup_observability(app)` — call from the FastAPI lifespan.
* :func:`setup_celery_observability(celery_app)` — call from the Celery
  app factory (:mod:`src.celery_app`).
* :func:`shutdown_observability()` — graceful flush on FastAPI shutdown.
* :data:`EXCLUDED_URLS` — comma-separated list of URLs that must NOT
  produce traces / spans (health probes are extremely noisy).
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Final

from src.core.config import settings

try:
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        BatchSpanProcessor,
        ConsoleSpanExporter,
    )
    from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased

    OTEL_SDK_AVAILABLE: bool = True
except ImportError:  # pragma: no cover — SDK is a hard dep
    OTEL_SDK_AVAILABLE = False
    trace = None  # type: ignore[assignment]
    Resource = None  # type: ignore[assignment,misc]
    TracerProvider = None  # type: ignore[assignment,misc]
    BatchSpanProcessor = None  # type: ignore[assignment,misc]
    ConsoleSpanExporter = None  # type: ignore[assignment,misc]
    ParentBased = None  # type: ignore[assignment,misc]
    TraceIdRatioBased = None  # type: ignore[assignment,misc]

try:
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

    OTLP_EXPORTER_AVAILABLE: bool = True
except ImportError:  # pragma: no cover — optional but typically available
    OTLP_EXPORTER_AVAILABLE = False
    OTLPSpanExporter = None  # type: ignore[assignment,misc]

_logger = logging.getLogger(__name__)

#: URLs the FastAPI instrumentor must NOT trace (high-frequency probes that
#: would otherwise dominate the trace budget).
EXCLUDED_URLS: Final[str] = "/health,/ready,/metrics,/providers/health,/queues/health"

_setup_lock = threading.Lock()
_setup_done = False
_provider: Any | None = None


# ---------------------------------------------------------------------------
# Resource + provider construction (pure, no side-effects)
# ---------------------------------------------------------------------------


def _build_resource() -> Any:
    """Compose the OTel ``Resource`` describing this process.

    The three required attributes (``service.name``, ``service.version``,
    ``deployment.environment``) match the canonical naming used by the
    Grafana dashboards in ``infra/observability/``. ``service.instance.id``
    is also added when an HOSTNAME / POD_NAME env var is available — not
    strictly required but helps differentiate replicas in Tempo.
    """
    if not OTEL_SDK_AVAILABLE or Resource is None:
        return None
    import os

    attrs: dict[str, str] = {
        "service.name": settings.otel_service_name,
        "service.version": settings.version,
        "deployment.environment": settings.otel_environment,
    }
    instance = os.environ.get("HOSTNAME") or os.environ.get("POD_NAME")
    if instance:
        attrs["service.instance.id"] = instance
    return Resource.create(attrs)


def _build_sampler() -> Any:
    """Build a parent-based ratio sampler.

    Parent-based sampling keeps trace tree integrity (a child span follows
    the parent's decision) while letting us scale total volume via
    ``OTEL_SAMPLER_RATIO``. Defaults to 1.0 (100 %) so dev/local does not
    silently drop spans.
    """
    if not OTEL_SDK_AVAILABLE or ParentBased is None or TraceIdRatioBased is None:
        return None
    return ParentBased(root=TraceIdRatioBased(settings.otel_sampler_ratio))


def _build_exporter() -> Any:
    """Build the OTLP gRPC exporter (or fall back to console for dev sanity).

    When the OTLP wheel is unavailable, the module logs a warning and
    falls back to the console exporter — that keeps the codepath alive in
    minimal CI builds while making the missing dep highly visible.
    """
    if OTLP_EXPORTER_AVAILABLE and OTLPSpanExporter is not None:
        try:
            return OTLPSpanExporter(
                endpoint=settings.otel_otlp_endpoint,
                insecure=settings.otel_insecure,
            )
        except Exception:  # pragma: no cover — defensive
            _logger.exception("otel.exporter.otlp_init_failed")
    if ConsoleSpanExporter is not None:
        _logger.warning(
            "otel.exporter.fallback_to_console",
            extra={"reason": "OTLP unavailable or init failed"},
        )
        return ConsoleSpanExporter()
    return None


def _install_provider() -> Any | None:
    """Install a real :class:`TracerProvider` and return it (or ``None``).

    The provider is installed at most once per process; subsequent calls
    are idempotent (the global tracer reference is reused). Returns the
    installed provider so test code can interrogate processors directly.
    """
    if not OTEL_SDK_AVAILABLE or TracerProvider is None or trace is None:
        return None
    resource = _build_resource()
    sampler = _build_sampler()
    provider = TracerProvider(resource=resource, sampler=sampler)
    exporter = _build_exporter()
    if exporter is not None and BatchSpanProcessor is not None:
        provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    return provider


# ---------------------------------------------------------------------------
# Instrumentation wrappers
# ---------------------------------------------------------------------------


def _instrument_fastapi(app: Any) -> None:
    """Wrap the given FastAPI ``app`` with the OTel ASGI instrumentor."""
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app, excluded_urls=EXCLUDED_URLS)
        _logger.info("otel.instrument.fastapi_ok")
    except Exception:  # pragma: no cover — defensive
        _logger.exception("otel.instrument.fastapi_failed")


def _instrument_httpx() -> None:
    """Patch the ``httpx`` client (sync + async) for outbound LLM call traces."""
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

        HTTPXClientInstrumentor().instrument()
        _logger.info("otel.instrument.httpx_ok")
    except Exception:  # pragma: no cover — defensive
        _logger.exception("otel.instrument.httpx_failed")


def _instrument_redis() -> None:
    """Patch the ``redis-py`` driver for broker / lock trace propagation."""
    try:
        from opentelemetry.instrumentation.redis import RedisInstrumentor

        RedisInstrumentor().instrument()
        _logger.info("otel.instrument.redis_ok")
    except Exception:  # pragma: no cover — defensive
        _logger.exception("otel.instrument.redis_failed")


def _instrument_sqlalchemy() -> None:
    """Patch the SQLAlchemy engine for SQL trace propagation.

    We instrument *globally* (not against a specific engine) because the
    backend creates the engine lazily per-request in some code paths.
    The instrumentor handles late-bound engines automatically.
    """
    try:
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

        SQLAlchemyInstrumentor().instrument(enable_commenter=False)
        _logger.info("otel.instrument.sqlalchemy_ok")
    except Exception:  # pragma: no cover — defensive
        _logger.exception("otel.instrument.sqlalchemy_failed")


def _instrument_celery() -> None:
    """Patch Celery signals so produced + consumed messages share a trace.

    Called from both ``setup_observability`` (FastAPI side; ensures that
    tasks dispatched by HTTP handlers carry the parent trace) and
    ``setup_celery_observability`` (worker side; ensures executed tasks
    join the trace tree). Idempotent because ``CeleryInstrumentor`` ignores
    repeated calls.
    """
    try:
        from opentelemetry.instrumentation.celery import CeleryInstrumentor

        CeleryInstrumentor().instrument()
        _logger.info("otel.instrument.celery_ok")
    except Exception:  # pragma: no cover — defensive
        _logger.exception("otel.instrument.celery_failed")


# ---------------------------------------------------------------------------
# Public lifecycle entry-points
# ---------------------------------------------------------------------------


def setup_observability(app: Any) -> Any | None:
    """Initialise the OTel pipeline + instrument the FastAPI ``app``.

    Idempotent — repeated calls are no-ops. Returns the installed
    :class:`TracerProvider` (or ``None`` when OTel is disabled / unavailable)
    so test code can attach extra processors.
    """
    global _setup_done, _provider
    if not settings.otel_enabled:
        _logger.info("otel.setup.skipped", extra={"reason": "OTEL_ENABLED=false"})
        return None
    with _setup_lock:
        if _setup_done:
            return _provider
        _provider = _install_provider()
        _instrument_fastapi(app)
        _instrument_httpx()
        _instrument_redis()
        _instrument_sqlalchemy()
        _instrument_celery()
        _setup_done = True
    _logger.info(
        "otel.setup.completed",
        extra={
            "endpoint": settings.otel_otlp_endpoint,
            "service": settings.otel_service_name,
            "environment": settings.otel_environment,
            "sampler_ratio": settings.otel_sampler_ratio,
        },
    )
    return _provider


def setup_celery_observability(celery_app: Any) -> None:  # noqa: ARG001
    """Worker-side OTel init.

    The ``celery_app`` argument is accepted for symmetry with the FastAPI
    side but the Celery instrumentor patches the global ``celery.task.Task``
    hierarchy, so the explicit handle is unused. Installing the provider
    inside the worker process is required because workers run in separate
    interpreter processes from the API.
    """
    global _setup_done, _provider
    if not settings.otel_enabled:
        return
    with _setup_lock:
        if _setup_done:
            return
        _provider = _install_provider()
        _instrument_httpx()
        _instrument_redis()
        _instrument_sqlalchemy()
        _instrument_celery()
        _setup_done = True
    _logger.info("otel.setup.celery_completed")


def shutdown_observability() -> None:
    """Flush + shut down the OTel pipeline gracefully on app shutdown.

    Called from the FastAPI lifespan teardown so the BatchSpanProcessor
    flushes pending spans before the process exits. Errors are swallowed
    because shutdown must never re-raise.
    """
    global _setup_done, _provider
    if _provider is None:
        return
    try:
        _provider.shutdown()
    except Exception:  # pragma: no cover — defensive
        _logger.exception("otel.shutdown.failed")
    finally:
        _provider = None
        _setup_done = False


def is_initialized() -> bool:
    """Return ``True`` once :func:`setup_observability` has installed a provider."""
    return _setup_done


__all__ = [
    "EXCLUDED_URLS",
    "OTEL_SDK_AVAILABLE",
    "OTLP_EXPORTER_AVAILABLE",
    "is_initialized",
    "setup_celery_observability",
    "setup_observability",
    "shutdown_observability",
]
