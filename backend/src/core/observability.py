"""Observability — Prometheus metrics, optional OpenTelemetry spans."""

from collections.abc import Generator
from contextlib import contextmanager

# Prometheus metrics
try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    generate_latest = None
    CONTENT_TYPE_LATEST = None

# OpenTelemetry (optional)
try:
    from opentelemetry import trace
    from opentelemetry.trace import Tracer
    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    trace = None
    Tracer = None


def _counter(name: str, doc: str, labels: tuple[str, ...] = ()):
    """Create Counter if Prometheus available."""
    if PROMETHEUS_AVAILABLE:
        return Counter(name, doc, labelnames=labels)
    return None


def _histogram(name: str, doc: str, labels: tuple[str, ...] = ()):
    """Create Histogram if Prometheus available."""
    if PROMETHEUS_AVAILABLE:
        return Histogram(name, doc, labelnames=labels, buckets=(1.0, 5.0, 10.0, 30.0, 60.0, 120.0))
    return None


# Metrics
SCAN_COUNT = _counter("argus_scans_total", "Total number of scans started")
PHASE_DURATION = _histogram("argus_phase_duration_seconds", "Duration of scan phases", ("phase",))
TOOL_RUN_COUNT = _counter("argus_tool_runs_total", "Total tool executions", ("tool",))


def record_scan_started() -> None:
    """Increment scan count."""
    if SCAN_COUNT:
        SCAN_COUNT.inc()


def record_phase_duration(phase: str, duration_seconds: float) -> None:
    """Record phase duration."""
    if PHASE_DURATION:
        PHASE_DURATION.labels(phase=phase).observe(duration_seconds)


def record_tool_run(tool: str) -> None:
    """Increment tool run count."""
    if TOOL_RUN_COUNT:
        TOOL_RUN_COUNT.labels(tool=tool).inc()


def get_metrics_content() -> tuple[bytes, str]:
    """Return Prometheus metrics body and content-type."""
    if PROMETHEUS_AVAILABLE:
        return generate_latest(), CONTENT_TYPE_LATEST
    return b"# Prometheus client not installed\n", "text/plain; charset=utf-8"


@contextmanager
def trace_phase(scan_id: str, phase: str) -> Generator[None, None, None]:
    """Optional OpenTelemetry span for scan phase."""
    if not OTEL_AVAILABLE or trace is None:
        yield
        return
    tracer: Tracer = trace.get_tracer("argus", "0.1.0")
    with tracer.start_as_current_span(
        f"scan.phase.{phase}",
        attributes={"argus.scan_id": scan_id, "argus.phase": phase},
    ):
        yield
