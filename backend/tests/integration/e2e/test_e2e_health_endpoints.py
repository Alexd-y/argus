"""ARG-047 — Health-endpoint contract tests against the live e2e stack.

Six independent cases cover the four observability endpoints surfaced by the
backend (``/health``, ``/ready``, ``/providers/health``, ``/queues/health``)
plus the unauthenticated ``/metrics`` endpoint and the API-prefixed alias
under ``/api/v1/health``.

Conventions
-----------
* Tests opt INTO the e2e lane via ``@pytest.mark.requires_docker_e2e``;
  the auto-classifier in ``backend/tests/conftest.py`` also marks them
  ``requires_postgres`` + ``requires_redis`` (regex match on ``localhost``)
  so a default ``pytest -q`` skips them automatically.
* The base URL is read from the ``E2E_BACKEND_URL`` env var so the same
  test file works against ``http://localhost:8000`` (host shell) and
  ``http://argus-backend:8000`` (in-network).
* HTTP errors are surfaced via ``assert response.status_code == ...`` —
  no stack traces leak into pytest output (Backlog/dev1_md security rule
  against information disclosure to operators).
"""

from __future__ import annotations

import os

import pytest
import urllib.request
import urllib.error
import json
from typing import Any

pytestmark = pytest.mark.requires_docker_e2e

BASE_URL: str = os.environ.get("E2E_BACKEND_URL", "http://localhost:8000")
TIMEOUT_SECONDS: float = 10.0


def _http_get(path: str, *, headers: dict[str, str] | None = None) -> tuple[int, dict[str, Any] | str]:
    """Minimal GET wrapper — returns (status_code, decoded_body).

    Uses stdlib so the test suite has zero new third-party deps. Body is
    JSON-decoded on success; otherwise returned as raw text for diagnostics.
    """
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        headers=headers or {"Accept": "application/json", "User-Agent": "argus-e2e-tests/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:  # noqa: S310
            body_bytes = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:
        body_bytes = exc.read() if exc.fp else b""
        status = exc.code
    try:
        return status, json.loads(body_bytes.decode("utf-8")) if body_bytes else {}
    except json.JSONDecodeError:
        return status, body_bytes.decode("utf-8", errors="replace")


def test_health_endpoint_returns_ok() -> None:
    """``GET /health`` — liveness probe MUST succeed without DB/Redis dependency."""
    status, body = _http_get("/health")
    assert status == 200, f"unexpected status {status}: {body}"
    assert isinstance(body, dict)
    assert body.get("status") == "ok"
    assert "version" in body


def test_health_endpoint_versioned_alias() -> None:
    """``GET /api/v1/health`` — versioned alias MUST mirror the root endpoint."""
    status, body = _http_get("/api/v1/health")
    assert status == 200, f"unexpected status {status}: {body}"
    assert isinstance(body, dict)
    assert body.get("status") == "ok"


def test_ready_endpoint_passes_against_live_stack() -> None:
    """``GET /ready`` — readiness MUST be 200 on a healthy compose stack.

    The body returns per-probe detail; we assert each known probe is ``ok``
    so a single failed dependency surfaces in the test output instead of
    being hidden behind a 200 with internal degradation.
    """
    status, body = _http_get("/ready")
    assert status == 200, f"readiness failed: status={status} body={body}"
    assert isinstance(body, dict)
    assert body.get("status") == "ok"
    for key in ("database", "redis", "storage", "llm_providers"):
        assert body.get(key) is True, f"probe {key!r} failed: {body}"


def test_providers_health_endpoint_returns_known_providers() -> None:
    """``GET /providers/health`` — MUST list the registered LLM providers."""
    status, body = _http_get("/providers/health")
    assert status == 200, f"unexpected status {status}: {body}"
    assert isinstance(body, dict)
    providers = body.get("providers", [])
    assert isinstance(providers, list)
    # The exact roster depends on env vars, but the response shape is fixed.
    for entry in providers:
        assert isinstance(entry, dict)
        assert "provider" in entry
        assert "state" in entry


def test_queues_health_endpoint_lists_celery_queues() -> None:
    """``GET /queues/health`` — Redis-backed; surfaces queue depth + worker count."""
    status, body = _http_get("/queues/health")
    # ``/queues/health`` returns 503 when Redis is down, 200 otherwise.
    assert status in (200, 503), f"unexpected status {status}: {body}"
    assert isinstance(body, dict)
    assert "queues" in body
    assert isinstance(body["queues"], list)
    if status == 200:
        assert body.get("redis_reachable") is True


def test_metrics_endpoint_serves_prometheus_text_format() -> None:
    """``GET /metrics`` — Prometheus exposition MUST mention canonical families."""
    status, body = _http_get("/metrics", headers={"Accept": "text/plain"})
    assert status == 200, f"metrics endpoint failed: {status}"
    text = body if isinstance(body, str) else json.dumps(body)
    # At minimum the HTTP-counter family MUST be present after any prior request.
    assert "argus_http_requests_total" in text, "argus_http_requests_total missing from /metrics"
