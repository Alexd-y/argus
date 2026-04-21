"""Integration: ``GET /metrics`` Prometheus endpoint — ARG-041.

Spins up a minimal FastAPI app with the metrics router only — the
production ``main.py`` pulls heavy dependencies (DB session factory, Redis
client, Celery app) that we do not need for exercising the exposition
contract. The point of this suite is to verify the Prometheus text format
contract, not the wider integration.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from prometheus_client import CollectorRegistry

from src.api.routers import metrics as metrics_router
from src.core.observability import (
    METRIC_CATALOGUE,
    record_celery_task,
    record_finding_emitted,
    record_http_request,
    record_llm_tokens,
    record_mcp_call,
    record_sandbox_run,
    reset_metrics_registry,
)


@pytest.fixture(autouse=True)
def _isolated_registry() -> CollectorRegistry:
    reg = CollectorRegistry()
    reset_metrics_registry(registry=reg)
    return reg


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(metrics_router.router)
    return TestClient(app)


def _emit_one_of_each() -> None:
    record_http_request(
        method="GET",
        route="/api/v1/scans",
        status_code=200,
        duration_seconds=0.05,
        tenant_id="tenant-test",
    )
    record_celery_task(
        task_name="test.task", status="success", duration_seconds=0.1
    )
    record_celery_task(
        task_name="test.task",
        status="failure",
        duration_seconds=0.2,
        error_class="ValueError",
    )
    record_sandbox_run(
        tool_id="nmap",
        status="success",
        profile="kubernetes",
        duration_seconds=2.5,
    )
    record_finding_emitted(tier="midgard", severity="high", kev_listed=True)
    record_llm_tokens(
        provider="openai", model="gpt-4o", direction="in", tokens=42
    )
    record_mcp_call(tool="scan.start", status="success", client_class="anthropic")


def test_metrics_endpoint_returns_prometheus_text_format(
    client: TestClient,
) -> None:
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    body = resp.text
    assert "# HELP" in body
    assert "# TYPE" in body


def test_all_nine_metric_families_appear_in_exposition(
    client: TestClient,
) -> None:
    _emit_one_of_each()
    body = client.get("/metrics").text
    for spec in METRIC_CATALOGUE:
        assert spec.name in body, f"metric not exposed: {spec.name}"


def test_http_counter_increments_after_request(client: TestClient) -> None:
    record_http_request(
        method="POST",
        route="/api/v1/scans",
        status_code=201,
        duration_seconds=0.01,
        tenant_id="t-A",
    )
    body = client.get("/metrics").text
    assert "argus_http_requests_total" in body
    line = next(
        ln
        for ln in body.splitlines()
        if ln.startswith("argus_http_requests_total{")
        and 'method="POST"' in ln
    )
    assert "1.0" in line


def test_findings_counter_kev_label_renders(client: TestClient) -> None:
    record_finding_emitted(tier="midgard", severity="critical", kev_listed=True)
    body = client.get("/metrics").text
    assert 'kev_listed="true"' in body


def test_sandbox_histogram_buckets_are_present(client: TestClient) -> None:
    record_sandbox_run(
        tool_id="nuclei", status="success", profile="kubernetes", duration_seconds=12
    )
    body = client.get("/metrics").text
    assert "argus_sandbox_run_duration_seconds_bucket" in body


def test_endpoint_is_idempotent(client: TestClient) -> None:
    first = client.get("/metrics").text
    second = client.get("/metrics").text
    assert first.splitlines()[:5] == second.splitlines()[:5]


def test_exposition_does_not_leak_raw_tenant_id(client: TestClient) -> None:
    record_http_request(
        method="GET",
        route="/api/v1/scans/{scan_id}",
        status_code=200,
        duration_seconds=0.01,
        tenant_id="acme-co-secret-id",
    )
    body = client.get("/metrics").text
    assert "acme-co-secret-id" not in body


def test_llm_tokens_value_records_actual_count(client: TestClient) -> None:
    record_llm_tokens(provider="openai", model="gpt-4o", direction="in", tokens=999)
    body = client.get("/metrics").text
    assert "argus_llm_tokens_total" in body
    line = next(
        ln
        for ln in body.splitlines()
        if ln.startswith("argus_llm_tokens_total{")
        and 'direction="in"' in ln
    )
    # Counter values are floats; substring check is sufficient.
    assert "999" in line
