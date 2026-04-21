"""Unit tests for the ``GET /providers/health`` router — ARG-041.

We stand up a minimal FastAPI app around the router so the registry can be
populated deterministically (the production app drags Postgres + Redis +
auth dependencies that are out of scope for this unit suite).

Status semantics under test:

* All providers green → ``status="ok"`` (HTTP 200).
* Any provider in ``open`` state → ``status="degraded"`` (HTTP 200, never 503).
* Provider with > 50 % 5xx in last 60 s → ``status="degraded"``.
* Response shape always lists every ``KNOWN_PROVIDERS`` entry, even on cold start.
* Closed-taxonomy state values (no free-form strings).
"""

from __future__ import annotations

import time
from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.routers.providers_health import router
from src.api.schemas import ProviderHealth
from src.core.provider_health_registry import (
    KNOWN_PROVIDERS,
    ProviderHealthRegistry,
    get_provider_health_registry,
    reset_provider_health_registry,
)


@pytest.fixture
def isolated_registry() -> Iterator[ProviderHealthRegistry]:
    """Each test runs against a fresh registry."""
    reset_provider_health_registry()
    yield get_provider_health_registry()
    reset_provider_health_registry()


@pytest.fixture
def app(isolated_registry: ProviderHealthRegistry) -> FastAPI:  # noqa: ARG001
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def test_cold_start_returns_ok_with_all_known_providers(
    client: TestClient, isolated_registry: ProviderHealthRegistry  # noqa: ARG001
) -> None:
    resp = client.get("/providers/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    names = {p["provider"] for p in body["providers"]}
    for known in KNOWN_PROVIDERS:
        assert known in names


def test_response_state_values_are_closed_taxonomy(
    client: TestClient, isolated_registry: ProviderHealthRegistry  # noqa: ARG001
) -> None:
    allowed = {"closed", "open", "half_open", "unknown"}
    body = client.get("/providers/health").json()
    for p in body["providers"]:
        assert p["state"] in allowed


def test_open_circuit_marks_response_degraded(
    client: TestClient, isolated_registry: ProviderHealthRegistry
) -> None:
    isolated_registry.set_state("openai", "open")
    body = client.get("/providers/health").json()
    assert body["status"] == "degraded"
    openai_entry = next(p for p in body["providers"] if p["provider"] == "openai")
    assert openai_entry["state"] == "open"


def test_high_5xx_rate_marks_response_degraded(
    client: TestClient, isolated_registry: ProviderHealthRegistry
) -> None:
    for _ in range(8):
        isolated_registry.record_call("anthropic", status_code=500)
    for _ in range(2):
        isolated_registry.record_call("anthropic", status_code=200)
    body = client.get("/providers/health").json()
    assert body["status"] == "degraded"


def test_low_5xx_rate_does_not_mark_degraded(
    client: TestClient, isolated_registry: ProviderHealthRegistry
) -> None:
    isolated_registry.record_call("openai", status_code=500)
    for _ in range(20):
        isolated_registry.record_call("openai", status_code=200)
    body = client.get("/providers/health").json()
    assert body["status"] == "ok"


def test_last_success_ts_advances_on_success(
    client: TestClient, isolated_registry: ProviderHealthRegistry
) -> None:
    before = time.time()
    isolated_registry.record_call("openai", status_code=200)
    body = client.get("/providers/health").json()
    openai_entry = next(p for p in body["providers"] if p["provider"] == "openai")
    assert openai_entry["last_success_ts"] is not None
    assert openai_entry["last_success_ts"] >= before - 1


def test_request_and_error_counts_present(
    client: TestClient, isolated_registry: ProviderHealthRegistry
) -> None:
    isolated_registry.record_call("openai", status_code=200)
    isolated_registry.record_call("openai", status_code=500)
    body = client.get("/providers/health").json()
    openai_entry = next(p for p in body["providers"] if p["provider"] == "openai")
    assert openai_entry["request_count_60s"] == 2
    assert openai_entry["error_count_60s"] == 1


def test_unknown_provider_does_not_appear_in_response(
    client: TestClient, isolated_registry: ProviderHealthRegistry
) -> None:
    isolated_registry.record_call("evil-llm-3000", status_code=200)
    body = client.get("/providers/health").json()
    names = {p["provider"] for p in body["providers"]}
    assert "evil-llm-3000" not in names


def test_response_validates_against_pydantic_schema(
    client: TestClient, isolated_registry: ProviderHealthRegistry  # noqa: ARG001
) -> None:
    body = client.get("/providers/health").json()
    for p in body["providers"]:
        ProviderHealth.model_validate(p)


def test_endpoint_never_returns_503(
    client: TestClient, isolated_registry: ProviderHealthRegistry
) -> None:
    """All providers DOWN must still return 200 — operators read this dashboard."""
    for known in KNOWN_PROVIDERS:
        isolated_registry.set_state(known, "open")
    resp = client.get("/providers/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "degraded"


def test_response_shape_has_no_extra_fields(
    client: TestClient, isolated_registry: ProviderHealthRegistry  # noqa: ARG001
) -> None:
    body = client.get("/providers/health").json()
    expected_keys = {"status", "providers"}
    assert set(body.keys()) == expected_keys
    expected_provider_keys = {
        "provider",
        "state",
        "last_success_ts",
        "error_rate_5xx",
        "error_count_60s",
        "request_count_60s",
    }
    for p in body["providers"]:
        assert set(p.keys()) == expected_provider_keys


def test_repeated_calls_are_idempotent(
    client: TestClient, isolated_registry: ProviderHealthRegistry  # noqa: ARG001
) -> None:
    first = client.get("/providers/health").json()
    second = client.get("/providers/health").json()
    assert first == second
