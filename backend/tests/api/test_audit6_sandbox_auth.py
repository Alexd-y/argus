"""Audit6 C-2: /sandbox/* requires authentication."""

import pytest
from starlette.testclient import TestClient


@pytest.mark.no_auth_override
def test_sandbox_execute_requires_auth(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/sandbox/execute",
        json={"command": "nmap --version"},
    )
    assert resp.status_code == 401


@pytest.mark.no_auth_override
def test_sandbox_processes_list_requires_auth(client: TestClient) -> None:
    resp = client.get("/api/v1/sandbox/processes")
    assert resp.status_code == 401


@pytest.mark.no_auth_override
def test_sandbox_kill_process_requires_auth(client: TestClient) -> None:
    resp = client.post("/api/v1/sandbox/processes/1/kill")
    assert resp.status_code == 401


@pytest.mark.no_auth_override
def test_sandbox_python_requires_auth(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/sandbox/python",
        json={"code": "1 + 1"},
    )
    assert resp.status_code == 401
