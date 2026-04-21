"""Audit6 C-1: /tools/* requires authentication."""

import pytest
from starlette.testclient import TestClient


@pytest.mark.no_auth_override
def test_tools_nmap_requires_auth(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/tools/nmap",
        json={"target": "127.0.0.1"},
    )
    assert resp.status_code == 401


@pytest.mark.no_auth_override
def test_tools_nuclei_requires_auth(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/tools/nuclei",
        json={"target": "https://example.com"},
    )
    assert resp.status_code == 401


@pytest.mark.no_auth_override
def test_tools_execute_requires_auth(client: TestClient) -> None:
    resp = client.post(
        "/api/v1/tools/execute",
        json={"command": "nmap --version", "use_cache": False},
    )
    assert resp.status_code == 401
