"""Audit6 C-3: recon routers require authentication."""

import pytest
from starlette.testclient import TestClient


@pytest.mark.no_auth_override
def test_recon_engagements_list_requires_auth(client: TestClient) -> None:
    resp = client.get("/api/v1/recon/engagements")
    assert resp.status_code == 401


@pytest.mark.no_auth_override
def test_recon_targets_get_requires_auth(client: TestClient) -> None:
    resp = client.get("/api/v1/recon/targets/nonexistent-target-id")
    assert resp.status_code == 401


@pytest.mark.no_auth_override
def test_recon_jobs_get_requires_auth(client: TestClient) -> None:
    resp = client.get("/api/v1/recon/jobs/nonexistent-job-id")
    assert resp.status_code == 401
