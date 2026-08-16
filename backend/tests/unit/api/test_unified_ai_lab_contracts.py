"""§16 remaining APIs + LAB lease gates + coverage/diff wiring."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from src.api.routers import execution_mode as em_api
from src.api.routers import unified_ai_lab as lab_api
from src.execution_mode.repository import get_execution_mode_repository
from src.findings.lifecycle import FindingOccurrence
from src.findings.repository import get_findings_repository
from src.oast.scan_traces import get_oast_provisioner
from src.orchestration.coverage_phase_sink import (
    ToolRunSignal,
    attach_phase_coverage,
    get_coverage_store,
)

_OPENAPI = """
openapi: 3.0.0
info:
  title: Lab API
  version: "1.0.0"
servers:
  - url: https://app.lab.argus
paths:
  /login:
    post:
      operationId: login
      parameters:
        - name: user
          in: query
          schema:
            type: string
      responses:
        "200":
          description: ok
"""


def _app() -> FastAPI:
    app = FastAPI()
    app.include_router(em_api.router, prefix="/api/v1")
    app.include_router(lab_api.nuclei_router, prefix="/api/v1")
    app.include_router(lab_api.lab_router, prefix="/api/v1")
    app.include_router(lab_api.findings_ext_router, prefix="/api/v1")
    app.include_router(lab_api.coverage_router, prefix="/api/v1")
    app.include_router(lab_api.api_surface_router, prefix="/api/v1")
    app.include_router(lab_api.rag_trace_router, prefix="/api/v1")
    app.include_router(lab_api.oast_trace_router, prefix="/api/v1")
    return app


def _client() -> TestClient:
    em_api._reset_stores_for_tests()
    lab_api._reset_stores_for_tests()
    get_coverage_store().clear()
    return TestClient(_app())


def _issue_lease(client: TestClient) -> str:
    headers = {"X-Tenant-Id": "t-1", "X-User-Id": "u-1"}
    client.post(
        "/api/v1/engagements/e-1/execution-mode",
        headers=headers,
        json={"mode": "lab_unrestricted"},
    )
    client.post(
        "/api/v1/engagements/e-1/lab-scope",
        headers=headers,
        json={
            "cidrs": ["10.90.0.0/16"],
            "dns_suffixes": ["lab.argus"],
            "k8s_namespace": "argus-lab-42",
            "vm_network_ids": ["labnet-42"],
            "capture_full": True,
        },
    )
    r = client.post(
        "/api/v1/engagements/e-1/lab-lease",
        headers=headers,
        json={
            "target": "https://app.lab.argus/login",
            "k8s_namespace": "argus-lab-42",
            "vm_network_id": "labnet-42",
        },
    )
    assert r.status_code == 201, r.text
    return r.json()["lease_id"]


def test_lab_script_requires_usable_lease() -> None:
    client = _client()
    r = client.post(
        "/api/v1/lab/scripts",
        json={"language": "python", "source": "print(1)", "lease_id": "missing"},
    )
    assert r.status_code == 403


def test_lab_script_and_artifact_execute_with_lease() -> None:
    client = _client()
    lease_id = _issue_lease(client)
    created = client.post(
        "/api/v1/lab/scripts",
        headers={"X-Tenant-Id": "t-1"},
        json={"language": "python", "source": "print(1)", "lease_id": lease_id},
    )
    assert created.status_code == 201
    assert created.json()["requires_approval"] is False
    script_id = created.json()["script_id"]
    executed = client.post(f"/api/v1/lab/scripts/{script_id}/execute")
    assert executed.status_code == 200
    assert executed.json()["requires_approval"] is False
    assert executed.json()["status"] == "completed"
    assert "1" in executed.json()["stdout"]
    artifact = client.post(
        "/api/v1/lab/artifacts/art-1/execute",
        json={"lease_id": lease_id, "argv": ["python3", "-c", "print(2)"]},
    )
    assert artifact.status_code == 200
    assert artifact.json()["requires_approval"] is False
    assert artifact.json()["status"] == "completed"
    assert "2" in artifact.json()["stdout"]
    exec_id = artifact.json()["execution_id"]
    got = client.get(f"/api/v1/lab/executions/{exec_id}")
    assert got.status_code == 200


def test_lab_nuclei_artifact_execute_uses_compiler() -> None:
    client = _client()
    lease_id = _issue_lease(client)
    ingested = client.post(
        "/api/v1/nuclei/templates/ingest",
        json={
            "content": "id: t-lab\ninfo:\n  name: demo\n",
            "template_id": "t-lab",
            "source": "internal",
            "mode": "lab_unrestricted",
        },
    )
    assert ingested.status_code == 201
    artifact_id = ingested.json()["artifact_id"]
    executed = client.post(
        f"/api/v1/lab/artifacts/{artifact_id}/execute",
        json={"lease_id": lease_id, "argv": ["https://example.com/"]},
    )
    assert executed.status_code == 200
    argv = executed.json()["argv"]
    assert argv[0] == "nuclei"
    assert "-code" in argv
    assert "-headless" in argv
    assert "-enable-javascript" in argv
    assert "-ni" not in argv
    assert executed.json()["requires_approval"] is False


def test_nuclei_validate_and_release_activate_rollback() -> None:
    client = _client()
    ingested = client.post(
        "/api/v1/nuclei/templates/ingest",
        json={
            "content": "id: t1\ninfo:\n  name: demo\n",
            "template_id": "t1",
            "source": "internal",
            "mode": "production",
        },
    )
    assert ingested.status_code == 201
    validated = client.post("/api/v1/nuclei/templates/t1/validate?mode=production")
    assert validated.status_code == 200
    assert validated.json()["template_id"] == "t1"
    digest = "a" * 64
    registered = client.post(
        "/api/v1/nuclei/releases",
        json={"version": "2026.08.15", "digest_sha256": digest},
    )
    assert registered.status_code == 201
    release_id = registered.json()["release_id"]
    activated = client.post(f"/api/v1/nuclei/releases/{release_id}/activate")
    assert activated.status_code == 200
    assert activated.json()["status"] == "active"
    rolled = client.post(f"/api/v1/nuclei/releases/{release_id}/rollback")
    assert rolled.status_code == 200
    assert rolled.json()["status"] == "rolled_back"


def test_nuclei_releases_get_lists_active_id() -> None:
    client = _client()
    empty = client.get("/api/v1/nuclei/releases")
    assert empty.status_code == 200
    assert empty.json()["releases"] == []
    assert empty.json()["active_release_id"] is None
    digest = "b" * 64
    registered = client.post(
        "/api/v1/nuclei/releases",
        json={"version": "2026.08.16", "digest_sha256": digest},
    )
    assert registered.status_code == 201
    release_id = registered.json()["release_id"]
    listed = client.get("/api/v1/nuclei/releases")
    assert listed.status_code == 200
    assert listed.json()["active_release_id"] is None
    assert listed.json()["releases"][0]["release_id"] == release_id
    activated = client.post(f"/api/v1/nuclei/releases/{release_id}/activate")
    assert activated.status_code == 200
    listed = client.get("/api/v1/nuclei/releases")
    assert listed.json()["active_release_id"] == release_id
    assert listed.json()["releases"][0]["status"] == "active"


def test_scan_occurrences_requires_tenant() -> None:
    client = _client()
    missing = client.get("/api/v1/scans/scan-occ-1/occurrences")
    assert missing.status_code == 400
    assert missing.json()["detail"] == "tenant_required"


def test_scan_occurrences_lists_saved_rows() -> None:
    client = _client()
    repo = get_findings_repository()
    finding_key = "a" * 64
    occurrence_key = "b" * 64
    seen = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)

    async def _seed() -> None:
        await repo.save_occurrence(
            FindingOccurrence(
                occurrence_key=occurrence_key,
                finding_key=finding_key,
                tenant_id="t-1",
                scan_id="scan-occ-1",
                scanner="nuclei",
                detector_id="xss-reflected",
                detector_version="1.0.0",
                evidence_refs=("ev-1",),
                first_seen_at=seen,
                last_seen_at=seen,
            )
        )

    asyncio.run(_seed())
    listed = client.get(
        "/api/v1/scans/scan-occ-1/occurrences",
        headers={"X-Tenant-Id": "t-1"},
    )
    assert listed.status_code == 200
    body = listed.json()
    assert body["scan_id"] == "scan-occ-1"
    assert len(body["occurrences"]) == 1
    row = body["occurrences"][0]
    assert row["occurrence_key"] == occurrence_key
    assert row["finding_key"] == finding_key
    assert row["detector_id"] == "xss-reflected"
    other_tenant = client.get(
        "/api/v1/scans/scan-occ-1/occurrences",
        headers={"X-Tenant-Id": "t-2"},
    )
    assert other_tenant.status_code == 200
    assert other_tenant.json()["occurrences"] == []


def test_api_surface_ingest_and_asset_endpoints() -> None:
    client = _client()
    ingested = client.post(
        "/api/v1/api-surface/ingest",
        headers={"X-Tenant-Id": "t-1"},
        json={"asset_id": "asset-1", "document": _OPENAPI, "mode": "production"},
    )
    assert ingested.status_code == 201, ingested.text
    endpoints = client.get("/api/v1/assets/asset-1/endpoints")
    assert endpoints.status_code == 200
    assert endpoints.json()["endpoints"]


def test_coverage_get_reads_phase_sink() -> None:
    client = _client()
    attach_phase_coverage(
        phase="vuln_analysis",
        tenant_id="t-1",
        scan_id="scan-cov-1",
        asset_id="asset-1",
        signals=[
            ToolRunSignal(
                tool_id="nuclei",
                capability_id="web.application.api.rest",
                tool_executed=True,
            )
        ],
        scan_options={"execution_mode": "lab_unrestricted"},
    )
    r = client.get("/api/v1/scans/scan-cov-1/coverage")
    assert r.status_code == 200
    assert r.json()["results"]


def test_finding_diff_new_resolved_regressed() -> None:
    client = _client()
    key = "fk-sqli-login"
    headers = {"X-Tenant-Id": "t-1"}
    assessed = client.post(
        f"/api/v1/findings/{key}/assessments",
        headers=headers,
        json={
            "classification": "sqli",
            "observation": "error based",
            "scan_id": "scan-base",
        },
    )
    assert assessed.status_code == 200
    resolved = client.post(
        f"/api/v1/findings/{key}/retest?scan_id=scan-fix&outcome=not_reproduced",
        headers=headers,
    )
    assert resolved.status_code == 200
    assert resolved.json()["finding"]["state"] == "resolved"
    regressed = client.post(
        f"/api/v1/findings/{key}/retest?scan_id=scan-reg&outcome=still_present",
        headers=headers,
    )
    assert regressed.status_code == 200
    assert regressed.json()["finding"]["state"] == "regressed"
    diff = client.get("/api/v1/scans/scan-reg/diff/scan-fix", headers=headers)
    assert diff.status_code == 200
    statuses = {row["status"] for row in diff.json()["entries"]}
    assert "regressed" in statuses or "changed" in statuses or diff.json()["entries"]


def test_rag_and_oast_traces() -> None:
    client = _client()
    rag = client.post(
        "/api/v1/rag/traces",
        json={
            "scan_id": "s-1",
            "query": "sqli login",
            "citations": [{"source_hash": "abc", "collection": "lab_research"}],
        },
    )
    assert rag.status_code == 201
    assert client.get("/api/v1/rag/traces/s-1").json()["citations"]
    oast = client.post(
        "/api/v1/oast/traces",
        json={"scan_id": "s-1", "protocol": "dns", "correlation_status": "matched"},
    )
    assert oast.status_code == 201
    assert oast.json()["correlation_status"] == "uncorrelated"
    listed = client.get("/api/v1/oast/traces/s-1")
    assert listed.json()["interactions"]
    assert listed.json()["interactions"][0]["correlation_status"] == "uncorrelated"


def test_oast_trace_correlates_issued_token() -> None:
    client = _client()
    token = get_oast_provisioner().issue(tenant_id=uuid4(), scan_id=uuid4())
    oast = client.post(
        "/api/v1/oast/traces",
        json={
            "scan_id": str(token.scan_id),
            "protocol": "dns",
            "token_id": str(token.id),
            "correlation_status": "matched",
        },
    )
    assert oast.status_code == 201
    assert oast.json()["correlation_status"] == "correlated"


@pytest.mark.asyncio
async def test_lookup_usable_lease_rejects_expired_payload() -> None:
    em_api._reset_stores_for_tests()
    expired = datetime.now(tz=UTC) - timedelta(hours=1)
    repo = get_execution_mode_repository()
    await repo.save_lease(
        "dead",
        {
            "lease_id": "dead",
            "tenant_id": "t-1",
            "engagement_id": "e-1",
            "manifest_id": "m-1",
            "mode": "lab_unrestricted",
            "status": "active",
            "issued_at": expired.isoformat(),
            "expires_at": expired.isoformat(),
            "capture_full": True,
            "boundary_proof": "proof-dead",
            "kill_switch_cleared": True,
            "policy": {
                "outcome": "allow",
                "requires_approval": False,
                "allowed_tools": "*",
                "allowed_actions": "*",
                "allowed_protocols": "*",
                "allowed_payloads": "*",
                "budget": "unlimited",
                "reason": "verified_lab_unrestricted",
            },
        },
    )
    assert await em_api.lookup_usable_lease("dead") is None
    assert await em_api.lookup_usable_lease(None) is None
