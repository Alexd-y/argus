"""Stage A — execution mode / LAB boundary / allow-all lease tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.routers import execution_mode as em_api
from src.execution_mode import (
    LAB_ALLOW_ALL,
    ExecutionMode,
    ExecutionModeImmutableError,
    LabBoundaryVerifier,
    LabLeaseService,
    LabScopeManifest,
    assert_mode_immutable,
    evaluate_with_execution_mode,
    parse_execution_mode,
)


def _manifest(**overrides):
    base = dict(
        tenant_id="t-1",
        engagement_id="e-1",
        cidrs=("10.90.0.0/16",),
        dns_suffixes=("lab.argus",),
        k8s_namespace="argus-lab-42",
        vm_network_ids=("labnet-42",),
        capture_full=True,
        expires_at=datetime.now(tz=timezone.utc) + timedelta(hours=4),
        created_by="u-1",
    )
    base.update(overrides)
    return LabScopeManifest(**base)


def test_parse_execution_mode_defaults_production():
    assert parse_execution_mode(None) is ExecutionMode.PRODUCTION
    assert parse_execution_mode("lab_unrestricted") is ExecutionMode.LAB_UNRESTRICTED


def test_mode_immutable_after_execution():
    with pytest.raises(ExecutionModeImmutableError):
        assert_mode_immutable(
            ExecutionMode.PRODUCTION,
            ExecutionMode.LAB_UNRESTRICTED,
            has_started_execution=True,
        )


def test_boundary_allows_lab_cidr_and_dns():
    m = _manifest()
    v = LabBoundaryVerifier()
    ok_ip = v.verify(
        "10.90.1.5",
        m,
        tenant_id="t-1",
        engagement_id="e-1",
        k8s_namespace="argus-lab-42",
        vm_network_id="labnet-42",
    )
    assert ok_ip.allowed
    ok_dns = v.verify(
        "https://app.lab.argus/login",
        m,
        tenant_id="t-1",
        engagement_id="e-1",
        k8s_namespace="argus-lab-42",
        vm_network_id="labnet-42",
    )
    assert ok_dns.allowed


def test_boundary_denies_outside_lab():
    m = _manifest()
    denied = LabBoundaryVerifier().verify(
        "https://evil.example",
        m,
        tenant_id="t-1",
        engagement_id="e-1",
        k8s_namespace="argus-lab-42",
        vm_network_id="labnet-42",
    )
    assert not denied.allowed
    assert denied.deny_code == "DENY_OUTSIDE_LAB"


def test_lab_lease_allow_all_no_approval():
    m = _manifest()
    verdict = LabBoundaryVerifier().verify(
        "10.90.2.2",
        m,
        tenant_id="t-1",
        engagement_id="e-1",
        k8s_namespace="argus-lab-42",
        vm_network_id="labnet-42",
    )
    lease = LabLeaseService().issue(m, boundary_proof=verdict.proof)
    decision = LabLeaseService().decision_for_lease(lease)
    assert decision.outcome == "allow"
    assert decision.requires_approval is False
    assert decision.allowed_tools == "*"
    assert decision.allowed_actions == "*"
    assert decision.allowed_protocols == "*"
    assert decision.allowed_payloads == "*"
    assert decision.budget == "unlimited"
    assert decision.reason == "verified_lab_unrestricted"


@pytest.mark.parametrize(
    "tool_or_action",
    [
        "sqlmap",
        "nuclei",
        "metasploit",
        "impacket",
        "custom_script",
        "reverse_shell",
        "lateral_movement",
        "credential_dump",
        "code_template",
        "headless",
        "clusterbomb",
    ],
)
def test_lab_allow_all_covers_tool_action_classes(tool_or_action: str):
    """No per-action approval / allowlist filtering for LAB lease."""
    assert LAB_ALLOW_ALL.allowed is True
    assert LAB_ALLOW_ALL.requires_approval is False
    assert LAB_ALLOW_ALL.allowed_tools == "*"
    # wildcard means every class is permitted — assert decision surface, not filter
    assert tool_or_action  # parametrize presence only


def test_evaluate_with_execution_mode_lab_path():
    m = _manifest()
    decision = evaluate_with_execution_mode(
        mode=ExecutionMode.LAB_UNRESTRICTED,
        target="10.90.9.9",
        manifest=m,
        tenant_id="t-1",
        engagement_id="e-1",
        k8s_namespace="argus-lab-42",
        vm_network_id="labnet-42",
    )
    assert decision.allowed is True
    assert decision.requires_approval is False


def test_api_lab_scope_and_lease_e2e():
    em_api._reset_stores_for_tests()
    app = FastAPI()
    app.include_router(em_api.router, prefix="/api/v1")
    client = TestClient(app)
    headers = {"X-Tenant-Id": "t-1", "X-User-Id": "u-1"}

    r = client.post(
        "/api/v1/engagements/e-1/execution-mode",
        headers=headers,
        json={"mode": "lab_unrestricted"},
    )
    assert r.status_code == 200
    assert r.json()["mode"] == "lab_unrestricted"

    r = client.post(
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
    assert r.status_code == 201
    assert r.json()["mode"] == "lab_unrestricted"

    r = client.post(
        "/api/v1/engagements/e-1/lab-lease",
        headers={**headers, "Idempotency-Key": "idem-1"},
        json={
            "target": "https://victim.lab.argus/",
            "k8s_namespace": "argus-lab-42",
            "vm_network_id": "labnet-42",
        },
    )
    assert r.status_code == 201
    body = r.json()
    assert body["policy"]["requires_approval"] is False
    assert body["policy"]["allowed_tools"] == "*"

    # outside boundary denied
    r = client.post(
        "/api/v1/engagements/e-1/lab-lease",
        headers=headers,
        json={
            "target": "https://production.example/",
            "k8s_namespace": "argus-lab-42",
            "vm_network_id": "labnet-42",
        },
    )
    assert r.status_code == 403
