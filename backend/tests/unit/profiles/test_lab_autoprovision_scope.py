"""Unit tests for deep-profile LAB lease auto-provisioning scope logic.

Pure (no DB): verifies that the target-scoped manifest built by
``lab_autoprovision`` covers exactly the requested target and passes both the
boundary verifier and the preflight scope check, while unrelated targets are
rejected.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from src.execution_mode.boundary_verifier import LabBoundaryVerifier
from src.execution_mode.lab_lease import LabLeaseService
from src.execution_mode.lab_scope import LabScopeManifest
from src.profiles.lab_autoprovision import _extract_host, _target_scope
from src.profiles.lab_preflight import ScopeView, target_in_scope

_TENANT = "t-1"
_ENGAGEMENT = "e-1"


def _manifest(target: str) -> LabScopeManifest:
    scope = _target_scope(target)
    return LabScopeManifest(
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        asset_ids=tuple(scope["asset_ids"]),
        cidrs=tuple(scope["cidrs"]),
        dns_suffixes=tuple(scope["dns_suffixes"]),
        internet_attached=True,
        capture_full=True,
        expires_at=datetime.now(UTC) + timedelta(hours=8),
        created_by="auto-provision",
    )


def _scope_view(manifest: LabScopeManifest) -> ScopeView:
    return ScopeView(
        manifest_id=manifest.manifest_id,
        tenant_id=manifest.tenant_id,
        engagement_id=manifest.engagement_id,
        expires_at=manifest.expires_at,
        revoked_at=None,
        asset_ids=manifest.asset_ids,
        cidrs=manifest.cidrs,
        dns_suffixes=manifest.dns_suffixes,
    )


@pytest.mark.parametrize(
    ("target", "expected_host"),
    [
        ("https://example.com/path?q=1", "example.com"),
        ("example.com", "example.com"),
        ("http://sub.example.com:8443", "sub.example.com"),
        ("10.0.0.5", "10.0.0.5"),
    ],
)
def test_extract_host(target: str, expected_host: str) -> None:
    assert _extract_host(target) == expected_host


def test_scope_covers_hostname_target() -> None:
    target = "https://example.com/login"
    manifest = _manifest(target)

    verdict = LabBoundaryVerifier().verify(
        target, manifest, tenant_id=_TENANT, engagement_id=_ENGAGEMENT
    )
    assert verdict.allowed, verdict.reason
    assert verdict.proof

    # Lease issues cleanly from a verified manifest.
    lease = LabLeaseService().issue(manifest, boundary_proof=verdict.proof)
    assert lease.tenant_id == _TENANT
    assert lease.engagement_id == _ENGAGEMENT

    # Preflight scope check accepts the same target.
    assert target_in_scope(target, _scope_view(manifest)) is True


def test_scope_covers_ip_target() -> None:
    target = "http://10.0.0.5:8080"
    manifest = _manifest(target)
    assert manifest.cidrs == ("10.0.0.5/32",)

    verdict = LabBoundaryVerifier().verify(
        target, manifest, tenant_id=_TENANT, engagement_id=_ENGAGEMENT
    )
    assert verdict.allowed, verdict.reason
    assert target_in_scope(target, _scope_view(manifest)) is True


def test_scope_rejects_unrelated_target() -> None:
    manifest = _manifest("https://example.com")
    other = "https://attacker.evil.net"

    verdict = LabBoundaryVerifier().verify(
        other, manifest, tenant_id=_TENANT, engagement_id=_ENGAGEMENT
    )
    assert verdict.allowed is False
    assert target_in_scope(other, _scope_view(manifest)) is False
