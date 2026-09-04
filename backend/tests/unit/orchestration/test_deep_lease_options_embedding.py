"""Regression: deep-profile scans must carry the LAB lease inside scan options.

The worker's phase preflight (`preflight_phase_execution_mode`) resolves the LAB
lease ONLY from scan options — it is passed no DB ``lease_lookup``. If a deep
scan carries just ``execution_mode`` + ``lab_lease_id`` (but not the serialized
``lab_lease``), every phase in worker-scans fails closed with
``lab_lease_required`` even though the lease exists in the DB. ``create_scan``
therefore embeds the validated lease + manifest via
``load_lease_scope_storage``; these tests lock that contract at the preflight
layer without a database.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from src.execution_mode.boundary_verifier import LabBoundaryVerifier
from src.execution_mode.lab_lease import LabExecutionLease, LabLeaseService
from src.execution_mode.lab_scope import LabScopeManifest
from src.orchestration.execution_mode_context import preflight_phase_execution_mode

_TENANT = "t-1"
_ENGAGEMENT = "e-1"
_TARGET = "https://alleksy.com/login"


def _issue_lease() -> tuple[LabExecutionLease, LabScopeManifest]:
    manifest = LabScopeManifest(
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        asset_ids=("alleksy.com",),
        cidrs=(),
        dns_suffixes=("alleksy.com",),
        internet_attached=True,
        capture_full=True,
        expires_at=datetime.now(UTC) + timedelta(hours=8),
        created_by="auto-provision",
    )
    verdict = LabBoundaryVerifier().verify(
        _TARGET, manifest, tenant_id=_TENANT, engagement_id=_ENGAGEMENT
    )
    assert verdict.allowed, verdict.reason
    lease = LabLeaseService().issue(manifest, boundary_proof=verdict.proof)
    return lease, manifest


def test_embedded_lease_activates_lab() -> None:
    """Options carrying the serialized lease → phase preflight sees LAB active."""
    lease, manifest = _issue_lease()
    options: dict[str, Any] = {
        "execution_mode": "lab_unrestricted",
        "lab_lease_id": lease.lease_id,
        "lab_lease": lease.to_storage_dict(),
        "lab_scope_manifest": manifest.to_storage_dict(),
    }

    preflight = preflight_phase_execution_mode(
        options, tenant_id=_TENANT, engagement_id=_ENGAGEMENT
    )

    assert preflight.lab_lease_active is True
    assert preflight.deny_code is None
    assert preflight.lab_lease_id == lease.lease_id


def test_missing_embedded_lease_fails_closed() -> None:
    """Only execution_mode + lab_lease_id (the pre-fix bug) → lab_lease_required."""
    lease, _ = _issue_lease()
    options: dict[str, Any] = {
        "execution_mode": "lab_unrestricted",
        "lab_lease_id": lease.lease_id,
    }

    preflight = preflight_phase_execution_mode(
        options, tenant_id=_TENANT, engagement_id=_ENGAGEMENT
    )

    assert preflight.lab_lease_active is False
    assert preflight.deny_code
    assert preflight.reason == "lab_lease_required"


def test_embedded_lease_tenant_mismatch_denied() -> None:
    """A lease for another tenant must not activate LAB (isolation)."""
    lease, manifest = _issue_lease()
    options: dict[str, Any] = {
        "execution_mode": "lab_unrestricted",
        "lab_lease_id": lease.lease_id,
        "lab_lease": lease.to_storage_dict(),
        "lab_scope_manifest": manifest.to_storage_dict(),
    }

    preflight = preflight_phase_execution_mode(
        options, tenant_id="other-tenant", engagement_id=_ENGAGEMENT
    )

    assert preflight.lab_lease_active is False
