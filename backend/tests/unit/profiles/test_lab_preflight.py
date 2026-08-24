"""Unit tests for LAB lease preflight (Requirements R4, P2)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from src.profiles.errors import (
    LabEngagementRequiredError,
    LabLeaseExpiredError,
    LabLeaseRequiredError,
    LabLeaseRevokedError,
    LabLeaseTenantMismatchError,
    LabScopeRequiredError,
    TargetOutOfLabScopeError,
)
from src.profiles.lab_preflight import (
    LeaseView,
    ScopeView,
    evaluate_lab_lease,
    target_in_scope,
)

TENANT = "t-1"
ENGAGEMENT = "e-1"
LEASE_ID = "lease-1"
MANIFEST_ID = "m-1"


def _lease(**overrides) -> LeaseView:
    base = dict(
        lease_id=LEASE_ID,
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        manifest_id=MANIFEST_ID,
        status="active",
        expires_at=datetime.now(UTC) + timedelta(hours=2),
        revoked_at=None,
    )
    base.update(overrides)
    return LeaseView(**base)


def _scope(**overrides) -> ScopeView:
    base = dict(
        manifest_id=MANIFEST_ID,
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        expires_at=datetime.now(UTC) + timedelta(hours=4),
        revoked_at=None,
        asset_ids=(),
        cidrs=("10.90.0.0/16",),
        dns_suffixes=("lab.argus",),
    )
    base.update(overrides)
    return ScopeView(**base)


def _evaluate(target="https://app.lab.argus", **kwargs):
    params = dict(
        tenant_id=TENANT,
        engagement_id=ENGAGEMENT,
        lab_lease_id=LEASE_ID,
        target=target,
        lease=_lease(),
        scope=_scope(),
    )
    params.update(kwargs)
    return evaluate_lab_lease(**params)


def test_valid_lease_allows():
    result = _evaluate()
    assert result.lease_id == LEASE_ID
    assert result.engagement_id == ENGAGEMENT
    assert result.manifest_id == MANIFEST_ID


def test_missing_engagement():
    with pytest.raises(LabEngagementRequiredError):
        _evaluate(engagement_id=None)


def test_missing_lease_id():
    with pytest.raises(LabLeaseRequiredError) as exc:
        _evaluate(lab_lease_id="")
    assert exc.value.details.get("engagement_id") == ENGAGEMENT
    assert exc.value.details.get("required_action") == "issue_or_select_lab_lease"


def test_lease_not_found():
    with pytest.raises(LabLeaseRequiredError):
        _evaluate(lease=None)


def test_wrong_tenant():
    with pytest.raises(LabLeaseTenantMismatchError):
        _evaluate(lease=_lease(tenant_id="other-tenant"))


def test_wrong_engagement():
    with pytest.raises(LabEngagementRequiredError):
        _evaluate(lease=_lease(engagement_id="e-other"))


def test_revoked_lease_status():
    with pytest.raises(LabLeaseRevokedError):
        _evaluate(lease=_lease(status="revoked"))


def test_revoked_lease_timestamp():
    with pytest.raises(LabLeaseRevokedError):
        _evaluate(lease=_lease(revoked_at=datetime.now(UTC)))


def test_expired_lease():
    with pytest.raises(LabLeaseExpiredError):
        _evaluate(lease=_lease(expires_at=datetime.now(UTC) - timedelta(minutes=1)))


def test_lease_expires_during_check():
    """Lease that expires exactly now is treated as expired."""
    with pytest.raises(LabLeaseExpiredError):
        _evaluate(
            lease=_lease(expires_at=datetime.now(UTC)),
            now=datetime.now(UTC) + timedelta(seconds=1),
        )


def test_missing_scope():
    with pytest.raises(LabScopeRequiredError):
        _evaluate(scope=None)


def test_expired_scope():
    with pytest.raises(LabScopeRequiredError):
        _evaluate(scope=_scope(expires_at=datetime.now(UTC) - timedelta(minutes=1)))


def test_target_outside_scope():
    with pytest.raises(TargetOutOfLabScopeError):
        _evaluate(target="https://production.example.com")


def test_target_in_scope_by_dns_suffix():
    assert target_in_scope("https://api.lab.argus/login", _scope()) is True


def test_target_in_scope_by_cidr():
    assert target_in_scope("http://10.90.1.5:8080", _scope()) is True


def test_target_in_scope_by_asset_exact():
    scope = _scope(asset_ids=("app.internal",), cidrs=(), dns_suffixes=())
    assert target_in_scope("https://app.internal", scope) is True


def test_target_out_of_scope_returns_false():
    assert target_in_scope("https://evil.com", _scope()) is False


def test_empty_target_out_of_scope():
    assert target_in_scope("", _scope()) is False
