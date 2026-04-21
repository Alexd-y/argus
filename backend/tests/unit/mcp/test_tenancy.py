"""Unit tests for :mod:`src.mcp.tenancy`.

The tenancy helpers are the second line of defence after authentication —
they catch the case where a caller authenticates as tenant A but tries to
read / mutate tenant B's resources via an explicit ``tenant_id`` argument
on a tool / resource.
"""

from __future__ import annotations

import uuid

import pytest

from src.mcp.auth import MCPAuthContext
from src.mcp.exceptions import TenantMismatchError, ValidationError
from src.mcp.tenancy import assert_tenant_match, assert_tenant_owns_resource


def _ctx(tenant: str) -> MCPAuthContext:
    return MCPAuthContext(
        user_id="tester",
        tenant_id=tenant,
        method="static_token",
        is_admin=False,
    )


class TestAssertTenantMatch:
    def test_no_claim_returns_authenticated_tenant(self) -> None:
        tenant = str(uuid.uuid4())
        result = assert_tenant_match(_ctx(tenant), None)
        assert result == tenant

    def test_matching_claim_returns_tenant(self) -> None:
        tenant = str(uuid.uuid4())
        result = assert_tenant_match(_ctx(tenant), tenant)
        assert result == tenant

    def test_blank_claim_returns_authenticated_tenant(self) -> None:
        tenant = str(uuid.uuid4())
        result = assert_tenant_match(_ctx(tenant), "  ")
        assert result == tenant

    def test_mismatched_claim_raises(self) -> None:
        tenant = str(uuid.uuid4())
        other = str(uuid.uuid4())
        with pytest.raises(TenantMismatchError) as exc_info:
            assert_tenant_match(_ctx(tenant), other)
        assert exc_info.value.code == "mcp_tenant_mismatch"

    def test_malformed_uuid_claim_raises_validation_error(self) -> None:
        tenant = str(uuid.uuid4())
        with pytest.raises(ValidationError):
            assert_tenant_match(_ctx(tenant), "not-a-uuid")

    def test_oversized_claim_rejected(self) -> None:
        tenant = str(uuid.uuid4())
        with pytest.raises(ValidationError):
            assert_tenant_match(_ctx(tenant), "x" * 65)

    def test_missing_authenticated_tenant_raises(self) -> None:
        ctx = MCPAuthContext(
            user_id="tester",
            tenant_id="",
            method="static_token",
            is_admin=False,
        )
        with pytest.raises(TenantMismatchError):
            assert_tenant_match(ctx, None)


class TestAssertTenantOwnsResource:
    def test_matching_owner_passes(self) -> None:
        tenant = str(uuid.uuid4())
        assert_tenant_owns_resource(
            _ctx(tenant), resource_kind="scan", resource_tenant_id=tenant
        )

    def test_mismatched_owner_raises(self) -> None:
        tenant = str(uuid.uuid4())
        other = str(uuid.uuid4())
        with pytest.raises(TenantMismatchError) as exc_info:
            assert_tenant_owns_resource(
                _ctx(tenant), resource_kind="scan", resource_tenant_id=other
            )
        assert exc_info.value.code == "mcp_tenant_mismatch"

    def test_missing_resource_tenant_raises(self) -> None:
        tenant = str(uuid.uuid4())
        with pytest.raises(TenantMismatchError):
            assert_tenant_owns_resource(
                _ctx(tenant), resource_kind="scan", resource_tenant_id=None
            )

    def test_missing_auth_tenant_raises(self) -> None:
        ctx = MCPAuthContext(
            user_id="tester",
            tenant_id="",
            method="static_token",
            is_admin=False,
        )
        with pytest.raises(TenantMismatchError):
            assert_tenant_owns_resource(
                ctx, resource_kind="scan", resource_tenant_id=str(uuid.uuid4())
            )

    def test_kind_appears_in_message(self) -> None:
        tenant = str(uuid.uuid4())
        other = str(uuid.uuid4())
        with pytest.raises(TenantMismatchError) as exc_info:
            assert_tenant_owns_resource(
                _ctx(tenant),
                resource_kind="finding",
                resource_tenant_id=other,
            )
        assert "finding" in exc_info.value.message.lower()
