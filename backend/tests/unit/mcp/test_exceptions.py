"""Unit tests for the closed-taxonomy MCP exception hierarchy."""

from __future__ import annotations

import pytest

from src.mcp.exceptions import (
    ApprovalRequiredError,
    AuthenticationError,
    AuthorizationError,
    MCPError,
    PolicyDeniedError,
    RateLimitedError,
    ResourceNotFoundError,
    ScopeViolationError,
    TenantMismatchError,
    UpstreamServiceError,
    ValidationError,
    is_known_error_code,
)


class TestErrorContract:
    @pytest.mark.parametrize(
        "exc_cls,expected_code,expected_status",
        [
            (AuthenticationError, "mcp_auth_unauthenticated", 401),
            (AuthorizationError, "mcp_auth_forbidden", 403),
            (TenantMismatchError, "mcp_tenant_mismatch", 403),
            (ScopeViolationError, "mcp_scope_violation", 403),
            (ApprovalRequiredError, "mcp_approval_required", 403),
            (PolicyDeniedError, "mcp_policy_denied", 403),
            (ResourceNotFoundError, "mcp_resource_not_found", 404),
            (ValidationError, "mcp_validation_error", 422),
            (RateLimitedError, "mcp_rate_limited", 429),
            (UpstreamServiceError, "mcp_upstream_error", 502),
        ],
    )
    def test_default_code_and_status(
        self,
        exc_cls: type[MCPError],
        expected_code: str,
        expected_status: int,
    ) -> None:
        exc = exc_cls("boom")
        assert exc.code == expected_code
        assert exc.http_status == expected_status
        assert exc.message == "boom"
        assert str(exc) == f"[{expected_code}] boom"

    def test_base_error_default_code(self) -> None:
        exc = MCPError("generic")
        assert exc.code == "mcp_error"
        assert exc.http_status == 500

    def test_explicit_code_overrides_default(self) -> None:
        exc = ValidationError("bad input", code="mcp_custom_code")
        assert exc.code == "mcp_custom_code"
        assert exc.message == "bad input"

    def test_inherits_exception(self) -> None:
        exc = ValidationError("x")
        assert isinstance(exc, Exception)
        assert isinstance(exc, MCPError)


class TestKnownErrorCodes:
    @pytest.mark.parametrize(
        "code",
        [
            "mcp_auth_unauthenticated",
            "mcp_auth_forbidden",
            "mcp_tenant_mismatch",
            "mcp_scope_violation",
            "mcp_approval_required",
            "mcp_policy_denied",
            "mcp_resource_not_found",
            "mcp_validation_error",
            "mcp_rate_limited",
            "mcp_upstream_error",
        ],
    )
    def test_known_codes(self, code: str) -> None:
        assert is_known_error_code(code) is True

    @pytest.mark.parametrize(
        "code",
        ["unknown", "", "internal", "MCP_AUTH_UNAUTHENTICATED"],
    )
    def test_unknown_codes(self, code: str) -> None:
        assert is_known_error_code(code) is False

    def test_base_code_not_in_taxonomy(self) -> None:
        assert is_known_error_code(MCPError("x").code) is False


class TestMessageNeverLeaksStackTrace:
    """Operator-safe contract — the ``message`` field is what the LLM sees."""

    def test_message_is_short_and_self_contained(self) -> None:
        exc = AuthenticationError("Provide a bearer token or X-API-Key header.")
        assert "Traceback" not in exc.message
        assert "src." not in exc.message
        assert len(exc.message) <= 200

    def test_repr_does_not_include_stack(self) -> None:
        try:
            raise ResourceNotFoundError("scan abc not found in tenant scope")
        except ResourceNotFoundError as exc:
            assert "site-packages" not in str(exc)
            assert "/Users/" not in str(exc)
            assert "C:\\" not in str(exc)
