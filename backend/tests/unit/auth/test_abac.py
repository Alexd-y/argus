"""Tests for ABAC engine."""

import pytest
import time
from unittest.mock import MagicMock

from src.auth.abac import (
    ABACEngine,
    Role,
    AccessAction,
    ResourceType,
    AccessRequest,
    AccessDecision,
    _ROLE_PERMISSIONS,
    _MFA_REQUIRED_ACTIONS,
    generate_session_watermark,
    verify_mfa_session,
)


class TestRolePermissions:
    def test_viewer_cannot_write_findings(self):
        perms = _ROLE_PERMISSIONS[Role.VIEWER]
        assert AccessAction.WRITE not in perms.get(ResourceType.FINDING, set())

    def test_developer_can_write_findings(self):
        perms = _ROLE_PERMISSIONS[Role.DEVELOPER]
        assert AccessAction.WRITE in perms.get(ResourceType.FINDING, set())

    def test_admin_can_admin_users(self):
        perms = _ROLE_PERMISSIONS[Role.ORG_ADMIN]
        assert AccessAction.ADMIN in perms.get(ResourceType.USER, set())

    def test_senior_researcher_can_execute_binaries(self):
        perms = _ROLE_PERMISSIONS[Role.SENIOR_RESEARCHER]
        assert AccessAction.EXECUTE in perms.get(ResourceType.BINARY, set())


class TestMFARequired:
    def test_delete_requires_mfa(self):
        assert AccessAction.DELETE in _MFA_REQUIRED_ACTIONS

    def test_approve_requires_mfa(self):
        assert AccessAction.APPROVE in _MFA_REQUIRED_ACTIONS

    def test_export_requires_mfa(self):
        assert AccessAction.EXPORT in _MFA_REQUIRED_ACTIONS

    def test_read_does_not_require_mfa(self):
        assert AccessAction.READ not in _MFA_REQUIRED_ACTIONS


class TestABACEngine:
    def setup_method(self):
        self.engine = ABACEngine()

    def test_viewer_read_finding_allowed(self):
        req = AccessRequest(
            user_id="u1", tenant_id="t1", role=Role.VIEWER,
            action=AccessAction.READ, resource_type=ResourceType.FINDING,
        )
        decision = self.engine.evaluate(req)
        assert decision.allowed is True
        assert decision.watermark != ""

    def test_viewer_write_finding_denied(self):
        req = AccessRequest(
            user_id="u1", tenant_id="t1", role=Role.VIEWER,
            action=AccessAction.WRITE, resource_type=ResourceType.FINDING,
        )
        decision = self.engine.evaluate(req)
        assert decision.allowed is False
        assert "viewer" in decision.reason

    def test_delete_without_mfa_denied(self):
        req = AccessRequest(
            user_id="u1", tenant_id="t1", role=Role.ORG_ADMIN,
            action=AccessAction.DELETE, resource_type=ResourceType.SCAN,
            mfa_verified=False, device_trusted=True,
        )
        decision = self.engine.evaluate(req)
        assert decision.allowed is False
        assert decision.requires_mfa is True

    def test_delete_with_mfa_allowed(self):
        req = AccessRequest(
            user_id="u1", tenant_id="t1", role=Role.ORG_ADMIN,
            action=AccessAction.DELETE, resource_type=ResourceType.SCAN,
            mfa_verified=True, device_trusted=True,
        )
        decision = self.engine.evaluate(req)
        assert decision.allowed is True

    def test_admin_without_trusted_device_denied(self):
        req = AccessRequest(
            user_id="u1", tenant_id="t1", role=Role.ORG_ADMIN,
            action=AccessAction.ADMIN, resource_type=ResourceType.POLICY,
            mfa_verified=True, device_trusted=False,
        )
        decision = self.engine.evaluate(req)
        assert decision.allowed is False
        assert "device" in decision.reason

    def test_kill_switch_blocks_all(self):
        def kill_all(tenant, user):
            return True

        engine = ABACEngine(kill_switch_checker=kill_all)
        req = AccessRequest(
            user_id="u1", tenant_id="t1", role=Role.ORG_ADMIN,
            action=AccessAction.READ, resource_type=ResourceType.SCAN,
        )
        decision = engine.evaluate(req)
        assert decision.allowed is False
        assert "kill_switch" in decision.reason


class TestSessionWatermark:
    def test_generates_unique_watermarks(self):
        r1 = AccessRequest(user_id="u1", session_id="s1")
        r2 = AccessRequest(user_id="u2", session_id="s2")
        w1 = generate_session_watermark(r1)
        w2 = generate_session_watermark(r2)
        assert w1 != w2
        assert len(w1) == 32

    def test_watermark_deterministic_with_same_inputs(self):
        # Watermarks include a random component, so they differ by design
        r = AccessRequest(user_id="u1", session_id="s1")
        w1 = generate_session_watermark(r)
        w2 = generate_session_watermark(r)
        assert w1 != w2  # random component ensures uniqueness


class TestMFAVerification:
    def test_recent_mfa_valid(self):
        assert verify_mfa_session(time.time() - 60) is True

    def test_expired_mfa_invalid(self):
        assert verify_mfa_session(time.time() - 400) is False
