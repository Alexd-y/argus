"""RBAC/ABAC Engine — role-based and attribute-based access control.

Multi-level model: Viewer, Developer, AppSec Analyst, Senior Researcher,
Org Admin, Compliance Officer. Just-in-time elevation, MFA enforcement,
device posture checks, session watermarking.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class Role(str, Enum):
    VIEWER = "viewer"
    DEVELOPER = "developer"
    APPSEC_ANALYST = "appsec_analyst"
    SENIOR_RESEARCHER = "senior_researcher"
    ORG_ADMIN = "org_admin"
    COMPLIANCE_OFFICER = "compliance_officer"


class AccessAction(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    APPROVE = "approve"
    EXPORT = "export"
    ADMIN = "admin"


class ResourceType(str, Enum):
    SCAN = "scan"
    FINDING = "finding"
    REPORT = "report"
    REPO = "repo"
    PATCH = "patch"
    SANDBOX = "sandbox"
    POLICY = "policy"
    AUDIT = "audit"
    USER = "user"
    TENANT = "tenant"
    BINARY = "binary"


@dataclass
class AccessRequest:
    user_id: str = ""
    tenant_id: str = ""
    role: Role = Role.VIEWER
    action: AccessAction = AccessAction.READ
    resource_type: ResourceType = ResourceType.FINDING
    resource_id: str = ""
    mfa_verified: bool = False
    device_trusted: bool = False
    session_id: str = ""
    elevation_reason: str = ""
    context: dict[str, Any] = field(default_factory=dict)


@dataclass
class AccessDecision:
    allowed: bool = False
    reason: str = ""
    requires_mfa: bool = False
    requires_elevation: bool = False
    watermark: str = ""
    expires_at: float = 0.0  # epoch timestamp


# Role → allowed actions per resource type
_ROLE_PERMISSIONS: dict[Role, dict[ResourceType, set[AccessAction]]] = {
    Role.VIEWER: {
        ResourceType.SCAN: {AccessAction.READ},
        ResourceType.FINDING: {AccessAction.READ},
        ResourceType.REPORT: {AccessAction.READ},
        ResourceType.AUDIT: {AccessAction.READ},
    },
    Role.DEVELOPER: {
        ResourceType.SCAN: {AccessAction.READ, AccessAction.WRITE},
        ResourceType.FINDING: {AccessAction.READ, AccessAction.WRITE},
        ResourceType.REPORT: {AccessAction.READ},
        ResourceType.REPO: {AccessAction.READ, AccessAction.WRITE},
        ResourceType.PATCH: {AccessAction.READ, AccessAction.WRITE},
    },
    Role.APPSEC_ANALYST: {
        ResourceType.SCAN: {AccessAction.READ, AccessAction.WRITE, AccessAction.EXECUTE},
        ResourceType.FINDING: {AccessAction.READ, AccessAction.WRITE, AccessAction.APPROVE},
        ResourceType.REPORT: {AccessAction.READ, AccessAction.WRITE, AccessAction.EXPORT},
        ResourceType.REPO: {AccessAction.READ, AccessAction.WRITE},
        ResourceType.PATCH: {AccessAction.READ, AccessAction.APPROVE},
        ResourceType.SANDBOX: {AccessAction.READ, AccessAction.EXECUTE},
    },
    Role.SENIOR_RESEARCHER: {
        ResourceType.SCAN: {AccessAction.READ, AccessAction.WRITE, AccessAction.EXECUTE},
        ResourceType.FINDING: {AccessAction.READ, AccessAction.WRITE, AccessAction.APPROVE, AccessAction.EXPORT},
        ResourceType.REPORT: {AccessAction.READ, AccessAction.WRITE, AccessAction.EXPORT},
        ResourceType.REPO: {AccessAction.READ, AccessAction.WRITE},
        ResourceType.PATCH: {AccessAction.READ, AccessAction.WRITE, AccessAction.APPROVE},
        ResourceType.SANDBOX: {AccessAction.READ, AccessAction.EXECUTE},
        ResourceType.BINARY: {AccessAction.READ, AccessAction.EXECUTE},
    },
    Role.ORG_ADMIN: {
        ResourceType.SCAN: {AccessAction.READ, AccessAction.WRITE, AccessAction.DELETE, AccessAction.EXECUTE},
        ResourceType.FINDING: {AccessAction.READ, AccessAction.WRITE, AccessAction.APPROVE, AccessAction.EXPORT},
        ResourceType.REPORT: {AccessAction.READ, AccessAction.WRITE, AccessAction.DELETE, AccessAction.EXPORT},
        ResourceType.REPO: {AccessAction.READ, AccessAction.WRITE, AccessAction.DELETE},
        ResourceType.PATCH: {AccessAction.READ, AccessAction.WRITE, AccessAction.APPROVE},
        ResourceType.SANDBOX: {AccessAction.READ, AccessAction.EXECUTE, AccessAction.ADMIN},
        ResourceType.POLICY: {AccessAction.READ, AccessAction.WRITE, AccessAction.ADMIN},
        ResourceType.AUDIT: {AccessAction.READ, AccessAction.EXPORT, AccessAction.ADMIN},
        ResourceType.USER: {
            AccessAction.READ,
            AccessAction.WRITE,
            AccessAction.DELETE,
            AccessAction.ADMIN,
        },
        ResourceType.TENANT: {AccessAction.READ, AccessAction.WRITE, AccessAction.ADMIN},
    },
    Role.COMPLIANCE_OFFICER: {
        ResourceType.SCAN: {AccessAction.READ},
        ResourceType.FINDING: {AccessAction.READ, AccessAction.EXPORT},
        ResourceType.REPORT: {AccessAction.READ, AccessAction.EXPORT},
        ResourceType.AUDIT: {AccessAction.READ, AccessAction.EXPORT},
    },
}

# Actions that always require MFA
_MFA_REQUIRED_ACTIONS = {
    AccessAction.DELETE,
    AccessAction.APPROVE,
    AccessAction.ADMIN,
    AccessAction.EXPORT,
}


class ABACEngine:
    """Attribute-Based Access Control engine.

    Evaluates access requests against role permissions, MFA requirements,
    device posture, and session constraints.
    """

    def __init__(
        self,
        kill_switch_checker: Callable[[str, str], bool] | None = None,
        rate_limiter: Callable[[str], bool] | None = None,
    ) -> None:
        self._kill_switch = kill_switch_checker or (lambda t, u: False)
        self._rate_limiter = rate_limiter or (lambda u: True)
        self._elevations: dict[str, float] = {}  # user_id → elevation_expiry

    def evaluate(self, request: AccessRequest) -> AccessDecision:
        """Evaluate access request and return decision."""
        # Kill switch override
        if self._kill_switch(request.tenant_id, request.user_id):
            return AccessDecision(
                allowed=False,
                reason="policy_kill_switch_active",
                requires_mfa=False,
            )

        # Rate limit check
        if not self._rate_limiter(request.user_id):
            return AccessDecision(
                allowed=False,
                reason="policy_rate_limit_exceeded",
                requires_mfa=False,
            )

        # Role-based check
        role_perms = _ROLE_PERMISSIONS.get(request.role, {})
        allowed_actions = role_perms.get(request.resource_type, set())

        if request.action not in allowed_actions:
            # Check if elevation is possible
            if request.elevation_reason:
                return self._evaluate_elevation(request)
            return AccessDecision(
                allowed=False,
                reason=f"role_{request.role.value}_cannot_{request.action.value}_on_{request.resource_type.value}",
                requires_mfa=False,
            )

        # MFA requirement
        requires_mfa = (
            request.action in _MFA_REQUIRED_ACTIONS and not request.mfa_verified
        )
        if requires_mfa:
            return AccessDecision(
                allowed=False,
                reason="mfa_required",
                requires_mfa=True,
            )

        # Device posture check (for sensitive actions)
        if (
            request.action in (AccessAction.ADMIN, AccessAction.DELETE)
            and not request.device_trusted
        ):
            return AccessDecision(
                allowed=False,
                reason="device_not_trusted",
                requires_mfa=True,
            )

        watermark = generate_session_watermark(request)
        return AccessDecision(
            allowed=True,
            watermark=watermark,
            expires_at=time.time() + 3600,  # 1 hour
        )

    def _evaluate_elevation(self, request: AccessRequest) -> AccessDecision:
        """Evaluate just-in-time elevation request."""
        if not request.mfa_verified:
            return AccessDecision(
                allowed=False, reason="elevation_requires_mfa",
                requires_mfa=True, requires_elevation=True,
            )
        if not request.device_trusted:
            return AccessDecision(
                allowed=False, reason="elevation_requires_trusted_device",
                requires_elevation=True,
            )
        # Grant 15-minute elevation
        self._elevations[request.user_id] = time.time() + 900
        watermark = generate_session_watermark(request)
        return AccessDecision(
            allowed=True, reason="elevation_granted",
            watermark=watermark,
            expires_at=time.time() + 900,
        )


def generate_session_watermark(request: AccessRequest) -> str:
    """Generate unique session watermark for audit trail."""
    raw = f"{request.user_id}:{request.tenant_id}:{request.session_id}:{uuid.uuid4().hex[:8]}"
    return hashlib.blake2b(raw.encode(), digest_size=16).hexdigest()


def check_device_posture(
    user_agent: str = "",
    ip_address: str = "",
    known_device_ids: set[str] | None = None,
) -> bool:
    """Basic device posture check."""
    return bool(user_agent and ip_address)


MFA_VERIFICATION_TIMEOUT = 300


def verify_mfa_session(mfa_timestamp: float) -> bool:
    """Check if MFA verification is still valid."""
    return (time.time() - mfa_timestamp) < MFA_VERIFICATION_TIMEOUT
