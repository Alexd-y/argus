"""Machine-readable profile/LAB errors with stable ``code`` attributes.

These errors carry a stable ``code`` (see Design §3.3) plus an optional
``details`` mapping. The API layer maps them to the unified error contract
``{"error": {"code", "message", "details", "correlation_id"}}`` and an HTTP
status. Nothing here leaks stack traces or secrets.
"""

from __future__ import annotations

from typing import Any


class ArgusProfileError(Exception):
    """Base class for scan-profile resolution / LAB validation errors."""

    #: Stable machine-readable code (overridden by subclasses).
    code: str = "profile_error"
    #: Default HTTP status the API layer should return.
    http_status: int = 422

    def __init__(
        self,
        message: str | None = None,
        *,
        code: str | None = None,
        details: dict[str, Any] | None = None,
        http_status: int | None = None,
    ) -> None:
        self.code = code or type(self).code
        self.details: dict[str, Any] = details or {}
        if http_status is not None:
            self.http_status = http_status
        super().__init__(message or self.code)

    @property
    def message(self) -> str:
        return str(self.args[0]) if self.args else self.code


class InvalidScanProfileError(ArgusProfileError):
    code = "invalid_scan_profile"
    http_status = 422


class ConflictingProfileFieldsError(ArgusProfileError):
    code = "conflicting_profile_fields"
    http_status = 422


class ProfileCapabilityDeniedError(ArgusProfileError):
    code = "profile_capability_denied"
    http_status = 422


class PayloadFamilyDeniedError(ArgusProfileError):
    code = "payload_family_denied"
    http_status = 422


# --- LAB (deep) errors -------------------------------------------------------


class LabLeaseError(ArgusProfileError):
    """Base for all LAB lease/scope validation failures (deep profile)."""

    code = "lab_lease_error"
    http_status = 422


class LabEngagementRequiredError(LabLeaseError):
    code = "lab_engagement_required"


class LabScopeRequiredError(LabLeaseError):
    code = "lab_scope_required"


class LabLeaseRequiredError(LabLeaseError):
    code = "lab_lease_required"


class LabLeaseExpiredError(LabLeaseError):
    code = "lab_lease_expired"


class LabLeaseRevokedError(LabLeaseError):
    code = "lab_lease_revoked"


class LabLeaseTenantMismatchError(LabLeaseError):
    code = "lab_lease_tenant_mismatch"
    http_status = 403


class TargetOutOfLabScopeError(LabLeaseError):
    code = "target_out_of_lab_scope"


__all__ = [
    "ArgusProfileError",
    "ConflictingProfileFieldsError",
    "InvalidScanProfileError",
    "LabEngagementRequiredError",
    "LabLeaseError",
    "LabLeaseExpiredError",
    "LabLeaseRequiredError",
    "LabLeaseRevokedError",
    "LabLeaseTenantMismatchError",
    "LabScopeRequiredError",
    "PayloadFamilyDeniedError",
    "ProfileCapabilityDeniedError",
    "TargetOutOfLabScopeError",
]
