"""Canonical external scan-profile resolution (quick | light | deep).

This package is the single source of truth that maps the external scan profile
selected by the UI onto the internal execution knobs (scan_mode, execution_mode,
quick_profile, nuclei_profile, capability/payload/approval/budget/report policy).

See ``.spec/argus-profile-orchestration-rework/Design.md`` §5.
"""

from __future__ import annotations

from src.profiles.errors import (
    ArgusProfileError,
    ConflictingProfileFieldsError,
    InvalidScanProfileError,
    LabEngagementRequiredError,
    LabLeaseError,
    LabLeaseExpiredError,
    LabLeaseRequiredError,
    LabLeaseRevokedError,
    LabLeaseTenantMismatchError,
    LabScopeRequiredError,
    TargetOutOfLabScopeError,
)
from src.profiles.resolver import (
    PROFILE_VERSION,
    ResolvedScanProfile,
    ScanProfile,
    detect_legacy_conflict,
    resolve_scan_profile,
)

__all__ = [
    "PROFILE_VERSION",
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
    "ResolvedScanProfile",
    "ScanProfile",
    "TargetOutOfLabScopeError",
    "detect_legacy_conflict",
    "resolve_scan_profile",
]
