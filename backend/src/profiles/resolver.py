"""Profile Resolver — canonical external ``scan_profile`` → internal knobs.

The external UI selects exactly one of ``quick`` | ``light`` | ``deep``. The
backend is the *single* place that decides what each profile means internally.
The resolved value is immutable and is frozen onto the scan for the whole run
(and on resume) so user input is never re-interpreted mid-scan.

Correctness properties (see Requirements §4):
* P1 — Quick never resolves to ``execution_mode=lab_unrestricted``.
* P3 — ``resolve_scan_profile`` is deterministic for identical input.
* P6 — Legacy ``scan_mode=deep`` (without ``scan_profile``) stays production-deep.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from src.core.structured_events import (
    EVENT_SCAN_PROFILE_CONFLICT,
    EVENT_SCAN_PROFILE_RESOLVED,
    emit_event,
)
from src.execution_mode.mode import ExecutionMode

logger = logging.getLogger(__name__)

PROFILE_VERSION: Final[str] = "v1"

_VALID_QUICK_PROFILES: Final[frozenset[str]] = frozenset({"compact", "balanced", "extended"})
_DEFAULT_QUICK_PROFILE: Final[str] = "balanced"


class ScanProfile(StrEnum):
    """Canonical external scan profile — the only value the UI selects."""

    QUICK = "quick"
    LIGHT = "light"
    DEEP = "deep"


@dataclass(frozen=True, slots=True)
class ResolvedScanProfile:
    """Immutable resolution of a single external ``scan_profile`` selection.

    All internal execution knobs are derived here and nowhere else. The
    structure is frozen so it can be safely persisted and re-used on resume.
    """

    external_profile: ScanProfile
    scan_mode: str  # quick | standard | lab
    execution_mode: ExecutionMode  # quick | production | lab_unrestricted
    quick_profile: str | None  # compact | balanced | extended (quick only)
    nuclei_profile: str  # quick-default | vuln_default | lab_unrestricted
    requires_lab_lease: bool
    tool_capability_set: str  # production_safe | production_active | lab_unrestricted
    payload_risk_ceiling: str  # low | medium | high
    approval_policy: str  # auto | gated | lease_bound
    budget_class: str  # quick_bounded | production_bounded | lab_unbounded
    report_policy: str  # partial_ok | standard | full_evidence
    profile_version: str = PROFILE_VERSION
    #: Diagnostic notes (never contains secrets).
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_public_dict(self) -> dict[str, object]:
        """Serialize for persistence/observability. No secrets."""
        return {
            "external_profile": self.external_profile.value,
            "scan_mode": self.scan_mode,
            "execution_mode": self.execution_mode.value,
            "quick_profile": self.quick_profile,
            "nuclei_profile": self.nuclei_profile,
            "requires_lab_lease": self.requires_lab_lease,
            "tool_capability_set": self.tool_capability_set,
            "payload_risk_ceiling": self.payload_risk_ceiling,
            "approval_policy": self.approval_policy,
            "budget_class": self.budget_class,
            "report_policy": self.report_policy,
            "profile_version": self.profile_version,
        }

    @classmethod
    def from_public_dict(cls, data: dict[str, Any]) -> ResolvedScanProfile:
        """Reconstruct an immutable profile from a persisted checkpoint (R11).

        Resume MUST use the frozen profile context, not re-interpret user input.
        """
        return cls(
            external_profile=ScanProfile(str(data["external_profile"])),
            scan_mode=str(data["scan_mode"]),
            execution_mode=ExecutionMode(str(data["execution_mode"])),
            quick_profile=data.get("quick_profile"),
            nuclei_profile=str(data["nuclei_profile"]),
            requires_lab_lease=bool(data["requires_lab_lease"]),
            tool_capability_set=str(data["tool_capability_set"]),
            payload_risk_ceiling=str(data["payload_risk_ceiling"]),
            approval_policy=str(data["approval_policy"]),
            budget_class=str(data["budget_class"]),
            report_policy=str(data["report_policy"]),
            profile_version=str(data.get("profile_version", PROFILE_VERSION)),
        )


def _coerce_profile(raw: str | ScanProfile) -> ScanProfile:
    if isinstance(raw, ScanProfile):
        return raw
    from src.profiles.errors import InvalidScanProfileError

    normalized = str(raw).strip().lower()
    try:
        return ScanProfile(normalized)
    except ValueError as exc:
        raise InvalidScanProfileError(
            f"Unknown scan_profile: {normalized!r}",
            details={"received": normalized, "allowed": [p.value for p in ScanProfile]},
        ) from exc


def _coerce_quick_profile(raw: str | None) -> str:
    if raw is None:
        return _DEFAULT_QUICK_PROFILE
    normalized = str(raw).strip().lower()
    if normalized not in _VALID_QUICK_PROFILES:
        from src.profiles.errors import InvalidScanProfileError

        raise InvalidScanProfileError(
            f"Unknown quick profile: {normalized!r}",
            code="invalid_scan_profile",
            details={"received": normalized, "allowed": sorted(_VALID_QUICK_PROFILES)},
        )
    return normalized


def resolve_scan_profile(
    scan_profile: str | ScanProfile,
    *,
    quick_profile: str | None = None,
) -> ResolvedScanProfile:
    """Resolve the external profile into the immutable internal contract.

    ``quick_profile`` only applies to the ``quick`` profile (defaults to
    ``balanced``); it is ignored for ``light``/``deep``.
    """
    profile = _coerce_profile(scan_profile)

    if profile is ScanProfile.QUICK:
        resolved = ResolvedScanProfile(
            external_profile=ScanProfile.QUICK,
            scan_mode="quick",
            execution_mode=ExecutionMode.QUICK,
            quick_profile=_coerce_quick_profile(quick_profile),
            nuclei_profile="quick-default",
            requires_lab_lease=False,  # P1: Quick never gets LAB permissions
            tool_capability_set="production_safe",
            payload_risk_ceiling="low",
            approval_policy="auto",
            budget_class="quick_bounded",
            report_policy="partial_ok",
        )
    elif profile is ScanProfile.LIGHT:
        resolved = ResolvedScanProfile(
            external_profile=ScanProfile.LIGHT,
            scan_mode="standard",
            execution_mode=ExecutionMode.PRODUCTION,
            quick_profile=None,
            nuclei_profile="vuln_default",
            requires_lab_lease=False,
            tool_capability_set="production_active",
            payload_risk_ceiling="medium",
            approval_policy="gated",
            budget_class="production_bounded",
            report_policy="standard",
        )
    else:  # ScanProfile.DEEP
        resolved = ResolvedScanProfile(
            external_profile=ScanProfile.DEEP,
            scan_mode="lab",
            execution_mode=ExecutionMode.LAB_UNRESTRICTED,
            quick_profile=None,
            nuclei_profile="lab_unrestricted",
            requires_lab_lease=True,
            tool_capability_set="lab_unrestricted",
            payload_risk_ceiling="high",
            approval_policy="lease_bound",
            budget_class="lab_unbounded",
            report_policy="full_evidence",
        )

    # P1 hard invariant — defense in depth.
    if resolved.execution_mode is ExecutionMode.LAB_UNRESTRICTED and resolved.external_profile is not ScanProfile.DEEP:
        raise AssertionError("only deep may resolve to lab_unrestricted")

    emit_event(
        EVENT_SCAN_PROFILE_RESOLVED,
        scan_profile=resolved.external_profile.value,
        scan_mode=resolved.scan_mode,
        execution_mode=resolved.execution_mode.value,
        nuclei_profile=resolved.nuclei_profile,
        requires_lab_lease=resolved.requires_lab_lease,
        profile_version=resolved.profile_version,
    )
    return resolved


def detect_legacy_conflict(
    scan_profile: str | ScanProfile,
    *,
    legacy_scan_mode: str | None,
    legacy_execution_mode: str | None,
) -> list[str]:
    """Return the list of legacy fields that conflict with the canonical profile.

    Empty list means no conflict. When ``scan_profile`` is provided the client
    MUST NOT also send legacy ``scan_mode`` / ``execution_mode`` values that
    disagree with what the profile resolves to (Requirements R1.4).
    """
    resolved = resolve_scan_profile(scan_profile)
    conflicts: list[str] = []

    if legacy_scan_mode is not None:
        norm = str(legacy_scan_mode).strip().lower()
        # Empty / equal-to-resolved is fine; also tolerate the default "standard"
        # only when it actually matches the resolved mode.
        if norm and norm != resolved.scan_mode:
            conflicts.append("scan_mode")

    if legacy_execution_mode is not None:
        norm = str(legacy_execution_mode).strip().lower()
        if norm and norm != resolved.execution_mode.value:
            conflicts.append("execution_mode")

    if conflicts:
        emit_event(
            EVENT_SCAN_PROFILE_CONFLICT,
            scan_profile=resolved.external_profile.value,
            reason_code="conflicting_profile_fields",
            level=logging.WARNING,
            conflicting_fields=conflicts,
        )
    return conflicts
