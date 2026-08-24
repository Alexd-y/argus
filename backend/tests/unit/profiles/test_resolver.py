"""Unit tests for the canonical Profile Resolver (Requirements R1-R4, P1/P3/P6)."""

from __future__ import annotations

import pytest

from src.execution_mode.mode import ExecutionMode
from src.profiles import (
    ScanProfile,
    detect_legacy_conflict,
    resolve_scan_profile,
)
from src.profiles.errors import InvalidScanProfileError


def test_quick_mapping():
    r = resolve_scan_profile("quick")
    assert r.external_profile is ScanProfile.QUICK
    assert r.scan_mode == "quick"
    assert r.execution_mode is ExecutionMode.QUICK
    assert r.quick_profile == "balanced"  # default
    assert r.nuclei_profile == "quick-default"
    assert r.requires_lab_lease is False
    assert r.tool_capability_set == "production_safe"
    assert r.payload_risk_ceiling == "low"
    assert r.report_policy == "partial_ok"


@pytest.mark.parametrize("quick_profile", ["compact", "balanced", "extended"])
def test_quick_profile_passthrough(quick_profile):
    r = resolve_scan_profile("quick", quick_profile=quick_profile)
    assert r.quick_profile == quick_profile


def test_quick_default_is_balanced():
    assert resolve_scan_profile("quick", quick_profile=None).quick_profile == "balanced"


def test_light_mapping():
    r = resolve_scan_profile("light")
    assert r.scan_mode == "standard"
    assert r.execution_mode is ExecutionMode.PRODUCTION
    assert r.quick_profile is None
    assert r.nuclei_profile == "vuln_default"
    assert r.requires_lab_lease is False
    assert r.tool_capability_set == "production_active"


def test_deep_mapping():
    r = resolve_scan_profile("deep")
    assert r.scan_mode == "lab"
    assert r.execution_mode is ExecutionMode.LAB_UNRESTRICTED
    assert r.nuclei_profile == "lab_unrestricted"
    assert r.requires_lab_lease is True
    assert r.approval_policy == "lease_bound"
    assert r.payload_risk_ceiling == "high"


def test_quick_never_gets_lab_permissions():
    """P1 — Quick never resolves to lab_unrestricted regardless of hints."""
    for hint in (None, "compact", "balanced", "extended"):
        r = resolve_scan_profile("quick", quick_profile=hint)
        assert r.execution_mode is not ExecutionMode.LAB_UNRESTRICTED
        assert r.requires_lab_lease is False


def test_only_deep_is_lab():
    for profile in (ScanProfile.QUICK, ScanProfile.LIGHT):
        assert resolve_scan_profile(profile).execution_mode is not ExecutionMode.LAB_UNRESTRICTED


def test_determinism():
    """P3 — deterministic for identical input."""
    a = resolve_scan_profile("deep").to_public_dict()
    b = resolve_scan_profile("deep").to_public_dict()
    assert a == b


def test_invalid_profile_rejected():
    with pytest.raises(InvalidScanProfileError) as exc:
        resolve_scan_profile("aggressive")
    assert exc.value.code == "invalid_scan_profile"


def test_invalid_quick_profile_rejected():
    with pytest.raises(InvalidScanProfileError):
        resolve_scan_profile("quick", quick_profile="nuclear")


def test_enum_accepts_string_and_enum():
    assert resolve_scan_profile(ScanProfile.LIGHT).scan_mode == "standard"
    assert resolve_scan_profile("LIGHT").scan_mode == "standard"


class TestLegacyConflict:
    def test_no_conflict_when_legacy_absent(self):
        assert detect_legacy_conflict("deep", legacy_scan_mode=None, legacy_execution_mode=None) == []

    def test_no_conflict_when_legacy_matches(self):
        assert (
            detect_legacy_conflict(
                "deep", legacy_scan_mode="lab", legacy_execution_mode="lab_unrestricted"
            )
            == []
        )

    def test_conflict_scan_mode(self):
        conflicts = detect_legacy_conflict(
            "deep", legacy_scan_mode="standard", legacy_execution_mode=None
        )
        assert "scan_mode" in conflicts

    def test_conflict_execution_mode(self):
        conflicts = detect_legacy_conflict(
            "quick", legacy_scan_mode=None, legacy_execution_mode="production"
        )
        assert "execution_mode" in conflicts

    def test_conflict_both(self):
        conflicts = detect_legacy_conflict(
            "light", legacy_scan_mode="lab", legacy_execution_mode="lab_unrestricted"
        )
        assert set(conflicts) == {"scan_mode", "execution_mode"}

    def test_legacy_deep_scan_mode_not_lab(self):
        """P6 — legacy scan_mode=deep (without scan_profile) is not this resolver's concern.

        The resolver only maps external profiles; legacy path is untouched. Here we
        verify that pairing external deep with legacy scan_mode=deep is a conflict
        (deep external → lab, not deep depth).
        """
        conflicts = detect_legacy_conflict(
            "deep", legacy_scan_mode="deep", legacy_execution_mode=None
        )
        assert "scan_mode" in conflicts
