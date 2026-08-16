"""QUICK-003 — quick-default Nuclei profile is production-gated, not LAB."""

from __future__ import annotations

from pathlib import Path

import yaml

from src.nuclei.profile_compiler import PROFILE_DIR, load_scan_profile
from src.nuclei.schemas import ScanProfile

_QUICK_YAML = PROFILE_DIR / "quick-default.yaml"


def _raw_profile() -> dict:
    payload = yaml.safe_load(_QUICK_YAML.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def test_quick_default_yaml_exists_and_is_not_lab_unrestricted() -> None:
    assert _QUICK_YAML.is_file()
    raw = _raw_profile()
    assert raw["id"] == "quick-default"
    assert raw["id"] != "lab_unrestricted"
    assert raw.get("mode") == "quick"
    profile = load_scan_profile("quick-default")
    assert isinstance(profile, ScanProfile)
    assert profile.id == "quick-default"
    assert profile.is_lab_unrestricted is False


def test_quick_default_requires_verified_templates() -> None:
    raw = _raw_profile()
    profile = load_scan_profile("quick-default")
    assert raw["require_verified_templates"] is True
    assert raw["disable_unsigned_templates"] is True
    assert profile.require_verified_templates is True
    assert profile.disable_unsigned_templates is True
    assert profile.allow_remote_templates is False
    assert profile.allow_remote_workflows is False


def test_quick_default_severity_floor_excludes_low_and_info() -> None:
    raw = _raw_profile()
    allowed = list(raw["severity_allow"])
    include = list((raw.get("severity") or {}).get("include") or [])
    profile = load_scan_profile("quick-default")
    for bucket in (allowed, include, list(profile.severity_allow)):
        assert "critical" in bucket
        assert "high" in bucket
        assert "medium" in bucket
        assert "low" not in bucket
        assert "info" not in bucket


def test_quick_default_disables_lab_capabilities() -> None:
    profile = load_scan_profile("quick-default")
    assert profile.allow_code is False
    assert profile.allow_javascript is False
    assert profile.allow_headless is False
    assert profile.allow_oast is False
    assert profile.allow_file is False
    assert profile.allow_self_contained is False
    assert profile.allow_local_file_access is False
    assert profile.disable_code is True
    assert profile.disable_javascript is True
    assert profile.disable_headless is True
    attack_types = {str(item).lower() for item in (profile.attack_types or ())}
    assert "clusterbomb" not in attack_types


def test_quick_default_is_not_the_lab_unrestricted_document() -> None:
    lab_path = PROFILE_DIR / "lab_unrestricted.yaml"
    assert lab_path.is_file()
    lab = yaml.safe_load(lab_path.read_text(encoding="utf-8"))
    quick = _raw_profile()
    assert lab["id"] == "lab_unrestricted"
    assert quick["id"] != lab["id"]
    assert Path(_QUICK_YAML).read_text(encoding="utf-8") != lab_path.read_text(
        encoding="utf-8"
    )
