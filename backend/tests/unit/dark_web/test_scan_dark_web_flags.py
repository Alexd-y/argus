"""scan_dark_web_flags: nested / legacy-flat / empty, default disabled."""

from __future__ import annotations

from src.recon.scan_options_dark_web import scan_dark_web_flags


def test_empty_defaults_disabled() -> None:
    f = scan_dark_web_flags(None)
    assert f["enabled"] is False
    assert f["include_domain_emails"] is True
    assert f["include_findings"] is True
    assert "breach_db" in f["networks"]


def test_nested_dark_web() -> None:
    f = scan_dark_web_flags({"dark_web": {"enabled": True, "include_findings": False}})
    assert f["enabled"] is True
    assert f["include_findings"] is False
    assert f["include_domain_emails"] is True


def test_legacy_flat_keys() -> None:
    f = scan_dark_web_flags({"enabled": True, "include_domain_emails": False})
    assert f["enabled"] is True
    assert f["include_domain_emails"] is False


def test_networks_override() -> None:
    f = scan_dark_web_flags({"dark_web": {"enabled": True, "networks": ["tor", "telegram"]}})
    assert f["networks"] == ["tor", "telegram"]


def test_non_dict_is_safe() -> None:
    assert scan_dark_web_flags("nope")["enabled"] is False  # type: ignore[arg-type]


def test_empty_networks_falls_back_to_default() -> None:
    f = scan_dark_web_flags({"dark_web": {"enabled": True, "networks": []}})
    assert "breach_db" in f["networks"]
