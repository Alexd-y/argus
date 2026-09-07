"""Full-Surface credential-testing authorization policy."""

from __future__ import annotations

from src.orchestration.auth_config import CredentialTestConfig
from src.orchestration.credential_testing_policy import (
    default_full_surface_credential_testing,
    is_full_surface,
    resolve_credential_testing,
)


def test_is_full_surface_by_profile():
    assert is_full_surface(scan_profile="deep") is True
    assert is_full_surface(scan_profile="light") is False
    assert is_full_surface(scan_profile="quick") is False


def test_is_full_surface_by_execution_mode():
    assert is_full_surface(execution_mode="lab_unrestricted") is True
    assert is_full_surface(execution_mode="lab") is True
    assert is_full_surface(execution_mode="production") is False


def test_default_is_bounded_and_enabled():
    d = default_full_surface_credential_testing()
    assert d.enabled is True
    assert d.credential_pair_wordlist == "argus-default-credentials"
    assert d.max_attempts == 500
    assert d.lockout_aware is True


def test_non_full_surface_force_disables_enabled_config():
    cfg = CredentialTestConfig(enabled=True, credential_pair_wordlist="argus-default-credentials")
    out = resolve_credential_testing(cfg, scan_profile="light")
    assert out is not None
    assert out.enabled is False


def test_non_full_surface_leaves_none():
    assert resolve_credential_testing(None, scan_profile="quick") is None


def test_full_surface_none_gets_default():
    out = resolve_credential_testing(None, scan_profile="deep")
    assert out is not None
    assert out.enabled is True
    assert out.password_wordlist == "seclists-passwords-top1000"


def test_full_surface_disabled_gets_default():
    cfg = CredentialTestConfig(enabled=False)
    out = resolve_credential_testing(cfg, execution_mode="lab_unrestricted")
    assert out is not None
    assert out.enabled is True


def test_full_surface_keeps_explicit_config():
    cfg = CredentialTestConfig(
        enabled=True, password_wordlist="seclists-passwords-top10k", max_attempts=42
    )
    out = resolve_credential_testing(cfg, scan_profile="deep")
    assert out is cfg  # explicit operator config preserved verbatim
    assert out.max_attempts == 42
