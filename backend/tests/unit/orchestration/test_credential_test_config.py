"""CredentialTestConfig — bounded, catalog-referencing credential testing config."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from src.orchestration.auth_config import CredentialTestConfig, TargetConfig


def test_defaults_are_safe_and_disabled():
    c = CredentialTestConfig()
    assert c.enabled is False
    assert c.max_attempts == 200
    assert c.rate_per_minute == 60
    assert c.lockout_aware is True
    assert c.stop_on_success is True


def test_accepts_wordlist_ids():
    c = CredentialTestConfig(
        enabled=True,
        username_wordlist="seclists-usernames-top",
        password_wordlist="seclists-passwords-top10k",
        credential_pair_wordlist="argus-default-credentials",
        max_attempts=5000,
        rate_per_minute=120,
    )
    assert c.enabled is True
    assert c.password_wordlist == "seclists-passwords-top10k"


def test_invalid_wordlist_id_rejected():
    with pytest.raises(ValidationError):
        CredentialTestConfig(password_wordlist="Bad Id!")  # spaces/upper not allowed


def test_max_attempts_must_be_positive():
    with pytest.raises(ValidationError):
        CredentialTestConfig(max_attempts=0)


def test_rate_ceiling_enforced():
    with pytest.raises(ValidationError):
        CredentialTestConfig(rate_per_minute=100000)


def test_extra_fields_forbidden():
    with pytest.raises(ValidationError):
        CredentialTestConfig(unknown_field=1)


def test_target_config_carries_credential_testing_via_json():
    tc = TargetConfig.from_json(
        {
            "description": "auth engagement",
            "credential_testing": {
                "enabled": True,
                "password_wordlist": "seclists-passwords-top1000",
                "usernames": ["admin", "editor"],
            },
        }
    )
    assert tc.credential_testing is not None
    assert tc.credential_testing.enabled is True
    assert tc.credential_testing.usernames == ["admin", "editor"]


def test_credential_testing_defaults_none():
    tc = TargetConfig()
    assert tc.credential_testing is None


def test_from_scan_options_preserves_credential_testing():
    tc = TargetConfig.from_scan_options(
        {"auth_config": {"credential_testing": {"enabled": True, "max_attempts": 10}}}
    )
    assert tc is not None
    assert tc.credential_testing is not None
    assert tc.credential_testing.max_attempts == 10
