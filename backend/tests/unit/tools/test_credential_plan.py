"""build_credential_test_plan — auth_config → resolved wordlist files (offline)."""

from __future__ import annotations

import pytest
from src.orchestration.auth_config import CredentialTestConfig
from src.tools.wordlists.credential_plan import build_credential_test_plan
from src.tools.wordlists.registry import WordlistError, WordlistRegistry


def _reg() -> WordlistRegistry:
    return WordlistRegistry()


def test_disabled_config_yields_disabled_plan():
    plan = build_credential_test_plan(CredentialTestConfig(enabled=False), _reg())
    assert plan.enabled is False
    assert plan.credential_pair_path is None


def test_builtin_pair_list_resolves_offline():
    cfg = CredentialTestConfig(enabled=True, credential_pair_wordlist="argus-default-credentials")
    plan = build_credential_test_plan(cfg, _reg())
    assert plan.enabled is True
    assert plan.credential_pair_path is not None
    assert plan.credential_pair_path.is_file()
    assert plan.max_attempts == 200


def test_category_mismatch_is_rejected():
    # a password list id passed where a username list is expected
    cfg = CredentialTestConfig(enabled=True, username_wordlist="seclists-passwords-top10k")
    with pytest.raises(WordlistError, match="expected 'username'"):
        build_credential_test_plan(cfg, _reg())


def test_enabled_without_usable_source_fails_closed():
    cfg = CredentialTestConfig(enabled=True, usernames=["admin"])  # usernames but no password/pair
    with pytest.raises(WordlistError, match="no usable source"):
        build_credential_test_plan(cfg, _reg())


def test_remote_password_list_needs_fetch():
    cfg = CredentialTestConfig(
        enabled=True, password_wordlist="seclists-passwords-top1000", usernames=["admin"]
    )
    with pytest.raises(WordlistError, match="not cached"):
        build_credential_test_plan(cfg, _reg(), allow_fetch=False)


def test_bounded_params_propagate():
    cfg = CredentialTestConfig(
        enabled=True,
        credential_pair_wordlist="argus-default-credentials",
        max_attempts=42,
        rate_per_minute=15,
        lockout_aware=False,
        stop_on_success=False,
    )
    plan = build_credential_test_plan(cfg, _reg())
    assert plan.max_attempts == 42
    assert plan.rate_per_minute == 15
    assert plan.lockout_aware is False
    assert plan.stop_on_success is False
