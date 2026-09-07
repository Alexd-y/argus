"""build_hydra_argv — pure Hydra form brute-force command construction."""

from __future__ import annotations

from src.tools.wordlists.credential_bruteforce import (
    DEFAULT_STAGED_DIR,
    LoginFormSpec,
    build_hydra_argv,
)
from src.tools.wordlists.credential_plan import CredentialTestPlan
from src.tools.wordlists.staging import CREDENTIALS_FILE, PASS_FILE, USERS_FILE


def _form(**kw) -> LoginFormSpec:
    base = {
        "host": "alleksy.com",
        "port": 443,
        "path": "/login",
        "body_template": "username=^USER^&password=^PASS^",
        "failure_marker": "Invalid credentials",
        "scheme": "https",
    }
    base.update(kw)
    return LoginFormSpec(**base)


def test_disabled_plan_returns_none():
    assert build_hydra_argv(CredentialTestPlan(enabled=False), _form()) is None


def test_invalid_form_returns_none():
    plan = CredentialTestPlan(enabled=True, inline_usernames=("admin",))
    # missing ^PASS^ placeholder → invalid
    assert build_hydra_argv(plan, _form(body_template="username=^USER^")) is None
    # empty host → invalid
    assert build_hydra_argv(plan, _form(host="")) is None


def test_user_pass_list_argv():
    plan = CredentialTestPlan(enabled=True)  # no pair path → -L/-P
    argv = build_hydra_argv(plan, _form())
    assert argv is not None
    assert argv[:4] == ["docker", "exec", "argus-sandbox", "hydra"]
    assert "-L" in argv and f"{DEFAULT_STAGED_DIR}/{USERS_FILE}" in argv
    assert "-P" in argv and f"{DEFAULT_STAGED_DIR}/{PASS_FILE}" in argv
    assert "https-post-form" in argv
    assert "-C" not in argv


def test_pair_list_uses_combined_flag(tmp_path):
    pair = tmp_path / "creds.txt"
    pair.write_text("admin:admin\n", encoding="utf-8")
    plan = CredentialTestPlan(enabled=True, credential_pair_path=pair)
    argv = build_hydra_argv(plan, _form())
    assert argv is not None
    assert "-C" in argv and f"{DEFAULT_STAGED_DIR}/{CREDENTIALS_FILE}" in argv
    assert "-L" not in argv


def test_form_string_and_bounds():
    plan = CredentialTestPlan(enabled=True)
    argv = build_hydra_argv(plan, _form())
    assert argv is not None
    # form string carries path, body and F= failure condition
    form_str = argv[-1]
    assert form_str == "/login:username=^USER^&password=^PASS^:F=Invalid credentials"
    # bounded concurrency + stop-on-first
    assert "-t" in argv and "4" in argv
    assert "-f" in argv
    # explicit port + host + http scheme service
    assert "-s" in argv and "443" in argv
    assert "alleksy.com" in argv


def test_http_scheme_service():
    plan = CredentialTestPlan(enabled=True)
    argv = build_hydra_argv(plan, _form(scheme="http", port=80))
    assert argv is not None
    assert "http-post-form" in argv
