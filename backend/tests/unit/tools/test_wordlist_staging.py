"""Wordlist staging — plan + materialize CredentialTestPlan into a sandbox in_dir."""

from __future__ import annotations

from src.orchestration.auth_config import CredentialTestConfig
from src.tools.wordlists.credential_plan import (
    CredentialTestPlan,
    build_credential_test_plan,
)
from src.tools.wordlists.registry import WordlistRegistry
from src.tools.wordlists.staging import (
    CREDENTIALS_FILE,
    PASS_FILE,
    USERS_FILE,
    materialize_staging,
    plan_wordlist_staging,
)


def test_disabled_plan_stages_nothing():
    assert plan_wordlist_staging(CredentialTestPlan(enabled=False)) == []


def test_inline_usernames_become_users_file_content():
    plan = CredentialTestPlan(enabled=True, inline_usernames=("admin", "editor"))
    stages = plan_wordlist_staging(plan)
    users = next(s for s in stages if s.dest_name == USERS_FILE)
    assert users.source is None
    assert users.content == "admin\neditor\n"


def test_pair_list_stages_credentials_file(tmp_path):
    src = tmp_path / "pairs.txt"
    src.write_text("admin:admin\n", encoding="utf-8")
    plan = CredentialTestPlan(enabled=True, credential_pair_path=src)
    stages = plan_wordlist_staging(plan)
    assert any(s.dest_name == CREDENTIALS_FILE and s.source == src for s in stages)


def test_materialize_writes_and_copies(tmp_path):
    pass_src = tmp_path / "src_pass.txt"
    pass_src.write_text("password\n123456\n", encoding="utf-8")
    plan = CredentialTestPlan(
        enabled=True, inline_usernames=("admin",), password_path=pass_src
    )
    in_dir = tmp_path / "in"
    written = materialize_staging(plan_wordlist_staging(plan), in_dir)
    names = {p.name for p in written}
    assert names == {USERS_FILE, PASS_FILE}
    assert (in_dir / USERS_FILE).read_text(encoding="utf-8") == "admin\n"
    assert (in_dir / PASS_FILE).read_text(encoding="utf-8") == "password\n123456\n"


def test_end_to_end_from_builtin_pair_list(tmp_path):
    # Real registry builtin default-credentials → staged credentials.txt.
    cfg = CredentialTestConfig(enabled=True, credential_pair_wordlist="argus-default-credentials")
    plan = build_credential_test_plan(cfg, WordlistRegistry())
    in_dir = tmp_path / "in"
    written = materialize_staging(plan_wordlist_staging(plan), in_dir)
    creds = in_dir / CREDENTIALS_FILE
    assert creds in written
    assert "admin:admin" in creds.read_text(encoding="utf-8")


def test_materialize_creates_missing_in_dir(tmp_path):
    plan = CredentialTestPlan(enabled=True, inline_usernames=("root",))
    in_dir = tmp_path / "deep" / "in"
    assert not in_dir.exists()
    materialize_staging(plan_wordlist_staging(plan), in_dir)
    assert (in_dir / USERS_FILE).is_file()
