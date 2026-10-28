"""Redaction tests — plaintext secrets / PII never survive into a summary."""

from __future__ import annotations

from src.intel.dark_web.redaction import build_redacted_summary, mask_email, redact_text


def test_mask_email_keeps_domain_hides_local() -> None:
    assert mask_email("alice@example.com") == "a***@example.com"
    assert mask_email("a@example.com") == "a***@example.com"
    assert mask_email("not-an-email") == "not-an-email"


def test_combolist_password_is_dropped() -> None:
    out = redact_text("victim@example.com:SuperSecret123!")
    assert "SuperSecret123!" not in out
    assert "<redacted>" in out
    assert "example.com" in out  # domain preserved for the analyst


def test_assigned_secrets_redacted() -> None:
    for s in [
        "password=hunter2",
        "api_key: AKIAIOSFODNN7EXAMPLE",
        "Authorization: Bearer abcdef.ghijkl.mnopqr",
        "token=ghp_0123456789abcdef0123",
    ]:
        out = redact_text(s)
        assert "hunter2" not in out
        assert "AKIAIOSFODNN7EXAMPLE" not in out
        assert "abcdef.ghijkl.mnopqr" not in out
        assert "ghp_0123456789abcdef0123" not in out


def test_private_key_block_redacted() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAImportantSecret\n-----END RSA PRIVATE KEY-----"
    out = redact_text(pem)
    assert "ImportantSecret" not in out
    assert "<redacted_private_key>" in out


def test_ssn_and_card_redacted() -> None:
    out = redact_text("SSN 123-45-6789 card 4111 1111 1111 1111")
    assert "123-45-6789" not in out
    assert "4111 1111 1111 1111" not in out


def test_build_summary_is_bounded_and_clean() -> None:
    raw = "combolist user@corp.com:Password1 " * 500
    summary = build_redacted_summary(raw, prefix="[breach_db]")
    assert "Password1" not in summary
    assert len(summary) <= 2000
    assert summary.startswith("[breach_db]")
