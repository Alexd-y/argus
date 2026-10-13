"""Wave 3 / etap 7 — the verification kit blocks release on a leaked secret (R-5.7.3)."""

from __future__ import annotations

import pytest
from src.reports.verification_kit import VerificationKitSecretError, _assert_no_secrets


def test_clean_kit_passes() -> None:
    # No secret → no raise.
    _assert_no_secrets(
        {
            "repro/a.json": b'{"title": "Reflected XSS", "request": "GET /s?q=<x>"}',
            "evidence/b.json": b'{"kind": "har", "sha256": "ab12"}',
        }
    )


# NB: the secret literals are ASSEMBLED at runtime from fragments so the full
# token never appears in this source file — otherwise GitHub push-protection
# (secret scanning) would block the push of this very test. The assembled value
# still exercises verification_kit._CREDENTIAL_PATTERNS.
_AWS_KEY = b"AKIA" + b"IOSFODNN7" + b"EXAMPLE"
_PEM = b"-----BEGIN RSA " + b"PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
_JWT = b"eyJhbGciOiJIUzI1NiJ9." + b"eyJzdWIiOiIxMjM0NTY3ODkwIn0." + b"abcDEFghiJKLmno"
_SLACK = b"xox" + b"b-123456789012-abcdefghijklmno"
_GH = b"ghp" + b"_abcdefghijklmnopqrstuvwxyz0123456789"


@pytest.mark.parametrize("secret", [_AWS_KEY, _PEM, _JWT, _SLACK, _GH])
def test_planted_secret_blocks_release(secret: bytes) -> None:
    with pytest.raises(VerificationKitSecretError):
        _assert_no_secrets({"repro/x.json": b'{"k": "' + secret + b'"}'})


def test_block_is_per_file_and_names_the_file() -> None:
    with pytest.raises(VerificationKitSecretError, match="leak.json"):
        _assert_no_secrets(
            {
                "repro/ok.json": b'{"title": "fine"}',
                "evidence/leak.json": b'{"k": "' + _AWS_KEY + b'"}',
            }
        )
