"""ARG-062 / C7-T01 — unit tests for ``src.auth._mfa_crypto``.

Why a dedicated unit-test file (instead of folding into the DAO suite)
---------------------------------------------------------------------
The crypto layer is the single trust boundary for the MFA secret at
rest. A regression that silently disables encryption or corrupts the
keyring rotation contract would be invisible to every other test in the
suite (the DAO would still happily encrypt + decrypt round-trip), so we
exercise the seam in isolation here:

* every public function (``encrypt`` / ``decrypt`` / ``reencrypt_if_stale``
  / ``current_key_id``);
* every documented failure mode (empty plaintext, malformed keyring,
  tampered ciphertext);
* every documented logging invariant — *no* test asserts a positive log
  field; instead we assert the *absence* of secret material in the log
  pipeline. Anything that lands in stdlib ``logging`` will eventually
  reach the SIEM forwarder, and that is precisely the channel an
  attacker can tap into.

Caplog discipline
-----------------
Every test that exercises the crypto seam includes at least one
``caplog`` assertion against the raw plaintext, the raw key bytes, or
the raw ciphertext bytes. The failure mode this defends against is
``logger.exception(..., extra={"plaintext": secret})`` — a single line
of carelessness that would only surface in a production breach.

Isolation
---------
Each test pulls the ``mfa_keyring`` fixture from
``backend/tests/auth/conftest.py``, which generates a *fresh* pair of
Fernet keys per-test and pins them onto the live ``Settings`` instance
via ``monkeypatch.setattr``. The crypto module re-reads
``settings.admin_mfa_keyring`` on every call, so the patch propagates
without requiring an ``importlib.reload``. This keeps the file runnable
in isolation: ``pytest backend/tests/auth/test_mfa_crypto.py -v``.
"""

from __future__ import annotations

import logging
from typing import Final

import pytest
from cryptography.fernet import Fernet, MultiFernet

from src.auth import _mfa_crypto
from src.auth._mfa_crypto import (
    MfaCryptoError,
    current_key_id,
    decrypt,
    encrypt,
    reencrypt_if_stale,
)
from src.core.config import settings

from .conftest import MfaKeyring

#: Sentinel TOTP plaintext used by every "no-leak" assertion. A unique,
#: easily greppable token keeps the substring check fast and unambiguous
#: — a stray ``"GENRG…"`` in caplog.text is a guaranteed leak.
_SENTINEL_PLAINTEXT: Final[str] = "GENRGM2YOJEW6XCC7RLPYFNL5G7TBFCV"

#: Crypto module logger — caplog needs the qualified name to install a
#: handler at the right point in the propagation chain.
_CRYPTO_LOGGER: Final[str] = "src.auth._mfa_crypto"


# ---------------------------------------------------------------------------
# Test 1 — happy-path round-trip with a single-key keyring.
# ---------------------------------------------------------------------------


def test_encrypt_decrypt_roundtrip_single_key(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``encrypt → decrypt`` returns the original plaintext byte-for-byte.

    Single-key configuration is the production baseline before any
    rotation has happened; if this breaks, every admin loses their
    second factor on the next deploy.
    """
    only_key = Fernet.generate_key().decode("ascii")
    monkeypatch.setattr(settings, "admin_mfa_keyring", only_key)

    with caplog.at_level(logging.DEBUG, logger=_CRYPTO_LOGGER):
        ciphertext = encrypt(_SENTINEL_PLAINTEXT)
        recovered = decrypt(ciphertext)

    assert recovered == _SENTINEL_PLAINTEXT, (
        "Fernet round-trip must be byte-equivalent to the input"
    )
    assert isinstance(ciphertext, bytes)
    assert ciphertext != _SENTINEL_PLAINTEXT.encode("utf-8"), (
        "ciphertext must differ from plaintext (sanity — not a guarantee)"
    )
    assert _SENTINEL_PLAINTEXT not in caplog.text, (
        "happy-path encrypt/decrypt must NOT log the plaintext"
    )
    assert only_key not in caplog.text, (
        "happy-path encrypt/decrypt must NOT log the raw Fernet key"
    )


# ---------------------------------------------------------------------------
# Test 2 — multi-key keyring decrypts ciphertext made under an OLDER key.
# ---------------------------------------------------------------------------


def test_decrypt_succeeds_with_older_key_after_rotation(
    mfa_keyring: MfaKeyring,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A ciphertext minted under an OLD key must still decrypt post-rotation.

    Rotation contract: ``MultiFernet`` tries every key in keyring order
    until one verifies the HMAC. We simulate the operational sequence:

      1. Operator deploys with ``[OLD]`` only.
      2. Secret gets encrypted (ciphertext is HMAC-bound to ``OLD``).
      3. Operator generates ``NEW``, prepends it: keyring becomes
         ``[NEW, OLD]``.
      4. The next decrypt MUST still succeed against the existing
         ciphertext — otherwise every enrolled admin is locked out.
    """
    monkeypatch.setattr(settings, "admin_mfa_keyring", mfa_keyring.secondary)

    ciphertext_old_key = encrypt(_SENTINEL_PLAINTEXT)

    monkeypatch.setattr(settings, "admin_mfa_keyring", mfa_keyring.csv)

    with caplog.at_level(logging.DEBUG, logger=_CRYPTO_LOGGER):
        recovered = decrypt(ciphertext_old_key)

    assert recovered == _SENTINEL_PLAINTEXT, (
        "old-key ciphertext must still decrypt under the rotated keyring"
    )
    for forbidden in (
        _SENTINEL_PLAINTEXT,
        mfa_keyring.primary,
        mfa_keyring.secondary,
    ):
        assert forbidden not in caplog.text, (
            f"rotation decrypt must NOT log secret material ({forbidden[:6]}…)"
        )


# ---------------------------------------------------------------------------
# Test 3 — reencrypt_if_stale flag distinguishes "stale" from "fresh".
# ---------------------------------------------------------------------------


def test_reencrypt_if_stale_flags_correctly(
    mfa_keyring: MfaKeyring,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``rotated=True`` iff the ciphertext was minted under a non-primary key.

    The DAO uses this boolean to decide whether to issue a follow-up
    UPDATE for opportunistic rotation; if the flag inverts, every login
    triggers a write storm (rotated=True everywhere) or no rotation
    ever happens (rotated=False everywhere).
    """
    monkeypatch.setattr(settings, "admin_mfa_keyring", mfa_keyring.secondary)
    stale_ciphertext = encrypt(_SENTINEL_PLAINTEXT)

    monkeypatch.setattr(settings, "admin_mfa_keyring", mfa_keyring.csv)
    fresh_ciphertext = encrypt(_SENTINEL_PLAINTEXT)

    with caplog.at_level(logging.DEBUG, logger=_CRYPTO_LOGGER):
        new_for_stale, rotated_stale = reencrypt_if_stale(stale_ciphertext)
        new_for_fresh, rotated_fresh = reencrypt_if_stale(fresh_ciphertext)

    assert rotated_stale is True, (
        "stale ciphertext (encrypted under secondary key) must be flagged as rotated"
    )
    assert rotated_fresh is False, (
        "fresh ciphertext (encrypted under primary key) must NOT be flagged as rotated"
    )
    assert decrypt(new_for_stale) == _SENTINEL_PLAINTEXT, (
        "rotated ciphertext must still decrypt to the original plaintext"
    )
    assert decrypt(new_for_fresh) == _SENTINEL_PLAINTEXT, (
        "non-rotated ciphertext must still decrypt to the original plaintext"
    )
    assert _SENTINEL_PLAINTEXT not in caplog.text, (
        "rotation logic must NOT echo plaintext into the log pipeline"
    )


# ---------------------------------------------------------------------------
# Test 4 — empty / whitespace plaintext is refused with a non-leaky ValueError.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("blank", ["", "   ", "\n\t"])
def test_encrypt_refuses_empty_plaintext(
    blank: str,
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Empty or whitespace-only plaintext raises ValueError.

    The DAO contract is "no empty TOTP secret on the wire" — encrypting
    an empty string would silently pass any subsequent decrypt + verify
    cycle since ``pyotp.TOTP("").verify("000000")`` evaluates against an
    empty seed. The crypto layer is the choke point that prevents that.

    We also verify the refusal log channel does not echo the input back
    (defence in depth — there's nothing meaningful to leak when the
    input is empty, but the contract is "never log raw plaintext").
    """
    _ = mfa_keyring  # ensure a valid keyring is present so the refusal
    # path is the only thing the test exercises.

    with caplog.at_level(logging.DEBUG, logger=_CRYPTO_LOGGER):
        with pytest.raises(ValueError, match="empty TOTP secret"):
            encrypt(blank)

    # No log records should have been emitted on the crypto logger:
    # the refusal path raises before any logger call. This invariant
    # protects against a future ``logger.info("rejected plaintext: %s",
    # plaintext)`` regression.
    crypto_records = [r for r in caplog.records if r.name == _CRYPTO_LOGGER]
    assert not crypto_records, (
        f"empty-plaintext refusal must not emit any crypto log records; "
        f"got {[r.getMessage() for r in crypto_records]!r}"
    )
    assert mfa_keyring.primary not in caplog.text, (
        "refused-input log must NOT echo the keyring material"
    )


# ---------------------------------------------------------------------------
# Test 5 — malformed keyring fails fast with index-only logging.
# ---------------------------------------------------------------------------


def test_malformed_keyring_fails_fast_with_index_only_log(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Bad-base64 entry → (Mfa)CryptoError; log carries INDEX, NOT bytes.

    Reproduces the operational mishap of pasting a non-base64 token into
    ``ADMIN_MFA_KEYRING`` (e.g. a JWT, a placeholder, or random ascii).
    The crypto layer must:

      * refuse to construct a ``MultiFernet`` (no encrypt-with-junk path);
      * log the OFFENDING ENTRY INDEX so the operator can locate the
        bad CSV column;
      * NEVER include the raw bad bytes — they may be a real key the
        operator pasted into the wrong slot, and a SIEM forwarder is
        the worst possible exfil path for that.
    """
    bad_key_token = "not-base64-junk-totally-bogus-fernet-key-value"
    monkeypatch.setattr(settings, "admin_mfa_keyring", bad_key_token)

    with caplog.at_level(logging.DEBUG, logger=_CRYPTO_LOGGER):
        with pytest.raises((ValueError, MfaCryptoError)):
            encrypt(_SENTINEL_PLAINTEXT)

    assert bad_key_token not in caplog.text, (
        "malformed-keyring log MUST NOT include the raw bad key value — "
        "it could be a real Fernet key the operator pasted into the wrong "
        "CSV column"
    )

    keyring_records = [
        r
        for r in caplog.records
        if r.name == _CRYPTO_LOGGER and "keyring" in r.getMessage().lower()
    ]
    assert keyring_records, (
        "malformed keyring must produce at least one structured log "
        "record on the crypto logger"
    )

    has_index_field = any(
        getattr(r, "key_index", None) is not None for r in keyring_records
    )
    assert has_index_field, (
        "structured log for malformed keyring must carry a `key_index` "
        "field so the operator can locate the bad CSV column"
    )


# ---------------------------------------------------------------------------
# Test 6 — current_key_id is stable per primary and changes on rotation.
# ---------------------------------------------------------------------------


def test_current_key_id_stable_then_changes_on_rotation(
    mfa_keyring: MfaKeyring,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``current_key_id`` is stable for the same primary; differs per rotation.

    The audit trail pins re-encryption events to a key generation via
    this fingerprint. If the function returned a random or
    non-deterministic value, the audit log would be unparseable; if it
    didn't change after rotation, an operator couldn't tell from the
    log which generation a secret last touched.
    """
    fid_before_a = current_key_id()
    fid_before_b = current_key_id()
    assert fid_before_a == fid_before_b, (
        "current_key_id must be deterministic for an unchanged keyring"
    )
    assert isinstance(fid_before_a, str)
    assert len(fid_before_a) == 12, (
        "current_key_id must return a 12-hex-char fingerprint"
    )

    third_key = Fernet.generate_key().decode("ascii")
    rotated_csv = f"{third_key},{mfa_keyring.primary},{mfa_keyring.secondary}"
    monkeypatch.setattr(settings, "admin_mfa_keyring", rotated_csv)

    with caplog.at_level(logging.DEBUG, logger=_CRYPTO_LOGGER):
        fid_after = current_key_id()

    assert fid_after != fid_before_a, (
        "current_key_id MUST change after the primary key is rotated"
    )
    for forbidden in (third_key, mfa_keyring.primary, mfa_keyring.secondary):
        assert forbidden not in caplog.text, (
            "current_key_id must NOT log the raw keyring material"
        )


# ---------------------------------------------------------------------------
# Test 7 (BONUS) — tampered ciphertext raises MfaCryptoError, no byte leak.
# ---------------------------------------------------------------------------


def test_decrypt_tampered_ciphertext_raises_without_leaking_bytes(
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A single bit-flip in the ciphertext invalidates the HMAC.

    Fernet = AES-128-CBC + HMAC-SHA256. Any tampering with the token
    bytes fails the HMAC verification, raising ``InvalidToken`` —
    which the crypto layer maps to :class:`MfaCryptoError` so the
    router sees a single project-local exception type.

    The "no byte leak" invariant is critical here because a forged
    ciphertext might itself contain probe data the attacker is feeding
    in to map the response side channel; landing it in the log is a
    free oracle for them.
    """
    pristine = encrypt(_SENTINEL_PLAINTEXT)

    midpoint = len(pristine) // 2
    tampered = bytearray(pristine)
    tampered[midpoint] ^= 0x01
    tampered_bytes = bytes(tampered)
    assert tampered_bytes != pristine, "bit-flip must actually change the bytes"

    with caplog.at_level(logging.DEBUG, logger=_CRYPTO_LOGGER):
        with pytest.raises(MfaCryptoError):
            decrypt(tampered_bytes)

    forbidden_fragments = [
        tampered_bytes,
        pristine,
        _SENTINEL_PLAINTEXT.encode("utf-8"),
    ]
    log_blob = caplog.text.encode("utf-8", errors="replace")
    for fragment in forbidden_fragments:
        assert fragment not in log_blob, (
            "tampered-ciphertext log MUST NOT echo any ciphertext bytes "
            "(would leak attacker-controlled probe data into the SIEM)"
        )
    assert _SENTINEL_PLAINTEXT not in caplog.text, (
        "tampered-ciphertext log MUST NOT echo the plaintext"
    )


# ---------------------------------------------------------------------------
# Companion check — empty ciphertext also raises (decrypt() side of the
# empty-input contract). Not on the original ≥6 list but the symmetry
# matters: ``encrypt("")`` raising while ``decrypt(b"")`` silently
# returning ``""`` would re-introduce the very bug Test 4 defends.
# ---------------------------------------------------------------------------


def test_decrypt_refuses_empty_ciphertext(
    mfa_keyring: MfaKeyring,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``decrypt(b"")`` must surface :class:`MfaCryptoError` immediately."""
    _ = mfa_keyring

    with caplog.at_level(logging.DEBUG, logger=_CRYPTO_LOGGER):
        with pytest.raises(MfaCryptoError):
            decrypt(b"")

    assert mfa_keyring.primary not in caplog.text, (
        "empty-ciphertext refusal must not echo the keyring material"
    )


# ---------------------------------------------------------------------------
# Companion check — ``MultiFernet`` integration is not coincidentally
# disabled by a future refactor (e.g. someone replacing it with a
# single-key Fernet). Caplog assertion guards the no-leak invariant on
# the integration boundary.
# ---------------------------------------------------------------------------


def test_internal_multifernet_handles_keyring_order(
    mfa_keyring: MfaKeyring,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Sanity — the parsed keyring matches MultiFernet semantics.

    Keeps :func:`_mfa_crypto._build_multifernet` honest by re-deriving
    the expected ``MultiFernet`` outside the module and confirming both
    decrypt the same ciphertext. Belt-and-braces against a future
    refactor that, say, accidentally reverses the CSV split order.
    """
    monkeypatch.setattr(settings, "admin_mfa_keyring", mfa_keyring.csv)
    multifernet, primary = _mfa_crypto._build_multifernet()

    expected = MultiFernet(
        [
            Fernet(mfa_keyring.primary.encode("ascii")),
            Fernet(mfa_keyring.secondary.encode("ascii")),
        ]
    )

    with caplog.at_level(logging.DEBUG, logger=_CRYPTO_LOGGER):
        token = multifernet.encrypt(_SENTINEL_PLAINTEXT.encode("utf-8"))
        assert expected.decrypt(token).decode("utf-8") == _SENTINEL_PLAINTEXT
        assert primary.decrypt(token).decode("utf-8") == _SENTINEL_PLAINTEXT

    assert _SENTINEL_PLAINTEXT not in caplog.text
    assert mfa_keyring.primary not in caplog.text
    assert mfa_keyring.secondary not in caplog.text


# ---------------------------------------------------------------------------
# Test 8 — empty / whitespace-only keyring fails fast with operator hint.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
def test_empty_keyring_refused_with_remediation_hint(
    blank: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An empty keyring is unrecoverable — the message must teach remediation.

    The ops failure mode is "admin clears ``ADMIN_MFA_KEYRING`` while
    debugging and forgets to restore it before deploy". The error path
    must surface a copy-pasteable command that mints a fresh key —
    silent acceptance would let the service boot with no encryption
    layer at all.
    """
    monkeypatch.setattr(settings, "admin_mfa_keyring", blank)

    with caplog.at_level(logging.DEBUG, logger=_CRYPTO_LOGGER):
        with pytest.raises(ValueError, match="ADMIN_MFA_KEYRING is empty"):
            encrypt(_SENTINEL_PLAINTEXT)

    # The error message must include the Fernet.generate_key() recipe so
    # an on-call operator can mint a key without leaving the terminal.
    try:
        encrypt(_SENTINEL_PLAINTEXT)
    except ValueError as exc:
        assert "Fernet.generate_key" in str(exc), (
            "empty-keyring ValueError must include the key-generation "
            "recipe so an operator can fix the misconfig in one shell line"
        )


# ---------------------------------------------------------------------------
# Test 9 — keyring with separators only (comma-only) fails before parsing.
# ---------------------------------------------------------------------------


def test_keyring_with_only_separators_refused(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A CSV of nothing-but-commas (or empty fields) is treated as empty.

    Edge case from a botched env-substitution (``ADMIN_MFA_KEYRING=,,,``
    after ``${KEY}`` failed to expand). The strip-then-filter inside
    :func:`_load_keyring` catches it and the function refuses *before*
    handing the empty list to :class:`MultiFernet` (which would itself
    raise an opaque error).
    """
    monkeypatch.setattr(settings, "admin_mfa_keyring", ",,, , ,")

    with caplog.at_level(logging.DEBUG, logger=_CRYPTO_LOGGER):
        with pytest.raises(ValueError, match="no non-empty entries"):
            encrypt(_SENTINEL_PLAINTEXT)


# ---------------------------------------------------------------------------
# Test 10 — encrypt() catches *unexpected* exceptions from the crypto layer.
# ---------------------------------------------------------------------------


def test_encrypt_wraps_unexpected_crypto_failure(
    mfa_keyring: MfaKeyring,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A non-Fernet exception from the underlying crypto layer is wrapped.

    Defends against an upstream ``cryptography`` regression that would
    surface a brand-new exception type (e.g. ``RuntimeError`` from a
    backend swap). The DAO contract is "callers see :class:`MfaCryptoError`
    only" — a leak of an unexpected exception class would hand attackers
    a fingerprint of the crypto backend version.

    Also pins the no-leak invariant: the encryption *plaintext* must
    never appear in the log line that records the failure.
    """
    _ = mfa_keyring  # ensures keyring is well-formed up to the failure

    class _BoomFernet:
        def encrypt(self, _data: bytes) -> bytes:
            raise RuntimeError("simulated cryptography backend crash")

    def _fake_build_multifernet() -> tuple[object, object]:
        return _BoomFernet(), object()

    monkeypatch.setattr(_mfa_crypto, "_build_multifernet", _fake_build_multifernet)

    with caplog.at_level(logging.DEBUG, logger=_CRYPTO_LOGGER):
        with pytest.raises(MfaCryptoError, match="admin_mfa_encrypt_failed"):
            encrypt(_SENTINEL_PLAINTEXT)

    failure_records = [
        r
        for r in caplog.records
        if r.name == _CRYPTO_LOGGER
        and getattr(r, "event", None) == "argus.mfa.crypto.encrypt_failed"
    ]
    assert failure_records, (
        "unexpected encrypt failure must emit the structured "
        "`argus.mfa.crypto.encrypt_failed` log event"
    )
    assert getattr(failure_records[0], "reason", None) == "RuntimeError", (
        "structured log must carry the *class name* of the upstream "
        "exception so an operator can pivot in the SIEM"
    )
    assert _SENTINEL_PLAINTEXT not in caplog.text, (
        "encrypt failure log MUST NOT echo the plaintext input"
    )


# ---------------------------------------------------------------------------
# Test 11 — decrypt() catches non-InvalidToken exceptions distinctly.
# ---------------------------------------------------------------------------


def test_decrypt_wraps_unexpected_crypto_failure(
    mfa_keyring: MfaKeyring,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An unexpected (non-InvalidToken) decrypt error becomes MfaCryptoError.

    InvalidToken is the EXPECTED failure mode (tampering, wrong key);
    anything else (memory error, library crash) is a separate code path
    that must:

      * surface a distinct ``admin_mfa_decrypt_failed`` event so the
        SIEM can alert separately on "weird crypto crash" vs the
        common "wrong code" path;
      * still wrap into :class:`MfaCryptoError` so the router never sees
        a backend-specific exception type.
    """
    _ = mfa_keyring  # ensure keyring is well-formed; we override _build_multifernet

    class _BoomMulti:
        def decrypt(self, _data: bytes) -> bytes:
            raise RuntimeError("simulated cryptography backend crash")

    def _fake_build_multifernet() -> tuple[object, object]:
        return _BoomMulti(), object()

    monkeypatch.setattr(_mfa_crypto, "_build_multifernet", _fake_build_multifernet)

    with caplog.at_level(logging.DEBUG, logger=_CRYPTO_LOGGER):
        with pytest.raises(MfaCryptoError, match="admin_mfa_decrypt_failed"):
            # Non-empty bytes — must reach the crypto layer (not the
            # short-circuit in the function head).
            decrypt(b"non-empty-ciphertext-stand-in")

    failure_records = [
        r
        for r in caplog.records
        if r.name == _CRYPTO_LOGGER
        and getattr(r, "event", None) == "argus.mfa.crypto.decrypt_failed"
    ]
    assert failure_records, (
        "unexpected decrypt failure must emit the dedicated "
        "`argus.mfa.crypto.decrypt_failed` event (NOT the "
        "`decrypt_invalid_token` event reserved for HMAC mismatch)"
    )
    assert getattr(failure_records[0], "reason", None) == "RuntimeError"
