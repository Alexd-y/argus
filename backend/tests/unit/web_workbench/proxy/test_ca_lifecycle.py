"""Unit tests for proxy CA lifecycle: sealing, issuance, reload (WB-P2b-1)."""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from src.web_workbench.proxy.ca_lifecycle import (
    SEALING_KEY_REF,
    FernetSecretSealer,
    build_sealer_from_settings,
    issue_ca,
    load_ca,
)
from src.web_workbench.proxy.ca_manager import CaError


@pytest.fixture()
def sealer() -> FernetSecretSealer:
    return FernetSecretSealer(Fernet.generate_key())


def test_fernet_sealer_round_trip(sealer: FernetSecretSealer) -> None:
    plaintext = b"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n"
    sealed = sealer.seal(plaintext)
    assert sealed != plaintext  # ciphertext must differ from plaintext
    assert plaintext not in sealed
    assert sealer.unseal(sealed) == plaintext


def test_fernet_sealer_rejects_invalid_key() -> None:
    with pytest.raises(CaError):
        FernetSecretSealer(b"not-a-valid-fernet-key")


def test_unseal_wrong_key_fails_closed(sealer: FernetSecretSealer) -> None:
    sealed = sealer.seal(b"payload")
    other = FernetSecretSealer(Fernet.generate_key())
    with pytest.raises(CaError):
        other.unseal(sealed)


def test_issue_ca_seals_key_and_exposes_public_only(sealer: FernetSecretSealer) -> None:
    sealed_ca = issue_ca(sealer, common_name="Test CA")

    assert sealed_ca.secrets_ref == SEALING_KEY_REF
    assert sealed_ca.certificate_pem.startswith("-----BEGIN CERTIFICATE-----")
    assert len(sealed_ca.fingerprint_sha256) == 64
    # The sealed key must not contain the plaintext PEM marker.
    assert b"PRIVATE KEY" not in sealed_ca.sealed_key
    # It must be unsealable back into a real private key PEM.
    assert b"PRIVATE KEY" in sealer.unseal(sealed_ca.sealed_key)


def test_load_ca_reconstructs_and_signs_leaf(sealer: FernetSecretSealer) -> None:
    sealed_ca = issue_ca(sealer)
    ca = load_ca(
        sealer,
        certificate_pem=sealed_ca.certificate_pem,
        sealed_key=sealed_ca.sealed_key,
    )
    assert ca.fingerprint_sha256 == sealed_ca.fingerprint_sha256

    leaf = ca.issue_leaf("juice-shop.local")
    assert leaf.host == "juice-shop.local"
    assert b"BEGIN CERTIFICATE" in leaf.certificate_pem


def test_build_sealer_from_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    from src.web_workbench.proxy import ca_lifecycle

    monkeypatch.setattr(ca_lifecycle.settings, "wb_ca_sealing_key", None)
    assert build_sealer_from_settings() is None

    monkeypatch.setattr(ca_lifecycle.settings, "wb_ca_sealing_key", Fernet.generate_key().decode())
    built = build_sealer_from_settings()
    assert built is not None
    round_trip = built.unseal(built.seal(b"x"))
    assert round_trip == b"x"
