"""CA lifecycle: sealing, issuance and loading of proxy MITM CAs (WB-P2b-1).

The proxy MITM CA private key must never be persisted in plaintext or logged.
This module seals it with an external KEK (a Fernet key sourced from
``settings.wb_ca_sealing_key`` / ``WB_CA_SEALING_KEY``) before it reaches the
database, and unseals it only in-process when the daemon needs to sign a leaf.

Fail-closed: if no sealing key is configured, :func:`build_sealer_from_settings`
returns ``None`` and CA issuance is refused (the API returns 503) — the system
never falls back to storing an unsealed key.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from cryptography.fernet import Fernet, InvalidToken

from src.core.config import settings
from src.web_workbench.proxy.ca_manager import CaError, CertificateAuthority

#: Recorded in ``ca_secrets_ref`` so operators know which KEK sealed a CA.
SEALING_KEY_REF = "env:WB_CA_SEALING_KEY"


class SecretSealer(Protocol):
    """Seals / unseals sensitive bytes with an external key (KEK)."""

    def seal(self, plaintext: bytes) -> bytes: ...

    def unseal(self, ciphertext: bytes) -> bytes: ...


class FernetSecretSealer:
    """Authenticated symmetric sealing backed by :class:`cryptography.fernet.Fernet`."""

    def __init__(self, key: str | bytes) -> None:
        try:
            self._fernet = Fernet(key if isinstance(key, bytes) else key.encode())
        except (ValueError, TypeError) as exc:
            raise CaError("invalid CA sealing key") from exc

    def seal(self, plaintext: bytes) -> bytes:
        return self._fernet.encrypt(plaintext)

    def unseal(self, ciphertext: bytes) -> bytes:
        try:
            return self._fernet.decrypt(ciphertext)
        except InvalidToken as exc:
            raise CaError("failed to unseal CA key") from exc


def build_sealer_from_settings() -> SecretSealer | None:
    """Return a sealer from ``settings.wb_ca_sealing_key`` or ``None`` if unset.

    ``None`` means CA issuance is unavailable (fail-closed) — callers must not
    fall back to plaintext storage.
    """
    key = settings.wb_ca_sealing_key
    if not key:
        return None
    return FernetSecretSealer(key)


@dataclass(frozen=True)
class SealedCa:
    """A freshly issued CA ready for persistence (public cert + sealed key)."""

    certificate_pem: str
    fingerprint_sha256: str
    sealed_key: bytes
    secrets_ref: str


def issue_ca(sealer: SecretSealer, *, common_name: str = "ARGUS Workbench CA") -> SealedCa:
    """Generate a fresh CA and seal its private key for at-rest storage."""
    ca = CertificateAuthority.generate(common_name=common_name)
    sealed = sealer.seal(ca.export_private_key_pem())
    return SealedCa(
        certificate_pem=ca.certificate_pem.decode("ascii"),
        fingerprint_sha256=ca.fingerprint_sha256,
        sealed_key=sealed,
        secrets_ref=SEALING_KEY_REF,
    )


def load_ca(
    sealer: SecretSealer, *, certificate_pem: str, sealed_key: bytes
) -> CertificateAuthority:
    """Unseal a stored CA key and rebuild the usable :class:`CertificateAuthority`."""
    private_key_pem = sealer.unseal(sealed_key)
    return CertificateAuthority.load(
        private_key_pem=private_key_pem,
        certificate_pem=certificate_pem.encode("ascii"),
    )


__all__ = [
    "SEALING_KEY_REF",
    "FernetSecretSealer",
    "SealedCa",
    "SecretSealer",
    "build_sealer_from_settings",
    "issue_ca",
    "load_ca",
]
