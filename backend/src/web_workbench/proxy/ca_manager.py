"""Per-tenant certificate authority for MITM interception (WB-P2a).

Each workbench tenant/project gets its own short-lived CA. The proxy signs a
leaf certificate per upstream host so the embedded browser trusts the
intercepted TLS connection. Security invariants enforced here:

* **Key material is never logged.** :class:`CertificateAuthority` redacts its
  ``repr`` and exposes the private key only through the explicit
  :meth:`CertificateAuthority.export_private_key_pem` accessor, which the
  caller is responsible for encrypting at rest (the value never touches logs).
* **CA is constrained.** The CA certificate carries ``BasicConstraints(ca=True,
  path_length=0)`` and ``keyCertSign`` usage; leaves are ``ca=False`` with
  ``serverAuth`` EKU only.
* **Leaves are short-lived** and scoped to the requested host via SAN, so a
  leaked leaf has a small blast radius.

Verification is offline and deterministic; no network or filesystem access.
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_CA_VALIDITY = _dt.timedelta(days=825)
_LEAF_VALIDITY = _dt.timedelta(days=90)
_CLOCK_SKEW = _dt.timedelta(minutes=5)
_RSA_KEY_SIZE = 2048
_RSA_PUBLIC_EXPONENT = 65537


class CaError(Exception):
    """Raised on CA/leaf generation or import failures (no key material)."""


def _utcnow() -> _dt.datetime:
    return _dt.datetime.now(tz=_dt.timezone.utc)


def _san_for_host(host: str) -> x509.GeneralName:
    """Return a DNSName or IPAddress SAN entry for ``host``."""
    try:
        return x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        return x509.DNSName(host)


@dataclass(frozen=True)
class IssuedLeaf:
    """A signed leaf certificate + its private key, both PEM-encoded.

    ``private_key_pem`` is sensitive: callers must not log it. It is a
    ``bytes`` value so it can be zeroized / handed to a secret store directly.
    """

    certificate_pem: bytes
    private_key_pem: bytes
    host: str
    not_valid_after: _dt.datetime

    def __repr__(self) -> str:  # pragma: no cover - trivial, but security-relevant
        return (
            f"IssuedLeaf(host={self.host!r}, "
            f"not_valid_after={self.not_valid_after.isoformat()}, "
            "private_key_pem=<redacted>)"
        )


class CertificateAuthority:
    """A per-tenant MITM certificate authority.

    Construct via :meth:`generate` (fresh CA) or :meth:`load` (from a stored,
    decrypted private-key + certificate PEM pair). Then call :meth:`issue_leaf`
    per upstream host.
    """

    def __init__(self, private_key: rsa.RSAPrivateKey, certificate: x509.Certificate) -> None:
        self._private_key = private_key
        self._certificate = certificate

    # -- construction --------------------------------------------------------

    @classmethod
    def generate(cls, *, common_name: str = "ARGUS Workbench CA") -> CertificateAuthority:
        """Generate a fresh, self-signed, path-length-0 CA."""
        key = rsa.generate_private_key(public_exponent=_RSA_PUBLIC_EXPONENT, key_size=_RSA_KEY_SIZE)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = _utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _CLOCK_SKEW)
            .not_valid_after(now + _CA_VALIDITY)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        return cls(key, cert)

    @classmethod
    def load(cls, *, private_key_pem: bytes, certificate_pem: bytes) -> CertificateAuthority:
        """Rebuild a CA from a decrypted private-key + certificate PEM pair."""
        try:
            key = serialization.load_pem_private_key(private_key_pem, password=None)
            cert = x509.load_pem_x509_certificate(certificate_pem)
        except (ValueError, TypeError) as exc:
            raise CaError("failed to load CA material") from exc
        if not isinstance(key, rsa.RSAPrivateKey):
            raise CaError("unsupported CA key type")
        return cls(key, cert)

    # -- accessors -----------------------------------------------------------

    @property
    def certificate_pem(self) -> bytes:
        """The CA certificate (public) — safe to distribute to clients."""
        return self._certificate.public_bytes(serialization.Encoding.PEM)

    @property
    def fingerprint_sha256(self) -> str:
        """Lowercase hex SHA-256 fingerprint of the CA certificate (DER)."""
        return self._certificate.fingerprint(hashes.SHA256()).hex()

    @property
    def not_valid_after(self) -> _dt.datetime:
        return self._certificate.not_valid_after_utc

    def export_private_key_pem(self) -> bytes:
        """Explicit, guarded export of the CA private key (SENSITIVE).

        The returned PEM must be encrypted before storage and MUST NOT be
        logged. This method is the only path to the key bytes.
        """
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    # -- leaf issuance -------------------------------------------------------

    def issue_leaf(self, host: str, *, validity: _dt.timedelta | None = None) -> IssuedLeaf:
        """Issue a short-lived leaf certificate for ``host`` (DNS or IP)."""
        if not host or len(host) > 253:
            raise CaError("invalid host for leaf certificate")
        leaf_key = rsa.generate_private_key(
            public_exponent=_RSA_PUBLIC_EXPONENT, key_size=_RSA_KEY_SIZE
        )
        now = _utcnow()
        expiry = now + (validity or _LEAF_VALIDITY)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(self._certificate.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _CLOCK_SKEW)
            .not_valid_after(expiry)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([_san_for_host(host)]), critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self._private_key, hashes.SHA256())
        )
        return IssuedLeaf(
            certificate_pem=cert.public_bytes(serialization.Encoding.PEM),
            private_key_pem=leaf_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ),
            host=host,
            not_valid_after=expiry,
        )

    def __repr__(self) -> str:  # pragma: no cover - trivial, security-relevant
        return f"CertificateAuthority(fingerprint_sha256={self.fingerprint_sha256!r})"


__all__ = ["CaError", "CertificateAuthority", "IssuedLeaf"]
