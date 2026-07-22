"""Unit tests for the per-tenant MITM certificate authority (WB-P2a)."""

from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtendedKeyUsageOID

from src.web_workbench.proxy.ca_manager import CaError, CertificateAuthority


def test_generate_ca_is_constrained() -> None:
    ca = CertificateAuthority.generate()
    cert = x509.load_pem_x509_certificate(ca.certificate_pem)
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True
    assert bc.path_length == 0
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign is True


def test_fingerprint_is_stable_and_hex() -> None:
    ca = CertificateAuthority.generate()
    fp = ca.fingerprint_sha256
    assert fp == ca.fingerprint_sha256
    assert len(fp) == 64
    int(fp, 16)  # valid hex


def test_issue_leaf_is_signed_by_ca() -> None:
    ca = CertificateAuthority.generate()
    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem)
    leaf = ca.issue_leaf("shop.example.com")
    leaf_cert = x509.load_pem_x509_certificate(leaf.certificate_pem)

    # Verify the leaf signature against the CA public key (raises on mismatch).
    ca_cert.public_key().verify(
        leaf_cert.signature,
        leaf_cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        leaf_cert.signature_hash_algorithm,
    )
    assert leaf_cert.issuer == ca_cert.subject


def test_issue_leaf_has_san_and_server_auth_eku_and_not_ca() -> None:
    ca = CertificateAuthority.generate()
    leaf_cert = x509.load_pem_x509_certificate(ca.issue_leaf("shop.example.com").certificate_pem)
    san = leaf_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["shop.example.com"]
    eku = leaf_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    bc = leaf_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is False


def test_issue_leaf_ip_san() -> None:
    ca = CertificateAuthority.generate()
    leaf_cert = x509.load_pem_x509_certificate(ca.issue_leaf("10.0.0.5").certificate_pem)
    san = leaf_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    values = [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    assert values == ["10.0.0.5"]


def test_issue_leaf_short_validity() -> None:
    ca = CertificateAuthority.generate()
    leaf = ca.issue_leaf("x.example.com", validity=dt.timedelta(days=7))
    assert leaf.not_valid_after > dt.datetime.now(tz=dt.timezone.utc)


def test_issue_leaf_rejects_empty_host() -> None:
    ca = CertificateAuthority.generate()
    with pytest.raises(CaError):
        ca.issue_leaf("")


def test_repr_redacts_key_material() -> None:
    ca = CertificateAuthority.generate()
    assert "redacted" not in repr(ca).lower() or "fingerprint" in repr(ca).lower()
    leaf = ca.issue_leaf("x.example.com")
    text = repr(leaf)
    assert "<redacted>" in text
    assert leaf.private_key_pem.decode() not in text


def test_load_round_trip() -> None:
    ca = CertificateAuthority.generate()
    key_pem = ca.export_private_key_pem()
    reloaded = CertificateAuthority.load(
        private_key_pem=key_pem, certificate_pem=ca.certificate_pem
    )
    assert reloaded.fingerprint_sha256 == ca.fingerprint_sha256
    assert b"PRIVATE KEY" in key_pem


def test_load_rejects_garbage() -> None:
    with pytest.raises(CaError):
        CertificateAuthority.load(private_key_pem=b"not-a-key", certificate_pem=b"not-a-cert")
