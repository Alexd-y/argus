"""Unit tests for the extension manifest schema + signed loader (WB-P8b)."""

from __future__ import annotations

import hashlib

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from src.sandbox.signing import (
    KeyNotFoundError,
    SignatureRecord,
    SignaturesFile,
    public_key_id,
    sign_blob,
)
from src.web_workbench.extensions.manifest import (
    ExtensionManifest,
    ExtensionPermission,
    ManifestError,
    load_manifest,
    parse_manifest_bytes,
    verify_and_load,
)


def _passive_check(check_id: str = "acme.header-leak") -> dict[str, object]:
    return {
        "schema_version": 1,
        "check_id": check_id,
        "name": "Header leak",
        "category": "info",
        "severity": "low",
        "scope": "passive",
        "match": {
            "matchers": [{"part": "response_header", "kind": "contains", "value": "Server"}],
        },
    }


def _manifest_dict(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "schema_version": 1,
        "extension_id": "acme.header-scanner",
        "name": "Header Scanner",
        "author": "acme",
        "version": 1,
        "permissions": ["read_http_history", "emit_findings", "register_passive_check"],
        "checks": [_passive_check()],
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------- #
# Schema validation                                                           #
# --------------------------------------------------------------------------- #


def test_load_valid_manifest() -> None:
    manifest = load_manifest(_manifest_dict())
    assert isinstance(manifest, ExtensionManifest)
    assert manifest.extension_id == "acme.header-scanner"
    assert len(manifest.checks) == 1


def test_manifest_without_checks_is_valid() -> None:
    manifest = load_manifest(_manifest_dict(checks=[], permissions=["read_http_history"]))
    assert manifest.checks == []


def test_non_mapping_rejected() -> None:
    with pytest.raises(ManifestError):
        load_manifest(["nope"])


def test_unknown_key_rejected() -> None:
    with pytest.raises(ManifestError):
        load_manifest(_manifest_dict(rogue="x"))


def test_bad_extension_id_rejected() -> None:
    with pytest.raises(ManifestError):
        load_manifest(_manifest_dict(extension_id="Bad_ID"))


def test_duplicate_permissions_rejected() -> None:
    with pytest.raises(ManifestError):
        load_manifest(
            _manifest_dict(permissions=["emit_findings", "emit_findings", "register_passive_check"])
        )


def test_duplicate_check_ids_rejected() -> None:
    with pytest.raises(ManifestError):
        load_manifest(
            _manifest_dict(checks=[_passive_check("acme.dup"), _passive_check("acme.dup")])
        )


def test_embedded_bad_check_rejected() -> None:
    bad = _passive_check()
    bad["match"] = {"matchers": [{"part": "response_body", "kind": "regex", "value": "("}]}
    with pytest.raises(ManifestError):
        load_manifest(_manifest_dict(checks=[bad]))


# --------------------------------------------------------------------------- #
# Least-privilege invariants                                                  #
# --------------------------------------------------------------------------- #


def test_passive_check_requires_register_passive_permission() -> None:
    with pytest.raises(ManifestError):
        load_manifest(_manifest_dict(permissions=["read_http_history"]))


def test_active_check_requires_register_active_permission() -> None:
    active = _passive_check("acme.active")
    active["scope"] = "active"
    with pytest.raises(ManifestError):
        load_manifest(_manifest_dict(checks=[active], permissions=["register_passive_check"]))


def test_active_check_with_permission_ok() -> None:
    active = _passive_check("acme.active")
    active["scope"] = "active"
    manifest = load_manifest(_manifest_dict(checks=[active], permissions=["register_active_check"]))
    assert manifest.checks[0].check_id == "acme.active"


def test_oast_check_requires_use_oast_permission() -> None:
    oast = _passive_check("acme.oast")
    oast["scope"] = "active"
    oast["requires_oast"] = True
    with pytest.raises(ManifestError):
        load_manifest(_manifest_dict(checks=[oast], permissions=["register_active_check"]))


def test_oast_check_with_permission_ok() -> None:
    oast = _passive_check("acme.oast")
    oast["scope"] = "active"
    oast["requires_oast"] = True
    manifest = load_manifest(
        _manifest_dict(checks=[oast], permissions=["register_active_check", "use_oast"])
    )
    assert manifest.checks[0].requires_oast is True


def test_network_egress_requires_provenance_source_url() -> None:
    with pytest.raises(ManifestError):
        load_manifest(
            _manifest_dict(
                permissions=["register_passive_check", "network_egress"],
            )
        )


def test_network_egress_with_provenance_ok() -> None:
    manifest = load_manifest(
        _manifest_dict(
            permissions=["register_passive_check", "network_egress"],
            provenance={"source_url": "https://github.com/acme/ext"},
        )
    )
    assert ExtensionPermission.NETWORK_EGRESS in manifest.permissions


# --------------------------------------------------------------------------- #
# YAML parsing                                                                #
# --------------------------------------------------------------------------- #


def test_parse_manifest_bytes_roundtrip() -> None:
    raw = yaml.safe_dump(_manifest_dict()).encode("utf-8")
    manifest = parse_manifest_bytes(raw)
    assert manifest.extension_id == "acme.header-scanner"


def test_parse_invalid_yaml_rejected() -> None:
    with pytest.raises(ManifestError):
        parse_manifest_bytes(b"not: : valid: yaml: [")


# --------------------------------------------------------------------------- #
# Signed loader (verify_and_load)                                             #
# --------------------------------------------------------------------------- #


def _signed(raw: bytes) -> tuple[SignaturesFile, dict[str, Ed25519PublicKey], str]:
    private_key = Ed25519PrivateKey.generate()
    key_id = public_key_id(private_key.public_key())
    rel = "acme.header-scanner.yaml"
    record = SignatureRecord(
        sha256_hex=hashlib.sha256(raw).hexdigest(),
        relative_path=rel,
        signature_b64=sign_blob(private_key, raw),
        public_key_id=key_id,
    )
    signatures = SignaturesFile()
    signatures.upsert(record)
    keys = {key_id: private_key.public_key()}
    return signatures, keys, rel


def test_verify_and_load_valid_signature() -> None:
    raw = yaml.safe_dump(_manifest_dict()).encode("utf-8")
    signatures, keys, rel = _signed(raw)
    manifest = verify_and_load(
        raw,
        relative_path=rel,
        signatures=signatures,
        public_key_resolver=keys.__getitem__,
    )
    assert manifest.extension_id == "acme.header-scanner"


def test_verify_and_load_tampered_bytes_rejected() -> None:
    raw = yaml.safe_dump(_manifest_dict()).encode("utf-8")
    signatures, keys, rel = _signed(raw)
    tampered = raw + b"\n# injected\n"
    with pytest.raises(ManifestError):
        verify_and_load(
            tampered,
            relative_path=rel,
            signatures=signatures,
            public_key_resolver=keys.__getitem__,
        )


def test_verify_and_load_unknown_key_rejected() -> None:
    raw = yaml.safe_dump(_manifest_dict()).encode("utf-8")
    signatures, _keys, rel = _signed(raw)

    def _empty_resolver(_key_id: str) -> Ed25519PublicKey:
        raise KeyNotFoundError("no such key")

    with pytest.raises(ManifestError):
        verify_and_load(
            raw,
            relative_path=rel,
            signatures=signatures,
            public_key_resolver=_empty_resolver,
        )


def test_verify_and_load_unsigned_path_rejected() -> None:
    raw = yaml.safe_dump(_manifest_dict()).encode("utf-8")
    signatures, keys, _rel = _signed(raw)
    with pytest.raises(ManifestError):
        verify_and_load(
            raw,
            relative_path="unknown.yaml",
            signatures=signatures,
            public_key_resolver=keys.__getitem__,
        )
