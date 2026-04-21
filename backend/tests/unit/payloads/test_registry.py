"""Unit tests for :mod:`src.payloads.registry` (ARG-005, Backlog/dev1_md §7).

Covers the fail-closed contract documented in :mod:`src.payloads.registry`:

* Missing payloads dir / file path / SIGNATURES file → :class:`RegistryLoadError`.
* Tampered YAML or unknown signing key → :class:`PayloadSignatureError`.
* Duplicate ``family_id`` / mismatched filename / unknown enum → fail-closed.
* Schema rules — unique CWE ids, OWASP prefix, unknown mutation/encoder names,
  approval gate on HIGH/DESTRUCTIVE risk levels.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from src.payloads.registry import (
    PayloadFamily,
    PayloadFamilyNotFoundError,
    PayloadRegistry,
    PayloadRegistrySummary,
    PayloadSignatureError,
    RegistryLoadError,
)
from src.sandbox.signing import SignatureRecord, SignaturesFile, sign_blob


# ---------------------------------------------------------------------------
# Pre-flight: invalid layouts
# ---------------------------------------------------------------------------


def test_missing_payloads_dir_raises(tmp_path: Path) -> None:
    registry = PayloadRegistry(payloads_dir=tmp_path / "nope")
    with pytest.raises(RegistryLoadError):
        registry.load()


def test_payloads_path_is_file_raises(tmp_path: Path) -> None:
    f = tmp_path / "payloads"
    f.write_text("dummy")
    registry = PayloadRegistry(payloads_dir=f)
    with pytest.raises(RegistryLoadError):
        registry.load()


def test_missing_signatures_file_raises(tmp_path: Path) -> None:
    payloads = tmp_path / "payloads"
    payloads.mkdir()
    (payloads / "_keys").mkdir()
    registry = PayloadRegistry(payloads_dir=payloads)
    with pytest.raises(RegistryLoadError) as exc_info:
        registry.load()
    assert "SIGNATURES" in str(exc_info.value)


def test_empty_catalog_raises(tmp_path: Path) -> None:
    payloads = tmp_path / "payloads"
    payloads.mkdir()
    (payloads / "_keys").mkdir()
    (payloads / "SIGNATURES").write_text("# header only\n", encoding="utf-8")
    registry = PayloadRegistry(payloads_dir=payloads)
    with pytest.raises(RegistryLoadError) as exc_info:
        registry.load()
    assert "no payload" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# Happy path on the signed mini-catalog from conftest
# ---------------------------------------------------------------------------


def test_load_signed_catalog_succeeds(
    signed_payloads_dir: tuple[Path, Path, Path, str],
) -> None:
    payloads_dir, keys_dir, signatures_path, _ = signed_payloads_dir
    registry = PayloadRegistry(
        payloads_dir=payloads_dir,
        keys_dir=keys_dir,
        signatures_path=signatures_path,
    )
    summary = registry.load()
    assert isinstance(summary, PayloadRegistrySummary)
    assert summary.total == 2
    assert summary.family_ids == ("demo_rce", "demo_sqli")
    assert summary.requires_approval_count == 1
    assert summary.by_risk == {"high": 1, "medium": 1}


def test_get_family_returns_pydantic_instance(
    signed_payloads_dir: tuple[Path, Path, Path, str],
) -> None:
    payloads_dir, keys_dir, signatures_path, _ = signed_payloads_dir
    registry = PayloadRegistry(
        payloads_dir=payloads_dir, keys_dir=keys_dir, signatures_path=signatures_path
    )
    registry.load()
    family = registry.get_family("demo_sqli")
    assert isinstance(family, PayloadFamily)
    assert family.family_id == "demo_sqli"


def test_get_family_unknown_raises_named_error(
    signed_payloads_dir: tuple[Path, Path, Path, str],
) -> None:
    payloads_dir, keys_dir, signatures_path, _ = signed_payloads_dir
    registry = PayloadRegistry(
        payloads_dir=payloads_dir, keys_dir=keys_dir, signatures_path=signatures_path
    )
    registry.load()
    with pytest.raises(PayloadFamilyNotFoundError) as exc_info:
        registry.get_family("ghost")
    assert exc_info.value.family_id == "ghost"


def test_list_families_is_sorted(
    signed_payloads_dir: tuple[Path, Path, Path, str],
) -> None:
    payloads_dir, keys_dir, signatures_path, _ = signed_payloads_dir
    registry = PayloadRegistry(
        payloads_dir=payloads_dir, keys_dir=keys_dir, signatures_path=signatures_path
    )
    registry.load()
    ids = [f.family_id for f in registry.list_families()]
    assert ids == sorted(ids)


def test_list_families_returns_immutable_tuple(
    signed_payloads_dir: tuple[Path, Path, Path, str],
) -> None:
    """Defensive copy: callers must not be able to mutate the catalog."""
    payloads_dir, keys_dir, signatures_path, _ = signed_payloads_dir
    registry = PayloadRegistry(
        payloads_dir=payloads_dir, keys_dir=keys_dir, signatures_path=signatures_path
    )
    registry.load()
    families = registry.list_families()
    assert isinstance(families, tuple)
    # Tuples reject append/pop — verify the contract is enforced by the type.
    assert not hasattr(families, "append")
    assert not hasattr(families, "pop")


def test_families_requiring_approval_filter(
    signed_payloads_dir: tuple[Path, Path, Path, str],
) -> None:
    payloads_dir, keys_dir, signatures_path, _ = signed_payloads_dir
    registry = PayloadRegistry(
        payloads_dir=payloads_dir, keys_dir=keys_dir, signatures_path=signatures_path
    )
    registry.load()
    approval = registry.families_requiring_approval()
    assert len(approval) == 1
    assert approval[0].family_id == "demo_rce"


def test_iteration_and_membership(
    signed_payloads_dir: tuple[Path, Path, Path, str],
) -> None:
    payloads_dir, keys_dir, signatures_path, _ = signed_payloads_dir
    registry = PayloadRegistry(
        payloads_dir=payloads_dir, keys_dir=keys_dir, signatures_path=signatures_path
    )
    registry.load()
    assert "demo_sqli" in registry
    assert 42 not in registry
    assert sorted(iter(registry)) == ["demo_rce", "demo_sqli"]
    assert len(registry) == 2


# ---------------------------------------------------------------------------
# Fail-closed conditions
# ---------------------------------------------------------------------------


def test_tampered_yaml_rejected(
    signed_payloads_dir: tuple[Path, Path, Path, str],
) -> None:
    payloads_dir, keys_dir, signatures_path, _ = signed_payloads_dir
    target = payloads_dir / "demo_sqli.yaml"
    payload = yaml.safe_load(target.read_text())
    payload["description"] = "tampered after signing"
    target.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")

    registry = PayloadRegistry(
        payloads_dir=payloads_dir, keys_dir=keys_dir, signatures_path=signatures_path
    )
    with pytest.raises(PayloadSignatureError):
        registry.load()


def test_unknown_signing_key_rejected(
    tmp_path: Path,
    sample_family_payload: Callable[..., dict[str, object]],
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    payloads_dir = tmp_path / "payloads"
    payloads_dir.mkdir()
    keys_dir = tmp_path / "_keys"
    keys_dir.mkdir()  # intentionally empty — no key matches the signing kid
    private_key, _, kid = ed25519_keypair

    payload = sample_family_payload()
    yaml_bytes = yaml.safe_dump(payload, sort_keys=True).encode("utf-8")
    (payloads_dir / "demo_sqli.yaml").write_bytes(yaml_bytes)

    sigfile = SignaturesFile()
    sigfile.upsert(
        SignatureRecord(
            sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
            relative_path="demo_sqli.yaml",
            signature_b64=sign_blob(private_key, yaml_bytes),
            public_key_id=kid,
        )
    )
    sig_path = payloads_dir / "SIGNATURES"
    sigfile.write(sig_path)

    registry = PayloadRegistry(
        payloads_dir=payloads_dir, keys_dir=keys_dir, signatures_path=sig_path
    )
    with pytest.raises(PayloadSignatureError):
        registry.load()


def test_missing_manifest_entry_rejected(
    tmp_path: Path,
    sample_family_payload: Callable[..., dict[str, object]],
    keys_dir: Path,
) -> None:
    payloads_dir = tmp_path / "payloads"
    payloads_dir.mkdir()
    payload = sample_family_payload()
    yaml_bytes = yaml.safe_dump(payload, sort_keys=True).encode("utf-8")
    (payloads_dir / "demo_sqli.yaml").write_bytes(yaml_bytes)
    (payloads_dir / "SIGNATURES").write_text("# empty manifest\n", encoding="utf-8")
    registry = PayloadRegistry(
        payloads_dir=payloads_dir,
        keys_dir=keys_dir,
        signatures_path=payloads_dir / "SIGNATURES",
    )
    with pytest.raises(PayloadSignatureError):
        registry.load()


def test_filename_mismatch_rejected(
    tmp_path: Path,
    sample_family_payload: Callable[..., dict[str, object]],
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    keys_dir: Path,
) -> None:
    private_key, _, kid = ed25519_keypair
    payloads_dir = tmp_path / "payloads"
    payloads_dir.mkdir()
    payload = sample_family_payload(family_id="demo_sqli")
    yaml_bytes = yaml.safe_dump(payload, sort_keys=True).encode("utf-8")
    # Wrong filename stem (mismatch with family_id).
    (payloads_dir / "wrong_name.yaml").write_bytes(yaml_bytes)
    sigfile = SignaturesFile()
    sigfile.upsert(
        SignatureRecord(
            sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
            relative_path="wrong_name.yaml",
            signature_b64=sign_blob(private_key, yaml_bytes),
            public_key_id=kid,
        )
    )
    sig_path = payloads_dir / "SIGNATURES"
    sigfile.write(sig_path)
    registry = PayloadRegistry(
        payloads_dir=payloads_dir, keys_dir=keys_dir, signatures_path=sig_path
    )
    with pytest.raises(RegistryLoadError) as exc_info:
        registry.load()
    assert "filename" in str(exc_info.value).lower()


def test_yaml_not_a_mapping_rejected(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    keys_dir: Path,
) -> None:
    private_key, _, kid = ed25519_keypair
    payloads_dir = tmp_path / "payloads"
    payloads_dir.mkdir()
    yaml_bytes = b"- not\n- a\n- mapping\n"
    (payloads_dir / "weird.yaml").write_bytes(yaml_bytes)
    sigfile = SignaturesFile()
    sigfile.upsert(
        SignatureRecord(
            sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
            relative_path="weird.yaml",
            signature_b64=sign_blob(private_key, yaml_bytes),
            public_key_id=kid,
        )
    )
    sig_path = payloads_dir / "SIGNATURES"
    sigfile.write(sig_path)
    registry = PayloadRegistry(
        payloads_dir=payloads_dir, keys_dir=keys_dir, signatures_path=sig_path
    )
    with pytest.raises(RegistryLoadError):
        registry.load()


def test_invalid_yaml_rejected(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    keys_dir: Path,
) -> None:
    private_key, _, kid = ed25519_keypair
    payloads_dir = tmp_path / "payloads"
    payloads_dir.mkdir()
    yaml_bytes = b"key: [unclosed\n"
    (payloads_dir / "broken.yaml").write_bytes(yaml_bytes)
    sigfile = SignaturesFile()
    sigfile.upsert(
        SignatureRecord(
            sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
            relative_path="broken.yaml",
            signature_b64=sign_blob(private_key, yaml_bytes),
            public_key_id=kid,
        )
    )
    sig_path = payloads_dir / "SIGNATURES"
    sigfile.write(sig_path)
    registry = PayloadRegistry(
        payloads_dir=payloads_dir, keys_dir=keys_dir, signatures_path=sig_path
    )
    with pytest.raises(RegistryLoadError):
        registry.load()


# ---------------------------------------------------------------------------
# Schema-level invariants
# ---------------------------------------------------------------------------


def test_high_risk_without_approval_rejected(
    sample_family_payload: Callable[..., dict[str, object]],
) -> None:
    payload = sample_family_payload(risk_level="high", requires_approval=False)
    with pytest.raises(ValueError, match="requires_approval=True"):
        PayloadFamily(**payload)


def test_destructive_risk_without_approval_rejected(
    sample_family_payload: Callable[..., dict[str, object]],
) -> None:
    payload = sample_family_payload(risk_level="destructive", requires_approval=False)
    with pytest.raises(ValueError, match="requires_approval=True"):
        PayloadFamily(**payload)


def test_owasp_top10_must_start_with_a(
    sample_family_payload: Callable[..., dict[str, object]],
) -> None:
    payload = sample_family_payload()
    payload["owasp_top10"] = ["BAD-VALUE"]
    with pytest.raises(ValueError, match="must start with 'A'"):
        PayloadFamily(**payload)


def test_owasp_top10_must_be_unique(
    sample_family_payload: Callable[..., dict[str, object]],
) -> None:
    payload = sample_family_payload()
    payload["owasp_top10"] = ["A03:2021", "A03:2021"]
    with pytest.raises(ValueError, match="unique"):
        PayloadFamily(**payload)


def test_cwe_ids_must_be_positive(
    sample_family_payload: Callable[..., dict[str, object]],
) -> None:
    payload = sample_family_payload()
    payload["cwe_ids"] = [0]
    with pytest.raises(ValueError, match="positive"):
        PayloadFamily(**payload)


def test_cwe_ids_must_be_unique(
    sample_family_payload: Callable[..., dict[str, object]],
) -> None:
    payload = sample_family_payload()
    payload["cwe_ids"] = [89, 89]
    with pytest.raises(ValueError, match="unique"):
        PayloadFamily(**payload)


def test_unknown_mutation_rule_rejected(
    sample_family_payload: Callable[..., dict[str, object]],
) -> None:
    payload = sample_family_payload()
    payload["mutations"] = [{"name": "ghost", "max_per_payload": 1, "description": ""}]
    with pytest.raises(ValueError, match="unknown mutation"):
        PayloadFamily(**payload)


def test_unknown_encoder_stage_rejected(
    sample_family_payload: Callable[..., dict[str, object]],
) -> None:
    payload = sample_family_payload()
    payload["encodings"] = [{"name": "bad", "stages": ["ghost"], "description": ""}]
    with pytest.raises(ValueError, match="unknown encoder"):
        PayloadFamily(**payload)


def test_duplicate_payload_id_rejected(
    sample_family_payload: Callable[..., dict[str, object]],
) -> None:
    payload = sample_family_payload()
    payload["payloads"] = [
        {"id": "dup", "template": "a", "confidence": "suspected", "notes": ""},
        {"id": "dup", "template": "b", "confidence": "suspected", "notes": ""},
        {"id": "third", "template": "c", "confidence": "suspected", "notes": ""},
    ]
    with pytest.raises(ValueError, match="payload entry ids must be unique"):
        PayloadFamily(**payload)


def test_duplicate_mutation_name_rejected(
    sample_family_payload: Callable[..., dict[str, object]],
) -> None:
    payload = sample_family_payload()
    payload["mutations"] = [
        {"name": "case_flip", "max_per_payload": 1, "description": ""},
        {"name": "case_flip", "max_per_payload": 2, "description": ""},
    ]
    with pytest.raises(ValueError, match="mutation rule names must be unique"):
        PayloadFamily(**payload)


def test_extra_field_rejected(
    sample_family_payload: Callable[..., dict[str, object]],
) -> None:
    payload = sample_family_payload()
    payload["bonus_field"] = "should be rejected"
    with pytest.raises(ValueError):
        PayloadFamily(**payload)
