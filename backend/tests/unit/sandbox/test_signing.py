"""Unit tests for :mod:`src.sandbox.signing`.

Exercises every branch of the Ed25519 signing layer. Keys are generated
in-process; no fixtures touch the production ``backend/config/tools/_keys/``
directory.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from src.sandbox.signing import (
    IntegrityError,
    KeyManager,
    KeyNotFoundError,
    SignatureError,
    SignatureRecord,
    SignaturesFile,
    compute_yaml_hash,
    load_private_key_bytes,
    load_public_key_bytes,
    public_key_id,
    sign_blob,
    verify_blob,
)


# ---------------------------------------------------------------------------
# sign / verify happy + sad paths
# ---------------------------------------------------------------------------


def test_sign_and_verify_round_trip(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    private_key, public_key, _ = ed25519_keypair
    payload = b"hello argus"
    signature = sign_blob(private_key, payload)
    assert isinstance(signature, str)
    assert verify_blob(public_key, payload, signature) is True


def test_verify_rejects_tampered_payload(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    private_key, public_key, _ = ed25519_keypair
    signature = sign_blob(private_key, b"hello argus")
    assert verify_blob(public_key, b"hello world", signature) is False


def test_verify_rejects_wrong_key(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    private_key, _, _ = ed25519_keypair
    other = Ed25519PrivateKey.generate().public_key()
    signature = sign_blob(private_key, b"hello argus")
    assert verify_blob(other, b"hello argus", signature) is False


def test_verify_rejects_malformed_base64(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    _, public_key, _ = ed25519_keypair
    assert verify_blob(public_key, b"hello", "not-base64!") is False


def test_verify_rejects_signature_of_wrong_length(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    _, public_key, _ = ed25519_keypair
    short = base64.b64encode(b"shortsig").decode("ascii")
    assert verify_blob(public_key, b"hello", short) is False


# ---------------------------------------------------------------------------
# Key loading helpers
# ---------------------------------------------------------------------------


def test_public_key_id_is_16_hex_chars(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    _, _, kid = ed25519_keypair
    assert len(kid) == 16
    assert all(c in "0123456789abcdef" for c in kid)


def test_load_public_key_bytes_raw_round_trip(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    _, public_key, _ = ed25519_keypair
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    loaded = load_public_key_bytes(raw)
    assert public_key_id(loaded) == public_key_id(public_key)


def test_load_public_key_bytes_pem_round_trip(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    _, public_key, _ = ed25519_keypair
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    loaded = load_public_key_bytes(pem)
    assert public_key_id(loaded) == public_key_id(public_key)


def test_load_public_key_bytes_rejects_wrong_length() -> None:
    with pytest.raises(SignatureError):
        load_public_key_bytes(b"too short")


def test_load_public_key_bytes_rejects_invalid_pem() -> None:
    with pytest.raises(SignatureError):
        load_public_key_bytes(b"-----BEGIN GARBAGE-----\nnope\n-----END GARBAGE-----\n")


def test_load_private_key_bytes_raw_round_trip(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    private_key, _, _ = ed25519_keypair
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    loaded = load_private_key_bytes(raw)
    assert public_key_id(loaded.public_key()) == public_key_id(private_key.public_key())


def test_load_private_key_bytes_rejects_wrong_length() -> None:
    with pytest.raises(SignatureError):
        load_private_key_bytes(b"too short")


def test_compute_yaml_hash_matches_sha256(tmp_path: Path) -> None:
    content = b"tool_id: nmap_quick\nphase: recon\n"
    yaml_path = tmp_path / "x.yaml"
    yaml_path.write_bytes(content)
    expected = hashlib.sha256(content).hexdigest()
    assert compute_yaml_hash(yaml_path) == expected


# ---------------------------------------------------------------------------
# KeyManager
# ---------------------------------------------------------------------------


def test_key_manager_loads_known_key(
    keys_dir: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    _, _, kid = ed25519_keypair
    manager = KeyManager(keys_dir)
    loaded = manager.load()
    assert loaded == 1
    assert kid in manager.loaded_key_ids
    fetched = manager.get(kid)
    assert public_key_id(fetched) == kid


def test_key_manager_get_missing_key_raises(keys_dir: Path) -> None:
    manager = KeyManager(keys_dir)
    manager.load()
    with pytest.raises(KeyNotFoundError):
        manager.get("0123456789abcdef")


def test_key_manager_rejects_malformed_key_id(keys_dir: Path) -> None:
    manager = KeyManager(keys_dir)
    manager.load()
    with pytest.raises(KeyNotFoundError):
        manager.get("not-hex")


def test_key_manager_load_missing_dir_returns_zero(tmp_path: Path) -> None:
    missing = tmp_path / "nonexistent"
    manager = KeyManager(missing)
    assert manager.load() == 0


def test_key_manager_rejects_filename_id_mismatch(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    _, public_key, _ = ed25519_keypair
    keys = tmp_path / "_keys"
    keys.mkdir()
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    (keys / "1111111111111111.ed25519.pub").write_bytes(raw)
    manager = KeyManager(keys)
    with pytest.raises(SignatureError):
        manager.load()


def test_generate_dev_keypair_writes_files(tmp_path: Path) -> None:
    out = tmp_path / "_keys"
    out.mkdir()
    priv, pub, kid = KeyManager.generate_dev_keypair(out)
    assert priv.exists()
    assert pub.exists()
    assert pub.name.startswith(kid)
    assert pub.read_bytes() != priv.read_bytes()


def test_generate_dev_keypair_missing_dir_raises(tmp_path: Path) -> None:
    with pytest.raises(SignatureError):
        KeyManager.generate_dev_keypair(tmp_path / "missing")


def test_generate_dev_keypair_target_is_file(tmp_path: Path) -> None:
    target = tmp_path / "not_a_dir"
    target.write_text("dummy")
    with pytest.raises(SignatureError):
        KeyManager.generate_dev_keypair(target)


# ---------------------------------------------------------------------------
# SignatureRecord
# ---------------------------------------------------------------------------


def _valid_signature_record_kwargs(public_key_id_value: str) -> dict[str, str]:
    return {
        "sha256_hex": "a" * 64,
        "relative_path": "nmap.yaml",
        "signature_b64": base64.b64encode(b"\x00" * 64).decode("ascii"),
        "public_key_id": public_key_id_value,
    }


def test_signature_record_happy(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    _, _, kid = ed25519_keypair
    record = SignatureRecord(**_valid_signature_record_kwargs(kid))
    assert record.public_key_id == kid


def test_signature_record_rejects_bad_sha(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    _, _, kid = ed25519_keypair
    kwargs = _valid_signature_record_kwargs(kid) | {"sha256_hex": "bad"}
    with pytest.raises(SignatureError):
        SignatureRecord(**kwargs)


def test_signature_record_rejects_path_traversal(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    _, _, kid = ed25519_keypair
    kwargs = _valid_signature_record_kwargs(kid) | {"relative_path": "../escape.yaml"}
    with pytest.raises(SignatureError):
        SignatureRecord(**kwargs)


def test_signature_record_rejects_absolute_path(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    _, _, kid = ed25519_keypair
    kwargs = _valid_signature_record_kwargs(kid) | {"relative_path": "/etc/passwd"}
    with pytest.raises(SignatureError):
        SignatureRecord(**kwargs)


def test_signature_record_rejects_bad_signature_b64(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    _, _, kid = ed25519_keypair
    kwargs = _valid_signature_record_kwargs(kid) | {"signature_b64": "@@@"}
    with pytest.raises(SignatureError):
        SignatureRecord(**kwargs)


def test_signature_record_rejects_short_signature(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    _, _, kid = ed25519_keypair
    kwargs = _valid_signature_record_kwargs(kid) | {
        "signature_b64": base64.b64encode(b"\x00" * 32).decode("ascii"),
    }
    with pytest.raises(SignatureError):
        SignatureRecord(**kwargs)


def test_signature_record_rejects_bad_key_id() -> None:
    kwargs = _valid_signature_record_kwargs("ZZZZ") | {"public_key_id": "ZZZZ"}
    with pytest.raises(SignatureError):
        SignatureRecord(**kwargs)


# ---------------------------------------------------------------------------
# SignaturesFile parser / writer
# ---------------------------------------------------------------------------


def test_signatures_file_round_trip(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    private_key, _, kid = ed25519_keypair
    yaml_path = tmp_path / "nmap.yaml"
    yaml_bytes = b"tool_id: nmap_quick\n"
    yaml_path.write_bytes(yaml_bytes)
    sha = hashlib.sha256(yaml_bytes).hexdigest()
    sig = sign_blob(private_key, yaml_bytes)
    record = SignatureRecord(
        sha256_hex=sha, relative_path="nmap.yaml", signature_b64=sig, public_key_id=kid
    )
    sigfile = SignaturesFile()
    sigfile.upsert(record)
    out = tmp_path / "SIGNATURES"
    sigfile.write(out)
    parsed = SignaturesFile.from_file(out)
    assert "nmap.yaml" in parsed
    assert len(parsed) == 1
    assert parsed.get("nmap.yaml") is not None


def test_signatures_file_parser_accepts_comments_and_blank_lines() -> None:
    sig_b64 = base64.b64encode(b"\x00" * 64).decode("ascii")
    sha = "b" * 64
    kid = "a" * 16
    text = f"# header line\n\n  # another comment\n{sha}  nmap.yaml  {sig_b64}  {kid}\n"
    parsed = SignaturesFile.parse(text)
    assert "nmap.yaml" in parsed


def test_signatures_file_parser_rejects_wrong_arity() -> None:
    with pytest.raises(SignatureError):
        SignaturesFile.parse("aa  bb  cc\n")


def test_signatures_file_parser_rejects_duplicates(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    _, _, kid = ed25519_keypair
    sig = base64.b64encode(b"\x00" * 64).decode("ascii")
    text = f"{'a' * 64}  nmap.yaml  {sig}  {kid}\n{'a' * 64}  nmap.yaml  {sig}  {kid}\n"
    with pytest.raises(SignatureError):
        SignaturesFile.parse(text)


def test_signatures_file_from_missing_path_raises(tmp_path: Path) -> None:
    with pytest.raises(SignatureError):
        SignaturesFile.from_file(tmp_path / "missing")


def _exploding_resolver(_kid: str) -> Ed25519PublicKey:
    raise AssertionError("resolver should not be invoked when the entry is missing")


def test_verify_one_rejects_unknown_path() -> None:
    sigfile = SignaturesFile()
    with pytest.raises(IntegrityError):
        sigfile.verify_one(
            relative_path="ghost.yaml",
            yaml_bytes=b"x",
            public_key_resolver=_exploding_resolver,
        )


def test_verify_one_rejects_hash_mismatch(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    private_key, public_key, kid = ed25519_keypair
    yaml_bytes = b"tool_id: nmap_quick\n"
    sig = sign_blob(private_key, yaml_bytes)
    record = SignatureRecord(
        sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
        relative_path="nmap.yaml",
        signature_b64=sig,
        public_key_id=kid,
    )
    sigfile = SignaturesFile({"nmap.yaml": record})
    with pytest.raises(IntegrityError):
        sigfile.verify_one(
            relative_path="nmap.yaml",
            yaml_bytes=b"tool_id: tampered\n",
            public_key_resolver=lambda _kid: public_key,
        )


def test_verify_one_rejects_unknown_key(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    private_key, public_key, kid = ed25519_keypair
    yaml_bytes = b"tool_id: nmap_quick\n"
    sig = sign_blob(private_key, yaml_bytes)
    record = SignatureRecord(
        sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
        relative_path="nmap.yaml",
        signature_b64=sig,
        public_key_id=kid,
    )
    sigfile = SignaturesFile({"nmap.yaml": record})

    def _resolver(_kid: str) -> Ed25519PublicKey:
        raise KeyNotFoundError("missing")

    with pytest.raises(KeyNotFoundError):
        sigfile.verify_one(
            relative_path="nmap.yaml",
            yaml_bytes=yaml_bytes,
            public_key_resolver=_resolver,
        )


def test_verify_one_rejects_wrong_key(
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    private_key, _, kid = ed25519_keypair
    yaml_bytes = b"tool_id: nmap_quick\n"
    sig = sign_blob(private_key, yaml_bytes)
    record = SignatureRecord(
        sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
        relative_path="nmap.yaml",
        signature_b64=sig,
        public_key_id=kid,
    )
    sigfile = SignaturesFile({"nmap.yaml": record})
    other_key = Ed25519PrivateKey.generate().public_key()
    with pytest.raises(IntegrityError):
        sigfile.verify_one(
            relative_path="nmap.yaml",
            yaml_bytes=yaml_bytes,
            public_key_resolver=lambda _kid: other_key,
        )
