"""No-drift + signature-validity gate for the signed DWM catalog.

Registry-free: uses ``src.sandbox.signing`` directly (the same machinery the
payloads/tools/prompts catalogs use) so it runs in the default offline
``pytest -q`` (it lives under ``tests/unit/`` which conftest allowlists).

Mirrors ``tests/integration/payloads/test_signatures_no_drift.py`` semantics
(purity + idempotency) and adds the real validity assertion (every YAML passes
Ed25519 verify, no stale/missing entries).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from src.sandbox.signing import KeyManager, SignaturesFile

_DARKWEB_DIR = Path(__file__).resolve().parents[3] / "config" / "darkweb"
_SIGNATURES = _DARKWEB_DIR / "SIGNATURES"
_KEYS_DIR = _DARKWEB_DIR / "_keys"


def _yaml_files() -> list[Path]:
    return sorted(p for p in _DARKWEB_DIR.glob("*.yaml") if p.is_file())


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_catalog_dir_and_manifest_exist() -> None:
    assert _DARKWEB_DIR.is_dir(), f"missing {_DARKWEB_DIR}"
    assert _SIGNATURES.is_file(), f"missing {_SIGNATURES}"
    assert _KEYS_DIR.is_dir(), f"missing {_KEYS_DIR}"
    assert _yaml_files(), "no DWM YAML catalogs found"


def test_every_yaml_is_signed_and_untampered() -> None:
    signatures = SignaturesFile.from_file(_SIGNATURES)
    keys = KeyManager(_KEYS_DIR)
    keys.load()
    yaml_paths = _yaml_files()

    # No stale entries (manifest references a YAML that no longer exists).
    expected = {p.relative_to(_DARKWEB_DIR).as_posix() for p in yaml_paths}
    stale = set(signatures.records) - expected
    assert not stale, f"SIGNATURES references missing YAML: {sorted(stale)}"

    # No missing entries (a YAML with no signature) + valid signature each.
    for yaml_path in yaml_paths:
        rel = yaml_path.relative_to(_DARKWEB_DIR).as_posix()
        assert rel in signatures.records, f"unsigned catalog file: {rel}"
        signatures.verify_one(
            relative_path=rel,
            yaml_bytes=yaml_path.read_bytes(),
            public_key_resolver=keys.get,
        )  # raises IntegrityError / KeyNotFoundError on drift


def test_verify_loop_does_not_mutate_files() -> None:
    before = {p.name: _sha(p) for p in [_SIGNATURES, *_yaml_files()]}
    signatures = SignaturesFile.from_file(_SIGNATURES)
    keys = KeyManager(_KEYS_DIR)
    keys.load()
    for yaml_path in _yaml_files():
        signatures.verify_one(
            relative_path=yaml_path.relative_to(_DARKWEB_DIR).as_posix(),
            yaml_bytes=yaml_path.read_bytes(),
            public_key_resolver=keys.get,
        )
    after = {p.name: _sha(p) for p in [_SIGNATURES, *_yaml_files()]}
    assert before == after


def test_signatures_hash_is_idempotent() -> None:
    hashes = {_sha(_SIGNATURES) for _ in range(5)}
    assert len(hashes) == 1


@pytest.mark.parametrize("name", [p.name for p in _yaml_files()])
def test_each_catalog_has_a_record(name: str) -> None:
    signatures = SignaturesFile.from_file(_SIGNATURES)
    assert name in signatures.records
