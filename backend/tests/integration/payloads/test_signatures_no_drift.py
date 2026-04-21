"""ISS-payload-signatures-drift regression guard.

Verifies that loading the production ``backend/config/payloads/`` registry
does NOT mutate the on-disk SIGNATURES manifest or any payload YAML file.

Cycle 3 reported intermittent drift where some test inadvertently rewrote
``SIGNATURES`` with a different ordering or trailing newline. The fix was
to ensure all unit-level fixtures use ``tmp_path``; this guard is a
safety net that runs after the catalog has been loaded multiple times
(via ``loaded_registry`` session fixture).

If this test fails, look for a fixture or test that opens the real
``backend/config/payloads/`` tree in ``"w"`` mode without copying it to
``tmp_path`` first.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Final

import pytest

from src.payloads.registry import PayloadRegistry


_PAYLOADS_RELATIVE: Final[tuple[str, ...]] = (
    "config",
    "payloads",
)


def _backend_root() -> Path:
    """Resolve ``backend/`` from this test file's location."""
    return Path(__file__).resolve().parents[3]


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def catalog_dir() -> Path:
    catalog = _backend_root().joinpath(*_PAYLOADS_RELATIVE)
    assert catalog.is_dir(), f"expected catalog dir at {catalog}"
    return catalog


@pytest.fixture(scope="module")
def initial_hashes(catalog_dir: Path) -> dict[str, str]:
    """Snapshot SHA-256 of SIGNATURES + every YAML before any test mutates state."""
    hashes: dict[str, str] = {
        "SIGNATURES": _hash_file(catalog_dir / "SIGNATURES"),
    }
    for yaml_path in sorted(catalog_dir.glob("*.yaml")):
        hashes[yaml_path.name] = _hash_file(yaml_path)
    return hashes


def test_loading_registry_does_not_mutate_signatures(
    catalog_dir: Path, initial_hashes: dict[str, str]
) -> None:
    """Loading the registry must be a pure read."""
    PayloadRegistry(payloads_dir=catalog_dir).load()
    actual = _hash_file(catalog_dir / "SIGNATURES")
    expected = initial_hashes["SIGNATURES"]
    assert actual == expected, (
        "SIGNATURES file was mutated by registry load — payload signing drift! "
        f"expected sha256={expected}, got sha256={actual}"
    )


def test_loading_registry_does_not_mutate_yaml_payloads(
    catalog_dir: Path, initial_hashes: dict[str, str]
) -> None:
    """Loading the registry must not touch any payload YAML."""
    PayloadRegistry(payloads_dir=catalog_dir).load()
    drift: list[tuple[str, str, str]] = []
    for yaml_path in sorted(catalog_dir.glob("*.yaml")):
        actual = _hash_file(yaml_path)
        expected = initial_hashes.get(yaml_path.name)
        if expected is None or actual != expected:
            drift.append((yaml_path.name, expected or "<missing>", actual))
    assert not drift, (
        "payload YAML files mutated by registry load: "
        + ", ".join(f"{name} expected={exp[:12]}.. got={act[:12]}.." for name, exp, act in drift)
    )


def test_repeated_load_is_idempotent(catalog_dir: Path) -> None:
    """Five sequential loads must produce the same SIGNATURES hash."""
    hashes = set()
    for _ in range(5):
        PayloadRegistry(payloads_dir=catalog_dir).load()
        hashes.add(_hash_file(catalog_dir / "SIGNATURES"))
    assert len(hashes) == 1, (
        f"PayloadRegistry.load() is non-idempotent: {len(hashes)} distinct hashes seen"
    )
