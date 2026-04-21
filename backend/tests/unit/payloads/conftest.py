"""Shared fixtures for the :mod:`src.payloads` unit-test suite.

Mirrors :mod:`backend.tests.unit.sandbox.conftest` so tests can spin up a
fully signed mini payload catalog under ``tmp_path`` without touching the
real production YAMLs.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from src.sandbox.signing import (
    SignatureRecord,
    SignaturesFile,
    public_key_id,
    sign_blob,
)


@pytest.fixture()
def ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey, str]:
    """Return a freshly generated Ed25519 keypair plus its canonical key id."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key, public_key_id(public_key)


@pytest.fixture()
def keys_dir(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> Path:
    """Materialise the keypair under a fresh ``_keys`` directory."""
    _, public_key, kid = ed25519_keypair
    keys = tmp_path / "_keys"
    keys.mkdir()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    (keys / f"{kid}.ed25519.pub").write_bytes(pub_bytes)
    return keys


def _sample_family_payload(
    family_id: str = "demo_sqli",
    *,
    risk_level: str = "medium",
    requires_approval: bool = False,
) -> dict[str, object]:
    """Return a minimal valid :class:`PayloadFamily` YAML payload."""
    return {
        "family_id": family_id,
        "description": "Demo seed family used in unit tests; not a real catalog entry.",
        "cwe_ids": [89],
        "owasp_top10": ["A03:2021"],
        "risk_level": risk_level,
        "requires_approval": requires_approval,
        "oast_required": False,
        "payloads": [
            {
                "id": "boolean_true",
                "template": "' OR '1'='1",
                "confidence": "suspected",
                "notes": "Classic boolean-true probe.",
            },
            {
                "id": "with_param",
                "template": "{param}' /* {canary} */",
                "confidence": "likely",
                "notes": "Parameterised probe with canary marker.",
            },
            {
                "id": "third_seed",
                "template": "1=1",
                "confidence": "suspected",
                "notes": "Bare tautology.",
            },
        ],
        "mutations": [
            {"name": "case_flip", "max_per_payload": 1, "description": ""},
            {"name": "comment_injection", "max_per_payload": 1, "description": ""},
        ],
        "encodings": [
            {"name": "identity", "stages": [], "description": ""},
            {"name": "url_only", "stages": ["url"], "description": ""},
            {"name": "url_then_b64", "stages": ["url", "base64"], "description": ""},
        ],
    }


@pytest.fixture()
def sample_family_payload() -> Callable[..., dict[str, object]]:
    """Factory that returns a fresh sample payload-family per call."""
    return _sample_family_payload


@pytest.fixture()
def signed_payloads_dir(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> tuple[Path, Path, Path, str]:
    """Build a complete signed mini catalog and return ``(payloads_dir, keys_dir, signatures_path, key_id)``."""
    private_key, public_key, kid = ed25519_keypair
    payloads_dir = tmp_path / "payloads"
    payloads_dir.mkdir()

    keys = tmp_path / "_keys"
    keys.mkdir()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    (keys / f"{kid}.ed25519.pub").write_bytes(pub_bytes)

    families = [
        _sample_family_payload("demo_sqli"),
        _sample_family_payload(
            "demo_rce",
            risk_level="high",
            requires_approval=True,
        ),
    ]

    signatures = SignaturesFile()
    for family in families:
        relative = f"{family['family_id']}.yaml"
        yaml_path = payloads_dir / relative
        yaml_bytes = yaml.safe_dump(family, sort_keys=True).encode("utf-8")
        yaml_path.write_bytes(yaml_bytes)
        signatures.upsert(
            SignatureRecord(
                sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
                relative_path=relative,
                signature_b64=sign_blob(private_key, yaml_bytes),
                public_key_id=kid,
            )
        )

    signatures_path = payloads_dir / "SIGNATURES"
    signatures.write(signatures_path)
    return payloads_dir, keys, signatures_path, kid
