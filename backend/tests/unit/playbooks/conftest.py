"""Shared fixtures for the :mod:`src.playbooks` unit-test suite.

Builds fully-signed mini playbook catalogs under ``tmp_path`` (per-category
subdirectories, mirroring the production layout) without touching the real
``backend/config/playbooks`` tree.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
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


def make_playbook_dict(
    playbook_id: str = "idor.cross-user-read",
    *,
    category: str = "authorization",
    risk_level: str = "low",
    requires_approval: bool = False,
) -> dict[str, object]:
    """Return a minimal, schema-valid playbook mapping."""
    return {
        "schema_version": 1,
        "playbook_id": playbook_id,
        "version": 1,
        "title": "Test IDOR cross-user read",
        "description": "Declarative test playbook; not a production entry.",
        "category": category,
        "cwe": [639],
        "wstg": ["WSTG-ATHZ-04"],
        "owasp_api": ["API1:2023"],
        "tags": ["idor"],
        "applies_when": {
            "methods": ["GET"],
            "path_globs": ["/api/*/users/*"],
            "requires_openapi": False,
            "input_kinds": ["path_param"],
        },
        "required_capabilities": ["http_client"],
        "required_principals": ["owner", "attacker"],
        "risk_level": risk_level,
        "requires_approval": requires_approval,
        "steps": [
            {
                "id": "owner_baseline",
                "action": "http_request",
                "principal": "owner",
                "save_as": "owner_resp",
                "params": {
                    "method": "GET",
                    "url": "https://{target_host}/api/v1/users/{victim_id}",
                    "headers": {},
                },
            },
            {
                "id": "attacker_probe",
                "action": "http_request",
                "principal": "attacker",
                "save_as": "attacker_resp",
                "params": {
                    "method": "GET",
                    "url": "https://{target_host}/api/v1/users/{victim_id}",
                    "headers": {},
                },
            },
        ],
        "assertions": [
            {
                "type": "authz",
                "params": {"sensitive_fields": ["email", "account_number"]},
            }
        ],
        "required_evidence": ["baseline_response", "mutated_response"],
        "timeout_seconds": 120,
        "max_concurrency": 1,
    }


@pytest.fixture()
def playbook_dict() -> Callable[..., dict[str, object]]:
    """Factory returning a fresh valid playbook mapping per call."""
    return make_playbook_dict


@pytest.fixture()
def ed25519_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey, str]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key, public_key_id(public_key)


CatalogEntry = tuple[str, dict[str, object], bool]


@pytest.fixture()
def build_signed_catalog(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> Callable[[Sequence[CatalogEntry]], Path]:
    """Return a builder that materialises a signed playbook catalog on disk.

    Each entry is ``(relative_posix_path, playbook_dict, do_sign)``. Files with
    ``do_sign=False`` are written but omitted from ``SIGNATURES`` so the
    registry's fail-closed behaviour can be exercised.
    """
    private_key, public_key, kid = ed25519_keypair

    def _build(entries: Sequence[CatalogEntry]) -> Path:
        playbooks_dir = tmp_path / "playbooks"
        keys = playbooks_dir / "_keys"
        keys.mkdir(parents=True)
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        (keys / f"{kid}.ed25519.pub").write_bytes(pub_bytes)

        signatures = SignaturesFile()
        for relative, payload, do_sign in entries:
            yaml_path = playbooks_dir / relative
            yaml_path.parent.mkdir(parents=True, exist_ok=True)
            yaml_bytes = yaml.safe_dump(payload, sort_keys=True).encode("utf-8")
            yaml_path.write_bytes(yaml_bytes)
            if do_sign:
                signatures.upsert(
                    SignatureRecord(
                        sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
                        relative_path=relative,
                        signature_b64=sign_blob(private_key, yaml_bytes),
                        public_key_id=kid,
                    )
                )
        signatures.write(playbooks_dir / "SIGNATURES")
        return playbooks_dir

    return _build
