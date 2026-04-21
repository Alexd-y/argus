"""Shared fixtures for the :mod:`src.sandbox` test suite."""

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
    tmp_path: Path, ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str]
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


def _sample_descriptor_payload(tool_id: str = "nmap_quick") -> dict[str, object]:
    """Return a minimal valid :class:`ToolDescriptor` YAML payload."""
    return {
        "tool_id": tool_id,
        "category": "recon",
        "phase": "recon",
        "risk_level": "passive",
        "requires_approval": False,
        "network_policy": {
            "name": "recon",
            "egress_allowlist": ["10.0.0.0/8"],
            "dns_resolvers": ["1.1.1.1"],
        },
        "seccomp_profile": "profiles/recon-default.json",
        "default_timeout_s": 300,
        "cpu_limit": "500m",
        "memory_limit": "256Mi",
        "pids_limit": 256,
        "image": "argus/nmap:7.94",
        "command_template": [
            "nmap",
            "-Pn",
            "-T4",
            "{host}",
            "-oX",
            "{out_dir}/nmap.xml",
        ],
        "parse_strategy": "xml_nmap",
        "evidence_artifacts": ["nmap.xml"],
        "cwe_hints": [200],
        "owasp_wstg": ["WSTG-INFO-02"],
    }


@pytest.fixture()
def sample_descriptor_payload() -> Callable[..., dict[str, object]]:
    """Factory that returns a fresh sample descriptor payload per call."""
    return _sample_descriptor_payload


@pytest.fixture()
def signed_tools_dir(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> tuple[Path, Path, Path, str]:
    """Build a complete signed catalog under ``tmp_path`` and return the layout.

    Returns ``(tools_dir, keys_dir, signatures_path, key_id)`` so a test can
    drive :class:`ToolRegistry` directly.
    """
    private_key, public_key, kid = ed25519_keypair
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()

    keys = tmp_path / "_keys"
    keys.mkdir()
    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    (keys / f"{kid}.ed25519.pub").write_bytes(pub_bytes)

    payloads = [
        _sample_descriptor_payload("nmap_quick"),
        _sample_descriptor_payload("httpx_probe")
        | {
            "phase": "vuln_analysis",
            "category": "web_va",
            "command_template": ["httpx", "-u", "{url}"],
            "parse_strategy": "json_lines",
            "evidence_artifacts": [],
            "cwe_hints": [],
            "owasp_wstg": [],
        },
    ]

    signatures = SignaturesFile()
    for payload in payloads:
        relative = f"{payload['tool_id']}.yaml"
        yaml_path = tools_dir / relative
        yaml_bytes = yaml.safe_dump(payload, sort_keys=True).encode("utf-8")
        yaml_path.write_bytes(yaml_bytes)
        signatures.upsert(
            SignatureRecord(
                sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
                relative_path=relative,
                signature_b64=sign_blob(private_key, yaml_bytes),
                public_key_id=kid,
            )
        )

    signatures_path = tools_dir / "SIGNATURES"
    signatures.write(signatures_path)

    return tools_dir, keys, signatures_path, kid
