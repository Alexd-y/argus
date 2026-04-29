"""Phase 2 signed safe catalog coverage (P2-005)."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Final

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.payloads.registry import PayloadRegistry, PayloadSignatureError
from src.sandbox.signing import SignatureRecord, SignaturesFile, public_key_id, sign_blob

PHASE2_SAFE_FAMILY_IDS: Final[frozenset[str]] = frozenset(
    {
        "xss_contextual",
        "sqli_safe",
        "nosqli_safe",
        "ldapi_safe",
        "xpathi_safe",
        "ssti_safe",
        "ssrf_oast_safe",
        "xxe_oast_safe",
        "command_injection_safe",
        "crlf_safe",
        "traversal_safe",
        "prototype_pollution_safe",
        "graphql_safe",
        "jwt_safe",
        "mass_assignment_safe",
        "open_redirect_safe",
    }
)


@pytest.fixture(scope="session")
def catalog_dir() -> Path:
    here = Path(__file__).resolve()
    backend_dir = here.parents[3]
    catalog = backend_dir / "config" / "payloads"
    assert catalog.is_dir(), f"expected catalog dir at {catalog}"
    return catalog


@pytest.fixture(scope="session")
def phase2_loaded_registry(catalog_dir: Path) -> PayloadRegistry:
    registry = PayloadRegistry(payloads_dir=catalog_dir)
    registry.load()
    return registry


def test_payload_catalog_signed_and_loaded(
    phase2_loaded_registry: PayloadRegistry,
) -> None:
    loaded = set(phase2_loaded_registry)
    missing = PHASE2_SAFE_FAMILY_IDS - loaded
    assert not missing, f"missing Phase 2 families: {sorted(missing)}"
    for fid in sorted(PHASE2_SAFE_FAMILY_IDS):
        fam = phase2_loaded_registry.get_family(fid)
        assert len(fam.payloads) >= 1
        assert fam.risk_level.value in {"passive", "low", "medium"}


def test_tampered_yaml_rejected_fail_closed(tmp_path: Path) -> None:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    kid = public_key_id(pub)

    keys = tmp_path / "_keys"
    keys.mkdir()
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    (keys / f"{kid}.ed25519.pub").write_bytes(pub_bytes)

    payloads_dir = tmp_path / "payloads"
    payloads_dir.mkdir()

    family = {
        "family_id": "phase2_sig_demo",
        "description": "demo",
        "cwe_ids": [89],
        "owasp_top10": ["A03:2021"],
        "risk_level": "low",
        "requires_approval": False,
        "oast_required": False,
        "payloads": [
            {
                "id": "one",
                "template": "SIG_DEMO_A",
                "confidence": "suspected",
                "notes": "",
            },
        ],
        "mutations": [],
        "encodings": [],
    }
    rel = "phase2_sig_demo.yaml"
    yaml_path = payloads_dir / rel
    yaml_bytes = yaml.safe_dump(family, sort_keys=True).encode("utf-8")
    yaml_path.write_bytes(yaml_bytes)

    sig = SignaturesFile()
    sig.upsert(
        SignatureRecord(
            sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
            relative_path=rel,
            signature_b64=sign_blob(priv, yaml_bytes),
            public_key_id=kid,
        )
    )
    sig.write(payloads_dir / "SIGNATURES")

    PayloadRegistry(payloads_dir=payloads_dir, keys_dir=keys).load()

    tampered = yaml.safe_load(yaml_path.read_bytes())
    assert isinstance(tampered, dict)
    tampered["description"] = "tampered"
    yaml_path.write_bytes(yaml.safe_dump(tampered, sort_keys=True).encode("utf-8"))

    reg_bad = PayloadRegistry(payloads_dir=payloads_dir, keys_dir=keys)
    with pytest.raises(PayloadSignatureError):
        reg_bad.load()
