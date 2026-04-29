"""P2-005 — signed Phase-2 safe curriculum catalog (production tree)."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Final

import pytest
import yaml

from src.payloads.registry import PayloadRegistry, PayloadSignatureError

_BACKEND: Final[Path] = Path(__file__).resolve().parents[1]
_CATALOG: Final[Path] = _BACKEND / "config" / "payloads"

_PHASE2_SAFE_FAMILIES: Final[frozenset[str]] = frozenset(
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


@pytest.fixture(scope="module")
def prod_catalog_dir() -> Path:
    assert _CATALOG.is_dir(), f"missing payload catalog at {_CATALOG}"
    return _CATALOG


def test_payload_catalog_signed_and_loaded(prod_catalog_dir: Path) -> None:
    reg = PayloadRegistry(payloads_dir=prod_catalog_dir)
    summary = reg.load()
    assert summary.total >= len(_PHASE2_SAFE_FAMILIES)
    for fid in sorted(_PHASE2_SAFE_FAMILIES):
        assert fid in reg, f"missing signed safe family {fid!r}"
        fam = reg.get_family(fid)
        assert 1 <= len(fam.payloads) <= 4
        for p in fam.payloads:
            assert len(p.template) >= 4


def test_payload_catalog_rejects_tampered_signed_yaml(
    prod_catalog_dir: Path, tmp_path: Path
) -> None:
    """Any byte change invalidates Ed25519 manifest entries (fail-closed)."""
    dest = tmp_path / "payloads"
    shutil.copytree(prod_catalog_dir, dest)
    target = dest / "sqli_safe.yaml"
    payload = yaml.safe_load(target.read_text(encoding="utf-8"))
    payload["description"] = payload.get("description", "") + " [tampered]"
    target.write_text(
        yaml.safe_dump(payload, sort_keys=True, allow_unicode=True),
        encoding="utf-8",
    )
    with pytest.raises(PayloadSignatureError):
        PayloadRegistry(payloads_dir=dest).load()
