"""Unit tests for :mod:`src.sandbox.tool_registry`.

Verifies the fail-closed contract documented in Backlog/dev1_md §3 / §18:
no untrusted YAML, no template typo, no duplicate tool_id may pass through
:meth:`ToolRegistry.load`.
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

from src.pipeline.contracts.phase_io import ScanPhase
from src.sandbox.adapter_base import ToolCategory, ToolDescriptor
from src.sandbox.signing import SignatureRecord, SignaturesFile, sign_blob
from src.sandbox.tool_registry import (
    RegistryLoadError,
    RegistrySummary,
    ToolRegistry,
)


# ---------------------------------------------------------------------------
# Empty catalog
# ---------------------------------------------------------------------------


def test_empty_catalog_is_valid(tmp_path: Path) -> None:
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "_keys").mkdir()
    (tools / "SIGNATURES").write_text("# header only\n", encoding="utf-8")
    registry = ToolRegistry(tools_dir=tools)
    summary = registry.load()
    assert isinstance(summary, RegistrySummary)
    assert summary.total == 0
    assert summary.tool_ids == ()
    assert len(registry) == 0


def test_missing_tools_dir_raises(tmp_path: Path) -> None:
    registry = ToolRegistry(tools_dir=tmp_path / "nope")
    with pytest.raises(RegistryLoadError):
        registry.load()


def test_tools_path_is_file_raises(tmp_path: Path) -> None:
    f = tmp_path / "tools"
    f.write_text("dummy")
    registry = ToolRegistry(tools_dir=f)
    with pytest.raises(RegistryLoadError):
        registry.load()


def test_missing_signatures_file_raises(tmp_path: Path) -> None:
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "_keys").mkdir()
    registry = ToolRegistry(tools_dir=tools)
    with pytest.raises(RegistryLoadError):
        registry.load()


# ---------------------------------------------------------------------------
# Happy path on a fully-signed catalog
# ---------------------------------------------------------------------------


def test_load_signed_catalog_succeeds(
    signed_tools_dir: tuple[Path, Path, Path, str],
) -> None:
    tools_dir, keys_dir, signatures_path, _ = signed_tools_dir
    registry = ToolRegistry(
        tools_dir=tools_dir,
        keys_dir=keys_dir,
        signatures_path=signatures_path,
    )
    summary = registry.load()
    assert summary.total == 2
    assert summary.tool_ids == ("httpx_probe", "nmap_quick")
    assert summary.by_phase == {"recon": 1, "vuln_analysis": 1}
    assert summary.by_category == {"recon": 1, "web_va": 1}


def test_get_returns_descriptor(signed_tools_dir: tuple[Path, Path, Path, str]) -> None:
    tools_dir, keys_dir, signatures_path, _ = signed_tools_dir
    registry = ToolRegistry(
        tools_dir=tools_dir, keys_dir=keys_dir, signatures_path=signatures_path
    )
    registry.load()
    descriptor = registry.get("nmap_quick")
    assert isinstance(descriptor, ToolDescriptor)
    assert descriptor.tool_id == "nmap_quick"
    assert registry.get("ghost") is None


def test_get_adapter_returns_adapter(
    signed_tools_dir: tuple[Path, Path, Path, str],
) -> None:
    tools_dir, keys_dir, signatures_path, _ = signed_tools_dir
    registry = ToolRegistry(
        tools_dir=tools_dir, keys_dir=keys_dir, signatures_path=signatures_path
    )
    registry.load()
    adapter = registry.get_adapter("nmap_quick")
    assert adapter is not None
    assert adapter.tool_id == "nmap_quick"
    assert registry.get_adapter("ghost") is None


def test_list_by_phase_filters(
    signed_tools_dir: tuple[Path, Path, Path, str],
) -> None:
    tools_dir, keys_dir, signatures_path, _ = signed_tools_dir
    registry = ToolRegistry(
        tools_dir=tools_dir, keys_dir=keys_dir, signatures_path=signatures_path
    )
    registry.load()
    recon_tools = registry.list_by_phase(ScanPhase.RECON)
    assert {t.tool_id for t in recon_tools} == {"nmap_quick"}
    web_tools = registry.list_by_phase(ScanPhase.VULN_ANALYSIS)
    assert {t.tool_id for t in web_tools} == {"httpx_probe"}
    assert registry.list_by_phase(ScanPhase.REPORTING) == []


def test_list_by_category_filters(
    signed_tools_dir: tuple[Path, Path, Path, str],
) -> None:
    tools_dir, keys_dir, signatures_path, _ = signed_tools_dir
    registry = ToolRegistry(
        tools_dir=tools_dir, keys_dir=keys_dir, signatures_path=signatures_path
    )
    registry.load()
    web = registry.list_by_category(ToolCategory.WEB_VA)
    assert {t.tool_id for t in web} == {"httpx_probe"}


def test_iteration_and_membership(
    signed_tools_dir: tuple[Path, Path, Path, str],
) -> None:
    tools_dir, keys_dir, signatures_path, _ = signed_tools_dir
    registry = ToolRegistry(
        tools_dir=tools_dir, keys_dir=keys_dir, signatures_path=signatures_path
    )
    registry.load()
    assert "nmap_quick" in registry
    assert 42 not in registry
    assert sorted(iter(registry)) == ["httpx_probe", "nmap_quick"]


# ---------------------------------------------------------------------------
# Fail-closed conditions
# ---------------------------------------------------------------------------


def test_tampered_yaml_rejected(
    signed_tools_dir: tuple[Path, Path, Path, str],
) -> None:
    tools_dir, keys_dir, signatures_path, _ = signed_tools_dir
    nmap_yaml = tools_dir / "nmap_quick.yaml"
    payload = yaml.safe_load(nmap_yaml.read_text())
    payload["risk_level"] = "destructive"
    payload["requires_approval"] = True
    nmap_yaml.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")

    registry = ToolRegistry(
        tools_dir=tools_dir, keys_dir=keys_dir, signatures_path=signatures_path
    )
    with pytest.raises(RegistryLoadError) as exc_info:
        registry.load()
    assert "signature" in str(exc_info.value).lower()


def test_unknown_signing_key_rejected(
    tmp_path: Path,
    sample_descriptor_payload: Callable[..., dict[str, object]],
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    keys_dir = tmp_path / "_keys"
    keys_dir.mkdir()  # intentionally empty — no key matches the signing kid
    private_key, _, kid = ed25519_keypair

    payload = sample_descriptor_payload()
    yaml_bytes = yaml.safe_dump(payload, sort_keys=True).encode("utf-8")
    (tools_dir / "nmap_quick.yaml").write_bytes(yaml_bytes)

    sigfile = SignaturesFile()
    sigfile.upsert(
        SignatureRecord(
            sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
            relative_path="nmap_quick.yaml",
            signature_b64=sign_blob(private_key, yaml_bytes),
            public_key_id=kid,
        )
    )
    sig_path = tools_dir / "SIGNATURES"
    sigfile.write(sig_path)

    registry = ToolRegistry(
        tools_dir=tools_dir, keys_dir=keys_dir, signatures_path=sig_path
    )
    with pytest.raises(RegistryLoadError):
        registry.load()


def test_missing_manifest_entry_rejected(
    tmp_path: Path,
    sample_descriptor_payload: Callable[..., dict[str, object]],
    keys_dir: Path,
) -> None:
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    payload = sample_descriptor_payload()
    yaml_bytes = yaml.safe_dump(payload, sort_keys=True).encode("utf-8")
    (tools_dir / "nmap_quick.yaml").write_bytes(yaml_bytes)
    (tools_dir / "SIGNATURES").write_text("# empty manifest\n", encoding="utf-8")

    registry = ToolRegistry(
        tools_dir=tools_dir,
        keys_dir=keys_dir,
        signatures_path=tools_dir / "SIGNATURES",
    )
    with pytest.raises(RegistryLoadError):
        registry.load()


def test_duplicate_tool_id_rejected(
    tmp_path: Path,
    sample_descriptor_payload: Callable[..., dict[str, object]],
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    keys_dir: Path,
) -> None:
    private_key, _, kid = ed25519_keypair
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    sigfile = SignaturesFile()
    for filename in ("a.yaml", "b.yaml"):
        payload = sample_descriptor_payload()  # both have tool_id "nmap_quick"
        yaml_bytes = yaml.safe_dump(payload, sort_keys=True).encode("utf-8")
        (tools_dir / filename).write_bytes(yaml_bytes)
        sigfile.upsert(
            SignatureRecord(
                sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
                relative_path=filename,
                signature_b64=sign_blob(private_key, yaml_bytes),
                public_key_id=kid,
            )
        )
    sig_path = tools_dir / "SIGNATURES"
    sigfile.write(sig_path)
    registry = ToolRegistry(
        tools_dir=tools_dir, keys_dir=keys_dir, signatures_path=sig_path
    )
    with pytest.raises(RegistryLoadError) as exc_info:
        registry.load()
    assert "duplicate" in str(exc_info.value).lower()


def test_yaml_not_a_mapping_rejected(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    keys_dir: Path,
) -> None:
    private_key, _, kid = ed25519_keypair
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    yaml_bytes = b"- not\n- a\n- mapping\n"
    (tools_dir / "weird.yaml").write_bytes(yaml_bytes)
    sigfile = SignaturesFile()
    sigfile.upsert(
        SignatureRecord(
            sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
            relative_path="weird.yaml",
            signature_b64=sign_blob(private_key, yaml_bytes),
            public_key_id=kid,
        )
    )
    sig_path = tools_dir / "SIGNATURES"
    sigfile.write(sig_path)
    registry = ToolRegistry(
        tools_dir=tools_dir, keys_dir=keys_dir, signatures_path=sig_path
    )
    with pytest.raises(RegistryLoadError):
        registry.load()


def test_invalid_yaml_rejected(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    keys_dir: Path,
) -> None:
    private_key, _, kid = ed25519_keypair
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    yaml_bytes = b"key: [unclosed\n"
    (tools_dir / "broken.yaml").write_bytes(yaml_bytes)
    sigfile = SignaturesFile()
    sigfile.upsert(
        SignatureRecord(
            sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
            relative_path="broken.yaml",
            signature_b64=sign_blob(private_key, yaml_bytes),
            public_key_id=kid,
        )
    )
    sig_path = tools_dir / "SIGNATURES"
    sigfile.write(sig_path)
    registry = ToolRegistry(
        tools_dir=tools_dir, keys_dir=keys_dir, signatures_path=sig_path
    )
    with pytest.raises(RegistryLoadError):
        registry.load()


def test_invalid_descriptor_schema_rejected(
    tmp_path: Path,
    sample_descriptor_payload: Callable[..., dict[str, object]],
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    keys_dir: Path,
) -> None:
    private_key, _, kid = ed25519_keypair
    payload = sample_descriptor_payload()
    payload["risk_level"] = "extremely_destructive"  # not in enum
    yaml_bytes = yaml.safe_dump(payload, sort_keys=True).encode("utf-8")

    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    (tools_dir / "bad_enum.yaml").write_bytes(yaml_bytes)
    sigfile = SignaturesFile()
    sigfile.upsert(
        SignatureRecord(
            sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
            relative_path="bad_enum.yaml",
            signature_b64=sign_blob(private_key, yaml_bytes),
            public_key_id=kid,
        )
    )
    sig_path = tools_dir / "SIGNATURES"
    sigfile.write(sig_path)
    registry = ToolRegistry(
        tools_dir=tools_dir, keys_dir=keys_dir, signatures_path=sig_path
    )
    with pytest.raises(RegistryLoadError):
        registry.load()


def test_template_with_unknown_placeholder_rejected(
    tmp_path: Path,
    sample_descriptor_payload: Callable[..., dict[str, object]],
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    keys_dir: Path,
) -> None:
    private_key, _, kid = ed25519_keypair
    payload = sample_descriptor_payload()
    payload["command_template"] = ["nmap", "{not_in_allowlist}"]
    yaml_bytes = yaml.safe_dump(payload, sort_keys=True).encode("utf-8")

    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    (tools_dir / "bad_template.yaml").write_bytes(yaml_bytes)
    sigfile = SignaturesFile()
    sigfile.upsert(
        SignatureRecord(
            sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
            relative_path="bad_template.yaml",
            signature_b64=sign_blob(private_key, yaml_bytes),
            public_key_id=kid,
        )
    )
    sig_path = tools_dir / "SIGNATURES"
    sigfile.write(sig_path)
    registry = ToolRegistry(
        tools_dir=tools_dir, keys_dir=keys_dir, signatures_path=sig_path
    )
    with pytest.raises(RegistryLoadError):
        registry.load()


def test_validate_template_placeholders_helper(
    sample_descriptor_payload: Callable[..., dict[str, object]],
) -> None:
    payload = sample_descriptor_payload()
    descriptor = ToolDescriptor(**payload)  # type: ignore[arg-type]
    ToolRegistry.validate_template_placeholders(descriptor)  # does not raise
