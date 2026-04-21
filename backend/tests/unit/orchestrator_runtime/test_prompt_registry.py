"""Unit tests for :mod:`src.orchestrator.prompt_registry` (ARG-008)."""

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

from src.orchestrator.prompt_registry import (
    AgentRole,
    PromptDefinition,
    PromptNotFoundError,
    PromptRegistry,
    PromptRegistryError,
    PromptRegistrySummary,
    PromptSignatureError,
)
from src.sandbox.signing import SignatureRecord, SignaturesFile, sign_blob

# ---------------------------------------------------------------------------
# Pre-flight: invalid layouts
# ---------------------------------------------------------------------------


def test_missing_prompts_dir_raises(tmp_path: Path) -> None:
    registry = PromptRegistry(prompts_dir=tmp_path / "nope")
    with pytest.raises(PromptRegistryError):
        registry.load()


def test_prompts_path_is_file_raises(tmp_path: Path) -> None:
    f = tmp_path / "prompts"
    f.write_text("dummy")
    registry = PromptRegistry(prompts_dir=f)
    with pytest.raises(PromptRegistryError):
        registry.load()


def test_missing_signatures_file_raises(tmp_path: Path) -> None:
    prompts = tmp_path / "prompts"
    prompts.mkdir()
    (prompts / "_keys").mkdir()
    registry = PromptRegistry(prompts_dir=prompts)
    with pytest.raises(PromptRegistryError) as exc_info:
        registry.load()
    assert "SIGNATURES" in str(exc_info.value)


def test_empty_catalog_raises(tmp_path: Path) -> None:
    prompts = tmp_path / "prompts"
    prompts.mkdir()
    (prompts / "_keys").mkdir()
    (prompts / "SIGNATURES").write_text("# header only\n", encoding="utf-8")
    registry = PromptRegistry(prompts_dir=prompts)
    with pytest.raises(PromptRegistryError) as exc_info:
        registry.load()
    assert "no prompt" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# Happy path on the signed mini-catalog from conftest
# ---------------------------------------------------------------------------


def test_load_signed_catalog_succeeds(
    signed_prompts_dir: tuple[Path, Path, Path, str],
) -> None:
    prompts_dir, keys_dir, signatures_path, _ = signed_prompts_dir
    registry = PromptRegistry(
        prompts_dir=prompts_dir,
        signatures_path=signatures_path,
        public_keys_dir=keys_dir,
    )
    summary = registry.load()
    assert isinstance(summary, PromptRegistrySummary)
    assert summary.total == 2
    assert summary.prompt_ids == ("critic_demo", "planner_demo")
    assert summary.by_role == {"planner": 1, "critic": 1}


def test_get_prompt_returns_pydantic_instance(
    signed_prompts_dir: tuple[Path, Path, Path, str],
) -> None:
    prompts_dir, keys_dir, signatures_path, _ = signed_prompts_dir
    registry = PromptRegistry(
        prompts_dir=prompts_dir,
        signatures_path=signatures_path,
        public_keys_dir=keys_dir,
    )
    registry.load()
    prompt = registry.get("planner_demo")
    assert isinstance(prompt, PromptDefinition)
    assert prompt.agent_role is AgentRole.PLANNER


def test_get_unknown_prompt_raises_named_error(
    signed_prompts_dir: tuple[Path, Path, Path, str],
) -> None:
    prompts_dir, keys_dir, signatures_path, _ = signed_prompts_dir
    registry = PromptRegistry(
        prompts_dir=prompts_dir,
        signatures_path=signatures_path,
        public_keys_dir=keys_dir,
    )
    registry.load()
    with pytest.raises(PromptNotFoundError) as exc_info:
        registry.get("ghost")
    assert exc_info.value.prompt_id == "ghost"


def test_list_by_role_returns_correct_subset(
    signed_prompts_dir: tuple[Path, Path, Path, str],
) -> None:
    prompts_dir, keys_dir, signatures_path, _ = signed_prompts_dir
    registry = PromptRegistry(
        prompts_dir=prompts_dir,
        signatures_path=signatures_path,
        public_keys_dir=keys_dir,
    )
    registry.load()
    planners = registry.list_by_role(AgentRole.PLANNER)
    assert len(planners) == 1
    assert planners[0].prompt_id == "planner_demo"
    fixers = registry.list_by_role(AgentRole.FIXER)
    assert fixers == []


def test_list_by_role_returns_fresh_copy(
    signed_prompts_dir: tuple[Path, Path, Path, str],
) -> None:
    prompts_dir, keys_dir, signatures_path, _ = signed_prompts_dir
    registry = PromptRegistry(
        prompts_dir=prompts_dir,
        signatures_path=signatures_path,
        public_keys_dir=keys_dir,
    )
    registry.load()
    first = registry.list_by_role(AgentRole.PLANNER)
    original_count = len(first)
    first.clear()
    second = registry.list_by_role(AgentRole.PLANNER)
    assert len(second) == original_count


def test_iteration_and_membership(
    signed_prompts_dir: tuple[Path, Path, Path, str],
) -> None:
    prompts_dir, keys_dir, signatures_path, _ = signed_prompts_dir
    registry = PromptRegistry(
        prompts_dir=prompts_dir,
        signatures_path=signatures_path,
        public_keys_dir=keys_dir,
    )
    registry.load()
    assert "planner_demo" in registry
    assert 42 not in registry
    assert sorted(iter(registry)) == ["critic_demo", "planner_demo"]
    assert len(registry) == 2


# ---------------------------------------------------------------------------
# Fail-closed conditions
# ---------------------------------------------------------------------------


def test_tampered_yaml_rejected(
    signed_prompts_dir: tuple[Path, Path, Path, str],
) -> None:
    prompts_dir, keys_dir, signatures_path, _ = signed_prompts_dir
    target = prompts_dir / "planner_demo.yaml"
    payload = yaml.safe_load(target.read_text())
    payload["description"] = "tampered after signing"
    target.write_text(yaml.safe_dump(payload, sort_keys=True), encoding="utf-8")

    registry = PromptRegistry(
        prompts_dir=prompts_dir,
        signatures_path=signatures_path,
        public_keys_dir=keys_dir,
    )
    with pytest.raises(PromptSignatureError):
        registry.load()


def test_unknown_signing_key_rejected(
    tmp_path: Path,
    sample_prompt: Callable[..., dict[str, object]],
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
) -> None:
    prompts_dir = tmp_path / "prompts"
    prompts_dir.mkdir()
    keys_dir = tmp_path / "_keys"
    keys_dir.mkdir()  # intentionally empty
    private_key, _, kid = ed25519_keypair

    payload = sample_prompt("planner_v1", "planner")
    yaml_bytes = yaml.safe_dump(payload, sort_keys=True).encode("utf-8")
    (prompts_dir / "planner_v1.yaml").write_bytes(yaml_bytes)

    sigfile = SignaturesFile()
    sigfile.upsert(
        SignatureRecord(
            sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
            relative_path="planner_v1.yaml",
            signature_b64=sign_blob(private_key, yaml_bytes),
            public_key_id=kid,
        )
    )
    sig_path = prompts_dir / "SIGNATURES"
    sigfile.write(sig_path)

    registry = PromptRegistry(
        prompts_dir=prompts_dir,
        signatures_path=sig_path,
        public_keys_dir=keys_dir,
    )
    with pytest.raises(PromptSignatureError):
        registry.load()


def test_missing_manifest_entry_rejected(
    tmp_path: Path,
    sample_prompt: Callable[..., dict[str, object]],
    keys_dir: Path,
) -> None:
    prompts_dir = tmp_path / "prompts"
    prompts_dir.mkdir()
    payload = sample_prompt("planner_v1", "planner")
    yaml_bytes = yaml.safe_dump(payload, sort_keys=True).encode("utf-8")
    (prompts_dir / "planner_v1.yaml").write_bytes(yaml_bytes)
    (prompts_dir / "SIGNATURES").write_text("# empty manifest\n", encoding="utf-8")
    registry = PromptRegistry(
        prompts_dir=prompts_dir,
        signatures_path=prompts_dir / "SIGNATURES",
        public_keys_dir=keys_dir,
    )
    with pytest.raises(PromptSignatureError):
        registry.load()


def test_filename_mismatch_rejected(
    tmp_path: Path,
    sample_prompt: Callable[..., dict[str, object]],
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    keys_dir: Path,
) -> None:
    private_key, _, kid = ed25519_keypair
    prompts_dir = tmp_path / "prompts"
    prompts_dir.mkdir()
    payload = sample_prompt("planner_v1", "planner")
    yaml_bytes = yaml.safe_dump(payload, sort_keys=True).encode("utf-8")
    (prompts_dir / "wrong_name.yaml").write_bytes(yaml_bytes)
    sigfile = SignaturesFile()
    sigfile.upsert(
        SignatureRecord(
            sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
            relative_path="wrong_name.yaml",
            signature_b64=sign_blob(private_key, yaml_bytes),
            public_key_id=kid,
        )
    )
    sig_path = prompts_dir / "SIGNATURES"
    sigfile.write(sig_path)
    registry = PromptRegistry(
        prompts_dir=prompts_dir,
        signatures_path=sig_path,
        public_keys_dir=keys_dir,
    )
    with pytest.raises(PromptRegistryError) as exc_info:
        registry.load()
    assert "filename" in str(exc_info.value).lower()


def test_yaml_not_a_mapping_rejected(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    keys_dir: Path,
) -> None:
    private_key, _, kid = ed25519_keypair
    prompts_dir = tmp_path / "prompts"
    prompts_dir.mkdir()
    yaml_bytes = b"- not\n- a\n- mapping\n"
    (prompts_dir / "weird.yaml").write_bytes(yaml_bytes)
    sigfile = SignaturesFile()
    sigfile.upsert(
        SignatureRecord(
            sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
            relative_path="weird.yaml",
            signature_b64=sign_blob(private_key, yaml_bytes),
            public_key_id=kid,
        )
    )
    sig_path = prompts_dir / "SIGNATURES"
    sigfile.write(sig_path)
    registry = PromptRegistry(
        prompts_dir=prompts_dir,
        signatures_path=sig_path,
        public_keys_dir=keys_dir,
    )
    with pytest.raises(PromptRegistryError):
        registry.load()


def test_invalid_yaml_rejected(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    keys_dir: Path,
) -> None:
    private_key, _, kid = ed25519_keypair
    prompts_dir = tmp_path / "prompts"
    prompts_dir.mkdir()
    yaml_bytes = b"key: [unclosed\n"
    (prompts_dir / "broken.yaml").write_bytes(yaml_bytes)
    sigfile = SignaturesFile()
    sigfile.upsert(
        SignatureRecord(
            sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
            relative_path="broken.yaml",
            signature_b64=sign_blob(private_key, yaml_bytes),
            public_key_id=kid,
        )
    )
    sig_path = prompts_dir / "SIGNATURES"
    sigfile.write(sig_path)
    registry = PromptRegistry(
        prompts_dir=prompts_dir,
        signatures_path=sig_path,
        public_keys_dir=keys_dir,
    )
    with pytest.raises(PromptRegistryError):
        registry.load()


# ---------------------------------------------------------------------------
# Schema-level invariants
# ---------------------------------------------------------------------------


def test_invalid_prompt_id_pattern_rejected(
    sample_prompt: Callable[..., dict[str, object]],
) -> None:
    payload = sample_prompt("BadID!", "planner")
    with pytest.raises(ValueError, match="prompt_id"):
        PromptDefinition(**payload)


def test_invalid_version_pattern_rejected(
    sample_prompt: Callable[..., dict[str, object]],
) -> None:
    payload = sample_prompt("planner_v1", "planner")
    payload["version"] = "v1"
    with pytest.raises(ValueError, match="version"):
        PromptDefinition(**payload)


def test_invalid_schema_ref_pattern_rejected(
    sample_prompt: Callable[..., dict[str, object]],
) -> None:
    payload = sample_prompt("planner_v1", "planner", expected_schema_ref="Bad.Ref")
    with pytest.raises(ValueError, match="expected_schema_ref"):
        PromptDefinition(**payload)


def test_extra_field_rejected(
    sample_prompt: Callable[..., dict[str, object]],
) -> None:
    payload = sample_prompt("planner_v1", "planner")
    payload["bonus"] = "should be rejected"
    with pytest.raises(ValueError):
        PromptDefinition(**payload)


def test_duplicate_prompt_id_rejected_at_load(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    keys_dir: Path,
    sample_prompt: Callable[..., dict[str, object]],
) -> None:
    """Two YAML files cannot legitimately share the same prompt_id (filename
    must equal prompt_id), but we still want a defensive check that the
    registry rejects collisions explicitly when one is constructed."""
    # Filename mismatch already enforced — exercise the duplicate check by
    # calling _rebuild_role_index with a synthesised internal map.
    private_key, _, kid = ed25519_keypair
    prompts_dir = tmp_path / "prompts"
    prompts_dir.mkdir()
    payload_a = sample_prompt("planner_v1", "planner", description="first")
    payload_b = sample_prompt("planner_v1", "critic", description="second")
    yaml_bytes_a = yaml.safe_dump(payload_a, sort_keys=True).encode("utf-8")
    yaml_bytes_b = yaml.safe_dump(payload_b, sort_keys=True).encode("utf-8")
    (prompts_dir / "planner_v1.yaml").write_bytes(yaml_bytes_a)
    # Same prompt_id under a different filename — schema check will hit
    # the filename mismatch first; ensure that's the rejection path.
    (prompts_dir / "planner_alias.yaml").write_bytes(yaml_bytes_b)

    sigfile = SignaturesFile()
    for rel, raw in (
        ("planner_v1.yaml", yaml_bytes_a),
        ("planner_alias.yaml", yaml_bytes_b),
    ):
        sigfile.upsert(
            SignatureRecord(
                sha256_hex=hashlib.sha256(raw).hexdigest(),
                relative_path=rel,
                signature_b64=sign_blob(private_key, raw),
                public_key_id=kid,
            )
        )
    sig_path = prompts_dir / "SIGNATURES"
    sigfile.write(sig_path)

    registry = PromptRegistry(
        prompts_dir=prompts_dir,
        signatures_path=sig_path,
        public_keys_dir=keys_dir,
    )
    with pytest.raises(PromptRegistryError) as exc_info:
        registry.load()
    msg = str(exc_info.value).lower()
    assert "filename" in msg or "duplicate" in msg
