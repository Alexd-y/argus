"""QUICK-001 — Nuclei planner/registry treat Quick like production, not LAB."""

from __future__ import annotations

import pytest

from src.execution_mode.mode import ExecutionMode
from src.nuclei.execution_planner import NucleiExecutionPlanner
from src.nuclei.profile_compiler import PROFILE_DIR, default_profile_id_for_mode
from src.nuclei.schemas import (
    LabTemplateArtifact,
    NucleiTemplateManifest,
    ScanProfile,
    TemplateSource,
)
from src.nuclei.template_registry import NucleiTemplateRegistry, TemplateRegistryError

_SHA256 = "a" * 64


def _safe_manifest(template_id: str = "http-fingerprint") -> NucleiTemplateManifest:
    return NucleiTemplateManifest(
        template_id=template_id,
        version="1",
        source=TemplateSource.INTERNAL,
        sha256=_SHA256,
        signature="sig",
        verified=True,
        protocols=("http",),
        risk_level="passive",
    )


def _unsigned_tenant_manifest(template_id: str = "tenant-unsigned") -> NucleiTemplateManifest:
    return NucleiTemplateManifest(
        template_id=template_id,
        version="1",
        source=TemplateSource.TENANT,
        sha256=_SHA256,
        signature=None,
        verified=True,
        protocols=("http",),
        risk_level="passive",
    )


def _destructive_manifest(template_id: str = "code-rce") -> NucleiTemplateManifest:
    return NucleiTemplateManifest(
        template_id=template_id,
        version="1",
        source=TemplateSource.INTERNAL,
        sha256=_SHA256,
        signature="sig",
        verified=True,
        protocols=("code",),
        risk_level="code_execution",
    )


def test_lab_short_circuit_does_not_trigger_for_quick() -> None:
    planner = NucleiExecutionPlanner()
    profile = ScanProfile(id="gate-test", requires_approval=True)
    candidates = ("unknown-template",)

    lab = planner.plan(candidates, profile, ExecutionMode.LAB_UNRESTRICTED)
    assert lab.mode == "lab_unrestricted"
    assert lab.template_ids == candidates
    assert lab.requires_approval is False
    assert lab.blocked_reasons == ()

    quick = planner.plan(candidates, profile, ExecutionMode.QUICK)
    assert quick.mode == "quick"
    assert "unknown-template" not in quick.template_ids
    assert "profile_requires_approval" in quick.blocked_reasons
    assert any(reason.startswith("unknown_template:") for reason in quick.blocked_reasons)


def test_quick_planner_matches_production_gates_not_lab() -> None:
    registry = NucleiTemplateRegistry()
    safe = _safe_manifest()
    destructive = _destructive_manifest()
    registry.register(safe, mode=ExecutionMode.QUICK)
    registry.register(destructive, mode=ExecutionMode.QUICK, skip_signature_gate=True)

    planner = NucleiExecutionPlanner(registry=registry)
    profile = ScanProfile(id="quick-default", requires_approval=False)
    candidates = (safe.template_id, destructive.template_id, "missing")

    lab = planner.plan(candidates, profile, ExecutionMode.LAB_UNRESTRICTED)
    assert lab.template_ids == candidates
    assert lab.blocked_reasons == ()

    quick = planner.plan(candidates, profile, ExecutionMode.QUICK)
    production = planner.plan(candidates, profile, ExecutionMode.PRODUCTION)
    assert quick.template_ids == production.template_ids == (safe.template_id,)
    assert f"production_denied:{destructive.template_id}" in quick.blocked_reasons
    assert "unknown_template:missing" in quick.blocked_reasons


def test_default_profile_id_for_mode_quick_is_quick_default_or_fingerprint_safe() -> None:
    profile_id = default_profile_id_for_mode(ExecutionMode.QUICK)
    assert profile_id in {"quick-default", "fingerprint_safe"}
    quick_yaml = PROFILE_DIR / "quick-default.yaml"
    if quick_yaml.is_file():
        assert profile_id == "quick-default"
    else:
        assert profile_id == "fingerprint_safe"


def test_default_profile_id_for_mode_quick_prefers_quick_default(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "quick-default.yaml").write_text("id: quick-default\n", encoding="utf-8")
    monkeypatch.setattr("src.nuclei.profile_compiler.PROFILE_DIR", tmp_path)
    assert default_profile_id_for_mode("quick") == "quick-default"


def test_default_profile_id_for_mode_quick_falls_back_without_yaml(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("src.nuclei.profile_compiler.PROFILE_DIR", tmp_path)
    assert default_profile_id_for_mode(ExecutionMode.QUICK) == "fingerprint_safe"


def test_signature_gate_quick_matches_production_not_lab_skip() -> None:
    unsigned = _unsigned_tenant_manifest()
    lab_registry = NucleiTemplateRegistry()
    lab_hash = lab_registry.register(unsigned, mode=ExecutionMode.LAB_UNRESTRICTED)
    assert lab_hash
    assert lab_registry.get(unsigned.template_id) is not None

    for mode in (ExecutionMode.QUICK, ExecutionMode.PRODUCTION):
        registry = NucleiTemplateRegistry()
        with pytest.raises(TemplateRegistryError, match="template_missing_signature"):
            registry.register(unsigned, mode=mode)
        assert registry.get(unsigned.template_id) is None


def test_unverified_tenant_template_rejected_in_quick() -> None:
    manifest = NucleiTemplateManifest(
        template_id="tenant-unverified",
        version="1",
        source=TemplateSource.TENANT,
        sha256=_SHA256,
        signature="sig",
        verified=False,
        protocols=("http",),
        risk_level="passive",
    )
    NucleiTemplateRegistry().register(manifest, mode=ExecutionMode.LAB_UNRESTRICTED)
    with pytest.raises(TemplateRegistryError, match="template_not_verified"):
        NucleiTemplateRegistry().register(manifest, mode=ExecutionMode.QUICK)


def test_lab_artifact_ingest_rejected_in_quick() -> None:
    artifact = LabTemplateArtifact(
        artifact_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        template_id="generated-lab",
        content_sha256=_SHA256,
    )
    registry = NucleiTemplateRegistry()
    with pytest.raises(TemplateRegistryError, match="lab_artifact_requires_lab_mode"):
        registry.ingest_lab_artifact(artifact, mode=ExecutionMode.QUICK)
    registry.ingest_lab_artifact(artifact, mode=ExecutionMode.LAB_UNRESTRICTED)
    assert registry.get("generated-lab") is not None
