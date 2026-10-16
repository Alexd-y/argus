"""Wave 5 / R-9.15-R-9.18 — model-variant reproducibility, admission, rollback."""

from __future__ import annotations

import pytest
from src.llm.model_variants import (
    ModelVariant,
    ReferenceGate,
    ReproducibilityManifest,
    VariantRegistry,
    compute_dataset_checksum,
)


def test_dataset_checksum_is_order_independent_and_sensitive():
    a = compute_dataset_checksum(["x", "y", "z"])
    b = compute_dataset_checksum(["z", "x", "y"])  # same set, different order
    c = compute_dataset_checksum(["x", "y", "z", "w"])  # one more sample
    assert a == b
    assert a != c


def test_manifest_roundtrips_to_dict():
    m = ReproducibilityManifest(
        base_model="wrb-v3-7b",
        dataset_checksum="abc",
        dataset_size=1000,
        hyperparameters={"lr": 0.0002, "epochs": 3},
        prep_code_ref="deadbeef",
    )
    d = m.to_dict()
    assert d["base_model"] == "wrb-v3-7b"
    assert d["dataset_size"] == 1000
    assert d["hyperparameters"]["epochs"] == 3


def test_reference_gate_admits_only_on_pass():
    gate = ReferenceGate(min_recall=0.8, max_forbidden_hits=0)
    ok, reasons = gate.admit(recall=0.9, forbidden_hits=0)
    assert ok and reasons == []
    ok2, reasons2 = gate.admit(recall=0.5, forbidden_hits=1)
    assert not ok2
    assert len(reasons2) == 2


def _reg() -> VariantRegistry:
    reg = VariantRegistry(base_model="wrb-base")
    reg.register(ModelVariant(variant_id="v1", base_model="wrb-base", recall=0.9, forbidden_hits=0))
    reg.register(ModelVariant(variant_id="v2", base_model="wrb-base", recall=0.4, forbidden_hits=2))
    return reg


def test_admission_updates_status_and_rejects_failing():
    reg = _reg()
    gate = ReferenceGate(min_recall=0.8)
    ok, _ = reg.admit("v1", gate)
    assert ok and reg.get("v1").admitted is True
    ok2, reasons = reg.admit("v2", gate)
    assert not ok2 and reg.get("v2").admitted is False and reasons


def test_resolve_active_falls_back_to_base_for_unadmitted():
    reg = _reg()
    gate = ReferenceGate(min_recall=0.8)
    reg.admit("v1", gate)
    # configured but admitted → selected
    assert reg.resolve_active("v1").variant_id == "v1"
    # configured but NOT admitted → fail-safe to base
    assert reg.resolve_active("v2").variant_id == "base"
    # unknown id → base
    assert reg.resolve_active("nope").variant_id == "base"
    # empty → base
    assert reg.resolve_active("").variant_id == "base"


def test_set_active_requires_admitted():
    reg = _reg()
    with pytest.raises(ValueError):
        reg.set_active("v2")  # not admitted
    reg.admit("v1", ReferenceGate(min_recall=0.8))
    assert reg.set_active("v1").variant_id == "v1"
    assert reg.active_id == "v1"


def test_rollback_restores_previous_active():
    reg = _reg()
    reg.admit("v1", ReferenceGate(min_recall=0.8))
    assert reg.active_id == "base"
    reg.set_active("v1")
    assert reg.active_id == "v1"
    reg.rollback()
    assert reg.active_id == "base"  # reverted without downtime
    reg.rollback()
    assert reg.active_id == "v1"  # rollback is a toggle of the two most recent
