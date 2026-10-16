"""Model-variant reproducibility, admission gate, and rollback (Wave 5, R-9.15-R-9.18).

This is the infrastructure that must exist BEFORE any fine-tuned variant is used,
independent of which fine-tuning variant produced it (the wave itself closes on
variant 1 — prompt/example work — but the plumbing here governs every variant):

* R-9.15 reproducibility — a :class:`ReproducibilityManifest` pins the base model
  version, the dataset composition (a deterministic checksum + size), the
  hyperparameters, and a reference to the preparation code.
* R-9.16 registry — :class:`VariantRegistry` holds variants alongside the base and
  resolves the ACTIVE one from config (``settings.llm_active_model_variant``), so
  selection is configuration, not code.
* R-9.17 admission — :class:`ReferenceGate` only admits a variant that passed the
  reference target set (recall floor + zero forbidden hits).
* R-9.18 rollback — switching the active variant (config) reverts without downtime;
  :meth:`VariantRegistry.rollback` restores the previous active selection.

Pure and dependency-light so the whole contract is testable offline.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any


def compute_dataset_checksum(samples: Iterable[str]) -> str:
    """Deterministic checksum of a training set, order-independent (R-9.15).

    Each sample is hashed, the hashes are sorted, and the sorted list is hashed
    again — so the same set of samples in any order yields the same checksum, and
    a single changed/added/removed sample changes it.
    """
    per = sorted(hashlib.sha256(s.encode("utf-8")).hexdigest() for s in samples)
    return hashlib.sha256(json.dumps(per).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ReproducibilityManifest:
    """Everything needed to reproduce a variant (R-9.15)."""

    base_model: str
    dataset_checksum: str
    dataset_size: int
    hyperparameters: Mapping[str, Any] = field(default_factory=dict)
    prep_code_ref: str = ""  # commit/tag of the data-prep code

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_model": self.base_model,
            "dataset_checksum": self.dataset_checksum,
            "dataset_size": self.dataset_size,
            "hyperparameters": dict(self.hyperparameters),
            "prep_code_ref": self.prep_code_ref,
        }


@dataclass(frozen=True)
class ReferenceGate:
    """Admission gate against the reference target set (R-9.17)."""

    min_recall: float = 0.8
    max_forbidden_hits: int = 0

    def admit(self, *, recall: float, forbidden_hits: int) -> tuple[bool, list[str]]:
        """Return (admitted, reasons). A variant is admitted only if it clears both."""
        reasons: list[str] = []
        if recall < self.min_recall:
            reasons.append(f"recall {recall:.3f} < floor {self.min_recall:.3f}")
        if forbidden_hits > self.max_forbidden_hits:
            reasons.append(f"forbidden_hits {forbidden_hits} > {self.max_forbidden_hits}")
        return (not reasons), reasons


@dataclass(frozen=True)
class ModelVariant:
    """A registered model variant (base or fine-tuned)."""

    variant_id: str
    base_model: str
    manifest: ReproducibilityManifest | None = None
    status: str = "candidate"  # candidate | admitted | retired
    recall: float = 0.0
    forbidden_hits: int = 0

    @property
    def admitted(self) -> bool:
        return self.status == "admitted"


class VariantRegistry:
    """In-process registry of model variants with config-driven active selection.

    The active variant is resolved from ``settings.llm_active_model_variant`` and
    MUST be an admitted variant; an unknown or un-admitted id falls back to the
    base (fail-safe). Rollback restores the previous active id.
    """

    def __init__(self, base_model: str) -> None:
        self._base = ModelVariant(variant_id="base", base_model=base_model, status="admitted")
        self._variants: dict[str, ModelVariant] = {"base": self._base}
        self._active_id: str = "base"
        self._prev_active_id: str = "base"

    def register(self, variant: ModelVariant) -> None:
        self._variants[variant.variant_id] = variant

    def get(self, variant_id: str) -> ModelVariant | None:
        return self._variants.get(variant_id)

    def list(self) -> list[ModelVariant]:
        return list(self._variants.values())

    def admit(self, variant_id: str, gate: ReferenceGate) -> tuple[bool, list[str]]:
        """Admit a registered variant iff it clears ``gate`` (R-9.17)."""
        v = self._variants.get(variant_id)
        if v is None:
            return False, [f"unknown variant {variant_id!r}"]
        ok, reasons = gate.admit(recall=v.recall, forbidden_hits=v.forbidden_hits)
        if ok:
            self._variants[variant_id] = replace(v, status="admitted")
        return ok, reasons

    def resolve_active(self, configured_id: str | None) -> ModelVariant:
        """Return the admitted variant named by config, else the base (fail-safe)."""
        if configured_id:
            v = self._variants.get(configured_id)
            if v is not None and v.admitted:
                return v
        return self._base

    def set_active(self, variant_id: str) -> ModelVariant:
        """Promote ``variant_id`` to active (must be admitted). Records the previous."""
        v = self._variants.get(variant_id)
        if v is None or not v.admitted:
            raise ValueError(f"cannot activate non-admitted variant {variant_id!r}")
        self._prev_active_id = self._active_id
        self._active_id = variant_id
        return v

    def rollback(self) -> ModelVariant:
        """Revert to the previous active variant without downtime (R-9.18)."""
        self._active_id, self._prev_active_id = self._prev_active_id, self._active_id
        return self._variants[self._active_id]

    @property
    def active_id(self) -> str:
        return self._active_id


__all__ = [
    "ModelVariant",
    "ReferenceGate",
    "ReproducibilityManifest",
    "VariantRegistry",
    "compute_dataset_checksum",
]
