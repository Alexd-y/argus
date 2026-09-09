"""Evidence resolution + validation for WSTG coverage (ARGUS-WSTG-COV-1 §Evidence).

Three cleanly separated layers, so the coverage math stays pure:

1. **IO layer** — an :class:`EvidenceResolver` fetches artifact *metadata* from
   the existing store (``ToolRun`` / ``Evidence`` / ``Finding`` rows + MinIO
   object keys). Resolution is batched (no N+1) and lives outside
   ``compute_wstg_coverage``.
2. **Deterministic validation** — :func:`validate_evidence` is a pure function
   over already-resolved metadata. It answers *"is this a valid evidence ref for
   this scan/target of the required type?"*.
3. **Aggregation / gate** — consumes only the boolean validation verdicts.

Hard rules (spec §Evidence):

* A bare string like ``"EV-TLS-001"`` or ``"FINDING:123"`` is **never** valid on
  its own — it must resolve to a concrete, existing artifact.
* An artifact must belong to the current scan (or an explicitly allowed origin)
  and match the target/context and expected artifact type.
* A content hash proves integrity, not sufficiency.
* A finding reference is valid only after the finding itself is resolved and its
  own evidence checked.
* When the store is unavailable the ref is *unresolved* → not validated; the
  technical reason is recorded, never silently treated as proven.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class ArtifactKind(StrEnum):
    """The kind of a resolved evidence artifact."""

    TOOL_OUTPUT = "tool_output"
    POC_FILE = "poc_file"
    HTTP_EXCHANGE = "http_exchange"
    FINDING = "finding"
    SCREENSHOT = "screenshot"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ResolvedArtifact:
    """Metadata for a single evidence ref resolved from the store.

    ``exists=False`` means the ref could not be resolved (dangling id, store
    unavailable, or a bare synthetic string). All other fields are only
    meaningful when ``exists`` is True.
    """

    ref: str
    exists: bool
    kind: ArtifactKind = ArtifactKind.UNKNOWN
    scan_id: str | None = None
    target_ref: str | None = None
    content_present: bool = False
    finding_resolved: bool = False
    unresolved_reason: str | None = None


@dataclass(frozen=True)
class EvidenceValidation:
    """Deterministic validation verdict for one evidence ref."""

    ref: str
    validated: bool
    reason: str


class EvidenceResolver(Protocol):
    """Batch resolver for evidence refs (implemented by the IO layer)."""

    def resolve(self, refs: list[str]) -> dict[str, ResolvedArtifact]:
        """Return metadata for each ref (missing → ``exists=False``)."""
        ...


def validate_evidence(
    resolved: dict[str, ResolvedArtifact],
    *,
    expected_scan_id: str,
    expected_target: str | None = None,
    allowed_kinds: frozenset[ArtifactKind] | None = None,
    allowed_foreign_scans: frozenset[str] = frozenset(),
) -> dict[str, EvidenceValidation]:
    """Pure validation of resolved artifacts against scan/target/type rules."""
    out: dict[str, EvidenceValidation] = {}
    for ref, art in resolved.items():
        out[ref] = _validate_one(
            art,
            expected_scan_id=expected_scan_id,
            expected_target=expected_target,
            allowed_kinds=allowed_kinds,
            allowed_foreign_scans=allowed_foreign_scans,
        )
    return out


def _validate_one(
    art: ResolvedArtifact,
    *,
    expected_scan_id: str,
    expected_target: str | None,
    allowed_kinds: frozenset[ArtifactKind] | None,
    allowed_foreign_scans: frozenset[str],
) -> EvidenceValidation:
    ref = art.ref
    if not art.exists:
        return EvidenceValidation(ref, False, art.unresolved_reason or "artifact does not exist")
    if (
        art.scan_id is not None
        and art.scan_id != expected_scan_id
        and art.scan_id not in allowed_foreign_scans
    ):
        return EvidenceValidation(ref, False, f"belongs to another scan ({art.scan_id})")
    if expected_target and art.target_ref and art.target_ref != expected_target:
        return EvidenceValidation(ref, False, "target/context mismatch")
    if allowed_kinds is not None and art.kind not in allowed_kinds:
        return EvidenceValidation(ref, False, f"unsuitable artifact type ({art.kind.value})")
    if not art.content_present:
        return EvidenceValidation(ref, False, "artifact has no usable content")
    if art.kind == ArtifactKind.FINDING and not art.finding_resolved:
        return EvidenceValidation(ref, False, "referenced finding is not resolved/validated")
    return EvidenceValidation(ref, True, "ok")


def any_validated(validations: dict[str, EvidenceValidation]) -> bool:
    """True when at least one ref is validated (used to gate a completed test)."""
    return any(v.validated for v in validations.values())


class StaticEvidenceResolver:
    """In-memory resolver for tests/fixtures. Never touches the network."""

    def __init__(self, artifacts: dict[str, ResolvedArtifact]) -> None:
        self._artifacts = dict(artifacts)

    def resolve(self, refs: list[str]) -> dict[str, ResolvedArtifact]:
        return {
            ref: self._artifacts.get(ref, ResolvedArtifact(ref=ref, exists=False)) for ref in refs
        }


__all__ = [
    "ArtifactKind",
    "EvidenceResolver",
    "EvidenceValidation",
    "ResolvedArtifact",
    "StaticEvidenceResolver",
    "any_validated",
    "validate_evidence",
]
