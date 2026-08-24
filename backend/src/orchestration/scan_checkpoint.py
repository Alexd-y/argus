"""Durable scan checkpoint (R11).

A ``ScanCheckpointV1`` snapshots everything needed to resume a scan from its
*frozen* profile context — never by re-interpreting user input:

* the resolved (immutable) scan profile,
* current phase + completed phases,
* remaining budget,
* scope hash + lease state,
* tool / payload / prompt registry versions,
* report snapshot status.

It is content-addressed (``checkpoint_hash``) and round-trips through JSON so it
can live in ``scan.options`` / a checkpoint row without new tables.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

from src.profiles.resolver import ResolvedScanProfile

CHECKPOINT_SCHEMA_VERSION: Final[str] = "v1"

LeaseState = Literal["none", "active", "expired", "revoked"]
SnapshotStatus = Literal["none", "pending", "created", "failed"]


class ScanCheckpointV1(BaseModel):
    """Immutable resume context for a scan."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = CHECKPOINT_SCHEMA_VERSION
    scan_id: str
    tenant_id: str
    resolved_profile: dict[str, Any]
    current_phase: str
    completed_phases: list[str] = Field(default_factory=list)
    remaining_budget: dict[str, Any] = Field(default_factory=dict)
    scope_hash: str = ""
    lease_state: LeaseState = "none"
    tool_registry_version: str | None = None
    payload_registry_version: str | None = None
    prompt_registry_version: str | None = None
    report_snapshot_status: SnapshotStatus = "none"
    updated_at: str = ""

    def canonical_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"checkpoint_hash", "updated_at"})

    def checkpoint_hash(self) -> str:
        blob = json.dumps(self.canonical_payload(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def resolved(self) -> ResolvedScanProfile:
        """Rebuild the frozen profile — R11: resume uses saved context, not input."""
        return ResolvedScanProfile.from_public_dict(self.resolved_profile)

    def touch(self) -> ScanCheckpointV1:
        return self.model_copy(update={"updated_at": datetime.now(UTC).isoformat()})


def build_checkpoint(
    *,
    scan_id: str,
    tenant_id: str,
    resolved_profile: ResolvedScanProfile,
    current_phase: str,
    completed_phases: list[str] | None = None,
    remaining_budget: dict[str, Any] | None = None,
    scope_hash: str = "",
    lease_state: LeaseState = "none",
    tool_registry_version: str | None = None,
    payload_registry_version: str | None = None,
    prompt_registry_version: str | None = None,
    report_snapshot_status: SnapshotStatus = "none",
) -> ScanCheckpointV1:
    """Assemble a checkpoint from a resolved profile + runtime state."""
    return ScanCheckpointV1(
        scan_id=scan_id,
        tenant_id=tenant_id,
        resolved_profile=resolved_profile.to_public_dict(),
        current_phase=current_phase,
        completed_phases=list(completed_phases or []),
        remaining_budget=remaining_budget or {},
        scope_hash=scope_hash,
        lease_state=lease_state,
        tool_registry_version=tool_registry_version,
        payload_registry_version=payload_registry_version,
        prompt_registry_version=prompt_registry_version,
        report_snapshot_status=report_snapshot_status,
        updated_at=datetime.now(UTC).isoformat(),
    )


def resume_context(checkpoint: ScanCheckpointV1) -> ResolvedScanProfile:
    """Return the frozen profile to resume with (never re-interprets input)."""
    return checkpoint.resolved()


__all__ = [
    "CHECKPOINT_SCHEMA_VERSION",
    "LeaseState",
    "ScanCheckpointV1",
    "SnapshotStatus",
    "build_checkpoint",
    "resume_context",
]
