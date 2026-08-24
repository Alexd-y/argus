"""Durable checkpoint persistence + profile-driven phase selection (R11).

Persists a :class:`ScanCheckpointV1` into ``scan.options`` (no new table, same
pattern as ``freeze_scan_scope``) and exposes the frozen resolved profile so the
state machine drives phase selection from it — and so *resume* uses the saved
immutable context instead of re-interpreting user input.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import String, cast, update

from src.db.models import Scan
from src.orchestration.profile_phase_policy import plan_phases
from src.orchestration.scan_checkpoint import (
    ScanCheckpointV1,
    build_checkpoint,
)
from src.profiles.resolver import ResolvedScanProfile, ScanProfile, resolve_scan_profile

logger = logging.getLogger(__name__)

_CHECKPOINT_KEY = "scan_checkpoint_v1"
_VALID_PROFILES = frozenset(p.value for p in ScanProfile)


def read_checkpoint(options: dict[str, Any] | None) -> ScanCheckpointV1 | None:
    """Return the persisted checkpoint from scan.options, if any."""
    if not isinstance(options, dict):
        return None
    raw = options.get(_CHECKPOINT_KEY)
    if not isinstance(raw, dict):
        return None
    try:
        return ScanCheckpointV1.model_validate(raw)
    except Exception:  # noqa: BLE001 — a corrupt checkpoint must not crash the run
        logger.warning("scan_checkpoint_invalid", extra={"event": "scan_checkpoint_invalid"})
        return None


def resolved_profile_from_options(
    options: dict[str, Any] | None,
) -> ResolvedScanProfile | None:
    """Resolve the frozen profile: checkpoint first (immutable), then scan_profile.

    R11: on resume we prefer the persisted checkpoint's frozen profile and never
    re-interpret raw user input.
    """
    checkpoint = read_checkpoint(options)
    if checkpoint is not None:
        try:
            return checkpoint.resolved()
        except Exception:  # noqa: BLE001 — fall through to re-resolve from options
            logger.debug("checkpoint_resolve_failed", extra={"event": "checkpoint_resolve_failed"})
    if not isinstance(options, dict):
        return None
    raw_profile = str(options.get("scan_profile") or "").strip().lower()
    if raw_profile in _VALID_PROFILES:
        return resolve_scan_profile(raw_profile, quick_profile=options.get("quick_profile"))
    return None


def profile_skipped_phases(options: dict[str, Any] | None) -> frozenset:
    """Phases skipped by the resolved profile (empty when no canonical profile)."""
    resolved = resolved_profile_from_options(options)
    if resolved is None:
        return frozenset()
    return frozenset(plan_phases(resolved).skipped.keys())


async def persist_checkpoint(
    session,
    scan_id: str,
    options: dict[str, Any],
    checkpoint: ScanCheckpointV1,
) -> None:
    """Write the checkpoint into scan.options + DB (same pattern as freeze_scan_scope)."""
    options[_CHECKPOINT_KEY] = checkpoint.model_dump(mode="json")
    await session.execute(
        update(Scan).where(cast(Scan.id, String) == scan_id).values(options=options)
    )
    await session.commit()


async def init_scan_checkpoint(
    session,
    *,
    scan_id: str,
    tenant_id: str,
    options: dict[str, Any],
    current_phase: str,
    registry_versions: dict[str, Any] | None = None,
) -> ScanCheckpointV1 | None:
    """Create + persist the initial checkpoint when a canonical profile is present."""
    resolved = resolved_profile_from_options(options)
    if resolved is None:
        return None
    existing = read_checkpoint(options)
    lease_state = "active" if (options.get("lab_lease_id") and resolved.requires_lab_lease) else "none"
    rv = registry_versions or {}
    checkpoint = build_checkpoint(
        scan_id=scan_id,
        tenant_id=tenant_id,
        resolved_profile=resolved,
        current_phase=current_phase,
        completed_phases=existing.completed_phases if existing else [],
        remaining_budget=(existing.remaining_budget if existing else {}),
        scope_hash=str(options.get("scope_hash") or (existing.scope_hash if existing else "")),
        lease_state=lease_state,  # type: ignore[arg-type]
        report_snapshot_status="none",
        tool_registry_version=rv.get("tools"),
        payload_registry_version=rv.get("payloads"),
        prompt_registry_version=rv.get("prompts"),
    )
    await persist_checkpoint(session, scan_id, options, checkpoint)
    logger.info(
        "scan_checkpoint_initialized",
        extra={
            "event": "scan_checkpoint_initialized",
            "scan_id": scan_id,
            "scan_profile": resolved.external_profile.value,
            "current_phase": current_phase,
        },
    )
    return checkpoint


async def update_checkpoint_phase(
    session,
    *,
    scan_id: str,
    options: dict[str, Any],
    current_phase: str,
    completed_phase: str | None = None,
) -> None:
    """Advance the persisted checkpoint's phase (called per-phase). Best-effort."""
    checkpoint = read_checkpoint(options)
    if checkpoint is None:
        return
    completed = list(checkpoint.completed_phases)
    if completed_phase and completed_phase not in completed:
        completed.append(completed_phase)
    updated = checkpoint.model_copy(
        update={"current_phase": current_phase, "completed_phases": completed}
    ).touch()
    await persist_checkpoint(session, scan_id, options, updated)


__all__ = [
    "init_scan_checkpoint",
    "persist_checkpoint",
    "profile_skipped_phases",
    "read_checkpoint",
    "resolved_profile_from_options",
    "update_checkpoint_phase",
]
