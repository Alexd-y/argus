"""Phase-level resume support for interrupted scans.

Enables resuming scans from the last completed phase, skipping already
completed work and restoring context from PhaseOutput records in PostgreSQL.
Inspired by Shannon's git-checkpointed workspace resume system but adapted
for ARGUS's PostgreSQL + MinIO artifact storage.

Usage:
    # In state_machine.py, before starting a phase:
    completed = await get_completed_phases(session, scan_id)
    if phase in completed:
        context = await restore_phase_context(session, scan_id, phase)
        # Skip phase, use restored context
"""

from __future__ import annotations

import json
import logging
from enum import StrEnum
from typing import Any

from sqlalchemy import String, cast, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import PhaseOutput, Scan, ScanStep
from src.orchestration.phases import PHASE_ORDER, ScanPhase

logger = logging.getLogger(__name__)


class ResumeDecision(StrEnum):
    """Decision for a phase when resuming a scan."""

    SKIP = "skip"          # Already completed, skip and use cached output
    RE_RUN = "re_run"      # Re-run even if previously completed
    RUN_FRESH = "run_fresh"  # No previous completion, run normally


async def get_completed_phases(
    session: AsyncSession,
    scan_id: str,
) -> set[ScanPhase]:
    """Query PhaseOutput and ScanStep to find all completed phases for a scan.

    A phase is considered completed if:
    1. A ScanStep with status='completed' exists for it
    2. A PhaseOutput with artifact_type='phase_output_final' exists
    """
    completed: set[ScanPhase] = set()

    # Check ScanStep status
    steps_result = await session.execute(
        select(ScanStep.step_name, ScanStep.status)
        .where(cast(ScanStep.scan_id, String) == scan_id)
    )
    for step_name, status in steps_result.all():
        if status == "completed":
            try:
                completed.add(ScanPhase(step_name))
            except ValueError:
                logger.warning("Unknown phase in ScanStep: %s", step_name)

    # Cross-verify with PhaseOutput existence
    outputs_result = await session.execute(
        select(PhaseOutput.phase)
        .where(cast(PhaseOutput.scan_id, String) == scan_id)
    )
    phase_outputs: set[ScanPhase] = set()
    for (phase_name,) in outputs_result.all():
        try:
            phase_outputs.add(ScanPhase(phase_name))
        except ValueError:
            logger.warning("Unknown phase in PhaseOutput: %s", phase_name)

    # Only count as completed if both exist
    return completed & phase_outputs


async def restore_phase_context(
    session: AsyncSession,
    scan_id: str,
    phase: ScanPhase,
) -> dict[str, Any] | None:
    """Restore the output context for a completed phase.

    Retrieves the PhaseOutput record and returns the output_data
    dict for use by downstream phases.
    """
    result = await session.execute(
        select(PhaseOutput.output_data)
        .where(cast(PhaseOutput.scan_id, String) == scan_id)
        .where(PhaseOutput.phase == phase.value)
        .order_by(PhaseOutput.created_at.desc())
        .limit(1)
    )
    row = result.scalar_one_or_none()
    if row is None:
        logger.warning("No PhaseOutput found for scan=%s phase=%s", scan_id, phase.value)
        return None

    if isinstance(row, dict):
        return row
    try:
        return json.loads(row) if isinstance(row, str) else row
    except (json.JSONDecodeError, TypeError):
        logger.warning("Failed to parse PhaseOutput for scan=%s phase=%s", scan_id, phase.value)
        return None


def compute_resume_plan(
    completed: set[ScanPhase],
    target_phases: list[ScanPhase] | None = None,
) -> dict[ScanPhase, ResumeDecision]:
    """Compute which phases to skip vs. re-run when resuming a scan.

    Parameters
    ----------
    completed:
        Set of phases already completed (from get_completed_phases).
    target_phases:
        Ordered list of phases to run. Defaults to PHASE_ORDER.

    Returns
    -------
    Dict mapping each phase to a ResumeDecision.
    """
    phases = target_phases or list(PHASE_ORDER)
    plan: dict[ScanPhase, ResumeDecision] = {}

    for phase in phases:
        if phase in completed:
            plan[phase] = ResumeDecision.SKIP
        else:
            plan[phase] = ResumeDecision.RUN_FRESH

    return plan


def format_resume_summary(plan: dict[ScanPhase, ResumeDecision]) -> str:
    """Format a human-readable summary of the resume plan."""
    lines: list[str] = []
    for phase in PHASE_ORDER:
        if phase not in plan:
            continue
        decision = plan[phase]
        icon = {"skip": "[SKIP]", "re_run": "[RE-RUN]", "run_fresh": "[RUN]"}[decision.value]
        lines.append(f"  {icon} {phase.value}")
    return "\n".join(lines)


async def freeze_scan_scope(
    session: AsyncSession,
    scan_id: str,
    vuln_classes: list[str] | None = None,
    exploit_enabled: bool = True,
    target_url: str = "",
) -> None:
    """Freeze the scan scope at session start to prevent scope drift on resume.

    Stores the initial configuration as a JSON blob in the scan's options
    so that resumed scans use the same scope as the original run.
    """
    scope_data = {
        "vuln_classes": vuln_classes or [],
        "exploit_enabled": exploit_enabled,
        "target_url": target_url,
        "frozen_at": str(__import__("datetime").datetime.now(tz=__import__("datetime").timezone.utc)),
    }

    result = await session.execute(
        select(Scan.options)
        .where(cast(Scan.id, String) == scan_id)
    )
    options = result.scalar_one_or_none() or {}
    if isinstance(options, str):
        try:
            options = json.loads(options)
        except (json.JSONDecodeError, TypeError):
            options = {}

    options["frozen_scope"] = scope_data

    from sqlalchemy import update
    await session.execute(
        update(Scan)
        .where(cast(Scan.id, String) == scan_id)
        .values(options=options)
    )
    await session.commit()


async def get_frozen_scope(
    session: AsyncSession,
    scan_id: str,
) -> dict[str, Any] | None:
    """Retrieve the frozen scope for a scan (set at initial run time)."""
    result = await session.execute(
        select(Scan.options)
        .where(cast(Scan.id, String) == scan_id)
    )
    options = result.scalar_one_or_none()
    if options is None:
        return None
    if isinstance(options, str):
        try:
            options = json.loads(options)
        except (json.JSONDecodeError, TypeError):
            return None
    return options.get("frozen_scope")


__all__ = [
    "ResumeDecision",
    "compute_resume_plan",
    "format_resume_summary",
    "freeze_scan_scope",
    "get_completed_phases",
    "get_frozen_scope",
    "restore_phase_context",
]