"""Sub-phase progress emitter for long-running scan phases (observability).

Long phases — notably ``vuln_analysis`` on Full Surface — emit progress only at
their entry, so a 30-minute active-scan + LLM run appears "stuck" at a single
percentage in the UI/timeline. This helper lets a handler emit intermediate
progress ticks between its internal sub-steps.

It uses its OWN short-lived DB session so it never races the caller's phase
transaction, and it never raises — observability must not break a phase.
"""

from __future__ import annotations

import logging
import uuid

from sqlalchemy import String, cast, update

from src.db.models import Scan, ScanEvent
from src.db.session import async_session_factory, set_session_tenant

logger = logging.getLogger(__name__)


async def emit_scan_subprogress(
    *,
    scan_id: str | None,
    tenant_id: str | None,
    phase: str,
    progress: int,
    message: str,
) -> None:
    """Append a ``progress`` scan event and bump ``Scan.progress`` (best-effort).

    No-op when ids are missing; swallows all errors (a failed observability write
    must never abort the phase).
    """
    if not (scan_id and tenant_id):
        return
    try:
        async with async_session_factory() as session:
            await set_session_tenant(session, tenant_id)
            session.add(
                ScanEvent(
                    id=str(uuid.uuid4()),
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    event="progress",
                    phase=phase,
                    progress=progress,
                    message=message,
                )
            )
            await session.execute(
                update(Scan).where(cast(Scan.id, String) == scan_id).values(progress=progress)
            )
            await session.commit()
    except Exception:  # observability write must never break the phase
        logger.debug(
            "subprogress_emit_failed",
            extra={"scan_id": scan_id, "phase": phase, "progress": progress},
            exc_info=True,
        )


__all__ = ["emit_scan_subprogress"]
