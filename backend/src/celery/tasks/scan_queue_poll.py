"""Scan queue poller — Celery beat task that picks queued scans.

When a scan finishes or an immediate-pick notification is lost (e.g.
worker crash before ``try_pick_queued_scan`` runs), queued scans can
accumulate. This periodic task scans every tenant with queued scans and
dispatches up to ``SCAN_MAX_CONCURRENT`` per tenant.

Routed to ``argus.scans`` queue so it shares worker capacity with the
scan phase executor.
"""

from __future__ import annotations

import asyncio
import logging

from src.celery_app import app

logger = logging.getLogger(__name__)


@app.task(bind=True, name="argus.scan_queue.poll")
def scan_queue_poll_task(_self) -> dict:
    """Beat-driven safety-net: pick queued scans for tenants with free slots."""

    async def _run() -> list[str]:
        from src.policy.scan_queue import poll_queued_scans

        return await poll_queued_scans()

    try:
        dispatched = asyncio.run(_run())
        if dispatched:
            logger.info(
                "scan_queue.poll.dispatched",
                extra={
                    "event": "argus.scan_queue.poll.dispatched",
                    "count": len(dispatched),
                    "scan_ids": dispatched,
                },
            )
        return {"dispatched": dispatched, "count": len(dispatched)}
    except Exception:
        logger.exception("scan_queue.poll.failed")
        return {"dispatched": [], "count": 0, "error": True}


@app.task(bind=True, name="argus.scan_queue.recover_stuck")
def scan_queue_recover_stuck_task(_self) -> dict:
    """Beat-driven recovery: re-drive scans stuck ``running`` with a stale heartbeat.

    Fast path for a hard worker crash (SIGKILL) that leaves a scan ``running``
    but frozen. Re-entry resumes from the interrupted phase (phase_resume skips
    completed phases idempotently).
    """

    async def _run() -> list[str]:
        from src.policy.scan_queue import recover_stuck_scans

        return await recover_stuck_scans()

    try:
        recovered = asyncio.run(_run())
        if recovered:
            logger.warning(
                "scan_queue.recover_stuck.recovered",
                extra={
                    "event": "argus.scan_queue.recover_stuck.recovered",
                    "count": len(recovered),
                    "scan_ids": recovered,
                },
            )
        return {"recovered": recovered, "count": len(recovered)}
    except Exception:
        logger.exception("scan_queue.recover_stuck.failed")
        return {"recovered": [], "count": 0, "error": True}
