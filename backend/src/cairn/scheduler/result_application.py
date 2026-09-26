"""Apply a validated agent result to the graph (upstream §10.5 table).

Bridges the Phase-4 contract validators to the Phase-2 graph service. Each function
returns an outcome code (``success`` / ``failed`` / ``rejected`` / ``noop``) that the
task lifecycle uses to drive backoff, exactly as upstream.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from src.cairn import graph_service as gs
from src.cairn.errors import CairnConflictError, CairnError, CairnForbiddenError

logger = logging.getLogger(__name__)


async def apply_reason_result(
    session: AsyncSession,
    tenant_id: str,
    project_id: str,
    worker: str,
    kind: str,
    data: Any,
) -> str:
    """Apply a reason outcome: complete | intents | noop | rejected."""
    if kind == "rejected":
        return "rejected"
    if kind == "noop":
        return "success"
    if kind == "complete":
        try:
            await gs.complete_project(
                session,
                tenant_id,
                project_id,
                from_refs=list(data.get("from", [])),
                description=str(data.get("description", "")),
                worker=worker,
            )
        except CairnForbiddenError:
            return "success"  # project already changed state — not our error
        return "success"
    if kind == "intents":
        created = 0
        intents = data if isinstance(data, list) else []
        for intent in intents:
            try:
                await gs.create_intent(
                    session,
                    tenant_id,
                    project_id,
                    from_refs=list(intent.get("from", [])),
                    description=str(intent.get("description", "")),
                    creator=worker,
                )
                created += 1
            except CairnForbiddenError:
                return "success"
            except CairnConflictError:
                continue  # lost a race for this intent — skip
            except CairnError as exc:  # bad from-refs etc.
                logger.warning("cairn_reason_intent_rejected", extra={"error": str(exc)})
        if intents and created == 0:
            return "failed"
        return "success"
    return "failed"


async def apply_bootstrap_result(
    session: AsyncSession,
    tenant_id: str,
    project_id: str,
    worker: str,
    bootstrap_intent_id: str,
    kind: str,
    data: Any,
    *,
    is_conclude: bool = False,
) -> str:
    """Apply a bootstrap outcome by concluding the bootstrap intent (and completing)."""
    if kind == "rejected":
        return "rejected"

    if is_conclude:
        # conclude phase: only conclude the bootstrap intent with the fact
        description = str(data) if isinstance(data, str) else str(data.get("fact_description", ""))
        try:
            await gs.conclude_intent(
                session,
                tenant_id,
                project_id,
                bootstrap_intent_id,
                worker,
                description,
                source_task_type="bootstrap",
            )
        except CairnError:
            return "success"
        return "success"

    # execute phase: conclude bootstrap intent, then complete the project
    fact_description = str(data.get("fact_description", ""))
    complete_description = str(data.get("complete_description", ""))
    try:
        conclude = await gs.conclude_intent(
            session,
            tenant_id,
            project_id,
            bootstrap_intent_id,
            worker,
            fact_description,
            source_task_type="bootstrap",
        )
    except CairnError:
        return "success"
    fact_ref = conclude.fact.ref
    try:
        await gs.complete_project(
            session,
            tenant_id,
            project_id,
            from_refs=[fact_ref],
            description=complete_description,
            worker=worker,
        )
    except CairnForbiddenError:
        return "success"
    except CairnConflictError:
        return "success"
    return "success"


async def apply_explore_result(
    session: AsyncSession,
    tenant_id: str,
    project_id: str,
    intent_id: str,
    worker: str,
    kind: str,
    description: str | None,
    *,
    source_task_type: str = "explore",
) -> str:
    """Apply an explore outcome: conclude the intent with the produced fact."""
    if kind == "rejected":
        return "rejected"
    try:
        await gs.conclude_intent(
            session,
            tenant_id,
            project_id,
            intent_id,
            worker,
            str(description or ""),
            source_task_type=source_task_type,
        )
    except CairnError:
        return "success"  # already concluded / project changed — not our failure
    return "success"


__all__ = [
    "apply_bootstrap_result",
    "apply_explore_result",
    "apply_reason_result",
]
