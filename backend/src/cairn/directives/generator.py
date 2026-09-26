"""Directive generation pipeline (§18.5–18.7).

LLM proposes directives; the application enforces safety deterministically:
intrusiveness is clamped to what the execution mode + lease allow, out-of-scope
focuses are rejected, priority is (re)computed by code, and duplicates by normalized
focus are dropped. The LLM caller is injected so the pipeline is unit-testable.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.cairn.directives.dedup import normalize_focus
from src.cairn.directives.models import CairnDirective
from src.cairn.directives.priority import compute_priority_score
from src.cairn.directives.schemas import (
    DirectiveFocus,
    FocusType,
    Intrusiveness,
    PentestDirective,
    PentestDirectiveBatch,
    allowed_intrusiveness_for,
    clamp_intrusiveness,
)
from src.cairn.output_parser import extract_json_object

logger = logging.getLogger(__name__)

#: Injected async caller: (system_prompt, user_prompt) -> raw text.
LlmCaller = Callable[[str, str], Awaitable[str]]
#: Injected scope check: focus value -> is it inside the authorised perimeter.
ScopeCheck = Callable[[DirectiveFocus], bool]


async def _next_directive_ref(session: AsyncSession, project_id: str) -> str:
    count = (
        await session.execute(
            select(func.count())
            .select_from(CairnDirective)
            .where(CairnDirective.project_id == project_id)
        )
    ).scalar_one()
    return f"d{int(count) + 1:03d}"


def _focus_in_scope(focus: DirectiveFocus, scope_check: ScopeCheck | None) -> bool:
    if scope_check is None:
        return True
    # Only host/target/endpoint focuses are scope-bounded; service/cve/port are abstract.
    if focus.type in (FocusType.HOST, FocusType.TARGET, FocusType.ENDPOINT):
        return scope_check(focus)
    return True


async def generate_directives(
    session: AsyncSession,
    tenant_id: str,
    project_id: str,
    *,
    context: dict[str, Any],
    execution_mode: str,
    has_target_lease: bool,
    llm_caller: LlmCaller,
    system_prompt: str = "",
    scope_check: ScopeCheck | None = None,
    max_directives: int = 5,
    scan_id: str | None = None,
    provenance: dict[str, Any] | None = None,
) -> list[CairnDirective]:
    """Generate, validate, gate, persist and return directives for a project."""
    allowed = allowed_intrusiveness_for(execution_mode, has_target_lease=has_target_lease)

    import json

    user_prompt = json.dumps(context, ensure_ascii=False)
    raw = await llm_caller(system_prompt, user_prompt)
    payload = extract_json_object(raw)
    batch = PentestDirectiveBatch.model_validate(payload)

    persisted: list[CairnDirective] = []
    seen_focus: set[str] = set()
    for directive in batch.directives[:max_directives]:
        gated = _gate_directive(directive, allowed, scope_check)
        if gated is None:
            continue
        key = normalize_focus(gated.focus)
        if key in seen_focus:
            continue
        seen_focus.add(key)

        ref = await _next_directive_ref(session, project_id)
        row = CairnDirective(
            ref=ref,
            tenant_id=tenant_id,
            project_id=project_id,
            scan_id=scan_id,
            kind=gated.kind.value,
            title=gated.title,
            directive_text=gated.directive_text,
            focus=gated.focus.model_dump(),
            success_criterion=gated.success_criterion,
            proof_requirement=gated.proof_requirement.value,
            intrusiveness=gated.intrusiveness.value,
            priority_score=gated.priority_score,
            priority_rationale=gated.priority_rationale,
            scope_guard=gated.scope_guard.model_dump(),
            basis={"fact_refs": gated.basis_fact_refs, "finding_ids": gated.basis_finding_ids},
            status="proposed",
            llm_provenance=provenance,
        )
        session.add(row)
        persisted.append(row)
    await session.flush()
    logger.info(
        "cairn_directives_generated",
        extra={"project_id": project_id, "count": len(persisted)},
    )
    return persisted


def _gate_directive(
    directive: PentestDirective,
    allowed: Intrusiveness,
    scope_check: ScopeCheck | None,
) -> PentestDirective | None:
    """Apply safety gates; return a clamped copy or None if it must be dropped."""
    if not _focus_in_scope(directive.focus, scope_check):
        logger.warning(
            "cairn_directive_out_of_scope",
            extra={"focus": directive.focus.value, "type": directive.focus.type.value},
        )
        return None
    clamped = clamp_intrusiveness(directive.intrusiveness, allowed)
    # Deterministic priority from the basis the model cited (text rationale kept).
    score = compute_priority_score(
        severity=None,
        public_poc=directive.proof_requirement.value in ("command_execution", "shell"),
        novelty=directive.priority_score if directive.priority_score else 0.5,
    )
    return directive.model_copy(update={"intrusiveness": clamped, "priority_score": score})


__all__ = ["generate_directives"]
