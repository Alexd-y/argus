"""Graph exports — YAML snapshot and chronological timeline.

Ported from ``_external/Cairn/cairn/src/cairn/server/routers/export.py`` (AGPL-3.0),
adapted to work from a :class:`~src.cairn.graph_service.ProjectDetailResult` and to
render graph-node ``id`` values as human refs. Completion is detected via
``CairnIntent.is_completion`` (ARGUS) rather than the upstream ``to == 'goal'``.
"""

from __future__ import annotations

from datetime import datetime

import yaml

from src.cairn.graph_service import ProjectDetailResult
from src.cairn.schemas import GOAL_REF, ORIGIN_REF


def format_export_timestamp(value: datetime | None) -> str | None:
    """Render a timestamp as local ``%Y-%m-%d %H:%M:%S`` (upstream form)."""
    if value is None:
        return None
    return value.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def _fact_ref_by_uuid(detail: ProjectDetailResult) -> dict[str, str]:
    return {fact.id: fact.ref for fact in detail.facts}


def export_yaml(detail: ProjectDetailResult) -> str:
    """Serialize the graph as a YAML snapshot (project / hints / facts / intents)."""
    facts_by_ref = {fact.ref: fact.description for fact in detail.facts}
    ref_by_uuid = _fact_ref_by_uuid(detail)

    data: dict = {
        "project": {
            "title": detail.project.title,
            "origin": facts_by_ref.get(ORIGIN_REF, ""),
            "goal": facts_by_ref.get(GOAL_REF, ""),
            "bootstrap_enabled": bool(detail.project.bootstrap_enabled),
        }
    }

    if detail.hints:
        data["hints"] = [
            {
                "content": hint.content,
                "creator": hint.creator,
                "created_at": format_export_timestamp(hint.created_at),
            }
            for hint in detail.hints
        ]

    data["facts"] = [{"id": fact.ref, "description": fact.description} for fact in detail.facts]

    intent_list = []
    for intent in detail.intents:
        to_ref = ref_by_uuid.get(intent.to_fact_id) if intent.to_fact_id else None
        if intent.is_completion and to_ref is None:
            to_ref = GOAL_REF
        intent_list.append(
            {
                "from": detail.intent_sources.get(intent.ref, []),
                "to": to_ref,
                "description": intent.description,
                "creator": intent.creator,
                "worker": intent.worker,
                "created_at": format_export_timestamp(intent.created_at),
                "concluded_at": format_export_timestamp(intent.concluded_at),
            }
        )
    if intent_list:
        data["intents"] = intent_list

    return yaml.dump(data, allow_unicode=True, default_flow_style=False, sort_keys=False)


def export_timeline(detail: ProjectDetailResult) -> str:
    """Render a chronological, human-readable event timeline."""
    facts_by_ref = {fact.ref: fact.description for fact in detail.facts}
    ref_by_uuid = _fact_ref_by_uuid(detail)

    # (sort_key, order, text) — order breaks ties deterministically.
    events: list[tuple[datetime, int, str]] = []
    order = 0
    epoch = datetime.min

    def _key(value: datetime | None) -> datetime:
        return value if value is not None else epoch

    created = detail.project.created_at
    block = (
        f"[{format_export_timestamp(created) or ''}] PROJECT CREATED\n"
        f"  origin: {facts_by_ref.get(ORIGIN_REF, '')}\n"
        f"  goal: {facts_by_ref.get(GOAL_REF, '')}"
    )
    events.append((_key(created), order, block))
    order += 1

    for hint in detail.hints:
        block = f"[{format_export_timestamp(hint.created_at) or ''}] HINT by {hint.creator}\n  {hint.content}"
        events.append((_key(hint.created_at), order, block))
        order += 1

    for intent in detail.intents:
        sources = detail.intent_sources.get(intent.ref, [])
        from_str = ", ".join(sources)
        meta = f"  from: {from_str}"
        if intent.worker and not intent.concluded_at:
            meta += f"\n  worker: {intent.worker} (in progress)"
        block = (
            f"[{format_export_timestamp(intent.created_at) or ''}] "
            f"INTENT DECLARED {intent.ref} by {intent.creator}\n{meta}\n  {intent.description}"
        )
        events.append((_key(intent.created_at), order, block))
        order += 1

        if not intent.concluded_at or not intent.to_fact_id:
            continue

        actor = intent.worker or intent.creator
        ts = format_export_timestamp(intent.concluded_at) or ""
        if intent.is_completion:
            block = f"[{ts}] PROJECT COMPLETED by {actor}\n  via: {intent.ref} from {from_str}"
        else:
            produced_ref = ref_by_uuid.get(intent.to_fact_id, "")
            fact_desc = facts_by_ref.get(produced_ref, "")
            block = (
                f"[{ts}] INTENT CONCLUDED {intent.ref} by {actor}\n"
                f"  from: {from_str}\n  produced: {produced_ref}\n  {fact_desc}"
            )
        events.append((_key(intent.concluded_at), order, block))
        order += 1

    events.sort(key=lambda event: (event[0], event[1]))
    return "\n\n".join(event[2] for event in events) + "\n"
