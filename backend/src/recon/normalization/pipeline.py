"""Normalization pipeline — orchestrates tool output normalization and dedup."""

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models_recon import NormalizedFinding
from src.recon.adapters import registry
from src.recon.normalization.dedup import deduplicate_findings
from src.recon.scope.validator import ScopeValidator

logger = logging.getLogger(__name__)


async def normalize_tool_output(
    adapter_name: str,
    raw_output: str,
    scope_validator: ScopeValidator | None = None,
) -> list[dict[str, Any]]:
    """Parse and normalize raw tool output using the appropriate adapter."""
    adapter = registry.get(adapter_name)
    if not adapter:
        logger.warning("No adapter found", extra={"tool": adapter_name})
        return []

    result = await adapter.execute(
        target="",
        config={"raw_output": raw_output},
        scope_validator=scope_validator,
    )
    return result.normalized_findings


async def save_findings(
    db: AsyncSession,
    findings: list[dict[str, Any]],
    tenant_id: str,
    engagement_id: str,
    target_id: str,
    job_id: str | None = None,
) -> dict[str, int]:
    """Save normalized findings to DB with upsert (skip duplicates).

    Returns counts: {"added": N, "skipped": N}
    """
    added = 0
    skipped = 0

    deduped = deduplicate_findings(findings)

    for finding in deduped:
        existing = await db.execute(
            select(NormalizedFinding).where(
                NormalizedFinding.target_id == target_id,
                NormalizedFinding.finding_type == finding["finding_type"],
                NormalizedFinding.value == finding["value"],
            )
        )
        if existing.scalar_one_or_none():
            skipped += 1
            continue

        nf = NormalizedFinding(
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            target_id=target_id,
            job_id=job_id,
            finding_type=finding["finding_type"],
            value=finding["value"],
            data=finding.get("data", {}),
            source_tool=finding.get("source_tool", "unknown"),
            confidence=finding.get("confidence", 1.0),
        )
        db.add(nf)
        added += 1

    if added > 0:
        await db.flush()

    logger.info(
        "Findings saved",
        extra={"added": added, "skipped": skipped, "total": len(findings)},
    )
    return {"added": added, "skipped": skipped}
