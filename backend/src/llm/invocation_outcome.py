"""LLM proposal → arbiter-verdict outcome linkage (Wave 5, R-9.2).

The wave-1 evidence arbiter is the only objective source of "was the model's
proposal real": it caps a finding's tier to what the collected artifacts
justify. This module turns that verdict into a persisted, measurable label per
finding (:class:`src.db.models.LlmInvocationOutcome`), so the measurement stage
(R-9.7) can compute confirmed-vs-rejected rates per task / model.

Writes go to a FRESH session so a telemetry failure can never poison the
findings-persistence transaction; the whole path is best-effort.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# EvidenceTier ints (src/pipeline/contracts/finding_dto.py): 1=INFORMATIONAL,
# 2=SUSPECTED, 3=CONFIRMED, 4=EXPLOITED.
_CONFIRMED_TIER = 3
_INFORMATIONAL_TIER = 1


def derive_outcome(
    *,
    applicable: bool,
    arbiter_tier: int | None,
) -> str:
    """Map an arbiter adjudication to a categorical outcome label.

    * ``not_applicable`` — the arbiter's domain does not cover this finding's
      class (heuristic/out-of-domain finding; no objective signal).
    * ``unknown`` — applicable but no arbiter tier was produced.
    * ``confirmed`` — artifacts justify CONFIRMED/EXPLOITED (tier ≥ 3).
    * ``suspected`` — artifacts justify only SUSPECTED (tier == 2).
    * ``rejected`` — artifacts justify nothing (tier == 1 / INFORMATIONAL).

    Whether the model over-claimed is a separate, computable fact
    (``arbiter_tier < model_tier``) and is intentionally not folded in here.
    """
    if not applicable:
        return "not_applicable"
    if arbiter_tier is None:
        return "unknown"
    if arbiter_tier >= _CONFIRMED_TIER:
        return "confirmed"
    if arbiter_tier <= _INFORMATIONAL_TIER:
        return "rejected"
    return "suspected"


@dataclass(frozen=True)
class OutcomeRecord:
    """One finding's LLM-proposal → arbiter-verdict link, ready to persist."""

    finding_id: str
    vuln_class: str = ""
    phase: str = ""
    task: str = ""
    invocation_id: str | None = None
    model: str = ""
    model_tier: int | None = None
    arbiter_tier: int | None = None
    applicable: bool = False


async def persist_invocation_outcomes(
    *,
    tenant_id: str,
    scan_id: str,
    records: list[OutcomeRecord],
) -> int:
    """Persist outcome rows in a FRESH, isolated session. Best-effort.

    Returns the number of rows written (0 on any failure or empty input). Never
    raises — analytics telemetry must not break the scan.
    """
    if not records or not tenant_id:
        return 0
    try:
        from src.db.models import LlmInvocationOutcome
        from src.db.session import async_session_factory, set_session_tenant

        async with async_session_factory() as session:
            await set_session_tenant(session, tenant_id)
            for rec in records:
                session.add(
                    LlmInvocationOutcome(
                        tenant_id=tenant_id,
                        scan_id=scan_id or None,
                        phase=rec.phase or None,
                        task=rec.task or None,
                        invocation_id=rec.invocation_id,
                        finding_id=rec.finding_id or None,
                        model=rec.model or None,
                        vuln_class=rec.vuln_class or None,
                        model_tier=rec.model_tier,
                        arbiter_tier=rec.arbiter_tier,
                        applicable=bool(rec.applicable),
                        outcome=derive_outcome(
                            applicable=rec.applicable,
                            arbiter_tier=rec.arbiter_tier,
                        ),
                    )
                )
            await session.commit()
        return len(records)
    except Exception:  # pragma: no cover - defensive; analytics never breaks scans
        logger.debug("persist_invocation_outcomes: suppressed best-effort error", exc_info=True)
        return 0


__all__ = ["OutcomeRecord", "derive_outcome", "persist_invocation_outcomes"]
