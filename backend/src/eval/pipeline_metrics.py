"""Full-pipeline eval metric snapshot (Wave 5, R-9.5/R-9.7).

Until now the product-metric comparison lived only in the Quick comparison
report (``src/quick/comparison.py`` + the Quick-only ``eval_config.json``). This
module computes the model-quality snapshot for the FULL scan pipeline from the
Stage-A telemetry, so the same metrics are available after any scan, not only
Quick:

* arbiter confirmed / rejected / not-applicable rates (R-9.7), from
  ``llm_invocation_outcomes``;
* structured-output parse rates (R-9.7), from the process-global counters.

Returns the flat ``{name: float}`` map that :mod:`src.eval.baseline` snapshots
and gates. Best-effort: any failure yields an empty map rather than breaking
scan finalisation.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


async def build_scan_metrics(session, tenant_id: str, scan_id: str) -> dict[str, float]:
    """Assemble the full-pipeline eval metric snapshot for one scan.

    Best-effort — returns ``{}`` on any failure.
    """
    try:
        from src.eval.model_metrics import compute_outcome_metrics, load_outcome_rows
        from src.eval.rates import snapshot_structured_parse_rates

        rows = await load_outcome_rows(session, tenant_id, scan_id=scan_id)
        overall = compute_outcome_metrics(rows)["__all__"]
        parse = snapshot_structured_parse_rates()
        return {
            "arbiter_confirmed_rate": overall.confirmed_rate,
            "arbiter_rejected_rate": overall.rejected_rate,
            "arbiter_not_applicable_rate": overall.not_applicable_rate,
            "outcome_total": float(overall.total),
            "outcome_applicable_total": float(overall.applicable_total),
            "structured_direct_parse_rate": parse.direct_parse_rate,
            "structured_fallback_parse_rate": parse.fallback_parse_rate,
            "structured_parse_failure_rate": parse.parse_failure_rate,
            "structured_parse_total": float(parse.total),
        }
    except Exception:  # pragma: no cover - defensive; eval never breaks scans
        logger.debug("build_scan_metrics: suppressed best-effort error", exc_info=True)
        return {}


__all__ = ["build_scan_metrics"]
