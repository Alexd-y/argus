"""Bounded searchsploit runs from recon service/version strings (KAL-006)."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from src.core.config import settings
from src.recon.adapters.security.searchsploit_adapter import SearchsploitAdapter
from src.orchestration.raw_phase_artifacts import RawPhaseSink
from src.recon.sandbox_tool_runner import SEARCHSPLOIT_INTEL_RAW_ARTIFACT_KEY
from src.recon.service_version_queries import bounded_service_queries_from_assets

logger = logging.getLogger(__name__)


async def run_searchsploit_for_recon_assets(
    assets: list[str],
    *,
    tenant_id: str | None = None,
    scan_id: str | None = None,
) -> list[dict[str, Any]]:
    """
    For each bounded query derived from ``assets``, run searchsploit and collect intel rows.

    Intel rows match the shape expected by ``handlers._normalize_intel_finding``
    (``finding_type``, ``source_tool``, ``data``).
    """
    if not settings.searchsploit_enabled:
        return []

    queries = bounded_service_queries_from_assets(
        assets,
        max_queries=settings.searchsploit_max_queries,
    )
    if not queries:
        return []

    adapter = SearchsploitAdapter()
    if not adapter.is_available():
        logger.info(
            "searchsploit_skipped",
            extra={"reason": "not_on_path", "scan_id": scan_id},
        )
        return []

    use_sandbox = settings.sandbox_enabled
    aggregated: list[dict[str, Any]] = []
    per_query_cap = 12

    for q in queries:
        rows: list[dict[str, Any]] = []
        for use_json in (True, False):
            config: dict[str, Any] = {"sandbox": use_sandbox, "use_json": use_json}
            try:
                chunk = await adapter.run(q, config)
            except Exception:
                logger.warning(
                    "searchsploit_query_failed",
                    extra={"scan_id": scan_id, "query_len": len(q), "json_mode": use_json},
                    exc_info=True,
                )
                chunk = []
            if chunk:
                rows = chunk
                break
        for row in rows[:per_query_cap]:
            if isinstance(row, dict) and row.get("data"):
                aggregated.append(row)

    if tenant_id and scan_id and aggregated:
        sink = RawPhaseSink(tenant_id, scan_id, "vuln_analysis")
        await asyncio.to_thread(
            sink.upload_json,
            SEARCHSPLOIT_INTEL_RAW_ARTIFACT_KEY,
            {
                "queries": queries,
                "finding_count": len(aggregated),
            },
        )

    logger.info(
        "searchsploit_intel_complete",
        extra={
            "scan_id": scan_id,
            "queries_run": len(queries),
            "rows": len(aggregated),
        },
    )
    return aggregated
