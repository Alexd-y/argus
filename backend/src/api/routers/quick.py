"""Quick catalog router — GET /api/v1/quick/profiles."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, status

from src.api.schemas import QuickProfileCatalogItem, QuickProfilesResponse
from src.quick.create import error_detail
from src.quick.profiles import QuickProfileCatalogError, load_quick_profiles
from src.quick.schemas import QuickProfileName

router = APIRouter(prefix="/quick", tags=["quick"])
logger = logging.getLogger(__name__)


@router.get("/profiles", response_model=QuickProfilesResponse)
async def list_quick_profiles() -> QuickProfilesResponse:
    """Return compact/balanced/extended catalog budgets. No secrets."""
    try:
        catalog = load_quick_profiles()
    except QuickProfileCatalogError:
        logger.warning("quick_profiles_catalog_unavailable", extra={"event": "quick_profiles_catalog_unavailable"})
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=error_detail("Quick profiles are unavailable", "quick_profile_catalog_unavailable"),
        ) from None

    items: list[QuickProfileCatalogItem] = []
    for name in (
        QuickProfileName.COMPACT,
        QuickProfileName.BALANCED,
        QuickProfileName.EXTENDED,
    ):
        defaults = catalog.get(name)
        items.append(
            QuickProfileCatalogItem(
                name=name.value,  # type: ignore[arg-type]
                wall_clock_budget_seconds=defaults.wall_clock_budget_seconds,
                ai_budget_seconds=defaults.ai_budget_seconds,
                reserve_for_validation_percent=defaults.reserve_for_validation_percent,
                max_targets=defaults.max_targets,
                max_urls_per_host=defaults.max_urls_per_host,
                crawl_depth=defaults.crawl_depth,
                severity_floor=defaults.severity_floor.value,
                enable_ai=defaults.enable_ai,
                enable_oast=defaults.enable_oast,
                enable_headless_on_signal=defaults.enable_headless_on_signal,
                request_budget=defaults.request_budget,
                per_host_budget=defaults.per_host_budget,
                concurrency_budget=defaults.concurrency_budget,
            )
        )
    return QuickProfilesResponse(profiles=items)


__all__ = ["router"]
