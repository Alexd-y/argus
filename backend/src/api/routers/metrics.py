"""Prometheus metrics endpoint — GET /metrics."""

from fastapi import APIRouter, Response

from src.core.observability import get_metrics_content

router = APIRouter(tags=["metrics"])


@router.get("/metrics")
async def metrics() -> Response:
    """Prometheus scrape endpoint."""
    body, content_type = get_metrics_content()
    return Response(content=body, media_type=content_type)
