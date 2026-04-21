"""ARG-041 — GET /providers/health (per-LLM-provider health snapshot).

Surfaces the in-process :class:`ProviderHealthRegistry` as JSON. The
endpoint is unauthenticated by design — it powers the operator dashboard
and contains no PII (provider names + numeric counters only). It is
mounted under the bare ``/providers/health`` path (no ``/api/v1``)
because the convention for liveness / readiness / metrics endpoints is
to keep them outside the versioned API namespace.

Status semantics:

* ``200 OK + status="ok"``    — every provider is closed and below the
  5xx threshold.
* ``200 OK + status="degraded"`` — at least one provider is open OR
  exceeds the 5xx threshold but the overall pod is still serving
  requests. The orchestrator should react (alert / failover) but the
  pod itself does not need a restart.

The endpoint never returns 503 — readiness (``/ready``) is the right
signal to remove the pod from the load balancer; ``/providers/health``
is informational so external dashboards can keep polling even during a
provider outage.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter

from src.api.schemas import ProviderHealth, ProvidersHealthResponse
from src.core.provider_health_registry import (
    KNOWN_PROVIDERS,
    get_provider_health_registry,
)

router = APIRouter(tags=["health"])
_logger = logging.getLogger(__name__)


@router.get(
    "/providers/health",
    response_model=ProvidersHealthResponse,
)
async def providers_health() -> ProvidersHealthResponse:
    """Return a per-provider health snapshot.

    The response includes every known provider even when the pod has
    never called it (counts default to zero, state defaults to ``closed``).
    Stable shape simplifies dashboards and avoids reactivity on cold
    starts.
    """
    registry = get_provider_health_registry()
    snapshots = registry.snapshot()
    providers: list[ProviderHealth] = []
    degraded = False
    for snap in snapshots:
        if snap.provider not in KNOWN_PROVIDERS:
            continue
        ph = ProviderHealth(
            provider=snap.provider,
            state=snap.state,
            last_success_ts=snap.last_success_ts,
            error_rate_5xx=snap.error_rate_5xx,
            error_count_60s=snap.error_count_60s,
            request_count_60s=snap.request_count_60s,
        )
        providers.append(ph)
        if ph.state == "open":
            degraded = True
        if ph.request_count_60s > 0 and ph.error_rate_5xx > 0.5:
            degraded = True
    return ProvidersHealthResponse(
        status="degraded" if degraded else "ok",
        providers=providers,
    )
