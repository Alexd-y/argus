"""ARG-041 — HTTP request metrics middleware.

Wraps every HTTP request through :func:`record_http_request` so the global
``argus_http_requests_total`` counter and ``argus_http_request_duration_seconds``
histogram receive a sample. The middleware:

* Resolves the FastAPI **route template** (e.g. ``/api/v1/scans/{scan_id}``)
  from ``request.scope["route"].path`` rather than the raw path. This keeps
  the ``route`` label cardinality bounded by the number of FastAPI handlers.
* Extracts the tenant id from the request state (populated by the auth
  layer) and routes it through :func:`tenant_hash` so the raw value never
  reaches Prometheus.
* Skips emit on the URLs in :data:`EXCLUDED_URLS` so health probes don't
  flood the metric series.
* Catches every internal failure: a metric crash MUST NOT break a 200 OK.
"""

from __future__ import annotations

import logging
import time
from typing import Final

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Match

from src.core.observability import record_http_request

_logger = logging.getLogger(__name__)

#: URL paths that must NOT emit HTTP metrics (high-frequency health probes).
EXCLUDED_PATHS: Final[frozenset[str]] = frozenset(
    {
        "/health",
        "/ready",
        "/metrics",
        "/providers/health",
        "/queues/health",
    },
)

#: Sentinel used when FastAPI cannot resolve a route template — almost
#: always means a 404 against an unknown path. Using a sentinel here keeps
#: the metric cardinality flat (a single "_unmatched" series instead of one
#: series per random URL).
_UNMATCHED_ROUTE: Final[str] = "_unmatched"


def _resolve_route_template(request: Request) -> str:
    """Return the FastAPI route template for *request* or ``_unmatched``.

    Walks the app's routing table to find the first matching route and
    extracts its ``path``. We cannot rely on ``request.scope.get("route")``
    being populated because the BaseHTTPMiddleware runs *before* routing
    in some Starlette versions.
    """
    route = request.scope.get("route")
    if route is not None and getattr(route, "path", None):
        return str(route.path)
    app = request.app
    if app is None or not hasattr(app, "routes"):
        return _UNMATCHED_ROUTE
    for r in app.routes:
        try:
            match, _scope = r.matches(request.scope)
        except Exception:  # noqa: BLE001 — defensive
            continue
        if match == Match.FULL and getattr(r, "path", None):
            return str(r.path)
    return _UNMATCHED_ROUTE


def _extract_tenant_id(request: Request) -> str | None:
    """Return the request's tenant id (from ``request.state.auth``) or ``None``.

    The auth dependency populates ``request.state.auth`` with the
    :class:`AuthContext` once the dependency chain runs; for unauthenticated
    paths the attribute is missing — we return ``None`` and let
    :func:`tenant_hash` map that to the ``system`` sentinel.
    """
    state = getattr(request, "state", None)
    if state is None:
        return None
    auth = getattr(state, "auth", None)
    if auth is None:
        return None
    return getattr(auth, "tenant_id", None)


class HttpMetricsMiddleware(BaseHTTPMiddleware):
    """Emit HTTP request metrics around every request.

    Lives at the *outer* edge of the middleware stack so the duration
    histogram captures the entire request handling time (auth +
    middleware + handler + render).
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        if path in EXCLUDED_PATHS:
            return await call_next(request)
        start = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            try:
                duration = time.perf_counter() - start
                record_http_request(
                    method=request.method,
                    route=_resolve_route_template(request),
                    status_code=status_code,
                    duration_seconds=duration,
                    tenant_id=_extract_tenant_id(request),
                )
            except Exception:  # pragma: no cover — defensive
                _logger.exception("http_metrics_middleware.emit_failed")


__all__ = ["EXCLUDED_PATHS", "HttpMetricsMiddleware"]
