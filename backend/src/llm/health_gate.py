"""Cached provider health gate (§4 health-gated routing).

A short-TTL reachability probe so routing can skip a KNOWN-down cloud primary
proactively — emitting a degradation metric/log — instead of eating a full failed
call before falling back. Cached per (env_key, base_url) so a probe runs at most
once per TTL; never raises (a probe failure is reported as "unhealthy", not an
exception), so wiring it into routing can only make routing more conservative.
"""

from __future__ import annotations

import logging
import os
import time

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_TTL = 60.0
_cache: dict[str, tuple[float, bool]] = {}


def reset_cache() -> None:
    """Test helper — drop cached health so the next check re-probes."""
    _cache.clear()


def provider_healthy(base_url: str, env_key: str, *, ttl: float = _DEFAULT_TTL) -> bool:
    """True when the OpenAI-compatible provider at ``base_url`` looks reachable.

    Cached for ``ttl`` seconds. An unset key is unhealthy. A 401/5xx or a transport
    error is unhealthy (and logged once per TTL as a degradation signal); any other
    status (200/400/403/404 — reached the service) is healthy.
    """
    base = (base_url or "").rstrip("/")
    cache_key = f"{env_key}@{base}"
    now = time.monotonic()
    hit = _cache.get(cache_key)
    if hit is not None and (now - hit[0]) < ttl:
        return hit[1]

    token = (os.environ.get(env_key) or "").strip()
    if not token:
        _cache[cache_key] = (now, False)
        return False

    healthy = False
    try:
        resp = httpx.get(
            f"{base}/v1/models",
            headers={"Authorization": f"Bearer {token}"},
            timeout=4.0,
        )
        healthy = resp.status_code not in (401, 403) and resp.status_code < 500
    except Exception:  # noqa: BLE001 — any transport error == unhealthy
        healthy = False

    if not healthy:
        logger.warning(
            "llm_provider_unhealthy",
            extra={"event": "llm_provider_unhealthy", "base_url": base, "env_key": env_key},
        )
    _cache[cache_key] = (now, healthy)
    return healthy


__all__ = ["provider_healthy", "reset_cache"]
