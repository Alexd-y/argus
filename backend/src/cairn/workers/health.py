"""Worker health checks — async LLM endpoint ping.

Ported from ``_external/Cairn/cairn/src/cairn/dispatcher/workers/health.py``
(AGPL-3.0), converted to async httpx. Healthy = a 2xx response; any other status or
a connection/timeout error is unhealthy. Secrets in ``detail`` are the caller's
responsibility to avoid — this module clips and never logs bodies itself.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

DETAIL_LIMIT = 200


@dataclass(slots=True)
class HealthResult:
    ok: bool
    status: int | None
    detail: str


def _clip(text: str) -> str:
    compact = " ".join(text.split())
    return compact if len(compact) <= DETAIL_LIMIT else compact[:DETAIL_LIMIT] + "..."


async def http_ping(
    url: str,
    *,
    headers: dict[str, str],
    json_body: dict,
    timeout: float,
    proxy: str | None = None,
) -> HealthResult:
    """POST a tiny request to an LLM endpoint and judge health by HTTP status."""
    try:
        async with httpx.AsyncClient(timeout=timeout, proxy=proxy) as client:
            response = await client.post(url, headers=headers, json=json_body)
    except httpx.HTTPError as exc:
        return HealthResult(ok=False, status=None, detail=_clip(str(exc)))
    ok = 200 <= response.status_code < 300
    return HealthResult(
        ok=ok,
        status=response.status_code,
        detail="" if ok else _clip(response.text),
    )


def proxy_from_env(env: dict[str, str]) -> str | None:
    """Return the outbound proxy the worker would use (all/https/http, any case)."""
    all_proxy = env.get("all_proxy") or env.get("ALL_PROXY")
    https = env.get("https_proxy") or env.get("HTTPS_PROXY") or all_proxy
    http = env.get("http_proxy") or env.get("HTTP_PROXY") or all_proxy
    return https or http


__all__ = ["DETAIL_LIMIT", "HealthResult", "http_ping", "proxy_from_env"]
