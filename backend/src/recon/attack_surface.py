"""Unified attack-surface builder (Block 1.1).

``AttackSurface`` is the single structured hand-off between recon and
vuln_analysis: instead of threading assets, ports, crawl params and forms as
separate loose arguments, recon emits one object and vuln_analysis consumes it.

This module holds the *pure* builder that assembles an :class:`AttackSurface`
from recon's reconciled outputs, deriving ``endpoints`` and ``injection_points``
so downstream active-scan targeting has explicit, machine-readable inputs.
The Pydantic model itself lives in ``src.orchestration.phases`` to avoid a
circular import (phases <-> recon).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from src.orchestration.phases import AttackSurface


def _dedup(seq: list[str]) -> list[str]:
    return list(dict.fromkeys(s for s in seq if s))


def _endpoint_of(url: str) -> str:
    """Return scheme://host/path (no query/fragment) for grouping endpoints."""
    try:
        p = urlparse(url)
    except (ValueError, TypeError):
        return url
    if not p.scheme or not p.netloc:
        return url
    return f"{p.scheme}://{p.netloc}{p.path or ''}".rstrip("/") or f"{p.scheme}://{p.netloc}"


def _injection_points_from_params(params: list[dict[str, Any]]) -> list[dict[str, Any]]:
    points: list[dict[str, Any]] = []
    for entry in params:
        if not isinstance(entry, dict):
            continue
        url = str(entry.get("url") or entry.get("endpoint") or "")
        method = str(entry.get("method") or "GET").upper()
        names: list[str] = []
        if entry.get("param"):
            names.append(str(entry["param"]))
        if isinstance(entry.get("params"), list):
            names.extend(str(n) for n in entry["params"])
        if isinstance(entry.get("names"), list):
            names.extend(str(n) for n in entry["names"])
        for name in names:
            if not name:
                continue
            points.append(
                {"url": url, "parameter": name, "method": method, "location": "query"}
            )
    return points


def _injection_points_from_forms(forms: list[dict[str, Any]]) -> list[dict[str, Any]]:
    points: list[dict[str, Any]] = []
    for form in forms:
        if not isinstance(form, dict):
            continue
        url = str(form.get("action") or form.get("url") or "")
        method = str(form.get("method") or "POST").upper()
        inputs = form.get("inputs") or form.get("fields") or []
        if not isinstance(inputs, list):
            continue
        for field in inputs:
            name = ""
            if isinstance(field, dict):
                name = str(field.get("name") or field.get("id") or "")
            elif isinstance(field, str):
                name = field
            if name:
                points.append(
                    {"url": url, "parameter": name, "method": method, "location": "body"}
                )
    return points


def build_attack_surface(
    *,
    assets: list[str] | None = None,
    subdomains: list[str] | None = None,
    open_ports: list[int] | None = None,
    urls: list[str] | None = None,
    params: list[dict[str, Any]] | None = None,
    forms: list[dict[str, Any]] | None = None,
) -> AttackSurface:
    """Assemble a unified :class:`AttackSurface` from recon outputs.

    ``endpoints`` is derived (path-normalized URLs) and ``injection_points`` is
    the union of query params and form fields, so exploitation targeting does
    not have to re-parse loose recon artifacts.
    """
    assets = assets or []
    subdomains = subdomains or []
    open_ports = sorted({p for p in (open_ports or []) if isinstance(p, int)})
    params = params or []
    forms = forms or []

    url_pool = _dedup(
        (urls or [])
        + [a for a in assets if isinstance(a, str) and a.lower().startswith(("http://", "https://"))]
        + [str(p.get("url")) for p in params if isinstance(p, dict) and p.get("url")]
        + [str(f.get("action")) for f in forms if isinstance(f, dict) and f.get("action")]
    )
    endpoints = _dedup([_endpoint_of(u) for u in url_pool])

    injection_points = _injection_points_from_params(params) + _injection_points_from_forms(forms)

    return AttackSurface(
        assets=_dedup([str(a) for a in assets]),
        subdomains=_dedup([str(s) for s in subdomains]),
        open_ports=open_ports,
        urls=url_pool,
        params=params,
        forms=forms,
        endpoints=endpoints,
        injection_points=injection_points,
    )


__all__ = ["build_attack_surface"]
