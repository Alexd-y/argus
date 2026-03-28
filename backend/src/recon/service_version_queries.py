"""Derive bounded searchsploit query strings from recon asset lines (nmap/LLM-style)."""

from __future__ import annotations

import re
from typing import Iterable

# Strip leading ip:port or [ip]:port
_LEADING_ENDPOINT_RE = re.compile(
    r"^(\[[0-9a-fA-F:.]+\]|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?\s+",
)
# "open tcp 80 http Apache httpd 2.4.41" style
_NMAP_TOKENS_RE = re.compile(
    r"\b(open|filtered|closed)\s+(\w+)\s+(\d+)\s*/\s*(\w+)\s+(.+)$",
    re.IGNORECASE,
)


def _normalize_asset_line(line: str) -> str:
    s = (line or "").strip()
    if not s:
        return ""
    s = _LEADING_ENDPOINT_RE.sub("", s)
    s = re.sub(r"^\d+/(?:tcp|udp)\s+", "", s, flags=re.IGNORECASE)
    m = _NMAP_TOKENS_RE.search(s)
    if m:
        return (m.group(5) or "").strip()
    return s


def _queries_from_text(text: str) -> list[str]:
    out: list[str] = []
    t = _normalize_asset_line(text)
    if not t or len(t) < 3:
        return out
    # Drop bare ports / status noise
    if re.fullmatch(r"\d{1,5}", t):
        return out
    low = t.lower()
    noise = {"http", "https", "tcp", "udp", "open", "unknown"}
    parts = [p for p in re.split(r"[/\s,;|]+", t) if p and p.lower() not in noise]
    if len(parts) >= 2:
        # product + version-ish tail
        candidate = f"{parts[0]} {parts[-1]}".strip()
        if len(candidate) >= 4:
            out.append(candidate[:120])
    if t not in out and len(t) <= 120:
        out.append(t)
    return out


def bounded_service_queries_from_assets(
    assets: Iterable[str],
    *,
    max_queries: int,
) -> list[str]:
    """
    Build deduplicated search terms for Exploit-DB / searchsploit (lowercase keys, stable order).

    ``max_queries`` caps total strings returned (recon-bound).
    """
    if max_queries <= 0:
        return []
    seen: set[str] = set()
    ordered: list[str] = []
    for raw in assets:
        if not isinstance(raw, str):
            continue
        for q in _queries_from_text(raw):
            key = q.strip().lower()
            if not key or key in seen:
                continue
            seen.add(key)
            ordered.append(q.strip())
            if len(ordered) >= max_queries:
                return ordered
    return ordered
