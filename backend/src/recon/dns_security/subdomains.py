"""Subdomain enumeration parsing (Block 2.4).

Pure parsers for ``subfinder`` / ``amass passive`` / ``dnsx`` line output. These
tools each print hostnames (sometimes with trailing annotations); this module
normalizes them into a clean, de-duplicated subdomain list scoped to the target
domain, complementing the existing crt.sh certificate-transparency source.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# A hostname label chain (no scheme, no port). Captures the leading FQDN token
# so amass verbose lines ("host (FQDN) --> a_record --> ip") reduce to the host.
_HOST_RE = re.compile(r"^[*]?\.?([a-z0-9_-]+(?:\.[a-z0-9_-]+)+)", re.IGNORECASE)


def _normalize_host(token: str, domain: str) -> str | None:
    token = token.strip().lower().rstrip(".")
    if not token:
        return None
    match = _HOST_RE.match(token)
    if not match:
        return None
    host = match.group(1)
    d = domain.strip().lower().rstrip(".")
    if d and not (host == d or host.endswith("." + d)):
        return None
    return host


def parse_subdomains(outputs: Iterable[str], domain: str) -> list[str]:
    """Extract in-scope subdomains from one or more tool stdout blobs.

    Handles subfinder (plain host per line), amass passive (host + annotations),
    and dnsx (host [A] [ip]) formats. Returns a sorted, de-duplicated list.
    """
    found: set[str] = set()
    for blob in outputs:
        if not isinstance(blob, str):
            continue
        for raw_line in blob.splitlines():
            line = raw_line.strip()
            if not line or line.startswith((";", "#")):
                continue
            # Take the first whitespace-delimited token (host), drop annotations.
            token = line.split()[0]
            host = _normalize_host(token, domain)
            if host:
                found.add(host)
    return sorted(found)


__all__ = ["parse_subdomains"]
