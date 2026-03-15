"""Resolved subdomains parser — subdomain -> list of IPs."""

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Format: "subdomain -> ip1, ip2, ip3, ..."
_LINE_RE = re.compile(r"^([^\s]+)\s*->\s*(.+)$")


def parse_resolved(path: str | Path) -> dict[str, list[str]]:
    """Parse resolved.txt into dict: subdomain -> list of IPs.

    Format: "autodiscover.svalbard.ca -> 52.96.165.8, 52.96.164.248, ..."
    """
    path = Path(path)
    if not path.exists():
        return {}

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning(
            "Failed to read resolved file", extra={"path": str(path), "error": str(e)}
        )
        return {}

    result: dict[str, list[str]] = {}

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue

        m = _LINE_RE.match(line)
        if not m:
            continue

        subdomain = m.group(1).strip()
        ips_str = m.group(2).strip()
        ips = [ip.strip() for ip in ips_str.split(",") if ip.strip()]
        existing = result.get(subdomain, [])
        merged = list(dict.fromkeys(existing + ips))
        result[subdomain] = merged

    return result
