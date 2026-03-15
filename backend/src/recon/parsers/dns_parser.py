"""DNS artifact parser — parses dns_records.txt, ns.txt, mx.txt, txt.txt, caa.txt."""

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# Patterns for different DNS record formats (svalbard-stage1)
_RE_NS = re.compile(r"^\S+\s+nameserver\s*=\s*(.+)$", re.IGNORECASE)
_RE_MX = re.compile(
    r"^\S+\s+MX\s+preference\s*=\s*\d+,\s*mail\s+exchanger\s*=\s*(.+)$",
    re.IGNORECASE,
)
_RE_TXT = re.compile(r'^\S+\s+text\s*=\s*"([^"]*)"\s*$', re.IGNORECASE)
_RE_A = re.compile(r"^\S+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*$")
_RE_AAAA = re.compile(r"^\S+\s+([0-9a-f:]+)\s*$", re.IGNORECASE)
_RE_CAA = re.compile(r'^\S+\s+\d+\s+(?:issue|iodef)\s+"([^"]*)"\s*$', re.IGNORECASE)


def parse_dns(path: str | Path) -> list[dict]:
    """Parse DNS record files into structured list of dicts.

    Supports: dns_records.txt, ns.txt, mx.txt, txt.txt, caa.txt.
    Returns list of dicts: {type, value}.
    """
    path = Path(path)
    if not path.exists():
        return []

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("Failed to read DNS file", extra={"path": str(path), "error": str(e)})
        return []

    records: list[dict] = []
    fname = path.name.lower()

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue

        rec = _parse_dns_line(line, fname)
        if rec:
            records.append(rec)

    return records


def _parse_dns_line(line: str, fname: str) -> dict | None:
    """Parse a single DNS line. Infer type from filename or content."""
    if "ns.txt" in fname or "nameserver" in line.lower():
        m = _RE_NS.search(line)
        if m:
            return {"type": "NS", "value": m.group(1).strip()}
    if "mx.txt" in fname or "mail exchanger" in line.lower():
        m = _RE_MX.search(line)
        if m:
            return {"type": "MX", "value": m.group(1).strip()}
    if "txt.txt" in fname or 'text =' in line:
        m = _RE_TXT.search(line)
        if m:
            return {"type": "TXT", "value": m.group(1)}
    if "caa.txt" in fname or ' issue "' in line.lower():
        m = _RE_CAA.search(line)
        if m:
            return {"type": "CAA", "value": m.group(1)}
    if "dns_records" in fname:
        for pattern, rtype in [
            (_RE_NS, "NS"),
            (_RE_MX, "MX"),
            (_RE_TXT, "TXT"),
            (_RE_CAA, "CAA"),
            (_RE_AAAA, "AAAA"),
            (_RE_A, "A"),
        ]:
            m = pattern.search(line)
            if m:
                return {"type": rtype, "value": m.group(1).strip()}
    return None
