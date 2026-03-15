"""WHOIS artifact parser — extracts registrar, expiry, nameservers, registrant, creation_date."""

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_REGISTRAR = re.compile(r"^Registrar:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
_EXPIRY = re.compile(r"^Registry Expiry Date:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
_NAMESERVERS = re.compile(r"^Name Server:\s*(.+)$", re.MULTILINE | re.IGNORECASE)
_REGISTRANT = re.compile(
    r"^Registrant (?:Name|Organization):\s*(.+)$", re.MULTILINE | re.IGNORECASE
)
_CREATION = re.compile(r"^Creation Date:\s*(.+)$", re.MULTILINE | re.IGNORECASE)


def parse_whois(path: str | Path) -> dict:
    """Parse whois.txt into structured dict.

    Returns:
        dict with keys: registrar, expiry, nameservers, registrant, creation_date.
        Missing fields are empty string or empty list.
    """
    path = Path(path)
    if not path.exists():
        return _empty_whois()

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("Failed to read whois file", extra={"path": str(path), "error": str(e)})
        return _empty_whois()

    if not text.strip():
        return _empty_whois()

    registrar = _first_match(_REGISTRAR, text)
    expiry = _first_match(_EXPIRY, text)
    nameservers = _NAMESERVERS.findall(text)
    nameservers = [ns.strip() for ns in nameservers if ns.strip()]
    registrant = _first_match(_REGISTRANT, text)
    creation_date = _first_match(_CREATION, text)

    return {
        "registrar": registrar or "",
        "expiry": expiry or "",
        "nameservers": nameservers,
        "registrant": registrant or "",
        "creation_date": creation_date or "",
    }


def _empty_whois() -> dict:
    return {
        "registrar": "",
        "expiry": "",
        "nameservers": [],
        "registrant": "",
        "creation_date": "",
    }


def _first_match(pattern: re.Pattern[str], text: str) -> str | None:
    m = pattern.search(text)
    return m.group(1).strip() if m else None
