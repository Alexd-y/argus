"""HTTP probe CSV parser — host, url, scheme, status, title, server, redirect."""

import csv
import logging
from pathlib import Path

from src.recon.parsers._utils import get_str

logger = logging.getLogger(__name__)


def parse_http_probe(path: str | Path) -> list[dict]:
    """Parse http_probe.csv into list of dicts.

    CSV format: host,url,scheme,status,title,server,redirect
    Returns list of dicts with those keys.
    """
    path = Path(path)
    if not path.exists():
        return []

    try:
        with path.open(encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            rows: list[dict] = []
            for row in reader:
                normalized = {
                    "host": get_str(row, "host"),
                    "url": get_str(row, "url"),
                    "scheme": get_str(row, "scheme"),
                    "status": get_str(row, "status"),
                    "title": get_str(row, "title"),
                    "server": get_str(row, "server"),
                    "redirect": get_str(row, "redirect"),
                }
                rows.append(normalized)
            return rows
    except (OSError, csv.Error) as e:
        logger.warning(
            "Failed to parse HTTP probe CSV",
            extra={"path": str(path), "error": str(e)},
        )
        return []
