"""CNAME map CSV parser — host, record_type, value, comment."""

import csv
import logging
from pathlib import Path

from src.recon.parsers._utils import get_str

logger = logging.getLogger(__name__)


def parse_cname(path: str | Path) -> list[dict]:
    """Parse cname_map.csv into list of dicts.

    CSV format: host,record_type,value,comment
    Returns list of dicts: {host, record_type, value, comment}.
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
                    "record_type": get_str(row, "record_type"),
                    "value": get_str(row, "value"),
                    "comment": get_str(row, "comment"),
                }
                rows.append(normalized)
            return rows
    except (OSError, csv.Error) as e:
        logger.warning(
            "Failed to parse CNAME CSV",
            extra={"path": str(path), "error": str(e)},
        )
        return []
