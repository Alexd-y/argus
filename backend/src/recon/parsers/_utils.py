"""Shared utilities for recon parsers."""


def get_str(row: dict, key: str) -> str:
    """Extract and normalize a string value from a dict (e.g. CSV row).

    Returns stripped string; empty string if key missing or value is None.
    """
    val = row.get(key, "")
    return str(val).strip() if val is not None else ""
