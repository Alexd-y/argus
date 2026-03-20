"""UTC timestamps for API responses (frontend expects ISO-8601 with Z)."""

from datetime import UTC, datetime


def format_created_at_iso_z(dt: datetime | None) -> str:
    """Return UTC instant as ``YYYY-MM-DDTHH:MM:SSZ`` (no subsecond)."""
    if dt is None:
        dt = datetime.now(UTC)
    elif dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    else:
        dt = dt.astimezone(UTC)
    dt = dt.replace(microsecond=0)
    return dt.isoformat().replace("+00:00", "Z")
