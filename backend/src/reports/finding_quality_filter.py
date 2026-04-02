"""Filter out incomplete/degenerate findings before report generation."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_INVALID_TITLES = frozenset({
    "unknown finding",
    "unknown",
    "untitled",
    "n/a",
    "none",
    "test",
    "placeholder",
})

_MIN_DESCRIPTION_LENGTH = 10


def _title_preview(title: object) -> str:
    if title is None:
        return "<empty>"
    if isinstance(title, str):
        s = title.strip()
        return s[:50] if s else "<empty>"
    return repr(title)[:50]


def filter_valid_findings(findings: list) -> list:
    """
    Remove degenerate findings that would add noise to the report.

    A finding is removed if:
    - title is empty or matches a known placeholder pattern
    - description is empty or too short (< 10 chars)
    """
    if not findings:
        return findings

    valid = []
    removed_count = 0

    for f in findings:
        title = _get_attr(f, "title")
        description = _get_attr(f, "description")

        if not _is_valid_title(title):
            removed_count += 1
            logger.info(
                "Filtered finding with invalid title: %r",
                _title_preview(title),
            )
            continue

        if not _is_valid_description(description):
            removed_count += 1
            logger.info(
                "Filtered finding with insufficient description, title=%r",
                _title_preview(title),
            )
            continue

        valid.append(f)

    if removed_count > 0:
        logger.info(
            "Quality filter removed %d findings (%d → %d)",
            removed_count, len(findings), len(valid),
        )

    return valid


def _is_valid_title(title) -> bool:
    if not title or not isinstance(title, str):
        return False
    normalized = title.strip().lower()
    if not normalized:
        return False
    return normalized not in _INVALID_TITLES


def _is_valid_description(description) -> bool:
    if not description or not isinstance(description, str):
        return False
    return len(description.strip()) >= _MIN_DESCRIPTION_LENGTH


def _get_attr(obj, name: str):
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)
