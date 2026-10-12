"""Transitional back-compat shim for the exploitability opinion (R-5.1.7).

Wave 1 renames ``ValidationResult.status`` (values ``confirmed`` / ``rejected``
/ ``uncertain``) to :class:`~src.validation.exploitability.ExploitabilityOpinion`
``.assessment`` (``plausible`` / ``implausible`` / ``undetermined``), because the
module renders a *model opinion*, not a confirmation. Existing consumers — the
``validation_status`` key threaded through the whole reporting pipeline and the
``/findings/{id}/validate`` API response — still expect the old vocabulary.

This module maps the new values back to the old ones for one release so nothing
downstream breaks while callers migrate. The misleading ``confirmed`` string
lives here (a compat boundary), deliberately NOT in ``exploitability.py`` whose
result enumeration must be free of it (wave-1 acceptance). Delete this module
once all consumers read ``assessment`` directly.
"""

from __future__ import annotations

#: New ``assessment`` -> legacy ``status`` (the old, over-stated wording).
_LEGACY_STATUS_FOR_ASSESSMENT: dict[str, str] = {
    "plausible": "confirmed",
    "implausible": "rejected",
    "undetermined": "uncertain",
}


def legacy_status(assessment: str) -> str:
    """Return the legacy ``ValidationResult.status`` for an ``assessment``.

    Unknown values fall back to ``"uncertain"`` (the legacy neutral value).
    """
    return _LEGACY_STATUS_FOR_ASSESSMENT.get(assessment, "uncertain")


__all__ = ["legacy_status"]
