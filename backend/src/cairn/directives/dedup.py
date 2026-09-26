"""Directive de-duplication by normalized focus (§18.7).

Focus normalization gives a stable key (``service:tomcat``, ``port:4000``,
``cve:cve-2026-34486``) so re-running the generator without new facts does not
create duplicates. Embedding-based text similarity is an optional refinement layered
on top by the caller.
"""

from __future__ import annotations

from src.cairn.directives.schemas import DirectiveFocus, FocusType


def normalize_focus(focus: DirectiveFocus) -> str:
    """Return a stable, comparable key for a directive's focus."""
    value = focus.value.strip().lower()
    if focus.type is FocusType.CVE:
        return f"cve:{value}"
    if focus.type is FocusType.PORT:
        port = focus.port if focus.port is not None else value
        return f"port:{port}"
    if focus.type is FocusType.SERVICE:
        version = f"@{focus.service_version.strip().lower()}" if focus.service_version else ""
        return f"service:{value}{version}"
    if focus.type is FocusType.COMPONENT:
        return f"component:{value}"
    if focus.type in (FocusType.HOST, FocusType.TARGET):
        return f"host:{value}"
    if focus.type is FocusType.ENDPOINT:
        return f"endpoint:{value}"
    return f"{focus.type.value}:{value}"


def is_duplicate_focus(focus: DirectiveFocus, existing_keys: set[str]) -> bool:
    return normalize_focus(focus) in existing_keys


def dedupe_focuses(focuses: list[DirectiveFocus]) -> list[DirectiveFocus]:
    """Keep the first directive per normalized focus key (stable order)."""
    seen: set[str] = set()
    kept: list[DirectiveFocus] = []
    for focus in focuses:
        key = normalize_focus(focus)
        if key in seen:
            continue
        seen.add(key)
        kept.append(focus)
    return kept


__all__ = ["dedupe_focuses", "is_duplicate_focus", "normalize_focus"]
