"""Prompt rendering for Cairn tasks.

Ported from ``_external/Cairn/cairn/src/cairn/dispatcher/prompting.py`` (AGPL-3.0).

The signed prompt templates contain literal JSON examples with ``{`` / ``}``.
``str.format`` (used by the generic ARGUS ``BaseAgent``) would treat those as
fields and raise / mangle them, so Cairn tasks render via :func:`render_prompt`,
which substitutes only the known ``{placeholder}`` tokens and leaves every other
brace untouched.

All untrusted content (graph snapshot, tool output, hints, service banners) is
wrapped in ``<untrusted_input>`` via :mod:`src.orchestration.prompt_injection_defense`
before it reaches the model — the graph is populated by external tool output and is
a prompt-injection vector.
"""

from __future__ import annotations

import json
from typing import Any

from src.orchestration.prompt_injection_defense import tag_untrusted


def render_prompt(template: str, replacements: dict[str, str]) -> str:
    """Substitute ``{key}`` tokens without touching other braces.

    Unlike ``str.format`` this never interprets JSON ``{...}`` examples embedded in
    the template as format fields.
    """
    rendered = template
    for key, value in replacements.items():
        rendered = rendered.replace("{" + key + "}", value)
    return rendered


def format_fact_ids(fact_refs: list[str]) -> str:
    """Render the valid fact-id list for the reason prompt."""
    if not fact_refs:
        return "(none)"
    return "\n".join(f"- {ref}" for ref in fact_refs)


def format_open_intents(open_intents: list[dict[str, Any]]) -> str:
    """Render currently open (unconcluded) intents for the reason prompt."""
    if not open_intents:
        return "(none)"
    lines = []
    for intent in open_intents:
        ref = intent.get("id") or intent.get("ref", "?")
        description = intent.get("description", "")
        worker = intent.get("worker")
        suffix = f" [worker: {worker}]" if worker else ""
        lines.append(f"- {ref}: {description}{suffix}")
    return "\n".join(lines)


def format_hints(hints: list[dict[str, Any]]) -> str:
    """Render human hints (wrapped as untrusted content)."""
    if not hints:
        return "(none)"
    rendered = "\n".join(
        f"- ({hint.get('creator', 'human')}) {hint.get('content', '')}" for hint in hints
    )
    return tag_untrusted(rendered, source="cairn_hints")


def format_json_block(obj: Any) -> str:
    """Serialize an object as a pretty JSON block (unicode preserved)."""
    return json.dumps(obj, ensure_ascii=False, indent=2)


def wrap_untrusted(text: str, *, source: str) -> str:
    """Wrap external/untrusted content (graph YAML, tool output) for a prompt."""
    return tag_untrusted(text, source=source)


__all__ = [
    "format_fact_ids",
    "format_hints",
    "format_json_block",
    "format_open_intents",
    "render_prompt",
    "wrap_untrusted",
]
